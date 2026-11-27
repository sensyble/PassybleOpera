// Only the 2FA step's field may take a pending code: after a Google sign-in, Gmail's compose Subject
// (on an inbox listing "Your verification code") must not get the 2FA menu.
import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { SKIP_DETECT_MS, TOAST_DELAY_MS } from '../src/shared/otp-logic.js';

mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: 1_700_000_000_000 });

const LOGIN = `<form id="login"><h1>Sign in</h1><input type="email" name="email">
  <input type="password" name="password"><button type="submit">Next</button></form>`;
const dom = new JSDOM(`<!doctype html><html><body>${LOGIN}</body></html>`, { url: 'https://example.com/signin', pretendToBeVisual: true });
const w = dom.window;
w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};

const sent = [];
let runtimeListener;
let autoFillOtp = true;
const responses = {
  'otp.context': () => ({ pending: { id: 'ex', title: 'Example' }, offer: true, autoFillOtp, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ({ items: [{ id: 'ex', title: 'Example', username: 'alice', has_totp: true, has_passkey: false }], pending_otp: { id: 'ex', title: 'Example' } }),
  'logins.fill': () => ({ username: 'alice', password: 'pw', totp: { code: '123456', period: 30, remaining_secs: 20 }, skips_2fa: false }),
  'totp.get': () => ({ id: 'ex', title: 'Example', code: '654321', period: 30, remaining_secs: 20 }),
  'save.query': () => null,
};

let main;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: w.document, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return { ok: true, result: fn ? fn(msg) : {} };
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: { local: { get: async () => ({ autoFillOtp: true }) }, onChanged: { addListener: () => {} } },
  };
  main = await import('../src/content/main.js');
  await main.start();
  await flush();
});

after(() => {
  main.stop();
  w.close();
  mock.timers.reset();
});

async function flush() {
  for (let i = 0; i < 6; i++) await new Promise((r) => setImmediate(r));
}

async function advance(ms) {
  for (let left = ms; left > 0; left -= 250) {
    mock.timers.tick(Math.min(250, left));
    await flush();
  }
}

const command = (msg) => new Promise((resolve) => runtimeListener(msg, { id: 'pass-ext' }, resolve));
const outcomes = () => sent.filter((m) => m.type === 'otp.outcome').map((m) => m.outcome);
const menuOpen = () => !!w.document.querySelector('pass-menu');
const toastShown = () => !!w.document.querySelector('pass-toast');

async function fillSignIn(path = '/signin') {
  w.document.activeElement?.blur?.();
  w.history.pushState({}, '', path);
  w.document.body.innerHTML = LOGIN;
  await advance(500);
  sent.length = 0;
  const filled = command({ type: 'cmd.fill-item', id: 'ex' });
  await flush();
  await filled;
  assert.equal(w.document.querySelector('[name=password]').value, 'pw');
}

async function focus(el) {
  el.focus();
  await flush();
  const open = menuOpen();
  el.blur();
  await flush();
  return open;
}

const INBOX = Array.from({ length: 40 }, (_, i) =>
  `<tr><td>Google</td><td>${i % 3 ? 'Your verification code is 123456' : '2-Step Verification is on'}</td><td>Use it with your authenticator app (message ${i}).</td></tr>`).join('');
const GMAIL = `<header><form role="search"><input id="q" name="q" aria-label="Search mail"></form></header>
  <nav><a href="#">Inbox</a><a href="#">Sent</a></nav><table>${INBOX}</table>
  <div role="dialog" aria-label="New Message"><form>
    <div><div role="combobox" aria-label="To recipients"></div></div>
    <div><input id="subject" name="subjectbox" placeholder="Subject" aria-label="Subject"></div>
    <div contenteditable="true" role="textbox" aria-label="Message Body"></div>
    <div role="button">Send</div>
  </form></div>
  <div class="chat"><div><input id="chat" placeholder="Reply to Alice"></div></div>
  <div class="settings"><div><input id="plain"></div></div>`;

test('signed in, landed on the mail app: Subject, search, chat and plain boxes never get the 2FA menu', async () => {
  await fillSignIn();
  w.history.pushState({}, '', '/mail/u/0/');
  w.document.body.innerHTML = GMAIL;
  await advance(500);
  for (const id of ['subject', 'q', 'chat', 'plain']) {
    assert.equal(await focus(w.document.getElementById(id)), false, id);
  }
  assert.ok(!sent.some((m) => m.type === 'focus' && m.kind === 'otp'), 'never reported as a code field');
  await advance(TOAST_DELAY_MS);
  assert.equal(toastShown(), false, 'an inbox mentioning verification codes is no 2FA step');
  // No 2FA step next to any field: after the skip delay the sign-in counts as done without 2FA,
  // which ends the offer.
  await advance(SKIP_DETECT_MS);
  assert.deepEqual(outcomes(), ['skipped']);
  assert.equal(await focus(w.document.getElementById('plain')), false);
  assert.ok(!sent.some((m) => m.type === 'totp.get'), 'the code was never fetched');
  assert.equal(w.document.getElementById('subject').value, '');
});

test('two-page sign-in: a separate code page on the same site still gets the pending code', async () => {
  await fillSignIn();
  w.history.pushState({}, '', '/signin/challenge');
  w.document.body.innerHTML = '<main><h2>Enter the code from your authenticator app</h2><form><input id="c" type="text"><button>Next</button></form></main>';
  await advance(500);
  assert.equal(w.document.getElementById('c').value, '654321', 'detected and filled');
  assert.ok(outcomes().includes('asked'));
});

test('two-page sign-in, nothing names the field: focusing it still offers the code', async () => {
  autoFillOtp = false;
  try {
    await fillSignIn();
    w.history.pushState({}, '', '/signin/step2');
    w.document.body.innerHTML = '<form><h1>One more step</h1><p>Type the number you see.</p><input id="n" name="answer"><button>OK</button></form>';
    await advance(500);
    assert.equal(w.document.getElementById('n').value, '');
    const el = w.document.getElementById('n');
    el.focus();
    await flush();
    assert.equal(menuOpen(), true, 'a short sign-in step page with one box');
    el.blur();
    await flush();
  } finally {
    autoFillOtp = true;
  }
});

test('a pending code and a long app page: a code-shaped box or a box named a code still gets it', async () => {
  await fillSignIn();
  w.history.pushState({}, '', '/app/home');
  w.document.body.innerHTML = `<table>${INBOX}</table><div class="modal"><div><input id="v" placeholder="Verification code"></div></div>`;
  await advance(500);
  // a named code field is detected (and filled on its own)
  assert.equal(w.document.getElementById('v').value, '654321');
});
