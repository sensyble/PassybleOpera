import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { SKIP_DETECT_MS, TOAST_DELAY_MS } from '../src/shared/otp-logic.js';

mock.timers.enable({ apis: ['setTimeout', 'setInterval', 'Date'], now: 1_700_000_000_000 });

const LOGIN = `<form id="login"><h1>Sign in</h1><input type="email" name="email">
  <input type="password" name="password"><button type="submit">Sign in</button></form>`;
const dom = new JSDOM(`<!doctype html><html><body>${LOGIN}</body></html>`, { url: 'https://example.com/login', pretendToBeVisual: true });
const w = dom.window;
w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};

const sent = [];
let runtimeListener;
let fillReply = { username: 'alice', password: 'pw', totp: { code: '123456', period: 30, remaining_secs: 20 }, skips_2fa: false };
const responses = {
  'otp.context': () => ({ pending: { id: 'ex', title: 'Example' }, offer: true, autoFillOtp: true, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ({ items: [{ id: 'ex', title: 'Example', username: 'alice', has_totp: true, has_passkey: false }], pending_otp: { id: 'ex', title: 'Example' } }),
  'logins.fill': () => fillReply,
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

/** Moves the mocked clock on in small steps, letting scans, timers and replies run. */
async function advance(ms) {
  for (let left = ms; left > 0; left -= 250) {
    mock.timers.tick(Math.min(250, left));
    await flush();
  }
}

const command = (msg) => new Promise((resolve) => runtimeListener(msg, { id: 'pass-ext' }, resolve));
const outcomes = () => sent.filter((m) => m.type === 'otp.outcome').map((m) => m.outcome);
const toastShown = () => !!w.document.querySelector('pass-toast');

/** Back to a sign-in page and fills it through Passyble (a login with 2FA). */
async function fillSignIn(path = '/login') {
  w.history.pushState({}, '', path);
  w.document.body.innerHTML = LOGIN;
  await advance(500);
  assert.equal(toastShown(), false);
  sent.length = 0;
  const filled = command({ type: 'cmd.fill-item', id: 'ex' });
  await flush();
  await filled;
  assert.equal(w.document.querySelector('[name=password]').value, 'pw');
}

test('the sign-in form still on screen: neither skipped nor a toast', async () => {
  await fillSignIn();
  await advance(SKIP_DETECT_MS + 2000);
  assert.deepEqual(outcomes(), []);
  assert.equal(toastShown(), false);
});

test('site skipped 2FA: no toast, nothing fetched, "skipped" reported', async () => {
  await fillSignIn();
  // Signed in straight away (same document, URL back to the app).
  w.history.pushState({}, '', '/dashboard');
  w.document.body.innerHTML = '<header><input type="search" name="q" placeholder="Search"></header><h1>Welcome back, Alice</h1><p>Your projects</p>';
  await advance(SKIP_DETECT_MS / 2);
  assert.deepEqual(outcomes(), [], 'not decided yet');
  await advance(SKIP_DETECT_MS / 2 + 1000);
  assert.deepEqual(outcomes(), ['skipped']);
  assert.equal(toastShown(), false);
  assert.ok(!sent.some((m) => m.type === 'totp.get'), 'the code was never fetched');
  await advance(30_000);
  assert.deepEqual(outcomes(), ['skipped'], 'reported once');
});

test('after a skip, a code field that shows up later still gets the code', async () => {
  w.document.body.insertAdjacentHTML('beforeend', '<form><input id="late" name="otp" autocomplete="one-time-code"></form>');
  await advance(1000);
  assert.equal(w.document.getElementById('late').value, '654321');
  assert.ok(sent.some((m) => m.type === 'otp.consumed' && m.id === 'ex'));
  assert.ok(outcomes().includes('asked'));
});

test('2FA wording but no code field: the toast, and "asked" reported', async () => {
  await fillSignIn();
  w.history.pushState({}, '', '/sessions/two-factor');
  w.document.body.innerHTML = '<h1>Two-factor authentication</h1><p>Approve the sign-in on your phone, or use the code from your authenticator app.</p><div id="widget"></div>';
  await advance(TOAST_DELAY_MS + 1000);
  assert.equal(toastShown(), true);
  assert.deepEqual(outcomes(), ['asked']);
  await advance(SKIP_DETECT_MS);
  assert.ok(!outcomes().includes('skipped'));
  await advance(3 * 60_000); // the toast closes with the pending window
  assert.equal(toastShown(), false);
});

test('2FA wording on a signed-in page (no input, not a sign-in URL) shows nothing', async () => {
  await fillSignIn();
  w.history.pushState({}, '', '/settings/security');
  w.document.body.innerHTML = '<h1>Security</h1><p>Two-factor authentication is on.</p>';
  await advance(SKIP_DETECT_MS + 1000);
  assert.equal(toastShown(), false);
  assert.deepEqual(outcomes(), [], 'neither asked nor skipped: wording keeps it undecided');
});

test('learned skip (skips_2fa): wording alone shows nothing, a code field is still filled', async () => {
  fillReply = { ...fillReply, skips_2fa: true };
  responses['otp.context'] = () => ({ pending: { id: 'ex', title: 'Example', skips_2fa: true }, offer: true, quiet: true, autoFillOtp: true, otpFieldElsewhere: false, items: [] });
  try {
    await fillSignIn();
    w.history.pushState({}, '', '/sessions/two-factor');
    w.document.body.innerHTML = '<h1>Two-factor authentication</h1><p>Use the code from your authenticator app.</p><div id="widget"></div>';
    await advance(TOAST_DELAY_MS + 3000);
    assert.equal(toastShown(), false, 'no toast for a site that usually skips 2FA');
    assert.ok(!w.document.querySelector('pass-menu'), 'no menu either');
    w.document.getElementById('widget').innerHTML = '<input id="c" name="otp" autocomplete="one-time-code">';
    await advance(1000);
    assert.equal(w.document.getElementById('c').value, '654321');
  } finally {
    fillReply = { ...fillReply, skips_2fa: false };
  }
});
