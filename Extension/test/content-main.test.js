import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM(`<!doctype html><html><body>
  <form id="login"><h1>Sign in</h1><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>
</body></html>`, { url: 'https://github.com/login', pretendToBeVisual: true });
const w = dom.window;

// jsdom has no layout: give every element a box so visibility checks pass.
w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};

const sent = [];
let runtimeListener;
const responses = {
  'otp.context': () => ({ pending: null, offer: false, autoFillOtp: true, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ({ items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }], pending_otp: null }),
  'logins.fill': () => ({ username: 'octo', password: 'hunter2', totp: { code: '123456', period: 30, remaining_secs: 20 } }),
  'totp.get': () => ({ id: 'gh', title: 'GitHub', code: '654321', period: 30, remaining_secs: 20 }),
  'save.query': () => null,
};

before(async () => {
  w.chrome = undefined;
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
    storage: {
      local: { get: async () => ({ autoFillOtp: true }) },
      onChanged: { addListener: () => {} },
    },
  };
  main = await import('../src/content/main.js');
  await main.start();
});

let main;
after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const command = (msg) => new Promise((resolve) => runtimeListener(msg, { id: 'pass-ext' }, resolve));

test('start() asks for the OTP context; no save banner while a sign-in form is still on screen', () => {
  assert.ok(sent.some((m) => m.type === 'otp.context' && m.navigation === true));
  // A visible login form right after load means the sign-in failed: the query says so, and the
  // background then only offers a sign-up / password change (see background.test.js).
  const queries = sent.filter((m) => m.type === 'save.query');
  assert.ok(queries.every((m) => m.loginFormVisible === true && m.sameDocument === false), JSON.stringify(queries));
});

test('focusing a detected field shows the inline icon in a shadow host', async () => {
  const email = w.document.querySelector('[name=email]');
  email.focus();
  await tick(5);
  assert.ok(w.document.querySelector('pass-icon'), 'icon host mounted');
  assert.equal(w.document.querySelector('pass-icon').shadowRoot, null, 'closed shadow root');
  assert.ok(sent.some((m) => m.type === 'focus' && m.kind === 'username'));
});

test('cmd.fill-item fills username and password through logins.fill', async () => {
  const res = await command({ type: 'cmd.fill-item', id: 'gh' });
  assert.deepEqual(res, { ok: true });
  assert.equal(w.document.querySelector('[name=email]').value, 'octo');
  assert.equal(w.document.querySelector('[name=password]').value, 'hunter2');
  const done = sent.find((m) => m.type === 'fill.done');
  assert.deepEqual(done, { type: 'fill.done', id: 'gh', otp: false });
});

test('OTP field in the same form is filled with the password', async () => {
  const otp = w.document.createElement('input');
  otp.name = 'otp';
  otp.setAttribute('autocomplete', 'one-time-code');
  w.document.getElementById('login').append(otp);
  await command({ type: 'cmd.fill-item', id: 'gh' });
  assert.equal(otp.value, '123456');
  assert.equal(sent.filter((m) => m.type === 'fill.done').at(-1).otp, true);
  otp.remove();
});

test('after an SPA navigation to the 2FA step, the pending OTP is auto-filled', async () => {
  responses['otp.context'] = () => ({ pending: { id: 'gh', title: 'GitHub' }, offer: true, autoFillOtp: true, otpFieldElsewhere: false, items: [] });
  w.history.pushState({}, '', '/sessions/two-factor');
  w.document.body.innerHTML = '<form><p>Enter the code from your authenticator app</p><input name="app_otp" autocomplete="one-time-code"><button>Verify</button></form>';
  await tick(400); // debounced rescan -> navigation -> otp.context -> autofill
  await tick(20);
  assert.equal(w.document.querySelector('[name=app_otp]').value, '654321');
  const totpCall = sent.find((m) => m.type === 'totp.get');
  assert.equal(totpCall.id, undefined, 'pending item: totp.get without id');
  assert.ok(sent.some((m) => m.type === 'otp.consumed' && m.id === 'gh'));
});

test('OTP shortcut without any OTP field shows the toast', async () => {
  w.document.body.innerHTML = '<div>Custom canvas widget</div>';
  await tick(300);
  await command({ type: 'cmd.fill-otp' });
  await tick(5);
  assert.ok(w.document.querySelector('pass-toast'), 'toast mounted');
});

test("the 2FA toast's next code never asks to unlock, and a lock closes the toast", async () => {
  const totp = responses['totp.get'];
  responses['totp.get'] = () => ({ id: 'gh', title: 'GitHub', code: '111222', period: 30, remaining_secs: 1 });
  try {
    w.document.body.innerHTML = '<div>Custom canvas widget</div>';
    await tick(300);
    await command({ type: 'cmd.fill-otp' });
    await tick(5);
    assert.ok(w.document.querySelector('pass-toast'), 'toast mounted');
    sent.length = 0;
    // The period rolls over (also what a resume from sleep looks like): the next code is fetched as
    // an automatic request, which the background never turns into an unlock prompt.
    await tick(2300);
    const refresh = sent.find((m) => m.type === 'totp.get');
    assert.ok(refresh, 'the next code was fetched');
    assert.equal(refresh.id, 'gh');
    assert.equal(refresh.automatic, true);
    await command({ type: 'lock_state', locked: true });
    await tick(5);
    assert.equal(w.document.querySelector('pass-toast'), null, 'no 2FA code stays on screen while locked');
  } finally {
    responses['totp.get'] = totp;
  }
});


test('2FA step in the same document (no URL change) after a fill: the pending code is auto-filled', async () => {
  w.document.body.innerHTML = `<form id="login"><h1>Sign in</h1><input type="email" name="email">
    <input type="password" name="password"><button>Sign in</button></form>`;
  await tick(300);
  sent.length = 0;
  await command({ type: 'cmd.fill-item', id: 'gh' });
  assert.equal(w.document.querySelector('[name=password]').value, 'hunter2');
  // The site sends the form with fetch and swaps in the 2FA step; the URL stays the same.
  w.document.getElementById('login').outerHTML = '<div><h1>Enter code</h1><input id="otc" name="otc" type="tel" maxlength="6"></div>';
  await tick(400);
  await tick(20);
  assert.equal(w.document.getElementById('otc').value, '654321');
  assert.equal(sent.find((m) => m.type === 'totp.get').id, undefined, 'the pending code (no id)');
  assert.ok(!sent.some((m) => m.type === 'otp.context'), 'no navigation needed');
});

test('a field Passyble does not recognise gets the pending code in the menu when focused', async () => {
  w.document.body.innerHTML = `<form id="login"><input type="email" name="email"><input type="password" name="password"></form>`;
  await tick(300);
  await command({ type: 'cmd.fill-item', id: 'gh' });
  w.document.body.innerHTML = '<form><h1>One more step</h1><input id="answer" name="answer"></form>';
  await tick(400);
  assert.equal(w.document.getElementById('answer').value, '', 'not filled on its own');
  sent.length = 0;
  w.document.getElementById('answer').focus();
  await tick(20);
  assert.ok(w.document.querySelector('pass-menu'), 'menu opened on the field');
  assert.ok(sent.some((m) => m.type === 'logins.find'));
  w.document.getElementById('answer').blur();
});

test('Alt+Shift+K fills the focused field even when nothing names it a code field', async () => {
  w.document.body.innerHTML = '<form><p>Type the number</p><input id="n" name="n"></form>';
  await tick(300);
  w.document.getElementById('n').focus();
  await command({ type: 'cmd.fill-otp' });
  assert.equal(w.document.getElementById('n').value, '654321');
});
test('a message the background did not get (service worker starting) is sent again after growing pauses', async () => {
  w.document.body.innerHTML = '<form id="login"><input type="email" name="email"><input type="password" name="password"></form>';
  await tick(300);
  const send = chrome.runtime.sendMessage;
  let failures = 1;
  chrome.runtime.sendMessage = async (msg) => {
    if (msg.type === 'logins.fill' && failures-- > 0) throw new Error('Could not establish connection. Receiving end does not exist.');
    return send(msg);
  };
  try {
    sent.length = 0;
    const started = Date.now();
    const res = await command({ type: 'cmd.fill-item', id: 'gh' });
    assert.deepEqual(res, { ok: true });
    assert.ok(Date.now() - started >= 200, 'after a short pause');
    assert.equal(w.document.querySelector('[name=password]').value, 'hunter2');
    // A service worker that is slow to wake (Brave): three misses, then it answers, after 250 + 500 + 1000 ms.
    w.document.querySelector('[name=password]').value = '';
    failures = 3;
    const slow = Date.now();
    const late = await command({ type: 'cmd.fill-item', id: 'gh' });
    assert.deepEqual(late, { ok: true });
    assert.ok(Date.now() - slow >= 1650, 'growing pauses');
    assert.equal(w.document.querySelector('[name=password]').value, 'hunter2');
    // Four in a row (about 2 s): Passyble really can't be reached through the extension.
    failures = 4;
    const again = await command({ type: 'cmd.fill-item', id: 'gh' });
    assert.equal(again.error.code, 'agent_unavailable');
    assert.equal(failures, 0, 'tried four times');
    // A failure after the message may have arrived is not repeated.
    let calls = 0;
    chrome.runtime.sendMessage = async (msg) => {
      if (msg.type !== 'logins.fill') return send(msg);
      calls++;
      throw new Error('The message port closed before a response was received.');
    };
    const once = await command({ type: 'cmd.fill-item', id: 'gh' });
    assert.equal(once.error.code, 'agent_unavailable');
    assert.equal(calls, 1);
  } finally {
    chrome.runtime.sendMessage = send;
  }
});

test('cmd.notice: the outcome of a copy the popup asked for shows as a notice on the page (the popup may be gone)', async () => {
  const before = w.document.querySelectorAll('pass-notice').length;
  const res = await command({ type: 'cmd.notice', text: 'Password copied by Passyble (clears in 45 s)' });
  assert.equal(res.ok, true);
  assert.equal(w.document.querySelectorAll('pass-notice').length, before + 1, 'a notice host on the page');
  const empty = await command({ type: 'cmd.notice', text: '' });
  assert.equal(empty.ok, false, 'nothing to say: no notice');
  const odd = await command({ type: 'cmd.notice', text: { html: '<b>x</b>' } });
  assert.equal(odd.ok, false, 'plain text only');
  assert.equal(w.document.querySelectorAll('pass-notice').length, before + 1);
});

// Last: the extension context dies, which tears this content script down.
test('extension updated under the page: extension_reloaded ("reload this page"), not "isn\'t running", and no retry', async () => {
  const send = chrome.runtime.sendMessage;
  let calls = 0;
  chrome.runtime.sendMessage = async () => {
    calls++;
    chrome.runtime.id = undefined;
    throw new Error('Extension context invalidated.');
  };
  try {
    const res = await command({ type: 'cmd.fill-item', id: 'gh' });
    assert.equal(res.error.code, 'extension_reloaded');
    assert.equal(calls, 1);
  } finally {
    chrome.runtime.sendMessage = send;
    chrome.runtime.id = 'pass-ext';
  }
});
