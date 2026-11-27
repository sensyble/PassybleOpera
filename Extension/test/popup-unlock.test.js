import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
const clipboard = [];
let closed = 0;
let runtimeListener = null;

async function openPopup({ search = '' } = {}) {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: `https://extension.test/${search}`, pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  Object.defineProperty(globalThis, 'navigator', {
    value: { clipboard: { writeText: async (t) => { clipboard.push(t); } } }, configurable: true,
  });
  globalThis.window = { close: () => { closed += 1; } };
  globalThis.location = { search };
  messages.length = 0;
  clipboard.length = 0;
  closed = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));
const sent = (type) => messages.filter((m) => m.type === type);

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }] },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

afterEach(() => {
  delete globalThis.window;
  delete globalThis.location;
});

const LOCKED = { url: 'https://github.com/login', supported: true, locked: true, can_unlock_inline: true, unlock_hello: false, ask_unlock: false };
const ITEMS = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }];
const SOFT = { ...LOCKED, soft_locked: true, items: ITEMS, pending_otp: null, can_edit: true, can_search: true, can_icons: false };
const UNLOCKED = { ...SOFT, locked: false, soft_locked: false };

/** A desktop app that unlocks with "master" (and Windows Hello when `hello`). */
function app({ state = LOCKED, hello = false, auto = false } = {}) {
  let locked = true;
  reply = (msg) => {
    switch (msg.type) {
      case 'popup.state': return { ok: true, result: locked ? { ...state, unlock_hello: hello, unlock_hello_auto: hello && auto } : UNLOCKED };
      case 'popup.unlock-password':
        if (msg.password !== 'master') return { ok: false, error: { code: 'wrong_password', message: 'Wrong master password. Check Caps Lock and try again.' } };
        locked = false;
        return { ok: true, result: { locked: false } };
      case 'popup.unlock-hello':
        locked = false;
        return { ok: true, result: msg.then ? { locked: false, filled: true } : { locked: false } };
      // An older desktop app: no copies of its own (the popup copies what popup.copy sends).
      case 'popup.copy-item': return { ok: false, error: { code: 'not_supported', message: 'unknown method' } };
      case 'popup.copy':
        if (locked && msg.inline) return { ok: false, error: { code: 'locked', message: 'Vault is locked' } };
        return { ok: true, result: { value: 'hunter2' } };
      case 'popup.fill': return { ok: true, result: { ok: true } };
      default: return { ok: true, result: null };
    }
  };
}

async function submit($, window, password) {
  $('master').value = password;
  $('unlock-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await flush();
  await flush();
  await flush();
}

test('locked: the form with a password field that no password manager fills, Unlock, and "Open Passyble"', async () => {
  app();
  const { $ } = await openPopup();
  assert.equal($('view-locked').hidden, false);
  assert.equal($('unlock-form').hidden, false);
  assert.equal($('master').type, 'password');
  assert.equal($('master').getAttribute('autocomplete'), 'off');
  assert.equal($('unlock').hidden, true, "the app-prompt button is for older desktop apps");
  assert.equal($('unlock-app').hidden, false, '"Open Passyble" stays as the fallback');
  assert.equal($('unlock-hello').hidden, true, 'no Windows Hello unless the desktop app offers it');
  assert.equal($('unlock-cancel').hidden, true);
});

test('a wrong master password shows the app\'s text; the right one loads the list', async () => {
  app();
  const { $, window } = await openPopup();
  await submit($, window, 'nope');
  assert.equal($('unlock-msg').textContent, 'Wrong master password. Is Caps Lock on?');
  assert.equal($('master').getAttribute('aria-invalid'), 'true', 'the field shows the error');
  assert.ok($('unlock-msg').classList.contains('error'));
  assert.equal($('master').value, '', 'the field is cleared');
  assert.equal($('view-locked').hidden, false);
  await submit($, window, 'master');
  await flush();
  assert.deepEqual(sent('popup.unlock-password').map((m) => m.password), ['nope', 'master']);
  assert.equal($('view-list').hidden, false, 'unlocked: the list');
  assert.equal(sent('popup.unlock').length, 0, "the desktop app's prompt wasn't needed");
});

test('an empty password is not sent', async () => {
  app();
  const { $, window } = await openPopup();
  await submit($, window, '');
  assert.equal(sent('popup.unlock-password').length, 0);
  assert.match($('unlock-msg').textContent, /Enter your master password/);
});

test('Windows Hello when the desktop app allows it', async () => {
  app({ hello: true });
  const { $ } = await openPopup();
  assert.equal($('unlock-hello').hidden, false);
  $('unlock-hello').click();
  await flush();
  await flush();
  await flush();
  assert.equal(sent('popup.unlock-hello').length, 1);
  assert.equal($('view-list').hidden, false);
});

test('Windows Hello not possible now: the reason, and the password form stays', async () => {
  app({ hello: true });
  const base = reply;
  reply = (msg) => (msg.type === 'popup.unlock-hello'
    ? { ok: false, error: { code: 'not_supported', message: 'Passyble asks for your master password every 7 days.' } }
    : base(msg));
  const { $ } = await openPopup();
  $('unlock-hello').click();
  await flush();
  await flush();
  assert.equal($('unlock-msg').textContent, 'Passyble asks for your master password every 7 days.');
  assert.equal($('unlock-hello').hidden, true);
  assert.equal($('unlock-form').hidden, false);
});

test('Passyble not running: unlocking shows the usual not-running view', async () => {
  app();
  const base = reply;
  reply = (msg) => (msg.type === 'popup.unlock-password'
    ? { ok: false, error: { code: 'agent_unavailable', message: 'Passyble desktop app is not running' } }
    : base(msg));
  const { $, window } = await openPopup();
  await submit($, window, 'master');
  assert.equal($('view-offline').hidden, false);
  assert.equal($('offline-title').textContent, "Passyble isn't running");
});

test('soft-locked: copying a password asks for the master password here, then copies', async () => {
  app({ state: SOFT });
  const { $, window } = await openPopup();
  assert.equal($('view-list').hidden, false);
  const row = window.document.querySelector('#list li.item');
  row.querySelector('button[title="Copy password"]').click();
  await flush();
  await flush();
  assert.equal($('view-locked').hidden, false, 'the unlock form, for the copy');
  assert.equal($('unlock-cancel').hidden, false, 'Cancel goes back to the list');
  assert.equal(sent('popup.copy')[0].inline, true, "the background didn't open the desktop app's prompt");
  await submit($, window, 'master');
  await flush();
  assert.equal(sent('popup.copy').length, 2, 'the copy ran again');
  assert.deepEqual(clipboard, ['hunter2']);
  assert.equal($('view-list').hidden, false);
});

test('soft-locked: Cancel goes back to the list and copies nothing', async () => {
  app({ state: SOFT });
  const { $, window } = await openPopup();
  window.document.querySelector('#list li.item button[title="Copy password"]').click();
  await flush();
  await flush();
  $('unlock-cancel').click();
  await flush();
  assert.equal($('view-list').hidden, false);
  assert.deepEqual(clipboard, []);
  assert.equal($('snack').textContent, '', 'no "Cancelled" message for the user\'s own Cancel');
});

test('soft-locked fill with Windows Hello: the background fills (the popup may close meanwhile)', async () => {
  app({ state: SOFT, hello: true });
  const { $, window } = await openPopup();
  window.document.querySelector('#list li.item button.item-main').click();
  await flush();
  assert.equal($('view-locked').hidden, false);
  $('unlock-hello').click();
  await flush();
  await flush();
  await flush();
  assert.deepEqual(sent('popup.unlock-hello')[0].then, { fill: { tabId: 1, id: 'gh' } });
  assert.equal(sent('popup.unlock-hello')[0].for, 'gh', 'the unlock is for that fill');
  assert.equal(sent('popup.fill').length, 0, 'not filled twice');
  assert.equal(closed, 1);
});

test('soft-locked fill with the master password: unlock, then fill', async () => {
  app({ state: SOFT });
  const { $, window } = await openPopup();
  window.document.querySelector('#list li.item button.item-main').click();
  await flush();
  await submit($, window, 'master');
  await flush();
  assert.equal(sent('popup.fill').length, 1);
  assert.equal(sent('popup.unlock-password')[0].for, 'gh', 'the unlock is for that fill');
  assert.equal(closed, 1);
});


/** Lets promise callbacks run, but no timer: what happens here happens "at once". */
async function microtasks(n = 200) {
  for (let i = 0; i < n; i++) await Promise.resolve();
}

test('soft-locked fill with the master password: the fill goes out the moment the unlock answers, before the list is drawn again', async () => {
  app({ state: SOFT });
  const base = reply;
  let answer = null;
  reply = (msg) => (msg.type === 'popup.unlock-password'
    ? new Promise((resolve) => { answer = () => resolve(base(msg)); })
    : base(msg));
  const { $, window } = await openPopup();
  window.document.querySelector('#list li.item button.item-main').click();
  await flush();
  $('master').value = 'master';
  $('unlock-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await flush();
  assert.ok(answer, 'unlocking');
  const from = messages.length;
  answer();
  await microtasks();
  // The list drawn again afterwards may ask for its 2FA codes, but only after the fill.
  assert.equal(messages.slice(from)[0]?.type, 'popup.fill', 'the fill is the first request');
  await flush();
  assert.equal(closed, 1);
  reply = base;
});

test('opened by the in-page menu: the form first; unlocked, the popup closes (the page fills)', async () => {
  app({ state: { ...SOFT, ask_unlock: true } });
  const { $, window } = await openPopup();
  assert.equal($('view-locked').hidden, false, 'the form, not the list');
  await submit($, window, 'master');
  assert.equal(closed, 1);
});

test('unlocked elsewhere while the form is up: on with the action', async () => {
  app({ state: SOFT });
  const { $, window } = await openPopup();
  window.document.querySelector('#list li.item button[title="Copy password"]').click();
  await flush();
  await flush();
  const base = reply;
  reply = (msg) => (msg.type === 'popup.copy' ? { ok: true, result: { value: 'hunter2' } } : base(msg));
  runtimeListener({ type: 'lock_state', locked: false });
  await flush();
  await flush();
  assert.deepEqual(clipboard, ['hunter2']);
  assert.equal($('view-list').hidden, false);
});

test('the unlock-only window (?unlock=1): the form; Cancel or the unlock closes it', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.unlock-options') return { ok: true, result: { inline: true, locked: true, hello: true } };
    if (msg.type === 'popup.unlock-password') return { ok: true, result: { locked: false } };
    return { ok: true, result: null };
  };
  const { $, window } = await openPopup({ search: '?unlock=1' });
  assert.equal(sent('popup.state').length, 0, 'no tab state: this window is not a tab popup');
  assert.equal($('view-locked').hidden, false);
  assert.equal($('unlock-hello').hidden, false);
  assert.equal($('unlock-cancel').hidden, false);
  assert.equal(sent('popup.unlock-hello').length, 0, 'the user asked for the password here: no Windows Hello on its own');
  await submit($, window, 'master');
  assert.equal(closed, 1);
});

test('older desktop apps: the Unlock button opens their own prompt, as before', async () => {
  reply = (msg) => (msg.type === 'popup.state'
    ? { ok: true, result: { url: 'https://github.com/login', supported: true, locked: true, can_unlock_inline: false } }
    : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('unlock-form').hidden, true);
  assert.equal($('unlock').hidden, false);
  $('unlock').click();
  await flush();
  assert.equal(sent('popup.unlock').length, 1);
});

/** `popup.unlock-hello` answers when the test says so. */
function holdHello() {
  const base = reply;
  let answer;
  reply = (msg) => (msg.type === 'popup.unlock-hello' ? new Promise((resolve) => { answer = resolve; }) : base(msg));
  return {
    unlock: () => answer(base({ type: 'popup.unlock-hello' })), // the app unlocks
    cancel: () => answer({ ok: false, error: { code: 'cancelled', message: 'unlock cancelled' } }),
  };
}

test('opened on a locked vault with Windows Hello: it starts at once, the password field stays usable beside it', async () => {
  app({ hello: true, auto: true });
  const hello = holdHello();
  const { $ } = await openPopup();
  assert.equal($('view-locked').hidden, false);
  assert.equal(sent('popup.unlock-hello').length, 1, 'no click on "Use Windows Hello" needed');
  assert.equal(sent('popup.unlock-hello')[0].then, undefined);
  assert.equal($('unlock-msg').textContent, 'Confirm with Windows Hello, or type your master password.');
  assert.equal($('master').disabled, false, 'the master password is the other way, right there');
  assert.equal($('unlock-hello').disabled, true, 'not a second Windows Hello');
  hello.unlock();
  await flush();
  await flush();
  assert.equal($('view-list').hidden, false, 'unlocked: the list');
  assert.equal(sent('popup.unlock-hello').length, 1);
});

test('popup.html in a browser tab (opened as a page, or restored as the browser starts): no Windows Hello on its own', async () => {
  app({ hello: true, auto: true });
  chrome.tabs.getCurrent = async () => ({ id: 7, url: 'chrome-extension://pass-ext/src/popup/popup.html' });
  try {
    const { $ } = await openPopup();
    assert.equal($('view-locked').hidden, false);
    assert.equal(sent('popup.unlock-hello').length, 0, 'nobody clicked the toolbar button');
    assert.equal($('unlock-hello').hidden, false, 'one click away');
  } finally {
    delete chrome.tabs.getCurrent;
  }
});

test('typing the master password while Windows Hello is up calls it off; its late answer changes nothing', async () => {
  app({ hello: true, auto: true });
  const hello = holdHello();
  const { $, window } = await openPopup();
  assert.equal(sent('popup.unlock-hello').length, 1);
  $('master').value = 'm';
  $('master').dispatchEvent(new window.Event('input', { bubbles: true }));
  await flush();
  assert.equal(sent('popup.unlock-cancel').length, 1, 'Windows Hello called off');
  assert.equal($('unlock-msg').textContent, '');
  assert.equal($('unlock-hello').disabled, false, 'Windows Hello again is one click away');
  hello.cancel();
  await flush();
  assert.equal($('unlock-msg').textContent, '', 'no "cancelled" message for the user\'s own switch');
  await submit($, window, 'master');
  await flush();
  assert.equal($('view-list').hidden, false);
  assert.equal(sent('popup.unlock-cancel').length, 1);
});

test('Cancel in Windows Hello: the password form, and no new Windows Hello on its own in this popup', async () => {
  app({ state: SOFT, hello: true, auto: true });
  const hello = holdHello();
  const { $, window } = await openPopup();
  assert.equal($('view-list').hidden, false, 'soft-locked: the list, nothing asked yet');
  assert.equal(sent('popup.unlock-hello').length, 0);
  // Copying the password needs the vault: Windows Hello at once.
  window.document.querySelector('#list li.item button[title="Copy password"]').click();
  await flush();
  await flush();
  assert.equal($('view-locked').hidden, false);
  assert.equal(sent('popup.unlock-hello').length, 1);
  hello.cancel();
  await flush();
  await flush();
  assert.match($('unlock-msg').textContent, /cancel/i);
  assert.equal(window.document.activeElement, $('master'), 'the master password field has the focus');
  // Back to the list, try again: the form only (the user just said no to Windows Hello).
  $('unlock-cancel').click();
  await flush();
  window.document.querySelector('#list li.item button[title="Copy password"]').click();
  await flush();
  await flush();
  assert.equal($('view-locked').hidden, false);
  assert.equal(sent('popup.unlock-hello').length, 1, 'not again on its own');
  $('unlock-hello').click();
  await flush();
  assert.equal(sent('popup.unlock-hello').length, 2, 'but one click away');
});

test('the background says the user declined Windows Hello moments ago: the popup opens with the form only', async () => {
  app({ hello: true, auto: false });
  const { $ } = await openPopup();
  assert.equal($('view-locked').hidden, false);
  assert.equal($('unlock-hello').hidden, false);
  assert.equal(sent('popup.unlock-hello').length, 0);
});

test('a Windows Hello already up (from the page): the popup waits for that one', async () => {
  app({ hello: true, auto: false, state: { ...LOCKED, unlock_hello_pending: true } });
  const hello = holdHello();
  const { $ } = await openPopup();
  assert.equal(sent('popup.unlock-hello').length, 1, 'the background joins it to the one that is up');
  hello.unlock();
  await flush();
  await flush();
  assert.equal($('view-list').hidden, false);
});

test('opened by the in-page menu for the master password: no Windows Hello on its own', async () => {
  app({ state: { ...SOFT, ask_unlock: true }, hello: true, auto: true });
  const { $ } = await openPopup();
  assert.equal($('view-locked').hidden, false);
  assert.equal(sent('popup.unlock-hello').length, 0);
});

test('soft-locked fill with Windows Hello on its own: one click on the login, the background fills', async () => {
  app({ state: SOFT, hello: true, auto: true });
  const { window } = await openPopup();
  window.document.querySelector('#list li.item button.item-main').click();
  await flush();
  await flush();
  await flush();
  assert.equal(sent('popup.unlock-hello').length, 1);
  assert.deepEqual(sent('popup.unlock-hello')[0].then, { fill: { tabId: 1, id: 'gh' } });
  assert.equal(sent('popup.unlock-hello')[0].for, 'gh', 'the unlock is for that fill');
  assert.equal(sent('popup.fill').length, 0, 'not filled twice');
  assert.equal(closed, 1);
});
