// The popup's unlock form for a browser vault linked to a Passyble account (real popup.html + popup.js in jsdom).
import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
const opened = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText: async () => {} } }, configurable: true });
  globalThis.window = { close: () => {} };
  globalThis.location = { search: '' };
  messages.length = 0;
  opened.length = 0;
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
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }], create: async (o) => { opened.push(o.url); } },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

afterEach(() => {
  delete globalThis.window;
  delete globalThis.location;
});

const LOCKED = { url: 'https://github.com/login', supported: true, locked: true, can_unlock_inline: true, unlock_hello: false, ask_unlock: false, browser: true };
const UNLOCKED = { ...LOCKED, locked: false, soft_locked: false, items: [], pending_otp: null, can_edit: true, can_search: true, can_icons: false };

function browserVault({ linked, unlock }) {
  let locked = true;
  reply = (msg) => {
    switch (msg.type) {
      case 'popup.state': return { ok: true, result: locked ? { ...LOCKED, account_unlock: linked } : UNLOCKED };
      case 'popup.unlock-password': {
        const out = unlock(msg);
        if (out.ok) locked = false;
        return out;
      }
      default: return { ok: true, result: null };
    }
  };
}

const submit = (win, $) => $('unlock-form').dispatchEvent(new win.Event('submit', { cancelable: true, bubbles: true }));

test('a linked vault: the Passyble password, the Secret Key once (shared computer: not kept), then unlocked', async () => {
  browserVault({
    linked: { account: 'acc_demo', email: 'demo@example.com', secret_key_needed: true, email_needed: false },
    unlock: (msg) => (msg.password === 'passyble pw' && msg.secret_key === 'P1-AAAAA' ? { ok: true, result: { locked: false } }
      : { ok: false, error: { code: 'wrong_password', message: 'wrong', reason: 'wrong_account_password' } }),
  });
  const { window: win, $ } = await openPopup();
  assert.equal($('view-locked').hidden, false);
  assert.equal($('master').placeholder, 'Passyble password');
  assert.equal($('unlock-secret-key').hidden, false);
  assert.equal($('unlock-shared-row').hidden, false);
  assert.equal($('unlock-email').hidden, true);
  assert.equal($('unlock-approve').hidden, false);
  assert.equal($('unlock-alt').hidden, false);

  submit(win, $);
  await flush();
  assert.equal(sent('popup.unlock-password').length, 0);
  assert.equal($('unlock-msg').textContent, 'Enter your Passyble password.');

  $('master').value = 'wrong';
  $('unlock-secret-key').value = 'P1-AAAAA';
  submit(win, $);
  await flush();
  await flush();
  assert.equal($('unlock-msg').textContent, 'Wrong Passyble password or Secret Key. Is Caps Lock on?');
  assert.equal($('master').value, '');

  $('master').value = 'passyble pw';
  $('unlock-shared').checked = true;
  submit(win, $);
  await flush();
  await flush();
  assert.deepEqual(sent('popup.unlock-password').at(-1), { type: 'popup.unlock-password', password: 'passyble pw', secret_key: 'P1-AAAAA', shared: true });
  assert.equal($('unlock-secret-key').value, '', 'the Secret Key is not left in the field');
});

test('a linked vault whose Secret Key is kept: only the password; the background may still ask for the key or the address', async () => {
  let ask = 'secret_key_needed';
  browserVault({
    linked: { account: 'acc_demo', email: '', secret_key_needed: false, email_needed: false },
    unlock: () => ({ ok: false, error: { code: 'invalid_state', message: ask, reason: ask } }),
  });
  const { window: win, $ } = await openPopup();
  assert.equal($('unlock-secret-key').hidden, true);
  $('master').value = 'pw';
  submit(win, $);
  await flush();
  await flush();
  assert.deepEqual(sent('popup.unlock-password').at(-1), { type: 'popup.unlock-password', password: 'pw' });
  assert.equal($('unlock-secret-key').hidden, false);
  assert.equal($('unlock-msg').textContent, "Enter your Secret Key once in this browser. It's in your Emergency Kit.");
  ask = 'email_needed';
  $('master').value = 'pw';
  submit(win, $);
  await flush();
  await flush();
  assert.equal($('unlock-email').hidden, false);
  assert.equal($('unlock-msg').textContent, "Enter your account's e-mail address.");
});

test('"Approve from another device" opens the account page', async () => {
  browserVault({ linked: { account: 'acc_demo', email: 'demo@example.com', secret_key_needed: true, email_needed: false }, unlock: () => ({ ok: true, result: {} }) });
  const { $ } = await openPopup();
  $('unlock-approve').click();
  await flush();
  assert.deepEqual(opened, ['chrome-extension://pass-ext/src/account/account.html#approve']);
});

test('a browser vault with its own master password is unchanged', async () => {
  browserVault({ linked: null, unlock: () => ({ ok: true, result: { locked: false } }) });
  const { window: win, $ } = await openPopup();
  assert.equal($('master').placeholder, 'Master password');
  assert.equal($('unlock-secret-key').hidden, true);
  assert.equal($('unlock-email').hidden, true);
  assert.equal($('unlock-approve').hidden, true);
  $('master').value = 'master';
  submit(win, $);
  await flush();
  await flush();
  assert.deepEqual(sent('popup.unlock-password').at(-1), { type: 'popup.unlock-password', password: 'master' });
});
