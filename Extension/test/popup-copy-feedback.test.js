// Copy feedback in the popup when the copy needs an unlock first: Windows Hello and "Open Passyble" may close the
// popup, so the background makes the copy (`then.copy`) and the popup only says how it went, never a second copy.
import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
let portListener = null;

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText: async () => {} } }, configurable: true });
  globalThis.window = { close: () => {} };
  globalThis.location = { search: '' };
  messages.length = 0;
  portListener = null;
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
      connect: () => ({ onMessage: { addListener: (f) => { portListener = f; } } }),
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

const ITEMS = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false }];
const SOFT = { url: 'https://github.com/login', supported: true, locked: true, soft_locked: true, can_unlock_inline: true,
  unlock_hello: true, ask_unlock: false, items: ITEMS, pending_otp: null, can_edit: true, can_search: true, can_icons: false };

/** A desktop app that copies by itself (`popup.copy-item`), locked until Windows Hello or its window. */
function app({ copy = { result: { copied: true } } } = {}) {
  let locked = true;
  reply = (msg) => {
    switch (msg.type) {
      case 'popup.state': return { ok: true, result: locked ? SOFT : { ...SOFT, locked: false, soft_locked: false } };
      case 'popup.copy-item':
        if (locked) return { ok: false, error: { code: 'locked', message: 'Vault is locked' } };
        return { ok: true, result: { copied: true } };
      case 'popup.unlock-hello':
      case 'popup.unlock':
        locked = false;
        return { ok: true, result: msg.then?.copy ? { locked: false, copy } : { locked: false } };
      default: return { ok: true, result: null };
    }
  };
}

async function copyPassword(window) {
  window.document.querySelector('#list li.item button[title="Copy password"]').click();
  await flush();
  await flush();
}

test('copy after Windows Hello: the background copies (then.copy), the popup says so, nothing is copied twice', async () => {
  app();
  const { $, window } = await openPopup();
  await copyPassword(window);
  assert.equal($('view-locked').hidden, false, 'the unlock form, for the copy');
  $('unlock-hello').click();
  for (let i = 0; i < 4; i++) await flush();
  const hello = sent('popup.unlock-hello');
  assert.equal(hello.length, 1);
  assert.deepEqual(hello[0].then, { copy: { type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'password', own: true } });
  assert.equal(hello[0].for, 'gh', 'the unlock is for that copy');
  assert.equal(sent('popup.copy-item').length, 1, 'only the first (locked) request: the background made the copy');
  assert.equal($('snack').textContent, 'Password copied by Passyble (clears in 45 s)');
});

test('copy after "Open Passyble": the same, through the desktop app\'s window', async () => {
  app();
  const { $, window } = await openPopup();
  await copyPassword(window);
  $('unlock-app').click();
  for (let i = 0; i < 4; i++) await flush();
  assert.deepEqual(sent('popup.unlock')[0].then, { copy: { type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'password', own: true } });
  assert.equal(sent('popup.copy-item').length, 1);
  assert.equal($('snack').textContent, 'Password copied by Passyble (clears in 45 s)');
});

test('a copy the background could not make after the unlock: its error, still no second copy', async () => {
  app({ copy: { error: { code: 'not_found', message: 'Not found' } } });
  const { $, window } = await openPopup();
  await copyPassword(window);
  $('unlock-hello').click();
  for (let i = 0; i < 4; i++) await flush();
  assert.equal(sent('popup.copy-item').length, 1);
  assert.notEqual($('snack').textContent, '');
  assert.ok(!/copied by Passyble/.test($('snack').textContent));
});

test('a popup that opens after the copy finished shows its outcome (feedback on the port)', async () => {
  app();
  const { $ } = await openPopup();
  assert.equal(typeof portListener, 'function', 'the popup listens on its port');
  portListener({ type: 'feedback', text: 'Password copied by Passyble (clears in 45 s)' });
  assert.equal($('snack').textContent, 'Password copied by Passyble (clears in 45 s)');
  portListener({ type: 'other', text: 'x' });
  assert.equal($('snack').textContent, 'Password copied by Passyble (clears in 45 s)', 'other messages are not notices');
});
