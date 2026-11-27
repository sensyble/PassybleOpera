import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
const clipboard = [];

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  Object.defineProperty(globalThis, 'navigator', {
    value: { clipboard: { writeText: async (t) => { clipboard.push(t); } } }, configurable: true,
  });
  messages.length = 0;
  clipboard.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }] },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

const SOFT = {
  url: 'https://github.com/login', supported: true, locked: true, soft_locked: true,
  items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }],
  pending_otp: null, can_edit: true, can_search: true, can_icons: false,
};

test('soft-locked: the list stays with the lock in the header; nothing asks to unlock on its own', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: SOFT } : { ok: true, result: null });
  const { $, window } = await openPopup();
  assert.equal($('view-list').hidden, false, 'the list, not the locked view');
  assert.equal($('view-locked').hidden, true);
  assert.equal($('lock-btn').title, 'Locked. Click to unlock');
  const rows = [...window.document.querySelectorAll('#list li.item')];
  assert.equal(rows.length, 1);
  assert.match(rows[0].textContent, /GitHub/);
  assert.match(rows[0].textContent, /octo/);
  const pill = rows[0].querySelector('.otp');
  assert.ok(pill.classList.contains('locked'), 'the 2FA pill waits for an unlock');
  assert.match(pill.textContent, /2FA/);
  await flush();
  for (const type of ['popup.totp', 'popup.unlock', 'popup.copy', 'popup.fill']) {
    assert.equal(messages.filter((m) => m.type === type).length, 0, `${type} sent on its own`);
  }
});

test('soft-locked, older desktop app: the username copies from the list; password and 2FA go through the background', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.state') return { ok: true, result: SOFT };
    if (msg.type === 'popup.copy-item') return { ok: false, error: { code: 'not_supported', message: 'unknown method' } };
    if (msg.type === 'popup.copy') return { ok: true, result: { value: 'pw' } };
    if (msg.type === 'popup.totp') return { ok: true, result: { code: '123456', period: 30, remaining_secs: 20 } };
    return { ok: true, result: null };
  };
  const { window } = await openPopup();
  const row = window.document.querySelector('#list li.item');
  row.querySelector('button[title="Copy username"]').click();
  await flush();
  assert.deepEqual(clipboard, ['octo']);
  assert.equal(messages.filter((m) => m.type === 'popup.copy').length, 0, 'no unlock for the username');

  row.querySelector('button[title="Copy password"]').click();
  await flush();
  await flush();
  assert.deepEqual(messages.filter((m) => m.type === 'popup.copy').map((m) => m.field), ['password']);
  assert.equal(clipboard.at(-1), 'pw');

  row.querySelector('.otp').click();
  await flush();
  await flush();
  assert.equal(messages.filter((m) => m.type === 'popup.totp').length, 1);
  assert.equal(clipboard.at(-1), '123456');
});

test('soft-locked: the desktop app copies the password and the 2FA code itself; nothing secret comes to the popup', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.state') return { ok: true, result: SOFT };
    if (msg.type === 'popup.copy-item') return { ok: true, result: { copied: true, field: msg.field } };
    if (msg.type === 'popup.copy') return { ok: true, result: { value: 'pw' } };
    if (msg.type === 'popup.totp') return { ok: true, result: { code: '123456', period: 30, remaining_secs: 20 } };
    return { ok: true, result: null };
  };
  clipboard.length = 0;
  const { window } = await openPopup();
  const row = window.document.querySelector('#list li.item');
  row.querySelector('button[title="Copy password"]').click();
  await flush();
  await flush();
  row.querySelector('.otp').click();
  await flush();
  await flush();
  assert.deepEqual(messages.filter((m) => m.type === 'popup.copy-item').map((m) => [m.id, m.field, m.own, m.tabId]),
    [['gh', 'password', true, 1], ['gh', 'totp', true, 1]]);
  assert.equal(messages.filter((m) => m.type === 'popup.copy' || m.type === 'popup.totp').length, 0, 'no value asked for');
  assert.deepEqual(clipboard, [], "the browser's clipboard API is not used for secrets");
  assert.ok(!messages.some((m) => m.type === 'clipboard.copied'));
});

test('fully locked: the locked view, as before', async () => {
  reply = (msg) => (msg.type === 'popup.state'
    ? { ok: true, result: { url: 'https://github.com/login', supported: true, locked: true } }
    : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('view-locked').hidden, false);
  assert.equal($('view-list').hidden, true);
});

test('soft-locked: the header lock starts an unlock; Cancel goes back to the list with the lock still in the header', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: { ...SOFT, can_unlock_inline: true } }
    : msg.type === 'popup.unlock-options' ? { ok: true, result: { inline: true, locked: true, hello: false } }
      : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('view-list').hidden, false);
  assert.equal($('lock-btn').hidden, false, 'the lock in the header');
  $('lock-btn').click();
  await flush();
  assert.equal($('view-locked').hidden, false, 'the unlock form');
  assert.equal($('lock-btn').hidden, true, 'no header lock on the unlock form itself');
  assert.equal($('unlock-cancel').hidden, false);
  $('unlock-cancel').click();
  await flush();
  assert.equal($('view-list').hidden, false, 'back to the list');
  assert.equal($('lock-btn').hidden, false, 'the header lock is back');
  assert.ok($('lock-btn').classList.contains('locked'), 'the closed lock');
});
