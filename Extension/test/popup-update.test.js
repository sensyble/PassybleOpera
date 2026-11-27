import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
let closed = false;

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = dom.window;
  dom.window.close = () => { closed = true; };
  closed = false;
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const types = () => messages.map((m) => m.type);
const visibleView = ($) => ['update', 'readonly', 'list', 'locked', 'offline', 'loading'].filter((v) => !$(`view-${v}`).hidden);

const REQUIRED = { required: true, recommended: false, minimum: '0.2.0', recommended_version: null, version: '0.1.0',
  message: 'Security fix.\n<img src=x onerror="window.__pwned=1"> Please update.' };
const RESULTS = [
  { id: 'gl', title: 'GitLab', username: 'me@x.test', domain: 'gitlab.com', has_totp: true },
  { id: 'gt', title: 'Gitea', username: 'admin', domain: 'gitea.example', has_totp: false },
];
const READ_ONLY_STATE = { url: 'https://github.com/login', supported: true, locked: false, soft_locked: false, items: [], read_only: 'extension',
  can_edit: false, can_search: true, can_icons: false, can_unlock_inline: true };

const blockedReply = (extra = {}) => (msg) => {
  if (msg.type === 'update.state') return { ok: true, result: { ...REQUIRED, ...extra.update } };
  if (msg.type === 'popup.state') return { ok: true, result: { ...READ_ONLY_STATE, ...extra.state } };
  if (msg.type === 'popup.search') return { ok: true, result: { items: RESULTS, truncated: false } };
  if (msg.type === 'popup.copy-item') return { ok: true, result: { copied: true, field: msg.field } };
  if (msg.type === 'update.apply') return extra.apply ?? { ok: true, result: { store: 'https://chromewebstore.google.com/search/Passyble' } };
  return { ok: true, result: null };
};

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }], create: async () => ({}) },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('below the minimum: "Update required" first, with the owner\'s message as plain text, and no vault request', async () => {
  reply = blockedReply();
  const { $, window } = await openPopup();
  assert.deepEqual(visibleView($), ['update']);
  assert.equal($('view-update').querySelector('h2').textContent, 'Update required');
  assert.equal($('update-message').hidden, false);
  assert.equal($('update-message').textContent, REQUIRED.message);
  assert.equal($('update-message').children.length, 0, 'no markup from the server');
  assert.equal($('update-message').querySelector('img'), null);
  assert.equal(window.__pwned, undefined);
  assert.equal($('update-now').textContent.trim(), 'Update');
  assert.equal($('update-view').textContent.trim(), 'View my passwords');
  assert.deepEqual(types(), ['update.state'], 'popup.state (and its logins.find) not even asked');
});

test('no message from the owner: no empty box', async () => {
  reply = blockedReply({ update: { message: '' } });
  const { $ } = await openPopup();
  assert.equal($('update-message').hidden, true);
});

test('Update: the store page when the browser has no update yet (the popup closes)', async () => {
  reply = blockedReply();
  const { $ } = await openPopup();
  $('update-now').click();
  assert.equal($('update-msg').textContent, 'Checking for an update…');
  await flush();
  await flush();
  assert.ok(types().includes('update.apply'));
  assert.equal(closed, true);
});

test('Update: the browser installs the update (the extension restarts)', async () => {
  reply = blockedReply({ apply: { ok: true, result: { reloading: true } } });
  const { $ } = await openPopup();
  $('update-now').click();
  await flush();
  await flush();
  assert.equal($('update-msg').textContent, 'Installing the update…');
  assert.equal($('update-now').disabled, true);
});

test('View my passwords: the read-only vault, search and copy only, a persistent read-only line', async () => {
  reply = blockedReply();
  const { $ } = await openPopup();
  $('update-view').click();
  await flush();
  await flush();
  assert.deepEqual(visibleView($), ['readonly']);
  assert.match($('ro-note-text').textContent, /read-only until you update it/);
  assert.equal($('ro-back').hidden, false);
  assert.equal($('ro-msg').textContent, 'Type at least 2 characters to find a login.');
  $('ro-search').value = 'git';
  $('ro-search').dispatchEvent(new globalThis.Event('input'));
  await wait(320);
  await flush();
  assert.deepEqual(messages.filter((m) => m.type === 'popup.search'), [{ type: 'popup.search', query: 'git' }]);
  const rows = [...$('ro-list').children];
  assert.deepEqual(rows.map((r) => r.dataset.id), ['gl', 'gt']);
  const labels = (r) => [...r.querySelectorAll('.icon-btn')].map((b) => b.title);
  assert.deepEqual(labels(rows[0]), ['Copy username', 'Copy password', 'Copy 2FA code']);
  assert.deepEqual(labels(rows[1]), ['Copy username', 'Copy password']);
  assert.equal(rows[0].querySelector('.item-main').title, 'Copy password', 'the row copies, never fills');
  // Nothing that fills, edits, adds, deletes or saves anywhere in the view.
  assert.equal($('view-readonly').querySelector('.more, [aria-haspopup="menu"]'), null, 'no ⋯ menu (Edit, Open in Passyble)');
  assert.ok(!/Fill|Edit|Delete|Add login|Save/.test($('view-readonly').textContent), $('view-readonly').textContent);
  // Copies are made by the desktop app.
  rows[0].querySelector('.item-main').click();
  await flush();
  [...rows[0].querySelectorAll('.icon-btn')].find((b) => b.title === 'Copy 2FA code').click();
  await flush();
  [...rows[1].querySelectorAll('.icon-btn')].find((b) => b.title === 'Copy username').click();
  await flush();
  assert.deepEqual(messages.filter((m) => m.type === 'popup.copy-item').map((m) => [m.id, m.field]),
    [['gl', 'password'], ['gl', 'totp'], ['gt', 'username']]);
  assert.match($('snack').textContent, /copied/i);
  for (const type of ['popup.fill', 'popup.fill-cross', 'popup.edit-get', 'popup.edit-save', 'popup.copy', 'popup.totp']) {
    assert.ok(!types().includes(type), type);
  }
});

test('the read-only vault: Back (and Esc) return to the Update screen', async () => {
  reply = blockedReply();
  const { $, window } = await openPopup();
  $('update-view').click();
  await flush();
  await flush();
  assert.deepEqual(visibleView($), ['readonly']);
  $('ro-back').click();
  assert.deepEqual(visibleView($), ['update']);
  $('update-view').click();
  await flush();
  await flush();
  window.document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape' }));
  assert.deepEqual(visibleView($), ['update']);
});

test('the read-only vault while locked: the unlock form first, then the vault', async () => {
  let locked = true;
  reply = (msg) => {
    if (msg.type === 'popup.state') return { ok: true, result: locked ? { url: 'https://github.com/login', supported: true, locked: true, read_only: 'extension', can_unlock_inline: true } : READ_ONLY_STATE };
    if (msg.type === 'popup.unlock-password') { locked = false; return { ok: true, result: { locked: false } }; }
    return blockedReply()(msg);
  };
  const { $ } = await openPopup();
  $('update-view').click();
  await flush();
  await flush();
  assert.deepEqual(visibleView($), ['locked']);
  $('master').value = 'correct horse';
  $('unlock-form').dispatchEvent(new globalThis.Event('submit', { cancelable: true }));
  await flush();
  await flush();
  await flush();
  assert.deepEqual(visibleView($), ['readonly']);
});

test('the desktop app read-only (its own minimum): the same vault, "Update the Passyble app to keep filling.", no Back', async () => {
  reply = (msg) => {
    if (msg.type === 'update.state') return { ok: true, result: { required: false, recommended: false, message: '' } };
    if (msg.type === 'popup.state') return { ok: true, result: { ...READ_ONLY_STATE, read_only: 'app' } };
    return blockedReply()(msg);
  };
  const { $ } = await openPopup();
  assert.deepEqual(visibleView($), ['readonly']);
  assert.equal($('ro-note-text').textContent, 'Update the Passyble app to keep filling.');
  assert.equal($('ro-back').hidden, true);
  assert.equal($('update-tip').hidden, true);
});

test('below the recommended version: a banner over the list; closing it is remembered by the background', async () => {
  reply = (msg) => {
    if (msg.type === 'update.state') return { ok: true, result: { required: false, recommended: true, recommended_version: '0.3.0', message: '' } };
    if (msg.type === 'popup.state') return { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, items: [], can_search: true } };
    return { ok: true, result: null };
  };
  const { $ } = await openPopup();
  assert.deepEqual(visibleView($), ['list']);
  assert.equal($('update-tip').hidden, false);
  assert.equal($('update-tip').textContent.includes('A new version of Passyble is available.'), true);
  $('update-tip-close').click();
  await flush();
  assert.equal($('update-tip').hidden, true);
  assert.ok(types().includes('update.dismiss'));
  reply = (msg) => {
    if (msg.type === 'update.state') return { ok: true, result: { required: false, recommended: true, recommended_version: '0.4.0', message: '' } };
    if (msg.type === 'popup.state') return { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, items: [], can_search: true } };
    if (msg.type === 'update.apply') return { ok: true, result: { store: 'https://addons.mozilla.org/firefox/addon/passyble/' } };
    return { ok: true, result: null };
  };
  const again = await openPopup();
  assert.equal(again.$('update-tip').hidden, false, 'a raised recommended version shows again');
  again.$('update-tip-now').click();
  await flush();
  await flush();
  assert.ok(types().includes('update.apply'));
  assert.equal(closed, true);
});

test('no update information (an older background, an error): the popup as usual', async () => {
  reply = (msg) => {
    if (msg.type === 'update.state') return { ok: false, error: { code: 'internal', message: 'x' } };
    if (msg.type === 'popup.state') return { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, items: [], can_search: true } };
    return { ok: true, result: null };
  };
  const { $ } = await openPopup();
  assert.deepEqual(visibleView($), ['list']);
  assert.equal($('update-tip').hidden, true);
});
