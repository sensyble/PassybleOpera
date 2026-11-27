// The popup's Sync now button (real popup.html + popup.js in jsdom): one `popup.sync` however often it is clicked.
// Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
const opened = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const ok = (result) => ({ ok: true, result });
const fail = (code, message = code, reason) => ({ ok: false, error: { code, message, ...(reason ? { reason } : {}) } });

const ITEMS = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false }];
const STATE = { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null, items: ITEMS,
  can_edit: true, can_notes: true, can_search: true };

function agent(overrides = {}, state = STATE) {
  return (msg) => {
    if (overrides[msg.type]) return overrides[msg.type](msg);
    switch (msg.type) {
      case 'popup.state': return ok(state);
      case 'popup.sync': return ok({ synced: 2, failed: [], no_sync: false, browser: false });
      default: return ok(null);
    }
  };
}

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = { close: () => {} };
  messages.length = 0;
  opened.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, document: dom.window.document, $ };
}

const flush = async (n = 12) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const sent = (type) => messages.filter((m) => m.type === type);
const visible = (node) => { for (let n = node; n; n = n.parentElement) if (n.hidden) return false; return true; };

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: {
      query: async () => [{ id: 1, windowId: 7, url: 'https://github.com/login' }],
      create: async (o) => { opened.push(o.url); return { id: 9 }; },
    },
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      sync: { get: async () => ({}), set: async () => {} },
    },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('the header button: Sync now on the list and the unlock card, also on a page Passyble cannot fill', async () => {
  reply = agent();
  const list = await openPopup();
  assert.ok(visible(list.$('sync-btn')));
  assert.equal(list.$('sync-btn').title, 'Sync now');
  assert.equal(list.$('sync-btn').getAttribute('aria-label'), 'Sync now');
  assert.equal(list.$('sync-btn').nextElementSibling, list.$('lock-btn'), 'before Lock');

  reply = agent({}, { url: 'https://github.com/login', supported: true, locked: true, can_unlock_inline: true, unlock_hello: false, ask_unlock: false });
  const locked = await openPopup();
  assert.equal(locked.$('view-locked').hidden, false);
  assert.ok(visible(locked.$('sync-btn')), 'on the unlock card too');

  reply = agent({}, { url: 'chrome://newtab/', supported: false });
  const notWeb = await openPopup();
  assert.ok(visible(notWeb.$('sync-btn')));
});

test('no Sync button offline, without a vault, read-only, or in browser mode where nothing syncs', async () => {
  reply = agent({ 'popup.state': () => fail('agent_unavailable', 'The Passyble desktop app is not running') });
  const offline = await openPopup();
  assert.equal(offline.$('view-offline').hidden, false);
  assert.equal(visible(offline.$('sync-btn')), false);

  reply = agent({}, { url: 'https://github.com/login', supported: true, locked: true, no_vault: true, browser: true });
  const novault = await openPopup();
  assert.equal(visible(novault.$('sync-btn')), false);

  reply = agent({}, { ...STATE, read_only: 'app', items: [] });
  const readOnly = await openPopup();
  assert.equal(visible(readOnly.$('sync-btn')), false);

  reply = agent({}, { ...STATE, browser: true, local_only: true, can_sync: false });
  const browserNone = await openPopup();
  assert.equal(visible(browserNone.$('sync-btn')), false, 'the vault in this browser has no sync of its own');

  reply = agent({}, { ...STATE, browser: true, local_only: true, can_sync: true });
  const browserTeams = await openPopup();
  assert.ok(visible(browserTeams.$('sync-btn')), 'a build with the shared vaults of Teams and Family');
});

test('click: the icon turns while syncing, one popup.sync however often it is clicked, then "Synced just now"', async () => {
  let finish;
  reply = agent({ 'popup.sync': () => new Promise((r) => { finish = () => r(ok({ synced: 2, failed: [], no_sync: false, browser: false })); }) });
  const { $ } = await openPopup();
  $('sync-btn').click();
  await flush();
  $('sync-btn').click();
  $('sync-btn').click();
  await flush();
  assert.equal(sent('popup.sync').length, 1, 'never two at once');
  assert.ok($('sync-btn').classList.contains('busy'));
  assert.equal($('sync-btn').getAttribute('aria-busy'), 'true');
  assert.equal($('sync-btn').getAttribute('aria-label'), 'Syncing…');
  finish();
  await flush();
  assert.equal($('sync-btn').classList.contains('busy'), false);
  assert.equal($('sync-btn').hasAttribute('aria-busy'), false);
  assert.equal($('sync-btn').title, 'Sync now');
  assert.equal($('snack').textContent, 'Synced just now');
  assert.equal($('snack').getAttribute('role'), 'status');
  assert.deepEqual(sent('popup.sync')[0], { type: 'popup.sync' });

  // Usable again afterwards.
  $('sync-btn').click();
  await flush();
  finish();
  await flush();
  assert.equal(sent('popup.sync').length, 2);
});

test('after a sync: a vault that did not sync and why; an older desktop app; no vault that syncs yet', async () => {
  reply = agent({ 'popup.sync': () => ok({ synced: 1, failed: [{ vault: 'Family', reason: "Couldn't reach the server" }], no_sync: false }) });
  let p = await openPopup();
  p.$('sync-btn').click();
  await flush();
  assert.equal(p.$('snack').textContent, "Family didn't sync: Couldn't reach the server");

  reply = agent({ 'popup.sync': () => fail('not_supported', 'unknown method', 'needs_update') });
  p = await openPopup();
  p.$('sync-btn').click();
  await flush();
  assert.equal(p.$('snack').textContent, 'Update the Passyble app to sync from here');
  assert.equal(p.$('sync-btn').disabled, false, 'still usable');
  assert.ok(visible(p.$('sync-btn')));

  reply = agent({ 'popup.sync': () => ok({ synced: 0, failed: [], no_sync: true, browser: false }) });
  p = await openPopup();
  p.$('sync-btn').click();
  await flush();
  assert.equal(p.$('snack').textContent, 'No vault syncs yet. Set it up in the Passyble app.');
  assert.equal(p.$('snack').querySelector('button'), null);
});

test('browser mode, nothing syncs: the notice offers Set up sync (the setup guide)', async () => {
  reply = agent({ 'popup.sync': () => ok({ synced: 0, failed: [], no_sync: true, browser: true }) },
    { ...STATE, browser: true, local_only: true, can_sync: true });
  const { $ } = await openPopup();
  $('sync-btn').click();
  await flush();
  assert.match($('snack').textContent, /^No vault syncs yet: this vault is only in this browser\. Set up sync$/);
  $('snack').querySelector('button').click();
  await flush();
  assert.deepEqual(opened, ['chrome-extension://pass-ext/src/welcome/welcome.html#sync']);
});

test('locked meanwhile: the unlock form first, then the sync runs again', async () => {
  let locked = false;
  reply = agent({
    'popup.state': () => ok(locked
      ? { url: 'https://github.com/login', supported: true, locked: true, can_unlock_inline: true, unlock_hello: false, ask_unlock: false }
      : { ...STATE, can_unlock_inline: true }),
    'popup.sync': () => (locked ? fail('locked', 'Vault is locked') : ok({ synced: 1, failed: [], no_sync: false })),
    'popup.unlock-password': () => { locked = false; return ok({ locked: false }); },
  });
  const { $, window } = await openPopup();
  locked = true;
  $('sync-btn').click();
  await flush();
  assert.equal($('view-locked').hidden, false, 'the unlock form');
  $('master').value = 'demo master';
  $('unlock-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await flush(20);
  assert.equal(sent('popup.sync').length, 2);
  assert.equal($('snack').textContent, 'Synced just now');
});
