import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
const created = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
let closed = 0;
let runtimeListener = null;
let ports = 0;

async function openPopup({ search = '' } = {}) {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: `https://extension.test/${search}`, pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText: async () => {} } }, configurable: true });
  globalThis.window = { close: () => { closed += 1; } };
  globalThis.location = { search };
  messages.length = 0;
  created.length = 0;
  closed = 0;
  ports = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => { for (let i = 0; i < 5; i++) await flush(); };
const sent = (type) => messages.filter((m) => m.type === type);

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
      connect: ({ name }) => { if (name === 'passyble-popup') ports++; return { onDisconnect: { addListener() {} } }; },
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }], create: async (o) => { created.push(o); } },
    storage: { local: { get: async () => ({ browserAutofillOff: true }), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} },
      session: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

afterEach(() => {
  delete globalThis.window;
  delete globalThis.location;
});

const ITEMS = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false }];
const UNLOCKED = { url: 'https://github.com/login', supported: true, locked: false, soft_locked: false, items: ITEMS, pending_otp: null,
  can_edit: true, can_search: true, can_unlock_inline: true, browser: true, local_only: false, drive_needs_app: false, reminder: false,
  ask: null };
/** A vault kept only in this browser, the reminder due. */
const LOCAL = { ...UNLOCKED, local_only: true, reminder: true };
const WELCOME = 'chrome-extension://pass-ext/src/welcome/welcome.html';

test('no vault yet: Create a vault, Google Drive sync and Sign in, each in the setup guide', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: { url: 'https://github.com/login', supported: true, locked: true, no_vault: true, browser: true } } : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('view-novault').hidden, false);
  assert.equal($('view-locked').hidden, true);
  assert.equal(ports, 1, 'the popup tells the background it is open');
  assert.equal($('view-novault').querySelector('h2').textContent, 'No vault yet');
  assert.equal($('view-novault').querySelector('.state-lead').textContent, 'Create a vault in this browser, or use the Passyble app for Google Drive sync.');
  const buttons = [...$('view-novault').querySelectorAll('button')].filter((b) => !b.hidden).map((b) => b.textContent.trim());
  assert.deepEqual(buttons, ['Create a vault', 'Google Drive sync', 'Sign in']);
  $('novault-create').click();
  await settle();
  assert.deepEqual(created, [{ url: `${WELCOME}#create` }]);
  assert.equal(closed, 1);
  $('novault-drive').click();
  await settle();
  assert.equal(created[1].url, `${WELCOME}#sync`, 'Google Drive sync: "needs the Passyble app"');
  $('novault-signin').click();
  await settle();
  assert.equal(created[2].url, `${WELCOME}#browser`);
});

test('locked: the master password form, no Windows Hello and no "Open Passyble"; no reminder on the unlock screen', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.state') return { ok: true, result: { ...LOCAL, locked: true, items: undefined, unlock_hello: false } };
    if (msg.type === 'popup.unlock-password') return msg.password === 'master' ? { ok: true, result: { locked: false } } : { ok: false, error: { code: 'wrong_password', message: 'x' } };
    return { ok: true, result: null };
  };
  const { $, window } = await openPopup();
  assert.equal($('view-locked').hidden, false);
  assert.equal($('view-list').hidden, true, 'the reminder is part of the list, never of the unlock screen');
  assert.equal($('local-reminder').closest('#view-list'), $('view-list'));
  assert.equal($('unlock-form').hidden, false);
  assert.equal($('unlock-hello').hidden, true);
  assert.equal($('unlock-app').hidden, true, 'no Passyble app to open');
  assert.equal($('unlock-alt').hidden, true);
  assert.equal($('lock-btn').hidden, true, 'the unlock card says it: no lock in the header');
  $('master').value = 'wrong';
  $('unlock-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await settle();
  assert.match($('unlock-msg').textContent, /Wrong master password/);
});

test('unlocked, a vault kept only here: "This vault is only on this device" above the list; Set up sync opens the setup guide (#sync)', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: LOCAL } : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('view-list').hidden, false);
  assert.equal($('lock-btn').title, 'Lock Passyble');
  assert.ok($('lock-btn').querySelector('svg[data-icon="lockOpen"]'), 'unlocked: the open lock');
  assert.equal($('local-reminder').hidden, false);
  assert.equal($('local-reminder').querySelector('.local-reminder-title').textContent, 'This vault is only on this device');
  const buttons = [...$('local-reminder').querySelectorAll('.local-reminder-actions button')].map((b) => b.textContent.trim());
  assert.deepEqual(buttons, ['Set up sync', 'Not now'], 'export is in the text, not a third button');
  // Title only at first; the explanation is the (i) button's tooltip.
  const info = $('local-reminder-info');
  assert.equal(info.getAttribute('aria-label'), 'What this means');
  const tip = info.ownerDocument.getElementById(info.getAttribute('aria-describedby'));
  assert.equal(tip.getAttribute('role'), 'tooltip');
  assert.equal(tip.textContent,
    'If this device is lost, stolen, broken or reset, the passwords in this vault are gone for good. Turn on sync or backup (Google Drive is free), or export a backup copy regularly.');
  assert.equal(tip.hidden, true);
  info.dispatchEvent(new info.ownerDocument.defaultView.Event('focus'));
  assert.equal(tip.hidden, false);
  info.dispatchEvent(new info.ownerDocument.defaultView.Event('blur'));
  assert.equal(tip.hidden, true);
  assert.equal($('vault-foot').hidden, true);
  $('local-reminder-sync').click();
  await settle();
  assert.deepEqual(created, [{ url: `${WELCOME}#sync` }]);
  assert.equal(closed, 1);
  assert.equal(sent('vault.reminder-dismiss').length, 0, 'Set up sync dismisses nothing');
});

test('"Not now" hides the reminder at once and tells the background (30 days for this vault); nothing is blocked', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.state') return { ok: true, result: LOCAL };
    if (msg.type === 'vault.reminder-dismiss') return { ok: true, result: { local_only: true, drive_needs_app: false, reminder: false } };
    return { ok: true, result: null };
  };
  const { $ } = await openPopup();
  assert.equal($('local-reminder').hidden, false);
  assert.equal($('list').children.length, 1, 'the list is there under it');
  $('local-reminder-later').click();
  await settle();
  assert.equal($('local-reminder').hidden, true);
  assert.deepEqual(sent('vault.reminder-dismiss'), [{ type: 'vault.reminder-dismiss' }]);
  assert.equal(created.length, 0);
  assert.equal(closed, 0);
});

test('dismissed within 30 days (the background says reminder: false): no reminder', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: { ...LOCAL, reminder: false } } : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('local-reminder').hidden, true);
  assert.equal($('move-tip').hidden, true, 'browser mode: no move offer');
});

test('a vault record of the builds that synced Google Drive themselves: the "Google Drive sync needs the app" chip opens the setup guide (#sync)', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: { ...UNLOCKED, drive_needs_app: true } } : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('local-reminder').hidden, true, 'it has a Drive copy: the needs-app chip instead');
  assert.equal($('vault-foot').hidden, false);
  assert.equal($('drive-app-chip').textContent.trim(), 'Google Drive sync needs the app');
  assert.equal($('sync-chip'), null, 'no "Not synced" any more');
  $('drive-app-chip').click();
  await settle();
  assert.deepEqual(created, [{ url: `${WELCOME}#sync` }]);
  assert.equal(closed, 1);
});

test('the more menu in browser mode: "Google Drive sync" (the setup guide, #sync) instead of Passyble Server', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: UNLOCKED } : { ok: true, result: null });
  const { $ } = await openPopup();
  $('menu-btn').click();
  await settle();
  const items = [...globalThis.document.querySelectorAll('.popover .menu-item')];
  const labels = items.map((b) => b.textContent.trim());
  assert.equal(labels.at(-1), 'Google Drive sync', labels.join());
  assert.ok(!labels.some((l) => /Passyble Server|back ?up/i.test(l)), labels.join());
  const drive = items.find((b) => b.id === 'vault');
  assert.ok(drive, 'the item is "vault"');
  drive.click();
  await settle();
  assert.deepEqual(created, [{ url: `${WELCOME}#sync` }]);
  assert.equal(closed, 1);
});

test('nothing to remind: no reminder, no chip; the row menu has no "Open in Passyble"', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: UNLOCKED } : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('local-reminder').hidden, true);
  assert.equal($('vault-foot').hidden, true);
  assert.equal($('move-tip').hidden, true);
  const more = $('list').querySelector('button[aria-haspopup="menu"]');
  more.click();
  await settle();
  const labels = [...globalThis.document.querySelectorAll('.popover .menu-item')].map((b) => b.textContent.trim());
  assert.ok(labels.includes('Edit'), labels.join());
  assert.ok(!labels.some((l) => /Open in Passyble/.test(l)), labels.join());
});

test('"Confirm each fill" while the popup is open: the master password here, then back to the list', async () => {
  let asked = null;
  reply = (msg) => {
    switch (msg.type) {
      case 'popup.state': return { ok: true, result: UNLOCKED };
      case 'popup.ask-get': return { ok: true, result: asked };
      case 'popup.ask-answer':
        if (msg.password !== 'master') return { ok: false, error: { code: 'wrong_password', message: 'x' } };
        asked = null;
        return { ok: true, result: { done: true } };
      default: return { ok: true, result: null };
    }
  };
  const { $, window } = await openPopup();
  asked = { token: 't1', kind: 'verify', host: 'github.com' };
  runtimeListener({ type: 'vault.ask' });
  await settle();
  assert.equal($('view-ask').hidden, false);
  assert.equal($('ask-title').textContent, "Confirm it's you");
  assert.equal($('ask-text').textContent, 'github.com');
  assert.equal($('ask-password').hidden, false);
  $('ask-password').value = 'wrong';
  $('ask-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await settle();
  assert.match($('ask-msg').textContent, /Wrong master password/);
  assert.equal($('ask-password').value, '', 'cleared');
  $('ask-password').value = 'master';
  $('ask-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await settle();
  assert.deepEqual(sent('popup.ask-answer').at(-1), { type: 'popup.ask-answer', token: 't1', password: 'master' });
  assert.equal($('view-list').hidden, false, 'back to the list');
  assert.equal(closed, 0, 'the user opened this popup: it stays');
});

test('a card fill asked in the small window (?ask=1): yes fills, the window closes; Cancel cancels', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.ask-get') return { ok: true, result: { token: 't2', kind: 'card', host: 'shop.example.com', card: 'Visa •••• 4242' } };
    return { ok: true, result: { done: true } };
  };
  let { $, window } = await openPopup({ search: '?ask=1' });
  assert.equal($('view-ask').hidden, false);
  assert.equal($('ask-text').textContent, 'Fill Visa •••• 4242 on shop.example.com?');
  assert.equal($('ask-password').hidden, true, 'a yes, no password');
  assert.equal($('ask-submit').textContent.trim(), 'Fill');
  $('ask-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await settle();
  assert.deepEqual(sent('popup.ask-answer').at(-1), { type: 'popup.ask-answer', token: 't2', yes: true });
  assert.equal(closed, 1);

  ({ $, window } = await openPopup({ search: '?ask=1' }));
  $('ask-cancel').click();
  await settle();
  assert.deepEqual(sent('popup.ask-answer').at(-1), { type: 'popup.ask-answer', token: 't2', cancel: true });
  assert.equal(closed, 1);
});

test('the small window for an unlock (?ask=1): the master password form; Cancel tells the background', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.ask-get') return { ok: true, result: { token: 't3', kind: 'unlock' } };
    if (msg.type === 'popup.unlock-options') return { ok: true, result: { inline: true, locked: true, hello: false, browser: true } };
    return { ok: true, result: { locked: false } };
  };
  const { $, window } = await openPopup({ search: '?ask=1' });
  assert.equal($('view-locked').hidden, false);
  assert.equal($('unlock-app').hidden, true);
  assert.equal($('unlock-cancel').hidden, false);
  $('master').value = 'master';
  $('unlock-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await settle();
  assert.equal(sent('popup.unlock-password').length, 1);
  assert.equal(closed, 1, 'closed once unlocked');

  const again = await openPopup({ search: '?ask=1' });
  again.$('unlock-cancel').click();
  await settle();
  assert.deepEqual(sent('popup.ask-answer').at(-1), { type: 'popup.ask-answer', token: 't3', cancel: true });
  assert.equal(closed, 1);
});

test('app mode, no Passyble app for this browser: "Keep a vault in this browser" opens the setup guide there', async () => {
  reply = (msg) => (msg.type === 'popup.state'
    ? { ok: false, error: { code: 'agent_unavailable', message: 'Specified native messaging host not found.' } }
    : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('view-offline').hidden, false);
  assert.equal($('browser-vault').hidden, false);
  $('browser-vault').click();
  await settle();
  assert.deepEqual(created, [{ url: 'chrome-extension://pass-ext/src/welcome/welcome.html#browser' }]);
});

test('app mode, Passyble just not running: no browser vault offer', async () => {
  reply = (msg) => (msg.type === 'popup.state'
    ? { ok: false, error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } }
    : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('view-offline').hidden, false);
  assert.equal($('browser-vault').hidden, true);
});

test('app mode, just switched from the vault in this browser: "Move 23 items" once; Move opens Options, the close button is Not now', async () => {
  const APPMODE = { ...UNLOCKED, browser: undefined, local_only: undefined, reminder: undefined, };
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: { ...APPMODE, move_offer: { count: 23 } } } : { ok: true, result: null });
  let { $ } = await openPopup();
  assert.equal($('move-tip').hidden, false);
  assert.equal($('move-tip-text').textContent, 'Move 23 items from this browser into the Passyble app');
  $('move-tip-close').click();
  await settle();
  assert.equal($('move-tip').hidden, true);
  assert.equal(sent('vault.move-later').length, 1);
  // One item, or a count not known.
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: { ...APPMODE, move_offer: { count: 1 } } } : { ok: true, result: null });
  ({ $ } = await openPopup());
  assert.equal($('move-tip-text').textContent, 'Move 1 item from this browser into the Passyble app');
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: { ...APPMODE, move_offer: { count: null } } } : { ok: true, result: null });
  ({ $ } = await openPopup());
  assert.equal($('move-tip-text').textContent, 'Move the items in this browser into the Passyble app');
  $('move-tip-move').click();
  await settle();
  assert.equal(created.at(-1).url, 'chrome-extension://pass-ext/src/options/options.html#move');
  // No offer: no tip.
  reply = (msg) => (msg.type === 'popup.state' ? { ok: true, result: APPMODE } : { ok: true, result: null });
  ({ $ } = await openPopup());
  assert.equal($('move-tip').hidden, true);
});
