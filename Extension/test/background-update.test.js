// Forced update: below its minimum version the extension is read-only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({});
const tabsById = new Map([[1, { id: 1, url: 'https://github.com/login', active: true }]]);
const tabMessages = [];
const tabsCreated = [];
const fetches = [];
const store = {};
let onMessage;
let reloads = 0;
const runtime = {
  id: 'pass-ext', lastError: undefined,
  getURL: (p) => `chrome-extension://pass-ext/${p}`,
  getManifest: () => ({ manifest_version: 3, version: '0.1.0' }),
  connectNative: () => {
    const port = { onMessage: evt(), onDisconnect: evt() };
    port.postMessage = (msg) => {
      calls.push([msg.method, msg.params]);
      queueMicrotask(async () => {
        const out = await agent(msg.method, msg.params);
        port.onMessage.fns.forEach((f) => f(out && out.__error ? { id: msg.id, error: out.__error } : { id: msg.id, result: out }));
      });
    };
    port.disconnect = () => {};
    return port;
  },
  onMessage: { addListener: (f) => { onMessage = f; } },
  onInstalled: evt(), onStartup: evt(), onUpdateAvailable: evt(),
  sendMessage: async () => undefined,
  requestUpdateCheck: async () => ({ status: 'update_available', version: '0.2.0' }),
  reload: () => { reloads++; },
};
const commands = evt();
const contextClicks = evt();

before(async () => {
  globalThis.fetch = async (url, init) => {
    fetches.push([url, init]);
    return { ok: true, status: 200, text: async () => JSON.stringify({ v: 1, platforms: {
      'extension-chrome': { minimum: '0.2.0', recommended: '0.2.0', message: 'This version has a security problem. <b>Update</b> now.' },
      'extension-firefox': { minimum: null },
    } }) };
  };
  globalThis.chrome = {
    runtime,
    alarms: { create: async () => {}, get: async () => undefined, onAlarm: { addListener: () => {} } },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [...tabsById.values()],
      get: async (id) => tabsById.get(id),
      sendMessage: async (tabId, msg, opts) => { tabMessages.push([tabId, msg, opts]); return { ok: true }; },
      create: async (o) => { tabsCreated.push(o.url); return {}; },
    },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, update: () => {}, onClicked: contextClicks },
    commands: { onCommand: commands },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {} },
    scripting: { executeScript: async () => [] },
    storage: {
      local: {
        get: async (key) => {
          if (typeof key === 'string') return Object.hasOwn(store, key) ? { [key]: structuredClone(store[key]) } : {};
          if (Array.isArray(key)) return Object.fromEntries(key.filter((k) => Object.hasOwn(store, k)).map((k) => [k, structuredClone(store[k])]));
          if (key && typeof key === 'object') return Object.fromEntries(Object.entries(key).map(([k, d]) => [k, Object.hasOwn(store, k) ? structuredClone(store[k]) : d]));
          return structuredClone(store);
        },
        set: async (o) => { Object.assign(store, structuredClone(o)); },
        remove: async (k) => { delete store[k]; },
      },
      sync: { get: async () => ({}), set: async () => {} },
      onChanged: evt(),
      session: { set: async () => {}, get: async () => ({}), remove: async () => {} },
    },
  };
  await import('../src/background.js');
  // The background's start: the check (stubbed fetch) decides the gate.
  for (let i = 0; i < 100 && store.appVersionGate?.required !== true; i++) await new Promise((r) => setTimeout(r, 5));
});

function send(msg, sender) {
  return new Promise((resolve) => {
    const async = onMessage(msg, { id: 'pass-ext', ...sender }, resolve);
    if (!async) resolve(undefined);
  });
}

const contentSender = (url = 'https://github.com/login') => ({ tab: tabsById.get(1), frameId: 0, url, origin: new URL(url).origin });
const popupSender = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const UPDATE_REQUIRED = { code: 'update_required', message: 'Update the Passyble extension to keep filling', reason: 'extension_update' };

test('the version check ran once, without anything that identifies the user, and the gate is stored for this version', () => {
  assert.equal(fetches.length, 1);
  const [url, init] = fetches[0];
  assert.equal(url, 'https://account.passyble.com/api/app-versions');
  assert.equal(init.credentials, 'omit');
  assert.equal(init.referrerPolicy, 'no-referrer');
  assert.equal(init.headers, undefined);
  assert.equal(store.appVersionGate.required, true);
  assert.equal(store.appVersionGate.version, '0.1.0');
  assert.equal(store.appVersionGate.platform, 'extension-chrome', 'Node is no Edge, Opera or Firefox');
});

test('content scripts: fills, saves, 2FA codes and passkeys are refused before the agent', async () => {
  agent = () => ({ items: [], locked: false, soft_locked: false, features: [] });
  const before = calls.length;
  for (const msg of [
    { type: 'logins.find' }, { type: 'logins.fill', id: 'gh' }, { type: 'totp.get', id: 'gh' }, { type: 'save.capture', username: 'u', password: 'p' },
    { type: 'save.query' }, { type: 'draft.save', username: 'u', password: 'p' }, { type: 'cards.fill', id: 'c' }, { type: 'otp.context' },
    { type: 'passkey.get', options: { challenge: 'AQID' } }, { type: 'passkey.create', options: {} }, { type: 'passkey.find', options: {} },
    { type: 'generate.email', kind: 'alias' }, { type: 'unlock.options' },
  ]) {
    const res = await send(msg, contentSender());
    assert.deepEqual(res, { ok: false, error: UPDATE_REQUIRED }, msg.type);
  }
  assert.equal(calls.length, before, 'nothing reached the agent');
});

test('the save banner\'s edit frame and the popup\'s fill and edit handlers are refused too', async () => {
  const before = calls.length;
  for (const msg of [
    { type: 'popup.fill', tabId: 1, id: 'gh' }, { type: 'popup.fill-cross', tabId: 1, id: 'gh' }, { type: 'popup.copy', tabId: 1, id: 'gh', field: 'password' },
    { type: 'popup.edit-get', tabId: 1, id: 'gh' }, { type: 'popup.edit-save', tabId: 1, item: {} }, { type: 'popup.edit-delete', tabId: 1, id: 'gh' },
    { type: 'save.edit-get', token: 't' }, { type: 'save.edit-set', token: 't' }, { type: 'popup.server-pair', link: 'pass.example.com' },
  ]) {
    const res = await send(msg, popupSender);
    assert.deepEqual(res, { ok: false, error: UPDATE_REQUIRED }, msg.type);
  }
  assert.equal(calls.length, before);
  assert.equal(tabMessages.length, 0, 'no fill command went to the page');
});

test('the popup still searches and copies: logins.search, logins.copy, a card number copy', async () => {
  agent = (m, p) => {
    if (m === 'logins.search') return { items: [{ id: 'gl', title: 'GitLab', username: 'me', domain: 'gitlab.com', has_totp: true }], truncated: false };
    if (m === 'logins.copy') return { copied: true, field: p.field };
    if (m === 'cards.fill') return { copied: true, field: p.field };
    return {};
  };
  const found = await send({ type: 'popup.search', query: 'git' }, popupSender);
  assert.equal(found.ok, true);
  assert.equal(found.result.items[0].id, 'gl');
  for (const field of ['username', 'password', 'totp']) {
    const res = await send({ type: 'popup.copy-item', tabId: 1, id: 'gl', field }, popupSender);
    assert.deepEqual(res, { ok: true, result: { copied: true, field } }, field);
  }
  assert.deepEqual(calls.filter((c) => c[0] === 'logins.copy').map((c) => c[1].field), ['username', 'password', 'totp']);
  const card = await send({ type: 'popup.card-copy', tabId: 1, id: 'c1', field: 'number' }, popupSender);
  assert.deepEqual(card, { ok: true, result: { copied: true } });
  assert.deepEqual(calls.find((c) => c[0] === 'cards.fill')[1], { url: 'https://github.com/login', id: 'c1', purpose: 'copy', field: 'number' });
  // An address copy fills nothing either, but goes through identities.fill, which a read-only Passyble refuses.
  assert.deepEqual(await send({ type: 'popup.identity-copy', tabId: 1, id: 'i1', field: 'email' }, popupSender), { ok: false, error: UPDATE_REQUIRED });
});

test('popup.state: the read-only vault (no site logins looked up), also on a page Passyble can\'t fill', async () => {
  agent = (m) => (m === 'status' ? { locked: false, soft_locked: false, features: ['logins.search', 'icons.get', 'unlock.inline', 'edit'] } : {});
  const before = calls.length;
  const res = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(res.ok, true);
  assert.equal(res.result.read_only, 'extension');
  assert.deepEqual(res.result.items, []);
  assert.equal(res.result.can_search, true);
  assert.equal(res.result.can_edit, false);
  assert.deepEqual(calls.slice(before).map((c) => c[0]), ['status'], 'no logins.find');
  tabsById.set(2, { id: 2, url: 'chrome://newtab/', active: false });
  const other = await send({ type: 'popup.state', tabId: 2 }, popupSender);
  assert.equal(other.result.read_only, 'extension');
});

test('update.state: required with the owner\'s message; the recommended banner never on top of it', async () => {
  const res = await send({ type: 'update.state' }, popupSender);
  assert.deepEqual(res, { ok: true, result: {
    required: true, recommended: false, minimum: '0.2.0', recommended_version: '0.2.0',
    message: 'This version has a security problem. <b>Update</b> now.', version: '0.1.0',
  } });
});

test('update.apply: the browser has the update, so the extension reloads (no store page)', async () => {
  const res = await send({ type: 'update.apply' }, popupSender);
  assert.deepEqual(res, { ok: true, result: { reloading: true } });
  // The reload waits until the browser has downloaded the update (runtime.onUpdateAvailable).
  await new Promise((r) => setTimeout(r, 80));
  assert.equal(reloads, 0);
  runtime.onUpdateAvailable.fns.forEach((f) => f({ version: '0.2.0' }));
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(reloads >= 1);
  assert.deepEqual(tabsCreated, []);
});

test('update.apply: no update in the store yet: the store page', async () => {
  runtime.requestUpdateCheck = async () => ({ status: 'no_update' });
  const res = await send({ type: 'update.apply' }, popupSender);
  assert.deepEqual(res, { ok: true, result: { store: 'https://chromewebstore.google.com/search/Passyble' } });
  assert.deepEqual(tabsCreated, ['https://chromewebstore.google.com/search/Passyble']);
});

test('keyboard commands and the context menu fill nothing', async () => {
  tabMessages.length = 0;
  for (const f of commands.fns) await f('fill-login', tabsById.get(1));
  for (const f of contextClicks.fns) await f({ menuItemId: 'pass-fill', frameId: 0 }, tabsById.get(1));
  for (const f of contextClicks.fns) await f({ menuItemId: 'pass-generate', frameId: 0 }, tabsById.get(1));
  await new Promise((r) => setTimeout(r, 10));
  assert.deepEqual(tabMessages, []);
});

test('the content script\'s harmless reports still get through (the in-page UI font, the right-click target)', async () => {
  const res = await send({ type: 'menu.target', password: false, username: false }, contentSender());
  assert.equal(res.ok, true);
});
