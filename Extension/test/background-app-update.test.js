import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = [];
let agent = () => ({});
const tabsById = new Map([[1, { id: 1, url: 'https://github.com/login', active: true }]]);
const store = {};
let fetches = 0;
let onMessage;

before(async () => {
  globalThis.fetch = async () => { fetches++; throw new TypeError('Failed to fetch'); };
  globalThis.chrome = {
    runtime: {
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
      onInstalled: evt(), onStartup: evt(),
      sendMessage: async () => undefined,
    },
    alarms: { create: async () => {}, onAlarm: { addListener: () => {} } },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [...tabsById.values()],
      get: async (id) => tabsById.get(id),
      sendMessage: async () => ({ ok: true }),
    },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, onClicked: evt() },
    commands: { onCommand: evt() },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {} },
    scripting: { executeScript: async () => [] },
    storage: {
      local: {
        get: async (key) => (typeof key === 'string' ? (Object.hasOwn(store, key) ? { [key]: store[key] } : {}) : {}),
        set: async (o) => { Object.assign(store, o); },
      },
      sync: { get: async () => ({}), set: async () => {} },
      onChanged: evt(),
      session: { set: async () => {}, get: async () => ({}), remove: async () => {} },
    },
  };
  await import('../src/background.js');
  for (let i = 0; i < 100 && !store.appVersionsTried; i++) await new Promise((r) => setTimeout(r, 5));
});

function send(msg, sender) {
  return new Promise((resolve) => {
    const async = onMessage(msg, { id: 'pass-ext', ...sender }, resolve);
    if (!async) resolve(undefined);
  });
}

const contentSender = { tab: tabsById.get(1), frameId: 0, url: 'https://github.com/login', origin: 'https://github.com' };
const popupSender = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const APP_REFUSED = { __error: { code: 'update_required', message: 'Update the Passyble app to keep filling' } };

test('this extension\'s check failed with nothing ever fetched: nothing is blocked', async () => {
  assert.equal(fetches, 1);
  assert.equal(store.appVersionGate.required, false);
  agent = (m) => (m === 'logins.find' ? { items: [], pending_otp: null } : {});
  const res = await send({ type: 'logins.find' }, contentSender);
  assert.equal(res.ok, true);
  const state = await send({ type: 'update.state' }, popupSender);
  assert.equal(state.result.required, false);
  assert.equal(state.result.recommended, false);
});

test('the desktop app\'s update_required reaches the page with its code (and no extension reason)', async () => {
  agent = (m) => (m === 'status' ? { locked: false, update_required: true, features: [] } : APP_REFUSED);
  for (const msg of [{ type: 'logins.find' }, { type: 'logins.fill', id: 'gh' }, { type: 'passkey.find', options: { rpId: 'github.com' } }]) {
    const res = await send(msg, contentSender);
    assert.equal(res.ok, false, msg.type);
    assert.equal(res.error.code, 'update_required', msg.type);
    assert.equal(res.error.reason, undefined, msg.type);
  }
});

test('popup.state while the desktop app is read-only: the read-only vault, no logins.find', async () => {
  agent = (m) => (m === 'status' ? { locked: false, soft_locked: false, update_required: true, features: ['logins.search', 'unlock.inline'] } : APP_REFUSED);
  const before = calls.length;
  const res = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(res.ok, true);
  assert.equal(res.result.read_only, 'app');
  assert.deepEqual(res.result.items, []);
  assert.equal(res.result.can_search, true);
  assert.deepEqual(calls.slice(before).map((c) => c[0]), ['status']);
  agent = (m) => (m === 'status' ? { locked: false, features: [] } : m === 'logins.find' ? { items: [{ id: 'gh', title: 'GitHub' }], pending_otp: null } : {});
  const normal = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(normal.result.read_only, undefined);
  assert.equal(normal.result.items.length, 1);
});

test('the "new version" banner: dismissed per recommended version, back when the owner raises it', async () => {
  const startup = () => globalThis.chrome.runtime.onStartup.fns.forEach((f) => f());
  const settle = async (want) => {
    for (let i = 0; i < 100; i++) {
      const s = await send({ type: 'update.state' }, popupSender);
      if (s.result.recommended_version === want) return s.result;
      await new Promise((r) => setTimeout(r, 5));
    }
    throw new Error(`no gate for ${want}`);
  };
  // An answer cached before (the fetch keeps failing here): 0.3.0 recommended, no minimum.
  store.appVersionsCache = { at: 1, data: { v: 1, platforms: { 'extension-chrome': { minimum: null, recommended: '0.3.0' } } } };
  startup();
  let state = await settle('0.3.0');
  assert.equal(state.required, false);
  assert.equal(state.recommended, true);
  assert.deepEqual(await send({ type: 'update.dismiss' }, popupSender), { ok: true, result: { dismissed: true } });
  state = await settle('0.3.0');
  assert.equal(state.recommended, false, 'dismissed for 0.3.0');
  assert.equal(store.appVersionDismissed, '0.3.0');
  store.appVersionsCache = { at: 2, data: { v: 1, platforms: { 'extension-chrome': { recommended: '0.4.0' } } } };
  startup();
  state = await settle('0.4.0');
  assert.equal(state.recommended, true, 'shows again for 0.4.0');
});
