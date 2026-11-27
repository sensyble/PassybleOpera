// "Sync now" (`popup.sync`, the `sync-now` shortcut): app mode asks the desktop app's `sync.now` once however many
// ask at the same time; browser mode without the shared vaults' WebAssembly has nothing that syncs. Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';

globalThis.__passFakeWasm = true;

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: (f) => { const i = fns.indexOf(f); if (i >= 0) fns.splice(i, 1); }, fns };
};

const local = {};
const session = {};
const notices = [];
// `answer(msg)`: `{ result }` or `{ error }` for one request, or a Promise of one.
const native = { answer: null, requests: [] };
let onMessage;
let onCommand;

function nativePort() {
  const port = { onMessage: evt(), onDisconnect: evt(), disconnect() {} };
  port.postMessage = (msg) => queueMicrotask(async () => {
    native.requests.push(msg);
    const out = await native.answer(msg);
    port.onMessage.fns.forEach((f) => f({ id: msg.id, ...out }));
  });
  return port;
}

let syncAnswer = () => ({ result: { synced: 2, failed: [], no_sync: false } });
function appAnswers(msg) {
  if (msg.method === 'status') return { result: { locked: false, version: '1.4', features: ['edit'] } };
  if (msg.method === 'logins.find') return { result: { items: [] } };
  if (msg.method === 'sync.now') return syncAnswer(msg);
  return { result: {} };
}

before(async () => {
  const onChanged = evt();
  onCommand = evt();
  globalThis.fetch = async () => { throw new TypeError('offline'); };
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext', lastError: undefined,
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      connectNative: () => nativePort(),
      onMessage: { addListener: (f) => { onMessage = f; } },
      onConnect: evt(),
      onInstalled: evt(), onStartup: evt(),
      sendMessage: async () => undefined,
    },
    offscreen: { createDocument: async () => {}, closeDocument: async () => {} },
    alarms: { create: async () => {}, clear: async () => true, onAlarm: evt() },
    idle: { onStateChanged: evt() },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [{ id: 1, url: 'https://github.com/login', active: true, windowId: 5 }],
      get: async () => ({ id: 1, url: 'https://github.com/login', active: true, windowId: 5 }),
      sendMessage: async (tabId, msg) => { if (msg?.type === 'cmd.notice') notices.push([tabId, msg.text]); return { ok: true }; },
      create: async () => ({ id: 9 }),
    },
    windows: { get: async () => ({ left: 0, top: 0, width: 1200, height: 800 }), create: async () => ({ id: 9 }), getAll: async () => [{ id: 5 }], onRemoved: evt() },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, update: () => {}, onClicked: evt() },
    commands: { onCommand },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {}, openPopup: async () => { throw new Error('not here'); } },
    scripting: { executeScript: async () => [] },
    storage: {
      local: {
        get: async (keys) => {
          if (keys == null) return { ...local };
          if (typeof keys === 'string') return keys in local ? { [keys]: local[keys] } : {};
          if (Array.isArray(keys)) return Object.fromEntries(keys.filter((k) => k in local).map((k) => [k, local[k]]));
          return Object.fromEntries(Object.entries(keys).map(([k, d]) => [k, k in local ? local[k] : d]));
        },
        set: async (o) => {
          const changes = Object.fromEntries(Object.entries(o).map(([k, v]) => [k, { oldValue: local[k], newValue: v }]));
          Object.assign(local, structuredClone(o));
          onChanged.fns.forEach((f) => f(changes, 'local'));
        },
        remove: async (k) => { for (const key of [k].flat()) delete local[key]; },
      },
      sync: { get: async () => ({}), set: async () => {} },
      session: {
        setAccessLevel: async () => {},
        get: async (k) => (typeof k === 'string' ? (k in session ? { [k]: structuredClone(session[k]) } : {}) : { ...session }),
        set: async (o) => { Object.assign(session, structuredClone(o)); },
        remove: async (k) => { for (const key of [k].flat()) delete session[key]; },
      },
      onChanged,
    },
  };
  local.vaultMode = 'app';
  native.answer = appAnswers;
  await import('../src/background.js');
});

const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async (n = 12) => { for (let i = 0; i < n; i++) await tick(); };
const POPUP = { id: 'pass-ext', url: 'chrome-extension://pass-ext/src/popup/popup.html' };

function send(msg) {
  return new Promise((resolve) => {
    const async = onMessage(msg, POPUP, resolve);
    if (!async) resolve(undefined);
  });
}
const sent = (method) => native.requests.filter((r) => r.method === method);
const later = (ms) => new Promise((r) => setTimeout(r, ms));

test('app mode: the desktop app\'s sync.now with params {}, its answer checked', async () => {
  syncAnswer = () => ({ result: { synced: 2, failed: [{ vault: 'Work', reason: 'WebDAV server not reachable' }], no_sync: false, extra: 1 } });
  const res = await send({ type: 'popup.sync' });
  assert.equal(res.ok, true, JSON.stringify(res.error));
  assert.deepEqual(res.result, { synced: 2, failed: [{ vault: 'Work', reason: 'WebDAV server not reachable' }], no_sync: false, browser: false });
  assert.deepEqual(sent('sync.now').map((r) => r.params), [{}]);
});

test('app mode: never two syncs at once (the popup and the shortcut together get the same one)', async () => {
  await later(3_100); // past the moment a finished sync answers again
  native.requests.length = 0;
  notices.length = 0;
  let release;
  syncAnswer = () => new Promise((r) => { release = () => r({ result: { synced: 3, failed: [], no_sync: false } }); });
  const a = send({ type: 'popup.sync' });
  await settle();
  onCommand.fns.forEach((f) => f('sync-now', { id: 1, url: 'https://github.com/login', windowId: 5 }));
  const b = send({ type: 'popup.sync' });
  await settle();
  assert.equal(sent('sync.now').length, 1);
  release();
  const [ra, rb] = await Promise.all([a, b]);
  assert.equal(ra.result.synced, 3);
  assert.deepEqual(ra.result, rb.result);
  await settle(20);
  assert.equal(sent('sync.now').length, 1);
  assert.deepEqual(notices, [[1, 'Synced just now']], 'the shortcut\'s notice in the page');
});

test('app mode: an older desktop app ("unknown method") is needs_update; locked comes back as locked', async () => {
  await later(3_100);
  syncAnswer = () => ({ error: { code: 'invalid_params', message: 'unknown method sync.now' } });
  let res = await send({ type: 'popup.sync' });
  assert.equal(res.ok, false);
  assert.equal(res.error.code, 'not_supported');
  assert.equal(res.error.reason, 'needs_update');

  syncAnswer = () => ({ error: { code: 'locked', message: 'Vault is locked' } });
  res = await send({ type: 'popup.sync' });
  assert.equal(res.error.code, 'locked', 'errors are not kept: asked again');

  syncAnswer = () => ({ result: { synced: 0, failed: [], no_sync: true } });
  res = await send({ type: 'popup.sync' });
  assert.deepEqual(res.result, { synced: 0, failed: [], no_sync: true, browser: false });
});

test('browser mode without the shared vaults\' WebAssembly: no Sync button, nothing that syncs, no request to the app', async () => {
  await later(3_100);
  await chrome.storage.local.set({ vaultMode: 'browser' });
  await settle(20);
  native.requests.length = 0;
  const res = await send({ type: 'popup.sync' });
  assert.equal(res.ok, true, JSON.stringify(res.error));
  assert.deepEqual(res.result, { synced: 0, failed: [], no_sync: true, browser: true });
  assert.equal(sent('sync.now').length, 0);
  local.vaultHostSeen = 'missing'; // no Passyble app on this computer: a vault may be made here
  const created = await send({ type: 'vault.create', password: 'orbit candle meadow 42' });
  assert.equal(created.ok, true, JSON.stringify(created.error));
  const state = await send({ type: 'popup.state', tabId: 1 });
  assert.equal(state.ok, true, JSON.stringify(state.error));
  assert.equal(state.result.browser, true);
  assert.equal(state.result.can_sync, false, 'the popup shows no Sync button');
  assert.deepEqual((await send({ type: 'popup.sync' })).result, { synced: 0, failed: [], no_sync: true, browser: true });
  // Pins name the shared vaults opened here (background/teams/), so the agent in this browser keeps them.
  const pins = await send({ type: 'popup.set-pins', ids: ['v-team', 'v-home'], known: ['v-team', 'v-family'] });
  assert.equal(pins.ok, true, JSON.stringify(pins.error));
  assert.deepEqual(pins.result, { pins: ['v-team', 'v-home'], max: 5, known: ['v-team', 'v-family'] });
  assert.equal((await send({ type: 'popup.set-pins', ids: ['v-team'], known: 'v-team' })).error.code, 'invalid_params');
  assert.equal(sent('vaults.set_pins').length, 0, 'nothing to the Passyble app');
});
