// The setup guide opens once, on a new install. Firefox reports 'install' for each load of a
// temporary add-on.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const created = [];
const injected = [];
const stored = {};
let onInstalled;

before(async () => {
  onInstalled = evt();
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext', lastError: undefined,
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      connectNative: () => ({ onMessage: evt(), onDisconnect: evt(), postMessage: () => {}, disconnect: () => {} }),
      onMessage: { addListener: () => {} },
      onInstalled, onStartup: evt(),
      sendMessage: async () => undefined,
    },
    alarms: { create: async () => {}, onAlarm: evt() },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [{ id: 3, url: 'https://example.com/' }],
      get: async () => ({ id: 3, url: 'https://example.com/' }),
      sendMessage: async () => ({ ok: true }),
      create: async (o) => { created.push(o); return { id: 9, ...o }; },
    },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, update: () => {}, onClicked: evt() },
    commands: { onCommand: evt() },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {} },
    scripting: { executeScript: async (o) => { injected.push(o.target.tabId); return []; } },
    storage: {
      local: {
        get: async (defaults) => ({ ...defaults, ...stored }),
        set: async (o) => { Object.assign(stored, o); },
        remove: async (keys) => { for (const k of [keys].flat()) delete stored[k]; },
      },
      sync: { get: async () => ({}), set: async () => {} },
      onChanged: evt(),
      session: { get: async () => ({}), set: async () => {}, remove: async () => {} },
    },
  };
  await import('../src/background.js');
});

async function install(details) {
  created.length = 0;
  injected.length = 0;
  for (const f of onInstalled.fns) await f(details);
  await new Promise((r) => setTimeout(r, 0));
}

test('a new install opens the setup guide in a tab, once', async () => {
  await install({ reason: 'install' });
  assert.deepEqual(created, [{ url: 'chrome-extension://pass-ext/src/welcome/welcome.html' }]);
  assert.ok(injected.includes(3), 'content scripts still go into open tabs');
  assert.equal(stored.welcomeShown, true);
});

test('Firefox reports install again on each temporary load: no second tab', async () => {
  await install({ reason: 'install', temporary: true });
  assert.deepEqual(created, []);
  assert.ok(injected.includes(3), 'content scripts are injected again');
});

test('an update, a browser update or a shared module update opens nothing', async () => {
  for (const reason of ['update', 'chrome_update', 'browser_update', 'shared_module_update']) {
    await install({ reason, previousVersion: '0.0.9' });
    assert.deepEqual(created, [], reason);
    assert.ok(injected.includes(3), `${reason}: content scripts are injected again`);
  }
  await install(undefined);
  assert.deepEqual(created, [], 'no details: nothing');
});

test('an update tidies away the stored value of the removed setting "Show the filled password"', async () => {
  stored.revealFilled = false;
  stored.inlineMenu = false;
  await install({ reason: 'update', previousVersion: '0.0.9' });
  assert.equal('revealFilled' in stored, false);
  assert.equal(stored.inlineMenu, false, 'other settings stay');
  delete stored.inlineMenu;
});
