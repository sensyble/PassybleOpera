// The Passyble app always wins: with the app installed the background goes to app mode, never offers the vault in
// this browser, and offers once to move its items there. The native host is a stand-in. Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { b64urlDecode } from '../src/shared/b64url.js';

globalThis.__passFakeWasm = true;

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: (f) => { const i = fns.indexOf(f); if (i >= 0) fns.splice(i, 1); }, fns };
};

const local = {};
const session = {};
// `answer(msg)`: `{ result }` or `{ error }` for one request; null: "host not found" (no Passyble app registered).
const native = { ports: 0, answer: null, requests: [] };
let onMessage;
let onInstalled;
let onStartup;

function nativePort() {
  native.ports++;
  const port = { onMessage: evt(), onDisconnect: evt(), disconnect() {} };
  port.postMessage = (msg) => queueMicrotask(() => {
    native.requests.push(msg);
    if (!native.answer) {
      port.onDisconnect.fns.forEach((f) => f({ error: { message: 'Specified native messaging host not found.' } }));
      return;
    }
    port.onMessage.fns.forEach((f) => f({ id: msg.id, ...native.answer(msg) }));
  });
  return port;
}

const FEATURES = ['edit', 'notes.create', 'items.import', 'vaults'];
/** The Passyble app, running and unlocked: `status`, `vaults.list`, and `items.import` answered by `onImport`. */
function appAnswers({ features = FEATURES, onImport = null, locked = false } = {}) {
  const state = { locked };
  return (msg) => {
    if (msg.method === 'status') return { result: { locked: state.locked, version: '1.4', features } };
    if (msg.method === 'unlock') { state.locked = false; return { result: { locked: false } }; }
    if (msg.method === 'vaults.list') {
      return { result: { vaults: [
        { id: 'home', name: 'Personal', home: true, can_edit: true, can_reveal: true, items: 40, open: true },
        { id: 'team', name: 'Team', home: false, can_edit: true, can_reveal: true, items: 3, open: true },
        { id: 'view', name: 'Read only', home: false, can_edit: false, can_reveal: true, items: 3, open: true },
      ], teams: null } };
    }
    if (msg.method === 'items.import') {
      if (state.locked) return { error: { code: 'locked', message: 'Vault is locked' } };
      return onImport ? onImport(msg.params) : { result: { total: 0, added: 0, skipped: 0, failed_count: 0, failed: [] } };
    }
    return { result: {} };
  };
}
const notRunning = () => ({ error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });

before(async () => {
  onInstalled = evt();
  onStartup = evt();
  const onChanged = evt();
  globalThis.fetch = async () => { throw new TypeError('offline'); };
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext', lastError: undefined,
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      connectNative: () => nativePort(),
      onMessage: { addListener: (f) => { onMessage = f; } },
      onConnect: evt(),
      onInstalled, onStartup,
      sendMessage: async () => undefined,
    },
    offscreen: { createDocument: async () => {}, closeDocument: async () => {} },
    alarms: { create: async () => {}, clear: async () => true, onAlarm: evt() },
    idle: { onStateChanged: evt() },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [{ id: 1, url: 'https://github.com/login', active: true, windowId: 5 }],
      get: async () => ({ id: 1, url: 'https://github.com/login', active: true, windowId: 5 }),
      sendMessage: async () => ({ ok: true }),
      create: async () => ({ id: 9 }),
    },
    windows: { get: async () => ({ left: 0, top: 0, width: 1200, height: 800 }), create: async () => ({ id: 9 }), getAll: async () => [{ id: 5 }], onRemoved: evt() },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, update: () => {}, onClicked: evt() },
    commands: { onCommand: evt() },
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
  await import('../src/background.js');
});

const tick = () => new Promise((r) => setTimeout(r, 0));
const settle = async (n = 12) => { for (let i = 0; i < n; i++) await tick(); };

function send(msg) {
  return new Promise((resolve) => {
    const async = onMessage(msg, { id: 'pass-ext', url: 'chrome-extension://pass-ext/src/options/options.html' }, resolve);
    if (!async) resolve(undefined);
  });
}
async function ok(msg) {
  const res = await send(msg);
  assert.ok(res?.ok, `${msg.type}: ${JSON.stringify(res?.error)}`);
  return res.result;
}
async function fails(msg) {
  const res = await send(msg);
  assert.equal(res?.ok, false, `${msg.type} should fail`);
  return res.error;
}

const MASTER = 'master password 1';
const sent = (method) => native.requests.filter((r) => r.method === method);

test('a new install with the Passyble app installed but not running: app mode at once, no choice, browser mode not offered', async () => {
  native.answer = notRunning;
  for (const f of onInstalled.fns) await f({ reason: 'install' });
  await settle(20);
  assert.equal(local.vaultMode, 'app', 'installed counts, running or not');
  assert.equal(local.vaultHostSeen, 'present');
  const state = await ok({ type: 'vault.state' });
  assert.deepEqual([state.mode, state.app_installed, state.app_gone, state.move], ['app', true, false, null]);
  // The vault in this browser isn't offered while the app is installed.
  assert.equal((await fails({ type: 'vault.create', password: MASTER })).code, 'invalid_state');
  assert.equal((await fails({ type: 'vault.set-mode', mode: 'browser' })).code, 'invalid_state');
  assert.equal(local.vaultMode, 'app');
});

test('the app closed or slow never leaves app mode: "not running" is still installed, and counts as no miss', async () => {
  native.answer = notRunning;
  const res = await send({ type: 'popup.status' });
  assert.equal(res.error.code, 'agent_unavailable');
  await settle();
  assert.equal(local.vaultMode, 'app');
  assert.equal(local.vaultHostSeen, 'present');
  assert.equal(local.vaultHostMisses, undefined, 'nothing counted');
  native.answer = appAnswers();
  assert.equal((await ok({ type: 'popup.status' })).version, '1.4');
});

test('the app uninstalled: one "host not found" is not enough; three spaced checks say so, and browser mode is offered again', async () => {
  const realNow = Date.now;
  let now = realNow();
  Date.now = () => now;
  try {
    native.answer = null;
    await send({ type: 'popup.status' });
    await settle();
    assert.deepEqual(local.vaultHostMisses?.count, 1);
    assert.equal(local.vaultHostSeen, 'present', 'one failure: still installed');
    // A burst right after counts once.
    await send({ type: 'popup.status' });
    await send({ type: 'popup.status' });
    await settle();
    assert.equal(local.vaultHostMisses.count, 1, 'not spaced: counted once');
    assert.equal((await ok({ type: 'vault.state' })).app_installed, true);
    // A flaky single failure is wiped by the next answer.
    native.answer = appAnswers();
    await ok({ type: 'popup.status' });
    await settle();
    assert.equal(local.vaultHostMisses.count, 0);
    native.answer = null;
    for (let i = 0; i < 3; i++) {
      now += 61_000;
      await send({ type: 'popup.status' });
      await settle();
    }
    assert.equal(local.vaultHostSeen, 'missing');
    assert.equal(local.vaultAppGone, true);
    const state = await ok({ type: 'vault.state' });
    assert.deepEqual([state.mode, state.app_installed, state.app_gone, state.has_vault], ['app', false, true, false],
      'still app mode, nothing created on its own');
  } finally {
    Date.now = realNow;
  }
});

test('the user chooses the vault in this browser again (the app is gone): created, browser mode, the notice answered', async () => {
  const created = await ok({ type: 'vault.create', password: MASTER });
  assert.ok(created.vault_id);
  assert.equal(local.vaultMode, 'browser');
  assert.equal(local.vaultAppGone, false);
  // Demo items: two logins and the fake's card.
  await ok({ type: 'popup.edit-save', tabId: 1, fields: { username: 'octo', password: 'demo-pass-1', urls: ['https://github.com'] } });
  await ok({ type: 'popup.edit-save', tabId: 1, fields: { username: 'ann', password: 'demo-pass-2', urls: ['https://gitlab.com'] } });
  assert.equal((await ok({ type: 'popup.state', tabId: 1 })).browser, true);
});

test('browser mode finds the app (the popup opens): app mode on its own, and the one-time offer counts the items', async () => {
  delete local.vaultHostProbeAt;
  native.answer = appAnswers();
  const ports = native.ports;
  await ok({ type: 'popup.state', tabId: 1 });
  await settle(30);
  assert.ok(native.ports > ports, 'looked for the app');
  assert.equal(local.vaultMode, 'app', 'switched by itself');
  assert.equal(local.vaultHostSeen, 'present');
  assert.deepEqual([local.vaultMove.state, local.vaultMove.count], ['offer', 3], '2 logins and a card');
  const popup = await ok({ type: 'popup.state', tabId: 1 });
  assert.deepEqual(popup.move_offer, { count: 3 });
  const state = await ok({ type: 'vault.state' });
  assert.deepEqual([state.mode, state.has_vault, state.app_installed, state.move.state], ['app', true, true, 'offer']);
  // Looking again later doesn't make a second offer, and a browser in app mode doesn't look at all.
  const before = native.ports;
  await ok({ type: 'vault.state', probe: true });
  assert.equal(native.ports, before);
});

test('"Not now": the popup stops offering, Options keeps it', async () => {
  const state = await ok({ type: 'vault.move-later' });
  assert.equal(state.move.state, 'later');
  assert.equal((await ok({ type: 'popup.state', tabId: 1 })).move_offer, undefined);
  assert.equal(state.has_vault, true, 'nothing lost');
});

test('the vaults the items can go into: editable ones only', async () => {
  const { vaults } = await ok({ type: 'vault.move-targets' });
  assert.deepEqual(vaults.map((v) => v.id), ['home', 'team']);
});

test('an older Passyble app without items.import: "update the app", nothing sent', async () => {
  native.answer = appAnswers({ features: ['edit'] });
  const err = await fails({ type: 'vault.move', password: MASTER });
  assert.deepEqual([err.code, err.reason], ['not_supported', 'needs_update']);
  assert.equal(sent('items.import').length, 0);
});

test('a wrong master password moves nothing', async () => {
  native.answer = appAnswers();
  const err = await fails({ type: 'vault.move', password: 'wrong' });
  assert.equal(err.code, 'wrong_password');
  assert.equal(sent('items.import').length, 0);
  assert.equal(local.vaultMove.state, 'later');
});

test('a partial move: what failed is listed, stays in this browser, and the vault here can\'t be deleted yet', async () => {
  native.answer = appAnswers({ onImport: () => ({ result: { total: 3, added: 1, skipped: 0, failed_count: 2,
    failed: [{ title: 'gitlab.com', kind: 'login', message: 'x' }, { title: 'Visa', kind: 'card', message: 'y' }] } }) });
  const state = await ok({ type: 'vault.move', password: MASTER, vault: 'team' });
  assert.equal(sent('items.import').at(-1).params.vault, 'team', 'into the vault the user chose');
  assert.deepEqual([state.move.state, state.move.added, state.move.failed_count, state.move.failed], ['partial', 1, 2, ['gitlab.com', 'Visa']]);
  assert.equal(state.has_vault, true);
  assert.equal((await fails({ type: 'vault.delete-moved', confirmed: true })).code, 'invalid_state');
});

test('the move: the browser vault opened with its master password, its file and key sent once; duplicates skipped by the app', async () => {
  let seen = null;
  native.answer = appAnswers({ locked: true, onImport: (params) => {
    seen = params;
    return { result: { total: 3, added: 2, skipped: 1, failed_count: 0, failed: [] } };
  } });
  const state = await ok({ type: 'vault.move', password: MASTER });
  assert.equal(sent('unlock').length, 1, 'the app was locked: its own unlock, then once more');
  // The vault file (the fake's JSON) and its 32-byte key.
  const file = JSON.parse(new TextDecoder().decode(b64urlDecode(seen.file)));
  assert.deepEqual(file.logins.map((l) => l.username).sort(), ['ann', 'octo']);
  assert.equal(b64urlDecode(seen.key).length, 32);
  assert.equal(seen.vault, undefined, 'the home vault by default');
  assert.equal(JSON.stringify(local).includes(MASTER), false, 'the master password is never kept');
  assert.deepEqual([state.move.state, state.move.added, state.move.skipped, state.move.failed_count], ['moved', 2, 1, 0]);
  assert.deepEqual([state.mode, state.has_vault], ['app', true], 'the vault here is kept, untouched');
  assert.equal(session.passBrowserVault, undefined, 'and stays locked');
});

test('"Delete the vault in this browser" after the move: confirmed first, then gone; nothing else changes', async () => {
  assert.equal((await fails({ type: 'vault.delete-moved' })).code, 'invalid_params', 'not without the confirmation');
  const state = await ok({ type: 'vault.delete-moved', confirmed: true });
  assert.deepEqual([state.has_vault, state.move, state.mode], [false, null, 'app']);
  assert.equal(local.vaultMove, undefined);
});

test('the browser starting: browser mode looks for the app at once; app mode does not', async () => {
  const before = native.ports;
  for (const f of onStartup.fns) await f();
  await settle();
  assert.equal(native.ports, before, 'app mode: its own requests tell');
});
