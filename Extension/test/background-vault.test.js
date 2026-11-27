// The background with the vault kept in this browser. fetch is refused, and the WebAssembly is the
// test stand-in (helpers/fake-wasm.js); local-wasm.test.js runs the real one.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { defaultVaultStore } from '../src/background/local/vault-store.js';
import { fakeStats } from './helpers/fake-wasm.js';

globalThis.__passFakeWasm = true;
const fetches = []; // every URL the background tried to fetch (all refused: offline)

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: (f) => { const i = fns.indexOf(f); if (i >= 0) fns.splice(i, 1); }, fns };
};

const local = {};
const session = {};
const native = { ports: 0, answer: null }; // answer: null = "host not found"
const windowsCreated = [];
const broadcasts = [];
const offscreenWrites = [];
const alarms = new Map();
const tabsById = new Map([[1, { id: 1, url: 'https://github.com/login', active: true, windowId: 5 }]]);
let onMessage;
let onInstalled;
let onConnect;
let onAlarm;
let onIdle;

function nativePort() {
  native.ports++;
  const port = { onMessage: evt(), onDisconnect: evt(), disconnect() {} };
  port.postMessage = (msg) => queueMicrotask(() => {
    if (native.answer) port.onMessage.fns.forEach((f) => f({ id: msg.id, result: native.answer(msg) }));
    else port.onDisconnect.fns.forEach((f) => f({ error: { message: 'Specified native messaging host not found.' } }));
  });
  return port;
}

before(async () => {
  onInstalled = evt();
  onConnect = evt();
  onAlarm = evt();
  onIdle = evt();
  const onChanged = evt();
  globalThis.fetch = async (url) => { fetches.push(String(url)); throw new TypeError('offline'); };
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext', lastError: undefined,
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      connectNative: () => nativePort(),
      onMessage: { addListener: (f) => { onMessage = f; } },
      onConnect,
      onInstalled, onStartup: evt(),
      sendMessage: async (msg) => {
        if (msg?.target === 'offscreen' && msg.type === 'clipboard.write') { offscreenWrites.push(msg.text); return { result: 'written' }; }
        broadcasts.push(msg);
        return undefined;
      },
    },
    offscreen: { createDocument: async () => {}, closeDocument: async () => {} },
    alarms: { create: async (name, o) => { alarms.set(name, o); }, clear: async (name) => alarms.delete(name), onAlarm },
    idle: { onStateChanged: onIdle },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [...tabsById.values()],
      get: async (id) => tabsById.get(id),
      sendMessage: async () => ({ ok: true }),
      create: async () => ({ id: 9 }),
    },
    windows: {
      get: async () => ({ left: 100, top: 50, width: 1200, height: 800 }),
      create: async (o) => { windowsCreated.push(o); return { id: 9 }; },
      getAll: async () => [{ id: 5 }],
      onRemoved: evt(),
    },
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
          Object.assign(local, o);
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
const settle = async (n = 8) => { for (let i = 0; i < n; i++) await tick(); };

function send(msg, sender) {
  return new Promise((resolve) => {
    const async = onMessage(msg, { id: 'pass-ext', ...sender }, resolve);
    if (!async) resolve(undefined);
  });
}
const page = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const content = { tab: tabsById.get(1), frameId: 0, url: 'https://github.com/login' };
const MASTER = 'master password 1';

async function ok(msg, sender = page) {
  const res = await send(msg, sender);
  assert.ok(res?.ok, `${msg.type}: ${JSON.stringify(res?.error)}`);
  return res.result;
}

/** A popup holding its port (the background shows its questions there). */
function openPopupPort() {
  const port = { name: 'passyble-popup', sender: { id: 'pass-ext', url: page.url }, onDisconnect: evt() };
  onConnect.fns.forEach((f) => f(port));
  return { close: () => port.onDisconnect.fns.forEach((f) => f(port)) };
}

test('first run without the Passyble app: no mode is set, the setup guide is told to ask', async () => {
  for (const f of onInstalled.fns) await f({ reason: 'install' });
  await settle(20);
  assert.equal(local.vaultMode, undefined, 'nothing chosen for the user');
  assert.equal(local.vaultHostSeen, 'missing');
  const state = await ok({ type: 'vault.state' });
  assert.deepEqual([state.mode, state.supported, state.host, state.has_vault], [null, true, 'missing', false]);
});

test('without a mode the extension stays in app mode: requests go to the native host', async () => {
  const before = native.ports;
  const res = await send({ type: 'popup.status' }, page);
  assert.equal(res.ok, false);
  assert.equal(res.error.code, 'agent_unavailable');
  assert.ok(native.ports > before);
});

test('switching to the browser needs a vault there first', async () => {
  const res = await send({ type: 'vault.set-mode', mode: 'browser' }, page);
  assert.equal(res.error.code, 'no_vault');
  assert.equal((await send({ type: 'vault.set-mode', mode: 'elsewhere' }, page)).error.code, 'invalid_params');
});

test('no Google Drive of its own: the old drive.* messages are gone, nothing signs in to Google', async () => {
  for (const type of ['drive.sign-in', 'drive.list', 'drive.open', 'drive.create', 'drive.upload-file', 'drive.move', 'drive.sync-now', 'drive.sign-out']) {
    assert.equal(await send({ type, password: MASTER }, page), undefined, type);
  }
  assert.equal(fetches.some((u) => /google/.test(u)), false);
});

test('vault.check-master: the master password rule for extension pages only; the answer has no secrets; the names are sanitized', async () => {
  assert.equal(await send({ type: 'vault.check-master', password: 'short' }, content), undefined, 'content scripts get no answer');
  const checks = fakeStats.masterChecks;
  const short = await ok({ type: 'vault.check-master', password: 'short' });
  assert.equal(fakeStats.masterChecks, checks + 1, 'answered by the WebAssembly, not by the background');
  assert.deepEqual(Object.keys(short).sort(), ['entropy_bits', 'issues', 'label', 'min_length', 'name', 'ok', 'score']);
  assert.equal(short.ok, false);
  assert.deepEqual(short.issues, ['too_short', 'guessable']);
  assert.equal(JSON.stringify(short).includes('"short"'), false, 'the password is not in the answer');
  const good = await ok({ type: 'vault.check-master', password: 'Longer Password 2026!', names: ['alex.smith@example.com', 42, 'x'.repeat(400), '  '] });
  assert.equal(good.ok, true);
  assert.equal(good.label, 'strong');
  assert.deepEqual(fakeStats.masterNames, ['alex.smith@example.com'], 'strings only, short ones, trimmed');
  const named = await ok({ type: 'vault.check-master', password: 'alexsmith-orbit-candle', names: ['alex.smith@example.com'] });
  assert.deepEqual([named.ok, named.issues, named.name], [false, ['contains_name', 'guessable'], 'alex']);
  const empty = await ok({ type: 'vault.check-master' });
  assert.deepEqual([empty.ok, empty.issues], [false, []], 'nothing typed: nothing to say');
  assert.equal((await send({ type: 'vault.check-master', password: 'x'.repeat(1025) }, page)).error.code, 'invalid_params');
});

test('vault.create refuses a new master password the rule refuses (also one built from the names the page passes); no vault', async () => {
  for (const [password, names] of [['short', []], ['password2024!', []], ['aaaabbbbcccc1234', []], ['alexsmith-orbit-candle', ['alex.smith@example.com']]]) {
    const res = await send({ type: 'vault.create', password, names }, page);
    assert.equal(res.error.code, 'invalid_params', password);
  }
  const state = await ok({ type: 'vault.state' });
  assert.equal(state.has_vault, false);
  assert.equal(local.vaultMode, undefined, 'still nothing chosen');
});

test('Create a vault in this browser: kept only here (the reminder is due); browser mode, unlocked, nothing over native messaging', async () => {
  const before = await ok({ type: 'vault.state' });
  assert.deepEqual([before.has_vault, before.local_only, before.drive_needs_app, before.reminder], [false, false, false, false]);
  assert.equal('drive' in before, false, 'no Google Drive state any more');
  assert.equal((await send({ type: 'vault.create', password: 'short' }, page)).error.code, 'invalid_params');
  const res = await ok({ type: 'vault.create', password: MASTER });
  assert.ok(res.vault_id);
  assert.equal(res.grant, undefined, 'the grant stays in the background');
  const state = await ok({ type: 'vault.state' });
  assert.deepEqual([state.mode, state.has_vault, state.locked, state.source], ['browser', true, false, null]);
  assert.deepEqual([state.local_only, state.drive_needs_app, state.reminder], [true, false, true]);
  assert.equal(local.vaultMode, 'browser');
  assert.ok(session.passBrowserVault?.key, 'the key is kept for this browser session');
  assert.match(local.browserDeviceId, /^[0-9a-f-]{36}$/);
  const ports = native.ports;
  const status = await ok({ type: 'popup.status' });
  assert.equal(status.vault, true);
  assert.equal(status.locked, false);
  assert.equal(native.ports, ports, 'browser mode never opens a native port');
  assert.ok(broadcasts.some((m) => m.type === 'lock_state' && m.locked === false), 'the pages hear it is unlocked');
  assert.equal((await send({ type: 'vault.create', password: MASTER }, page)).error.code, 'invalid_state', 'one vault here at a time');
});

test('popup.state in browser mode: "only on this device" is due, no Drive chip, no pending question; logins go through the vault', async () => {
  const saved = await ok({ type: 'popup.edit-save', tabId: 1, fields: { username: 'octo', password: 'hunter2-long', urls: ['https://github.com'] } });
  assert.ok(saved.id);
  const state = await ok({ type: 'popup.state', tabId: 1 });
  assert.equal(state.browser, true);
  assert.deepEqual([state.local_only, state.reminder, state.drive_needs_app], [true, true, false]);
  assert.equal('not_synced' in state, false);
  assert.equal('backup_due' in state, false, 'no "Not backed up" any more');
  assert.equal('app_tip' in state, false, 'no app tip: the extension switches to the app itself');
  assert.equal(state.ask, null);
  assert.equal(state.can_unlock_inline, true);
  assert.equal(state.items.length, 1);
  const fill = await ok({ type: 'logins.fill', id: saved.id }, content);
  assert.equal(fill.password, 'hunter2-long');
  const opts = await ok({ type: 'unlock.options' }, content);
  assert.equal(opts.browser, true, 'the in-page menu offers no "Open Passyble"');
});

test('copies: the vault releases the value to the background, the offscreen document writes it, cleared in 45 s', async () => {
  const id = (await ok({ type: 'popup.state', tabId: 1 })).items[0].id;
  alarms.delete('pass-clipboard-clear');
  const res = await ok({ type: 'popup.copy-item', tabId: 1, id, field: 'password', own: true, inline: true });
  assert.deepEqual(res, { copied: true, field: 'password' });
  assert.deepEqual(offscreenWrites.slice(-1), ['hunter2-long']);
  assert.ok(alarms.get('pass-clipboard-clear')?.when > Date.now() + 40_000);
});

test('quick actions in browser mode: a scanned 2FA link and a new note go to the vault here, Generate copies through it; nothing over native messaging', async () => {
  const ports = native.ports;
  const id = (await ok({ type: 'popup.state', tabId: 1 })).items[0].id;
  const state = await ok({ type: 'popup.state', tabId: 1 });
  assert.equal(state.can_notes, true, 'the vault here has notes.create');
  const link = 'otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
  const attached = await ok({ type: 'popup.totp-attach', tabId: 1, id, totp: link, inline: true });
  assert.equal(attached.has_totp, true);
  const after = (await ok({ type: 'popup.state', tabId: 1 })).items.find((i) => i.id === id);
  assert.equal(after.has_totp, true);
  assert.equal('totp' in after, false, 'the 2FA value stays in the vault');
  assert.equal((await send({ type: 'popup.totp-attach', tabId: 1, id, totp: 'not a secret' }, page)).error.code, 'invalid_params');
  const note = await ok({ type: 'popup.note-create', fields: { title: 'Recovery codes for github.com', notes: '1111-2222' + String.fromCharCode(10) + '3333-4444' }, inline: true });
  assert.match(note.id, /^note-/);
  assert.equal(note.title, 'Recovery codes for github.com');
  assert.equal((await send({ type: 'popup.note-create', fields: { title: '  ', notes: 'x' } }, page)).error.code, 'invalid_params');
  const gen = await ok({ type: 'popup.generate', length: 20 });
  const copied = await ok({ type: 'popup.generate-copy', password: gen.password });
  assert.equal(copied.copied, true);
  assert.deepEqual(offscreenWrites.slice(-1), [gen.password], 'written to the clipboard by the background');
  assert.equal(native.ports, ports, 'browser mode never opens a native port');
  await settle();
  assert.equal(await send({ type: 'popup.note-create', fields: { title: 'x', notes: 'y' } }, content), undefined);
});

test('secure notes in browser mode: listed by title, opened and copied by the vault here', async () => {
  const state = await ok({ type: 'popup.state', tabId: 1 });
  assert.equal(state.can_note_list, true, 'the vault here has notes.list');
  const note = await ok({ type: 'popup.note-create', fields: { title: 'Demo backup codes', notes: '5555-6666' }, inline: true });
  const list = await ok({ type: 'popup.notes' });
  const listed = list.items.find((n) => n.id === note.id);
  assert.equal(listed.title, 'Demo backup codes');
  assert.equal(JSON.stringify(list).includes('5555'), false, 'the list has no text');
  const opened = await ok({ type: 'popup.note-get', id: note.id, inline: true });
  assert.equal(opened.notes, '5555-6666');
  const copied = await ok({ type: 'popup.note-get', id: note.id, copy: true, inline: true });
  assert.deepEqual(copied, { copied: true });
  assert.deepEqual(offscreenWrites.slice(-1), ['5555-6666'], 'written to the clipboard by the background');
  assert.equal((await send({ type: 'popup.note-get', id: 'no-such-note' }, page)).error.code, 'not_found');
  assert.equal(await send({ type: 'popup.note-get', id: note.id }, content), undefined);
  await settle();
});

test('a card fill from the page asks in the small window; only the yes there fills it', async () => {
  windowsCreated.length = 0;
  const filling = send({ type: 'cards.fill', id: 'card1' }, content);
  await settle();
  assert.match(windowsCreated[0]?.url, /popup\.html\?ask=1$/, 'the small window (no toolbar popup here)');
  const ask = await ok({ type: 'popup.ask-get' });
  assert.equal(ask.kind, 'card');
  assert.equal(ask.host, 'github.com');
  assert.match(ask.card, /Visa •••• 4242/);
  assert.equal((await send({ type: 'popup.ask-answer', token: 'not-it', yes: true }, page)).error.code, 'not_found');
  await ok({ type: 'popup.ask-answer', token: ask.token, yes: true });
  const res = await filling;
  assert.equal(res.result.number, '4242424242424242');

  const again = send({ type: 'cards.fill', id: 'card1' }, content);
  await settle();
  const ask2 = await ok({ type: 'popup.ask-get' });
  await ok({ type: 'popup.ask-answer', token: ask2.token, cancel: true });
  assert.equal((await again).error.code, 'cancelled');
});

test('"Confirm each fill": the master password in the open popup, then the fill goes on with the grant', async () => {
  await ok({ type: 'vault.settings', settings: { vaultVerifyEachFill: true } });
  assert.equal(local.vaultVerifyEachFill, true);
  const popup = openPopupPort();
  broadcasts.length = 0;
  const id = (await ok({ type: 'popup.state', tabId: 1 })).items[0].id;
  const filling = send({ type: 'logins.fill', id }, content);
  await settle();
  assert.ok(broadcasts.some((m) => m.type === 'vault.ask'), 'the open popup is told');
  const ask = await ok({ type: 'popup.ask-get' });
  assert.equal(ask.kind, 'verify');
  assert.equal((await send({ type: 'popup.ask-answer', token: ask.token, password: 'wrong' }, page)).error.code, 'wrong_password');
  await ok({ type: 'popup.ask-answer', token: ask.token, password: MASTER });
  assert.equal((await filling).result.password, 'hunter2-long');

  // The popup that showed the question closes without an answer: the fill is cancelled.
  const next = send({ type: 'logins.fill', id }, content);
  await settle();
  await ok({ type: 'popup.ask-get' });
  popup.close();
  assert.equal((await next).error.code, 'cancelled');
  await ok({ type: 'vault.settings', settings: { vaultVerifyEachFill: false } });
});

test('locked: a fill from the page opens the unlock form; the master password there unlocks and the fill goes on', async () => {
  await ok({ type: 'popup.lock' });
  assert.equal(session.passBrowserVault, undefined, 'the key is gone');
  assert.equal((await ok({ type: 'popup.status' })).locked, true);
  windowsCreated.length = 0;
  const id = (await ok({ type: 'popup.state', tabId: 1 })).items[0].id;
  const filling = send({ type: 'logins.fill', id }, content);
  await settle();
  assert.match(windowsCreated[0]?.url, /popup\.html\?ask=1$/);
  const ask = await ok({ type: 'popup.ask-get' });
  assert.equal(ask.kind, 'unlock');
  assert.equal((await send({ type: 'popup.unlock-password', password: 'wrong' }, page)).error.code, 'wrong_password');
  await ok({ type: 'popup.unlock-password', password: MASTER });
  assert.equal((await filling).result.password, 'hunter2-long');
  assert.ok(session.passBrowserVault?.key);
});

test('passkeys wait for a later update in browser mode: the card says so, the browser\'s own dialog stays', async () => {
  for (const type of ['passkey.find', 'passkey.create_options', 'passkey.get', 'passkey.create']) {
    const res = await send({ type, options: { rpId: 'github.com', challenge: 'AA', user: { id: 'AA' } } }, { ...content, origin: 'https://github.com' });
    assert.equal(res.error.code, 'not_supported', type);
    assert.equal(res.error.reason, 'passkeys_need_app', type);
  }
});

test('the computer locks: the vault locks (unless that setting is off); the alarm runs the vault\'s timers', async () => {
  await ok({ type: 'vault.settings', settings: { vaultLockOnIdle: false } });
  onIdle.fns.forEach((f) => f('locked'));
  await settle(20);
  assert.equal((await ok({ type: 'popup.status' })).locked, false);
  await ok({ type: 'vault.settings', settings: { vaultLockOnIdle: true } });
  onIdle.fns.forEach((f) => f('idle'));
  await settle(20);
  assert.equal((await ok({ type: 'popup.status' })).locked, false, '"idle" is not "locked"');
  onIdle.fns.forEach((f) => f('locked'));
  await settle(20);
  assert.equal((await ok({ type: 'popup.status' })).locked, true);
  await ok({ type: 'popup.unlock-password', password: MASTER });
  assert.ok(alarms.get('pass-vault-tick')?.when > Date.now(), 'the auto-lock alarm is set');
  await ok({ type: 'vault.settings', settings: { vaultAutoLockMins: 1 } });
  session.passBrowserVault.lastUseAt = Date.now() - 120_000;
  // The worker is gone and comes back for the alarm (a second copy of the background, same storage).
  await import('../src/background.js?alarm');
  onAlarm.fns.at(-1)({ name: 'pass-vault-tick' });
  await settle(20);
  assert.equal(session.passBrowserVault, undefined, 'locked by the alarm: the key is gone');
  await ok({ type: 'vault.settings', settings: { vaultAutoLockMins: 15 } });
});

test('a restarted service worker opens the vault again from storage.session, without the master password', async () => {
  await ok({ type: 'popup.unlock-password', password: MASTER });
  await import('../src/background.js?restart');
  // The newest copy's router answers (as after a restart: the old worker is gone).
  const status = await ok({ type: 'popup.status' });
  assert.equal(status.locked, false);
  const state = await ok({ type: 'popup.state', tabId: 1 });
  assert.equal(state.items.length, 1);
});

test('"Not now" on the reminder: hidden for 30 days for this vault (the time kept per vault id), then due again', async () => {
  const before = await ok({ type: 'vault.state' });
  assert.deepEqual([before.local_only, before.reminder], [true, true]);
  const res = await ok({ type: 'vault.reminder-dismiss' });
  assert.deepEqual([res.local_only, res.reminder], [true, false]);
  const id = Object.keys(local.vaultLocalReminderDismissed)[0];
  assert.ok(Math.abs(local.vaultLocalReminderDismissed[id] - Date.now()) < 5000, 'the dismiss time, per vault id');
  assert.equal((await ok({ type: 'popup.state', tabId: 1 })).reminder, false);
  assert.equal((await ok({ type: 'vault.state' })).reminder, false);
  // 30 days later (the stored time moved back): due again, the vault is still only here.
  local.vaultLocalReminderDismissed = { [id]: Date.now() - 30 * 24 * 3600 * 1000 - 1000 };
  assert.equal((await ok({ type: 'popup.state', tabId: 1 })).reminder, true);
  // Only extension pages may dismiss it.
  assert.equal(await send({ type: 'vault.reminder-dismiss' }, content), undefined);
});

test('"Check again": whether the Passyble app is on this computer now; found, the extension uses it', async () => {
  const ports = native.ports;
  assert.deepEqual(await ok({ type: 'vault.check-app' }), { app: 'missing', mode: 'browser' });
  assert.ok(native.ports > ports, 'asked the native host');
  assert.equal(local.vaultHostSeen, 'missing');
  assert.equal((await ok({ type: 'popup.status' })).vault, true, 'browser mode still answers from the vault here');
  native.answer = (msg) => (msg.method === 'status' ? { locked: true, version: '1', features: [] } : {});
  assert.deepEqual(await ok({ type: 'vault.check-app' }), { app: 'connected', mode: 'app' });
  assert.equal(local.vaultHostSeen, 'present');
  assert.equal(local.vaultMode, 'app', 'the app is installed: app mode on its own');
  assert.equal(local.vaultMove?.state, 'offer', 'the offer to move the items here');
  // Back to the browser for the tests below: the app is uninstalled again.
  native.answer = null;
  local.vaultHostSeen = 'missing';
  delete local.vaultMove;
  const back = await ok({ type: 'vault.set-mode', mode: 'browser' });
  assert.equal(back.mode, 'browser');
  delete local.vaultHostSeen;
});

test('Download a copy, delete the vault (after the backup), and open the copy again in this browser', async () => {
  const copy = await ok({ type: 'vault.export' });
  assert.match(copy.name, /^Passyble-\d{4}-\d{2}-\d{2}\.vault$/);
  assert.match(copy.file, /^[A-Za-z0-9_-]+$/);
  assert.equal((await send({ type: 'vault.delete', password: 'wrong' }, page)).error.code, 'wrong_password');
  const state = await ok({ type: 'vault.delete', password: MASTER });
  assert.deepEqual([state.has_vault, state.local_only, state.reminder], [false, false, false]);
  const popup = await ok({ type: 'popup.state', tabId: 1 });
  assert.deepEqual([popup.no_vault, popup.browser, popup.locked], [true, true, true]);
  assert.equal((await send({ type: 'logins.find', automatic: true }, content)).error.code, 'no_vault');

  assert.equal((await send({ type: 'vault.open-file', file: '', password: MASTER }, page)).error.code, 'invalid_params');
  assert.equal((await send({ type: 'vault.open-file', file: copy.file, password: 'wrong' }, page)).error.code, 'wrong_password');
  const opened = await ok({ type: 'vault.open-file', file: copy.file, password: MASTER });
  assert.ok(opened.vault_id);
  assert.equal((await ok({ type: 'popup.state', tabId: 1 })).items.length, 1);
  const again = await ok({ type: 'vault.state' });
  assert.deepEqual([again.mode, again.has_vault, again.local_only, again.source], ['browser', true, true, null]);
  assert.equal((await send({ type: 'vault.open-file', file: copy.file, password: MASTER }, page)).error.code, 'invalid_state', 'one vault here at a time');
});

test('a vault record of the builds that synced Google Drive themselves: still opens and saves here; "Drive sync needs the Passyble app", no local-only reminder', async () => {
  const store = defaultVaultStore();
  const rec = await store.load();
  await store.update(rec.id, { source: 'drive', name: 'Personal', account: 'ada@example.com', pending: true, syncedAt: 1, syncError: 'sign_in' });
  // The worker is gone and comes back (a second copy of the background, same storage): it reads the record.
  await import('../src/background.js?drive-record');
  const state = await ok({ type: 'vault.state' });
  assert.deepEqual([state.has_vault, state.source, state.drive_needs_app, state.local_only, state.reminder], [true, 'drive', true, false, false]);
  const popup = await ok({ type: 'popup.state', tabId: 1 });
  assert.deepEqual([popup.drive_needs_app, popup.local_only, popup.reminder], [true, false, false]);
  assert.equal('not_synced' in popup, false, 'no sync state any more');
  const saved = await ok({ type: 'popup.edit-save', tabId: 1, fields: { username: 'second', password: 'hunter3-long', urls: ['https://github.com'] } });
  assert.ok(saved.id, 'changes are saved here as before');
  assert.equal((await ok({ type: 'popup.state', tabId: 1 })).items.length, 2);
  assert.equal(alarms.has('pass-drive-sync'), false, 'nothing schedules a sync');
  // Back to a vault kept only here for the tests below.
  await store.update(rec.id, { source: null });
  await import('../src/background.js?local-again');
});

test('the master password tip: set from the rule at a master password unlock, left alone by a restored session, Dismiss kept per vault, browser mode only', async () => {
  const store = defaultVaultStore();
  const rec = await store.load();
  const tipOf = () => local.vaultMasterPasswordTip?.[rec.id];
  assert.equal((await ok({ type: 'vault.state' })).master_tip, false, 'MASTER passes the rule');
  assert.equal(tipOf(), undefined, 'nothing kept for a master password that passes');
  // The vault's name counts as known to an attacker: "master" is in MASTER, so it is below the rule.
  await store.update(rec.id, { name: 'Master Vault' });
  await import('../src/background.js?tip-name');
  await ok({ type: 'popup.lock' });
  assert.equal((await send({ type: 'popup.unlock-password', password: 'wrong' }, page)).error.code, 'wrong_password');
  assert.equal(tipOf(), undefined, 'a failed unlock records nothing');
  await ok({ type: 'popup.unlock-password', password: MASTER });
  assert.deepEqual(tipOf(), { weak: true }, 'only the flag');
  assert.equal(JSON.stringify(local).includes(MASTER), false, 'the password is never stored');
  assert.equal((await ok({ type: 'vault.state' })).master_tip, true);
  assert.equal('master_tip' in (await ok({ type: 'popup.state', tabId: 1 })), false, 'only Options shows it, not the popup');
  // A restarted service worker opens the vault from storage.session: no master password, no check.
  const checks = fakeStats.masterChecks;
  await import('../src/background.js?tip-restart');
  assert.equal((await ok({ type: 'popup.status' })).locked, false);
  assert.equal((await ok({ type: 'vault.state' })).master_tip, true);
  assert.equal(fakeStats.masterChecks, checks, 'a restored session runs no check and leaves the flag');
  // Dismiss: extension pages only; kept for this vault, also after the next unlock with the same password.
  assert.equal(await send({ type: 'vault.master-tip-dismiss' }, content), undefined);
  const dismissed = await ok({ type: 'vault.master-tip-dismiss' });
  assert.equal(dismissed.master_tip, false);
  assert.deepEqual(tipOf(), { weak: true, dismissed: true });
  await ok({ type: 'popup.lock' });
  await ok({ type: 'popup.unlock-password', password: MASTER });
  assert.equal((await ok({ type: 'vault.state' })).master_tip, false, 'still dismissed');
  // In app mode the Passyble app owns the tip: none here, and Dismiss is not for it.
  local.vaultMasterPasswordTip = { [rec.id]: { weak: true } };
  assert.equal((await ok({ type: 'vault.state' })).master_tip, true);
  assert.equal((await ok({ type: 'vault.set-mode', mode: 'app' })).master_tip, false);
  assert.equal((await send({ type: 'vault.master-tip-dismiss' }, page)).error.code, 'not_supported');
  await ok({ type: 'vault.set-mode', mode: 'browser' });
  // Changed elsewhere (here: the name doesn't match): the next master password unlock clears the flag.
  await store.update(rec.id, { name: '' });
  await import('../src/background.js?tip-clear');
  await ok({ type: 'popup.unlock-password', password: MASTER });
  assert.equal(tipOf(), undefined);
  assert.equal((await ok({ type: 'vault.state' })).master_tip, false);
  // Deleting the vault removes its flags (the copy is opened again for the tests below).
  local.vaultMasterPasswordTip = { [rec.id]: { weak: true, dismissed: true }, other: { weak: true } };
  const copy = await ok({ type: 'vault.export' });
  await ok({ type: 'vault.delete', password: MASTER });
  assert.deepEqual(local.vaultMasterPasswordTip, { other: { weak: true } });
  await ok({ type: 'vault.open-file', file: copy.file, password: MASTER });
  assert.equal(tipOf(), undefined, 'Open a vault file checks the typed master password too');
  delete local.vaultMasterPasswordTip;
});

test('switching to the app: the browser vault is locked and kept; the next requests go to the native host', async () => {
  const state = await ok({ type: 'vault.set-mode', mode: 'app' });
  assert.equal(state.mode, 'app');
  assert.equal(state.has_vault, true, 'kept, inactive');
  assert.equal(session.passBrowserVault, undefined);
  const ports = native.ports;
  native.answer = (msg) => (msg.method === 'status' ? { locked: true, version: '1', features: [] } : {});
  const status = await ok({ type: 'popup.status' });
  assert.equal(status.version, '1');
  assert.ok(native.ports > ports);
  await settle();
  assert.equal(local.vaultHostSeen, 'present', 'the app answered: installed');
  // While the app is installed, browser mode isn't offered.
  const refused = await send({ type: 'vault.set-mode', mode: 'browser' }, page);
  assert.equal(refused.error.code, 'invalid_state');
  assert.equal(local.vaultMode, 'app');
  // Back to the browser once the app is gone: the kept vault, locked.
  local.vaultHostSeen = 'missing';
  const back = await ok({ type: 'vault.set-mode', mode: 'browser' });
  assert.deepEqual([back.mode, back.has_vault, back.locked], ['browser', true, true]);
  native.answer = null;
});

test('a new install where the Passyble app answers: app mode, silently', async () => {
  for (const k of Object.keys(local)) delete local[k];
  native.answer = (msg) => (msg.method === 'status' ? { locked: true, version: '1', features: [] } : {});
  await import('../src/background.js?app-present');
  await onInstalled.fns.at(-1)({ reason: 'install' });
  await settle(20);
  assert.equal(local.vaultMode, 'app');
  assert.equal(local.vaultHostSeen, 'present');
  native.answer = null;
});

test('account: only extension pages ask about the Passyble account; a content script gets no answer', async () => {
  for (const type of ['account.status', 'account.sign-in', 'account.sign-out']) {
    assert.equal(await send({ type }, content), undefined, type);
  }
  const st = await ok({ type: 'account.status' });
  assert.equal(st.signed_in, false);
  assert.equal(st.email, null);
});
