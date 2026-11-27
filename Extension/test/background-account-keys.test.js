// A browser vault linked to a Passyble account (background/account-keys.js), with the WebAssembly stand-in:
// opening a linked file signs in once, then unlocks offline. The account service is a fake answering in this process.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import * as fake from './helpers/fake-wasm.js';
import { b64urlEncode } from '../src/shared/b64url.js';

globalThis.__passFakeWasm = true;
const fetches = []; // every URL the background fetched (the fake account service below answers)

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
  globalThis.fetch = async (url, init) => { fetches.push(String(url)); return service(String(url), init); };
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

function send(msg, sender) {
  return new Promise((resolve) => {
    const async = onMessage(msg, { id: 'pass-ext', ...sender }, resolve);
    if (!async) resolve(undefined);
  });
}
const page = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const content = { tab: tabsById.get(1), frameId: 0, url: 'https://github.com/login' };

async function ok(msg, sender = page) {
  const res = await send(msg, sender);
  assert.ok(res?.ok, `${msg.type}: ${JSON.stringify(res?.error)}`);
  return res.result;
}

const ACCOUNT = 'acc_demo';
const EMAIL = 'demo@example.com';
const AK = 'cd'.repeat(32);
const SK = 'P1-ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567';
const SALT = 'c2FsdHNhbHRzYWx0c2FsdA';
const KDF = { alg: 'argon2id', m_kib: 65536, t: 3, p: 1 };
const PASSWORD = 'a demo passphrase only';
const posts = [];

function pwWrap() {
  const derived = new fake.AccountPassword(PASSWORD, SK, SALT, JSON.stringify(KDF));
  const ak = fake.AccountKey.fromBytes(ACCOUNT, Uint8Array.from(AK.match(/../g), (h) => parseInt(h, 16)), fake.fakeAkId(ACCOUNT, AK));
  return JSON.parse(ak.passwordWrap(derived));
}

function service(url, init) {
  const path = new URL(url).pathname;
  // The version check (app-versions.js) is not the account service.
  if (!path.startsWith('/v1/')) return { status: 404, ok: false, json: async () => ({}), headers: { get: () => null } };
  const body = init?.body && init.headers?.['Content-Type'] === 'application/json' ? JSON.parse(init.body) : null;
  posts.push({ path, body });
  const json = (status, data) => ({ status, ok: status < 300, json: async () => data, headers: { get: () => null } });
  if (path === '/v1/prelogin') return json(200, { salt: SALT, kdf: KDF, nonce: 'nonce-1' });
  if (path === '/v1/session/password') {
    const good = body?.sig?.startsWith(`sig:${new fake.AccountPassword(PASSWORD, SK, SALT, JSON.stringify(KDF))._h}:`);
    if (!good) return json(403, { error: 'wrong_password' });
    return json(200, { access_token: 'pat_x', refresh_token: 'prt_x', expires_in: 900, account: { id: ACCOUNT, email: EMAIL },
      account_key: { ak_id: fake.fakeAkId(ACCOUNT, AK), salt: SALT, kdf: KDF, pw_wrap: pwWrap(), sk_wrap: { nonce: 'n', ct: 'x' }, recovery: null } });
  }
  // Signed in: the password wrap again after a signature over an unlock nonce.
  if (path === '/v1/account-key') return json(200, { set: true, ak_id: fake.fakeAkId(ACCOUNT, AK), salt: SALT, kdf: KDF });
  if (path === '/v1/account-key/nonce') return json(200, { nonce: 'nonce-unlock' });
  if (path === '/v1/account-key/unlock') {
    const good = body?.sig?.startsWith(`sig:${new fake.AccountPassword(PASSWORD, SK, SALT, JSON.stringify(KDF))._h}:${EMAIL}:nonce-unlock:`);
    return good ? json(200, { account_key: { ak_id: fake.fakeAkId(ACCOUNT, AK), salt: SALT, kdf: KDF, pw_wrap: pwWrap() } }) : json(403, { error: 'wrong_password' });
  }
  return json(404, { error: 'not_found' });
}

const linkedFile = () => b64urlEncode(fake.fakeLinkedVaultFile(ACCOUNT, AK, [
  { id: 'l1', title: 'GitHub', username: 'octo', password: 'gh-demo', url: 'https://github.com/login', has_totp: false, has_passkey: false },
]));

test('app mode (the first run found an app): the Passyble password is the app\'s; nothing here', async () => {
  local.vaultHostSeen = 'present';
  const st = await ok({ type: 'account.keys-state' });
  assert.deepEqual(st, { available: false, linked: null });
  const res = await send({ type: 'account.approval-start', email: EMAIL }, page);
  assert.equal(res.error.code, 'not_supported');
  delete local.vaultHostSeen;
  local.vaultHostSeen = 'missing';
});

test('"Open a vault file" of a linked vault: what the form needs, the Secret Key once, one sign-in', async () => {
  const access = await ok({ type: 'vault.file-access', file: linkedFile() });
  assert.deepEqual(access, { kind: 'account', email: '', secret_key_needed: true, email_needed: true });
  const plain = await send({ type: 'vault.open-file', file: linkedFile(), password: PASSWORD }, page);
  assert.equal(plain.error.reason, 'secret_key_needed');
  assert.equal(posts.length, 0, 'nothing sent before the form has what it needs');
  const opened = await ok({ type: 'vault.open-file', file: linkedFile(), password: PASSWORD, secret_key: SK, email: EMAIL });
  assert.ok(opened.vault_id);
  assert.deepEqual(posts.map((p) => p.path), ['/v1/prelogin', '/v1/session/password']);
  assert.ok(fetches.filter((u) => u.includes('/v1/')).every((u) => u.startsWith('https://account.passyble.com/v1/')), 'only the account service');
  assert.ok(posts.every((p) => !JSON.stringify(p.body || {}).includes(PASSWORD) && !JSON.stringify(p.body || {}).includes('FGHJK')));
  assert.equal(local.vaultMode, 'browser');
  assert.equal((await ok({ type: 'account.status' })).email, EMAIL);
});

test('the popup: the Passyble password unlocks offline; its state says no Secret Key is needed now', async () => {
  await ok({ type: 'popup.lock' });
  const state = await ok({ type: 'popup.state', tabId: 1 });
  assert.equal(state.locked, true);
  assert.deepEqual(state.account_unlock, { account: ACCOUNT, email: EMAIL, secret_key_needed: false, email_needed: false });
  const before = posts.length;
  const wrong = await send({ type: 'popup.unlock-password', password: 'not it' }, page);
  assert.equal(wrong.error.code, 'wrong_password');
  await ok({ type: 'popup.unlock-password', password: PASSWORD });
  assert.equal((await ok({ type: 'popup.state', tabId: 1 })).locked, false);
  // The wrong one went to the service once, signed in (the password may have changed elsewhere); the right one
  // opened offline.
  assert.deepEqual(posts.slice(before).map((p) => p.path), ['/v1/account-key', '/v1/account-key/nonce', '/v1/account-key/unlock']);
  // The in-page frame learns it is the Passyble password.
  assert.equal((await ok({ type: 'account.keys-state' })).linked.account, ACCOUNT);
});

test('content scripts reach none of the Passyble password handlers', async () => {
  for (const type of ['account.password-sign-in', 'account.keys-state', 'account.approval-start', 'account.approval-poll',
    'account.approval-confirm', 'account.approval-cancel', 'vault.file-access']) {
    assert.equal(await send({ type, email: EMAIL, password: PASSWORD }, content), undefined, type);
  }
});
