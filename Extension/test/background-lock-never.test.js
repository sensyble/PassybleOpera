import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({});
const tabsById = new Map([
  [1, { id: 1, url: 'https://github.com/login', active: true }],
  [2, { id: 2, url: 'https://www.example.com/', active: false }],
]);
const tabMessages = [];
const store = {}; // storage.local
let onMessage;

function fakePort() {
  const port = { onMessage: evt(), onDisconnect: evt() };
  port.postMessage = (msg) => {
    calls.push([msg.method, msg.params]);
    queueMicrotask(async () => {
      const out = await agent(msg.method, msg.params);
      const reply = out && out.__error ? { id: msg.id, error: out.__error } : { id: msg.id, result: out };
      port.onMessage.fns.forEach((f) => f(reply));
    });
  };
  port.disconnect = () => {};
  return port;
}

before(async () => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext', lastError: undefined,
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      connectNative: () => fakePort(),
      onMessage: { addListener: (f) => { onMessage = f; } },
      onInstalled: evt(), onStartup: evt(),
      sendMessage: async () => undefined,
    },
    alarms: { create: async () => {}, onAlarm: evt() },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [...tabsById.values()],
      get: async (id) => tabsById.get(id),
      sendMessage: async (tabId, msg, opts) => { tabMessages.push([tabId, msg, opts]); return { ok: true }; },
    },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, onClicked: evt() },
    commands: { onCommand: evt() },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {} },
    scripting: { executeScript: async () => [] },
    storage: {
      local: {
        get: async (keys) => {
          const list = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(store);
          return Object.fromEntries(list.filter((k) => k in store).map((k) => [k, structuredClone(store[k])]));
        },
        set: async (o) => { Object.assign(store, structuredClone(o)); },
      },
      sync: { get: async () => ({}), set: async () => {} },
      onChanged: evt(),
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

const POPUP = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const contentSender = (url, extra = {}) => ({ tab: tabsById.get(1), frameId: 0, url, ...extra });
const callsOf = (method) => calls.filter((c) => c[0] === method).map((c) => c[1]);
const settle = () => new Promise((r) => setTimeout(r, 10));

test('popup.lock: the popup locks the vault through the native `lock` method; the pages and badge follow', async () => {
  agent = (m) => (m === 'lock' ? { locked: true } : { items: [], pending_otp: null, locked: true });
  calls.length = 0;
  tabMessages.length = 0;
  const res = await send({ type: 'popup.lock' }, POPUP);
  assert.deepEqual(res, { ok: true, result: { locked: true } });
  assert.deepEqual(callsOf('lock'), [{}], 'no parameters');
  await settle();
  assert.ok(tabMessages.some(([id, m]) => id === 1 && m.type === 'lock_state' && m.locked === true), 'active tab hears it');
  assert.ok(callsOf('logins.find').length > 0, 'the badge is refreshed from the agent');
});

test('popup.lock is not reachable from content scripts', async () => {
  calls.length = 0;
  const res = await send({ type: 'popup.lock' }, contentSender('https://evil.test/'));
  assert.equal(res, undefined, 'no handler: the listener returns false');
  assert.equal(callsOf('lock').length, 0);
  // Not from an extension page of another extension either.
  assert.equal(await send({ type: 'popup.lock' }, { url: 'chrome-extension://other/popup.html' }), undefined);
});

test('popup.lock: agent_unavailable reaches the popup with its code; an older desktop app is not_supported', async () => {
  agent = () => ({ __error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });
  let res = await send({ type: 'popup.lock' }, POPUP);
  assert.equal(res.ok, false);
  assert.equal(res.error.code, 'agent_unavailable');
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method lock' } });
  res = await send({ type: 'popup.lock' }, POPUP);
  assert.equal(res.error.code, 'not_supported');
});

// Never save for this site.

const cap = (url, extra = {}) => send({ type: 'save.capture', username: 'octo', password: 'typed-pw', kind: 'login', ...extra }, contentSender(url));
const query = (url) => send({ type: 'save.query' }, contentSender(url));

test('save.never stores the origin of the form frame from the browser sender URL, not from the message', async () => {
  agent = (m) => (m === 'logins.save_check' ? { action: 'save_new' } : { items: [], pending_otp: null });
  await cap('https://shop.example.com/session');
  const q = await query('https://shop.example.com/');
  assert.equal(q.result.mode, 'save');
  const res = await send({ type: 'save.never', token: q.result.token, site: 'https://evil.test', url: 'https://evil.test/' },
    contentSender('https://shop.example.com/'));
  assert.deepEqual(res, { ok: true, result: { site: 'https://shop.example.com' } });
  assert.deepEqual(store.neverSave, ['https://shop.example.com']);
  assert.ok(!JSON.stringify(store).includes('typed-pw'), 'the password is not stored');
  assert.ok(!JSON.stringify(store).includes('evil.test'));
});

test('after "never": no banner for that site, even for a new submit; other sites still get one', async () => {
  agent = (m) => (m === 'logins.save_check' ? { action: 'save_new' } : { items: [], pending_otp: null });
  calls.length = 0;
  await cap('https://shop.example.com/session');
  assert.equal((await query('https://shop.example.com/')).result, null);
  assert.equal(callsOf('logins.save_check').length, 0, 'the agent is not even asked');
  // The form was on a frame of the site, the banner on a page of another one: the form's site decides.
  await cap('https://shop.example.com/session');
  assert.equal((await query('https://www.example.com/')).result, null);
  await cap('https://github.com/session');
  assert.equal((await query('https://github.com/')).result.mode, 'save');
});

test('save.never needs the banner\'s token, the top frame and a web page', async () => {
  agent = (m) => (m === 'logins.save_check' ? { action: 'save_new' } : { items: [], pending_otp: null });
  await cap('https://a.example.org/login');
  const q = await query('https://a.example.org/');
  const before = JSON.stringify(store.neverSave);
  let res = await send({ type: 'save.never', token: 'guess' }, contentSender('https://a.example.org/'));
  assert.equal(res.error.code, 'not_found');
  assert.equal(res.error.reason, 'nothing_to_save');
  res = await send({ type: 'save.never', token: q.result.token }, contentSender('https://a.example.org/frame', { frameId: 3 }));
  assert.equal(res.error.code, 'not_found');
  assert.equal(JSON.stringify(store.neverSave), before, 'nothing stored');
  // Extension pages have no save in progress.
  assert.equal(await send({ type: 'save.never', token: q.result.token }, POPUP), undefined);
  res = await send({ type: 'save.never', token: q.result.token }, contentSender('https://a.example.org/'));
  assert.equal(res.ok, true);
  assert.ok(store.neverSave.includes('https://a.example.org'));
});

test('"never" on a site with an auto-saved generated password still lets the sign-up update the draft', async () => {
  // The draft is the login itself (not a banner): never-save only silences the banner.
  agent = (m) => (m === 'logins.create' ? { id: 'd1', title: 'shop' } : m === 'logins.update' ? { title: 'shop' } : { items: [], pending_otp: null });
  calls.length = 0;
  const created = await send({ type: 'draft.save', password: 'Gen-Pw-1!', username: '' }, contentSender('https://shop.example.com/signup'));
  assert.equal(created.result.created, true);
  await cap('https://shop.example.com/signup', { kind: 'signup', password: 'Gen-Pw-1!' });
  assert.equal((await query('https://shop.example.com/welcome')).result, null);
  assert.equal(callsOf('logins.update').length, 1, 'the draft got the final password');
});
