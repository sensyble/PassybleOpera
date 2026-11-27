// A login submitted while the vault is locked: the agent can't compare passwords then
// (logins.save_check answers `locked`), so the banner waits for the unlock or checks again after it.
import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({});
const tabsById = new Map([[1, { id: 1, url: 'https://github.com/login', active: true }]]);
const tabMessages = [];
const ports = [];
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
  ports.push(port);
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
      local: { get: async () => ({}), set: async () => {} },
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

const contentSender = (url, extra = {}) => ({ tab: tabsById.get(1), frameId: 0, url, ...extra });
const callsOf = (method) => calls.filter((c) => c[0] === method).map((c) => c[1]);
const settle = () => new Promise((r) => setTimeout(r, 10));
const LOCKED = { __error: { code: 'locked', message: 'Vault is locked' } };
const PW = 'typed-Pw-1';

/** The agent's `lock_state` event (the desktop app was unlocked). */
async function unlockedEvent() {
  for (const port of ports) port.onMessage.fns.forEach((f) => f({ event: 'lock_state', data: { locked: false } }));
  await settle();
}

const rechecks = () => tabMessages.filter(([, m]) => m.type === 'save.recheck');

/**
 * A fake agent: `state` is 'soft' (list kept), 'full' or 'open'; `list` the site's logins in the
 * kept list; `decision` what `logins.save_check` answers once unlocked.
 */
function fakeAgent({ list = [{ id: 'gh', title: 'GitHub', username: 'octo' }], decision = { action: 'none', id: 'gh', title: 'GitHub' } } = {}) {
  const box = { state: 'soft' };
  agent = (m) => {
    if (m === 'unlock') { box.state = 'open'; return {}; }
    if (m === 'logins.find') {
      if (box.state === 'full') return LOCKED;
      return { items: list, pending_otp: null, locked: box.state !== 'open' };
    }
    if (m === 'logins.save_check' || m === 'logins.save') {
      if (box.state !== 'open') return LOCKED;
      return m === 'logins.save' ? { id: 'new' } : decision;
    }
    if (m === 'password.check') return { score: 3, label: 'good', vault_checked: true, issues: [] };
    return {};
  };
  return box;
}

const capture = (fields = {}) => send({ type: 'save.capture', username: 'octo', password: PW, kind: 'login', ...fields },
  contentSender('https://github.com/session'));
const query = (extra = {}) => send({ type: 'save.query', ...extra }, contentSender('https://github.com/'));

beforeEach(() => {
  calls.length = 0;
  tabMessages.length = 0;
});

test('soft-locked, a login with this username is saved for the site: no banner now, none after the unlock if saved as is', async () => {
  const box = fakeAgent();
  await capture({ username: ' OCTO ' });
  assert.equal((await query()).result, null, 'held: may be saved already');
  assert.equal(callsOf('logins.find').at(-1).url, 'https://github.com/session');
  // A later page of the same tab while still locked: still held.
  assert.equal((await query()).result, null);
  box.state = 'open';
  await unlockedEvent();
  assert.deepEqual(rechecks().map(([tabId, m, opts]) => [tabId, m, opts]), [[1, { type: 'save.recheck' }, { frameId: 0 }]]);
  const after = await query({ recheck: true });
  assert.equal(after.result, null, 'saved as is: nothing to ask');
  assert.equal(callsOf('logins.save_check').at(-1).password, PW);
  assert.equal(callsOf('logins.save').length, 0);
  assert.equal((await query()).result, null);
  assert.equal((await query({ recheck: true })).result, null);
});

test('soft-locked, same username: after the unlock a changed password gets "Update password?"', async () => {
  const box = fakeAgent({ decision: { action: 'update_password', id: 'gh', title: 'GitHub' } });
  await capture();
  assert.equal((await query()).result, null);
  // Asked again while still locked (an unlock that failed): nothing changes, the login stays held.
  assert.equal((await query({ recheck: true })).result, null);
  box.state = 'open';
  await unlockedEvent();
  const banner = (await query({ recheck: true })).result;
  assert.equal(banner.mode, 'update');
  assert.equal(banner.title, 'GitHub');
  assert.equal(banner.password, undefined, 'never to the content script (the edit frame asks for it: save.edit-get)');
  // Shown once: the event of a second unlock doesn't bring it back.
  tabMessages.length = 0;
  await unlockedEvent();
  assert.equal(rechecks().length, 0);
  const done = await send({ type: 'save.commit', token: banner.token }, contentSender('https://github.com/'));
  assert.equal(done.ok, true);
  assert.deepEqual(callsOf('logins.save').at(-1), { url: 'https://github.com/session', username: 'octo', password: PW, id: 'gh' });
});

test('identifier-first while soft-locked: no username on the password page and the site has logins: held', async () => {
  const box = fakeAgent();
  await capture({ username: '' });
  assert.equal((await query()).result, null);
  box.state = 'open';
  await unlockedEvent();
  assert.equal(rechecks().length, 1);
  assert.equal((await query({ recheck: true })).result, null);
  assert.equal(callsOf('logins.save_check').at(-1).username, '');
});

test('soft-locked, no login with this username: "Save login?" right away; it goes away if the unlock shows it is saved', async () => {
  const box = fakeAgent({ list: [{ id: 'gh', title: 'GitHub', username: 'someone-else' }] });
  await capture();
  const banner = (await query()).result;
  assert.equal(banner.mode, 'save', 'shown while locked');
  box.state = 'open';
  await unlockedEvent();
  assert.equal(rechecks().length, 1, 'the banner on screen is checked again');
  assert.deepEqual((await query({ recheck: true })).result, { close: true });
  const late = await send({ type: 'save.commit', token: banner.token }, contentSender('https://github.com/'));
  assert.equal(late.ok, false);
  assert.equal(callsOf('logins.save').length, 0);
});

test('a password change form submitted while soft-locked is never held back', async () => {
  fakeAgent();
  await capture({ kind: 'change' });
  const banner = (await query()).result;
  assert.equal(banner.mode, 'save');
});

test('fully locked: the banner shows; Save unlocks, checks again and writes nothing for a login saved as is', async () => {
  const box = fakeAgent();
  box.state = 'full';
  await capture();
  const banner = (await query()).result;
  assert.equal(banner.mode, 'save', 'nothing to tell without the list');
  const done = await send({ type: 'save.commit', token: banner.token }, contentSender('https://github.com/'));
  assert.deepEqual(done.result, { id: 'gh', unchanged: true, action: 'none' });
  assert.ok(callsOf('unlock').length >= 1, 'Save asked to unlock');
  assert.equal(callsOf('logins.save').length, 0);
});

test('fully locked, then unlocked while the banner is on screen: a new login keeps its banner', async () => {
  const box = fakeAgent({ decision: { action: 'save_new' } });
  box.state = 'full';
  await capture({ username: 'new@user.test' });
  const banner = (await query()).result;
  assert.equal(banner.mode, 'save');
  box.state = 'open';
  await unlockedEvent();
  assert.equal(rechecks().length, 1);
  assert.equal((await query({ recheck: true })).result, null, 'stays as it is');
  const done = await send({ type: 'save.commit', token: banner.token }, contentSender('https://github.com/'));
  assert.equal(done.ok, true);
  assert.deepEqual(callsOf('logins.save').at(-1), { url: 'https://github.com/session', username: 'new@user.test', password: PW });
});

test('unlocked: the agent decides at once, nothing is held', async () => {
  const box = fakeAgent();
  box.state = 'open';
  await capture();
  assert.equal((await query()).result, null, 'saved as is');
  assert.equal(callsOf('logins.find').length, 0, 'the kept list is not needed');
  await unlockedEvent();
  assert.equal(rechecks().length, 0);
});
