// Feedback for copies the popup asked for: Windows Hello and the desktop app's prompt take the focus and close the
// popup, so the outcome of a copy that finishes after that goes to the page (`cmd.notice`) or to the next popup.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({});
const tabsById = new Map([[1, { id: 1, url: 'https://github.com/login', active: true, windowId: 5 }]]);
const tabMessages = [];
let tabReply = async () => ({ ok: true });
let onMessage;
const onConnect = evt();

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
      onConnect,
      onInstalled: evt(), onStartup: evt(),
      sendMessage: async () => undefined,
    },
    alarms: { create: async () => {}, onAlarm: evt() },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [...tabsById.values()],
      get: async (id) => tabsById.get(id),
      sendMessage: async (tabId, msg, opts) => { tabMessages.push([tabId, msg, opts]); return tabReply(tabId, msg, opts); },
    },
    windows: { get: async () => ({ left: 0, top: 0, width: 1200, height: 800 }), create: async () => ({ id: 9 }) },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, onClicked: evt() },
    commands: { onCommand: evt() },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {}, openPopup: async () => {} },
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

const POPUP_URL = 'chrome-extension://pass-ext/src/popup/popup.html';
const popupSender = { url: POPUP_URL, documentId: 'doc-1' };
const tick = () => new Promise((r) => setTimeout(r, 0));
const notices = () => tabMessages.filter(([, msg]) => msg.type === 'cmd.notice').map(([tabId, msg, opts]) => ({ tabId, text: msg.text, frameId: opts?.frameId }));

/** A popup's port (POPUP_PORT): `close()` is the popup closing. */
function openPopupPort(documentId = 'doc-1') {
  const port = { name: 'passyble-popup', sender: { id: 'pass-ext', url: POPUP_URL, documentId }, onDisconnect: evt(), posted: [] };
  port.postMessage = (m) => port.posted.push(m);
  port.close = () => port.onDisconnect.fns.forEach((f) => f());
  onConnect.fns.forEach((f) => f(port));
  return port;
}

/** An unlocked desktop app whose `logins.copy` / `cards.fill` answer as `copy` says. */
function copyingAgent({ copy = () => ({ copied: true }), locked = false } = {}) {
  const state = { locked };
  agent = (m, p) => {
    if (m === 'status') return { locked: state.locked, version: '1', features: ['edit', 'logins.search', 'unlock.inline', 'cards'] };
    if (m === 'unlock.hello') { state.locked = false; return { locked: false }; }
    if (m === 'logins.find') return { items: [], pending_otp: null, locked: state.locked };
    if (state.locked) return { __error: { code: 'locked', message: 'Vault is locked' } };
    if (m === 'logins.copy' || m === 'cards.fill') return copy(m, p);
    return {};
  };
  return state;
}

function reset() {
  tabMessages.length = 0;
  calls.length = 0;
  tabReply = async () => ({ ok: true });
}

test('a copy that finishes after the popup closed: the page says so', async () => {
  reset();
  copyingAgent();
  const res = await send({ type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'password', own: true }, popupSender);
  assert.equal(res.ok, true);
  await tick();
  assert.deepEqual(notices(), [{ tabId: 1, text: 'Password copied by Passyble (clears in 45 s)', frameId: 0 }]);
});

test('the popup that asked is still open: it says it itself, no notice on the page', async () => {
  reset();
  copyingAgent();
  const port = openPopupPort('doc-1');
  try {
    await send({ type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'totp', own: true }, popupSender);
    await tick();
    assert.deepEqual(notices(), []);
    // Another popup (a new one) is open, not the one that asked: the page says it.
    await send({ type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'totp', own: true }, { ...popupSender, documentId: 'doc-old' });
    await tick();
    assert.deepEqual(notices().map((n) => n.text), ['2FA code copied by Passyble (clears in 45 s)']);
  } finally {
    port.close();
  }
});

test('cancelled in Windows Hello or the desktop app: "not copied"; other errors their own message', async () => {
  reset();
  copyingAgent({ copy: () => ({ __error: { code: 'cancelled', message: 'Cancelled' } }) });
  const res = await send({ type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'password', own: true }, popupSender);
  assert.equal(res.error.code, 'cancelled');
  await tick();
  assert.deepEqual(notices().map((n) => n.text), ['Password not copied']);
  reset();
  copyingAgent({ copy: () => ({ __error: { code: 'not_found', message: 'Not found' } }) });
  await send({ type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'password', own: true }, popupSender);
  await tick();
  assert.equal(notices().length, 1);
  assert.ok(!/copied by Passyble/.test(notices()[0].text));
});

test('a card value the desktop app copied: the page says so, with when it clears', async () => {
  reset();
  tabsById.set(2, { id: 2, url: 'https://shop.example.com/checkout', active: false, windowId: 5 });
  copyingAgent({ copy: (m, p) => ({ copied: true, field: p.field }) });
  const res = await send({ type: 'popup.card-copy', tabId: 2, id: 'card1', field: 'number' }, popupSender);
  assert.deepEqual(res.result, { copied: true });
  await tick();
  assert.deepEqual(notices().map((n) => n.text), ['Card number copied (clears in 45 s)']);
});

test('no content script on the tab: the next popup that opens shows it, once', async () => {
  reset();
  copyingAgent();
  tabReply = async () => { throw new Error('Could not establish connection. Receiving end does not exist.'); };
  await send({ type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'password', own: true }, popupSender);
  await tick();
  await tick();
  const port = openPopupPort('doc-2');
  assert.deepEqual(port.posted, [{ type: 'feedback', text: 'Password copied by Passyble (clears in 45 s)' }]);
  port.close();
  const again = openPopupPort('doc-3');
  assert.deepEqual(again.posted, [], 'shown once');
  again.close();
});

test('popup.unlock-hello with a pending copy (then.copy): copied here once Windows Hello answers, and the page told', async () => {
  reset();
  copyingAgent({ locked: true });
  const then = { copy: { type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'password', own: true } };
  const res = await send({ type: 'popup.unlock-hello', then, for: 'gh' }, popupSender);
  assert.equal(res.ok, true);
  assert.deepEqual(res.result.copy, { result: { copied: true } });
  const methods = calls.map((c) => c[0]);
  assert.ok(methods.indexOf('unlock.hello') < methods.indexOf('logins.copy'), 'unlocked, then copied');
  assert.deepEqual(calls.find((c) => c[0] === 'logins.copy')[1], { id: 'gh', field: 'password', url: 'https://github.com/login' });
  await tick();
  assert.deepEqual(notices().map((n) => n.text), ['Password copied by Passyble (clears in 45 s)']);
});

test('then.copy only finishes the popup\'s copies, and an error comes back in the answer', async () => {
  reset();
  copyingAgent({ locked: true, copy: () => ({ __error: { code: 'not_found', message: 'Not found' } }) });
  const odd = await send({ type: 'popup.unlock-hello', then: { copy: { type: 'popup.edit-delete', tabId: 1, id: 'gh' } } }, popupSender);
  assert.equal(odd.result.copy, undefined, 'not a copy: nothing done');
  assert.ok(!calls.some((c) => c[0] === 'logins.delete'));
  reset();
  copyingAgent({ locked: true, copy: () => ({ __error: { code: 'not_found', message: 'Not found' } }) });
  const res = await send({ type: 'popup.unlock-hello', then: { copy: { type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'password', own: true } } }, popupSender);
  assert.equal(res.ok, true, 'the unlock itself worked');
  assert.equal(res.result.copy.error.code, 'not_found');
});

test('Windows Hello cancelled for a pending copy: "not copied" on the page', async () => {
  reset();
  copyingAgent({ locked: true });
  const real = agent;
  agent = (m, p) => (m === 'unlock.hello' ? { __error: { code: 'cancelled', message: 'Cancelled' } } : real(m, p));
  const then = { copy: { type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'totp', own: true } };
  const res = await send({ type: 'popup.unlock-hello', then }, popupSender);
  assert.equal(res.error.code, 'cancelled');
  await tick();
  assert.deepEqual(notices().map((n) => n.text), ['2FA code not copied']);
  assert.ok(!calls.some((c) => c[0] === 'logins.copy'));
});
