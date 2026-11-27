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
const windowsCreated = [];
const popupsOpened = [];
let openPopup = async (opts) => { popupsOpened.push(opts); };
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
    windows: {
      get: async () => ({ left: 100, top: 50, width: 1200, height: 800 }),
      create: async (opts) => { windowsCreated.push(opts); return { id: 9 }; },
    },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, onClicked: evt() },
    commands: { onCommand: evt() },
    action: {
      setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {},
      openPopup: (opts) => openPopup(opts),
    },
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

const popupSender = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const contentSender = { tab: tabsById.get(1), frameId: 0, url: 'https://github.com/login' };
const tick = () => new Promise((r) => setTimeout(r, 0));
const methods = () => calls.map((c) => c[0]);

/** A desktop app with the extension's unlock form; `locked` until unlock.password / unlock.hello. */
function inlineAgent({ hello = true, password = 'master' } = {}) {
  const state = { locked: true, unlockPrompts: 0 };
  agent = (m, p) => {
    if (m === 'status') return { locked: state.locked, soft_locked: state.locked, version: '1', features: ['edit', 'logins.search', 'locked.list', 'unlock.inline'] };
    if (m === 'unlock.options') return { locked: state.locked, password: true, hello: state.locked && hello };
    if (m === 'unlock.password') {
      if (p.password !== password) return { __error: { code: 'wrong_password', message: 'Wrong master password. Check Caps Lock and try again.' } };
      state.locked = false;
      return { locked: false };
    }
    if (m === 'unlock.hello') {
      if (!hello) return { __error: { code: 'not_supported', message: 'Windows Hello is off for this vault. Use your master password.' } };
      state.locked = false;
      return { locked: false };
    }
    if (m === 'unlock') { state.unlockPrompts += 1; state.locked = false; return { locked: false }; }
    if (m === 'logins.find') return { items: [{ id: 'gh', title: 'GitHub', username: 'octo' }], pending_otp: null, locked: state.locked };
    if (state.locked) return { __error: { code: 'locked', message: 'Vault is locked' } };
    if (m === 'logins.fill') return { username: 'octo', password: 'hunter2', totp: null };
    if (m === 'totp.get') return { id: 'gh', title: 'GitHub', code: '123456', period: 30, remaining_secs: 20 };
    return {};
  };
  return state;
}

test('popup.state says what the unlock form can offer', async () => {
  inlineAgent();
  const res = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(res.result.can_unlock_inline, true);
  assert.equal(res.result.unlock_hello, true);
  assert.equal(res.result.ask_unlock, false);
  assert.equal(res.result.soft_locked, true);
});

test('popup.unlock-password: the password goes to the agent once; wrong ones come back as wrong_password', async () => {
  inlineAgent();
  tabMessages.length = 0;
  const wrong = await send({ type: 'popup.unlock-password', password: 'nope' }, popupSender);
  assert.deepEqual(wrong, { ok: false, error: { code: 'wrong_password', message: 'Wrong master password. Check Caps Lock and try again.' } });
  for (const password of ['', 7, 'x'.repeat(1025)]) {
    const bad = await send({ type: 'popup.unlock-password', password }, popupSender);
    assert.equal(bad.error.code, 'invalid_params');
  }
  const before = calls.length;
  const ok = await send({ type: 'popup.unlock-password', password: 'master' }, popupSender);
  assert.deepEqual(ok, { ok: true, result: { locked: false } });
  assert.deepEqual(calls.slice(before).filter((c) => c[0].startsWith('unlock')), [['unlock.password', { password: 'master' }]]);
  await tick();
  assert.ok(tabMessages.some(([, msg]) => msg.type === 'lock_state' && msg.locked === false), 'the pages hear it at once');
  assert.ok(!methods().includes('unlock'), "the desktop app's prompt is not used");
});

test('the unlock methods are only for the popup; content scripts get options, Windows Hello and the form', async () => {
  inlineAgent();
  assert.equal(await send({ type: 'popup.unlock-password', password: 'master' }, contentSender), undefined);
  const opts = await send({ type: 'unlock.options' }, contentSender);
  assert.deepEqual(opts.result, { inline: true, locked: true, hello: true, hello_auto: true, hello_pending: false });
  tabMessages.length = 0;
  const hello = await send({ type: 'unlock.hello' }, contentSender);
  assert.deepEqual(hello.result, { locked: false });
  assert.ok(methods().includes('unlock.hello'));
  await tick();
  assert.ok(tabMessages.some(([, msg]) => msg.type === 'lock_state' && msg.locked === false));
});

test('an older desktop app: no inline unlock, the method answers not_supported', async () => {
  agent = (m) => (m === 'status' ? { locked: true, version: '0.9', features: ['edit'] }
    : { __error: { code: 'invalid_params', message: `unknown method ${m}` } });
  const opts = await send({ type: 'unlock.options' }, contentSender);
  assert.deepEqual(opts.result, { inline: false, locked: true, hello: false, hello_auto: false, hello_pending: false });
  const res = await send({ type: 'popup.unlock-password', password: 'master' }, popupSender);
  assert.equal(res.error.code, 'not_supported');
  const state = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(state.result.can_unlock_inline, false);
});

test('popup.unlock-hello with a pending fill: the background finishes it (the popup may be gone)', async () => {
  inlineAgent();
  tabMessages.length = 0;
  const res = await send({ type: 'popup.unlock-hello', then: { fill: { tabId: 1, id: 'gh' } } }, popupSender);
  assert.equal(res.ok, true);
  assert.equal(res.result.filled, true);
  assert.ok(tabMessages.some(([tabId, msg]) => tabId === 1 && msg.type === 'cmd.fill-item' && msg.id === 'gh'));
});

/** Lets promise callbacks run, but no timer. */
async function microtasks(n = 300) {
  for (let i = 0; i < n; i++) await Promise.resolve();
}

test('popup.unlock-hello with a pending fill: the page is told to fill the moment Windows Hello answers', async () => {
  const state = inlineAgent();
  const real = agent;
  let answer = null;
  agent = (m, p) => (m === 'unlock.hello'
    ? new Promise((resolve) => { answer = () => { state.locked = false; resolve({ locked: false }); }; })
    : real(m, p));
  tabMessages.length = 0;
  const done = send({ type: 'popup.unlock-hello', then: { fill: { tabId: 1, id: 'gh' } } }, popupSender);
  await microtasks();
  assert.ok(answer, 'Windows Hello is up');
  assert.equal(tabMessages.filter(([, msg]) => msg.type === 'cmd.fill-item').length, 0);
  answer();
  await microtasks();
  assert.ok(tabMessages.some(([tabId, msg]) => tabId === 1 && msg.type === 'cmd.fill-item' && msg.id === 'gh'), 'no timer before the fill');
  assert.equal((await done).result.filled, true);
  agent = real;
});

test('inline popup requests answer locked instead of opening the desktop app; others still unlock there', async () => {
  const state = inlineAgent();
  const res = await send({ type: 'popup.copy', tabId: 1, id: 'gh', field: 'password', inline: true }, popupSender);
  assert.equal(res.error.code, 'locked');
  assert.equal(state.unlockPrompts, 0);
  const totp = await send({ type: 'popup.totp', tabId: 1, id: 'gh', inline: true }, popupSender);
  assert.equal(totp.error.code, 'locked');
  const edit = await send({ type: 'popup.edit-get', tabId: 1, id: 'gh', inline: true }, popupSender);
  assert.equal(edit.error.code, 'locked');
  assert.equal(state.unlockPrompts, 0);
  // Without `inline` (older popups, the page's own requests): the desktop app's prompt, then the retry.
  const old = await send({ type: 'popup.copy', tabId: 1, id: 'gh', field: 'password' }, popupSender);
  assert.deepEqual(old.result, { value: 'hunter2' });
  assert.equal(state.unlockPrompts, 1);
});

test('unlock.open-form: the popup opens for the tab and shows the form first', async () => {
  inlineAgent();
  popupsOpened.length = 0;
  windowsCreated.length = 0;
  const res = await send({ type: 'unlock.open-form' }, contentSender);
  assert.deepEqual(res.result, { opened: 'popup' });
  assert.deepEqual(popupsOpened, [{ windowId: 5 }]);
  assert.equal(windowsCreated.length, 0);
  const state = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(state.result.ask_unlock, true, 'the popup opened for the page shows the unlock form');
  const again = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(again.result.ask_unlock, false, 'only once');
});

test('unlock.open-form where the popup cannot be opened: a small window of the unlock form', async () => {
  inlineAgent();
  openPopup = async () => { throw new Error('openPopup requires a user gesture'); };
  windowsCreated.length = 0;
  const res = await send({ type: 'unlock.open-form' }, contentSender);
  assert.deepEqual(res.result, { opened: 'window' });
  assert.equal(windowsCreated.length, 1);
  const w = windowsCreated[0];
  assert.equal(w.url, 'chrome-extension://pass-ext/src/popup/popup.html?unlock=1');
  assert.equal(w.type, 'popup');
  assert.equal(w.focused, true);
  assert.ok(w.left >= 100 && w.top >= 50, 'over the browser window');
  const state = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(state.result.ask_unlock, false);
  openPopup = async (opts) => { popupsOpened.push(opts); };
});

test('popup.unlock-options for the unlock window', async () => {
  inlineAgent({ hello: false });
  const res = await send({ type: 'popup.unlock-options' }, popupSender);
  assert.deepEqual(res.result, { inline: true, locked: true, hello: false, hello_auto: false, hello_pending: false });
});

test('unlock.cancel: "Use master password instead" calls the pending Windows Hello off; older desktop apps answer nothing to do', async () => {
  const state = inlineAgent();
  const plain = agent;
  agent = (m, p) => (m === 'unlock.cancel' ? { cancelled: true } : plain(m, p));
  const res = await send({ type: 'unlock.cancel' }, contentSender);
  assert.deepEqual(res, { ok: true, result: { cancelled: true } });
  assert.equal(calls.at(-1)[0], 'unlock.cancel');
  agent = (m, p) => (m === 'unlock.cancel' ? { __error: { code: 'invalid_params', message: 'unknown method unlock.cancel' } } : plain(m, p));
  const old = await send({ type: 'unlock.cancel' }, contentSender);
  assert.deepEqual(old, { ok: true, result: { cancelled: false } });
  assert.equal(state.locked, true);
});

test('the in-page menu\'s master password frame (an extension page in the tab) unlocks like the popup form', async () => {
  inlineAgent();
  tabMessages.length = 0;
  const frameSender = { url: 'chrome-extension://pass-ext/src/unlock/frame.html?focus=1', tab: tabsById.get(1), frameId: 3 };
  const wrong = await send({ type: 'popup.unlock-password', password: 'nope' }, frameSender);
  assert.equal(wrong.error.code, 'wrong_password');
  const ok = await send({ type: 'popup.unlock-password', password: 'master' }, frameSender);
  assert.deepEqual(ok, { ok: true, result: { locked: false } });
  await tick();
  assert.ok(tabMessages.some(([tabId, msg]) => tabId === 1 && msg.type === 'lock_state' && msg.locked === false), 'the page fills what was picked');
});

/** Runs `fn` with the clock `ms` ahead (the background reads Date.now()). */
async function later(ms, fn) {
  const real = Date.now;
  Date.now = () => real() + ms;
  try { return await fn(); } finally { Date.now = real; }
}

test('one Windows Hello at a time: the popup and the page join the one that is up', async () => {
  await later(60_000, async () => {
    const state = inlineAgent();
    const plain = agent;
    let answer;
    agent = (m, p) => (m === 'unlock.hello' ? new Promise((resolve) => { answer = resolve; }) : plain(m, p));
    const before = calls.length;
    const fromPage = send({ type: 'unlock.hello' }, contentSender);
    await tick();
    const opts = await send({ type: 'unlock.options' }, contentSender);
    assert.equal(opts.result.hello_pending, true, 'the page can see it is up');
    const popupState = await send({ type: 'popup.state', tabId: 1 }, popupSender);
    assert.equal(popupState.result.unlock_hello_pending, true);
    const fromPopup = send({ type: 'popup.unlock-hello' }, popupSender);
    await tick();
    assert.equal(calls.slice(before).filter((c) => c[0] === 'unlock.hello').length, 1, 'one prompt for both');
    state.locked = false;
    answer({ locked: false });
    assert.deepEqual((await fromPage).result, { locked: false });
    assert.deepEqual((await fromPopup).result, { locked: false });
    agent = plain;
  });
});

test('after a cancel in Windows Hello (or "Use master password instead"), it doesn\'t start on its own for 30 s', async () => {
  await later(120_000, async () => {
    const state = inlineAgent();
    const plain = agent;
    agent = (m, p) => (m === 'unlock.hello' ? { __error: { code: 'cancelled', message: 'unlock cancelled' } } : plain(m, p));
    const res = await send({ type: 'unlock.hello' }, contentSender);
    assert.equal(res.error.code, 'cancelled');
    agent = plain;
    const opts = await send({ type: 'unlock.options' }, contentSender);
    assert.equal(opts.result.hello, true, 'still offered: one click away');
    assert.equal(opts.result.hello_auto, false, 'but not on its own');
    const popupState = await send({ type: 'popup.state', tabId: 1 }, popupSender);
    assert.equal(popupState.result.unlock_hello, true);
    assert.equal(popupState.result.unlock_hello_auto, false);
    assert.equal(state.locked, true);
  });
  await later(120_000 + 31_000, async () => {
    inlineAgent();
    const opts = await send({ type: 'unlock.options' }, contentSender);
    assert.equal(opts.result.hello_auto, true, 'on its own again later');
    // The page's "Use master password instead" counts as a no too.
    const plain = agent;
    agent = (m, p) => (m === 'unlock.cancel' ? { cancelled: true } : plain(m, p));
    await send({ type: 'unlock.cancel' }, contentSender);
    agent = plain;
    assert.equal((await send({ type: 'unlock.options' }, contentSender)).result.hello_auto, false);
  });
  await later(240_000, async () => {
    inlineAgent();
    const plain = agent;
    agent = (m, p) => (m === 'unlock.cancel' ? { cancelled: true } : plain(m, p));
    const res = await send({ type: 'popup.unlock-cancel' }, popupSender);
    assert.deepEqual(res.result, { cancelled: true });
    assert.equal(await send({ type: 'popup.unlock-cancel' }, contentSender), undefined, 'not for content scripts');
    agent = plain;
    assert.equal((await send({ type: 'unlock.options' }, contentSender)).result.hello_auto, false);
  });
});

/** The params of the last call of `method` since `from`. */
function lastParams(method, from) {
  return calls.slice(from).filter((c) => c[0] === method).at(-1)?.[1];
}

test('an unlock for a login picked while locked says which one (`for`), however it is done', async () => {
  // The in-page menu: `unlock.options` names the login, Windows Hello then says it is for that one.
  inlineAgent();
  let from = calls.length;
  await send({ type: 'unlock.options', for: 'gh' }, contentSender);
  assert.deepEqual((await send({ type: 'unlock.hello' }, contentSender)).result, { locked: false });
  assert.deepEqual(lastParams('unlock.hello', from), { for: 'gh' });
  // The menu's master password frame (an extension page in that tab).
  inlineAgent();
  from = calls.length;
  await send({ type: 'unlock.options', for: 'gh' }, contentSender);
  const frameSender = { url: 'chrome-extension://pass-ext/src/unlock/frame.html', tab: tabsById.get(1), frameId: 3 };
  await send({ type: 'popup.unlock-password', password: 'master' }, frameSender);
  assert.deepEqual(lastParams('unlock.password', from), { password: 'master', for: 'gh' });
  // "Open Passyble" from the menu: the desktop app's prompt, for that login too.
  inlineAgent();
  from = calls.length;
  await send({ type: 'unlock.options', for: 'gh' }, contentSender);
  await send({ type: 'unlock' }, contentSender);
  assert.deepEqual(lastParams('unlock', from), { for: 'gh' });
  // The menu opened for nothing in particular (fully locked, "Unlock"): no `for`, also not an old one.
  inlineAgent();
  from = calls.length;
  await send({ type: 'unlock.options', for: 'gh' }, contentSender);
  await send({ type: 'unlock.options' }, contentSender);
  await send({ type: 'unlock.hello' }, contentSender);
  assert.deepEqual(lastParams('unlock.hello', from), {});
  // The popup names the login its unlock form stands in for.
  inlineAgent();
  from = calls.length;
  await send({ type: 'popup.unlock-password', password: 'master', for: 'gh' }, popupSender);
  assert.deepEqual(lastParams('unlock.password', from), { password: 'master', for: 'gh' });
  inlineAgent();
  from = calls.length;
  await send({ type: 'popup.unlock-hello', for: 'gh' }, popupSender);
  assert.deepEqual(lastParams('unlock.hello', from), { for: 'gh' });
  // A fill that meets a locked vault: the desktop app's unlock prompt, for that login.
  const state = inlineAgent();
  from = calls.length;
  const fill = await send({ type: 'logins.fill', id: 'gh' }, contentSender);
  assert.equal(fill.result.password, 'hunter2');
  assert.equal(state.unlockPrompts, 1);
  assert.deepEqual(lastParams('unlock', from), { for: 'gh' });
  // Nothing that can't be an item id goes out.
  inlineAgent();
  from = calls.length;
  await send({ type: 'popup.unlock-hello', for: 'x'.repeat(200) }, popupSender);
  assert.deepEqual(lastParams('unlock.hello', from), {});
});
