import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({});
const tabsById = new Map([[1, { id: 1, url: 'https://shop.example/signup', active: true }]]);
const tabMessages = [];
const created = [];
const updates = [];
const local = {};
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
    alarms: { create: async () => {}, onAlarm: { addListener: () => {} } },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [...tabsById.values()],
      get: async (id) => tabsById.get(id),
      sendMessage: async (tabId, msg, opts) => { tabMessages.push([tabId, msg, opts]); return { ok: true }; },
    },
    contextMenus: {
      removeAll: (cb) => cb?.(),
      create: (props, cb) => { created.push(props); cb?.(); },
      update: (id, props, cb) => { updates.push([id, props]); cb?.(); },
      onClicked: evt(),
    },
    commands: { onCommand: evt() },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {} },
    scripting: { executeScript: async () => [] },
    storage: {
      local: { get: async (keys) => Object.fromEntries((keys || []).filter((k) => k in local).map((k) => [k, local[k]])), set: async (o) => { Object.assign(local, o); } },
      sync: { get: async () => ({}), set: async () => {} },
      onChanged: evt(),
      session: { set: async () => {}, get: async () => ({}), remove: async () => {} },
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
const content = (frameId = 0, url = 'https://shop.example/signup') => ({ tab: tabsById.get(1), frameId, url });
const lastCall = (method) => [...calls].reverse().find((c) => c[0] === method)?.[1];
const callsOf = (method) => calls.filter((c) => c[0] === method);
const tick = () => new Promise((r) => setTimeout(r, 0));

const FEATURES = ['edit', 'generate.username', 'generate.email'];
function desktop({ features = FEATURES, locked = false, aliases = [{ id: 'simplelogin', name: 'SimpleLogin', default: true }], email } = {}) {
  return (m, p) => {
    if (m === 'status') return { locked, features };
    if (m === 'logins.find') return { items: [], pending_otp: null };
    if (m === 'generate.username') return { username: 'Swift-Otter' };
    if (m === 'generate.options') return locked ? { __error: { code: 'locked', message: 'vault is locked' } } : { plus: true, catch_all: false, aliases };
    if (m === 'generate.email') return email ? email(p) : { email: `${p.kind}@example.test` };
    if (m === 'unlock') { locked = false; return {}; }
    return {};
  };
}

test('popup.state says whether the desktop app can generate usernames and e-mail addresses', async () => {
  agent = desktop();
  const res = await send({ type: 'popup.state', tabId: 1 }, POPUP);
  assert.equal(res.result.can_generate_username, true);
  assert.equal(res.result.can_generate_email, true);
  agent = desktop({ features: ['edit'] });
  const old = await send({ type: 'popup.state', tabId: 1 }, POPUP);
  assert.equal(old.result.can_generate_username, false);
  assert.equal(old.result.can_generate_email, false);
});

test('popup.generate-username / -options / -email: the tab page from tabs.get, website only when ticked', async () => {
  agent = desktop();
  assert.deepEqual((await send({ type: 'popup.generate-username' }, POPUP)).result, { username: 'Swift-Otter' });
  assert.deepEqual(lastCall('generate.username'), {});
  const opts = await send({ type: 'popup.generate-options', tabId: 1 }, POPUP);
  assert.equal(opts.result.plus, true);

  await send({ type: 'popup.generate-email', tabId: 1, kind: 'plus', url: 'https://evil.test/' }, POPUP);
  assert.deepEqual(lastCall('generate.email'), { kind: 'plus', url: 'https://shop.example/signup' });
  await send({ type: 'popup.generate-email', tabId: 1, kind: 'alias', service: 'simplelogin', website: true }, POPUP);
  assert.deepEqual(lastCall('generate.email'), { kind: 'alias', url: 'https://shop.example/signup', website: true, service: 'simplelogin' });
  await send({ type: 'popup.generate-email', tabId: 1, kind: 'alias', service: 'Bad Id!', website: 'yes' }, POPUP);
  assert.deepEqual(lastCall('generate.email'), { kind: 'alias', url: 'https://shop.example/signup' }, 'bad service and website dropped');

  const before = callsOf('generate.email').length;
  const bad = await send({ type: 'popup.generate-email', tabId: 1, kind: 'other' }, POPUP);
  assert.equal(bad.error.code, 'invalid_params');
  assert.equal(callsOf('generate.email').length, before, 'never reached the agent');
});

test('popup.generate-options while locked: `locked` back to the popup, no unlock prompt', async () => {
  agent = desktop({ locked: true });
  const res = await send({ type: 'popup.generate-options', tabId: 1 }, POPUP);
  assert.equal(res.error.code, 'locked');
  assert.equal(callsOf('unlock').length, 0);
});

test('agent errors keep their code and text; "unknown method" from an older app is not_supported', async () => {
  agent = desktop({ email: () => ({ __error: { code: 'internal', message: "SimpleLogin didn't accept the API token: check it in Settings" } }) });
  const res = await send({ type: 'popup.generate-email', tabId: 1, kind: 'alias' }, POPUP);
  assert.deepEqual(res.error, { code: 'internal', message: "SimpleLogin didn't accept the API token: check it in Settings" });
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method generate.username' } });
  const old = await send({ type: 'popup.generate-username' }, POPUP);
  assert.deepEqual(old.error, { code: 'not_supported', message: 'unknown method', reason: 'needs_update' });
});

test('generate.* popup handlers are not reachable from content scripts', async () => {
  assert.equal(await send({ type: 'popup.generate-email', tabId: 1, kind: 'alias' }, content()), undefined);
});

test('context menu: "Generate username" / "Generate e-mail alias" follow the right-clicked field and the desktop app', async () => {
  agent = desktop();
  for (const f of chrome.runtime.onInstalled.fns) await f({ reason: 'update' });
  await tick();
  const user = created.find((c) => c.id === 'pass-generate-username');
  const alias = created.find((c) => c.id === 'pass-generate-alias');
  assert.equal(user.title, 'Generate username');
  assert.equal(alias.title, 'Generate e-mail alias');
  for (const c of [user, alias]) {
    assert.deepEqual(c.contexts, ['editable']);
    assert.equal(c.visible, false, 'hidden until a username field is right-clicked');
  }

  updates.length = 0;
  await send({ type: 'menu.target', password: false, username: true }, content());
  assert.deepEqual(updates, [['pass-generate-username', { visible: true }], ['pass-generate-alias', { visible: true }]]);
  await send({ type: 'menu.target', password: true, username: false }, content());
  assert.deepEqual(updates.slice(2), [['pass-generate', { visible: true }], ['pass-generate-plain', { visible: true }], ['pass-generate-username', { visible: false }], ['pass-generate-alias', { visible: false }]]);
});

test('context menu: no alias service set up, or an older desktop app: those items stay hidden', async () => {
  // The cached answers ran out (30 s): a desktop app with no alias service set up.
  agent = desktop({ aliases: [] });
  updates.length = 0;
  const realNow = Date.now;
  Date.now = () => realNow() + 60_000;
  try {
    await send({ type: 'menu.target', password: false, username: true }, content());
    assert.deepEqual(updates.filter(([id]) => !['pass-generate', 'pass-generate-plain'].includes(id)), [['pass-generate-username', { visible: true }]], 'username only');
    await send({ type: 'menu.target', password: false, username: false }, content());
    updates.length = 0;
    agent = desktop({ features: ['edit'] });
    Date.now = () => realNow() + 120_000;
    await send({ type: 'menu.target', password: false, username: true }, content());
    assert.deepEqual(updates, [], 'nothing shown');
  } finally {
    Date.now = realNow;
  }
});

test('context menu click: the frame fills the field; generate.email only right after "Generate e-mail alias" in that frame', async () => {
  agent = desktop();
  tabMessages.length = 0;
  for (const f of chrome.contextMenus.onClicked.fns) f({ menuItemId: 'pass-generate-username', frameId: 2 }, { id: 1 });
  await tick();
  assert.deepEqual(tabMessages.at(-1), [1, { type: 'cmd.generate-username-here', kind: 'username' }, { frameId: 2 }]);
  assert.deepEqual((await send({ type: 'generate.username' }, content(2))).result, { username: 'Swift-Otter' });

  // Without a click, a page can't make its content script create aliases.
  const before = callsOf('generate.email').length;
  const refused = await send({ type: 'generate.email', kind: 'alias' }, content(2));
  assert.equal(refused.ok, false);
  assert.equal(callsOf('generate.email').length, before);

  for (const f of chrome.contextMenus.onClicked.fns) f({ menuItemId: 'pass-generate-alias', frameId: 2 }, { id: 1 });
  await tick();
  assert.deepEqual(tabMessages.at(-1), [1, { type: 'cmd.generate-username-here', kind: 'alias' }, { frameId: 2 }]);
  assert.equal((await send({ type: 'generate.email', kind: 'alias' }, content(0))).ok, false, 'another frame: refused');

  for (const f of chrome.contextMenus.onClicked.fns) f({ menuItemId: 'pass-generate-alias', frameId: 2 }, { id: 1 });
  const res = await send({ type: 'generate.email', kind: 'plus', url: 'https://evil.test/' }, content(2, 'https://login.shop.example/frame'));
  assert.deepEqual(res.result, { email: 'alias@example.test' });
  assert.deepEqual(lastCall('generate.email'), { kind: 'alias', url: 'https://login.shop.example/frame' }, 'always an alias, the frame page, no website');
  assert.equal((await send({ type: 'generate.email', kind: 'alias' }, content(2))).ok, false, 'one alias per click');

  local.mentionWebsite = true;
  for (const f of chrome.contextMenus.onClicked.fns) f({ menuItemId: 'pass-generate-alias', frameId: 2 }, { id: 1 });
  await send({ type: 'generate.email', kind: 'alias' }, content(2));
  assert.deepEqual(lastCall('generate.email'), { kind: 'alias', url: 'https://shop.example/signup', website: true });
  delete local.mentionWebsite;
});

test('context menu alias while locked: the desktop app unlock prompt, then the alias', async () => {
  let locked = true;
  agent = (m, p) => {
    if (m === 'unlock') { locked = false; return {}; }
    if (m === 'generate.email') return locked ? { __error: { code: 'locked', message: 'locked' } } : { email: 'new@alias.test' };
    return desktop()(m, p);
  };
  for (const f of chrome.contextMenus.onClicked.fns) f({ menuItemId: 'pass-generate-alias', frameId: 0 }, { id: 1 });
  const res = await send({ type: 'generate.email', kind: 'alias' }, content(0));
  assert.deepEqual(res.result, { email: 'new@alias.test' });
  assert.equal(callsOf('unlock').length, 1);
});

test('generate.copy: the desktop app copies a generated password, and an older app is not_supported', async () => {
  const sendFromPage = (msg) => new Promise((resolve) => {
    onMessage(msg, { id: 'pass-ext', tab: { id: 1, url: 'https://shop.example/signup' }, frameId: 0, url: 'https://shop.example/signup' }, resolve);
  });
  agent = () => ({ copied: true });
  calls.length = 0;
  const done = await sendFromPage({ type: 'generate.copy', password: 'Gen-Pass-2468-xyz' });
  assert.deepEqual(done, { ok: true, result: { copied: true } });
  assert.deepEqual(calls.at(-1), ['generate.copy', { password: 'Gen-Pass-2468-xyz' }]);

  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method generate.copy' } });
  const older = await sendFromPage({ type: 'generate.copy', password: 'Gen-Pass-2468-xyz' });
  assert.equal(older.ok, false);
  assert.equal(older.error.code, 'not_supported');

  calls.length = 0;
  for (const password of ['', 7, undefined, 'x'.repeat(129)]) {
    const refused = await sendFromPage({ type: 'generate.copy', password });
    assert.equal(refused.error.code, 'invalid_params', String(password));
  }
  assert.deepEqual(calls, [], 'never sent to the agent');
});

test('generate { symbols: false }: sent to the agent; an older one that ignores it is replaced by a password generated here', async () => {
  const PLAIN = 'AgentPlainPw23456789';
  agent = (m, p) => (m === 'generate' ? { password: p.symbols === false ? PLAIN : 'With-Symbols-Pw-12345!' } : {});
  calls.length = 0;
  const plain = await send({ type: 'generate', length: 20, symbols: false }, content());
  assert.deepEqual(plain.result, { password: PLAIN });
  assert.deepEqual(lastCall('generate'), { length: 20, symbols: false });
  const strong = await send({ type: 'generate', length: 20, symbols: 'no' }, content());
  assert.deepEqual(lastCall('generate'), { length: 20 }, 'only `false` turns symbols off');
  assert.equal(strong.result.password, 'With-Symbols-Pw-12345!');

  agent = (m) => (m === 'generate' ? { password: 'With-Symbols-Pw-12345!' } : {});
  const older = await send({ type: 'popup.generate', length: 24, symbols: false }, POPUP);
  assert.equal(older.result.local, true, 'generated here: the desktop app cannot copy it');
  assert.match(older.result.password, /^[A-Za-z0-9]{24}$/);
});

test('generate.filled { symbols }: "Letters and numbers only" is remembered for the site, the strong password forgets it', async () => {
  agent = () => ({});
  delete local.generateNoSymbols;
  const filled = (symbols, url = 'https://shop.example/signup') => send({ type: 'generate.filled', password: 'AgentPlainPw23456789', symbols },
    { tab: { id: 1, url }, frameId: 0, url });
  await filled(false);
  assert.deepEqual(local.generateNoSymbols, ['shop.example']);
  await filled(false, 'https://accounts.bank.example.co.uk/join');
  assert.deepEqual(local.generateNoSymbols, ['shop.example', 'example.co.uk']);
  await filled(true);
  assert.deepEqual(local.generateNoSymbols, ['example.co.uk']);
  await send({ type: 'generate.filled', password: 'AgentPlainPw23456789' }, content());
  assert.deepEqual(local.generateNoSymbols, ['example.co.uk'], 'no choice given: nothing changes');
});

test('generate.filled { options }: the generator options changed in the page are remembered for every site', async () => {
  agent = () => ({});
  delete local.generateOptions;
  const url = 'https://shop.example/signup';
  const sender = { tab: { id: 1, url }, frameId: 0, url };
  await send({ type: 'generate.filled', password: 'Agent-Pw-1234567890!', options: { mode: 'passphrase', words: 7, length: 3 } }, sender);
  assert.deepEqual(local.generateOptions, { mode: 'passphrase', length: 20, lowercase: true, uppercase: true, digits: true, words: 7 });
  await send({ type: 'generate.filled', password: 'Agent-Pw-1234567890!', options: ['passphrase'] }, sender);
  await send({ type: 'generate.filled', password: 'Agent-Pw-1234567890!' }, sender);
  assert.equal(local.generateOptions.words, 7, 'no options given (or not an object): nothing changes');
});
