// "Save selection to Passyble note": the context menu on selected text, the chooser window it opens, and the
// clip.* requests that add the selection to a note (`notes.append`) or save a new one (`notes.create`).
import { test, before, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({});
const created = [];
const windowsCreated = [];
const logged = [];
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
  for (const level of ['log', 'info', 'warn', 'error', 'debug']) {
    const original = console[level];
    console[level] = (...args) => { logged.push(args.map(String).join(' ')); if (level === 'error') original(...args); };
  }
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
      query: async () => [TAB],
      get: async () => TAB,
      sendMessage: async () => ({ ok: true }),
    },
    windows: {
      get: async () => ({ left: 100, top: 50, width: 1200, height: 800 }),
      create: async (opts) => { windowsCreated.push(opts); return { id: 9 }; },
    },
    contextMenus: {
      removeAll: (cb) => cb?.(),
      create: (props, cb) => { created.push(props); cb?.(); },
      update: (id, props, cb) => cb?.(),
      onClicked: evt(),
    },
    commands: { onCommand: evt() },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {} },
    scripting: { executeScript: async () => [] },
    storage: {
      local: { get: async () => ({}), set: async () => {}, remove: async () => {} },
      sync: { get: async () => ({}), set: async () => {} },
      onChanged: evt(),
    },
  };
  await import('../src/background.js');
});

beforeEach(() => {
  calls.length = 0;
  windowsCreated.length = 0;
});

const TAB = { id: 1, url: 'https://blog.example/post/42', title: '  Demo post\n about notes ', windowId: 5, active: true };
const PAGE = { url: 'chrome-extension://pass-ext/src/clip/clip.html?clip=x' };
const CONTENT = { tab: TAB, frameId: 0, url: TAB.url };
const SELECTION = 'Demo quote from a page';

function send(msg, sender = PAGE) {
  return new Promise((resolve) => {
    const async = onMessage(msg, { id: 'pass-ext', ...sender }, resolve);
    if (!async) resolve(undefined);
  });
}

const tick = () => new Promise((r) => setTimeout(r, 0));
const methods = () => calls.map((c) => c[0]);
const lastCall = (method) => [...calls].reverse().find((c) => c[0] === method)?.[1];
const FEATURES = ['edit', 'notes.list', 'notes.create', 'notes.append'];
const NOTES = [
  { id: 'n-old', title: 'Old ideas', favorite: true, updated: 1_000, vault_id: 'home' },
  { id: 'n-new', title: 'Reading list', favorite: false, updated: 3_000, vault_id: 'home' },
  { id: 'n-team', title: 'Team links', favorite: false, updated: 2_000, vault_id: 'team' },
];
const VAULTS = [{ id: 'home', name: '', home: true, can_edit: true }, { id: 'team', name: 'Support', home: false, can_edit: false }];

/** A desktop app; `locked` until `unlock`. */
function desktop({ features = FEATURES, locked = false, soft = false, append } = {}) {
  const app = { locked, unlocks: 0 };
  agent = (m, p) => {
    if (m === 'status') return { locked: app.locked, soft_locked: app.locked && soft, features };
    if (m === 'unlock') { app.unlocks += 1; app.locked = false; return { locked: false }; }
    if (!features.includes(m) && m.startsWith('notes.')) return { __error: { code: 'invalid_params', message: `unknown method ${m}` } };
    if (m === 'notes.list') {
      if (app.locked && !soft) return { __error: { code: 'locked', message: 'Vault is locked' } };
      return { items: NOTES, truncated: false, locked: app.locked, vaults: VAULTS };
    }
    if (app.locked) return { __error: { code: 'locked', message: 'Vault is locked' } };
    if (m === 'notes.append') return append ? append(p) : { id: p.id, title: 'Reading list', kind: 'note', vault: VAULTS[0] };
    if (m === 'notes.create') return { id: 'n-made', title: p.fields.title, kind: 'note', vault: VAULTS[0] };
    return {};
  };
  return app;
}

async function rightClick(info = {}) {
  for (const f of chrome.contextMenus.onClicked.fns) {
    await f({ menuItemId: 'pass-save-selection', selectionText: SELECTION, pageUrl: TAB.url, frameId: 0, ...info }, TAB);
  }
  for (let i = 0; i < 5; i++) await tick();
  const opened = windowsCreated.at(-1);
  return opened ? new URL(opened.url).searchParams.get('clip') : null;
}

test('the menu shows on selected text of web pages only', async () => {
  for (const f of chrome.runtime.onInstalled.fns) await f({ reason: 'update' });
  const menu = created.find((m) => m.id === 'pass-save-selection');
  assert.ok(menu, 'created');
  assert.deepEqual(menu.contexts, ['selection']);
  assert.deepEqual(menu.documentUrlPatterns, ['http://*/*', 'https://*/*']);
  assert.equal(menu.title, 'Save selection to Passyble note');
  assert.notEqual(menu.visible, false);
});

test('a click opens the chooser window; the selection stays out of its address and goes nowhere yet', async () => {
  desktop();
  const token = await rightClick({ selectionText: `  ${SELECTION}\u0007 \r\n` });
  const opened = windowsCreated.at(-1);
  assert.equal(opened.type, 'popup');
  assert.equal(opened.focused, true);
  assert.match(opened.url, /^chrome-extension:\/\/pass-ext\/src\/clip\/clip\.html\?clip=[0-9a-f-]{36}$/);
  assert.ok(!opened.url.includes('Demo'), 'no selection in the URL');
  assert.equal(opened.left, 510, 'centred on the browser window');
  assert.deepEqual(calls, [], 'nothing sent to the agent');

  // Only an extension page gets it, once.
  assert.equal(await send({ type: 'clip.take', token }, CONTENT), undefined, 'content scripts have no clip.take');
  const taken = await send({ type: 'clip.take', token });
  assert.deepEqual(taken.result, { text: SELECTION, url: TAB.url, site: 'blog.example', title: 'Demo post about notes' });
  const again = await send({ type: 'clip.take', token });
  assert.equal(again.error.code, 'not_found', 'spent');
  assert.equal((await send({ type: 'clip.take', token: 'made-up' })).error.code, 'not_found');
  assert.ok(!logged.some((line) => line.includes('Demo quote')), 'never logged');
});

test('no selection text: no window', async () => {
  desktop();
  assert.equal(await rightClick({ selectionText: ' \n\t ' }), null);
  assert.equal(windowsCreated.length, 0);
});

test('clip.state lists note titles, the most recently changed first', async () => {
  desktop();
  const res = (await send({ type: 'clip.state' })).result;
  assert.equal(res.can_append, true);
  assert.equal(res.can_create, true);
  assert.equal(res.locked, false);
  assert.deepEqual(res.notes.map((n) => n.id), ['n-new', 'n-team', 'n-old']);
  assert.deepEqual(res.vaults, VAULTS);
  assert.deepEqual(lastCall('notes.list'), { limit: 200 });
});

test('clip.append adds the text as a new line of the chosen note, through the agent only', async () => {
  desktop();
  const text = `${SELECTION}\nhttps://blog.example/post/42`;
  const res = await send({ type: 'clip.append', id: 'n-new', text });
  assert.deepEqual(res.result, { id: 'n-new', title: 'Reading list' });
  assert.deepEqual(lastCall('notes.append'), { id: 'n-new', text });
  assert.ok(!logged.some((line) => line.includes('Demo quote')), 'never logged');
});

test('clip.append refuses what the agent would: nothing to add, too long, a bad id', async () => {
  desktop();
  for (const msg of [
    { id: 'n-new', text: '   ' },
    { id: 'n-new', text: 'x'.repeat(20_001) },
    { id: 'n-new', text: 7 },
    { id: '', text: 'x' },
  ]) {
    const res = await send({ type: 'clip.append', ...msg });
    assert.equal(res.error.code, 'invalid_params', JSON.stringify(msg).slice(0, 60));
  }
  assert.ok(!methods().includes('notes.append'));
});

test('locked: clip.state says so; an append unlocks first, then adds', async () => {
  const app = desktop({ locked: true });
  const state = (await send({ type: 'clip.state' })).result;
  assert.equal(state.locked, true);
  assert.deepEqual(state.notes, []);
  const res = await send({ type: 'clip.append', id: 'n-new', text: SELECTION });
  assert.equal(res.result.title, 'Reading list');
  assert.equal(app.unlocks, 1);
  assert.deepEqual(methods().filter((m) => m.startsWith('notes.') || m === 'unlock'), ['notes.append', 'unlock', 'notes.append'],
    'no list while fully locked');
});

test('soft-locked: the kept list is offered; clip.unlock asks the app to unlock', async () => {
  const app = desktop({ locked: true, soft: true });
  const state = (await send({ type: 'clip.state' })).result;
  assert.equal(state.locked, true);
  assert.equal(state.notes.length, 3);
  assert.deepEqual((await send({ type: 'clip.unlock' })).result, { locked: false });
  assert.equal(app.unlocks, 1);
});

test('a note of a vault the user may only view: the agent refuses with read_only', async () => {
  desktop({ append: () => ({ __error: { code: 'read_only', message: "You can use this vault's logins but not change them" } }) });
  const res = await send({ type: 'clip.append', id: 'n-team', text: SELECTION });
  assert.equal(res.error.code, 'read_only');
});

test('an older desktop app: no append (and no list), a new note still works', async () => {
  desktop({ features: ['edit', 'notes.list', 'notes.create'] });
  const state = (await send({ type: 'clip.state' })).result;
  assert.equal(state.can_append, false);
  assert.equal(state.can_create, true);
  assert.ok(!methods().includes('notes.list'));
  const append = await send({ type: 'clip.append', id: 'n-new', text: SELECTION });
  assert.equal(append.error.code, 'not_supported');
  assert.equal(append.error.reason, 'needs_update');

  const made = await send({ type: 'clip.create', title: 'Demo post', text: SELECTION });
  assert.deepEqual(made.result, { id: 'n-made', title: 'Demo post' });
  assert.deepEqual(lastCall('notes.create'), { fields: { title: 'Demo post', notes: SELECTION } });

  desktop({ features: ['edit'] });
  const oldest = (await send({ type: 'clip.state' })).result;
  assert.equal(oldest.can_append, false);
  assert.equal(oldest.can_create, false);
});

test('clip.create: a title is required and the text must fit a new note', async () => {
  desktop();
  assert.equal((await send({ type: 'clip.create', title: '  ', text: SELECTION })).error.code, 'invalid_params');
  assert.equal((await send({ type: 'clip.create', title: 'Long', text: 'x'.repeat(20_001) })).error.code, 'invalid_params');
  assert.ok(!methods().includes('notes.create'));
});
