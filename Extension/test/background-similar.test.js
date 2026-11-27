// Similar sites in the in-page menu and popup, and "Use this login on <site> too?" after a cross fill.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({}); // (method, params) => result | { __error: {code, message} }
const tabsById = new Map([[1, { id: 1, url: 'https://github.com/login', active: true }]]);
const tabMessages = [];
let onMessage;
const alarmsCreated = [];
const alarmListeners = [];
const offscreenLog = [];
const sessionStore = {};
const storageWrites = []; // every storage.*.set payload, to check that no secret is persisted
const ports = []; // every native port the background opened
let connectBehaviour = null; // (port) => void, e.g. simulate "native messaging host not found"
const captures = []; // tabs.captureVisibleTab calls
let capture = async () => 'data:image/png;base64,iVBORw0+/A==';

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
  port.disconnect = () => { port.closed = true; };
  return port;
}

before(async () => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext', lastError: undefined,
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      connectNative: () => {
        const port = fakePort();
        ports.push(port);
        connectBehaviour?.(port);
        return port;
      },
      onMessage: { addListener: (f) => { onMessage = f; } },
      onInstalled: evt(), onStartup: evt(),
      sendMessage: async (msg) => {
        if (msg?.target !== 'offscreen') return undefined;
        offscreenLog.push(['msg', msg]);
        return { result: 'cleared' };
      },
    },
    alarms: { create: async (name, info) => { alarmsCreated.push([name, info]); }, onAlarm: { addListener: (f) => alarmListeners.push(f) } },
    offscreen: {
      createDocument: async (opts) => { offscreenLog.push(['create', opts.reasons]); },
      closeDocument: async () => { offscreenLog.push(['close']); },
    },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [...tabsById.values()],
      get: async (id) => tabsById.get(id),
      sendMessage: async (tabId, msg, opts) => { tabMessages.push([tabId, msg, opts]); return { ok: true }; },
      captureVisibleTab: async (windowId, opts) => { captures.push([windowId, opts]); return capture(windowId, opts); },
    },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, onClicked: evt() },
    commands: { onCommand: evt() },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {} },
    scripting: { executeScript: async () => [] },
    storage: {
      local: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
      sync: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
      onChanged: evt(),
      session: {
        set: async (o) => { storageWrites.push(o); Object.assign(sessionStore, o); },
        get: async (k) => (k in sessionStore ? { [k]: sessionStore[k] } : {}),
        remove: async (k) => { delete sessionStore[k]; },
      },
    },
  };
  await import('../src/background.js');
});

/** Sends `msg` to the router as if from `sender`; resolves with the response. */
function send(msg, sender) {
  return new Promise((resolve) => {
    const async = onMessage(msg, { id: 'pass-ext', ...sender }, resolve);
    if (!async) resolve(undefined);
  });
}

const lastCall = (method) => [...calls].reverse().find((c) => c[0] === method)?.[1];
const callsOf = (method) => calls.filter((c) => c[0] === method).map((c) => c[1]);
const POPUP = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const PAGE = 'https://www.amazon.co.uk/ap/signin';
const tab = (id, url, frameId = 0) => {
  tabsById.set(id, { id, url, active: false, windowId: 1 });
  return { tab: { id, url, windowId: 1 }, frameId, url };
};
const FEATURES = ['edit', 'logins.search', 'logins.similar', 'logins.add_url'];
const SIMILAR = {
  items: [
    { id: 'de', title: 'Amazon DE', username: 'ann', domain: 'amazon.de', has_totp: false, vault_id: null, reason: 'same_name' },
    { id: 'us', title: 'Amazon US', username: 'ann', domain: 'amazon.com', has_totp: true, vault_id: null, reason: 'same_name' },
  ],
  name: 'amazon', locked: false, vaults: [],
};

/** An agent of a desktop app with these features; `fill` answers logins.fill_cross. */
function app({ features = FEATURES, fill = null, extra = {} } = {}) {
  return (m, p) => {
    if (m === 'status') return { locked: false, soft_locked: false, features };
    if (m === 'logins.similar') return SIMILAR;
    if (m === 'logins.find') return { items: [], pending_otp: null };
    if (m === 'logins.fill_cross') {
      return fill ? fill(p) : { username: 'ann', password: 'amz-pw', totp: null, cross: true,
        title: 'Amazon US', domain: 'amazon.com', add_url_token: 'agent-token-1' };
    }
    if (m in extra) return extra[m](p);
    return {};
  };
}

test('menu.similar: the agent decides for the frame\'s own URL; only those logins can be picked, from that frame', async () => {
  agent = app();
  const res = await send({ type: 'menu.similar', url: 'https://evil.test/' }, tab(40, PAGE, 3));
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('logins.similar'), { url: PAGE, limit: 3 });
  assert.deepEqual(res.result.items.map((i) => i.id), ['de', 'us']);
  assert.equal(res.result.search, true);
  assert.equal(res.result.name, 'amazon');
  assert.ok(!JSON.stringify(res.result).includes('reason'), 'titles, usernames and sites only');

  // A pick goes to the agent as a cross fill (the desktop app asks), with the frame's URL.
  const picked = await send({ type: 'logins.fill_cross', id: 'us', similar: true, url: 'https://evil.test/' }, tab(40, PAGE, 3));
  assert.equal(picked.ok, true, JSON.stringify(picked));
  assert.deepEqual(lastCall('logins.fill_cross'), { url: PAGE, id: 'us' });
  assert.equal(picked.result.password, 'amz-pw');
  assert.equal(picked.result.add_url_token, undefined, 'the agent\'s token never reaches the page\'s frame');

  // Not offered, another frame, or another origin in that frame: refused before the agent.
  const before = callsOf('logins.fill_cross').length;
  for (const [id, sender] of [['gh', tab(40, PAGE, 3)], ['us', tab(40, PAGE, 0)], ['us', tab(40, 'https://evil.test/login', 3)]]) {
    const r = await send({ type: 'logins.fill_cross', id, similar: true }, sender);
    assert.equal(r.ok, false);
    assert.equal(r.error.code, 'not_found');
  }
  assert.equal(callsOf('logins.fill_cross').length, before);
});

test('menu.similar: a lookalike in the answer is dropped; an older desktop app has none, the search may still open', async () => {
  const base = app();
  const withLookalike = { ...SIMILAR, items: [...SIMILAR.items,
    { id: 'pp', title: 'PayPal', username: 'p', domain: 'paypal.com', lookalike: { domain: 'paypal.com' } }] };
  agent = (m, p) => (m === 'logins.similar' ? withLookalike : base(m, p));
  const res = await send({ type: 'menu.similar' }, tab(41, 'https://paypa1.example/'));
  assert.deepEqual(res.result.items.map((i) => i.id), ['de', 'us']);

  // An agent that doesn't know the method: no similar sites, nothing to pick.
  agent = (m, p) => (m === 'logins.similar' ? { __error: { code: 'invalid_params', message: 'unknown method logins.similar' } } : base(m, p));
  const old = await send({ type: 'menu.similar' }, tab(42, PAGE));
  assert.deepEqual(old.result.items, []);
  assert.equal(old.result.search, true);
  const refused = await send({ type: 'logins.fill_cross', id: 'de', similar: true }, tab(42, PAGE));
  assert.equal(refused.ok, false, 'nothing was offered to that tab');
});

test('menu.search: the popup opens with the vault search for the site\'s name', async () => {
  agent = app();
  const opened = [];
  chrome.action.openPopup = async (opts) => { opened.push(opts); };
  try {
    await send({ type: 'menu.similar' }, tab(43, PAGE));
    const res = await send({ type: 'menu.search' }, tab(43, PAGE));
    assert.deepEqual(res.result, { opened: true });
    assert.deepEqual(opened, [{ windowId: 1 }]);
    const state = await send({ type: 'popup.state', tabId: 43 }, POPUP);
    assert.equal(state.result.search, 'amazon');
    const again = await send({ type: 'popup.state', tabId: 43 }, POPUP);
    assert.equal(again.result.search, undefined, 'once');
    // No popup allowed here: the menu says to use the toolbar button; that popup starts with the search.
    chrome.action.openPopup = async () => { throw new Error('not allowed'); };
    const failed = await send({ type: 'menu.search' }, tab(44, 'https://www.example.org/login'));
    assert.deepEqual(failed.result, { opened: false });
    assert.equal((await send({ type: 'popup.state', tabId: 44 }, POPUP)).result.search, 'example.org');
  } finally {
    delete chrome.action.openPopup;
  }
});

test('popup.state: a site without logins gets its similar sites', async () => {
  agent = app();
  tab(45, PAGE);
  const state = await send({ type: 'popup.state', tabId: 45 }, POPUP);
  assert.deepEqual(state.result.items, []);
  assert.deepEqual(state.result.similar.items.map((i) => i.id), ['de', 'us']);
  assert.deepEqual(lastCall('logins.similar'), { url: PAGE, limit: 3 });
  // A site with logins: no similar sites.
  const base = agent;
  agent = (m, p) => (m === 'logins.find' ? { items: [{ id: 'own', title: 'Own', username: 'me' }], pending_otp: null } : base(m, p));
  const own = await send({ type: 'popup.state', tabId: 45 }, POPUP);
  assert.equal(own.result.similar, undefined);
});

/** A cross fill in tab `id` (frame 0 unless `frameId`), picked in the in-page menu. */
async function crossFill(id, { url = PAGE, frameId = 0, fill = null } = {}) {
  agent = app({ fill, extra: {
    'logins.add_url': (p) => ({ added: true, id: p.id, title: 'Amazon US' }),
    'logins.save': () => ({ id: 'copy-1' }),
  } });
  await send({ type: 'menu.similar' }, tab(id, url, frameId));
  const before = tabMessages.length;
  const filled = await send({ type: 'logins.fill_cross', id: 'us', similar: true }, tab(id, url, frameId));
  assert.equal(filled.ok, true, JSON.stringify(filled));
  assert.deepEqual(tabMessages.slice(before).map(([t, m, o]) => [t, m, o]), [[id, { type: 'cross.offer' }, { frameId: 0 }]]);
  return filled.result;
}

test('after a cross fill: the top frame\'s card, once, with no secret; "Add" uses the agent\'s token for that fill', async () => {
  await crossFill(50, { frameId: 2 });
  assert.equal((await send({ type: 'cross.query' }, tab(50, PAGE, 2))).result, null, 'top frame only');
  const info = (await send({ type: 'cross.query' }, tab(50, PAGE))).result;
  assert.equal(info.host, 'amazon.co.uk');
  assert.equal(info.site, 'amazon.com');
  assert.equal(info.username, 'ann');
  assert.equal(info.can_add, true);
  assert.equal(info.lookalike, '');
  assert.ok(info.token && info.token !== 'agent-token-1');
  assert.ok(!JSON.stringify(info).includes('amz-pw') && !JSON.stringify(info).includes('agent-token'), 'no password, no agent token');
  assert.equal((await send({ type: 'cross.query' }, tab(50, PAGE))).result, null, 'shown once');

  // The card's token, from the top frame only.
  assert.equal((await send({ type: 'cross.add', token: 'guess' }, tab(50, PAGE))).ok, false);
  assert.equal((await send({ type: 'cross.add', token: info.token }, tab(50, PAGE, 2))).ok, false);
  assert.equal(callsOf('logins.add_url').length, 0);
  const added = await send({ type: 'cross.add', token: info.token }, tab(50, PAGE));
  assert.equal(added.ok, true, JSON.stringify(added));
  assert.deepEqual(added.result, { added: true, title: 'Amazon US' });
  assert.deepEqual(lastCall('logins.add_url'), { id: 'us', url: PAGE, token: 'agent-token-1' });
  assert.equal((await send({ type: 'cross.add', token: info.token }, tab(50, PAGE))).ok, false, 'answered');
  assert.equal((await send({ type: 'cross.copy', token: info.token }, tab(50, PAGE))).ok, false, 'answered');
});

test('"Save a copy" saves a new login for the page through logins.save', async () => {
  await crossFill(51);
  const { token } = (await send({ type: 'cross.query' }, tab(51, PAGE))).result;
  const before = callsOf('logins.add_url').length;
  const copied = await send({ type: 'cross.copy', token }, tab(51, PAGE));
  assert.equal(copied.ok, true, JSON.stringify(copied));
  assert.deepEqual(lastCall('logins.save'), { url: PAGE, username: 'ann', password: 'amz-pw' });
  assert.equal(callsOf('logins.add_url').length, before);
});

test('the form\'s submit with the filled login shows the card again instead of "Save login?", until answered', async () => {
  await crossFill(52);
  const first = (await send({ type: 'cross.query' }, tab(52, PAGE))).result;
  // Submitted (the card went with the page): the next page shows the card, not the save banner.
  await send({ type: 'save.capture', username: 'ANN ', password: 'amz-pw' }, tab(52, PAGE));
  const before = callsOf('logins.save_check').length;
  const q = await send({ type: 'save.query' }, tab(52, 'https://www.amazon.co.uk/home'));
  assert.equal(q.result?.cross?.token, first.token, JSON.stringify(q));
  assert.equal(callsOf('logins.save_check').length, before, 'no save check: the card covers it');
  // "Not now": nothing more for this fill.
  await send({ type: 'cross.dismiss', token: first.token }, tab(52, PAGE));
  await send({ type: 'save.capture', username: 'ann', password: 'amz-pw' }, tab(52, PAGE));
  assert.equal((await send({ type: 'save.query' }, tab(52, 'https://www.amazon.co.uk/home'))).result, null);
  assert.equal((await send({ type: 'cross.add', token: first.token }, tab(52, PAGE))).ok, false);
  // Another password typed: the usual banner decides.
  agent = (m) => (m === 'logins.save_check' ? { action: 'save_new' } : {});
  await send({ type: 'save.capture', username: 'ann', password: 'typed-other' }, tab(52, PAGE));
  const other = await send({ type: 'save.query' }, tab(52, 'https://www.amazon.co.uk/home'));
  assert.equal(other.result?.cross, undefined);
  assert.equal(callsOf('logins.save_check').length, before + 1);
});

test('a cross fill on a lookalike: the card says so; an older desktop app (no token) offers only the copy', async () => {
  await crossFill(53, { url: 'https://paypa1.example/login',
    fill: () => ({ username: 'p', password: 'pp', totp: null, cross: true, title: 'PayPal', domain: 'paypal.com',
      lookalike: { domain: 'paypal.com', host: 'paypa1.example', reason: 'homograph' }, add_url_token: 't' }) });
  const like = (await send({ type: 'cross.query' }, tab(53, 'https://paypa1.example/login'))).result;
  assert.equal(like.lookalike, 'paypal.com');
  assert.equal(like.can_add, true);

  await crossFill(54, { fill: () => ({ username: 'ann', password: 'amz-pw', totp: null, cross: true }) });
  const old = (await send({ type: 'cross.query' }, tab(54, PAGE))).result;
  assert.equal(old.can_add, false);
  assert.equal(old.can_copy, true);
  const add = await send({ type: 'cross.add', token: old.token }, tab(54, PAGE));
  assert.equal(add.error.code, 'not_supported');
});

test('a fill of the page\'s own login (cross: false) offers nothing', async () => {
  agent = app({ fill: () => ({ username: 'ann', password: 'own', totp: null, cross: false }) });
  await send({ type: 'menu.similar' }, tab(55, PAGE));
  const before = tabMessages.length;
  await send({ type: 'logins.fill_cross', id: 'us', similar: true }, tab(55, PAGE));
  assert.equal(tabMessages.length, before);
  assert.equal((await send({ type: 'cross.query' }, tab(55, PAGE))).result, null);
});
