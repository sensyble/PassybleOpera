// "Update this login?": Passyble filled a login and the user typed another username or password over it before
// signing in. The fill is kept with the password only as a hash; the card's buttons act by its one-time token.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { changedPlan, changesOf, filledLogin, liveFilled, FILLED_TTL_MS } from '../src/background/fill-changes.js';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({}); // (method, params) => result | { __error: {code, message} }
const tabsById = new Map([[1, { id: 1, url: 'https://github.com/login', active: true }]]);
const tabMessages = [];
const ports = [];
let onMessage;
const settle = () => new Promise((r) => setTimeout(r, 10));

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

/** A chrome.storage area in memory. */
function area() {
  const data = {};
  return {
    get: async (k) => {
      if (k == null) return { ...data };
      const keys = Array.isArray(k) ? k : typeof k === 'string' ? [k] : Object.keys(k);
      const out = typeof k === 'object' && !Array.isArray(k) ? { ...k } : {};
      for (const key of keys) if (key in data) out[key] = data[key];
      return out;
    },
    set: async (o) => { Object.assign(data, o); },
    remove: async (k) => { for (const key of [].concat(k)) delete data[key]; },
  };
}

before(async () => {
  const sessionStore = {};
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext', lastError: undefined,
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      connectNative: () => { const port = fakePort(); ports.push(port); return port; },
      onMessage: { addListener: (f) => { onMessage = f; } },
      onInstalled: evt(), onStartup: evt(),
      sendMessage: async () => undefined,
    },
    alarms: { create: async () => {}, onAlarm: { addListener: () => {} } },
    offscreen: { createDocument: async () => {}, closeDocument: async () => {} },
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
      local: area(),
      sync: area(),
      onChanged: evt(),
      session: {
        set: async (o) => { Object.assign(sessionStore, o); },
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

const PAGE = 'https://github.com/login';
const AFTER = 'https://github.com/';
const tab = (id, url = PAGE, frameId = 0) => {
  tabsById.set(id, { id, url, active: false, windowId: 1 });
  return { tab: { id, url, windowId: 1 }, frameId, url };
};
const lastCall = (method) => [...calls].reverse().find((c) => c[0] === method)?.[1];
const callsOf = (method) => calls.filter((c) => c[0] === method).map((c) => c[1]);
const FEATURES = ['edit', 'logins.search', 'logins.similar', 'logins.add_url'];
const OWN = { username: 'alice', password: 'pw-1', totp: null, vault: { id: 'home', home: true, can_edit: true, can_reveal: true } };

/** A desktop app: `decision` answers logins.save_check; `fill` logins.fill; `extra` anything else. */
function app({ decision = { action: 'none', id: 'gh', title: 'GitHub' }, fill = OWN, extra = {} } = {}) {
  return (m, p) => {
    if (m === 'status') return { locked: false, soft_locked: false, features: FEATURES };
    if (m === 'logins.fill') return fill;
    if (m === 'logins.save_check') return typeof decision === 'function' ? decision(p) : decision;
    if (m === 'logins.find') return { items: [{ id: 'gh', title: 'GitHub', username: 'alice' }], pending_otp: null };
    if (m === 'logins.update') return { id: p.id, title: 'GitHub' };
    if (m === 'logins.save') return { id: 'new-1' };
    if (m in extra) return extra[m](p);
    return {};
  };
}

/** Fills login `gh` into tab `id`, then submits `username` / `password` and asks for the banner. */
async function fillThenSubmit(id, { username, password, decision, fill, extra, kind = 'login' } = {}) {
  agent = app({ decision, fill, extra });
  const filled = await send({ type: 'logins.fill', id: 'gh' }, tab(id));
  assert.equal(filled.ok, true, JSON.stringify(filled));
  await send({ type: 'save.capture', username, password, kind }, tab(id));
  return (await send({ type: 'save.query' }, tab(id, AFTER))).result;
}

test('changesOf: a new username, another password, or nothing (as filled, or changed back)', async () => {
  const origin = 'https://github.com';
  const filled = await filledLogin({ itemId: 'gh', origin, result: OWN });
  assert.ok(!JSON.stringify(filled).includes('pw-1'), 'the password is kept only as a hash');
  assert.deepEqual(await changesOf(filled, { username: 'bob@example.com', password: 'pw-1' }), { username: 'bob@example.com', password: false });
  assert.deepEqual(await changesOf(filled, { username: 'alice', password: 'pw-2' }), { username: '', password: true });
  assert.deepEqual(await changesOf(filled, { username: 'bob', password: 'pw-2' }), { username: 'bob', password: true });
  assert.equal(await changesOf(filled, { username: ' ALICE ', password: 'pw-1' }), null, 'case and spaces do not count');
  assert.equal(await changesOf(filled, { username: '', password: 'pw-1' }), null, 'a form without a username field');
  assert.equal(filled.canEdit, true);
  const shared = await filledLogin({ itemId: 'x', origin, result: { ...OWN, vault: { can_edit: false, can_reveal: false } } });
  assert.deepEqual([shared.canEdit, shared.noReveal], [false, true]);
});

test('liveFilled: same origin, within 10 minutes', async () => {
  let now = 1000;
  const filled = await filledLogin({ itemId: 'gh', origin: 'https://github.com', result: OWN, now: () => now });
  assert.equal(liveFilled(filled, 'https://github.com', now), filled);
  assert.equal(liveFilled(filled, 'https://gist.github.com', now), null);
  now += FILLED_TTL_MS + 1;
  assert.equal(liveFilled(filled, 'https://github.com', now), null);
});

test('changedPlan: the card unless the agent names another login, or the "Update password?" banner says it', () => {
  const user = { username: 'bob', password: false };
  const pass = { username: '', password: true };
  assert.equal(changedPlan({ decided: { action: 'none', id: 'gh' }, filledId: 'gh', changes: user }), 'card');
  assert.equal(changedPlan({ decided: { action: 'none', id: 'other' }, filledId: 'gh', changes: user }), 'usual');
  assert.equal(changedPlan({ decided: { action: 'update_password', id: 'gh' }, filledId: 'gh', changes: pass }), 'usual');
  assert.equal(changedPlan({ decided: { action: 'update_password', id: 'bob' }, filledId: 'gh', changes: user }), 'usual');
  assert.equal(changedPlan({ decided: { action: 'update_username', id: 'other' }, filledId: 'gh', changes: user }), 'usual');
  assert.equal(changedPlan({ decided: { action: 'save_new' }, filledId: 'gh', changes: { username: 'bob', password: true } }), 'card');
  assert.equal(changedPlan({ decided: null, filledId: 'gh', changes: user }), 'usual', 'locked');
  assert.equal(changedPlan({ decided: { action: 'none', id: 'gh' }, filledId: 'gh', changes: null }), 'usual');
});

test('a new username over the filled login: "Update this login?" names the change; Update changes only the username', async () => {
  const q = await fillThenSubmit(10, { username: 'bob@example.com', password: 'pw-1' });
  const card = q?.changed;
  assert.ok(card, JSON.stringify(q));
  assert.equal(lastCall('logins.save_check').filled_id, 'gh');
  assert.deepEqual({ ...card, token: '' }, {
    token: '', host: 'github.com', title: 'GitHub', username: 'alice', new_username: 'bob@example.com', password_changed: false,
    cross: false, site: '', lookalike: '', can_update: true, can_copy: true, read_only: false,
  });
  assert.ok(!JSON.stringify(q).includes('pw-1'), 'never the password');
  // The card's token, from the top frame only.
  assert.equal((await send({ type: 'changed.update', token: 'guess' }, tab(10))).ok, false);
  assert.equal((await send({ type: 'changed.update', token: card.token }, tab(10, PAGE, 3))).ok, false);
  assert.equal(callsOf('logins.update').length, 0);
  const res = await send({ type: 'changed.update', token: card.token }, tab(10));
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.deepEqual(res.result, { updated: true, title: 'GitHub' });
  assert.deepEqual(lastCall('logins.update'), { url: PAGE, id: 'gh', fields: { username: 'bob@example.com' } });
  assert.equal((await send({ type: 'changed.update', token: card.token }, tab(10))).ok, false, 'one use');
  assert.equal((await send({ type: 'changed.save', token: card.token }, tab(10))).ok, false, 'one use');
});

test('a new username and password: the card names both; "Save as new login" saves a separate login', async () => {
  const q = await fillThenSubmit(11, { username: 'bob', password: 'pw-2', decision: { action: 'save_new', vaults: [], default_vault: 'home' } });
  const card = q.changed;
  assert.equal(card.new_username, 'bob');
  assert.equal(card.password_changed, true);
  assert.equal(card.title, 'GitHub', 'the title from the page\'s list');
  const saved = await send({ type: 'changed.save', token: card.token }, tab(11));
  assert.equal(saved.ok, true, JSON.stringify(saved));
  assert.deepEqual(lastCall('logins.save'), { url: PAGE, username: 'bob', password: 'pw-2' });
  assert.deepEqual(saved.result, { id: 'new-1', unchanged: false });
});

test('Update with both changed sends both; the password only to the agent', async () => {
  const q = await fillThenSubmit(12, { username: 'bob', password: 'pw-2', decision: { action: 'save_new' } });
  await send({ type: 'changed.update', token: q.changed.token }, tab(12));
  assert.deepEqual(lastCall('logins.update'), { url: PAGE, id: 'gh', fields: { username: 'bob', password: 'pw-2' } });
});

test('only the password changed: the usual "Update password?" banner (the existing path)', async () => {
  const q = await fillThenSubmit(13, { username: 'alice', password: 'pw-2', decision: { action: 'update_password', id: 'gh', title: 'GitHub' } });
  assert.equal(q.changed, undefined);
  assert.equal(q.mode, 'update');
  await send({ type: 'save.commit', token: q.token }, tab(13));
  assert.deepEqual(lastCall('logins.save'), { url: PAGE, username: 'alice', password: 'pw-2', id: 'gh' });
});

test('changed back to what was filled, or typed another saved login: nothing to ask', async () => {
  assert.equal(await fillThenSubmit(14, { username: 'Alice', password: 'pw-1' }), null);
  assert.equal(await fillThenSubmit(15, { username: 'bob', password: 'bob-pw', decision: { action: 'none', id: 'bob' } }), null);
  // Another saved login of the site with a new password: that login's banner.
  const other = await fillThenSubmit(16, { username: 'bob', password: 'bob-new', decision: { action: 'update_password', id: 'bob', title: 'GitHub (Bob)' } });
  assert.equal(other.mode, 'update');
  assert.equal(other.title, 'GitHub (Bob)');
});

test('the fill counts for one submit only, on its own origin, and goes with the lock', async () => {
  const first = await fillThenSubmit(17, { username: 'bob', password: 'pw-1' });
  assert.ok(first.changed);
  await send({ type: 'changed.dismiss', token: first.changed.token }, tab(17));
  assert.equal((await send({ type: 'changed.update', token: first.changed.token }, tab(17))).ok, false, 'dismissed');
  // The next submit doesn't see that fill again: the agent's answer stands (none: no banner).
  await send({ type: 'save.capture', username: 'bob', password: 'pw-1', kind: 'login' }, tab(17));
  assert.equal((await send({ type: 'save.query' }, tab(17, AFTER))).result, null);

  agent = app();
  await send({ type: 'logins.fill', id: 'gh' }, tab(18));
  await send({ type: 'save.capture', username: 'bob', password: 'pw-1', kind: 'login' }, tab(18, 'https://gist.github.com/login'));
  assert.equal((await send({ type: 'save.query' }, tab(18, 'https://gist.github.com/'))).result, null);

  // Locked in between: what was filled is gone.
  await send({ type: 'logins.fill', id: 'gh' }, tab(19));
  for (const port of ports) port.onMessage.fns.forEach((f) => f({ event: 'lock_state', data: { locked: true } }));
  await settle();
  await send({ type: 'save.capture', username: 'bob', password: 'pw-1', kind: 'login' }, tab(19));
  assert.equal((await send({ type: 'save.query' }, tab(19, AFTER))).result, null);
});

test('a password change form or a sign-up keeps its own banner', async () => {
  const q = await fillThenSubmit(20, { username: 'alice', password: 'pw-new', kind: 'change', decision: { action: 'update_password', id: 'gh', title: 'GitHub' } });
  assert.equal(q.changed, undefined);
  assert.equal(q.mode, 'update');
});

test('a login in a vault the user can\'t change: no Update, "Save as new login" only', async () => {
  const fill = { ...OWN, vault: { id: 'team', home: false, can_edit: false, can_reveal: true } };
  const q = await fillThenSubmit(21, { username: 'bob', password: 'pw-1', fill });
  assert.equal(q.changed.can_update, false);
  assert.equal(q.changed.read_only, true);
  assert.equal(q.changed.can_copy, true);
  const before = callsOf('logins.update').length;
  const upd = await send({ type: 'changed.update', token: q.changed.token }, tab(21));
  assert.equal(upd.error.code, 'read_only');
  assert.equal(callsOf('logins.update').length, before, 'nothing written');
});

test('a fill-only login with only the username changed: no card (its password never goes into a new login)', async () => {
  const fill = { ...OWN, vault: { id: 'team', home: false, can_edit: false, can_reveal: false } };
  assert.equal(await fillThenSubmit(22, { username: 'bob', password: 'pw-1', fill }), null);
  // With a password the user typed: a new login of theirs may be saved.
  const q = await fillThenSubmit(23, { username: 'bob', password: 'mine', fill, decision: { action: 'save_new' } });
  assert.deepEqual([q.changed.can_update, q.changed.can_copy], [false, true]);
});

test('"Never for this site" stays quiet here too', async () => {
  agent = app();
  await send({ type: 'logins.fill', id: 'gh' }, tab(24, 'https://never.example/login'));
  await send({ type: 'save.capture', username: 'x', password: 'y', kind: 'login' }, tab(24, 'https://never.example/login'));
  const q = await send({ type: 'save.query' }, tab(24, 'https://never.example/'));
  await send({ type: 'save.never', token: q.result?.changed?.token }, tab(24, 'https://never.example/'));
  agent = app();
  await send({ type: 'logins.fill', id: 'gh' }, tab(24, 'https://never.example/login'));
  await send({ type: 'save.capture', username: 'bob', password: 'pw-1', kind: 'login' }, tab(24, 'https://never.example/login'));
  assert.equal((await send({ type: 'save.query' }, tab(24, 'https://never.example/'))).result, null);
});

// After a cross fill: one card.

const AMAZON = 'https://www.amazon.co.uk/ap/signin';
const CROSS = { username: 'ann', password: 'amz-pw', totp: null, cross: true, title: 'Amazon US', domain: 'amazon.com',
  add_url_token: 'agent-token-1', vault: { id: 'home', home: true, can_edit: true, can_reveal: true } };

/** A cross fill of login `us` into tab `id` (picked under "Similar sites"), then a submit. */
async function crossThenSubmit(id, { username, password, fill = CROSS, decision = { action: 'save_new' } } = {}) {
  agent = (m, p) => {
    if (m === 'logins.similar') {
      return { items: [{ id: 'us', title: 'Amazon US', username: 'ann', domain: 'amazon.com', has_totp: false, vault_id: null }],
        name: 'amazon', locked: false, vaults: [] };
    }
    if (m === 'logins.fill_cross') return fill;
    if (m === 'logins.add_url') return { added: true, id: p.id, title: 'Amazon US' };
    return app({ decision })(m, p);
  };
  await send({ type: 'menu.similar' }, tab(id, AMAZON));
  const filled = await send({ type: 'logins.fill_cross', id: 'us', similar: true }, tab(id, AMAZON));
  assert.equal(filled.ok, true, JSON.stringify(filled));
  await send({ type: 'save.capture', username, password, kind: 'login' }, tab(id, AMAZON));
  return (await send({ type: 'save.query' }, tab(id, 'https://www.amazon.co.uk/home'))).result;
}

test('a cross fill changed before signing in: one card; Update adds the page to the login, then updates it', async () => {
  const q = await crossThenSubmit(30, { username: 'ann.uk', password: 'amz-pw' });
  const card = q?.changed;
  assert.ok(card, JSON.stringify(q));
  assert.equal(q.cross, undefined, 'not two cards');
  assert.deepEqual([card.cross, card.site, card.title, card.username, card.new_username, card.can_update],
    [true, 'amazon.com', 'Amazon US', 'ann', 'ann.uk', true]);
  assert.ok(!JSON.stringify(q).includes('agent-token') && !JSON.stringify(q).includes('amz-pw'));
  // The cross card doesn't come as well.
  assert.equal((await send({ type: 'cross.query' }, tab(30, AMAZON))).result, null);
  const res = await send({ type: 'changed.update', token: card.token }, tab(30));
  assert.equal(res.ok, true, JSON.stringify(res));
  assert.deepEqual(lastCall('logins.add_url'), { id: 'us', url: AMAZON, token: 'agent-token-1' });
  assert.deepEqual(lastCall('logins.update'), { url: AMAZON, id: 'us', fields: { username: 'ann.uk' } });
  const order = calls.map((c) => c[0]).filter((m) => m === 'logins.add_url' || m === 'logins.update').slice(-2);
  assert.deepEqual(order, ['logins.add_url', 'logins.update']);
});

test('a cross fill with the values as filled still gets "Use this login on <site> too?"', async () => {
  const q = await crossThenSubmit(31, { username: 'ann', password: 'amz-pw' });
  assert.ok(q.cross);
  assert.equal(q.changed, undefined);
});

test('a cross fill with another password: "Save as new login" is a login for this page; the cross card is answered', async () => {
  const q = await crossThenSubmit(32, { username: 'ann', password: 'uk-pw' });
  assert.equal(q.changed.password_changed, true);
  assert.equal(q.changed.new_username, '');
  const saved = await send({ type: 'changed.save', token: q.changed.token }, tab(32));
  assert.equal(saved.ok, true, JSON.stringify(saved));
  assert.deepEqual(lastCall('logins.save'), { url: AMAZON, username: 'ann', password: 'uk-pw' });
  assert.equal((await send({ type: 'cross.query' }, tab(32, AMAZON))).result, null);
});

test('a cross fill on a lookalike: the warning on the card; an older desktop app (no token) can\'t update', async () => {
  const like = await crossThenSubmit(33, { username: 'p2', password: 'pp',
    fill: { ...CROSS, username: 'p', password: 'pp', title: 'PayPal', domain: 'paypal.com',
      lookalike: { domain: 'paypal.com', host: 'www.amazon.co.uk', reason: 'homograph' } } });
  assert.equal(like.changed.lookalike, 'paypal.com');
  const old = await crossThenSubmit(34, { username: 'ann2', password: 'amz-pw', fill: { ...CROSS, add_url_token: undefined } });
  assert.deepEqual([old.changed.can_update, old.changed.can_copy], [false, true]);
});

test('a cross fill whose card was answered ("Not now" on the page): the usual banner decides', async () => {
  // The card shows as the fill happens; the user says "Not now", then changes the username and signs in.
  agent = (m, p) => {
    if (m === 'logins.similar') {
      return { items: [{ id: 'us', title: 'Amazon US', username: 'ann', domain: 'amazon.com', has_totp: false, vault_id: null }],
        name: 'amazon', locked: false, vaults: [] };
    }
    if (m === 'logins.fill_cross') return CROSS;
    return app({ decision: { action: 'save_new' } })(m, p);
  };
  await send({ type: 'menu.similar' }, tab(35, AMAZON));
  await send({ type: 'logins.fill_cross', id: 'us', similar: true }, tab(35, AMAZON));
  const card = (await send({ type: 'cross.query' }, tab(35, AMAZON))).result;
  await send({ type: 'cross.dismiss', token: card.token }, tab(35, AMAZON));
  await send({ type: 'save.capture', username: 'other', password: 'amz-pw', kind: 'login' }, tab(35, AMAZON));
  const q = (await send({ type: 'save.query' }, tab(35, 'https://www.amazon.co.uk/home'))).result;
  assert.equal(q?.changed, undefined);
  assert.equal(q?.mode, 'save');
});
