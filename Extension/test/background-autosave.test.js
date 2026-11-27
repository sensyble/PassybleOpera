import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({});
const store = {}; // storage.local
const storageWrites = [];
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
      query: async () => [],
      get: async () => undefined,
      sendMessage: async () => ({ ok: true }),
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
        set: async (o) => { storageWrites.push(o); Object.assign(store, structuredClone(o)); },
      },
      sync: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
      session: { get: async () => ({}), set: async (o) => { storageWrites.push(o); }, remove: async () => {} },
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

let nextTab = 100;
/** A fresh tab: `at(url)` is its top frame on `url`. */
function newTab() {
  const id = nextTab++;
  return (url, extra = {}) => ({ tab: { id, url }, frameId: 0, url, ...extra });
}
const callsOf = (method) => calls.filter((c) => c[0] === method).map((c) => c[1]);
const lastCall = (method) => callsOf(method).at(-1);

/** The agent answers `save_check` with `decided` and `logins.find` with `items`. */
function agentWith({ decided = { action: 'save_new' }, items = [], save = (p) => ({ id: p.id ?? 'new-1' }) } = {}) {
  agent = (m, p) => {
    if (m === 'logins.save_check') return decided;
    if (m === 'logins.find') return { items, pending_otp: null };
    if (m === 'logins.save') return save(p);
    if (m === 'logins.delete') return { undo_secs: 60 };
    if (m === 'logins.restore') return { id: p.id };
    return {};
  };
}

/** Fills `password` as generated in the form on `formUrl`, submits it, and asks on `nextUrl`. */
async function generateAndSubmit(at, { formUrl, nextUrl = formUrl, username = '', password, kind = 'signup', typed = null }) {
  await send({ type: 'generate.filled', password }, at(formUrl));
  await send({ type: 'save.capture', username, password: typed ?? password, kind }, at(formUrl));
  return (await send({ type: 'save.query' }, at(nextUrl))).result;
}

test('sign-up with a generated password on a site without logins: saved, no banner; Undo deletes it', async () => {
  const at = newTab();
  agentWith({ decided: { action: 'save_new' } });
  const info = await generateAndSubmit(at, { formUrl: 'https://shop.example/join', nextUrl: 'https://shop.example/welcome', username: 'me@x.test', password: 'Gen-A-1' });
  assert.equal(info.autosaved, 'saved');
  assert.equal(info.host, 'shop.example');
  assert.equal(typeof info.token, 'string');
  assert.deepEqual(lastCall('logins.save'), { url: 'https://shop.example/join', username: 'me@x.test', password: 'Gen-A-1' }, 'a new login, no id');
  // Nothing left to commit: the password left memory with the save.
  assert.equal((await send({ type: 'save.commit', token: info.token }, at('https://shop.example/welcome'))).ok, false);
  // Undo: only by the notice's token, from the top frame.
  assert.equal((await send({ type: 'save.undo', token: 'guess' }, at('https://shop.example/welcome'))).error.reason, 'nothing_to_undo');
  assert.equal((await send({ type: 'save.undo', token: info.token }, at('https://shop.example/welcome', { frameId: 3 }))).ok, false);
  const undo = await send({ type: 'save.undo', token: info.token }, at('https://shop.example/welcome'));
  assert.deepEqual(undo.result, { undone: 'saved' });
  assert.deepEqual(lastCall('logins.delete'), { url: 'https://shop.example/join', id: 'new-1' });
  assert.equal((await send({ type: 'save.undo', token: info.token }, at('https://shop.example/welcome'))).ok, false, 'once');
});

test('a generated password whose username has a login on the site: that login is updated; Undo restores it', async () => {
  const at = newTab();
  agentWith({ decided: { action: 'update_password', id: 'gh', title: 'GitHub' } });
  const info = await generateAndSubmit(at, { formUrl: 'https://github.com/password_reset', username: 'octo', password: 'Gen-B-1', kind: 'change' });
  assert.equal(info.autosaved, 'updated');
  assert.deepEqual(lastCall('logins.save'), { url: 'https://github.com/password_reset', username: 'octo', password: 'Gen-B-1', id: 'gh' });
  const restores = callsOf('logins.restore').length;
  const undo = await send({ type: 'save.undo', token: info.token }, at('https://github.com/'));
  assert.deepEqual(undo.result, { undone: 'updated' });
  assert.deepEqual(callsOf('logins.restore').slice(restores), [{ url: 'https://github.com/password_reset', id: 'gh' }], 'no draft to bring back');
});

test('the canonical address goes to the auto-save as it would to the banner\'s save', async () => {
  const at = newTab();
  agentWith({ decided: { action: 'update_password', id: 'ex' } });
  await send({ type: 'generate.filled', password: 'Gen-C-1' }, at('https://app.example.com/reset'));
  await send({ type: 'save.capture', username: 'me', password: 'Gen-C-1', kind: 'change', canonical: 'https://example.com/' }, at('https://app.example.com/reset'));
  const info = (await send({ type: 'save.query' }, at('https://app.example.com/'))).result;
  assert.equal(info.autosaved, 'updated');
  assert.equal(lastCall('logins.save').canonical_url, 'https://example.com');
});

test('no username: saved only when the site has no logins yet; with logins (which one?) the banner asks', async () => {
  let at = newTab();
  agentWith({ decided: { action: 'save_new' }, items: [] });
  let info = await generateAndSubmit(at, { formUrl: 'https://new.example/signup', password: 'Gen-D-1' });
  assert.equal(info.autosaved, 'saved');

  at = newTab();
  agentWith({ decided: { action: 'save_new' }, items: [{ id: 'a', username: 'me' }, { id: 'b', username: 'you' }] });
  const saves = callsOf('logins.save').length;
  info = await generateAndSubmit(at, { formUrl: 'https://two.example/password', password: 'Gen-D-2', kind: 'change' });
  assert.equal(info.mode, 'save', 'the banner, as for a typed password');
  assert.equal(callsOf('logins.save').length, saves, 'nothing saved');

  // A username change is never made without asking either.
  at = newTab();
  agentWith({ decided: { action: 'update_username', id: 'a', title: 'Two' } });
  info = await generateAndSubmit(at, { formUrl: 'https://two.example/join', username: 'new-name', password: 'Gen-D-3' });
  assert.equal(info.mode, 'username');
});

test('only a password generated in this tab, for this origin, as submitted: anything else gets the banner', async () => {
  agentWith({ decided: { action: 'save_new' } });
  const saves = callsOf('logins.save').length;
  // Typed over the generated one.
  let at = newTab();
  let info = await generateAndSubmit(at, { formUrl: 'https://shop.example/join', username: 'me', password: 'Gen-E-1', typed: 'my-own-pw' });
  assert.equal(info.mode, 'save');
  // Generated for another origin of the same tab.
  at = newTab();
  await send({ type: 'generate.filled', password: 'Gen-E-2' }, at('https://other.example/join'));
  await send({ type: 'save.capture', username: 'me', password: 'Gen-E-2', kind: 'signup' }, at('https://shop.example/join'));
  info = (await send({ type: 'save.query' }, at('https://shop.example/join'))).result;
  assert.equal(info.mode, 'save');
  // Generated in another tab.
  const elsewhere = newTab();
  at = newTab();
  await send({ type: 'generate.filled', password: 'Gen-E-3' }, elsewhere('https://shop.example/join'));
  await send({ type: 'save.capture', username: 'me', password: 'Gen-E-3', kind: 'signup' }, at('https://shop.example/join'));
  info = (await send({ type: 'save.query' }, at('https://shop.example/join'))).result;
  assert.equal(info.mode, 'save');
  assert.equal(callsOf('logins.save').length, saves, 'none of them saved without asking');
  // Never stored: neither the password nor its hash.
  assert.ok(!JSON.stringify(storageWrites).includes('Gen-E'), 'no generated password in storage');
});

test('generate.filled: web pages only, a password of sensible length', async () => {
  const at = newTab();
  assert.equal((await send({ type: 'generate.filled', password: 'x' }, at('file:///C:/page.html'))).ok, false);
  assert.equal((await send({ type: 'generate.filled', password: '' }, at('https://shop.example/'))).ok, false);
  assert.equal((await send({ type: 'generate.filled', password: 'x'.repeat(5000) }, at('https://shop.example/'))).ok, false);
  assert.deepEqual((await send({ type: 'generate.filled', password: 'Gen-F-1' }, at('https://shop.example/'))).result, {});
});

test('a generated password is remembered for 30 minutes: later, the banner asks', async () => {
  const at = newTab();
  agentWith({ decided: { action: 'save_new' } });
  await send({ type: 'generate.filled', password: 'Gen-G-1' }, at('https://late.example/join'));
  const realNow = Date.now;
  Date.now = () => realNow() + 30 * 60_000 + 1000;
  try {
    await send({ type: 'save.capture', username: 'me', password: 'Gen-G-1', kind: 'signup' }, at('https://late.example/join'));
    const info = (await send({ type: 'save.query' }, at('https://late.example/join'))).result;
    assert.equal(info.mode, 'save');
  } finally {
    Date.now = realNow;
  }
});

test('"never save" on the site: a generated password is saved all the same; a typed one gets nothing', async () => {
  store.neverSave = ['https://never.example'];
  try {
    agentWith({ decided: { action: 'save_new' } });
    let at = newTab();
    const info = await generateAndSubmit(at, { formUrl: 'https://never.example/join', username: 'me', password: 'Gen-H-1' });
    assert.equal(info.autosaved, 'saved');
    at = newTab();
    await send({ type: 'save.capture', username: 'me', password: 'typed-pw', kind: 'signup' }, at('https://never.example/join'));
    assert.equal((await send({ type: 'save.query' }, at('https://never.example/join'))).result, null);
  } finally {
    delete store.neverSave;
  }
});

test('locked at the submit: the banner offers it; once unlocked, it is saved and the banner goes away', async () => {
  const at = newTab();
  let locked = true;
  agent = (m, p) => {
    if (locked && m !== 'status') return { __error: { code: 'locked', message: 'Vault is locked' } };
    if (m === 'logins.save_check') return { action: 'save_new' };
    if (m === 'logins.save') return { id: 'late-1' };
    return { items: [], pending_otp: null };
  };
  const info = await generateAndSubmit(at, { formUrl: 'https://locked.example/join', username: 'me', password: 'Gen-I-1' });
  assert.equal(info.mode, 'save', 'the banner (its Save unlocks)');
  locked = false;
  const after = (await send({ type: 'save.query', recheck: true }, at('https://locked.example/join'))).result;
  assert.equal(after.close, true, 'the banner shown while locked goes away');
  assert.equal(after.autosaved, 'saved');
  assert.equal(lastCall('logins.save').password, 'Gen-I-1');
});

test('the save fails (agent away): the banner offers it instead', async () => {
  const at = newTab();
  agent = (m) => {
    if (m === 'logins.save_check') return { action: 'save_new' };
    if (m === 'logins.save') return { __error: { code: 'internal', message: 'disk full' } };
    return { items: [], pending_otp: null };
  };
  const info = await generateAndSubmit(at, { formUrl: 'https://fail.example/join', username: 'me', password: 'Gen-J-1' });
  assert.equal(info.mode, 'save');
});
