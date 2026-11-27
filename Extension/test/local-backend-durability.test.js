// No saved change of the browser vault is lost, whatever the order of events: LocalBackend with the WebAssembly
// stand-in, a vault store that can refuse writes and fake timers; and vault-store.js on a small fake IndexedDB that
// commits a transaction's writes all together or not at all, as the real one does.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LocalBackend } from '../src/background/local/local-backend.js';
import { idbVaultStore, memoryVaultStore } from '../src/background/local/vault-store.js';
import { keySession, SESSION_KEY, UNSAVED_KEY } from '../src/background/local/session.js';
import { BrowserAgent } from './helpers/fake-wasm.js';

const URL_ = 'https://github.com/login';
const dec = new TextDecoder();

function sessionArea() {
  const data = {};
  return {
    data,
    setAccessLevel: async () => {},
    get: async (k) => (k in data ? { [k]: structuredClone(data[k]) } : {}),
    set: async (o) => { Object.assign(data, structuredClone(o)); },
    remove: async (k) => { delete data[k]; },
  };
}

/** A vault store whose saves fail while `failing.on` is true (a full disk, an IndexedDB error). */
function flakyStore() {
  const inner = memoryVaultStore();
  const failing = { on: false, attempts: 0 };
  const store = {
    ...inner,
    save: async (...a) => {
      failing.attempts++;
      if (failing.on) throw new Error('QuotaExceededError');
      return inner.save(...a);
    },
  };
  return { store, inner, failing };
}

function make({ store = memoryVaultStore(), area = sessionArea(), config = {} } = {}) {
  const timers = [];
  const backend = new LocalBackend({
    wasm: async () => ({ BrowserAgent }),
    store,
    session: keySession(area),
    config: async () => ({ device_id: 'test-device', ...config }),
    alarms: { create: async () => {}, clear: async () => {} },
    setTimeout: (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; },
    clearTimeout: (t) => { const i = timers.indexOf(t); if (i >= 0) timers.splice(i, 1); },
    log: { error() {}, warn() {} },
  });
  return { backend, store, area, timers };
}

/** The logins in a stored (fake, plain JSON) vault file. */
async function storedUsernames(store) {
  const rec = await store.load();
  return rec ? JSON.parse(dec.decode(rec.file)).logins.map((l) => l.username).sort() : null;
}

/** Runs the timers that are due within `ms` (fake time: they are only collected). */
async function runTimers(timers, ms) {
  for (const t of timers.filter((x) => x.ms <= ms)) {
    timers.splice(timers.indexOf(t), 1);
    await t.fn();
  }
}

test('two pages saving at the same moment: both changes are stored, in order', async () => {
  const { backend, store } = make();
  await backend.create('master pw 1');
  // The popup's editor, a content script's save prompt and an autofill, all at once.
  await Promise.all([
    backend.request('logins.create', { url: URL_, fields: { username: 'from-popup', password: 'pw-1234567890' } }),
    backend.request('logins.save', { url: URL_, username: 'from-page', password: 'pw-0987654321' }),
    backend.request('logins.find', { url: URL_ }),
  ]);
  assert.deepEqual(await storedUsernames(store), ['from-page', 'from-popup']);
});

test('a save IndexedDB refused survives a stopped service worker and is written by the next one', async () => {
  const { store, inner, failing } = flakyStore();
  const area = sessionArea();
  const first = make({ store, area });
  await first.backend.create('master pw 1');
  failing.on = true;
  await first.backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  assert.deepEqual(await storedUsernames(inner), [], 'IndexedDB does not have it');
  assert.ok(area.data[UNSAVED_KEY], 'the refused file is kept in storage.session');
  // The browser stops the service worker; IndexedDB works again; the next one starts.
  failing.on = false;
  const again = make({ store, area });
  const found = await again.backend.request('logins.find', { url: URL_ });
  assert.equal(found.items.length, 1, 'the vault opens with the change');
  assert.deepEqual(await storedUsernames(inner), ['octo'], 'and IndexedDB has it now');
  assert.equal(area.data[UNSAVED_KEY], undefined, 'the kept copy is gone once stored');
});

test('a save IndexedDB refused is retried on a timer, without waiting for another call', async () => {
  const { store, inner, failing } = flakyStore();
  const { backend, timers } = make({ store });
  await backend.create('master pw 1');
  failing.on = true;
  await backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  const retry = timers.find((t) => t.ms <= 1000);
  assert.ok(retry, 'a retry is scheduled');
  await runTimers(timers, 1000);
  await backend.info();
  assert.deepEqual(await storedUsernames(inner), [], 'still refused');
  assert.ok(timers.some((t) => t.ms > 1000 && t.ms <= 30_000), 'retried later again, backing off');
  failing.on = false;
  await runTimers(timers, 30_000);
  await backend.info();
  assert.deepEqual(await storedUsernames(inner), ['octo']);
  assert.ok(!timers.some((t) => t.ms <= 30_000), 'no more retries');
});

test('a refused save, then a lock: the lock keeps it, the next start writes it', async () => {
  const { store, inner, failing } = flakyStore();
  const area = sessionArea();
  const first = make({ store, area });
  await first.backend.create('master pw 1');
  failing.on = true;
  await first.backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  await first.backend.lock(true);
  assert.equal(area.data[SESSION_KEY], undefined, 'the key goes with the lock');
  assert.ok(area.data[UNSAVED_KEY], 'the refused file does not');
  failing.on = false;
  const again = make({ store, area });
  await again.backend.unlock('master pw 1');
  assert.equal((await again.backend.request('logins.find', { url: URL_ })).items.length, 1);
  assert.deepEqual(await storedUsernames(inner), ['octo']);
});

test('switching to app mode and back with a refused save: the vault reopens with it, a later edit keeps both', async () => {
  const { store, inner, failing } = flakyStore();
  const { backend } = make({ store });
  await backend.create('master pw 1');
  failing.on = true;
  await backend.request('logins.save', { url: URL_, username: 'first', password: 'pw-1234567890' });
  await backend.reset(); // app mode: the instance goes, the refused file stays in memory
  failing.on = false;
  await backend.unlock('master pw 1'); // browser mode again
  assert.equal((await backend.request('logins.find', { url: URL_ })).items.length, 1, 'opened from the newest copy');
  await backend.request('logins.save', { url: URL_, username: 'second', password: 'pw-0987654321' });
  assert.deepEqual(await storedUsernames(inner), ['first', 'second'], 'the older stored copy never wins');
});

test('an older refused copy never replaces a newer stored one', async () => {
  const { store, inner, failing } = flakyStore();
  const area = sessionArea();
  const first = make({ store, area });
  await first.backend.create('master pw 1');
  failing.on = true;
  await first.backend.request('logins.save', { url: URL_, username: 'a', password: 'pw-1234567890' });
  failing.on = false;
  await first.backend.request('logins.save', { url: URL_, username: 'b', password: 'pw-0987654321' });
  assert.deepEqual(await storedUsernames(inner), ['a', 'b']);
  assert.equal(area.data[UNSAVED_KEY], undefined, 'nothing older left to write');
  const again = make({ store, area });
  await again.backend.request('status');
  assert.deepEqual(await storedUsernames(inner), ['a', 'b']);
});

test('deleting the vault also forgets a refused copy', async () => {
  const { store, failing } = flakyStore();
  const area = sessionArea();
  const { backend } = make({ store, area });
  await backend.create('master pw 1');
  failing.on = true;
  await backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  assert.ok(area.data[UNSAVED_KEY]);
  await backend.deleteVault();
  assert.equal(area.data[UNSAVED_KEY], undefined);
  failing.on = false;
  const again = make({ store, area });
  assert.equal((await again.backend.request('status')).vault, false, 'nothing comes back');
});

test('a use waiting for the save delay is written by the lock, and by the timer', async () => {
  const { backend, store, timers } = make();
  await backend.create('master pw 1');
  await backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  // The agent counted a use and saves it 1 s later (the fake's save delay: the agent's save_soon).
  const agent = backend._agent;
  agent.vault.logins[0].uses = 1;
  agent.saveDueAt = Date.now() + 1000;
  await backend.lock(false);
  assert.equal(JSON.parse(dec.decode((await store.load()).file)).logins[0].uses, 1, 'the lock saved it');
  await backend.unlock('master pw 1');
  backend._agent.vault.logins[0].uses = 2;
  backend._agent.saveDueAt = Date.now() + 30;
  await backend.request('status'); // schedules the tick for the save
  assert.equal(JSON.parse(dec.decode((await store.load()).file)).logins[0].uses, 1, 'not yet');
  await new Promise((r) => setTimeout(r, 40));
  await runTimers(timers, 100);
  await backend.info();
  assert.equal(JSON.parse(dec.decode((await store.load()).file)).logins[0].uses, 2, 'the timer saved it');
});

/**
 * A small IndexedDB: one database, object stores with a key path, transactions whose writes become
 * visible only when the transaction completes (all of them) and vanish when it aborts. `failCommits`
 * makes the next commits fail (as a full disk does). `options` records each transaction's options.
 */
function fakeIndexedDB() {
  const stores = new Map(); // name -> Map(key -> value)
  const keyPaths = new Map();
  const state = { failCommits: 0, transactions: [] };
  const later = (fn) => setTimeout(fn, 0);
  const db = {
    objectStoreNames: { contains: (n) => stores.has(n) },
    createObjectStore(name, { keyPath }) { stores.set(name, new Map()); keyPaths.set(name, keyPath); },
    transaction(names, mode, options) {
      const staged = new Map(); // `${store}\u0000${key}` -> { store, key, value | undefined (delete) }
      let pending = 0;
      let done = false;
      const tx = { mode, options, error: null, oncomplete: null, onerror: null, onabort: null };
      state.transactions.push(tx);
      const settle = () => later(() => {
        if (done || pending) return;
        done = true;
        if (state.failCommits > 0) {
          state.failCommits--;
          tx.error = new Error('QuotaExceededError');
          tx.onerror?.();
          tx.onabort?.();
          return;
        }
        for (const { store, key, value } of staged.values()) {
          if (value === undefined) stores.get(store).delete(key);
          else stores.get(store).set(key, structuredClone(value));
        }
        tx.oncomplete?.();
      });
      const request = (fn) => {
        pending++;
        const r = { result: undefined, error: null, onsuccess: null, onerror: null };
        later(() => {
          r.result = fn();
          pending--;
          r.onsuccess?.();
          settle();
        });
        return r;
      };
      tx.abort = () => {
        if (done) throw new Error('finished');
        done = true;
        tx.onabort?.();
      };
      tx.objectStore = (name) => {
        if (!names.includes(name)) throw new Error(`not in this transaction: ${name}`);
        const id = (key) => `${name}\u0000${key}`;
        return {
          get: (key) => request(() => {
            const s = staged.get(id(key));
            if (s) return s.value === undefined ? undefined : structuredClone(s.value);
            const v = stores.get(name).get(key);
            return v === undefined ? undefined : structuredClone(v);
          }),
          put: (value) => {
            const key = value[keyPaths.get(name)];
            return request(() => { staged.set(id(key), { store: name, key, value: structuredClone(value) }); return key; });
          },
          delete: (key) => request(() => { staged.set(id(key), { store: name, key, value: undefined }); }),
        };
      };
      settle();
      return tx;
    },
  };
  let created = false;
  return {
    state,
    open() {
      const req = { result: db, onupgradeneeded: null, onsuccess: null, onerror: null, onblocked: null };
      later(() => {
        if (!created) { created = true; req.onupgradeneeded?.(); }
        req.onsuccess?.();
      });
      return req;
    },
  };
}

test('IndexedDB: every write asks for strict durability, so an answered save is on disk', async () => {
  const idb = fakeIndexedDB();
  const store = idbVaultStore(idb);
  await store.save('v1', new Uint8Array([1, 2, 3]), 1);
  await store.update('v1', { backedUpAt: 5 });
  await store.load();
  const writes = idb.state.transactions.filter((t) => t.mode === 'readwrite');
  assert.equal(writes.length, 2);
  for (const t of writes) assert.equal(t.options?.durability, 'strict');
});

test('IndexedDB: the file, the previous copy and the active pointer land together or not at all', async () => {
  const idb = fakeIndexedDB();
  const store = idbVaultStore(idb);
  await store.save('v1', new Uint8Array([1]), 1);
  await store.save('v1', new Uint8Array([2]), 2);
  idb.state.failCommits = 1;
  await assert.rejects(store.save('v1', new Uint8Array([3]), 3), /Quota/);
  const rec = await store.load();
  assert.deepEqual([...rec.file], [2], 'the refused write left the last stored copy as it was');
  assert.deepEqual([...rec.prev], [1]);
  await store.save('v1', new Uint8Array([3]), 3);
  const now = await store.load();
  assert.deepEqual([...now.file], [3]);
  assert.deepEqual([...now.prev], [2]);
});

test('IndexedDB: the backend with a refused commit keeps the change and stores it on the retry', async () => {
  const idb = fakeIndexedDB();
  const store = idbVaultStore(idb);
  const area = sessionArea();
  const { backend, timers } = make({ store, area });
  await backend.create('master pw 1');
  idb.state.failCommits = 1;
  await backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  assert.deepEqual(await storedUsernames(store), []);
  await runTimers(timers, 1000);
  await backend.info();
  assert.deepEqual(await storedUsernames(store), ['octo']);
  assert.equal(area.data[UNSAVED_KEY], undefined);
});
