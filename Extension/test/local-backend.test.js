// Uses the WebAssembly stand-in (helpers/fake-wasm.js); local-wasm.test.js runs the same backend on
// the real one.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LocalBackend, TICK_ALARM } from '../src/background/local/local-backend.js';
import { memoryVaultStore } from '../src/background/local/vault-store.js';
import { keySession, SESSION_KEY } from '../src/background/local/session.js';
import { BrowserAgent, checkMasterPassword, fakeStats } from './helpers/fake-wasm.js';

/** A storage.session stand-in (what survives a service worker restart, until the browser exits). */
function sessionArea() {
  const data = {};
  return {
    data,
    accessLevel: null,
    setAccessLevel: async (o) => { sessionArea.level = o.accessLevel; },
    get: async (k) => (k in data ? { [k]: structuredClone(data[k]) } : {}),
    set: async (o) => { Object.assign(data, structuredClone(o)); },
    remove: async (k) => { delete data[k]; },
  };
}

function fakeAlarms() {
  const alarms = new Map();
  return { alarms, create: async (name, o) => { alarms.set(name, o); }, clear: async (name) => alarms.delete(name) };
}

function make({ store = memoryVaultStore(), area = sessionArea(), alarms = fakeAlarms(), config = {} } = {}) {
  const timers = [];
  const backend = new LocalBackend({
    wasm: async () => ({ BrowserAgent, checkMasterPassword }),
    store,
    session: keySession(area),
    config: async () => ({ device_id: 'test-device', ...config }),
    alarms,
    setTimeout: (fn, ms) => { const t = { fn, ms }; timers.push(t); return t; },
    clearTimeout: (t) => { const i = timers.indexOf(t); if (i >= 0) timers.splice(i, 1); },
    log: { error() {}, warn() {} },
  });
  const events = [];
  for (const name of ['lock_state', 'vault_changed', 'copy']) backend.on(name, (data) => events.push([name, data]));
  return { backend, store, area, alarms, timers, events };
}

const URL_ = 'https://github.com/login';

test('no vault yet: status says so, everything else is no_vault; nothing is stored', async () => {
  const { backend, store, area } = make();
  const status = await backend.request('status');
  assert.equal(status.vault, false);
  assert.ok(status.features.includes('vault.browser'));
  await assert.rejects(backend.request('logins.find', { url: URL_ }), (e) => e.code === 'no_vault');
  assert.equal(await store.load(), null);
  assert.deepEqual(area.data, {});
  assert.equal((await backend.info()).hasVault, false);
});

test('create: the file goes to the store, the key to storage.session, the pages hear "unlocked"', async () => {
  const { backend, store, area, events, alarms, timers } = make();
  const res = await backend.create('master pw 1');
  assert.ok(res.vault_id);
  assert.ok(res.grant);
  const rec = await store.load();
  assert.equal(rec.id, res.vault_id);
  assert.ok(rec.file instanceof Uint8Array && rec.file.length > 10);
  assert.equal(area.data[SESSION_KEY].vaultId, res.vault_id);
  assert.match(area.data[SESSION_KEY].key, /^[A-Za-z0-9_-]{43}$/, 'only the 32-byte key, base64url');
  assert.deepEqual(events, [['lock_state', { locked: false }]]);
  // The auto-lock is scheduled: a timer here and an alarm that wakes a stopped service worker.
  assert.ok(timers.length === 1 && timers[0].ms > 800_000);
  assert.ok(alarms.alarms.get(TICK_ALARM)?.when > Date.now() + 800_000);
  await assert.rejects(backend.create('again'), (e) => e.code === 'invalid_state');
});

test('every change is saved at once (the old file kept as prev); effects become events', async () => {
  const { backend, store, events } = make();
  await backend.create('master pw 1');
  const first = (await store.load()).file;
  events.length = 0;
  const { id } = await backend.request('logins.save', { url: URL_, username: 'octo', password: 'hunter2-long' });
  const rec = await store.load();
  assert.deepEqual(rec.prev, first);
  assert.notDeepEqual(rec.file, first);
  assert.deepEqual(events, [['vault_changed', {}]]);
  events.length = 0;
  assert.deepEqual(await backend.request('logins.copy', { id, field: 'password', url: URL_ }), { copied: true, field: 'password' });
  assert.deepEqual(events, [['copy', { text: 'hunter2-long' }]], 'the copied secret goes to the background, never into an answer');
});

test('grant and confirmed go next to params, only when given', async () => {
  const { backend } = make({ config: { verify_each_fill: true } });
  const { grant } = await backend.create('master pw 1');
  const { id } = await backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  await assert.rejects(backend.request('logins.fill', { url: URL_, id }), (e) => e.code === 'verification_required');
  assert.equal((await backend.request('logins.fill', { url: URL_, id }, { grant })).password, 'pw-1234567890');
  await assert.rejects(backend.request('logins.fill', { url: URL_, id }, { grant }), (e) => e.code === 'verification_required', 'one request per grant');
  await assert.rejects(backend.request('cards.fill', { url: URL_, id: 'card1' }), (e) => e.code === 'cancelled');
  assert.equal((await backend.request('cards.fill', { url: URL_, id: 'card1' }, { confirmed: true })).number, '4242424242424242');
  const { grant: again } = await backend.verifyPassword('master pw 1');
  assert.equal((await backend.request('logins.fill', { url: URL_, id }, { grant: again })).username, 'octo');
  await assert.rejects(backend.verifyPassword('nope'), (e) => e.code === 'wrong_password');
});

test('lock removes the key from storage.session and stops the timer; unlock puts it back', async () => {
  const { backend, area, events, alarms, timers } = make();
  await backend.create('master pw 1');
  events.length = 0;
  await backend.lock(false);
  assert.equal(area.data[SESSION_KEY], undefined);
  assert.deepEqual(events, [['lock_state', { locked: true }]]);
  assert.equal(timers.length, 0);
  assert.equal(alarms.alarms.has(TICK_ALARM), false);
  await assert.rejects(backend.unlock('wrong'), (e) => e.code === 'wrong_password');
  assert.equal(area.data[SESSION_KEY], undefined);
  const res = await backend.unlock('master pw 1');
  assert.equal(res.locked, false);
  assert.ok(area.data[SESSION_KEY]);
  assert.equal((await backend.info()).locked, false);
});

test('a restarted service worker opens the vault with the kept key, quietly, with the idle time carried over', async () => {
  const store = memoryVaultStore();
  const area = sessionArea();
  const first = make({ store, area });
  await first.backend.create('master pw 1');
  await first.backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  area.data[SESSION_KEY].lastUseAt = Date.now() - 60_000; // a minute without use before the restart
  const again = make({ store, area });
  const found = await again.backend.request('logins.find', { url: URL_ });
  assert.equal(found.locked, false);
  assert.equal(found.items.length, 1);
  assert.deepEqual(again.events, [], 'nothing changed for the pages');
  // The timer counts from the last use before the restart (15 min minus about one minute).
  const ms = again.timers.at(-1).ms;
  assert.ok(ms < 900_000 - 55_000 && ms > 900_000 - 70_000, String(ms));
});

test('after a restart past the auto-lock time the vault is locked and the key is gone', async () => {
  const store = memoryVaultStore();
  const area = sessionArea();
  const first = make({ store, area, config: { auto_lock_secs: 60 } });
  await first.backend.create('master pw 1');
  area.data[SESSION_KEY].lastUseAt = Date.now() - 120_000;
  const again = make({ store, area, config: { auto_lock_secs: 60 } });
  await assert.rejects(again.backend.request('logins.fill', { url: URL_, id: 'x' }), (e) => e.code === 'locked');
  assert.equal(area.data[SESSION_KEY], undefined);
});

test('a key that does not open the vault (another vault, a wrong key) is dropped', async () => {
  const store = memoryVaultStore();
  const area = sessionArea();
  const first = make({ store, area });
  const { vault_id: id } = await first.backend.create('master pw 1');
  area.data[SESSION_KEY] = { key: 'A'.repeat(43), vaultId: id, lastUseAt: Date.now() };
  const again = make({ store, area });
  assert.equal((await again.backend.request('status')).locked, true);
  assert.equal(area.data[SESSION_KEY], undefined);
});

test('the timer runs tick(): the auto-lock locks and says so', async () => {
  const { backend, timers, events, area } = make({ config: { auto_lock_secs: 1 } });
  await backend.create('master pw 1');
  events.length = 0;
  await new Promise((r) => setTimeout(r, 1100));
  await timers.at(-1).fn();
  await backend.info(); // after the queued tick
  assert.deepEqual(events, [['lock_state', { locked: true }]]);
  assert.equal(area.data[SESSION_KEY], undefined);
});

test('openFile: checked with its master password before anything is kept', async () => {
  const src = make();
  await src.backend.create('master pw 1');
  await src.backend.request('logins.save', { url: URL_, username: 'octo', password: 'pw-1234567890' });
  const file = await src.backend.exportVault();
  const dst = make();
  await assert.rejects(dst.backend.openFile(file, 'wrong'), (e) => e.code === 'wrong_password');
  assert.equal(await dst.store.load(), null);
  await assert.rejects(dst.backend.openFile(new Uint8Array([1, 2, 3]), 'master pw 1'), (e) => e.code === 'invalid_params');
  const res = await dst.backend.openFile(file, 'master pw 1');
  assert.ok(res.vault_id);
  assert.deepEqual((await dst.store.load()).file, file);
  assert.equal((await dst.backend.request('logins.find', { url: URL_ })).items[0].username, 'octo');
  assert.deepEqual(dst.events, [['lock_state', { locked: false }]]);
  await assert.rejects(dst.backend.openFile(file, 'master pw 1'), (e) => e.code === 'invalid_state');
});

test('exportVault is a backup (backedUpAt); deleteVault removes the vault and the key', async () => {
  const { backend, store, area, events } = make();
  await backend.create('master pw 1');
  assert.equal((await backend.info()).backedUpAt, 0);
  const file = await backend.exportVault();
  assert.ok(file.length > 10);
  const at = (await backend.info()).backedUpAt;
  assert.ok(Date.now() - at < 5000);
  assert.equal((await store.load()).backedUpAt, at);
  events.length = 0;
  assert.deepEqual(await backend.deleteVault(), { deleted: true });
  assert.equal(await store.load(), null);
  assert.equal(area.data[SESSION_KEY], undefined);
  assert.deepEqual(events, [['lock_state', { locked: true }], ['vault_changed', {}]]);
  assert.equal((await backend.request('status')).vault, false);
  assert.equal(await backend.exportVault(), null);
});

test('reset (switching to app mode) locks completely and keeps the vault in the store', async () => {
  const { backend, store, area } = make();
  await backend.create('master pw 1');
  await backend.reset();
  assert.ok(await store.load(), 'the vault stays, inactive');
  assert.equal(area.data[SESSION_KEY], undefined);
  assert.equal((await backend.request('status')).locked, true);
});

test('a save IndexedDB refused is written again after the next call', async () => {
  const inner = memoryVaultStore();
  let fail = false;
  const store = { ...inner, save: async (...a) => { if (fail) throw new Error('quota'); return inner.save(...a); } };
  const { backend } = make({ store });
  await backend.create('master pw 1');
  fail = true;
  await backend.request('logins.save', { url: URL_, username: 'a', password: 'pw-1234567890' });
  const before = (await inner.load()).file;
  fail = false;
  await backend.request('status');
  assert.notDeepEqual((await inner.load()).file, before, 'written now');
});

test('calls run one at a time, in order', async () => {
  const { backend } = make();
  await backend.create('master pw 1');
  const order = [];
  await Promise.all([
    backend.request('logins.save', { url: URL_, username: 'a', password: 'pw-1234567890' }).then(() => order.push('save')),
    backend.request('logins.find', { url: URL_ }).then((r) => order.push(`find:${r.items.length}`)),
  ]);
  assert.deepEqual(order, ['save', 'find:1']);
});

test('keySession asks for trusted contexts only and stores nothing but the key, the vault id and a time', async () => {
  const area = sessionArea();
  const s = keySession(area);
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(sessionArea.level, 'TRUSTED_CONTEXTS');
  await s.save({ key: new Uint8Array(32).fill(7), vaultId: 'v1', lastUseAt: 5 });
  assert.deepEqual(Object.keys(area.data[SESSION_KEY]).sort(), ['key', 'lastUseAt', 'vaultId']);
  const back = await s.load();
  assert.deepEqual(back.key, new Uint8Array(32).fill(7));
  area.data[SESSION_KEY].key = 'short';
  assert.equal(await s.load(), null, 'not a 32-byte key');
  await s.clear();
  assert.equal(area.data[SESSION_KEY], undefined);
});

test('checkMasterPassword: the WebAssembly\'s rule with the names, no vault or agent needed; older glue says not_supported', async () => {
  const { backend, store, area } = make();
  const instances = fakeStats.instances;
  const check = await backend.checkMasterPassword('alexsmith-orbit-candle', ['alex.smith@example.com', 7, '']);
  assert.deepEqual([check.ok, check.issues, check.name, check.min_length], [false, ['contains_name', 'guessable'], 'alex', 12]);
  assert.deepEqual(fakeStats.masterNames, ['alex.smith@example.com'], 'strings only');
  assert.equal((await backend.checkMasterPassword('Longer Password 2026!')).ok, true);
  assert.equal(fakeStats.instances, instances, 'no BrowserAgent was built for it');
  assert.equal(await store.load(), null);
  assert.deepEqual(area.data, {}, 'nothing kept');
  const old = new LocalBackend({ wasm: async () => ({ BrowserAgent }), store: memoryVaultStore(), session: keySession(sessionArea()), config: async () => ({ device_id: 'd' }) });
  await assert.rejects(old.checkMasterPassword('Longer Password 2026!'), (e) => e.code === 'not_supported');
});
