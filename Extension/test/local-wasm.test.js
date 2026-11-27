// The browser vault end to end on the real WebAssembly (src/wasm/, `npm run wasm`) in Node's V8.
// Skipped when src/wasm/ isn't built (it is git-ignored).
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { LocalBackend } from '../src/background/local/local-backend.js';
import { memoryVaultStore } from '../src/background/local/vault-store.js';
import { keySession, SESSION_KEY } from '../src/background/local/session.js';
import { autoLockSecs } from '../src/shared/vault-mode.js';

const dir = new URL('../src/wasm/', import.meta.url);
const built = existsSync(new URL('pass_wasm_bg.wasm', dir)) && existsSync(new URL('pass_wasm_kdf.wasm', dir));
const skip = built ? false : 'src/wasm/ is not built (npm run wasm)';

// A passphrase the master password rule accepts (pass-core's own tests use it).
const MASTER = 'correct-horse-battery-staple-orbit';
const URL_ = 'https://github.com/login';
let wasm = null;

before(async () => {
  if (skip) return;
  const glue = await import(new URL('pass_wasm.js', dir));
  await glue.default({ module_or_path: readFileSync(new URL('pass_wasm_bg.wasm', dir)) });
  const { loadKdf } = await import(new URL('kdf.js', dir));
  glue.setKdf(await loadKdf(readFileSync(new URL('pass_wasm_kdf.wasm', dir))));
  wasm = { BrowserAgent: glue.BrowserAgent };
});

function sessionArea() {
  const data = {};
  return {
    data,
    get: async (k) => (k in data ? { [k]: structuredClone(data[k]) } : {}),
    set: async (o) => { Object.assign(data, structuredClone(o)); },
    remove: async (k) => { delete data[k]; },
  };
}

function make({ store = memoryVaultStore(), area = sessionArea(), config = {} } = {}) {
  const backend = new LocalBackend({
    wasm: async () => wasm,
    store,
    session: keySession(area),
    config: async () => ({ device_id: 'node-test', ...config }),
    setTimeout: () => null,
    clearTimeout: () => {},
    log: { error() {}, warn() {} },
  });
  const events = [];
  for (const name of ['lock_state', 'vault_changed', 'copy']) backend.on(name, (d) => events.push([name, d]));
  return { backend, store, area, events };
}

test('create, save a login, fill it, lock, unlock, back up, delete, and open the backup again', { skip }, async () => {
  const { backend, store, area, events } = make();
  assert.equal((await backend.request('status')).vault, false);
  await assert.rejects(backend.request('logins.find', { url: URL_ }), (e) => e.code === 'no_vault');

  const created = await backend.create(MASTER);
  assert.ok(created.vault_id && created.grant);
  assert.ok((await store.load()).file.length > 100, 'the encrypted file is stored');
  assert.ok(area.data[SESSION_KEY], 'the key is kept for this session');

  const { id } = await backend.request('logins.save', { url: URL_, username: 'octo', password: 'hunter2-Long-enough' });
  assert.ok(events.some(([n]) => n === 'vault_changed'));
  const fill = await backend.request('logins.fill', { url: URL_, id });
  assert.equal(fill.password, 'hunter2-Long-enough');
  await assert.rejects(backend.request('logins.fill', { url: 'https://evil.example/', id }), (e) => e.code === 'url_mismatch');
  const stored = (await store.load()).file;
  assert.ok(!Buffer.from(stored).toString('latin1').includes('hunter2'), 'the stored file is encrypted');

  events.length = 0;
  await backend.lock(true);
  assert.deepEqual(events, [['lock_state', { locked: true }]]);
  assert.equal(area.data[SESSION_KEY], undefined);
  await assert.rejects(backend.request('logins.fill', { url: URL_, id }), (e) => e.code === 'locked');
  await assert.rejects(backend.unlock('wrong'), (e) => e.code === 'wrong_password');
  const unlocked = await backend.unlock(MASTER);
  assert.equal(unlocked.locked, false);
  assert.ok(unlocked.grant);

  const backup = await backend.exportVault();
  assert.ok((await backend.info()).backedUpAt > 0);
  await backend.deleteVault();
  assert.equal(await store.load(), null);
  assert.equal((await backend.request('status')).vault, false);

  const reopened = await backend.openFile(backup, MASTER);
  assert.equal(reopened.vault_id, created.vault_id, 'the same vault');
  assert.equal((await backend.request('logins.fill', { url: URL_, id })).username, 'octo');
});

test('a restarted service worker opens the vault from IndexedDB with the key in storage.session (no Argon2id)', { skip }, async () => {
  const store = memoryVaultStore();
  const area = sessionArea();
  const first = make({ store, area });
  await first.backend.create(MASTER);
  const { id } = await first.backend.request('logins.save', { url: URL_, username: 'octo', password: 'hunter2-Long-enough' });
  const start = performance.now();
  const again = make({ store, area });
  assert.equal((await again.backend.request('logins.fill', { url: URL_, id })).password, 'hunter2-Long-enough');
  const ms = performance.now() - start;
  console.log(`restart with the kept key: ${ms.toFixed(1)} ms`);
  assert.deepEqual(again.events, []);
});

test('the browser-only answers: unlock, desktop windows, confirmations, grants, copies', { skip }, async () => {
  const { backend, events } = make({ config: { verify_each_fill: true } });
  await backend.create(MASTER);
  const { id } = await backend.request('logins.save', { url: URL_, username: 'octo', password: 'hunter2-Long-enough' });
  await backend.lock(false);
  // Locked: `unlock` (the desktop app's own window) is the extension's popup in the browser.
  await assert.rejects(backend.request('unlock'), (e) => e.code === 'cancelled');
  const { grant } = await backend.unlock(MASTER);
  for (const [method, params] of [['totp.popup', { url: URL_, id }], ['app.show_item', { url: URL_, id }], ['server.pair', { link: 'https://pass.example.com' }]]) {
    await assert.rejects(backend.request(method, params), (e) => e.code === 'not_supported', method);
  }
  await assert.rejects(backend.request('logins.fill', { url: URL_, id }), (e) => e.code === 'verification_required');
  assert.equal((await backend.request('logins.fill', { url: URL_, id }, { grant })).password, 'hunter2-Long-enough');
  await assert.rejects(backend.request('logins.fill', { url: URL_, id }, { grant }), (e) => e.code === 'verification_required', 'used up');
  await assert.rejects(backend.request('logins.fill', { url: URL_, id }, { grant: 'forged-'.padEnd(43, 'x') }), (e) => e.code === 'verification_required');
  // Another site's login: only one the vault search just listed, and only with the yes of an extension page.
  await assert.rejects(backend.request('logins.fill_cross', { url: 'https://other.example/', id }, { confirmed: true }), (e) => e.code === 'url_mismatch');
  await backend.request('logins.search', { query: 'github', limit: 20 });
  await assert.rejects(backend.request('logins.fill_cross', { url: 'https://other.example/', id }), (e) => e.code === 'cancelled');
  const cross = await backend.request('logins.fill_cross', { url: 'https://other.example/', id }, { confirmed: true, grant: (await backend.verifyPassword(MASTER)).grant });
  assert.equal(cross.cross, true);
  assert.equal(cross.password, 'hunter2-Long-enough');
  events.length = 0;
  const g2 = (await backend.verifyPassword(MASTER)).grant;
  assert.deepEqual(await backend.request('logins.copy', { id, field: 'password', url: URL_ }, { grant: g2 }), { copied: true, field: 'password' });
  assert.deepEqual(events.filter(([n]) => n === 'copy'), [['copy', { text: 'hunter2-Long-enough' }]]);
  await backend.lock(false);
  const g3 = (await backend.unlock(MASTER)).grant;
  assert.equal((await backend.request('logins.fill', { url: URL_, id }, { grant: g3 })).username, 'octo', 'an unlock\'s grant counts for one fill');
});

test('setOptions: the auto-lock choices, including "only when the browser closes"', { skip }, async () => {
  const { backend } = make();
  await backend.create(MASTER);
  await backend.setOptions({ auto_lock_secs: autoLockSecs(0), verify_each_fill: false });
  assert.equal((await backend.info()).locked, false);
  await backend.setOptions({ auto_lock_secs: autoLockSecs(5) });
  assert.equal((await backend.request('status')).locked, false);
  await assert.rejects(backend.setOptions({ nope: 1 }), (e) => e.code === 'invalid_params');
});

test('a vault record of the builds that synced Google Drive themselves still opens and saves here (no sync)', { skip }, async () => {
  const store = memoryVaultStore();
  const first = make({ store });
  await first.backend.create(MASTER, { source: 'drive', name: 'Personal', account: 'alice@example.com', pending: false, syncedAt: 1, syncError: null });
  await first.backend.request('logins.save', { url: URL_, username: 'octo', password: 'hunter2-Long-enough' });
  await first.backend.lock(true);
  const again = make({ store });
  const info = await again.backend.info();
  assert.deepEqual([info.hasVault, info.locked, info.source, info.name, info.account], [true, true, 'drive', 'Personal', 'alice@example.com']);
  assert.equal('pending' in info, false, 'no sync state any more');
  await again.backend.unlock(MASTER);
  await again.backend.request('logins.save', { url: 'https://gitlab.com/users/sign_in', username: 'tanuki', password: 'hunter3-Long-enough' });
  const found = async (url) => (await again.backend.request('logins.find', { url })).items.map((i) => i.username);
  assert.deepEqual(await found(URL_), ['octo']);
  assert.deepEqual(await found('https://gitlab.com/users/sign_in'), ['tanuki']);
  assert.equal(typeof again.backend.drive, 'undefined', 'no Google Drive calls in the extension');
});
test('moving into the Passyble app: the file and its vault key, checked on a second instance; this one unchanged', { skip }, async () => {
  const { backend, events } = make();
  await backend.create(MASTER);
  await backend.request('logins.save', { url: URL_, username: 'octo', password: 'hunter2-Long-enough' });
  // Its vaults.list counts the items (the move offer).
  const list = await backend.request('vaults.list');
  assert.equal(list.vaults.find((v) => v.home).items, 1);
  await backend.lock(true);
  const before = events.length;
  await assert.rejects(backend.exportForMove((fresh) => fresh.unlock('wrong password here')), (e) => e.code === 'wrong_password');
  const out = await backend.exportForMove((fresh) => fresh.unlock(MASTER));
  assert.ok(out.file.length > 100);
  assert.equal(out.key.length, 32, 'the vault key');
  assert.ok(out.vaultId);
  assert.equal((await backend.info()).locked, true, 'this browser\'s vault stays locked');
  assert.equal(events.slice(before).some(([n]) => n === 'lock_state'), false, 'no lock event from the second instance');
  // The key opens that very file (what the agent's items.import does).
  const check = new wasm.BrowserAgent(JSON.stringify({ device_id: 'check' }));
  assert.ok(JSON.parse(check.load(out.file)).result);
  assert.equal(JSON.parse(check.unlockWithKey(out.key, 0)).result?.locked, false);
  check.free();
});
