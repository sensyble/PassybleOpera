// The browser vault's WebAssembly as the extension ships it (src/wasm/, `npm run wasm`) in Node's V8.
// Skipped when it hasn't been built (it is git-ignored).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

const dir = new URL('../src/wasm/', import.meta.url);
const built = existsSync(new URL('pass_wasm.js', dir)) && existsSync(new URL('pass_wasm_kdf.wasm', dir));
const skip = built ? false : 'src/wasm/ is not built (npm run wasm)';

// A passphrase the master password rule accepts (pass-core's own tests use it).
const PASSWORD = 'correct-horse-battery-staple-orbit';
const URL_ = 'https://github.com/login';

async function load() {
  const glue = await import(new URL('pass_wasm.js', dir));
  await glue.default({ module_or_path: readFileSync(new URL('pass_wasm_bg.wasm', dir)) });
  const { loadKdf } = await import(new URL('kdf.js', dir));
  return { ...glue, loadKdf };
}

const json = (text) => JSON.parse(text);
const request = (agent, method, params = {}, extra = {}) =>
  json(agent.handle(JSON.stringify({ id: 1, method, params, ...extra })));

test('create, fill, lock, restart with the key and unlock, through the Argon2id module', { skip }, async () => {
  const { BrowserAgent, setKdf, loadKdf } = await load();
  const argon2id = await loadKdf(readFileSync(new URL('pass_wasm_kdf.wasm', dir)));
  let runs = 0;
  setKdf((...args) => { runs++; return argon2id(...args); });

  const agent = new BrowserAgent(JSON.stringify({ device_id: 'node-test' }));
  assert.equal(agent.hasVault(), false);
  assert.equal(request(agent, 'logins.find', { url: URL_ }).error.code, 'no_vault');
  const created = json(agent.create(PASSWORD));
  assert.ok(created.result.vault_id, JSON.stringify(created));
  assert.equal(runs, 1, 'Argon2id ran in the separate module');
  assert.ok(agent.takeSave() instanceof Uint8Array);

  const saved = request(agent, 'logins.save', { url: URL_, username: 'octo', password: 'hunter2-Long-enough' });
  const id = saved.result.id;
  assert.equal(request(agent, 'logins.fill', { url: URL_, id }).result.password, 'hunter2-Long-enough');
  assert.equal(request(agent, 'logins.fill', { url: 'https://evil.example/', id }).error.code, 'url_mismatch');
  const status = request(agent, 'status').result;
  assert.ok(status.features.includes('vault.browser'));
  assert.equal(status.vault, true);

  // The service worker stops: the file from IndexedDB and the key from storage.session.
  const key = agent.vaultKey();
  const file = agent.exportVault();
  assert.equal(key.length, 32);
  assert.deepEqual(json(agent.lock(false)), { result: { locked: true } });
  const effects = json(agent.takeEffects());
  assert.ok(effects.some((e) => e.type === 'lock_state' && e.locked === true));

  const again = new BrowserAgent(JSON.stringify({ device_id: 'node-test' }));
  assert.ok(json(again.load(file)).result.vault_id);
  assert.deepEqual(json(again.unlockWithKey(key, 0)), { result: { locked: false } });
  assert.equal(runs, 1, 'no Argon2id for a restart');
  assert.equal(request(again, 'logins.fill', { url: URL_, id }).result.password, 'hunter2-Long-enough');

  const third = new BrowserAgent(JSON.stringify({ device_id: 'node-test' }));
  third.load(file);
  assert.equal(json(third.unlock('wrong')).error.code, 'wrong_password');
  assert.equal(json(third.unlock(PASSWORD)).result.locked, false);
  assert.equal(runs, 3);
  setKdf(undefined);
});

test('Argon2id with the vault defaults: the same key as the module itself, and how long it takes', { skip }, async () => {
  const { loadKdf } = await load();
  const argon2id = await loadKdf(readFileSync(new URL('pass_wasm_kdf.wasm', dir)));
  const salt = new Uint8Array(16).fill(7);
  const secret = new TextEncoder().encode(PASSWORD);
  const times = [];
  let first;
  for (let i = 0; i < 3; i++) {
    const start = performance.now();
    const key = argon2id(secret, salt, 64 * 1024, 3, 1);
    times.push(performance.now() - start);
    assert.equal(key.length, 32);
    if (first) assert.deepEqual(key, first);
    first = key;
  }
  // Each run is a fresh instance: nothing stays allocated in a long-lived one.
  console.log(`Argon2id m=64 MiB t=3 p=1 in a fresh instance: ${times.map((t) => t.toFixed(0)).join(', ')} ms`);
  assert.throws(() => argon2id(secret, salt, 64, 0, 1), /refused/);
});

test('checkMasterPassword: the core\'s master password rule, and create refuses what it refuses', { skip }, async () => {
  const { BrowserAgent, checkMasterPassword } = await load();
  const check = (pw, names = []) => json(checkMasterPassword(pw, JSON.stringify(names)));
  const empty = check('');
  assert.deepEqual([empty.ok, empty.label, empty.issues, empty.min_length], [false, '', [], 12]);
  assert.equal(check('short').issues[0], 'too_short');
  assert.ok(check('Password1234!').issues.includes('common'));
  assert.ok(check('AlexSmith2024!!', ['alex.smith@example.com']).issues.includes('contains_name'));
  assert.equal(check(PASSWORD).ok, true);
  assert.ok(['good', 'strong'].includes(check(PASSWORD).label));
  const agent = new BrowserAgent(JSON.stringify({ device_id: 'node-test' }));
  assert.equal(json(agent.create('Password1234!')).error.code, 'invalid_params');
  assert.equal(agent.hasVault(), false);
  agent.free();
});
