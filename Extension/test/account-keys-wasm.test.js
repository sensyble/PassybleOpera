// The Passyble password on the real WebAssembly and Argon2id module: the pass-wasm exports give exactly Core's
// vectors, and a vault linked to the vectors' account key opens through account-keys.js. Skipped when src/wasm/
// isn't built or the sibling Core checkout isn't there.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { LocalBackend } from '../src/background/local/local-backend.js';
import { memoryVaultStore } from '../src/background/local/vault-store.js';
import { keySession } from '../src/background/local/session.js';
import { createAccountKeys, memoryKeyStore } from '../src/background/account-keys.js';
import { b64urlDecode } from '../src/shared/b64url.js';

const dir = new URL('../src/wasm/', import.meta.url);
const vectorsUrl = new URL('../../Core/core/tests/account_key_vectors.json', import.meta.url);
const fixtureUrl = new URL('../../Core/wasm/tests/fixtures/linked.vault', import.meta.url);
const built = existsSync(new URL('pass_wasm_bg.wasm', dir)) && existsSync(new URL('pass_wasm_kdf.wasm', dir));
const skip = !built ? 'src/wasm/ is not built (npm run wasm)'
  : !existsSync(vectorsUrl) || !existsSync(fixtureUrl) ? 'no ../Core checkout with the account key vectors' : false;
let glue = null;
let v = null;

before(async () => {
  if (skip) return;
  glue = await import(new URL('pass_wasm.js', dir));
  await glue.default({ module_or_path: readFileSync(new URL('pass_wasm_bg.wasm', dir)) });
  const { loadKdf } = await import(new URL('kdf.js', dir));
  glue.setKdf(await loadKdf(readFileSync(new URL('pass_wasm_kdf.wasm', dir))));
  if (typeof glue.AccountPassword !== 'function') throw new Error('src/wasm/ is from a core without the account key exports: npm run wasm');
  v = JSON.parse(readFileSync(vectorsUrl, 'utf8'));
});

const enc = new TextEncoder();
const envelope = (text) => JSON.parse(text);

test('the Secret Key, the sign-in key, its signature and the password wrap give Core\'s vectors', { skip }, () => {
  const typed = v.secret_key.text.toLowerCase().replace(/-/g, ' ');
  assert.equal(envelope(glue.secretKeyText(typed)).result.text, v.secret_key.text);
  assert.equal(envelope(glue.secretKeyText('P1-not-a-key')).error.code, 'invalid_params');
  const pw = v.passwords[0];
  const derived = new glue.AccountPassword(pw.password, v.secret_key.text, pw.salt, JSON.stringify(pw.kdf));
  try {
    assert.equal(derived.authPub(), pw.auth_pub);
    assert.equal(derived.signIn(v.email, v.sign_in.nonce, v.sign_in.device_name, v.sign_in.platform), v.sign_in.sig);
    const ak = derived.openAccountKey(v.account, v.ak_id, JSON.stringify({ nonce: v.password_wrap.nonce, ct: v.password_wrap.ct }));
    try {
      assert.equal(ak.akId(), v.ak_id);
      assert.equal(ak.akSignPub(), v.ak_sign_pub);
      assert.deepEqual([...ak.toBytes()], [...b64urlDecode(v.ak)]);
      const r = v.request_signature;
      assert.equal(ak.signRequest(r.nonce, r.method, r.path, enc.encode(r.body)), r.sig);
      assert.equal(ak.openSecretKey(JSON.stringify({ nonce: v.sk_wrap.nonce, ct: v.sk_wrap.ct })), v.secret_key.text);
    } finally {
      ak.free();
    }
    // Another password: wrong_password, nothing opened.
    const wrong = new glue.AccountPassword('another password', v.secret_key.text, pw.salt, JSON.stringify(pw.kdf));
    assert.throws(() => wrong.openAccountKey(v.account, v.ak_id, JSON.stringify({ nonce: v.password_wrap.nonce, ct: v.password_wrap.ct })),
      /^Error: wrong_password: /);
    wrong.free();
  } finally {
    derived.free();
  }
  // Parameters below the apps' minimum are refused.
  assert.throws(() => new glue.AccountPassword('x', v.secret_key.text, pw.salt, JSON.stringify({ ...pw.kdf, m_kib: 19456 })), /invalid_params/);
});

test('a passkey PRF wrap, the Emergency Kit QR and a new device\'s keys', { skip }, () => {
  const prf = glue.AccountKey.openPrf(v.account, v.ak_id, b64urlDecode(v.prf.prf_output), v.prf.credential_id,
    JSON.stringify({ nonce: v.prf.wrap.nonce, ct: v.prf.wrap.ct }));
  assert.equal(prf.akId(), v.ak_id);
  prf.free();
  const kit = envelope(glue.parseKitQr(v.emergency_kit_qr)).result;
  assert.deepEqual(kit, { email: v.email, account: v.account, secret_key: v.secret_key.text });

  const keys = new glue.DeviceApprovalKeys();
  const again = glue.DeviceApprovalKeys.restore(String(keys.secret()));
  assert.equal(again.encPub(), keys.encPub());
  assert.equal(again.code('akq_1', v.account, v.device_approval.r_a), keys.code('akq_1', v.account, v.device_approval.r_a));
  assert.match(keys.code('akq_1', v.account, v.device_approval.r_a), /^\d{6}$/);
  assert.ok(keys.approvalQr('akq_1').startsWith('passyble:approve/v1?id=akq%5F1&k='));
  const qr = envelope(glue.qrSvgPath(keys.approvalQr('akq_1'))).result;
  assert.ok(qr.size >= 29 && qr.path.startsWith('M'));
  // Sealed keys for another one-time key don't open.
  assert.throws(() => keys.open('akq_1', v.account, v.ak_id, v.device_approval.r_a, JSON.stringify({ enc: v.device_approval.enc_pub, ct: 'AAAA' })));
  keys.free();
  again.free();
});

test('the linked fixture opens in the browser vault with the Passyble password, then offline', { skip }, async () => {
  const fixture = readFileSync(fixtureUrl);
  const access = envelope(glue.vaultFileAccess(fixture)).result;
  assert.equal(access.kind, 'account');
  assert.equal(access.ak_id, v.ak_id);
  const data = {};
  const area = {
    get: async (k) => (k in data ? { [k]: structuredClone(data[k]) } : {}),
    set: async (o) => { Object.assign(data, structuredClone(o)); },
    remove: async (k) => { delete data[k]; },
  };
  const local = new LocalBackend({
    wasm: async () => ({ BrowserAgent: glue.BrowserAgent, glue }),
    store: memoryVaultStore(),
    session: keySession(area),
    config: async () => ({ device_id: 'chrome-test' }),
    setTimeout: () => 0,
    clearTimeout: () => {},
    log: { error() {}, warn() {} },
  });
  const pw = v.passwords[0];
  const sent = [];
  const fetch = async (url, init) => {
    const path = new URL(url).pathname;
    sent.push(path);
    const body = path === '/v1/prelogin' ? { salt: pw.salt, kdf: pw.kdf, nonce: 'n-1' }
      : { access_token: 'pat', refresh_token: 'prt', expires_in: 900, account: { id: v.account, email: v.email },
        account_key: { ak_id: v.ak_id, salt: pw.salt, kdf: pw.kdf, pw_wrap: { nonce: v.password_wrap.nonce, ct: v.password_wrap.ct } } };
    return { status: 200, ok: true, json: async () => body, headers: { get: () => null } };
  };
  const account = { base: async () => 'https://account.test', current: async () => null, accessToken: async () => null,
    signedInWith: async (b) => ({ id: b.account.id, email: b.account.email }), revoke: async () => {} };
  const keys = createAccountKeys({ glue: async () => glue, account, local, store: memoryKeyStore(), session: area, fetch,
    consent: async () => true, deviceName: () => 'Chrome on Linux' });

  const res = await keys.openFile(fixture, access, { password: pw.password, secretKey: v.secret_key.text, email: v.email });
  assert.ok(res.vault_id);
  const found = await local.request('logins.find', { url: 'https://example.com/login' });
  assert.deepEqual(found.items.map((i) => i.title), ['Demo']);
  assert.deepEqual(sent, ['/v1/prelogin', '/v1/session/password']);
  // Locked and opened again: the kept Secret Key and wrap, no request.
  await local.lock(true);
  await keys.unlockVault({ password: pw.password });
  assert.equal(sent.length, 2);
  assert.equal((await local.info()).locked, false);
  await assert.rejects(keys.verify({ password: 'not it' }), (e) => e.reason === 'wrong_account_password' || e.code === 'wrong_password');
});
