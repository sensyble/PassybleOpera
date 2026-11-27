// The Passyble password in the browser vault (src/background/account-keys.js) with the WebAssembly stand-in, a real
// LocalBackend and a fake account service. The service is never sent the password or the Secret Key.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { LocalBackend } from '../src/background/local/local-backend.js';
import { memoryVaultStore } from '../src/background/local/vault-store.js';
import { keySession } from '../src/background/local/session.js';
import { APPROVAL_KEY, PLATFORM, cleanDeviceName, createAccountKeys, memoryKeyStore, normalizeEmail } from '../src/background/account-keys.js';
import * as glue from './helpers/fake-wasm.js';

const ACCOUNT = 'acc_demo';
const EMAIL = 'demo@example.com';
const AK = 'ab'.repeat(32);
const SK = 'P1-ABCDE-FGHJK-MNPQR-STVWX-YZ012-34567';
const SALT = 'c2FsdHNhbHRzYWx0c2FsdA';
const KDF = { alg: 'argon2id', m_kib: 65536, t: 3, p: 1 };
const PASSWORD = 'a demo passphrase only';

function sessionArea() {
  const data = {};
  return {
    data,
    get: async (k) => (k in data ? { [k]: structuredClone(data[k]) } : {}),
    set: async (o) => { Object.assign(data, structuredClone(o)); },
    remove: async (k) => { delete data[k]; },
  };
}

/** The password wrap of AK the account service keeps for PASSWORD and SK. */
function pwWrap(password = PASSWORD, salt = SALT) {
  const derived = new glue.AccountPassword(password, SK, salt, JSON.stringify(KDF));
  const ak = glue.AccountKey.fromBytes(ACCOUNT, Uint8Array.from(AK.match(/../g), (h) => parseInt(h, 16)), glue.fakeAkId(ACCOUNT, AK));
  return JSON.parse(ak.passwordWrap(derived));
}

/** A fake account service: routes answer from `routes[METHOD path]` (a value or a function of the request). */
function service(routes) {
  const calls = [];
  const fetch = async (url, init) => {
    const u = new URL(url);
    const key = `${init.method} ${u.pathname}`;
    const body = init.body ? JSON.parse(init.body) : undefined;
    calls.push({ key, body, headers: init.headers, credentials: init.credentials });
    let answer = routes[key];
    if (typeof answer === 'function') answer = answer({ body, headers: init.headers, calls });
    if (answer instanceof Error) throw answer;
    if (!answer) answer = { status: 404, body: { error: 'not_found' } };
    const status = answer.status ?? 200;
    return { status, ok: status >= 200 && status < 300, json: async () => answer.body ?? answer, headers: { get: () => null } };
  };
  return { fetch, calls };
}

function tokens(account = ACCOUNT, email = EMAIL) {
  return { access_token: 'pat_x', refresh_token: 'prt_x', expires_in: 900, account: { id: account, email } };
}

function fakeAccount({ signedIn = null } = {}) {
  const state = { me: signedIn, kept: [], revoked: [] };
  return {
    state,
    base: async () => 'https://account.test',
    current: async () => state.me,
    accessToken: async () => (state.me ? 'pat_signed_in' : null),
    signedInWith: async (body) => { state.kept.push(body); state.me = { id: body.account.id, email: body.account.email }; return state.me; },
    revoke: async (t) => { state.revoked.push(t); },
  };
}

async function make({ file = glue.fakeLinkedVaultFile(ACCOUNT, AK), routes = {}, signedIn = null, store = memoryKeyStore(), area = sessionArea(), now = () => Date.now(),
  wasm = glue } = {}) {
  const local = new LocalBackend({
    wasm: async () => ({ BrowserAgent: glue.BrowserAgent, glue }),
    store: memoryVaultStore(),
    session: keySession(sessionArea()),
    config: async () => ({ device_id: 'test-device' }),
    setTimeout: () => 0,
    clearTimeout: () => {},
    log: { error() {}, warn() {} },
  });
  if (file) {
    // A linked vault from another device, opened once with its account key, then locked: as after a restart.
    const ak = glue.AccountKey.fromBytes(ACCOUNT, Uint8Array.from(AK.match(/../g), (h) => parseInt(h, 16)), glue.fakeAkId(ACCOUNT, AK));
    await local.openFileWithAccountKey(file, ak);
    await local.lock(true);
  }
  const svc = service(routes);
  const account = fakeAccount({ signedIn });
  const keys = createAccountKeys({ glue: async () => wasm, account, local, store, session: area, fetch: svc.fetch,
    deviceName: () => '  Chrome on Linux\u0007  ', now, consent: async () => true });
  return { keys, local, svc, account, store, area };
}

const signInRoutes = (extra = {}) => ({
  'POST /v1/prelogin': { salt: SALT, kdf: KDF, nonce: 'nonce-1' },
  'POST /v1/session/password': ({ body }) => (body.sig.startsWith(`sig:${new glue.AccountPassword(PASSWORD, SK, SALT, JSON.stringify(KDF))._h}:`)
    ? { ...tokens(), account_key: { ak_id: glue.fakeAkId(ACCOUNT, AK), salt: SALT, kdf: KDF, pw_wrap: pwWrap(), sk_wrap: { nonce: 'n', ct: 'x' } } }
    : { status: 403, body: { error: 'wrong_password' } }),
  ...extra,
});

test('the address and the device name are signed as the account service normalizes them', () => {
  assert.equal(normalizeEmail('  Demo@Example.COM '), EMAIL);
  assert.equal(normalizeEmail('no-at-sign'), '');
  assert.equal(normalizeEmail('a@b@example.com'), '');
  assert.equal(cleanDeviceName('  Chrome on Linux\u0007 '), 'Chrome on Linux');
  assert.equal(cleanDeviceName(''), 'Passyble');
  assert.equal(cleanDeviceName('x'.repeat(80)).length, 64);
});

test('a linked vault: the Secret Key once, a password sign-in the first time, offline from the kept wrap after', async () => {
  const { keys, local, svc, account, store } = await make({ routes: signInRoutes() });
  const info = await keys.unlockInfo();
  assert.deepEqual(info, { account: ACCOUNT, email: '', secret_key_needed: true, email_needed: true });

  // No Secret Key here yet: asked for, nothing sent.
  await assert.rejects(keys.unlockVault({ password: PASSWORD }), (e) => e.reason === 'secret_key_needed');
  // No address known: asked for.
  await assert.rejects(keys.unlockVault({ password: PASSWORD, secretKey: SK }), (e) => e.reason === 'email_needed');
  assert.equal(svc.calls.length, 0);
  // A recovery code (or anything else) typed as the Secret Key.
  await assert.rejects(keys.unlockVault({ password: PASSWORD, secretKey: 'not a key', email: EMAIL }), (e) => e.reason === 'bad_secret_key');

  const typed = SK.toLowerCase().replace(/-/g, ' ');
  const res = await keys.unlockVault({ password: PASSWORD, secretKey: typed, email: ' Demo@Example.com ' });
  assert.ok(res.grant);
  assert.equal((await local.info()).locked, false);
  assert.deepEqual(svc.calls.map((c) => c.key), ['POST /v1/prelogin', 'POST /v1/session/password']);
  assert.deepEqual(svc.calls[0].body, { email: EMAIL });
  const signIn = svc.calls[1].body;
  assert.deepEqual(Object.keys(signIn).sort(), ['client_id', 'device_name', 'email', 'nonce', 'platform', 'sig']);
  assert.equal(signIn.client_id, 'passyble-extension');
  assert.equal(signIn.device_name, 'Chrome on Linux');
  assert.equal(signIn.platform, PLATFORM);
  assert.match(signIn.sig, new RegExp(`:${EMAIL}:nonce-1:Chrome on Linux:${PLATFORM}$`));
  // Nothing secret went out, cookies neither.
  assert.ok(svc.calls.every((c) => !JSON.stringify(c.body || {}).includes(PASSWORD) && !JSON.stringify(c.body || {}).includes('ABCDE')));
  assert.ok(svc.calls.every((c) => c.credentials === 'omit'));
  // The sign-in also signed this browser in.
  assert.equal(account.state.kept.length, 1);
  const kept = (await store.get()).accounts[ACCOUNT];
  assert.equal(kept.secret_key, SK);
  assert.equal(kept.email, EMAIL);
  assert.equal(kept.ak_id, glue.fakeAkId(ACCOUNT, AK));
  assert.deepEqual(kept.pw_wrap, pwWrap());

  // Next time: offline, the kept Secret Key and wrap; nothing sent.
  await local.lock(true);
  assert.deepEqual(await keys.unlockInfo(), { account: ACCOUNT, email: EMAIL, secret_key_needed: false, email_needed: false });
  const before = svc.calls.length;
  await keys.unlockVault({ password: PASSWORD });
  assert.equal(svc.calls.length, before);
  assert.equal((await local.info()).locked, false);
  // The Passyble password checked again while unlocked ("Confirm each fill").
  assert.ok((await keys.verify({ password: PASSWORD })).grant);
  assert.ok(glue.fakeStats.keysFreed >= 2);
});

test('"This is a shared computer": the Secret Key is used once and not kept', async () => {
  const { keys, store } = await make({ routes: signInRoutes() });
  await keys.unlockVault({ password: PASSWORD, secretKey: SK, shared: true, email: EMAIL });
  const kept = (await store.get()).accounts[ACCOUNT];
  assert.equal(kept.secret_key, undefined);
  assert.equal((await keys.unlockInfo()).secret_key_needed, true);
});

test('a wrong password: offline it is wrong, online the service says so, with the reason the pages show', async () => {
  const store = memoryKeyStore();
  await store.set({ accounts: { [ACCOUNT]: { email: EMAIL, ak_id: glue.fakeAkId(ACCOUNT, AK), salt: SALT, kdf: KDF, pw_wrap: pwWrap(), secret_key: SK } } });
  // Offline: the kept wrap says no, the service can't be asked.
  const offline = await make({ store, routes: { 'POST /v1/prelogin': new TypeError('Failed to fetch') } });
  await assert.rejects(offline.keys.unlockVault({ password: 'wrong one' }), (e) => e.code === 'wrong_password' && e.reason === 'wrong_account_password');
  assert.equal((await offline.local.info()).locked, true);
  // Online: the kept wrap says no, the sign-in too.
  const online = await make({ store, routes: signInRoutes() });
  await assert.rejects(online.keys.unlockVault({ password: 'wrong one' }), (e) => e.reason === 'wrong_account_password');
  assert.deepEqual(online.svc.calls.map((c) => c.key), ['POST /v1/prelogin', 'POST /v1/session/password']);
  // Too many: the service's limit.
  const limited = await make({ store, routes: signInRoutes({ 'POST /v1/session/password': { status: 429, body: { error: 'password_limited' } } }) });
  await assert.rejects(limited.keys.unlockVault({ password: 'wrong one' }), (e) => e.reason === 'password_limited');
});

test('the password changed on another device: the signed-in browser gets the new wrap through /v1/account-key/unlock', async () => {
  const store = memoryKeyStore();
  await store.set({ accounts: { [ACCOUNT]: { email: EMAIL, ak_id: glue.fakeAkId(ACCOUNT, AK), salt: SALT, kdf: KDF, pw_wrap: pwWrap('the old one'), secret_key: SK } } });
  const NEW_SALT = 'bmV3c2FsdG5ld3NhbHRuZQ';
  const { keys, svc } = await make({
    store,
    signedIn: { id: ACCOUNT, email: EMAIL },
    routes: {
      'GET /v1/account-key': { set: true, ak_id: glue.fakeAkId(ACCOUNT, AK), salt: NEW_SALT, kdf: KDF },
      'POST /v1/account-key/nonce': ({ body }) => (body.purpose === 'unlock' ? { nonce: 'n-unlock' } : { status: 400 }),
      'POST /v1/account-key/unlock': { account_key: { ak_id: glue.fakeAkId(ACCOUNT, AK), salt: NEW_SALT, kdf: KDF, pw_wrap: pwWrap(PASSWORD, NEW_SALT) } },
    },
  });
  await keys.unlockVault({ password: PASSWORD });
  assert.deepEqual(svc.calls.map((c) => c.key), ['GET /v1/account-key', 'POST /v1/account-key/nonce', 'POST /v1/account-key/unlock']);
  assert.ok(svc.calls.every((c) => c.headers.Authorization === 'Bearer pat_signed_in'));
  assert.match(svc.calls[2].body.sig, new RegExp(`:${EMAIL}:n-unlock:`));
  assert.equal((await store.get()).accounts[ACCOUNT].salt, NEW_SALT);
});

test("another account's password signs nothing in here", async () => {
  const { keys, account } = await make({
    routes: signInRoutes({
      'POST /v1/session/password': { ...tokens('acc_other', 'other@example.com'),
        account_key: { ak_id: glue.fakeAkId('acc_other', AK), salt: SALT, kdf: KDF, pw_wrap: pwWrap() } },
    }),
  });
  await assert.rejects(keys.unlockVault({ password: PASSWORD, secretKey: SK, email: 'other@example.com' }),
    (e) => e.reason === 'other_account' || e.code === 'wrong_password');
  assert.equal(account.state.kept.length, 0);
});

test('"Sign in with your Passyble password": signs in, keeps the Secret Key, opens the linked vault', async () => {
  const { keys, local, account, store } = await make({ routes: signInRoutes() });
  await assert.rejects(keys.signIn({ email: EMAIL, password: PASSWORD }), (e) => e.reason === 'secret_key_needed');
  const res = await keys.signIn({ email: 'DEMO@example.com', password: PASSWORD, secretKey: SK });
  assert.deepEqual(res, { email: EMAIL, unlocked: true });
  assert.equal((await local.info()).locked, false);
  assert.equal(account.state.kept.length, 1);
  assert.equal((await store.get()).accounts[ACCOUNT].secret_key, SK);
  // Next time this address needs no Secret Key typed.
  await local.lock(true);
  assert.deepEqual(await keys.signIn({ email: EMAIL, password: PASSWORD }), { email: EMAIL, unlocked: true });
});

test('"Open a vault file" of a linked vault opens with the Passyble password', async () => {
  const { keys, local } = await make({ file: null, routes: signInRoutes() });
  const file = glue.fakeLinkedVaultFile(ACCOUNT, AK);
  const access = await local.fileAccess(file);
  assert.equal(access.kind, 'account');
  assert.equal((await keys.fileInfo(ACCOUNT, access.ak_id)).secret_key_needed, true);
  const res = await keys.openFile(file, access, { password: PASSWORD, secretKey: SK, email: EMAIL });
  assert.ok(res.vault_id);
  const info = await local.info();
  assert.equal(info.hasVault, true);
  assert.equal(info.locked, false);
});

test('approved as a new device: the request without a session, the code, then the keys and a session', async () => {
  let state = 'waiting';
  let rA = null;
  let enc = null;
  const area = sessionArea();
  const { keys, local, svc, account, store } = await make({
    area,
    routes: {
      'POST /v1/account-key/requests': ({ body }) => { enc = body.enc_pub; return { status: 201, body: { id: 'akq_1', expires_at: Date.now() + 600_000, poll_token: 'akp_secret' } }; },
      'GET /v1/account-key/requests/akq_1': ({ headers }) => {
        if (headers['X-Pass-Request-Token'] !== 'akp_secret') return { status: 401, body: { error: 'sign_in_required' } };
        if (state === 'waiting') return { id: 'akq_1', state };
        if (state === 'accepted') return { id: 'akq_1', state, account: ACCOUNT, r_a: rA };
        return { id: 'akq_1', state: 'sealed', account: ACCOUNT, ak_id: glue.fakeAkId(ACCOUNT, AK), r_a: rA,
          sealed: glue.fakeSealFor(enc, AK, SK), session: tokens() };
      },
      'POST /v1/account-key/requests/akq_1/reveal': ({ body }) => ({ status: 204, body: { r_n: body.r_n } }),
    },
  });
  await assert.rejects(keys.approvalStart({ email: 'nope' }), (e) => e.reason === 'email_needed');
  const start = await keys.approvalStart({ email: ' Demo@Example.com ' });
  assert.equal(start.id, 'akq_1');
  assert.deepEqual(start.qr, { size: 29, path: 'M4 4h1v1h-1z' });
  const req = svc.calls[0].body;
  assert.deepEqual(Object.keys(req).sort(), ['client_id', 'commitment', 'device_name', 'email', 'enc_pub', 'platform']);
  assert.equal(req.email, EMAIL);
  assert.equal(req.client_id, 'passyble-extension');
  assert.equal(svc.calls[0].headers.Authorization, undefined);
  // The one-time key waits in storage.session (a restarted service worker goes on).
  assert.ok(area.data[APPROVAL_KEY].secret.startsWith('dak-'));

  assert.equal((await keys.approvalPoll()).state, 'waiting');
  state = 'accepted';
  rA = 'r-a-value';
  const coded = await keys.approvalPoll();
  assert.equal(coded.state, 'code');
  assert.equal(coded.code, glue.fakeApprovalCode('akq_1', ACCOUNT, enc, rA));
  assert.ok(svc.calls.some((c) => c.key === 'POST /v1/account-key/requests/akq_1/reveal' && c.body.r_n.startsWith('rn-')));
  // Revealed once only.
  await keys.approvalPoll();
  assert.equal(svc.calls.filter((c) => c.key.endsWith('/reveal')).length, 1);

  state = 'sealed';
  // The keys arrived: held for the fingerprint check, nothing kept and no session taken yet.
  const check = await keys.approvalPoll();
  assert.deepEqual(check, { state: 'check', fingerprint: glue.fakeAkFingerprint(AK) });
  assert.equal(account.state.kept.length, 0);
  assert.equal((await store.get())?.accounts?.[ACCOUNT]?.secret_key, undefined);
  assert.equal((await local.info()).locked, true);
  assert.equal(area.data[APPROVAL_KEY], undefined, 'the request is over');
  // The page polls on while the user compares (and a page opened again gets the same fingerprint).
  assert.deepEqual(await keys.approvalPoll(), check);

  const done = await keys.approvalConfirm({ matches: true });
  assert.deepEqual(done, { state: 'done', email: EMAIL, unlocked: true });
  assert.equal(account.state.kept.length, 1);
  assert.equal((await store.get()).accounts[ACCOUNT].secret_key, SK);
  assert.equal((await local.info()).locked, false);
  assert.equal(area.data[APPROVAL_KEY], undefined);
  assert.equal((await keys.approvalPoll()).state, 'none');
});

test('an approval that is denied, expires, or brings keys that do not open ends cleanly', async () => {
  const area = sessionArea();
  let answer = { id: 'akq_2', state: 'denied' };
  const { keys, account } = await make({
    area,
    routes: {
      'POST /v1/account-key/requests': { status: 201, body: { id: 'akq_2', poll_token: 'akp_2' } },
      'GET /v1/account-key/requests/akq_2': () => answer,
    },
  });
  await keys.approvalStart({ email: EMAIL });
  assert.equal((await keys.approvalPoll()).state, 'denied');
  assert.equal(area.data[APPROVAL_KEY], undefined);

  await keys.approvalStart({ email: EMAIL, shared: true });
  answer = { status: 404, body: { error: 'not_found' } };
  assert.equal((await keys.approvalPoll()).state, 'expired');

  await keys.approvalStart({ email: EMAIL });
  answer = { id: 'akq_2', state: 'sealed', account: ACCOUNT, ak_id: glue.fakeAkId(ACCOUNT, AK), r_a: 'x',
    sealed: glue.fakeSealFor('enc-someone-else', AK, SK), session: tokens() };
  await assert.rejects(keys.approvalPoll(), (e) => e.reason === 'approval_mismatch');
  // The session that came with keys that don't open is given back, never kept.
  assert.equal(account.state.kept.length, 0);
  assert.deepEqual(account.state.revoked, ['prt_x']);
  assert.equal(area.data[APPROVAL_KEY], undefined);
});

/** A fake account service that seals `akHex` to this browser's request as soon as it is asked. */
function sealingRoutes(akHex = AK, { session = tokens() } = {}) {
  let enc = null;
  return {
    'POST /v1/account-key/requests': ({ body }) => { enc = body.enc_pub; return { status: 201, body: { id: 'akq_3', poll_token: 'akp_3' } }; },
    'GET /v1/account-key/requests/akq_3': () => ({ id: 'akq_3', state: 'sealed', account: ACCOUNT, ak_id: glue.fakeAkId(ACCOUNT, akHex), r_a: 'r-a',
      sealed: glue.fakeSealFor(enc, akHex, SK), session }),
  };
}

/** Nothing of an approval was kept: no record, no Secret Key, no session, the vault still locked, the keys freed. */
async function assertNothingKept({ store, account, local }, freedBefore) {
  assert.deepEqual((await store.get())?.accounts?.[ACCOUNT] ?? null, null);
  assert.equal(account.state.kept.length, 0);
  assert.deepEqual(account.state.revoked, ['prt_x'], 'the session that came with them is given back');
  assert.equal((await local.info()).locked, true);
  assert.equal(glue.fakeStats.approvedFreed, freedBefore + 1, 'the WebAssembly keys are freed');
}

test('attack: the service seals its own account key: another fingerprint, and a mismatch keeps nothing', async () => {
  const ATTACKER_AK = 'cd'.repeat(32);
  const made = await make({ routes: sealingRoutes(ATTACKER_AK) });
  const { keys } = made;
  await keys.approvalStart({ email: EMAIL });
  const freed = glue.fakeStats.approvedFreed;
  const check = await keys.approvalPoll();
  assert.equal(check.state, 'check');
  // The user compares with Settings, Passyble password on the other device, which shows the real key's.
  assert.notEqual(check.fingerprint, glue.fakeAkFingerprint(AK));
  assert.deepEqual(await keys.approvalConfirm({ matches: false }), { state: 'rejected' });
  await assertNothingKept(made, freed);
  assert.equal((await keys.approvalPoll()).state, 'none');
  assert.equal((await keys.approvalConfirm({ matches: true })).state, 'expired', 'an "It matches" after it keeps nothing either');
  assert.deepEqual((await made.store.get())?.accounts?.[ACCOUNT] ?? null, null);
});

test('arrived keys: only a strict yes keeps them; Cancel drops them and says so', async () => {
  let made = await make({ routes: sealingRoutes() });
  await made.keys.approvalStart({ email: EMAIL });
  let freed = glue.fakeStats.approvedFreed;
  await made.keys.approvalPoll();
  assert.deepEqual(await made.keys.approvalConfirm({ matches: 'yes' }), { state: 'rejected' });
  await assertNothingKept(made, freed);

  made = await make({ routes: sealingRoutes() });
  await made.keys.approvalStart({ email: EMAIL });
  freed = glue.fakeStats.approvedFreed;
  assert.equal((await made.keys.approvalPoll()).state, 'check');
  assert.deepEqual(await made.keys.approvalCancel(), { state: 'none', dropped: true });
  await assertNothingKept(made, freed);
  assert.deepEqual(await made.keys.approvalCancel(), { state: 'none' }, 'nothing left to drop');

  // A new request while keys wait drops them first.
  made = await make({ routes: sealingRoutes() });
  await made.keys.approvalStart({ email: EMAIL });
  freed = glue.fakeStats.approvedFreed;
  await made.keys.approvalPoll();
  await made.keys.approvalStart({ email: EMAIL });
  assert.equal(glue.fakeStats.approvedFreed, freed + 1);
  assert.deepEqual(made.account.state.revoked, ['prt_x']);
});

test('arrived keys wait 5 minutes for the check, then they are dropped', async () => {
  let clock = Date.now();
  const made = await make({ routes: sealingRoutes(), now: () => clock });
  await made.keys.approvalStart({ email: EMAIL });
  const freed = glue.fakeStats.approvedFreed;
  assert.equal((await made.keys.approvalPoll()).state, 'check');
  clock += 5 * 60_000 + 1;
  assert.deepEqual(await made.keys.approvalPoll(), { state: 'expired' });
  await assertNothingKept(made, freed);
  assert.deepEqual(await made.keys.approvalConfirm({ matches: true }), { state: 'expired' });
});

test('a build that cannot show the account key fingerprint keeps no arrived keys', async () => {
  class NoFingerprint extends glue.DeviceApprovalKeys {
    static restore(secret) { return Object.setPrototypeOf(glue.DeviceApprovalKeys.restore(secret), NoFingerprint.prototype); }
    open(...args) { const approved = super.open(...args); approved.fingerprint = undefined; return approved; }
  }
  const made = await make({ routes: sealingRoutes(), wasm: { ...glue, DeviceApprovalKeys: NoFingerprint } });
  await made.keys.approvalStart({ email: EMAIL });
  const freed = glue.fakeStats.approvedFreed;
  await assert.rejects(made.keys.approvalPoll(), (e) => e.code === 'update_required' && e.reason === 'extension_update');
  await assertNothingKept(made, freed);
  assert.equal((await made.keys.approvalConfirm({ matches: true })).state, 'expired');
});
