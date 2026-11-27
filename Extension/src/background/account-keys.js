// The Passyble password for the browser vault (browser mode only; in app mode the app holds the account key).
// A linked vault opens with the account key (AK), which this browser gets from the Passyble password and the
// Secret Key (the password and Secret Key never leave the browser), or from another device approving this one.
// Approved keys stay in memory until the user confirms the AK fingerprint matches the other device's: a
// breached service sealing its own key would show another fingerprint.
//
// The Secret Key and the password wrap are kept in IndexedDB (out of reach of content scripts) unless the
// user says the computer is shared; AK itself is never stored.
import { ErrorCode, PassError, Reason } from '../shared/errors.js';
import { ACCOUNT_DATA, hasDataConsent } from '../shared/data-consent.js';
import { CLIENT_ID, deviceName as defaultDeviceName, idbAccountRecord } from './account.js';

export const PLATFORM = 'extension';
export const APPROVAL_KEY = 'passAccountApproval';
export const MAX_ACCOUNT_PASSWORD = 128;
const MAX_DEVICE_NAME = 64;
const REQUEST_TOKEN_HEADER = 'X-Pass-Request-Token';
const REQUEST_TTL_MS = 10 * 60_000;
// Arrived keys wait this long for the fingerprint check (the page's polling keeps the service worker up).
const CHECK_TTL_MS = 5 * 60_000;

const ACCOUNT_KEY_ROUTES = Object.freeze({
  prelogin: ['POST', '/v1/prelogin'],
  sessionPassword: ['POST', '/v1/session/password'],
  status: ['GET', '/v1/account-key'],
  nonce: ['POST', '/v1/account-key/nonce'],
  unlock: ['POST', '/v1/account-key/unlock'],
  request: ['POST', '/v1/account-key/requests'],
  poll: ['GET', '/v1/account-key/requests/<id>'],
  reveal: ['POST', '/v1/account-key/requests/<id>/reveal'],
});

export function normalizeEmail(input) {
  const email = String(input ?? '').trim().toLowerCase();
  if (!email || email.length > 254 || /[\s<>()[\],;:\\"]/.test(email) || /\p{Cc}/u.test(email)) return '';
  const at = email.indexOf('@');
  if (at <= 0 || at > 64 || email.indexOf('@', at + 1) >= 0 || !email.slice(at + 1).includes('.')) return '';
  return email;
}

export function cleanDeviceName(name) {
  const clean = [...String(name ?? '').trim()].filter((c) => !/\p{Cc}/u.test(c)).slice(0, MAX_DEVICE_NAME).join('');
  return clean || 'Passyble';
}

/** A pass-wasm error (`"<code>: <message>"`) as a PassError with that code. */
function wasmError(err) {
  const text = String(err?.message ?? err ?? '');
  const m = /^([a-z_]+): /.exec(text);
  return new PassError(m ? m[1] : ErrorCode.INTERNAL, text);
}

function keyError(reason, message) {
  const code = reason === Reason.WRONG_ACCOUNT_PASSWORD ? ErrorCode.WRONG_PASSWORD
    : reason === Reason.PASSWORD_LIMITED ? ErrorCode.RATE_LIMITED : ErrorCode.INVALID_STATE;
  return new PassError(code, message, reason);
}

function serviceError(status, code) {
  if (status === 0) return new PassError(ErrorCode.INTERNAL, 'no answer from the account service', Reason.ACCOUNT_OFFLINE);
  if (code === 'wrong_password') return keyError(Reason.WRONG_ACCOUNT_PASSWORD, 'wrong password');
  if (code === 'password_limited' || status === 429) return keyError(Reason.PASSWORD_LIMITED, code || 'too many attempts');
  if (code === 'account_keys_off') return keyError(Reason.ACCOUNT_KEYS_OFF, code);
  if (code === 'no_password') return keyError(Reason.NO_ACCOUNT_PASSWORD, code);
  return new PassError(ErrorCode.INTERNAL, `${status} ${code || ''}`.trim(), Reason.ACCOUNT_SERVICE);
}

function sanitizeRecords(value) {
  const accounts = {};
  for (const [id, r] of Object.entries(value?.accounts || {})) {
    if (!/^[A-Za-z0-9_-]{1,128}$/.test(id) || !r || typeof r !== 'object') continue;
    accounts[id] = {
      email: typeof r.email === 'string' ? r.email : '',
      ak_id: typeof r.ak_id === 'string' ? r.ak_id : '',
      salt: typeof r.salt === 'string' ? r.salt : '',
      kdf: r.kdf && typeof r.kdf === 'object' ? r.kdf : null,
      pw_wrap: r.pw_wrap && typeof r.pw_wrap.nonce === 'string' && typeof r.pw_wrap.ct === 'string' ? r.pw_wrap : null,
      ...(typeof r.secret_key === 'string' && r.secret_key ? { secret_key: r.secret_key } : {}),
    };
  }
  return { accounts };
}

export function memoryKeyStore() {
  let value = null;
  return { get: async () => (value ? structuredClone(value) : null), set: async (v) => { value = structuredClone(v); }, clear: async () => { value = null; } };
}

export function defaultKeyStore() {
  return typeof globalThis.indexedDB?.open === 'function' ? idbAccountRecord('keys') : memoryKeyStore();
}

export function createAccountKeys({ glue, account, local, store, session, fetch: fetchFn = (...a) => globalThis.fetch(...a),
  deviceName = defaultDeviceName, now = Date.now, consent = () => hasDataConsent(ACCOUNT_DATA) }) {
  // Keys an approval brought, waiting for the fingerprint check. Memory only, never stored.
  let arrived = null;

  async function call(method, path, { body, token = null, headers = {} } = {}) {
    // Firefox: without the data consent given on the click, nothing goes out.
    if (!(await consent())) throw new PassError(ErrorCode.CANCELLED, 'no data consent');
    const init = {
      method,
      headers: { Accept: 'application/json', ...headers },
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
    };
    if (token) init.headers.Authorization = `Bearer ${token}`;
    if (body !== undefined) {
      init.headers['Content-Type'] = 'application/json';
      init.body = JSON.stringify(body);
    }
    let res;
    try {
      res = await fetchFn(`${await account.base()}${path}`, init);
    } catch {
      throw serviceError(0);
    }
    let data = null;
    if (res.status !== 204) {
      try { data = await res.json(); } catch { data = null; }
    }
    if (!res.ok) {
      const err = serviceError(res.status, typeof data?.error === 'string' ? data.error : res.headers?.get?.('X-Pass-Error'));
      err.status = res.status;
      throw err;
    }
    return data ?? {};
  }

  async function bearer() {
    const token = await account.accessToken();
    if (!token) throw new PassError(ErrorCode.INVALID_STATE, 'not signed in', Reason.ACCOUNT_SIGNED_OUT);
    return token;
  }

  const records = async () => sanitizeRecords(await store.get().catch(() => null));

  async function updateRecord(accountId, patch) {
    const all = await records();
    const next = { ...(all.accounts[accountId] || { email: '', ak_id: '', salt: '', kdf: null, pw_wrap: null }), ...patch };
    if (patch.secret_key === null) delete next.secret_key;
    all.accounts[accountId] = next;
    await store.set(all);
  }

  async function recordByEmail(email) {
    const all = await records();
    const found = Object.entries(all.accounts).find(([, r]) => r.email && r.email === email);
    return found ? { id: found[0], ...found[1] } : null;
  }

  const device = () => cleanDeviceName(deviceName());

  async function readSecretKey(text) {
    const g = await glue();
    let out;
    try { out = JSON.parse(g.secretKeyText(String(text))); } catch { out = null; }
    if (!out?.result?.text) throw new PassError(ErrorCode.INVALID_PARAMS, 'not a Secret Key', Reason.BAD_SECRET_KEY);
    return out.result.text;
  }

  function checkPassword(password) {
    if (typeof password !== 'string' || !password || [...password].length > MAX_ACCOUNT_PASSWORD) {
      throw new PassError(ErrorCode.INVALID_PARAMS, 'No Passyble password');
    }
    return password;
  }

  async function secretKeyFor(rec, typed) {
    if (typeof typed === 'string' && typed.trim()) return { text: await readSecretKey(typed), typed: true };
    if (rec?.secret_key) return { text: rec.secret_key, typed: false };
    throw keyError(Reason.SECRET_KEY_NEEDED, 'secret key needed');
  }

  async function derive(password, secretKey, salt, kdf) {
    const g = await glue();
    try {
      return new g.AccountPassword(password, secretKey, String(salt || ''), JSON.stringify(kdf || {}));
    } catch (err) {
      throw wasmError(err);
    }
  }

  function openWrap(derived, accountId, akId, wrap) {
    try {
      return derived.openAccountKey(accountId, akId, JSON.stringify(wrap));
    } catch (err) {
      const e = wasmError(err);
      if (e.code === ErrorCode.WRONG_PASSWORD) throw keyError(Reason.WRONG_ACCOUNT_PASSWORD, 'wrong password');
      throw e;
    }
  }

  function blobsOf(key) {
    return {
      ak_id: String(key?.ak_id || ''),
      salt: String(key?.salt || ''),
      kdf: key?.kdf && typeof key.kdf === 'object' ? key.kdf : null,
      pw_wrap: key?.pw_wrap && typeof key.pw_wrap.nonce === 'string' ? { nonce: key.pw_wrap.nonce, ct: key.pw_wrap.ct } : null,
    };
  }

  function sign(derived, email, nonce, name) {
    try {
      return derived.signIn(email, String(nonce || ''), name, PLATFORM);
    } catch (err) {
      throw wasmError(err);
    }
  }

  /** A password sign-in with `email`. Returns the answer and the AccountKey; the tokens are not kept yet. */
  async function passwordSignIn(email, password, secretKey) {
    const pre = await call(...ACCOUNT_KEY_ROUTES.prelogin, { body: { email } });
    const derived = await derive(password, secretKey, pre.salt, pre.kdf);
    try {
      const name = device();
      const sig = sign(derived, email, pre.nonce, name);
      const body = await call(...ACCOUNT_KEY_ROUTES.sessionPassword, {
        body: { client_id: CLIENT_ID, email, nonce: pre.nonce, sig, device_name: name, platform: PLATFORM },
      });
      const accountId = String(body?.account?.id || '');
      const key = body?.account_key;
      if (!accountId || !key?.pw_wrap) throw new PassError(ErrorCode.INTERNAL, 'unexpected answer', Reason.ACCOUNT_SERVICE);
      const ak = openWrap(derived, accountId, String(key.ak_id || ''), key.pw_wrap);
      return { body, ak };
    } finally {
      derived.free?.();
    }
  }

  async function signedInOpen(me, accountId, password, secretKey) {
    const token = await bearer();
    const status = await call(...ACCOUNT_KEY_ROUTES.status, { token });
    if (!status?.set) throw keyError(Reason.NO_ACCOUNT_PASSWORD, 'no Passyble password');
    const derived = await derive(password, secretKey, status.salt, status.kdf);
    try {
      const { nonce } = await call(...ACCOUNT_KEY_ROUTES.nonce, { token, body: { purpose: 'unlock' } });
      const name = device();
      const sig = sign(derived, me.email, nonce, name);
      const out = await call(...ACCOUNT_KEY_ROUTES.unlock, { token, body: { nonce, sig, device_name: name, platform: PLATFORM } });
      const key = out?.account_key;
      if (!key?.pw_wrap) throw new PassError(ErrorCode.INTERNAL, 'unexpected answer', Reason.ACCOUNT_SERVICE);
      return { ak: openWrap(derived, accountId, String(key.ak_id || ''), key.pw_wrap), key };
    } finally {
      derived.free?.();
    }
  }

  /**
   * The account key with the Passyble password: the wrap kept here first (offline), else the service's.
   * Returns a pass-wasm AccountKey; the caller frees it.
   */
  async function openAccountKey({ accountId, akId = null, password, secretKey = '', shared = false, email = '' }) {
    checkPassword(password);
    const rec = (await records()).accounts[accountId] || null;
    const sk = await secretKeyFor(rec, secretKey);
    let ak = null;
    let wrongOffline = false;
    if (rec?.pw_wrap && rec.salt && rec.ak_id && (!akId || rec.ak_id === akId)) {
      const derived = await derive(password, sk.text, rec.salt, rec.kdf);
      try {
        ak = openWrap(derived, accountId, rec.ak_id, rec.pw_wrap);
      } catch (err) {
        // The password may have changed on another device: ask the service.
        if (err?.reason !== Reason.WRONG_ACCOUNT_PASSWORD) throw err;
        wrongOffline = true;
      } finally {
        derived.free?.();
      }
    }
    let patch = {};
    if (!ak) {
      try {
        const me = await account.current().catch(() => null);
        if (me?.id === accountId) {
          const { ak: opened, key } = await signedInOpen(me, accountId, password, sk.text);
          ak = opened;
          patch = { ...blobsOf(key), email: me.email };
        } else {
          const address = normalizeEmail(email) || rec?.email || '';
          if (!address) throw keyError(Reason.EMAIL_NEEDED, 'e-mail address needed');
          const { body, ak: opened } = await passwordSignIn(address, password, sk.text);
          if (String(body.account.id) !== accountId) {
            opened.free?.();
            await account.revoke(body.refresh_token);
            throw keyError(Reason.OTHER_ACCOUNT, 'another account');
          }
          await account.signedInWith(body);
          ak = opened;
          patch = { ...blobsOf(body.account_key), email: String(body.account.email || address) };
        }
      } catch (err) {
        if (wrongOffline && err?.reason === Reason.ACCOUNT_OFFLINE) throw keyError(Reason.WRONG_ACCOUNT_PASSWORD, 'wrong password');
        throw err;
      }
    }
    if (akId && ak.akId() !== akId) {
      ak.free?.();
      throw keyError(Reason.OTHER_ACCOUNT_KEY, 'another account key');
    }
    if (sk.typed && !shared) patch.secret_key = sk.text;
    if (Object.keys(patch).length) await updateRecord(accountId, patch);
    return ak;
  }

  async function vaultLink() {
    const access = await local.vaultAccess().catch(() => null);
    return access?.kind === 'account' && access.account ? { account: String(access.account), ak_id: String(access.ak_id || '') } : null;
  }

  async function unlockInfo() {
    const link = await vaultLink();
    return link ? { account: link.account, ...(await fileInfo(link.account, link.ak_id)) } : null;
  }

  async function fileInfo(accountId, akId = '') {
    const rec = (await records()).accounts[accountId] || null;
    const me = await account.current().catch(() => null);
    const email = rec?.email || (me?.id === accountId ? me.email : '');
    const offline = !!(rec?.pw_wrap && (!akId || rec.ak_id === akId));
    return { email, secret_key_needed: !rec?.secret_key, email_needed: !email && me?.id !== accountId && !offline };
  }

  async function unlockVault({ password, secretKey = '', shared = false, email = '' }) {
    const link = await vaultLink();
    if (!link) throw new PassError(ErrorCode.INVALID_STATE, 'not a linked vault');
    const ak = await openAccountKey({ accountId: link.account, akId: link.ak_id, password, secretKey, shared, email });
    try {
      return await local.unlockWithAccountKey(ak);
    } finally {
      ak.free?.();
    }
  }

  async function verify({ password, secretKey = '', shared = false }) {
    const link = await vaultLink();
    if (!link) throw new PassError(ErrorCode.INVALID_STATE, 'not a linked vault');
    const ak = await openAccountKey({ accountId: link.account, akId: link.ak_id, password, secretKey, shared });
    try {
      return await local.verifyAccountKey(ak);
    } finally {
      ak.free?.();
    }
  }

  async function openFile(file, access, { password, secretKey = '', shared = false, email = '' }) {
    const ak = await openAccountKey({ accountId: String(access.account), akId: String(access.ak_id || ''), password, secretKey, shared, email });
    try {
      return await local.openFileWithAccountKey(file, ak);
    } finally {
      ak.free?.();
    }
  }

  async function openVaultWith(ak) {
    const link = await vaultLink();
    if (!link || link.account !== ak.account() || link.ak_id !== ak.akId()) return false;
    const info = await local.info().catch(() => null);
    if (!info?.locked) return false;
    try {
      await local.unlockWithAccountKey(ak);
      return true;
    } catch {
      return false;
    }
  }

  async function signIn({ email, password, secretKey = '', shared = false }) {
    checkPassword(password);
    const address = normalizeEmail(email);
    if (!address) throw keyError(Reason.EMAIL_NEEDED, 'e-mail address needed');
    const rec = await recordByEmail(address);
    const sk = await secretKeyFor(rec, secretKey);
    const { body, ak } = await passwordSignIn(address, password, sk.text);
    try {
      const me = await account.signedInWith(body);
      const patch = { ...blobsOf(body.account_key), email: me?.email || address };
      if (sk.typed && !shared) patch.secret_key = sk.text;
      await updateRecord(String(body.account.id), patch);
      return { email: patch.email, unlocked: await openVaultWith(ak) };
    } finally {
      ak.free?.();
    }
  }

  async function pending() {
    const got = (await session.get(APPROVAL_KEY).catch(() => ({})))?.[APPROVAL_KEY];
    return got && typeof got.id === 'string' && typeof got.secret === 'string' ? got : null;
  }

  async function dropPending() {
    await session.remove(APPROVAL_KEY).catch(() => {});
  }

  async function qrOf(text) {
    const g = await glue();
    try {
      const out = JSON.parse(g.qrSvgPath(text));
      return out?.result ? { size: Number(out.result.size) || 0, path: String(out.result.path || '') } : null;
    } catch {
      return null;
    }
  }

  /** "Approve from another device": the QR another device scans. The same answer for every address. */
  async function approvalStart({ email, shared = false }) {
    const address = normalizeEmail(email);
    if (!address) throw keyError(Reason.EMAIL_NEEDED, 'e-mail address needed');
    await dropPending();
    await dropArrived();
    const g = await glue();
    const keys = new g.DeviceApprovalKeys();
    try {
      const me = await account.current().catch(() => null);
      const token = me?.email === address ? await account.accessToken().catch(() => null) : null;
      const body = { enc_pub: keys.encPub(), commitment: keys.commitment() };
      if (!token) Object.assign(body, { email: address, client_id: CLIENT_ID, device_name: device(), platform: PLATFORM });
      const made = await call(...ACCOUNT_KEY_ROUTES.request, { body, token });
      const id = String(made?.id || '');
      if (!id || (!token && !made.poll_token)) throw new PassError(ErrorCode.INTERNAL, 'unexpected answer', Reason.ACCOUNT_SERVICE);
      const expiresAt = Number(made.expires_at) || now() + REQUEST_TTL_MS;
      await session.set({ [APPROVAL_KEY]: {
        id, email: address, secret: String(keys.secret()), poll_token: made.poll_token ? String(made.poll_token) : null,
        with_session: !!token, expires_at: expiresAt, revealed: false, shared: shared === true,
      } });
      return { id, expires_at: expiresAt, qr: await qrOf(keys.approvalQr(id)) };
    } finally {
      keys.free?.();
    }
  }

  async function pollHeaders(p) {
    if (p.with_session) return { token: await bearer() };
    return { headers: { [REQUEST_TOKEN_HEADER]: p.poll_token } };
  }

  async function approvalPoll() {
    if (arrived) {
      if (now() > arrived.until) { await dropArrived(); return { state: 'expired' }; }
      return { state: 'check', fingerprint: arrived.fingerprint };
    }
    const p = await pending();
    if (!p) return { state: 'none' };
    if (now() > p.expires_at) { await dropPending(); return { state: 'expired' }; }
    const path = `/v1/account-key/requests/${encodeURIComponent(p.id)}`;
    let v;
    try {
      v = await call('GET', path, await pollHeaders(p));
    } catch (err) {
      if (err?.status === 404) { await dropPending(); return { state: 'expired' }; }
      throw err;
    }
    const g = await glue();
    let keys;
    try { keys = g.DeviceApprovalKeys.restore(p.secret); } catch (err) { await dropPending(); throw wasmError(err); }
    try {
      const accountId = String(v?.account || '');
      const rA = String(v?.r_a || '');
      switch (v?.state) {
        case 'accepted':
        case 'revealed': {
          if (!rA || !accountId) return { state: 'waiting' };
          if (!p.revealed) {
            await call('POST', `${path}/reveal`, { ...(await pollHeaders(p)), body: { r_n: keys.reveal() } });
            await session.set({ [APPROVAL_KEY]: { ...p, revealed: true } });
          }
          let code;
          try { code = keys.code(p.id, accountId, rA); } catch (err) { throw wasmError(err); }
          return { state: 'code', code };
        }
        case 'sealed':
        case 'done': {
          // The sealed keys come once: whatever happens next, this request is over.
          await dropPending();
          if (!v.sealed) return { state: 'expired' };
          return await finish(p, keys, v);
        }
        case 'denied':
          await dropPending();
          return { state: 'denied' };
        default:
          return { state: 'waiting', qr: await qrOf(keys.approvalQr(p.id)) };
      }
    } finally {
      keys.free?.();
    }
  }

  /** Opens the sealed keys and holds them; nothing is kept and no session taken until approvalConfirm. */
  async function finish(p, keys, v) {
    const accountId = String(v.account || '');
    const akId = String(v.ak_id || '');
    const sessionBody = v.session && typeof v.session === 'object' ? v.session : null;
    let approved;
    try {
      approved = keys.open(p.id, accountId, akId, String(v.r_a || ''), JSON.stringify(v.sealed));
    } catch {
      await giveBack(sessionBody);
      throw keyError(Reason.APPROVAL_MISMATCH, 'the sealed keys do not open');
    }
    let fingerprint = '';
    try { fingerprint = typeof approved.fingerprint === 'function' ? String(approved.fingerprint() || '') : ''; } catch { fingerprint = ''; }
    if (!fingerprint) {
      // A build that can't show the fingerprint can't let the user check the keys: none are kept.
      approved.free?.();
      await giveBack(sessionBody);
      throw new PassError(ErrorCode.UPDATE_REQUIRED, 'no account key fingerprint', Reason.EXTENSION_UPDATE);
    }
    await dropArrived();
    arrived = { approved, accountId, akId, session: sessionBody, email: p.email, shared: p.shared === true, fingerprint,
      until: now() + CHECK_TTL_MS };
    return { state: 'check', fingerprint };
  }

  async function giveBack(sessionBody) {
    const token = sessionBody?.refresh_token;
    if (token) await account.revoke(token).catch(() => {});
  }

  async function dropArrived() {
    const held = arrived;
    arrived = null;
    if (!held) return false;
    try { held.approved.free?.(); } catch { /* freed */ }
    await giveBack(held.session);
    return true;
  }

  async function approvalConfirm({ matches = false } = {}) {
    if (!arrived || now() > arrived.until) { await dropArrived(); return { state: 'expired' }; }
    if (matches !== true) { await dropArrived(); return { state: 'rejected' }; }
    const held = arrived;
    arrived = null;
    const ak = held.approved.accountKey();
    try {
      let me = await account.current().catch(() => null);
      if (held.session) {
        if (String(held.session.account?.id || '') !== held.accountId) {
          await giveBack(held.session);
          throw keyError(Reason.OTHER_ACCOUNT, 'another account');
        }
        me = await account.signedInWith(held.session);
      }
      const patch = { ak_id: held.akId, email: me?.id === held.accountId ? me.email : held.email };
      const rec = (await records()).accounts[held.accountId];
      if (rec && rec.ak_id !== held.akId) Object.assign(patch, { pw_wrap: null, salt: '', kdf: null });
      if (!held.shared) patch.secret_key = String(held.approved.secretKey());
      await updateRecord(held.accountId, patch);
      return { state: 'done', email: patch.email, unlocked: await openVaultWith(ak) };
    } finally {
      ak.free?.();
      held.approved.free?.();
    }
  }

  async function approvalCancel() {
    await dropPending();
    const dropped = await dropArrived();
    return dropped ? { state: 'none', dropped: true } : { state: 'none' };
  }

  return {
    unlockInfo, fileInfo, unlockVault, verify, openFile, signIn, openAccountKey, vaultLink,
    approvalStart, approvalPoll, approvalConfirm, approvalCancel,
  };
}
