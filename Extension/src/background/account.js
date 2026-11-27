// Optional Passyble account: OAuth authorization code with PKCE S256 through launchWebAuthFlow.
// The refresh token lives in the extension's own IndexedDB because content scripts can read
// chrome.storage.local. The short-lived access token goes in storage.session (trusted contexts only).
// In app mode, or without a known redirect (Safari), Sign in just opens the website.
import { b64urlEncode } from '../shared/b64url.js';
import { ErrorCode, PassError } from '../shared/errors.js';
import { ACCOUNT_DATA, hasDataConsent } from '../shared/data-consent.js';
import { cameBackTo, webAuthRedirect } from './web-auth.js';

export const ACCOUNT_BASE = 'https://account.passyble.com';
export const CLIENT_ID = 'passyble-extension';
/** storage.local: another account service for an unpacked extension (tests). */
export const DEV_BASE_KEY = 'devAccountBase';
export const ACCESS_KEY = 'passAccountAccess';
const DB_NAME = 'passyble-account';
const REFRESH_EARLY_MS = 60_000;
export const HANDOFF_REDIRECT = 'urn:passyble:handoff';
export const APP_CLIENT_ID = 'passyble-windows';
export const PEER_EVERY_MS = 30_000;
const PEER_WAIT_MS = 2500;
// The service allows 20 handoff codes per account an hour.
const HANDOFF_RETRY_MS = 10 * 60_000;

/** One record of the IndexedDB database `passyble-account` (store `kv`), out of reach of content scripts. */
export function idbAccountRecord(name, idb = globalThis.indexedDB) {
  let opened = null;
  const db = () => {
    opened ??= new Promise((resolve, reject) => {
      const req = idb.open(DB_NAME, 1);
      req.onupgradeneeded = () => { if (!req.result.objectStoreNames.contains('kv')) req.result.createObjectStore('kv'); };
      req.onsuccess = () => { req.result.onversionchange = () => { req.result.close(); opened = null; }; resolve(req.result); };
      req.onerror = () => reject(req.error);
    });
    opened.catch(() => { opened = null; });
    return opened;
  };
  const run = async (mode, fn) => {
    const d = await db();
    return new Promise((resolve, reject) => {
      const tx = d.transaction('kv', mode);
      const req = fn(tx.objectStore('kv'));
      tx.oncomplete = () => resolve(req?.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
    });
  };
  return {
    get: () => run('readonly', (s) => s.get(name)).then((v) => v || null),
    set: (value) => run('readwrite', (s) => s.put(value, name)),
    clear: () => run('readwrite', (s) => s.delete(name)),
  };
}

function defaultAccountStore() {
  return typeof globalThis.indexedDB?.open === 'function' ? idbAccountRecord('current') : memoryAccountStore();
}

function defaultPeerStore() {
  return typeof globalThis.indexedDB?.open === 'function' ? idbAccountRecord('peer') : memoryAccountStore();
}

function sameAddress(a, b) {
  return typeof a === 'string' && typeof b === 'string' && !!a.trim() && a.trim().toLowerCase() === b.trim().toLowerCase();
}

export function memoryAccountStore() {
  let value = null;
  return { get: async () => value, set: async (v) => { value = structuredClone(v); }, clear: async () => { value = null; } };
}

function randomB64url(bytes) {
  return b64urlEncode(globalThis.crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function pkceChallenge(verifier) {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return b64urlEncode(new Uint8Array(digest));
}

export function deviceName(nav = globalThis.navigator) {
  const brands = nav?.userAgentData?.brands || [];
  const ua = nav?.userAgent || '';
  const browser = brands.some((b) => /Edge/i.test(b.brand)) || /\bEdg\//.test(ua) ? 'Edge'
    : brands.some((b) => /Opera GX/i.test(b.brand)) ? 'Opera GX'
    : brands.some((b) => /Opera/i.test(b.brand)) || /\bOPR\//.test(ua) ? 'Opera'
    : nav?.brave || brands.some((b) => /Brave/i.test(b.brand)) ? 'Brave'
      : /Firefox\//.test(ua) ? 'Firefox'
        : /Safari\//.test(ua) && !/(Chrome|Chromium|CriOS)\//.test(ua) ? 'Safari' : 'Chrome';
  const p = `${nav?.userAgentData?.platform || ''} ${nav?.platform || ''} ${ua}`;
  const os = /Win/i.test(p) ? 'Windows' : /CrOS/i.test(p) ? 'ChromeOS' : /Mac/i.test(p) ? 'macOS' : /Android/i.test(p) ? 'Android' : /Linux/i.test(p) ? 'Linux' : '';
  return os ? `${browser} on ${os}` : browser;
}

/**
 * `appMode`: the Passyble app owns the account; `app`: its account through the native host; `peer`: the app's
 * handoff methods. Each throws when the app can't be reached or is too old.
 */
export function createAccount({ ext, fetch: fetchFn = (...a) => globalThis.fetch(...a), store = defaultAccountStore(), now = Date.now, appMode,
  app = null, peer = null, peerStore = defaultPeerStore(), onSignedOut = () => {} }) {
  let busy = null;
  let syncing = null;
  let peerAt = -Infinity;
  let handoffAfter = -Infinity;
  let peerSeen = null;
  try { ext.storage.session?.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' })?.catch?.(() => {}); } catch { /* the default */ }

  async function base() {
    try {
      const self = await ext.management?.getSelf?.();
      if (self?.installType !== 'development') return ACCOUNT_BASE;
      const dev = (await ext.storage.local.get(DEV_BASE_KEY))?.[DEV_BASE_KEY];
      if (typeof dev === 'string' && /^https?:\/\/[^/?#]+$/.test(dev)) return dev;
    } catch { /* the default */ }
    return ACCOUNT_BASE;
  }

  function redirectUri() {
    return webAuthRedirect(ext);
  }

  async function post(path, params) {
    const res = await fetchFn(`${await base()}${path}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
      body: new URLSearchParams(params).toString(),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
    });
    let body = null;
    try { body = await res.json(); } catch { /* not JSON */ }
    return { status: res.status, ok: res.ok, body };
  }

  async function keep(body, { via = null } = {}) {
    const email = String(body?.account?.email || '');
    if (typeof body?.access_token !== 'string' || typeof body?.refresh_token !== 'string' || !email) {
      throw new PassError(ErrorCode.INTERNAL, 'unexpected token answer');
    }
    await store.set({ refresh_token: body.refresh_token, account: { id: String(body.account.id || ''), email }, signed_in_at: now(),
      ...(via === 'app' ? { via } : {}) });
    const expiresIn = Math.max(0, Number(body.expires_in) || 0) * 1000;
    await ext.storage.session.set({ [ACCESS_KEY]: { token: body.access_token, expires_at: now() + expiresIn } });
    return email;
  }

  async function forget() {
    await store.clear();
    try { await ext.storage.session.remove(ACCESS_KEY); } catch { /* gone */ }
  }

  async function appAccount() {
    if (!app) return null;
    try {
      const got = await app.status();
      if (typeof got?.signed_in !== 'boolean') return null;
      const email = got.signed_in && typeof got.email === 'string' && got.email ? got.email : null;
      return { signed_in: got.signed_in, email };
    } catch {
      return null;
    }
  }

  async function inApp(signInToo) {
    if (!app) return false;
    try {
      await app.show(signInToo ? { sign_in: true } : {});
      return true;
    } catch {
      return false;
    }
  }

  async function status() {
    const inAppMode = await appMode();
    const rec = await store.get().catch(() => null);
    if (inAppMode) {
      const fromApp = await appAccount();
      if (fromApp) {
        const other = fromApp.signed_in && rec && !sameAddress(fromApp.email, rec.account?.email);
        return { ...fromApp, app_mode: true, app_reachable: true, ...(other ? { browser_email: rec.account?.email || null } : {}) };
      }
    }
    const out = { signed_in: !!rec, email: rec?.account?.email || null, app_mode: inAppMode };
    if (inAppMode) out.app_reachable = false;
    else {
      if (rec?.via === 'app') out.via_app = true;
      if (peerSeen) {
        out.app_peer = { signed_in: peerSeen.signed_in, same_account: !!rec && peerSeen.signed_in && sameAddress(peerSeen.email, rec.account?.email) };
      }
    }
    return out;
  }

  /** account.status for a page: waits for the handoff check at most `waitMs`, else `app_syncing: true`. */
  async function statusWithApp({ waitMs = PEER_WAIT_MS } = {}) {
    let timer;
    const done = await Promise.race([syncWithApp().then(() => true),
      new Promise((resolve) => { timer = setTimeout(() => resolve(false), waitMs); })]);
    clearTimeout(timer);
    const out = await status();
    return done ? out : { ...out, app_syncing: true };
  }

  async function openWebsite() {
    await ext.tabs.create({ url: `${await base()}/sign-in` });
    return { ...(await status()), opened: true };
  }

  async function signIn() {
    if (await appMode() && await inApp(true)) return { ...(await status()), in_app: true };
    const redirect = redirectUri();
    if (!redirect) return openWebsite();
    // Firefox: nothing goes out without the data consent.
    if (!(await hasDataConsent(ACCOUNT_DATA, ext))) throw new PassError(ErrorCode.CANCELLED, 'no data consent');
    const origin = await base();
    const verifier = randomB64url(32);
    const state = randomB64url(16);
    const url = new URL(`${origin}/oauth/authorize`);
    for (const [k, v] of Object.entries({
      client_id: CLIENT_ID, redirect_uri: redirect, response_type: 'code', code_challenge: await pkceChallenge(verifier),
      code_challenge_method: 'S256', state, device_name: deviceName(),
    })) url.searchParams.set(k, v);
    let answer;
    try {
      answer = await ext.identity.launchWebAuthFlow({ url: url.href, interactive: true });
    } catch {
      throw new PassError(ErrorCode.CANCELLED, 'Sign in was cancelled');
    }
    let back;
    try { back = new URL(answer); } catch { throw new PassError(ErrorCode.INTERNAL, 'no answer from the sign-in page'); }
    const q = back.searchParams;
    if (!cameBackTo(answer, redirect) || q.get('state') !== state) throw new PassError(ErrorCode.INTERNAL, 'the sign-in answer does not match');
  // RFC 9207: the answer names the service that sent it.
    if (q.has('iss') && q.get('iss') !== origin) throw new PassError(ErrorCode.INTERNAL, 'the sign-in answer comes from another service');
    if (q.get('error')) {
      throw new PassError(q.get('error') === 'access_denied' ? ErrorCode.CANCELLED : ErrorCode.INTERNAL, `sign-in: ${q.get('error')}`);
    }
    const code = q.get('code');
    if (!code) throw new PassError(ErrorCode.INTERNAL, 'no code');
    const res = await post('/oauth/token', { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: CLIENT_ID, redirect_uri: redirect });
    if (!res.ok) throw new PassError(ErrorCode.INTERNAL, `token: ${res.body?.error || res.status}`);
    await keep(res.body);
    await setPaused(false);
    return status();
  }

  /** A valid access token, refreshed when about to expire; a refused refresh token signs this browser out. */
  async function accessToken() {
    const got = (await ext.storage.session.get(ACCESS_KEY))?.[ACCESS_KEY];
    if (got?.token && got.expires_at - REFRESH_EARLY_MS > now()) return got.token;
    const rec = await store.get();
    if (!rec) return null;
    const res = await post('/oauth/token', { grant_type: 'refresh_token', refresh_token: rec.refresh_token, client_id: CLIENT_ID });
    if (res.status === 400 || res.status === 401) { await forget(); return null; }
    if (!res.ok) throw new PassError(ErrorCode.INTERNAL, `refresh: ${res.body?.error || res.status}`);
    await keep(res.body, { via: rec.via });
    return res.body.access_token;
  }

  /**
   * Browser mode: `alsoApp` also signs the app out when it is signed in to the same address; otherwise this
   * pauses the handoff so the app doesn't sign this browser in again at once.
   */
  async function signOut({ alsoApp = false } = {}) {
    if (await appMode() && await inApp(false)) return { ...(await status()), in_app: true };
    const rec = await store.get().catch(() => null);
    await forget();
    await revoke(rec?.refresh_token);
    if (rec && peer && !(await appMode())) {
      const appOut = alsoApp && await signOutApp(rec.account?.email);
      if (!appOut) await setPaused(true);
    }
    return status();
  }

  async function signOutApp(email) {
    try {
      const got = await askPeer();
      if (!got) return false;
      if (got.signed_in) {
        if (!sameAddress(got.email, email)) return false;
        await peer.call('account.sign_out', {});
      }
      peerSeen = { signed_in: false, email: null };
      return true;
    } catch {
      return false;
    } finally {
      peer.end?.();
    }
  }

  const once = (fn) => (...args) => {
    if (busy) return Promise.reject(new PassError(ErrorCode.INVALID_STATE, 'busy'));
    const run = (async () => {
      await syncing;
      return fn(...args);
    })();
    busy = run;
    return run.finally(() => { if (busy === run) busy = null; });
  };

  async function setPaused(paused) {
    try {
      if (paused) await peerStore.set({ paused: true, at: now() });
      else if ((await peerStore.get())?.paused) await peerStore.clear();
    } catch { /* the flag stays as it was */ }
  }

  async function isPaused() {
    return (await peerStore.get().catch(() => null))?.paused === true;
  }

  async function askPeer() {
    let got;
    try { got = await peer.call('account.peer', {}); } catch { return null; }
    if (typeof got?.signed_in !== 'boolean') return null;
    return {
      signed_in: got.signed_in,
      email: typeof got.email === 'string' && got.email ? got.email : null,
      accepts_handoff: got.accepts_handoff === true,
      sign_out_extension: got.sign_out_extension === true,
    };
  }

  /** The handoff check, at most every PEER_EVERY_MS and never during a sign-in or sign-out here. Never rejects. */
  function syncWithApp({ force = false } = {}) {
    if (!peer) return Promise.resolve();
    if (syncing) return syncing;
    if (busy || (!force && now() - peerAt < PEER_EVERY_MS)) return Promise.resolve();
    peerAt = now();
    const run = syncOnce().catch(() => {}).finally(() => { if (syncing === run) syncing = null; });
    syncing = run;
    return run;
  }

  async function syncOnce() {
    const inAppMode = await appMode();
    let rec = await store.get().catch(() => null);
    if (inAppMode && !rec) { peerSeen = null; return; }
    try {
      const got = await askPeer();
      peerSeen = !inAppMode && got ? { signed_in: got.signed_in, email: got.signed_in ? got.email : null } : null;
      if (!got) return;
      if (inAppMode) { await syncAppMode(got, rec); return; }
      if (!got.signed_in) await setPaused(false);
      rec = await store.get().catch(() => null);
      if (!got.signed_in && got.sign_out_extension) {
        if (rec && sameAddress(got.email, rec.account?.email)) await signedOutByApp();
        return;
      }
      if (now() < handoffAfter) return;
      const handoff = !rec && got.signed_in && !(await isPaused()) ? handoffFromApp
        : rec && !got.signed_in && got.accepts_handoff ? handoffToApp : null;
      if (!handoff) return;
      try {
        await handoff();
      } catch (err) {
        handoffAfter = now() + HANDOFF_RETRY_MS;
        throw err;
      }
    } finally {
      peer.end?.();
    }
  }

  /** App mode with a session of the extension's own: it goes to the app or is dropped when the app has the same address. */
  async function syncAppMode(got, rec) {
    if (got.signed_in) {
      if (sameAddress(got.email, rec.account?.email)) await dropOwnSession();
      return;
    }
    if (got.sign_out_extension) {
      if (sameAddress(got.email, rec.account?.email)) await signedOutByApp();
      return;
    }
    if (!got.accepts_handoff || now() < handoffAfter) return;
    let handed = false;
    try {
      handed = await handoffToApp();
    } finally {
      if (!handed) handoffAfter = now() + HANDOFF_RETRY_MS;
    }
    if (handed) await dropOwnSession();
  }

  async function handoffFromApp() {
    if (!(await hasDataConsent(ACCOUNT_DATA, ext))) return;
    const verifier = randomB64url(32);
    const got = await peer.call('account.handoff_to_extension', { code_challenge: await pkceChallenge(verifier), device_name: deviceName() });
    const code = typeof got?.code === 'string' ? got.code : '';
    if (!code || code.length > 512) throw new PassError(ErrorCode.INTERNAL, 'no handoff code');
    const res = await post('/oauth/token', { grant_type: 'authorization_code', code, code_verifier: verifier, client_id: CLIENT_ID, redirect_uri: HANDOFF_REDIRECT });
    if (!res.ok) throw new PassError(ErrorCode.INTERNAL, `handoff token: ${res.body?.error || res.status}`);
      // Signed in here meanwhile: that sign-in stays, this session goes.
    if (await store.get().catch(() => null)) { await revoke(res.body?.refresh_token); return; }
    await keep(res.body, { via: 'app' });
    peerSeen = { signed_in: true, email: typeof got.email === 'string' ? got.email : String(res.body.account.email) };
  }

  async function handoffToApp() {
    const begin = await peer.call('account.handoff_begin', {});
    const challenge = begin?.code_challenge;
    if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) throw new PassError(ErrorCode.INTERNAL, 'no handoff challenge');
    const token = await accessToken();
    if (!token) return false;
    const params = { client_id: APP_CLIENT_ID, code_challenge: challenge };
    const device = typeof begin.device_name === 'string' ? begin.device_name.trim().slice(0, 100) : '';
    if (device) params.device_name = device;
    const res = await fetchFn(`${await base()}/v1/session/handoff`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify(params),
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
    });
    let body = null;
    try { body = await res.json(); } catch { /* not JSON */ }
    if (!res.ok || typeof body?.code !== 'string' || !body.code) throw new PassError(ErrorCode.INTERNAL, `handoff: ${body?.error || res.status}`);
    const done = await peer.call('account.handoff_finish', { code: body.code });
    peerSeen = { signed_in: done?.signed_in === true, email: typeof done?.email === 'string' ? done.email : null };
    return done?.signed_in === true;
  }

  async function dropOwnSession() {
    const rec = await store.get().catch(() => null);
    if (!rec) return;
    await forget();
    await revoke(rec.refresh_token);
    try { await onSignedOut(); } catch { /* best effort */ }
  }

  async function signedOutByApp() {
    await dropOwnSession();
    try { await peer.call('account.peer_signed_out', {}); } catch { /* the app's marker expires on its own */ }
  }

  async function useAppAccount() {
    if (!(await appMode())) throw new PassError(ErrorCode.NOT_SUPPORTED, 'browser mode');
    if (!(await appAccount())?.signed_in) throw new PassError(ErrorCode.INVALID_STATE, 'The Passyble app is not signed in');
    await dropOwnSession();
    return status();
  }

  /** Keeps tokens from a sign-in made without the website (Passyble password, new device approval). */
  async function signedInWith(body) {
    await keep(body);
    await setPaused(false);
    syncWithApp({ force: true });
    return current();
  }

  async function revoke(refreshToken) {
    if (typeof refreshToken !== 'string' || !refreshToken) return;
    try { await post('/oauth/revoke', { token: refreshToken, client_id: CLIENT_ID }); } catch { /* offline */ }
  }

  async function current() {
    const rec = await store.get().catch(() => null);
    return rec?.account?.id ? { id: String(rec.account.id), email: String(rec.account.email || '') } : null;
  }

  const signInOnce = once(signIn);
  async function signInThenSync() {
    const res = await signInOnce();
    if (res?.signed_in && !res.in_app) syncWithApp({ force: true });
    return res;
  }

  return { status, statusWithApp, syncWithApp, signIn: signInThenSync, signOut: once(signOut), useAppAccount: once(useAppAccount), accessToken, base, current, signedInWith, revoke };
}
