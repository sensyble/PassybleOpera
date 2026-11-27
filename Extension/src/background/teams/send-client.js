// Secure send: a text sealed here, with its key only in the link's fragment (which browsers never send); the
// account service gets the ciphertext, counts the views and deletes the send at expiry or after the last view.
import { toBytes } from '../../shared/b64url.js';
import { apiRequest, TeamsHttpError } from './org-api.js';

/** Standard base64 (with padding), as the service reads the ciphertext. */
export function base64Encode(data) {
  const bytes = toBytes(data);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

/** The base sendLink takes: the service's `link_base` without its last "/", else `fallback`. */
export function linkBaseOf(res, fallback) {
  const base = typeof res?.link_base === 'string' ? res.link_base.trim() : '';
  return /^https:\/\//.test(base) ? base.replace(/\/+$/, '') : fallback;
}

/** What the core allows: at most 10 MiB, expiry within 30 days. */
export const SEND_MAX_BYTES = 10 * 1024 * 1024;
const SEND_MAX_DAYS = 30;
const DAY_MS = 24 * 3600 * 1000;

export function sealOptions({ days = 7, maxViews = 1, password = '' } = {}, now = Date.now()) {
  const d = Math.min(SEND_MAX_DAYS, Math.max(1, Math.floor(Number(days) || 1)));
  const views = Math.min(100, Math.max(0, Math.floor(Number(maxViews) || 0)));
  const options = { kind: 'text', name: '', mime: 'text/plain', expires_at: now + d * DAY_MS, max_views: views };
  if (typeof password === 'string' && password) options.password = password;
  return options;
}

/** The body of `POST /v1/sends` from sendSeal's result. The link key is never part of it. */
export function createBody(sealed) {
  const body = { meta: String(sealed.meta), ciphertext: base64Encode(sealed.ciphertext) };
  if (typeof sealed.password_auth === 'string' && sealed.password_auth) body.password_auth = sealed.password_auth;
  return body;
}

/** One send as the popup lists it (no content, no key: the link can't be made again). */
export function sendView(s, now = Date.now()) {
  const maxViews = Number(s?.max_views) || 0;
  const views = Number(s?.views) || 0;
  const left = Number.isFinite(Number(s?.views_left)) ? Number(s.views_left) : maxViews ? Math.max(0, maxViews - views) : null;
  const expiresAt = Number(s?.expires_at) || 0;
  const state = typeof s?.state === 'string' ? s.state : '';
  const gone = state ? state !== 'active' : !!expiresAt && expiresAt <= now;
  return { id: String(s?.id || ''), created_at: Number(s?.created_at) || 0, expires_at: expiresAt, max_views: maxViews,
    views_left: left, expired: gone, state: state || (gone ? 'expired' : 'active'), has_password: s?.has_password === true };
}

export function createSendClient({ account, fetch: fetchFn = (...a) => globalThis.fetch(...a) }) {
  async function call(method, path, body) {
    const token = await account.accessToken();
    if (!token) throw new TeamsHttpError(401, 'signed_out', 'not signed in');
    let res;
    try {
      res = await fetchFn(`${await account.base()}${path}`, apiRequest(method, token, body));
    } catch {
      throw new TeamsHttpError(0, 'network', 'no answer');
    }
    let data = null;
    if (res.status !== 204) {
      try { data = await res.json(); } catch { data = null; }
    }
    if (!res.ok) {
      const code = res.headers?.get?.('X-Pass-Error') || (typeof data?.error === 'string' ? data.error : '');
      throw new TeamsHttpError(res.status, code, typeof data?.message === 'string' ? data.message : '');
    }
    return data ?? {};
  }

  return {
    create: (body) => call('POST', '/v1/sends', body),
    list: () => call('GET', '/v1/sends'),
    revoke: (id) => call('DELETE', `/v1/sends/${encodeURIComponent(String(id))}`),
    linkBase: async () => `${await account.base()}/send`,
  };
}
