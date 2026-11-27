// Shared vault files on Passyble Server in cloud mode, with the Passyble Cloud device's Basic credentials.
// Uploads are guarded by `If-Match`, so another member's newer copy is merged first, never overwritten.
import { retryAfterMs } from './cloud-cadence.js';
import { TeamsHttpError } from './org-api.js';

/** The URL of a vault file: `path` under the device's server (only an absolute path, never another host). */
function fileUrl(device, path) {
  const p = String(path || '');
  if (!p.startsWith('/') || p.startsWith('//')) throw new TeamsHttpError(400, 'invalid_params', 'bad vault path');
  const base = new URL(String(device?.server_url || ''));
  if (base.protocol !== 'https:' && !(base.protocol === 'http:' && /^(localhost|127\.0\.0\.1|\[::1\])$/.test(base.hostname))) {
    throw new TeamsHttpError(400, 'invalid_params', 'the server must be https');
  }
  const url = new URL(p, base);
  if (url.origin !== base.origin) throw new TeamsHttpError(400, 'invalid_params', 'another host');
  return url.href;
}

function basic(device) {
  const bytes = new TextEncoder().encode(`${device.user}:${device.token}`);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return `Basic ${btoa(bin)}`;
}

function fileRequest(device, { method = 'GET', etag = null, body = null } = {}) {
  const headers = { Authorization: basic(device), Accept: 'application/octet-stream' };
  const init = { method, headers, credentials: 'omit', cache: 'no-store', redirect: 'error' };
  if (method === 'GET' && etag) headers['If-None-Match'] = etag;
  if (method === 'PUT') {
    headers['Content-Type'] = 'application/octet-stream';
    if (etag) headers['If-Match'] = etag;
    else headers['If-None-Match'] = '*';
    init.body = body;
  }
  return init;
}

export function fileErrorCode(status, serverCode) {
  if (status === 0) return 'network';
  if (status === 429) return 'busy';
  if (serverCode === 'no_vault_access' || status === 404) return 'not_a_member';
  if (['read_only_member', 'subscription_inactive', 'account_suspended', 'vault_limit'].includes(serverCode)) return serverCode;
  if (status === 401) return 'signed_out';
  if (status >= 500) return 'network';
  return 'internal';
}

export function createCloudFiles({ fetch: fetchFn = (...a) => globalThis.fetch(...a) } = {}) {
  async function send(device, path, opts) {
    let res;
    try {
      res = await fetchFn(fileUrl(device, path), fileRequest(device, opts));
    } catch (err) {
      if (err instanceof TeamsHttpError) throw err;
      throw new TeamsHttpError(0, 'network', 'no answer');
    }
    return res;
  }

  function refused(res) {
    const server = res.headers?.get?.('X-Pass-Error') || '';
    const err = new TeamsHttpError(res.status, fileErrorCode(res.status, server), server || String(res.status));
    err.retryAfterMs = res.status === 429 ? retryAfterMs(res.headers?.get?.('Retry-After')) : 0;
    return err;
  }

  return {
    async download(device, path, etag = null) {
      const res = await send(device, path, { method: 'GET', etag });
      if (res.status === 304) return { unchanged: true, etag };
      if (!res.ok) throw refused(res);
      return { file: new Uint8Array(await res.arrayBuffer()), etag: res.headers?.get?.('ETag') || null };
    },
    /** `{ conflict: true }` on 412: someone uploaded meanwhile. */
    async upload(device, path, file, etag = null) {
      const res = await send(device, path, { method: 'PUT', etag, body: file });
      if (res.status === 412) return { conflict: true };
      if (!res.ok) throw refused(res);
      return { etag: res.headers?.get?.('ETag') || null };
    },
  };
}
