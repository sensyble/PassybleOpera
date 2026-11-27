// The account service's organisation API for browser mode. Only the background calls it, and only with a
// signed-in account. Errors come back as a TeamsHttpError with the service's code and the status.
import { ErrorCode, PassError } from '../../shared/errors.js';

export class TeamsHttpError extends PassError {
  constructor(status, code, message) {
    super(statusCode(status, code), message || `${status} ${code || ''}`.trim());
    this.status = status;
    this.serviceCode = code || '';
    this.data = null;
  }
}

function statusCode(status, code) {
  if (status === 0) return 'network';
  if (status === 401) return 'signed_out';
  return code || (status >= 500 ? 'network' : ErrorCode.INTERNAL);
}

export function apiRequest(method, token, body) {
  const init = {
    method,
    headers: { Accept: 'application/json', Authorization: `Bearer ${token}` },
    credentials: 'omit',
    cache: 'no-store',
    redirect: 'error',
  };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  return init;
}

export const ORG_ROUTES = Object.freeze({
  orgs: ['GET', '/v1/orgs'],
  keys: ['GET', '/v1/keys'],
  putKeys: ['PUT', '/v1/keys'],
  cloudDevice: ['POST', '/v1/cloud/devices'],
  orgVaults: ['GET', '/v1/orgs/<org>/vaults'],
  confirmations: ['GET', '/v1/orgs/<org>/confirmations'],
  confirm: ['POST', '/v1/orgs/<org>/confirmations'],
  personKeys: ['GET', '/v1/orgs/<org>/keys/<account>'],
  invites: ['GET', '/v1/invites'],
  answerInvite: ['POST', '/v1/invites/<member>/accept|decline'],
  leaveOrg: ['POST', '/v1/orgs/<org>/leave'],
  leaveVault: ['POST', '/v1/orgs/<org>/vaults/<vault>/leave'],
  deviceApprovals: ['GET', '/v1/device-approvals'],
  answerDevice: ['POST', '/v1/device-approvals/<id>/approve|deny'],
  deviceApprovalEmail: ['POST', '/v1/device-approvals/email'],
  secondPassword: ['PUT', '/v1/me/second-password'],
});

const seg = (v) => encodeURIComponent(String(v || ''));

export function createOrgApi({ account, fetch: fetchFn = (...a) => globalThis.fetch(...a) }) {
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
      const err = new TeamsHttpError(res.status, code, typeof data?.message === 'string' ? data.message : '');
      err.data = data;
      throw err;
    }
    return data ?? {};
  }

  return {
    orgs: () => call('GET', '/v1/orgs'),
    keys: () => call('GET', '/v1/keys'),
    putKeys: (keys) => call('PUT', '/v1/keys', keys),
    cloudDevice: (deviceName) => call('POST', '/v1/cloud/devices', { device_name: String(deviceName || '').slice(0, 80) }),
    orgVaults: (org) => call('GET', `/v1/orgs/${seg(org)}/vaults`),
    confirmations: (org) => call('GET', `/v1/orgs/${seg(org)}/confirmations`),
    confirm: (org, accountId, fingerprint) => call('POST', `/v1/orgs/${seg(org)}/confirmations`, { account_id: String(accountId), fingerprint: String(fingerprint) }),
    personKeys: (org, accountId) => call('GET', `/v1/orgs/${seg(org)}/keys/${seg(accountId)}`),
    invites: () => call('GET', '/v1/invites'),
    answerInvite: (memberId, accept) => call('POST', `/v1/invites/${seg(memberId)}/${accept ? 'accept' : 'decline'}`),
    leaveOrg: (org) => call('POST', `/v1/orgs/${seg(org)}/leave`),
    /** Leave one shared vault given directly (`409 bad_state` through a department or everyone). */
    leaveVault: (org, vaultId) => call('POST', `/v1/orgs/${seg(org)}/vaults/${seg(vaultId)}/leave`),
    deviceApprovals: () => call('GET', '/v1/device-approvals'),
    /** Deny is "This wasn't me", which signs that session out. */
    answerDevice: (id, approve) => call('POST', `/v1/device-approvals/${seg(id)}/${approve ? 'approve' : 'deny'}`),
    deviceApprovalEmail: () => call('POST', '/v1/device-approvals/email'),
    secondPassword: (on) => call('PUT', '/v1/me/second-password', { second_password: on === true }),
  };
}

export function consoleUrl(base, org) {
  if (!org?.id) return `${base}/`;
  return org.kind === 'family' ? `${base}/family` : `${base}/org/${seg(org.id)}`;
}

/**
 * The caller's password mode across their Teams: `second_password` if any Team says so, else `one_password`
 * if any, else `choice`. A Family, a missing key (an older service) or an unknown value counts as `choice`.
 */
export function passwordMode(orgs) {
  const modes = new Set((Array.isArray(orgs) ? orgs : []).filter((o) => o?.kind === 'team').map((o) => o.policy?.password_mode));
  if (modes.has('second_password')) return 'second_password';
  if (modes.has('one_password')) return 'one_password';
  return 'choice';
}

/** The account service's policy as the core's policy JSON. Core names given as such are kept. */
export function corePolicy(p) {
  if (!p || typeof p !== 'object') return null;
  const out = {};
  const score = p.master_password_min_strength ?? p.min_password_score;
  if (score !== undefined && score !== null) out.master_password_min_strength = score;
  const lock = p.max_auto_lock_minutes;
  if (Number.isFinite(lock) && lock > 0) out.max_auto_lock_minutes = lock;
  if (typeof p.export_allowed === 'boolean') out.export_allowed = p.export_allowed;
  const outside = p.sharing_outside_allowed ?? p.share_outside;
  if (typeof outside === 'boolean') out.sharing_outside_allowed = outside;
  if (typeof p.require_two_step === 'boolean') out.require_two_step = p.require_two_step;
  else if (typeof p.sign_in === 'string') out.require_two_step = p.sign_in !== 'any';
  return out;
}
