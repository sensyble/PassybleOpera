// How often browser mode checks its shared vault files on Passyble Cloud: about every minute while the vault is
// unlocked and the Cloud plan is live, and at once on unlock and when the browser is back online. A check is one
// conditional GET per shared vault (304 when nothing changed); the account service keeps its 5 minutes.
// Pure rules: the state `{ checkedAt, failures, retryAt, code }` is kept by the caller.

export const CLOUD_SYNC_ALARM = 'pass-cloud-sync';
export const CLOUD_SYNC_PERIOD_MIN = 1;
export const FAST_MS = 60_000;
export const BACKOFF_MS = 30_000;
export const BACKOFF_MAX_MS = 10 * 60_000;
export const RETRY_AFTER_MAX_MS = 60 * 60_000;
const JITTER = 0.2;

/** The least time since the last check per reason; the alarm allows for Chrome's timing. */
const MIN_GAP_MS = Object.freeze({ unlock: 0, online: 0, popup: 15_000, alarm: 30_000 });

/** File answers worth trying again later; anything else is an answer (a member removed is no reason to wait). */
export const TRANSIENT_CODES = Object.freeze(['network', 'busy', 'internal']);
/** File answers saying the Cloud plan behind a vault is not live: no quick checks of it. */
export const PLAN_CODES = Object.freeze(['subscription_inactive', 'account_suspended']);

export function emptyCadence() {
  return { checkedAt: 0, failures: 0, retryAt: 0, code: '' };
}

export function cadenceOf(raw) {
  const num = (v) => (Number.isFinite(v) && v > 0 ? v : 0);
  return { checkedAt: num(raw?.checkedAt), failures: Math.floor(num(raw?.failures)), retryAt: num(raw?.retryAt),
    code: typeof raw?.code === 'string' ? raw.code : '' };
}

/** Quick checks only with a Cloud device, an unlocked vault and a shared vault whose plan is live. */
export function cloudLive({ device = null, locked = true, vaults = [], blocked = [] } = {}) {
  if (!device || locked) return false;
  const out = new Set(blocked);
  return vaults.some((id) => !out.has(id));
}

/** 30 s doubling per failure in a row, at most 10 minutes, give or take a tenth. */
export function backoffMs(failures, random = Math.random) {
  if (!(failures > 0)) return 0;
  const base = Math.min(BACKOFF_MAX_MS, BACKOFF_MS * 2 ** Math.min(failures - 1, 20));
  return Math.min(BACKOFF_MAX_MS, Math.round(base * (1 - JITTER / 2 + JITTER * random())));
}

/** A `Retry-After` header (seconds or an HTTP date) in milliseconds from `now`; 0 without one. */
export function retryAfterMs(value, now = Date.now()) {
  const text = String(value ?? '').trim();
  if (!text) return 0;
  const ms = /^\d+$/.test(text) ? Number(text) * 1000 : Date.parse(text) - now;
  return Number.isFinite(ms) && ms > 0 ? Math.min(ms, RETRY_AFTER_MAX_MS) : 0;
}

/** When a check for `reason` (unlock, online, popup, alarm) may run. Unlock and online wait only for a busy server. */
export function nextCheckAt(state, reason) {
  const gap = MIN_GAP_MS[reason] ?? FAST_MS;
  const after = state.checkedAt + gap;
  return gap > 0 || state.code === 'busy' ? Math.max(after, state.retryAt) : after;
}

export function shouldCheck(state, reason, now) {
  return now >= nextCheckAt(state, reason);
}

/** The state after a check whose failed vaults are `failed` (`[{ code, retryAfterMs }]`). */
export function afterCheck(state, failed, now, random = Math.random) {
  const again = (Array.isArray(failed) ? failed : []).filter((f) => TRANSIENT_CODES.includes(f?.code));
  if (!again.length) return { checkedAt: now, failures: 0, retryAt: 0, code: '' };
  const failures = state.failures + 1;
  const busy = again.find((f) => f.code === 'busy');
  const wait = Math.max(backoffMs(failures, random), busy ? Number(busy.retryAfterMs) || 0 : 0);
  return { checkedAt: now, failures, retryAt: now + wait, code: busy ? 'busy' : again[0].code };
}
