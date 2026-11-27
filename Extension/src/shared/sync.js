// `sync.now` answer: `{ synced, failed: [{ vault, reason }], no_sync }`, plus `browser: true` in browser mode.
// An older desktop app answers "unknown method", reported as `not_supported` / `needs_update`.
import { t, tp } from './i18n.js';
import { friendlyError } from './messages.js';

const MAX_NAME = 120;
const MAX_REASON = 300;

export function syncResult(raw) {
  const n = Number(raw?.synced);
  const failed = (Array.isArray(raw?.failed) ? raw.failed : [])
    .filter((f) => f && typeof f === 'object')
    .map((f) => ({ vault: oneLine(f.vault, MAX_NAME), reason: oneLine(f.reason, MAX_REASON) }));
  return { synced: Number.isFinite(n) && n > 0 ? Math.floor(n) : 0, failed, no_sync: raw?.no_sync === true, browser: raw?.browser === true };
}

function oneLine(value, max) {
  return (typeof value === 'string' ? value : '').replace(/\s+/g, ' ').trim().slice(0, max);
}

export function syncNeedsUpdate(err) {
  if (!err || err.code !== 'not_supported') return false;
  return err.reason === 'needs_update' || /unknown method/i.test(String(err.message || ''));
}

/** What to tell the user after a sync: `{ text, kind }` with kind done, failed, none, update or error. */
export function syncOutcome({ result = null, error = null } = {}) {
  if (error) {
    if (syncNeedsUpdate(error)) return { text: t('syncNeedsUpdate'), kind: 'update' };
    return { text: friendlyError(error), kind: 'error' };
  }
  const r = syncResult(result);
  if (r.failed.length) {
    const first = r.failed[0];
    const reason = first.reason || friendlyError({ code: 'internal' });
    let text;
    if (r.failed.length > 1) text = tp('syncFailedMany', r.failed.length, first.vault || t('syncVaultUnnamed'), reason);
    else if (first.vault) text = t('syncFailed', first.vault, reason);
    else text = t('syncFailedNoName', reason);
    return { text, kind: 'failed' };
  }
  if (r.no_sync) return { text: r.browser ? t('syncNoneBrowser') : t('syncNoneApp'), kind: 'none' };
  return { text: t('syncDone'), kind: 'done' };
}
