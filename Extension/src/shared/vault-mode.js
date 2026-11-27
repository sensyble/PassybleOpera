// Where the vault is: `app` (the desktop app over native messaging) or `browser` (a WebAssembly vault in IndexedDB).
// Whenever the Passyble app is installed it wins. Never in chrome.storage.sync: the vault isn't on other computers.
import { ext, isGecko } from './api.js';

// Storage keys use backticks so the i18n test, which scans quoted strings, doesn't take them for message names.
export const VAULT_MODE_KEY = `vaultMode`;
export const VaultMode = Object.freeze({ APP: 'app', BROWSER: 'browser' });

// 'missing' or 'present' (connectNative works, whether or not the app is running); 'present' rules out browser mode.
export const HOST_SEEN_KEY = `vaultHostSeen`;

export const HOST_MISSES_KEY = `vaultHostMisses`;
// Set only after MISSING_CHECKS spaced host-not-found answers, never by one failure.
export const APP_GONE_KEY = `vaultAppGone`;
/** Host-not-found answers, each at least MISS_SPACING_MS after the one before, before the app counts as gone. */
export const MISSING_CHECKS = 3;
export const MISS_SPACING_MS = 60_000;

/** `connected`, `installed` (host there; the app is closed, slow or has no vault) or `missing`. */
export function hostOutcome(err, isHostMissing) {
  if (!err) return 'connected';
  return isHostMissing(err) ? 'missing' : 'installed';
}

/** The next state after one look for the app; only MISSING_CHECKS spaced misses mark a seen app as gone. */
export function nextHostState(prev = {}, outcome, { now = Date.now(), supported = true } = {}) {
  const mode = prev.mode === VaultMode.APP || prev.mode === VaultMode.BROWSER ? prev.mode : null;
  const misses = Number.isInteger(prev.misses) && prev.misses > 0 ? prev.misses : 0;
  const missAt = Number(prev.missAt) || 0;
  const base = { mode, host: prev.host === 'present' || prev.host === 'missing' ? prev.host : null,
    misses, missAt, appGone: prev.appGone === true, switched: false, gone: false };
  if (outcome === 'connected' || outcome === 'installed') {
    return { ...base, mode: supported ? VaultMode.APP : mode, host: 'present', misses: 0, missAt: 0, appGone: false,
      switched: supported && mode === VaultMode.BROWSER };
  }
  if (outcome !== 'missing') return base;
  if (base.host !== 'present') return { ...base, host: 'missing', misses: 0, missAt: 0 };
  const counts = now - missAt >= MISS_SPACING_MS || now < missAt;
  const count = counts ? misses + 1 : misses;
  if (count >= MISSING_CHECKS) {
    // Gone: browser mode is offered again. In browser mode there is nothing to tell (the vault is here).
    return { ...base, host: 'missing', misses: 0, missAt: 0, appGone: mode !== VaultMode.BROWSER, gone: mode !== VaultMode.BROWSER };
  }
  return { ...base, misses: count, missAt: counts ? now : missAt };
}

export function browserModeOffered({ supported, host }) {
  return !!supported && host !== 'present';
}

// Plain record, no secrets (titles of items that could not move). After 'moved' the vault here is kept, unused, until deleted.
export const MOVE_KEY = `vaultMove`;
export const MoveState = Object.freeze({ OFFER: 'offer', LATER: 'later', PARTIAL: 'partial', MOVED: 'moved' });

export function sanitizeMove(value, vaultId = undefined) {
  if (!value || typeof value !== 'object' || !Object.values(MoveState).includes(value.state)) return null;
  if (vaultId !== undefined && value.vault_id !== vaultId) return null;
  const n = (v) => (Number.isInteger(v) && v >= 0 ? v : 0);
  return {
    state: value.state,
    vault_id: typeof value.vault_id === 'string' ? value.vault_id : null,
    count: Number.isInteger(value.count) && value.count >= 0 ? value.count : null,
    total: n(value.total), added: n(value.added), skipped: n(value.skipped), failed_count: n(value.failed_count),
    failed: Array.isArray(value.failed) ? value.failed.filter((t) => typeof t === 'string').slice(0, 50) : [],
    at: n(value.at),
  };
}

export function moveAfterImport(vaultId, res, now = Date.now()) {
  const n = (v) => (Number.isInteger(v) && v >= 0 ? v : 0);
  const failed = Array.isArray(res?.failed) ? res.failed.map((f) => String(f?.title ?? '').slice(0, 256)).slice(0, 50) : [];
  const failedCount = Math.max(n(res?.failed_count), failed.length);
  return {
    state: failedCount > 0 ? MoveState.PARTIAL : MoveState.MOVED,
    vault_id: vaultId, count: n(res?.total), total: n(res?.total), added: n(res?.added), skipped: n(res?.skipped),
    failed_count: failedCount, failed, at: now,
  };
}

export function moveOfferDue(move, { mode, hasVault }) {
  return mode === VaultMode.APP && !!hasVault && move?.state === MoveState.OFFER && move.count !== 0;
}

/** "Lock after N minutes": the choices; 0 is "only when the browser closes". */
export const AUTO_LOCK_CHOICES = Object.freeze([1, 5, 15, 30, 60, 0]);
// "Only when the browser closes": the browser clears the key (storage.session), so the agent's own
// timer is set far out instead of off.
const BROWSER_CLOSE_SECS = 365 * 24 * 3600;

export const DEFAULT_VAULT_SETTINGS = Object.freeze({
  vaultAutoLockMins: 15,
  vaultLockOnIdle: true,     // lock when the computer locks (chrome.idle "locked")
  vaultVerifyEachFill: false,
});

/** Feature-detected (WebAssembly and storage.session), not by browser name. `api` and `scope` are for tests. */
export function browserVaultSupported(api = ext, scope = globalThis) {
  try {
    return typeof scope.WebAssembly?.instantiate === 'function' && typeof api?.storage?.session?.get === 'function';
  } catch {
    return false;
  }
}

/** Firefox has the idle API but only reports `active` and `idle`; Safari has no idle API. */
export function lockOnComputerLockSupported(api = ext) {
  return typeof api?.idle?.onStateChanged?.addListener === 'function' && !isGecko;
}

/** `app`, `browser`, or null when nobody chose yet (then the extension behaves as in app mode). */
export async function getVaultMode() {
  try {
    const got = await ext.storage.local.get(VAULT_MODE_KEY);
    const mode = got?.[VAULT_MODE_KEY];
    if (mode === VaultMode.BROWSER) return browserVaultSupported() ? VaultMode.BROWSER : VaultMode.APP;
    return mode === VaultMode.APP ? VaultMode.APP : null;
  } catch {
    return null;
  }
}

export async function setVaultMode(mode) {
  if (mode !== VaultMode.APP && mode !== VaultMode.BROWSER) throw new TypeError('bad vault mode');
  await ext.storage.local.set({ [VAULT_MODE_KEY]: mode });
}

export async function getVaultSettings() {
  let got = {};
  try { got = (await ext.storage.local.get(Object.keys(DEFAULT_VAULT_SETTINGS))) || {}; } catch { /* defaults */ }
  return sanitizeVaultSettings({ ...DEFAULT_VAULT_SETTINGS, ...got });
}

export function sanitizeVaultSettings(input) {
  const out = {};
  if (input && AUTO_LOCK_CHOICES.includes(input.vaultAutoLockMins)) out.vaultAutoLockMins = input.vaultAutoLockMins;
  else if (input && Object.hasOwn(input, `vaultAutoLockMins`)) out.vaultAutoLockMins = DEFAULT_VAULT_SETTINGS.vaultAutoLockMins;
  for (const key of [`vaultLockOnIdle`, `vaultVerifyEachFill`]) {
    if (input && typeof input[key] === 'boolean') out[key] = input[key];
  }
  return out;
}

export function autoLockSecs(mins) {
  return Number.isInteger(mins) && mins > 0 ? mins * 60 : BROWSER_CLOSE_SECS;
}

export const LOCAL_REMINDER_KEY = `vaultLocalReminderDismissed`;
export const LOCAL_REMINDER_SNOOZE_MS = 30 * 24 * 3600 * 1000;

/** Whether the vault of this browser is only on this device: there is one, and it has no sync. */
export function isLocalOnlyVault(info) {
  return !!info?.hasVault && !!info.vaultId && !info.source;
}

export function isDriveRecord(info) {
  return !!info?.hasVault && info.source === 'drive';
}

/** A dismiss time in the future (another clock) counts as just now. */
export function localReminderDue(dismissed, vaultId, now = Date.now()) {
  const at = Number(dismissed && typeof dismissed === 'object' ? dismissed[vaultId] : 0) || 0;
  if (at <= 0) return true;
  return now - Math.min(at, now) >= LOCAL_REMINDER_SNOOZE_MS;
}

/** Also tidies away other vaults' entries 30 days old or more, so the setting stays small. */
export function dismissLocalReminder(dismissed, vaultId, now = Date.now()) {
  const out = {};
  for (const [id, at] of Object.entries(dismissed && typeof dismissed === 'object' ? dismissed : {})) {
    if (Number.isFinite(at) && now - at < LOCAL_REMINDER_SNOOZE_MS) out[id] = at;
  }
  out[String(vaultId)] = now;
  return out;
}

// Plain device-local flags, never the password, a score or the rule's reasons.
export const MASTER_TIP_KEY = `vaultMasterPasswordTip`;

export function sanitizeMasterTips(value) {
  const out = {};
  if (!value || typeof value !== 'object' || Array.isArray(value)) return out;
  for (const [id, entry] of Object.entries(value)) {
    if (!id || !entry || typeof entry !== 'object') continue;
    const flags = {};
    if (entry.weak === true) flags.weak = true;
    if (entry.dismissed === true) flags.dismissed = true;
    if (Object.keys(flags).length) out[id] = flags;
  }
  return out;
}

function withMasterTip(tips, vaultId, flags) {
  const out = sanitizeMasterTips(tips);
  const id = String(vaultId ?? '');
  if (!id) return out;
  const entry = {};
  if (flags.weak === true) entry.weak = true;
  if (flags.dismissed === true) entry.dismissed = true;
  if (Object.keys(entry).length) out[id] = entry;
  else delete out[id];
  return out;
}

function masterTipOf(tips, vaultId) {
  const entry = sanitizeMasterTips(tips)[String(vaultId ?? '')] || {};
  return { weak: entry.weak === true, dismissed: entry.dismissed === true };
}

/** Only unlocks with a typed master password call this; a restored session key leaves the flags alone. */
export function masterTipAfterUnlock(tips, vaultId, weak) {
  return withMasterTip(tips, vaultId, { ...masterTipOf(tips, vaultId), weak: weak === true });
}

export function dismissMasterTip(tips, vaultId) {
  return withMasterTip(tips, vaultId, { ...masterTipOf(tips, vaultId), dismissed: true });
}

export function clearMasterTip(tips, vaultId) {
  return withMasterTip(tips, vaultId, {});
}

export function masterTipVisible(tips, vaultId) {
  const { weak, dismissed } = masterTipOf(tips, vaultId);
  return weak && !dismissed;
}

/** "Delete vault" of a vault kept only in this browser needs a copy downloaded this recently. */
export const DELETE_BACKUP_MS = 60 * 60 * 1000;

export function backupFileName(date = new Date()) {
  const pad = (n) => String(n).padStart(2, '0');
  return `Passyble-${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}.vault`;
}
