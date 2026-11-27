// Passyble background: MV3 service worker in Chromium, background module script in Firefox.
// URLs and origins sent to the agent always come from the browser's sender info (`sender.url`,
// `sender.origin`, `tabs.get`), never from what a content script claims. It holds no vault data: a
// credential being filled or copied, or a just-submitted password for the save banner, only passes
// through and is never logged. Secret copies are made by the desktop app when it can, which keeps them
// out of clipboard history.
import { ext, isGecko } from './shared/api.js';
import { NativeClient } from './background/native-client.js';
import { ErrorCode, PassError, Reason } from './shared/errors.js';
import { getSettings } from './shared/settings.js';
import { shouldOfferPendingOtp, latePendingOtp, PENDING_OTP_WINDOW_MS } from './shared/otp-logic.js';
import { createClipboardClearer, defaultClearNow, writeClipboard } from './background/clipboard-clear.js';
import { parsePairingLink, normalizeServerAddress } from './shared/pairing.js';
import { isNeverSave, addNeverSave, NEVER_SAVE_CARDS_KEY } from './shared/never-save.js';
import { createCardSave } from './background/card-save.js';
import { prefersNoSymbols, rememberSymbols, rememberOptions } from './shared/generate-prefs.js';
import { createCommands } from './background/commands.js';
import { MENU_SAVE_SELECTION, createNoteClip } from './background/note-clip.js';
import { generatePassword, isPlainPassword, DEFAULT_LENGTH } from './shared/generator.js';
import { autoSavePlan, createGeneratedPasswords } from './background/generated.js';
import { changedPlan, changesOf, filledLogin, liveFilled } from './background/fill-changes.js';
import { isSecureFormUrl } from './shared/cards.js';
import { t, tp } from './shared/i18n.js';
import { openWelcome } from './shared/welcome-link.js';
import { friendlyError, isHostMissing } from './shared/messages.js';
import { LocalBackend, TICK_ALARM } from './background/local/local-backend.js';
import { loadWasm } from './background/local/wasm.js';
import { defaultVaultStore } from './background/local/vault-store.js';
import { keySession } from './background/local/session.js';
import { createAccount, DEV_BASE_KEY } from './background/account.js';
import { createAccountKeys, defaultKeyStore, MAX_ACCOUNT_PASSWORD } from './background/account-keys.js';
import { openSupport } from './shared/support-link.js';
import { isSafariExtension, safariPort } from './background/native-safari.js';
import { VERSIONS_ALARM, VERSIONS_PATH, VERSIONS_URL, applyUpdate, createVersionCheck } from './background/app-versions.js';
import { allowedWhileReadOnly, detectPlatform, ownVersion } from './shared/app-versions.js';
import { b64urlDecode, b64urlEncode } from './shared/b64url.js';
import { MASTER_MIN_LENGTH } from './shared/master-password.js';
import { chosenVault, newLoginVaultChoice, teamsErrorKey } from './shared/vaults.js';
import { ACROSS_VAULTS, createBrowserTeams, hasTeamsApi } from './background/teams/browser-teams.js';
import { createSync } from './background/sync.js';
import { syncOutcome } from './shared/sync.js';
import { createOrgApi } from './background/teams/org-api.js';
import { createCloudFiles } from './background/teams/cloud-files.js';
import { CLOUD_SYNC_ALARM, CLOUD_SYNC_PERIOD_MIN } from './background/teams/cloud-cadence.js';
import { createSendClient } from './background/teams/send-client.js';
import { defaultTeamsStore } from './background/teams/teams-store.js';
import {
  APP_GONE_KEY, DEFAULT_VAULT_SETTINGS, DELETE_BACKUP_MS, HOST_MISSES_KEY, HOST_SEEN_KEY, LOCAL_REMINDER_KEY, VAULT_MODE_KEY,
  MOVE_KEY, MoveState, browserModeOffered, hostOutcome, moveAfterImport, moveOfferDue, nextHostState, sanitizeMove,
  VaultMode, autoLockSecs, backupFileName, browserVaultSupported, dismissLocalReminder, getVaultMode, getVaultSettings,
  isDriveRecord, isLocalOnlyVault, localReminderDue, sanitizeVaultSettings, setVaultMode,
  MASTER_TIP_KEY, clearMasterTip, dismissMasterTip, masterTipAfterUnlock, masterTipVisible, sanitizeMasterTips,
} from './shared/vault-mode.js';

const SAVE_TTL_MS = 60_000;
const SAVE_EDIT_PATH = 'src/save/edit.html';
const IDENTIFIER_TTL_MS = 5 * 60_000;
const FOCUS_TTL_MS = 10 * 60_000;
const BACKOFF_MS = 10_000;
const DRAFT_TTL_MS = 30 * 60_000;
// Undo window for an auto-saved submit: as long as the agent keeps the copy `logins.restore` puts back.
const AUTO_UNDO_MS = 60_000;
const CROSS_FILL_TTL_MS = 2 * 60_000;
const SIMILAR_TTL_MS = 5 * 60_000;
const CROSS_OFFER_TTL_MS = 10 * 60_000;
const POPUP_SEARCH_TTL_MS = 60_000;
const B64URL_RE = /^[A-Za-z0-9_-]*$/;

// Safari routes native messages one at a time to its containing app (background/native-safari.js).
const safari = isSafariExtension();
const client = new NativeClient({
  connect: (name) => (safari ? safariPort((host, msg) => ext.runtime.sendNativeMessage(host, msg), name) : ext.runtime.connectNative(name)),
  lastError: () => ext.runtime.lastError,
});

async function versionsUrl() {
  try {
    const self = await ext.management?.getSelf?.();
    if (self?.installType === 'development') {
      const dev = (await ext.storage.local.get(DEV_BASE_KEY))?.[DEV_BASE_KEY];
      if (typeof dev === 'string' && /^https?:\/\/[^/?#]+$/.test(dev)) return `${dev}${VERSIONS_PATH}`;
    }
  } catch { /* the default */ }
  return VERSIONS_URL;
}

// The Safari extension ships inside the macOS and iOS apps and follows their versions: not checked here.
let platformKey = null;
const versionCheck = createVersionCheck({
  ext,
  version: () => ownVersion(ext),
  platform: () => (platformKey ??= safari ? Promise.resolve(null) : detectPlatform({ api: ext })),
  url: versionsUrl,
});

function extensionUpdateError() {
  return new PassError(ErrorCode.UPDATE_REQUIRED, 'Update the Passyble extension to keep filling', Reason.EXTENSION_UPDATE);
}

// An update downloaded while this version is read-only is applied at once. Chromium only: Firefox
// postpones an update until restart for an add-on that listens to this event.
let updateReady = false;
const updateReadyWaiters = new Set();
if (!isGecko && !safari) {
  ext.runtime.onUpdateAvailable?.addListener(() => {
    updateReady = true;
    for (const done of [...updateReadyWaiters]) done();
    versionCheck.blocked().then((blocked) => { if (blocked) ext.runtime.reload?.(); }).catch(() => {});
  });
}

function waitUpdateReady(ms) {
  if (updateReady) return Promise.resolve();
  return new Promise((resolve) => {
    const done = () => { updateReadyWaiters.delete(done); clearTimeout(timer); resolve(); };
    const timer = setTimeout(done, ms);
    updateReadyWaiters.add(done);
  });
}

let unavailableUntil = 0;

// Read-only methods lost with a native port that just closed are sent once more on a fresh port;
// anything else could have reached the agent already.
const RETRY_ON_NEW_PORT = new Set([
  'status', 'logins.find', 'logins.search', 'logins.save_check', 'cards.list', 'cards.save_check', 'identities.list',
  'generate', 'unlock.options', 'icons.get', 'password.check', 'passkey.find', 'passkey.create_options',
  'vaults.list', 'vaults.pins', 'vaults.own', 'sites.rule_hint', 'sites.suggest', 'sites.name_for',
]);

function retryOnNewPort(method, err) {
  return RETRY_ON_NEW_PORT.has(method) && err?.portClosed === true && !isHostMissing(err);
}

/**
 * Calls the agent (desktop app, or the browser vault in browser mode). `automatic` calls back off for a
 * few seconds after the app was unavailable, so browsing does not spawn a native host per navigation.
 */
async function agent(method, params = {}, { automatic = false, confirmed = false } = {}) {
  if (!allowedWhileReadOnly(method, params) && await versionCheck.blocked()) throw extensionUpdateError();
  if (await inBrowserMode()) return localAgent(method, params, { automatic, confirmed });
  if (automatic && Date.now() < unavailableUntil) {
    throw new PassError(ErrorCode.AGENT_UNAVAILABLE, 'Passyble desktop app is not running');
  }
  try {
    let result;
    try {
      result = await client.request(method, params);
    } catch (err) {
      if (!retryOnNewPort(method, err)) throw err;
      result = await client.request(method, params);
    }
    unavailableUntil = 0;
    noteAgentOutcome(null);
    return result;
  } catch (err) {
    const e = PassError.from(err);
    if (e.code === ErrorCode.AGENT_UNAVAILABLE) unavailableUntil = Date.now() + BACKOFF_MS;
    noteAgentOutcome(err);
    throw e;
  }
}

const vaultStore = defaultVaultStore();
const local = new LocalBackend({
  wasm: () => loadWasm((p) => ext.runtime.getURL(p)),
  store: vaultStore,
  session: keySession(ext.storage?.session),
  config: vaultConfig,
  alarms: ext.alarms,
});

let modeCache = null;

async function inBrowserMode() {
  modeCache ??= getVaultMode();
  return (await modeCache) === VaultMode.BROWSER;
}

const DEVICE_ID_KEY = `browserDeviceId`; // backticks: not a message name (test/i18n.test.js)

async function deviceId() {
  const got = await ext.storage.local.get(DEVICE_ID_KEY);
  const id = got?.[DEVICE_ID_KEY];
  if (typeof id === 'string' && /^[0-9a-f-]{36}$/.test(id)) return id;
  const fresh = crypto.randomUUID();
  await ext.storage.local.set({ [DEVICE_ID_KEY]: fresh });
  return fresh;
}

async function vaultConfig() {
  const s = await getVaultSettings();
  return { device_id: await deviceId(), auto_lock_secs: autoLockSecs(s.vaultAutoLockMins), verify_each_fill: s.vaultVerifyEachFill };
}

async function applyVaultSettings() {
  if (!(await inBrowserMode())) return;
  const s = await getVaultSettings();
  await local.setOptions({ auto_lock_secs: autoLockSecs(s.vaultAutoLockMins), verify_each_fill: s.vaultVerifyEachFill });
}

/**
 * agent() in browser mode. On `verification_required` ("Confirm each fill") it asks for the master
 * password in an extension page and retries once with that grant.
 */
async function localAgent(method, params, { automatic = false, confirmed = false } = {}) {
  if (method === 'unlock') return unlockInBrowser();
  const call = async (grant) => {
    const copies = copySeq;
    const teams = browserTeams();
    const res = teams && ACROSS_VAULTS.has(method) && (await teams.ensureOpen().catch(() => false))
      ? await teams.handle(method, params, (p) => local.request(method, p, { grant, confirmed }), { grant, confirmed })
      : await local.request(method, params, { grant, confirmed });
    // A copy the agent released must be written before the answer.
    if (copySeq !== copies && !(await copyDone)) throw new PassError(ErrorCode.INTERNAL, 'copy failed', Reason.COPY_FAILED);
    return res;
  };
  try {
    return await call(null);
  } catch (err) {
    const e = PassError.from(err);
    if (e.code !== ErrorCode.VERIFICATION_REQUIRED || automatic) throw e;
    const grant = takeUnlockGrant(params?.id) ?? (await askUser('verify', { url: params?.url })).grant;
    return call(grant);
  }
}

// An unlock the user started to fill one login counts as that fill's check.
const UNLOCK_GRANT_TTL_MS = 100_000;
let unlockGrant = null;

function takeUnlockGrant(id) {
  const g = unlockGrant;
  if (!g || typeof id !== 'string' || g.id !== id || Date.now() - g.at > UNLOCK_GRANT_TTL_MS) return null;
  unlockGrant = null;
  return g.grant;
}

async function unlockInBrowser() {
  const info = await local.info();
  if (!info.hasVault) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser yet');
  if (!info.locked) return { locked: false };
  await askUser('unlock');
  return { locked: false };
}

// Browser mode asks in the popup what the desktop app asks in its own windows. One ask at a time; a new
// one cancels the old, and closing the popup that showed it cancels it.
const POPUP_PORT = 'passyble-popup';
const ASK_TTL_MS = 3 * 60_000;
const popupPorts = new Set();
let pendingAsk = null;

function cancelledError() {
  return new PassError(ErrorCode.CANCELLED, 'Cancelled');
}

function askUser(kind, info = {}) {
  pendingAsk?.reject(cancelledError());
  return new Promise((resolve, reject) => {
    const token = crypto.randomUUID();
    let timer = null;
    const settle = (fn) => (value) => {
      if (pendingAsk?.token !== token) return;
      clearTimeout(timer);
      pendingAsk = null;
      fn(value);
    };
    pendingAsk = { token, kind, info, shown: false, resolve: settle(resolve), reject: settle(reject) };
    const ask = pendingAsk;
    timer = setTimeout(() => ask.reject(cancelledError()), ASK_TTL_MS);
    timer?.unref?.(); // Node (tests) only
    showAsk(ask).catch(() => ask.reject(cancelledError()));
  });
}

async function showAsk(ask) {
  if (popupPorts.size) {
    await ext.runtime.sendMessage({ type: 'vault.ask' }).catch(() => {});
    return;
  }
  const [tab] = await ext.tabs.query({ active: true, lastFocusedWindow: true }).catch(() => []);
  if (pendingAsk !== ask) return;
  await openUnlockForm(tab, { query: 'ask=1' });
}

/** What the popup shows for the pending ask (no secret: a site, a title, a card's last digits). */
function publicAsk() {
  if (!pendingAsk) return null;
  const { token, kind, info } = pendingAsk;
  const out = { token, kind };
  for (const key of ['host', 'title', 'domain', 'card', 'lookalike']) if (typeof info?.[key] === 'string' && info[key]) out[key] = info[key].slice(0, 256);
  if (!out.host && isWebUrl(info?.url)) out.host = hostOf(info.url);
  return out;
}

function lookalikeDomain(value) {
  const domain = typeof value === 'string' ? value : value?.domain;
  return typeof domain === 'string' ? domain.trim().slice(0, 256) : '';
}

function label(value) {
  return typeof value === 'string' ? value.slice(0, 256) : '';
}

ext.runtime.onConnect?.addListener((port) => {
  if (port?.name !== POPUP_PORT || port.sender?.id !== ext.runtime.id || !isExtensionPage(port.sender || {})) return;
  popupPorts.add(port);
  const feedback = takePopupFeedback();
  if (feedback) { try { port.postMessage?.({ type: 'feedback', text: feedback }); } catch { /* closed again */ } }
  port.onDisconnect.addListener(() => {
    popupPorts.delete(port);
    if (!popupPorts.size && pendingAsk?.shown) pendingAsk.reject(cancelledError());
  });
});

let copyDone = Promise.resolve(true);
let copySeq = 0;

local.on('lock_state', (data) => {
  // Lock the shared vaults now: the service worker may live on, held by the native port.
  if (data?.locked === true) { try { teamsInstance?.lock(); } catch { /* not started */ } setCloudAlarm(false).catch(() => {}); }
  if (data?.locked === false) cloudPull('unlock');
  onLockState(data);
  if (data?.locked === false && pendingAsk?.kind === 'unlock') pendingAsk.resolve({});
});
local.on('vault_changed', () => { featuresCache = null; });
local.on('copy', ({ text }) => {
  copySeq++;
  copyDone = writeClipboard(ext, text).then(async (ok) => {
    if (ok) await clipboardClearer.schedule(text).catch(() => {});
    return ok;
  }, () => false);
});

async function lockOnComputerLock() {
  if (!(await inBrowserMode()) || !(await getVaultSettings()).vaultLockOnIdle) return;
  await local.lock(false);
}

ext.idle?.onStateChanged?.addListener((state) => {
  if (state === 'locked') lockOnComputerLock().catch(() => {});
});

// The browser keeps running after its last window closed (background apps): lock as if it had exited.
ext.windows?.onRemoved?.addListener(async () => {
  try {
    if (!(await inBrowserMode())) return;
    const left = await ext.windows.getAll({ windowTypes: ['normal'] });
    if (!left.length) await local.lock(false);
  } catch { /* the browser is going away */ }
});

let appliedMode; // the mode onModeChanged last applied (the storage event follows the handler's own call)

async function onModeChanged() {
  modeCache = null;
  const browser = await inBrowserMode();
  if (appliedMode === browser) return;
  appliedMode = browser;
  featuresCache = null;
  unavailableUntil = 0;
  pendingAsk?.reject(cancelledError());
  if (!browser) await local.reset().catch(() => {});
  else broadcastToActiveTabs({ type: 'lock_state', locked: (await local.info()).locked });
  refreshActiveBadges();
}

ext.storage.onChanged?.addListener((changes, area) => {
  if (area !== 'local' || !changes) return;
  if (VAULT_MODE_KEY in changes) onModeChanged().catch(() => {});
  else if (Object.keys(DEFAULT_VAULT_SETTINGS).some((k) => k in changes)) applyVaultSettings().catch(() => {});
});

// The Passyble app always wins over the browser vault.

const DETECT_TIMEOUT_MS = 20_000;
let detecting = Promise.resolve();

async function hostState() {
  const got = await ext.storage.local.get([VAULT_MODE_KEY, HOST_SEEN_KEY, HOST_MISSES_KEY, APP_GONE_KEY]).catch(() => ({}));
  const misses = got?.[HOST_MISSES_KEY] && typeof got[HOST_MISSES_KEY] === 'object' ? got[HOST_MISSES_KEY] : {};
  return { mode: got?.[VAULT_MODE_KEY] ?? null, host: got?.[HOST_SEEN_KEY] ?? null, misses: misses.count, missAt: misses.at,
    appGone: got?.[APP_GONE_KEY] === true };
}

let hostClean = false;
let hostQueue = Promise.resolve();

function noteHost(outcome) {
  const run = hostQueue.then(() => applyHostOutcome(outcome));
  hostQueue = run.catch(() => {});
  return run;
}

async function applyHostOutcome(outcome) {
  if (!browserVaultSupported()) return null;
  const prev = await hostState();
  const next = nextHostState(prev, outcome);
  const patch = {};
  if (next.host && next.host !== prev.host) patch[HOST_SEEN_KEY] = next.host;
  if (next.misses !== (Number(prev.misses) || 0) || next.missAt !== (Number(prev.missAt) || 0)) {
    patch[HOST_MISSES_KEY] = { count: next.misses, at: next.missAt };
  }
  if (next.appGone !== prev.appGone) patch[APP_GONE_KEY] = next.appGone;
  // Before the mode switch, while the browser vault is still open to count its items.
  if (next.switched) await offerMove().catch(() => {});
  if (next.mode && next.mode !== prev.mode) patch[VAULT_MODE_KEY] = next.mode;
  if (Object.keys(patch).length) await ext.storage.local.set(patch);
  if (patch[VAULT_MODE_KEY]) await onModeChanged();
  hostClean = next.host === 'present' && !next.misses && !next.appGone && next.mode === VaultMode.APP;
  return next;
}

/** A host not found counts towards "the app is gone"; the app not running or slow never does. */
function noteAgentOutcome(err) {
  if (!browserVaultSupported()) return;
  if (err && !isHostMissing(err) && PassError.from(err).code !== ErrorCode.AGENT_UNAVAILABLE) return;
  const outcome = hostOutcome(err, isHostMissing);
  if (outcome !== 'missing' && hostClean) return;
  noteHost(outcome).catch(() => {});
}

async function probeHost({ timeoutMs = DETECT_TIMEOUT_MS } = {}) {
  let failure = null;
  try {
    await client.request('status', {}, { timeoutMs });
  } catch (err) {
    failure = err;
  } finally {
    // Browser mode does not keep the native port open.
    if (await inBrowserMode()) client.disconnect();
  }
  return hostOutcome(failure, isHostMissing);
}

/** New install: app mode silently when the native host is there; otherwise the setup guide asks. */
async function detectMode() {
  if (!browserVaultSupported() || (await getVaultMode())) return;
  const outcome = await probeHost();
  if (await getVaultMode()) return; // the user chose meanwhile
  await noteHost(outcome);
}

const APP_PROBE_KEY = `vaultHostProbeAt`;
const APP_PROBE_EVERY_MS = 10 * 60 * 1000;
let probing = null;

/** Browser mode or nothing chosen: looks whether the Passyble app is installed now, at most once per `every`. */
function lookForApp({ every = APP_PROBE_EVERY_MS } = {}) {
  if (!browserVaultSupported()) return Promise.resolve(null);
  probing ??= (async () => {
    try {
      if ((await getVaultMode()) === VaultMode.APP) return null;
      const got = await ext.storage.local.get(APP_PROBE_KEY).catch(() => ({}));
      const last = Number(got?.[APP_PROBE_KEY]) || 0;
      if (Date.now() - last < every && last <= Date.now()) return null;
      await ext.storage.local.set({ [APP_PROBE_KEY]: Date.now() });
      return await noteHost(await probeHost());
    } finally {
      probing = null;
    }
  })();
  return probing;
}

async function moveRecord(vaultId) {
  const got = await ext.storage.local.get(MOVE_KEY).catch(() => ({}));
  return sanitizeMove(got?.[MOVE_KEY], vaultId);
}

/** Browser mode found the app: the one-time offer to move this browser's items (none for an empty vault). */
async function offerMove() {
  const info = await local.info();
  if (!info.hasVault || !info.vaultId || (await moveRecord(info.vaultId))) return;
  let count = null;
  if (!info.locked) {
    const list = await local.request('vaults.list').catch(() => null);
    const vaults = Array.isArray(list?.vaults) ? list.vaults : [];
    const home = vaults.find((v) => v?.home) || vaults[0];
    if (Number.isInteger(home?.items)) count = home.items;
  }
  if (count === 0) return;
  await ext.storage.local.set({ [MOVE_KEY]: { state: MoveState.OFFER, vault_id: info.vaultId, count, at: Date.now() } });
}

async function storedBrowserVault() {
  return vaultStore.load().catch(() => null);
}

async function moveState(rec) {
  if (!rec?.id) return null;
  return (await moveRecord(rec.id)) || sanitizeMove({ state: MoveState.LATER, vault_id: rec.id, count: null });
}

/** Moves the browser vault's items into the Passyble app (`items.import`). The password is never kept. */
async function moveToApp(msg) {
  requireBrowserVault();
  if (await inBrowserMode()) throw new PassError(ErrorCode.INVALID_STATE, 'Use the Passyble app first');
  const rec = await storedBrowserVault();
  if (!rec?.id) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser');
  const status = await agent('status');
  if (!Array.isArray(status?.features) || !status.features.includes('items.import')) {
    throw new PassError(ErrorCode.NOT_SUPPORTED, 'This Passyble app cannot take items from the browser', Reason.NEEDS_UPDATE);
  }
  let opened;
  if (await linkedBrowserVault()) {
    const link = await accountKeys.vaultLink();
    const p = accountPasswordParams(msg);
    const ak = await accountKeys.openAccountKey({ accountId: link.account, akId: link.ak_id, password: p.password,
      secretKey: p.secretKey, shared: p.shared, email: p.email });
    try {
      opened = await local.exportForMove((fresh) => fresh.unlockWithAccountKey(ak));
    } finally {
      ak.free?.();
    }
  } else {
    const password = masterPassword(msg.password);
    opened = await local.exportForMove((fresh) => fresh.unlock(password));
  }
  const params = { file: b64urlEncode(opened.file), key: b64urlEncode(opened.key) };
  opened.key.fill(0);
  if (typeof msg.vault === 'string' && msg.vault) params.vault = msg.vault.slice(0, 128);
  let res;
  try {
    res = await agent('items.import', params);
  } catch (err) {
    if (PassError.from(err).code !== ErrorCode.LOCKED) throw err;
    await agent('unlock');
    res = await agent('items.import', params);
  }
  const record = moveAfterImport(opened.vaultId || rec.id, res);
  await ext.storage.local.set({ [MOVE_KEY]: record });
  return record;
}

async function reminderDismissals() {
  const got = await ext.storage.local.get(LOCAL_REMINDER_KEY).catch(() => ({}));
  const value = got?.[LOCAL_REMINDER_KEY];
  return value && typeof value === 'object' ? value : {};
}

async function vaultFlags(info) {
  const localOnly = isLocalOnlyVault(info);
  return {
    local_only: localOnly,
    drive_needs_app: isDriveRecord(info),
    reminder: localOnly && localReminderDue(await reminderDismissals(), info.vaultId),
  };
}

async function browserPopupExtras() {
  const info = await local.info();
  lookForApp().catch(() => {});
  const accountUnlock = info.hasVault ? await accountKeys.unlockInfo().catch(() => null) : null;
  const canSync = info.hasVault ? await browserCanSync() : false;
  return { browser: true, ...(await vaultFlags(info)), ask: publicAsk(), account_unlock: accountUnlock, can_sync: canSync };
}

async function vaultState() {
  await detecting.catch(() => {});
  const mode = await getVaultMode();
  const got = await ext.storage.local.get([HOST_SEEN_KEY, APP_GONE_KEY]).catch(() => ({}));
  const host = got?.[HOST_SEEN_KEY] || null;
  const supported = browserVaultSupported();
  const out = { mode, supported, host, app_installed: supported && !browserModeOffered({ supported, host }),
    app_gone: got?.[APP_GONE_KEY] === true, move: null,
    has_vault: false, locked: true, source: null, backed_up_at: 0, settings: await getVaultSettings() };
  let info;
  if (mode === VaultMode.BROWSER) {
    info = await local.info();
    Object.assign(out, { has_vault: info.hasVault, locked: info.locked, backed_up_at: info.backedUpAt, created_at: info.createdAt,
      source: info.hasVault ? info.source : null, name: info.name || '' });
  } else {
    const rec = await vaultStore.load().catch(() => null);
    info = { hasVault: !!rec, vaultId: rec?.id || null, source: rec?.source || null };
    Object.assign(out, { has_vault: !!rec, backed_up_at: rec?.backedUpAt || 0, created_at: rec?.createdAt || 0, source: rec?.source || null });
    if (supported && rec) out.move = await moveState(rec);
  }
  out.master_tip = mode === VaultMode.BROWSER && !!info.hasVault && masterTipVisible(await masterTips(), info.vaultId);
  return Object.assign(out, await vaultFlags(info));
}

async function masterTips() {
  const got = await ext.storage.local.get(MASTER_TIP_KEY).catch(() => ({}));
  return sanitizeMasterTips(got?.[MASTER_TIP_KEY]);
}

async function updateMasterTips(vaultId, update) {
  if (!vaultId) return;
  await ext.storage.local.set({ [MASTER_TIP_KEY]: update(await masterTips(), vaultId) });
}

/**
 * After an unlock with a typed master password, sets the per-vault weak flag from the core's rule.
 * Only the flag is kept, never the password, score or reasons.
 */
async function recordMasterTip(password) {
  try {
    const info = await local.info();
    if (!info.hasVault || !info.vaultId) return;
    const check = await masterPasswordRule(password, info.name ? [info.name] : []);
    await updateMasterTips(info.vaultId, (tips, id) => masterTipAfterUnlock(tips, id, !check.ok));
  } catch { /* the flags stay as they were */ }
}

async function useBrowserVault() {
  await setVaultMode(VaultMode.BROWSER);
  await ext.storage.local.set({ [APP_GONE_KEY]: false }).catch(() => {});
  await onModeChanged();
}

async function requireBrowserModeOffered() {
  if (!browserModeOffered({ supported: browserVaultSupported(), host: (await hostState()).host })) {
    throw new PassError(ErrorCode.INVALID_STATE, 'The Passyble app is installed on this computer, so Passyble uses it here');
  }
}

const APP_CHECK_TIMEOUT_MS = 20_000;

async function checkForApp() {
  client.disconnect();
  unavailableUntil = 0;
  const app = await probeHost({ timeoutMs: APP_CHECK_TIMEOUT_MS });
  await noteHost(app).catch(() => {});
  return { app, mode: await getVaultMode() };
}

function vaultFileOf(value) {
  let file;
  try {
    file = b64urlDecode(String(value || ''));
  } catch {
    throw new PassError(ErrorCode.INVALID_PARAMS, 'This is not a Passyble vault file');
  }
  if (!file.length || file.length > MAX_VAULT_FILE) throw new PassError(ErrorCode.INVALID_PARAMS, 'This is not a Passyble vault file');
  return file;
}

function requireBrowserVault() {
  if (!browserVaultSupported()) throw new PassError(ErrorCode.NOT_SUPPORTED, 'This browser can not keep the vault (no WebAssembly, IndexedDB or storage.session)');
}

function masterPassword(value, { create = false } = {}) {
  const password = typeof value === 'string' ? value : '';
  if (!password || password.length > MAX_MASTER_PASSWORD || (create && [...password].length < MASTER_MIN_LENGTH)) {
    throw new PassError(ErrorCode.INVALID_PARAMS, 'Bad master password');
  }
  return password;
}

function masterNames(value) {
  if (!Array.isArray(value)) return [];
  return value.filter((n) => typeof n === 'string' && n.trim() && n.length <= 320).map((n) => n.trim()).slice(0, 8);
}

/** The core's master password rule; the signed-in account's e-mail counts as known. Never logged or kept. */
async function masterPasswordRule(password, names) {
  const known = masterNames(names);
  const email = (await account.status().catch(() => null))?.email;
  if (typeof email === 'string' && email && !known.includes(email)) known.push(email);
  return local.checkMasterPassword(password, known);
}

// A vault file up to this size (a vault of 1000 logins is 1 to 2 MB).
const MAX_VAULT_FILE = 64 * 1024 * 1024;

/** Runs `fn`; on `locked`, brings up the desktop app's unlock prompt once and retries (unless `prompt` is false). */
async function withUnlock(fn, { prompt = true, forItem = null } = {}) {
  try {
    return await fn();
  } catch (err) {
    if (PassError.from(err).code !== ErrorCode.LOCKED) throw err;
    if (!(typeof prompt === 'function' ? await prompt() : prompt)) throw err;
    await agent('unlock', forParams(forItem));
    return fn();
  }
}

async function unlocksInPage() {
  try {
    const status = await agent('status');
    return Array.isArray(status.features) && status.features.includes('unlock.inline');
  } catch {
    return false;
  }
}

// An unlock started to fill one login tells the desktop app (`for`), so with "Confirm each fill" that
// unlock is that fill's check: one prompt, not two.
const UNLOCK_FOR_TTL_MS = 2 * 60_000;
const unlockFor = new Map(); // tabId -> { id, at }

function forParams(id) {
  return typeof id === 'string' && id && id.length <= 128 ? { for: id } : {};
}

function unlockForTab(tabId) {
  const pending = typeof tabId === 'number' ? unlockFor.get(tabId) : null;
  return pending && Date.now() - pending.at < UNLOCK_FOR_TTL_MS ? pending.id : null;
}

function unlockForPage(msg, sender) {
  if (forParams(msg?.for).for) return msg.for;
  if (typeof sender?.tab?.id === 'number') return unlockForTab(sender.tab.id);
  const form = unlockFormTab;
  return form && Date.now() - form.at < UNLOCK_FOR_TTL_MS ? unlockForTab(form.tabId) : null;
}

function promptFor(msg) {
  return { prompt: msg?.inline !== true };
}

const MAX_MASTER_PASSWORD = 1024;
const UNLOCK_ASK_TTL_MS = 60_000;
let unlockAsk = null;
let popupSearch = null;
let unlockFormTab = null;

async function unlockOptions() {
  // Both at once: Windows Hello starts one round trip sooner. An older app's error on `unlock.options` is
  // moot once `status` answers.
  const asked = agent('unlock.options');
  asked.catch(() => {});
  const status = await agent('status');
  const features = Array.isArray(status.features) ? status.features : [];
  const browser = features.includes('vault.browser') ? { browser: true } : {};
  if (!features.includes('unlock.inline')) return { inline: false, locked: !!status.locked, hello: false, hello_auto: false, hello_pending: false };
  if (!status.locked) return { inline: true, locked: false, hello: false, hello_auto: false, hello_pending: false, ...browser };
  const opts = await asked;
  const hello = opts?.hello === true;
  return { inline: true, locked: opts?.locked !== false, hello, hello_auto: hello && helloAutoAllowed(), hello_pending: !!helloPending, ...browser };
}

// One Windows Hello unlock at a time for the whole extension; callers join the one in progress. After the
// user declines it, it does not start on its own for HELLO_QUIET_MS and the master password form shows first.
const HELLO_QUIET_MS = 30_000;
let helloPending = null;
let helloDeclinedAt = 0;

function helloAutoAllowed() {
  return Date.now() - helloDeclinedAt >= HELLO_QUIET_MS;
}

function helloDeclined() {
  helloDeclinedAt = Date.now();
}

function helloUnlock(forItem = null) {
  if (!helloPending) {
    helloPending = unlockCall('unlock.hello', forParams(forItem)).then((res) => {
      unlockedHere();
      return res;
    }, (err) => {
      const code = PassError.from(err).code;
      if (code === ErrorCode.CANCELLED || code === ErrorCode.NOT_SUPPORTED) helloDeclined();
      throw err;
    }).finally(() => { helloPending = null; });
  }
  return helloPending;
}

/** "Use master password instead": calls off the pending `unlock.hello`; older apps lack `unlock.cancel`. */
async function helloCancel() {
  helloDeclined();
  try {
    return await unlockCall('unlock.cancel');
  } catch (err) {
    if (PassError.from(err).code === ErrorCode.NOT_SUPPORTED) return { cancelled: false };
    throw err;
  }
}

async function unlockCall(method, params = {}) {
  try {
    return await agent(method, params);
  } catch (err) {
    const e = PassError.from(err);
    if (e.code === ErrorCode.INVALID_PARAMS && /unknown method/i.test(e.message)) {
      throw new PassError(ErrorCode.NOT_SUPPORTED, 'unknown method', Reason.NEEDS_UPDATE);
    }
    throw e;
  }
}

/** The pages hear the unlock at once, without waiting for the agent's `lock_state` event. */
function unlockedHere() {
  unlockFor.clear();
  broadcastToActiveTabs({ type: 'lock_state', locked: false });
  refreshActiveBadges();
  recheckSaves();
}

/**
 * The master password is never typed into the page: the popup opens with its unlock form
 * (`action.openPopup`, Chrome 127+), or where that isn't allowed (Firefox outside a toolbar click) a small window.
 */
async function openUnlockForm(tab, { query = 'unlock=1' } = {}) {
  unlockAsk = { tabId: tab?.id, at: Date.now() };
  unlockFormTab = { tabId: tab?.id, at: Date.now() };
  if (typeof ext.action?.openPopup === 'function') {
    try {
      await ext.action.openPopup(typeof tab?.windowId === 'number' ? { windowId: tab.windowId } : undefined);
      return { opened: 'popup' };
    } catch { /* not allowed here: a window instead */ }
  }
  unlockAsk = null;
  const size = { width: 360, height: 420 };
  let place = {};
  try {
    const w = await ext.windows.get(tab.windowId);
    place = { left: Math.round(w.left + Math.max(0, (w.width - size.width) / 2)), top: Math.round(w.top + Math.max(0, Math.min(120, (w.height - size.height) / 2))) };
  } catch { /* the browser places it */ }
  await ext.windows.create({ url: ext.runtime.getURL(`src/popup/popup.html?${query}`), type: 'popup', focused: true, ...size, ...place });
  return { opened: 'window' };
}

function onLockState(data) {
  const locked = !!data?.locked;
  broadcastToActiveTabs({ type: 'lock_state', locked });
  ext.runtime.sendMessage({ type: 'lock_state', locked }).catch(() => {});
  refreshActiveBadges();
  if (locked) {
    for (const s of tabs.values()) s.filled = null;
  } else {
    unlockFor.clear();
    recheckSaves();
  }
}

client.on('lock_state', onLockState);

const clipboardClearer = createClipboardClearer({ ext, clearNow: defaultClearNow(ext) });

// Registered at top level so the alarm wakes a suspended service worker / event page.
ext.alarms?.onAlarm.addListener((alarm) => {
  clipboardClearer.onAlarm(alarm).catch((err) => console.warn('[Passyble] clipboard clear failed', err));
  if (alarm?.name === TICK_ALARM) {
    inBrowserMode().then((on) => (on ? local.tick() : null)).catch((err) => console.warn('[Passyble] vault timer failed', err));
  }
  versionCheck.onAlarm(alarm);
  if (alarm?.name === VERSIONS_ALARM) account.syncWithApp().catch(() => {});
  if (alarm?.name === CLOUD_SYNC_ALARM) cloudPull('alarm');
});

// The service worker hears the network come back: the shared vaults are checked at once.
globalThis.addEventListener?.('online', () => cloudPull('online'));

async function clipboardCopied(msg) {
  return { scheduled: await clipboardClearer.schedule(msg.value) };
}

// Windows Hello and the app's prompt take the focus, which closes the popup: the outcome of a copy it
// asked for goes to the tab's page or the next popup instead. Never a secret, only the notice text.
const POPUP_FEEDBACK_TTL_MS = 2 * 60_000;
let popupFeedback = null;

function takePopupFeedback() {
  const pending = popupFeedback;
  popupFeedback = null;
  return pending && Date.now() - pending.at < POPUP_FEEDBACK_TTL_MS ? pending.text : null;
}

/** Whether the sending popup still has its port open. Chrome names the document; elsewhere any open popup counts. */
function popupStillOpen(sender) {
  const doc = sender?.documentId;
  const ports = [...popupPorts];
  if (doc && ports.some((p) => p.sender?.documentId)) return ports.some((p) => p.sender?.documentId === doc);
  return ports.length > 0;
}

async function tellAfterPopup(sender, tabId, text) {
  if (!text || popupStillOpen(sender)) return;
  const id = Number(tabId);
  if (Number.isInteger(id) && id >= 0) {
    const res = await Promise.resolve().then(() => sendToFrame(id, { type: 'cmd.notice', text }, 0)).catch(() => null);
    if (res?.ok) return;
  }
  popupFeedback = { text, at: Date.now() };
}

async function copyWithFeedback(msg, sender, run, { done, notDone }) {
  let res;
  try {
    res = await run();
  } catch (err) {
    const e = PassError.from(err);
    const text = e.code === ErrorCode.CANCELLED ? notDone : friendlyError(e);
    tellAfterPopup(sender, msg.tabId, text).catch(() => {});
    throw err;
  }
  tellAfterPopup(sender, msg.tabId, done(res)).catch(() => {});
  return res;
}

const COPY_NOTICE = {
  username: { done: 'popupCopiedUsername', notDone: 'popupNotCopiedUsername' },
  password: { done: 'popupCopiedByAppPassword', notDone: 'popupNotCopiedPassword' },
  totp: { done: 'popupCopiedByAppOtp', notDone: 'popupNotCopiedOtp' },
  number: { done: 'popupCopiedCardNumberClears', notDone: 'popupNotCopiedCardNumber' },
  security_code: { done: 'popupCopiedSecurityCodeClears', notDone: 'popupNotCopiedSecurityCode' },
};

const COPY_AFTER_UNLOCK = new Set(['popup.copy-item', 'popup.card-copy']);

/** Finishes the fill or copy (`then.fill`, `then.copy`) a popup asked for before an unlock that may have closed it. */
async function finishAfterUnlock(msg, sender, res) {
  const fill = msg.then?.fill;
  if (fill) {
    const done = await sendToFillFrame(Number(fill.tabId), { type: 'cmd.fill-item', id: itemId(fill.id) }).catch(() => null);
    return { ...res, filled: !!done && done.ok !== false };
  }
  const copy = msg.then?.copy;
  if (copy && typeof copy === 'object' && COPY_AFTER_UNLOCK.has(copy.type)) {
    try {
      return { ...res, copy: { result: (await pageHandlers[copy.type]({ ...copy, inline: true }, sender)) ?? null } };
    } catch (err) {
      return { ...res, copy: { error: PassError.from(err).toJSON() } };
    }
  }
  return res;
}

function copyNotDone(msg, sender) {
  const copy = msg.then?.copy;
  const notice = COPY_AFTER_UNLOCK.has(copy?.type) ? COPY_NOTICE[copy.field] : null;
  if (notice) tellAfterPopup(sender, copy.tabId, t(notice.notDone)).catch(() => {});
}

/** @type {Map<number, {fill?: any, save?: any, identifier?: any, focus?: any, navAt?: number, otpFieldAt?: number, draft?: any, crossFill?: any}>} */
const tabs = new Map();

function tabState(tabId) {
  let s = tabs.get(tabId);
  if (!s) { s = {}; tabs.set(tabId, s); }
  return s;
}

ext.tabs.onRemoved.addListener((tabId) => tabs.delete(tabId));

const EXTENSION_ORIGIN = ext.runtime.getURL('');

function isExtensionPage(sender) {
  return typeof sender.url === 'string' && sender.url.startsWith(EXTENSION_ORIGIN);
}

function senderUrl(sender) {
  // A sub-frame's own URL only: the tab URL belongs to the top frame (another origin, maybe).
  return sender.url || ((sender.frameId ?? 0) === 0 ? sender.tab?.url : '') || '';
}

function safeOrigin(url) {
  try { return new URL(url).origin; } catch { return 'null'; }
}

/**
 * The sender frame's origin as the browser reports it; "null" for an opaque (sandboxed) origin, which must
 * not be treated as the site its URL names. Firefox has no `sender.origin`, and its content scripts skip
 * opaque-origin documents.
 */
function senderOrigin(sender) {
  if (typeof sender.origin === 'string' && sender.origin) return sender.origin;
  return safeOrigin(senderUrl(sender));
}

/** The sender frame's URL, or '' (refused) when the browser says its origin differs (opaque / sandboxed). */
function frameUrl(sender) {
  const url = senderUrl(sender);
  if (typeof sender.origin === 'string' && sender.origin && sender.origin !== safeOrigin(url)) return '';
  return url;
}

function isWebUrl(url) {
  return /^https?:\/\//i.test(url || '');
}

function requireWebUrl(url) {
  if (!isWebUrl(url)) throw new PassError(ErrorCode.NOT_FOUND, 'Passyble only works on http(s) pages', Reason.WEB_PAGES_ONLY);
  return url;
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

// `status.features`, cached briefly: content scripts ask before showing a card or address menu.
const FEATURES_TTL_MS = 30_000;
let featuresCache = null;

async function agentFeatures({ automatic = false } = {}) {
  if (featuresCache && Date.now() - featuresCache.at < FEATURES_TTL_MS) return featuresCache.features;
  const status = await agent('status', {}, { automatic });
  const features = Array.isArray(status?.features) ? status.features : [];
  featuresCache = { at: Date.now(), features };
  return features;
}

async function formFeatures({ automatic = false } = {}) {
  if (!(await getSettings()).formFill) return { cards: false, identities: false };
  const features = await agentFeatures({ automatic });
  return { cards: features.includes('cards'), identities: features.includes('identities') };
}

/** The page a card or address goes to: https (or http on this device) only, as the agent checks too. */
function requireSecureFormUrl(url) {
  if (!isSecureFormUrl(url)) {
    throw new PassError(ErrorCode.NEEDS_SECURE_PAGE, t('bgFormsNeedHttps'));
  }
  return url;
}

async function formUrl(sender) {
  if (!(await getSettings()).formFill) {
    throw new PassError(ErrorCode.NOT_SUPPORTED, 'Cards and addresses are turned off in the Passyble settings', Reason.FORMS_OFF);
  }
  return requireSecureFormUrl(frameUrl(sender));
}

/**
 * The desktop app's local check of a password about to be saved (`password.check`): only codes come back,
 * `null` when it can't answer. Not cached, not logged, never asks to unlock.
 */
async function passwordCheck({ password, username = '', url = '', id = null, title = '' }) {
  if (typeof password !== 'string' || !password || password.length > FIELD_LIMITS.password) return null;
  try {
    const params = { password };
    if (typeof username === 'string' && username) params.username = username.slice(0, FIELD_LIMITS.username);
    if (isWebUrl(url)) params.url = url;
    if (typeof id === 'string' && id && id.length <= 128) params.id = id;
    if (typeof title === 'string' && title) params.title = title.slice(0, FIELD_LIMITS.title);
    return publicCheck(await agent('password.check', params, { automatic: true }));
  } catch {
    return null;
  }
}

/** Only the fields the pages use, with their types checked. */
function publicCheck(res) {
  if (!res || typeof res !== 'object' || !Array.isArray(res.issues)) return null;
  const issues = res.issues
    .filter((i) => i && typeof i.code === 'string' && /^[a-z_]{1,32}$/.test(i.code))
    .slice(0, 16)
    .map((i) => {
      const out = { code: i.code, severity: ['high', 'medium', 'low'].includes(i.severity) ? i.severity : 'medium' };
      if (Number.isInteger(i.count) && i.count > 0) out.count = i.count;
      if (Number.isInteger(i.min_length) && i.min_length > 0) out.min_length = i.min_length;
      return out;
    });
  const score = Number.isInteger(res.score) ? Math.min(Math.max(res.score, 0), 4) : 0;
  return { score, label: typeof res.label === 'string' ? res.label : '', issues, vault_checked: res.vault_checked === true };
}

function reportOtpOutcome(url, outcome) {
  if (!isWebUrl(url)) return Promise.resolve();
  return agent('otp.outcome', { url, outcome }, { automatic: true }).catch(() => {});
}

function recordFill(tabId, itemId, patch = {}) {
  const s = tabState(tabId);
  if (!s.fill || s.fill.itemId !== itemId || Date.now() - s.fill.at > PENDING_OTP_WINDOW_MS) {
    s.fill = { itemId, at: Date.now(), otpFilledInline: false, consumed: false };
  }
  Object.assign(s.fill, patch);
}

/** Keeps what a fill put into this frame (the password only as a hash), so a submit with other values can offer an update. */
async function rememberFilled(sender, itemId, result, cross) {
  const url = frameUrl(sender);
  const origin = safeOrigin(url);
  if (!isWebUrl(url) || origin === 'null' || !result || typeof result !== 'object') return;
  const s = tabState(sender.tab.id);
  s.filled = await filledLogin({ itemId, origin, frameId: sender.frameId ?? 0, result, cross });
}

const contentHandlers = {
  async 'logins.find'(msg, sender) {
    return agent('logins.find', { url: requireWebUrl(frameUrl(sender)) }, { automatic: !!msg.automatic });
  },

  async 'logins.fill'(msg, sender) {
    const url = requireWebUrl(frameUrl(sender));
    const result = await withUnlock(() => agent('logins.fill', { url, id: String(msg.id) }), { forItem: String(msg.id) });
    // A fill-only login's password goes into the page only; the save banner's Edit never shows it.
    recordFill(sender.tab.id, String(msg.id), { skipped: false, noReveal: result?.vault?.can_reveal === false });
    await rememberFilled(sender, String(msg.id), result, false);
    return result;
  },

  async 'fill.done'(msg, sender) {
    if (msg.otp) {
      recordFill(sender.tab.id, String(msg.id), { otpFilledInline: true });
      reportOtpOutcome(frameUrl(sender), 'used');
    }
    return {};
  },

  async 'totp.get'(msg, sender) {
    const params = { url: requireWebUrl(frameUrl(sender)) };
    // A picked login unlocks first; the pending code (no id) and `automatic` requests never ask.
    if (msg.id) params.id = String(msg.id);
    if (msg.id && msg.automatic !== true) return withUnlock(() => agent('totp.get', params), { forItem: params.id });
    return agent('totp.get', params);
  },

  async 'totp.popup'(msg, sender) {
    return withUnlock(() => agent('totp.popup', { url: requireWebUrl(frameUrl(sender)), id: String(msg.id) }), { forItem: String(msg.id) });
  },

  /**
   * The OTP toast's Copy: the desktop app copies the code itself, out of clipboard history. On
   * `not_supported` the toast copies the code it shows.
   */
  async 'totp.copy'(msg, sender) {
    const url = requireWebUrl(frameUrl(sender));
    const id = itemId(msg.id);
    return callNew(() => withUnlock(() => agent('logins.copy', { id, field: 'totp', url }), { forItem: id }));
  },

  async 'otp.context'(msg, sender) {
    const url = frameUrl(sender);
    const s = tabState(sender.tab.id);
    if (sender.frameId === 0 && msg.navigation) {
      s.navAt = Date.now();
      s.otpFieldAt = 0;
    }
    const settings = await getSettings();
    const base = { pending: null, offer: false, autoFillOtp: settings.autoFillOtp,
      otpFieldElsewhere: !!s.otpFieldAt && s.otpFieldAt >= (s.navAt || 0) };
    if (!isWebUrl(url)) return base;
    let found;
    try {
      found = await agent('logins.find', { url }, { automatic: true });
    } catch {
      return base;
    }
    const pending = found.pending_otp || null;
    const record = s.fill || null;
    const now = Date.now();
    const items = found.items || [];
    // `quiet`: the site usually skips 2FA or skipped it now, so only a code field gets the code, never the toast.
    if (pending) {
      return { ...base, pending, items, late: false,
        offer: shouldOfferPendingOtp({ pending, record, now }),
        quiet: !!pending.skips_2fa || (record?.itemId === pending.id && !!record.skipped) };
    }
    // After the agent's window, the code of the login filled here is still offered, to a code field only.
    const late = latePendingOtp({ record, items, now });
    if (late) return { ...base, pending: late, items, offer: true, late: true, quiet: true };
    return { ...base, pending: null, items, offer: false };
  },

  async 'otp.field-seen'(msg, sender) {
    tabState(sender.tab.id).otpFieldAt = Date.now();
    return {};
  },

  async 'otp.consumed'(msg, sender) {
    recordFill(sender.tab.id, String(msg.id), { consumed: true });
    reportOtpOutcome(frameUrl(sender), 'used');
    return {};
  },

  async 'otp.outcome'(msg, sender) {
    if (msg.outcome !== 'asked' && msg.outcome !== 'skipped') throw badParams('Bad outcome');
    const s = tabState(sender.tab.id);
    if (msg.outcome === 'skipped' && (sender.frameId ?? 0) === 0 && s.fill) s.fill.skipped = true;
    await reportOtpOutcome(frameUrl(sender), msg.outcome);
    return {};
  },

  async unlock(msg, sender) {
    return agent('unlock', forParams(unlockForTab(sender.tab.id)));
  },

  async 'unlock.options'(msg, sender) {
    const id = forParams(msg.for).for;
    if (id) unlockFor.set(sender.tab.id, { id, at: Date.now() });
    else unlockFor.delete(sender.tab.id);
    return unlockOptions();
  },

  async 'unlock.hello'(msg, sender) {
    return helloUnlock(unlockForTab(sender.tab.id));
  },

  async 'unlock.cancel'() {
    return helloCancel();
  },

  async 'unlock.open-form'(msg, sender) {
    return openUnlockForm(sender.tab);
  },

  /**
   * `automatic`: the inline menu opened on its own. An agent from before `symbols` ignores `symbols: false`:
   * its answer is replaced by one generated here (`local: true`, so the browser's clipboard copies it).
   */
  async generate(msg) {
    const params = {};
    if (Number.isInteger(msg.length) && msg.length >= 8 && msg.length <= 128) params.length = msg.length;
    if (msg.symbols === false) params.symbols = false;
    const res = await agent('generate', params, { automatic: !!msg.automatic });
    if (params.symbols === false && !isPlainPassword(res?.password)) {
      return { password: generatePassword({ length: params.length ?? DEFAULT_LENGTH, symbols: false }), local: true };
    }
    return res;
  },

  /** The desktop app copies a password it just generated, out of clipboard history; on error the callout copies it. */
  async 'generate.copy'(msg) {
    if (typeof msg.password !== 'string' || !msg.password || msg.password.length > 128) {
      throw new PassError(ErrorCode.INVALID_PARAMS, 'password must be a generated password');
    }
    return callNew(() => agent('generate.copy', { password: msg.password }));
  },

  async focus(msg, sender) {
    tabState(sender.tab.id).focus = { frameId: sender.frameId ?? 0, at: Date.now() };
    return {};
  },

  /** Shows the generate items in the context menu only over a password field; the frame checks its target again on click. */
  async 'menu.target'(msg) {
    setGenerateMenuVisible(msg.password === true);
    await setUsernameMenusVisible(msg.username === true);
    return {};
  },

  async 'generate.username'() {
    return callNew(() => agent('generate.username', {}));
  },

  /**
   * Only right after "Generate e-mail alias" was clicked in this frame: each alias is an account change at
   * the service, so a page can't make the content script create them.
   */
  async 'generate.email'(msg, sender) {
    const click = aliasClick;
    aliasClick = null;
    if (!click || click.tabId !== sender.tab?.id || click.frameId !== (sender.frameId ?? 0) || Date.now() - click.at > ALIAS_CLICK_TTL_MS) {
      throw new PassError(ErrorCode.INVALID_PARAMS, 'no alias requested', Reason.BAD_REQUEST);
    }
    const url = frameUrl(sender);
    if (!isWebUrl(url)) throw new PassError(ErrorCode.INVALID_PARAMS, 'not a web page', Reason.WEB_PAGES_ONLY);
    const params = { kind: 'alias', url };
    if ((await getSettings()).mentionWebsite) params.website = true;
    return callNew(() => withUnlock(() => agent('generate.email', params)));
  },

  async 'save.capture'(msg, sender) {
    const url = frameUrl(sender);
    if (!isWebUrl(url)) return {};
    const s = tabState(sender.tab.id);
    const username = typeof msg.username === 'string' ? msg.username.trim().slice(0, 512) : '';
    const password = typeof msg.password === 'string' ? msg.password.slice(0, 1024) : '';
    if (!password) {
      // identifier-first sign-in: remember the username for the password step
      if (username) s.identifier = { username, origin: safeOrigin(url), at: Date.now() };
      return {};
    }
    let user = username;
    if (!user && s.identifier && Date.now() - s.identifier.at < IDENTIFIER_TTL_MS) user = s.identifier.username;
    s.save = {
      url, username: user, password, kind: msg.kind === 'change' || msg.kind === 'signup' ? msg.kind : 'login',
      at: Date.now(), shown: false, token: crypto.randomUUID(),
      filledItemId: s.fill && Date.now() - s.fill.at < 10 * 60_000 ? s.fill.itemId : null,
      canonical: sender.frameId === 0 ? canonicalOf(msg.canonical, url) : null,
    };
    // Submitted right after filling a fill-only login: its password may be what was captured.
    s.save.noReveal = !!(s.save.filledItemId && s.fill?.noReveal);
    const entry = s.save;
    entry.generated = !!s.generated && (await s.generated.matches(safeOrigin(url), password));
    if (s.save !== entry) return {}; // a newer submit meanwhile
    const draft = activeDraft(s, url);
    if (draft) {
      s.save.draftId = draft.id;
      if (s.save.kind === 'change') {
        // The changed login gets the banner; the draft (kept in case the change failed) goes once that's saved.
        s.save.ignoreId = draft.id;
      } else {
        // Sign-up: the draft is this login and is updated in place. No unlock prompt on submit: the banner's Save unlocks.
        s.save.draftWork = updateDraft(url, draft, user, password);
      }
    }
    // Never keep a typed password around longer than the banner could need it.
    const purge = setTimeout(() => { if (s.save === entry) s.save = null; }, 5 * SAVE_TTL_MS);
    purge?.unref?.(); // Node (tests) only; browsers return a number
    return {};
  },

  /** Whether the top frame shows the save / update banner. Never returns the password (the edit frame asks: `save.edit-get`). */
  async 'save.query'(msg, sender) {
    if (sender.frameId !== 0) return null;
    const s = tabState(sender.tab.id);
    if (msg.recheck === true) return recheckSave(s, sender);
    const save = s.save;
    if (!save || save.shown || Date.now() - save.at > SAVE_TTL_MS) return null;
    // A sign-in form still on screen after a plain login usually means the password was wrong. After a
    // sign-up or password change, sites often redirect to their login page: offer the banner there.
    if (msg.loginFormVisible && save.kind === 'login') return null;
    if (!(await getSettings()).saveBanner) { s.save = null; return null; }
    const sameOrigin = safeOrigin(frameUrl(sender)) === safeOrigin(save.url);
    if (msg.sameDocument && !sameOrigin) return null;
    save.shown = true;
    const offer = liveCrossOffer(s);
    const filled = takeFilled(s, save, offer);
    const changes = filled ? await changesOf(filled, save) : null;
    if (offer && !changes && await crossSubmitted(offer, save)) {
      if (s.save === save) s.save = null;
      if (offer.answered) return null;
      offer.shown = true;
      return { cross: crossInfo(offer) };
    }
    if (save.draftWork) {
      if (await save.draftWork) { s.save = null; return null; }
      save.draftWork = null;
    }
    // A password Passyble generated on a "never save" site was the user's choice: saved all the same.
    if (!save.generated && (await isNeverSave(save.url))) { s.save = null; return null; }
    let decided;
    try {
      decided = await saveDecision(save);
    } catch (err) {
      if (PassError.from(err).code !== ErrorCode.LOCKED) { s.save = null; return null; }
      // Locked: the agent can't compare passwords. If the list says it may be saved already, wait for the
      // unlock (recheckSave); otherwise offer Save, which unlocks and decides then.
      if (await mayBeSaved(save)) { save.shown = false; save.held = true; return null; }
      decided = null;
    }
    if (changes && changedPlan({ decided, filledId: filled.itemId, changes }) === 'card') {
      const card = await changedCard(save, filled, changes, decided, filled.cross ? offer : null);
      if (card) return { changed: card };
    }
    if (decided?.action === 'none') {
      // Already saved (another login has this password): a draft of it is a duplicate.
      if (save.ignoreId) dropDraft(s, save.url, save.ignoreId);
      s.save = null;
      return null;
    }
    if (save.generated) {
      const done = await autoSave(s, save, decided);
      if (done) return done;
    }
    return bannerInfo(save, decided);
  },

  /** The banner's password check again (only codes come back), by its one-time token. Older banners sent the edited values. */
  async 'save.check'(msg, sender) {
    if (sender.frameId !== 0) return null;
    const save = tabState(sender.tab.id).save;
    if (!save || msg.token !== save.token || Date.now() - save.at > 5 * SAVE_TTL_MS) return null;
    return checkOf(save, sentValues(msg) ? editedValues(msg, save) : save.edits || {});
  },

  async 'save.commit'(msg, sender) {
    const s = tabState(sender.tab.id);
    const save = s.save;
    if (!save || msg.token !== save.token || Date.now() - save.at > 5 * SAVE_TTL_MS) {
      throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
    }
    const edited = sentValues(msg) ? editedValues(msg, save) : save.edits || { changed: false };
    s.save = null; // drop the password from memory whatever happens next
    const target = { ...save, ...edited };
    const params = { url: save.url, username: target.username, password: target.password };
    if (save.canonical) params.canonical_url = save.canonical;
    const vault = chosenVault(save.vaultChoice, msg.vault);
    let action = save.action;
    if (!save.decided || edited.changed) {
      const decided = await withUnlock(() => saveDecision(target));
      action = decided.action;
      if (decided.action === 'none') {
        if (save.ignoreId) dropDraft(s, save.url, save.ignoreId);
        return { id: decided.id ?? null, unchanged: true, action };
      }
      if ((decided.action === 'update_password' || decided.action === 'update_username') && decided.id) params.id = decided.id;
      if (decided.action === 'update_username') params.update = 'username';
    } else if (save.id) {
      params.id = save.id;
      if (save.action === 'update_username') params.update = 'username';
    }
    if (vault && !params.id) params.vault = vault;
    const res = await withUnlock(() => agent('logins.save', params));
    // A change saves to its login, so its draft copy goes, unless the draft is that login now.
    if (save.ignoreId && res?.id != null && String(res.id) === save.ignoreId) keepDraft(s, save.url, save.ignoreId);
    else if (save.ignoreId) dropDraft(s, save.url, save.ignoreId);
    refreshActiveBadges();
    return { ...res, action };
  },

  /** Undo on an auto-saved submit's notice: a new login goes to the trash, an updated one is restored (`logins.restore`). */
  async 'save.undo'(msg, sender) {
    const s = tabState(sender.tab.id);
    const done = s.autoSaved;
    if (sender.frameId !== 0 || !done || typeof msg.token !== 'string' || msg.token !== done.token ||
        Date.now() - done.at > AUTO_UNDO_MS) {
      throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to undo', Reason.NOTHING_TO_UNDO);
    }
    s.autoSaved = null;
    if (done.kind === 'updated') {
      // No unlock prompt: locking drops the agent's copy, so an unlock couldn't bring it back.
      await agent('logins.restore', { url: done.url, id: done.id });
      if (done.draftId) await agent('logins.restore', { url: done.url, id: done.draftId }).catch(() => {});
    } else {
      await editCall('logins.delete', { url: done.url, id: done.id });
    }
    refreshActiveBadges();
    return { undone: done.kind };
  },

  /**
   * Saves a password Passyble just generated and filled as a login of the frame's site, so it is never
   * lost if the sign-up fails half-way. Later calls in the same tab and site update it.
   */
  async 'draft.save'(msg, sender) {
    const url = requireWebUrl(frameUrl(sender));
    const password = typeof msg.password === 'string' ? msg.password : '';
    if (!password || password.length > FIELD_LIMITS.password) throw badParams('Bad password');
    const username = typeof msg.username === 'string' ? msg.username.trim().slice(0, FIELD_LIMITS.username) : '';
    const kind = msg.kind === 'change' ? 'change' : 'signup';
    const s = tabState(sender.tab.id);
    await rememberGenerated(s, url, password);
    const draft = activeDraft(s, url);
    if (draft) {
      const fields = { password };
      if (username) fields.username = username;
      try {
        const res = await editCall('logins.update', { url, id: draft.id, fields });
        draft.at = Date.now();
        return { id: draft.id, created: false, title: res?.title ?? null };
      } catch (err) {
        const code = PassError.from(err).code;
        if (code !== ErrorCode.NOT_FOUND && code !== ErrorCode.URL_MISMATCH) throw err;
        s.draft = null;
      }
    }
    const fields = { password, username };
    if (kind === 'change') fields.title = t('bgNewPasswordTitle', hostOf(url).replace(/^www\./, ''));
    const res = await editCall('logins.create', { url, fields });
    s.draft = { id: String(res.id), origin: safeOrigin(url), kind, at: Date.now() };
    refreshActiveBadges();
    return { id: s.draft.id, created: true, title: res?.title ?? null };
  },

  /** A generated password was filled here: its submit is saved without asking. Kept as a hash, in memory, for 30 minutes. */
  async 'generate.filled'(msg, sender) {
    const url = requireWebUrl(frameUrl(sender));
    const password = typeof msg.password === 'string' ? msg.password : '';
    if (!password || password.length > FIELD_LIMITS.password) throw badParams('Bad password');
    await rememberGenerated(tabState(sender.tab.id), url, password);
    if (typeof msg.symbols === 'boolean') await rememberSymbols(url, msg.symbols).catch(() => {});
    if (msg.options && typeof msg.options === 'object' && !Array.isArray(msg.options)) await rememberOptions(msg.options).catch(() => {});
    return {};
  },

  async 'draft.undo'(msg, sender) {
    const url = requireWebUrl(frameUrl(sender));
    const s = tabState(sender.tab.id);
    const draft = activeDraft(s, url);
    if (!draft || (msg.id !== undefined && String(msg.id) !== draft.id)) throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to undo', Reason.NOTHING_TO_UNDO);
    await editCall('logins.delete', { url, id: draft.id });
    s.draft = null;
    refreshActiveBadges();
    return { deleted: true };
  },

  /**
   * A login of another site, only after the popup asked for exactly this login in this tab moments ago
   * (`popup.fill-cross`); the agent asks the user before it releases it.
   */
  async 'logins.fill_cross'(msg, sender) {
    const s = tabState(sender.tab.id);
    let pending;
    if (msg.similar === true) {
      const offer = s.similar;
      const hit = offer && offer.frameId === (sender.frameId ?? 0) && offer.origin === safeOrigin(frameUrl(sender)) &&
        Date.now() - offer.at < SIMILAR_TTL_MS ? offer.items.get(String(msg.id)) : null;
      if (!hit) throw new PassError(ErrorCode.NOT_FOUND, 'Pick the login in the Passyble menu first', Reason.PICK_IN_POPUP);
      pending = { id: String(msg.id), at: Date.now(), title: hit.title, domain: hit.domain, lookalike: '' };
    } else {
      pending = s.crossFill;
      s.crossFill = null; // one fill per request
      if (!pending || pending.id !== String(msg.id) || Date.now() - pending.at > CROSS_FILL_TTL_MS) {
        throw new PassError(ErrorCode.NOT_FOUND, 'Pick the login in the Passyble popup first', Reason.PICK_IN_POPUP);
      }
    }
    const url = requireWebUrl(frameUrl(sender));
    const fillCross = async () => {
      if (!(await inBrowserMode())) return agent('logins.fill_cross', { url, id: pending.id });
      await requireUnlocked();
      await askUser('cross', { title: pending.title, domain: pending.domain, lookalike: pending.lookalike || '', url });
      return agent('logins.fill_cross', { url, id: pending.id }, { confirmed: true });
    };
    const res = await callNew(() => withUnlock(fillCross, { forItem: pending.id }));
    if (!res?.cross) recordFill(sender.tab.id, pending.id, { skipped: false });
    else await offerCrossLink(sender, pending, res, url);
    await rememberFilled(sender, pending.id, res, res?.cross === true);
    // The agent's token for "Add <site> to this login" stays here; the page's frame never sees it.
    if (res && typeof res === 'object' && 'add_url_token' in res) {
      const { add_url_token: _token, ...rest } = res;
      return rest;
    }
    return res;
  },

  /** Logins of similar sites for the in-page menu (never a lookalike); a pick is a cross fill offered to this frame only. */
  async 'menu.similar'(msg, sender) {
    const url = frameUrl(sender);
    const none = { items: [], vaults: [], search: false, name: '' };
    if (!isWebUrl(url)) return none;
    let features;
    try { features = await agentFeatures(); } catch { return none; }
    const search = features.includes('logins.search');
    const s = tabState(sender.tab.id);
    s.similar = null;
    if (!features.includes('logins.similar')) return { ...none, search };
    let res;
    try {
      res = await agent('logins.similar', { url, limit: SIMILAR_LIMIT });
    } catch {
      return { ...none, search };
    }
    const items = (Array.isArray(res?.items) ? res.items : [])
      .filter((it) => it && typeof it.id === 'string' && it.id && !it.lookalike)
      .slice(0, SIMILAR_LIMIT)
      .map((it) => ({ id: it.id, title: label(it.title), username: label(it.username), domain: label(it.domain),
        has_totp: it.has_totp === true, vault_id: typeof it.vault_id === 'string' ? it.vault_id : null }));
    const name = label(res?.name).slice(0, 128);
    s.similar = { frameId: sender.frameId ?? 0, origin: safeOrigin(url), name, at: Date.now(),
      items: new Map(items.map((it) => [it.id, { title: it.title, domain: it.domain }])) };
    return { items, vaults: Array.isArray(res?.vaults) ? res.vaults : [], locked: res?.locked === true, search, name };
  },

  async 'menu.search'(msg, sender) {
    const url = frameUrl(sender);
    const s = tabState(sender.tab.id);
    const name = s.similar && Date.now() - s.similar.at < SIMILAR_TTL_MS ? s.similar.name : '';
    const query = (name || hostOf(url).replace(/^www\./, '')).slice(0, 128);
    popupSearch = query.length >= 2 ? { tabId: sender.tab.id, query, at: Date.now() } : null;
    if (typeof ext.action?.openPopup !== 'function') return { opened: false };
    try {
      await ext.action.openPopup(typeof sender.tab?.windowId === 'number' ? { windowId: sender.tab.windowId } : undefined);
      return { opened: true };
    } catch {
      return { opened: false };
    }
  },

  /** "Use this login on <site> too?" after a cross fill, shown once per offer. No secret in the answer. */
  async 'cross.query'(msg, sender) {
    if ((sender.frameId ?? 0) !== 0) return null;
    const offer = liveCrossOffer(tabState(sender.tab.id));
    if (!offer || offer.answered || offer.shown || !(await getSettings()).saveBanner) return null;
    offer.shown = true;
    return crossInfo(offer);
  },

  async 'cross.add'(msg, sender) {
    const offer = crossOfferFor(sender, msg);
    const token = offer.agentToken;
    if (!token) throw new PassError(ErrorCode.NOT_SUPPORTED, 'unknown method', Reason.NEEDS_UPDATE);
    offer.agentToken = ''; // one try: the agent uses it up either way
    const res = await callNew(() => withUnlock(() => agent('logins.add_url', { id: offer.id, url: offer.url, token })));
    offer.answered = 'added';
    forgetCrossSecrets(offer);
    refreshActiveBadges();
    return { added: res?.added !== false, title: typeof res?.title === 'string' ? res.title : offer.title };
  },

  async 'cross.copy'(msg, sender) {
    const offer = crossOfferFor(sender, msg);
    if (!offer.password) throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
    const params = { url: offer.url, username: offer.username, password: offer.password };
    const res = await withUnlock(() => agent('logins.save', params));
    offer.answered = 'copied';
    forgetCrossSecrets(offer);
    refreshActiveBadges();
    return { id: res?.id ?? null, unchanged: res?.unchanged === true };
  },

  async 'cross.dismiss'(msg, sender) {
    const offer = liveCrossOffer(tabState(sender.tab.id));
    if ((sender.frameId ?? 0) === 0 && offer && typeof msg.token === 'string' && msg.token === offer.token) {
      offer.answered ||= 'dismissed';
      forgetCrossSecrets(offer);
    }
    return {};
  },

  /**
   * "Update login" on "Update this login?" by the card's one-time token. A cross-filled login gets the page
   * added first (`logins.add_url`), so it can be changed from it. The captured password is dropped first.
   */
  async 'changed.update'(msg, sender) {
    const { s, save, changed } = changedFor(sender, msg);
    s.save = null;
    if (!changed.canUpdate) throw new PassError(ErrorCode.READ_ONLY, "This login is in a vault you can't change");
    const fields = {};
    if (changed.username) fields.username = changed.username;
    if (changed.password) fields.password = save.password;
    const offer = changed.offer;
    if (offer) {
      const token = offer.agentToken;
      offer.agentToken = ''; // one try: the agent uses it up either way
      offer.answered = 'added';
      forgetCrossSecrets(offer);
      if (!token) throw new PassError(ErrorCode.NOT_SUPPORTED, 'unknown method', Reason.NEEDS_UPDATE);
      await callNew(() => withUnlock(() => agent('logins.add_url', { id: changed.id, url: offer.url, token })));
    }
    const res = await editCall('logins.update', { url: save.url, id: changed.id, fields }, { forItem: changed.id });
    refreshActiveBadges();
    return { updated: true, title: typeof res?.title === 'string' ? res.title : changed.title };
  },

  /** "Save as new login" on that card; never with the password of a fill-only login nobody changed. */
  async 'changed.save'(msg, sender) {
    const { s, save, changed } = changedFor(sender, msg);
    s.save = null;
    if (!changed.canCopy) throw new PassError(ErrorCode.FILL_ONLY, 'This login can be filled but not shown or copied');
    if (changed.offer) {
      changed.offer.answered = 'copied';
      forgetCrossSecrets(changed.offer);
    }
    const params = { url: save.url, username: save.username, password: save.password };
    if (save.canonical) params.canonical_url = save.canonical;
    const res = await withUnlock(() => agent('logins.save', params));
    refreshActiveBadges();
    return { id: res?.id ?? null, unchanged: res?.unchanged === true };
  },

  async 'changed.dismiss'(msg, sender) {
    const s = tabState(sender.tab.id);
    const save = s.save;
    if ((sender.frameId ?? 0) !== 0 || !save?.changed || typeof msg.token !== 'string' || msg.token !== save.token) return {};
    s.save = null;
    if (save.changed.offer) {
      save.changed.offer.answered ||= 'dismissed';
      forgetCrossSecrets(save.changed.offer);
    }
    return {};
  },

  /** "Never for this site": stores the browser-reported URL of the submitting frame, never what the page sends. */
  async 'save.never'(msg, sender) {
    if (sender.frameId !== 0) throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
    const s = tabState(sender.tab.id);
    const save = s.save;
    if (!save || msg.token !== save.token) throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
    const site = await addNeverSave(save.url);
    s.save = null;
    if (!site) throw new PassError(ErrorCode.NOT_FOUND, 'Passyble only works on http(s) pages', Reason.WEB_PAGES_ONLY);
    return { site };
  },

  async 'save.dismiss'(msg, sender) {
    tabState(sender.tab.id).save = null;
    return {};
  },

  async 'clipboard.copied'(msg) {
    return clipboardCopied(msg);
  },

  /** The packaged UI font, read here so the page never fetches it. */
  async 'ui.font'() {
    return uiFont();
  },

  // ---- cards and addresses: the URL is the asking frame's own (also in a cross-origin payment iframe) ----

  async 'forms.features'() {
    return formFeatures({ automatic: true });
  },

  async 'cards.list'(msg, sender) {
    const url = await formUrl(sender);
    return callNew(() => agent('cards.list', { url }, { automatic: !!msg.automatic }));
  },

  /** The desktop app asks "Fill <card> on <site>?" every time; `top_url` (another page above this frame) is shown there. */
  async 'cards.fill'(msg, sender) {
    const url = await formUrl(sender);
    const params = { url, id: itemId(msg.id) };
    const top = sender.tab?.url;
    if ((sender.frameId ?? 0) !== 0 && isWebUrl(top) && safeOrigin(top) !== safeOrigin(url)) params.top_url = top;
    if (await inBrowserMode()) return withUnlock(() => browserCardFill(params));
    return callNew(() => withUnlock(() => agent('cards.fill', params)));
  },

  async 'identities.list'(msg, sender) {
    const url = await formUrl(sender);
    return callNew(() => agent('identities.list', { url }, { automatic: !!msg.automatic }));
  },

  async 'identities.fill'(msg, sender) {
    const url = await formUrl(sender);
    return callNew(() => withUnlock(() => agent('identities.fill', { url, id: itemId(msg.id) })));
  },

  async 'passkey.create'(msg, sender) {
    await noPasskeysInBrowser();
    return passkeyRequest('create', msg, sender);
  },

  async 'passkey.get'(msg, sender) {
    await noPasskeysInBrowser();
    return passkeyRequest('get', msg, sender);
  },

  /**
   * Passkey names for the page's pending request; never a prompt. `automatic: false` (the user waits)
   * asks even right after Passyble was found not running.
   */
  async 'passkey.find'(msg, sender) {
    await noPasskeysInBrowser();
    const { origin, host } = passkeyOrigin(msg, sender);
    const o = msg.options && typeof msg.options === 'object' ? msg.options : {};
    return callNew(() => agent('passkey.find', {
      origin,
      rpId: String(o.rpId || host),
      allowCredentials: credList(o.allowCredentials),
    }, { automatic: msg.automatic !== false }));
  },

  /**
   * "Open Passyble" in the passkey card: a fresh native host starts the desktop app. A content script asks
   * for it, so the restart happens at most once in PASSKEY_START_MS whatever a page sends.
   */
  async 'passkey.start_app'() {
    await noPasskeysInBrowser();
    try {
      return { locked: !!(await agent('status')).locked };
    } catch (err) {
      if (PassError.from(err).code !== ErrorCode.AGENT_UNAVAILABLE || isHostMissing(err)) throw err;
      if (Date.now() - passkeyStartAt < PASSKEY_START_MS) throw err;
    }
    passkeyStartAt = Date.now();
    client.disconnect();
    unavailableUntil = 0;
    const status = await agent('status');
    refreshActiveBadges();
    return { locked: !!status.locked };
  },

  async 'passkey.create_options'(msg, sender) {
    await noPasskeysInBrowser();
    const { origin, host } = passkeyOrigin(msg, sender);
    const o = msg.options && typeof msg.options === 'object' ? msg.options : {};
    return callNew(() => agent('passkey.create_options', {
      origin,
      rpId: String(o.rpId || host),
      userName: String(o.userName ?? '').slice(0, 512),
      excludeCredentials: credList(o.excludeCredentials),
    }));
  },
};

/**
 * What the save banner offers for a captured submit. The agent compares with the saved logins
 * (`logins.save_check`), so stored passwords never come to the browser; older apps fall back to `logins.find`.
 */
async function saveDecision(save) {
  const params = { url: save.url, username: save.username, password: save.password, kind: save.kind };
  if (save.filledItemId) params.filled_id = save.filledItemId;
  if (save.ignoreId) params.ignore_id = save.ignoreId;
  if (save.canonical) params.canonical_url = save.canonical;
  try {
    return await agent('logins.save_check', params);
  } catch (err) {
    const e = PassError.from(err);
    if (!(e.code === ErrorCode.INVALID_PARAMS && /unknown method/i.test(e.message))) throw e;
  }
  const items = (await agent('logins.find', { url: save.url })).items || [];
  const lower = save.username.toLowerCase();
  let match = (save.username && items.find((it) => (it.username || '').toLowerCase() === lower)) || null;
  if (!match && save.kind === 'change') {
    match = items.find((it) => it.id === save.filledItemId) || (items.length === 1 ? items[0] : null);
  }
  return match ? { action: 'update_password', id: match.id, title: match.title } : { action: 'save_new' };
}

/**
 * What the save banner shows (`decided` null while locked). Never the password: a closed shadow root hides an
 * input's value but not the keys typed into it. The edit frame (an extension page) gets it via `save.edit-get`.
 */
async function bannerInfo(save, decided) {
  save.held = false;
  save.shown = true;
  save.decided = !!decided;
  save.id = decided?.id || null;
  save.action = decided?.action || 'save_new';
  save.edits = null;
  const mode = { update_password: 'update', update_username: 'username' }[save.action] || 'save';
  const out = { mode, host: hostOf(save.url), username: save.username,
    title: mode === 'save' ? null : decided.title ?? null, token: save.token, editable: true };
  // A lookalike of one of the user's sites: the banner warns. Only the site's name goes to the page.
  const lookalike = mode === 'save' ? lookalikeDomain(decided?.lookalike) : '';
  if (lookalike) out.lookalike = lookalike;
  save.vaultChoice = mode === 'save' ? newLoginVaultChoice(decided) : null;
  if (save.vaultChoice) out.vaults = save.vaultChoice;
  const updated = decided?.vault;
  if (mode !== 'save' && updated && updated.home !== true && typeof updated.name === 'string') out.vault_name = updated.name.slice(0, 120);
  out.check = await passwordCheck({ password: save.password, username: save.username, url: save.url, id: save.id });
  save.check = out.check;
  return out;
}

function sameName(a, b) {
  const x = String(a ?? '').trim().toLowerCase();
  return x !== '' && x === String(b ?? '').trim().toLowerCase();
}

/**
 * While locked: whether the submitted login may already be saved, from the soft lock's list (no passwords).
 * A password change form is never held, so its new password is not lost.
 */
async function mayBeSaved(save) {
  if (save.kind === 'change') return false;
  let res;
  try { res = await agent('logins.find', { url: save.url }); } catch { return false; }
  if (res?.locked !== true) return false;
  const items = Array.isArray(res.items) ? res.items.filter((it) => it.id !== save.ignoreId) : [];
  const anyone = !save.username.trim();
  return items.some((it) => it.id === save.filledItemId || anyone || sameName(it.username, save.username));
}

/** After an unlock, asks each tab whose captured login waits for it to check again (`save.recheck`). */
function recheckSaves() {
  cardSave.recheckAll();
  for (const [tabId, s] of tabs) {
    if (!awaitsUnlock(s.save)) continue;
    Promise.resolve(ext.tabs.sendMessage(tabId, { type: 'save.recheck' }, { frameId: 0 })).catch(() => {});
  }
}

function awaitsUnlock(save) {
  return !!save && !save.decided && !save.rechecked && (save.held || save.shown) && Date.now() - save.at <= 5 * SAVE_TTL_MS;
}

async function recheckSave(s, sender) {
  const save = s.save;
  if (!awaitsUnlock(save)) return null;
  let decided;
  try { decided = await saveDecision(save); } catch { return null; }
  if (s.save !== save) return null; // saved, dismissed or replaced meanwhile
  save.rechecked = true;
  if (decided?.action === 'none') {
    if (save.ignoreId) dropDraft(s, save.url, save.ignoreId);
    s.save = null;
    return save.held ? null : { close: true };
  }
  if (save.generated) {
    const done = await autoSave(s, save, decided);
    if (done) return save.held ? done : { close: true, ...done };
  }
  if (!save.held) return null;
  if (!save.generated && (await isNeverSave(save.url))) { s.save = null; return null; }
  return bannerInfo(save, decided);
}

async function rememberGenerated(s, url, password) {
  s.generated ??= createGeneratedPasswords();
  await s.generated.remember(safeOrigin(url), password);
}

/**
 * Saves the submit of a password Passyble generated without the banner, as autoSavePlan allows. Returns the
 * page's notice (with the `save.undo` token), or null when the banner should ask instead.
 */
async function autoSave(s, save, decided) {
  let siteLogins = null;
  if (decided?.action === 'save_new' && !save.username.trim()) {
    // A password-only form: a new login only when the site has none yet (other subdomains count).
    try {
      const res = await agent('logins.find', { url: save.url });
      if (res?.locked !== true && Array.isArray(res?.items)) {
        siteLogins = res.items.filter((it) => String(it.id) !== save.ignoreId).length;
      }
    } catch { /* unknown: ask */ }
  }
  const plan = autoSavePlan(decided, { username: save.username, siteLogins });
  if (plan === 'prompt' || s.save !== save) return null;
  const params = { url: save.url, username: save.username, password: save.password };
  if (save.canonical) params.canonical_url = save.canonical;
  if (plan === 'update') params.id = decided.id;
  let res;
  try {
    res = await agent('logins.save', params);
  } catch {
    return null;
  }
  if (s.save === save) s.save = null; // the password leaves memory with the save
  const id = res?.id != null ? String(res.id) : null;
  let draftId = null;
  if (save.ignoreId && id === save.ignoreId) keepDraft(s, save.url, save.ignoreId);
  else if (save.ignoreId) { dropDraft(s, save.url, save.ignoreId); draftId = save.ignoreId; }
  refreshActiveBadges();
  if (!id || (res.unchanged && id !== save.ignoreId)) return null;
  const kind = plan === 'update' && !res.unchanged ? 'updated' : 'saved';
  s.autoSaved = { token: crypto.randomUUID(), url: save.url, kind, id, draftId: kind === 'updated' ? draftId : null, at: Date.now() };
  return { autosaved: kind, token: s.autoSaved.token, host: hostOf(save.url) };
}

const SIMILAR_LIMIT = 3;

/**
 * A login of another site was just filled into this tab: kept for the top frame's card. The agent's one-time
 * `add_url_token`, the username and the password stay here; content scripts only get the card's own token.
 */
async function offerCrossLink(sender, pending, res, url) {
  const origin = safeOrigin(url);
  if (!isWebUrl(url) || origin === 'null') return;
  const s = tabState(sender.tab.id);
  const password = typeof res.password === 'string' ? res.password : '';
  const passwords = createGeneratedPasswords();
  await passwords.remember(origin, password);
  const offer = {
    token: crypto.randomUUID(), agentToken: typeof res.add_url_token === 'string' ? res.add_url_token : '',
    id: pending.id, url, origin, host: hostOf(url).replace(/^www\./, ''),
    site: label(res.domain) || label(pending.domain), title: label(res.title) || label(pending.title),
    username: typeof res.username === 'string' ? res.username : '', password, passwords,
    lookalike: lookalikeDomain(res.lookalike) || lookalikeDomain(pending.lookalike),
    at: Date.now(), shown: false, answered: '',
  };
  s.crossOffer = offer;
  const purge = setTimeout(() => {
    forgetCrossSecrets(offer);
    if (s.crossOffer === offer) s.crossOffer = null;
  }, CROSS_OFFER_TTL_MS);
  purge?.unref?.(); // Node (tests) only
  Promise.resolve(ext.tabs.sendMessage(sender.tab.id, { type: 'cross.offer' }, { frameId: 0 })).catch(() => {});
}

function liveCrossOffer(s) {
  const offer = s?.crossOffer;
  if (!offer) return null;
  if (Date.now() - offer.at > CROSS_OFFER_TTL_MS) {
    forgetCrossSecrets(offer);
    s.crossOffer = null;
    return null;
  }
  return offer;
}

function crossOfferFor(sender, msg) {
  const offer = liveCrossOffer(tabState(sender.tab.id));
  if ((sender.frameId ?? 0) !== 0 || !offer || offer.answered || typeof msg.token !== 'string' || msg.token !== offer.token) {
    throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
  }
  return offer;
}

function forgetCrossSecrets(offer) {
  offer.password = '';
  offer.agentToken = '';
}

/** What the card shows (no secret). `can_add`: the agent gave a token (newer desktop apps). */
function crossInfo(offer) {
  return { token: offer.token, host: offer.host, site: offer.site, title: offer.title, username: offer.username,
    lookalike: offer.lookalike, can_add: !!offer.agentToken, can_copy: !!offer.password };
}

async function crossSubmitted(offer, save) {
  if (!(await offer.passwords.matches(safeOrigin(save.url), save.password))) return false;
  const typed = String(save.username || '').trim().toLowerCase();
  return !typed || typed === String(offer.username || '').trim().toLowerCase();
}

/** The tab's last fill if it was into this submit's origin, for a plain sign-in only; taken once. */
function takeFilled(s, save, offer) {
  const filled = liveFilled(s.filled, safeOrigin(save.url));
  if (!filled) return null;
  s.filled = null;
  if (save.kind !== 'login' || save.generated || save.draftId) return null;
  if (filled.cross && (!offer || offer.answered || offer.id !== filled.itemId)) return null;
  return filled;
}

/**
 * What "Update this login?" shows (never the password), or null when it would have no button. `offer`: the
 * cross card it stands in for, so one card shows, not two.
 */
async function changedCard(save, filled, changes, decided, offer) {
  // Update: only a login the user may change, and of another site only with the agent's token of that fill.
  const canUpdate = filled.canEdit && (!offer || !!offer.agentToken);
  // Save as new: never the password of a fill-only login the user didn't change.
  const canCopy = !(filled.noReveal && !changes.password);
  if (!canUpdate && !canCopy) return null;
  let title = offer?.title || filled.title || '';
  if (!title && decided?.id != null && String(decided.id) === filled.itemId) title = String(decided.title ?? '');
  if (!title) title = await loginTitle(save.url, filled.itemId);
  save.changed = { id: filled.itemId, title, username: changes.username, password: changes.password,
    canUpdate, canCopy, offer };
  if (offer) offer.shown = true;
  const lookalike = offer?.lookalike || (decided?.action === 'save_new' ? lookalikeDomain(decided?.lookalike) : '');
  return {
    token: save.token, host: hostOf(save.url).replace(/^www\./, ''), title: title.slice(0, 256),
    username: filled.username.slice(0, 512), new_username: changes.username.slice(0, 512), password_changed: changes.password,
    cross: !!offer, site: offer?.site || '', lookalike: lookalike || '',
    can_update: canUpdate, can_copy: canCopy, read_only: !filled.canEdit,
  };
}

async function loginTitle(url, id) {
  try {
    const res = await agent('logins.find', { url });
    const item = (Array.isArray(res?.items) ? res.items : []).find((it) => String(it?.id) === id);
    return typeof item?.title === 'string' ? item.title : '';
  } catch {
    return '';
  }
}

function changedFor(sender, msg) {
  const s = tabState(sender.tab.id);
  const save = s.save;
  if ((sender.frameId ?? 0) !== 0 || !save?.changed || typeof msg.token !== 'string' || msg.token !== save.token ||
      Date.now() - save.at > 5 * SAVE_TTL_MS) {
    throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
  }
  return { s, save, changed: save.changed };
}

function sentValues(msg) {
  return msg.username !== undefined || msg.password !== undefined;
}

function checkOf(save, edited) {
  return passwordCheck({ password: edited.password ?? save.password, username: edited.username ?? save.username,
    url: save.url, id: save.id });
}

/**
 * The captured login for a request of the save banner's edit frame: only that extension page (by the URL the
 * browser reports), only as a frame inside a tab, only for the banner on screen (its one-time token).
 */
function editFrameSave(msg, sender) {
  if (typeof sender.url !== 'string' || sender.url.split(/[?#]/)[0] !== ext.runtime.getURL(SAVE_EDIT_PATH)) return null;
  if (!sender.tab || typeof sender.tab.id !== 'number' || !(Number(sender.frameId) > 0)) return null;
  const save = tabs.get(sender.tab.id)?.save;
  if (!save || !save.shown || typeof msg.token !== 'string' || msg.token !== save.token) return null;
  if (Date.now() - save.at > 5 * SAVE_TTL_MS) return null;
  return save;
}

function editedValues(msg, save) {
  const out = { changed: false };
  if (msg.username !== undefined) {
    if (typeof msg.username !== 'string' || msg.username.length > FIELD_LIMITS.username) throw badParams('Bad username');
    const username = msg.username.trim();
    if (username !== save.username) { out.username = username; out.changed = true; }
  }
  if (msg.password !== undefined && msg.password !== '') {
    if (typeof msg.password !== 'string' || msg.password.length > FIELD_LIMITS.password) throw badParams('Bad password');
    if (msg.password !== save.password) { out.password = msg.password; out.changed = true; }
  }
  return out;
}

/** The page's https canonical address of another host, or null. The agent decides itself whether it shares the page's logins. */
function canonicalOf(value, pageUrl) {
  if (typeof value !== 'string' || value.length > 2048) return null;
  try {
    const page = new URL(pageUrl);
    const canonical = new URL(value);
    if (page.protocol !== 'https:' || canonical.protocol !== 'https:') return null;
    if (canonical.hostname === page.hostname) return null;
    return canonical.origin;
  } catch {
    return null;
  }
}

function activeDraft(s, url) {
  const d = s.draft;
  if (!d) return null;
  if (Date.now() - d.at > DRAFT_TTL_MS) { s.draft = null; return null; }
  return d.origin === safeOrigin(url) ? d : null;
}

async function updateDraft(url, draft, username, password) {
  const fields = { password };
  if (username) fields.username = username;
  try {
    await agent('logins.update', { url, id: draft.id, fields });
    draft.at = Date.now();
    return true;
  } catch {
    return false;
  }
}

function dropDraft(s, url, id) {
  if (s.draft?.id === id) s.draft = null;
  agent('logins.delete', { url, id }).then(refreshActiveBadges, () => {});
}

function keepDraft(s, url, id) {
  if (s.draft?.id === id) s.draft = null;
  agent('logins.update', { url, id, fields: { title: hostOf(url).replace(/^www\./, '') } }).then(refreshActiveBadges, () => {});
}

async function callNew(fn) {
  try {
    return await fn();
  } catch (err) {
    const e = PassError.from(err);
    if (e.code === ErrorCode.INVALID_PARAMS && /unknown method/i.test(e.message)) {
      throw new PassError(ErrorCode.NOT_SUPPORTED, 'unknown method', Reason.NEEDS_UPDATE);
    }
    throw e;
  }
}

/** `locked` before asking the user anything (withUnlock unlocks, then the question comes once). */
async function requireUnlocked() {
  const info = await local.info();
  if (!info.hasVault) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser yet');
  if (info.locked) throw new PassError(ErrorCode.LOCKED, 'Vault is locked');
}

async function noPasskeysInBrowser() {
  if (await inBrowserMode()) throw new PassError(ErrorCode.NOT_SUPPORTED, 'Passkeys need the Passyble app for now', Reason.PASSKEYS_NEED_APP);
}

/** Browser mode card fill: the popup asks first, and only that yes goes to the agent (`confirmed`). */
async function browserCardFill(params) {
  await requireUnlocked();
  let card = '';
  try {
    const found = (await agent('cards.list', { url: params.url })).items || [];
    const c = found.find((x) => x.id === params.id);
    if (c) card = [c.title, c.last4 ? `•••• ${c.last4}` : ''].filter(Boolean).join(' ');
  } catch (err) {
    if (PassError.from(err).code === ErrorCode.LOCKED) throw err; // unlock first (withUnlock)
  }
  await askUser('card', { url: params.top_url || params.url, card });
  return agent('cards.fill', params, { confirmed: true });
}

const PASSKEY_START_MS = 15_000;
let passkeyStartAt = 0;

function b64(v, name) {
  if (typeof v !== 'string' || !B64URL_RE.test(v)) throw new PassError(ErrorCode.INVALID_PARAMS, `Bad ${name}`);
  return v;
}

function credList(list) {
  return (Array.isArray(list) ? list : []).filter((c) => c && (c.type === undefined || c.type === 'public-key'))
    .map((c) => ({ id: b64(c.id, 'credential id') }));
}

/** The origin a passkey request is for, from the browser's sender info; `not_found` leaves it to the browser's WebAuthn. */
function passkeyOrigin(msg, sender) {
  const origin = senderOrigin(sender);
  let u;
  try { u = new URL(origin); } catch { throw new PassError(ErrorCode.NOT_FOUND, 'Opaque origin'); }
  const localhost = u.hostname === 'localhost' || u.hostname.endsWith('.localhost');
  if (!(u.protocol === 'https:' || (u.protocol === 'http:' && localhost))) {
    throw new PassError(ErrorCode.NOT_FOUND, 'Passkeys need a secure origin'); // native WebAuthn reports the real error
  }
  const topOrigin = safeOrigin(sender.tab?.url || origin);
  // The top frame alone misses A > B > A nesting (WebAuthn's crossOrigin is true there too): the
  // isolated world reports a cross-origin ancestor. That hint can only make this stricter.
  const crossOrigin = (sender.frameId ?? 0) !== 0 && (topOrigin !== origin || msg.crossOriginAncestor === true);
  if (crossOrigin) {
    // Cross-origin iframes need the publickey-credentials-* permissions policy, which only the
    // browser can check. Leave them to the native implementation.
    throw new PassError(ErrorCode.NOT_FOUND, 'Cross-origin frame');
  }
  return { origin, host: u.hostname };
}

async function passkeyRequest(kind, msg, sender) {
  const { origin, host } = passkeyOrigin(msg, sender);
  const crossOrigin = false; // cross-origin frames were left to the browser (passkeyOrigin)
  const o = msg.options && typeof msg.options === 'object' ? msg.options : {};
  let method;
  let params;
  if (kind === 'create') {
    const rpId = o.rp?.id || host;
    const algs = Array.isArray(o.pubKeyCredParams) && o.pubKeyCredParams.length
      ? o.pubKeyCredParams.filter((p) => p && p.type === 'public-key' && Number.isInteger(p.alg)).map((p) => ({ type: 'public-key', alg: p.alg }))
      : [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }];
    method = 'passkey.create';
    params = {
      origin,
      rp: { id: String(rpId), name: String(o.rp?.name || rpId) },
      user: { id: b64(o.user?.id, 'user.id'), name: String(o.user?.name ?? ''), displayName: String(o.user?.displayName ?? '') },
      challenge: b64(o.challenge, 'challenge'),
      pubKeyCredParams: algs,
      excludeCredentials: credList(o.excludeCredentials),
      authenticatorSelection: { userVerification: uvRequirement(o.authenticatorSelection?.userVerification) },
      crossOrigin,
    };
    addPrf(params, o);
    // Saved in the extension's own card after a real click there: no consent window. The agent checks the login belongs to the site.
    if (msg.inPage === true && msg.consent && typeof msg.consent === 'object') {
      const id = msg.consent.itemId;
      params.consent = { itemId: typeof id === 'string' && id && id.length <= 128 ? id : null };
      // The vault a new login goes to; the agent checks it.
      const v = msg.consent.vault;
      if (params.consent.itemId === null && typeof v === 'string' && v && v.length <= 128) params.consent.vault = v;
    }
  } else {
    method = 'passkey.get';
    params = {
      origin,
      rpId: String(o.rpId || host),
      challenge: b64(o.challenge, 'challenge'),
      allowCredentials: credList(o.allowCredentials),
      userVerification: uvRequirement(o.userVerification),
      crossOrigin,
    };
    addPrf(params, o);
    // Conditional mediation: the user already picked an item in the inline menu or the passkey prompt.
    if (typeof msg.id === 'string' && msg.id) {
      params.id = msg.id;
      if (msg.credentialId != null) params.credentialId = b64(msg.credentialId, 'credential id');
    }
  }
  // Locked: the unlock prompt only for a ceremony the user started. A page asking as it loads gets `locked`
  // and the browser's own WebAuthn takes over. An in-page choice unlocks in the page unless the app can't.
  const prompt = msg.userActivated !== true ? false : msg.inPage === true ? async () => !(await unlocksInPage()) : true;
  return withUnlock(() => agent(method, params), { prompt, forItem: params.id ?? null });
}

function addPrf(params, o) {
  const prf = o.extensions && typeof o.extensions === 'object' ? o.extensions.prf : undefined;
  if (prf && typeof prf === 'object' && !Array.isArray(prf)) params.extensions = { prf };
}

function uvRequirement(value) {
  return ['required', 'preferred', 'discouraged'].includes(value) ? value : 'preferred';
}

async function tabUrl(tabId) {
  const tab = await ext.tabs.get(Number(tabId));
  return tab.url || '';
}

const pageHandlers = {
  async 'popup.status'() {
    return agent('status');
  },

  async 'popup.state'(msg) {
    const url = await tabUrl(msg.tabId);
    // Read-only (forced update): search and copy only, nothing filled, edited or saved.
    const extensionBlocked = await versionCheck.blocked();
    if (!isWebUrl(url) && !extensionBlocked) {
      const action = commands.takePopupAction(msg.tabId);
      return { url, supported: false, ...(action ? { quick_action: action } : {}) };
    }
    const status = await agent('status');
    const features = Array.isArray(status.features) ? status.features : [];
    const readOnly = extensionBlocked ? 'extension' : status.update_required === true ? 'app' : null;
    const unlock = { can_unlock_inline: features.includes('unlock.inline'), unlock_hello: false, unlock_hello_auto: false,
      unlock_hello_pending: false, ask_unlock: false };
    if (status.locked && unlock.can_unlock_inline) {
      try { unlock.unlock_hello = (await agent('unlock.options'))?.hello === true; } catch { /* password only */ }
      unlock.unlock_hello_auto = unlock.unlock_hello && helloAutoAllowed();
      unlock.unlock_hello_pending = !!helloPending;
    }
    if (unlockAsk && unlockAsk.tabId === Number(msg.tabId) && Date.now() - unlockAsk.at < UNLOCK_ASK_TTL_MS) {
      unlock.ask_unlock = !!status.locked;
    }
    unlockAsk = null;
    const search = popupSearch && popupSearch.tabId === Number(msg.tabId) && Date.now() - popupSearch.at < POPUP_SEARCH_TTL_MS
      ? popupSearch.query : '';
    popupSearch = null;
    const action = readOnly ? null : commands.takePopupAction(msg.tabId);
    const quickAction = action ? { quick_action: action } : {};
    // Soft-locked: the agent still lists the logins (no secrets); filling or copying a secret unlocks first.
    const readOnlyFields = readOnly ? { read_only: readOnly } : {};
    const quick = readOnly ? {} : { can_edit: features.includes('edit'), can_notes: features.includes('notes.create') };
    if (status.locked && !status.soft_locked) return { url, supported: true, locked: true, ...readOnlyFields, ...quick, ...unlock, ...quickAction };
    if (readOnly) {
      return { url, supported: true, locked: !!status.locked, soft_locked: !!status.locked, items: [], pending_otp: null, read_only: readOnly,
        can_edit: false, can_icons: features.includes('icons.get'), can_search: features.includes('logins.search'), ...unlock };
    }
    let found;
    try {
      found = await agent('logins.find', { url });
    } catch (err) {
      if (PassError.from(err).code === ErrorCode.LOCKED) return { url, supported: true, locked: true, ...quick, ...unlock, ...quickAction };
      throw err;
    }
    const forms = isSecureFormUrl(url) && (await getSettings()).formFill;
    let similar = null;
    if (!(found.items || []).length && features.includes('logins.similar')) {
      try {
        const res = await agent('logins.similar', { url, limit: SIMILAR_LIMIT });
        similar = { items: (Array.isArray(res?.items) ? res.items : []).filter((it) => it && !it.lookalike).slice(0, SIMILAR_LIMIT),
          vaults: Array.isArray(res?.vaults) ? res.vaults : [] };
      } catch { /* none */ }
    }
    return { url, supported: true, locked: !!status.locked, soft_locked: !!status.locked, items: found.items || [], pending_otp: found.pending_otp || null,
      ...(similar ? { similar } : {}), ...(search ? { search } : {}),
      vaults: Array.isArray(found.vaults) ? found.vaults : [], can_vaults: features.includes('vaults'),
      can_pins: features.includes('vaults.pins'), can_move: features.includes('items.move'),
      can_edit: features.includes('edit'), can_scan: features.includes('totp.from_image'), can_notes: features.includes('notes.create'),
      can_url_rules: features.includes('url_rules'), can_sites: features.includes('sites.suggest'), can_icons: features.includes('icons.get'), can_search: features.includes('logins.search'),
      can_cards: forms && features.includes('cards'), can_identities: forms && features.includes('identities'),
      can_favorites: features.includes('items.favorite'), can_note_list: features.includes('notes.list'),
      can_generate_username: features.includes('generate.username'), can_generate_email: features.includes('generate.email'), ...unlock, ...quickAction };
  },

  async 'popup.forms'(msg) {
    const url = await tabUrl(msg.tabId);
    const none = { cards: [], identities: [], locked: false };
    if (!isSecureFormUrl(url)) return none;
    const support = await formFeatures();
    const list = async (on, method) => (on ? callNew(() => agent(method, { url })) : { items: [], locked: false });
    const [cards, identities] = await Promise.all([list(support.cards, 'cards.list'), list(support.identities, 'identities.list')]);
    return { cards: cards.items || [], identities: identities.items || [], locked: !!(cards.locked || identities.locked) };
  },

  /**
   * Copies a card's number or security code (`cards.fill` with `purpose: "copy"`). A desktop app that copies it
   * itself answers `{ copied: true }`; from an older one only the requested value goes to the popup.
   */
  async 'popup.card-copy'(msg, sender) {
    if (!['number', 'security_code'].includes(msg.field)) throw badParams('Bad field');
    const url = requireSecureFormUrl(await tabUrl(msg.tabId));
    const params = { url, id: itemId(msg.id), purpose: 'copy', field: msg.field };
    // The vault in this browser: the pick in the popup is the user's yes (`confirmed`).
    const confirmed = await inBrowserMode();
    const notice = COPY_NOTICE[msg.field];
    const res = await copyWithFeedback(msg, sender,
      () => callNew(() => withUnlock(() => agent('cards.fill', params, { confirmed }), promptFor(msg))),
      { done: (r) => t(r?.copied === true ? notice.done : notice.notDone), notDone: t(notice.notDone) });
    if (res?.copied === true) return { copied: true };
    return { value: String((msg.field === 'number' ? res?.number : res?.security_code) || '') };
  },

  /** Secure note titles for the popup (`notes.list`), never a note's text. */
  async 'popup.notes'() {
    return callNew(() => agent('notes.list', { limit: NOTES_LIMIT }));
  },

  /** A secure note's text for the viewer (`notes.get`), or with `copy` copied by the desktop app so the text stays out of the browser. */
  async 'popup.note-get'(msg) {
    const params = { id: itemId(msg.id), ...(msg.copy === true ? { copy: true } : {}) };
    return callNew(() => withUnlock(() => agent('notes.get', params), promptFor(msg)));
  },

  async 'popup.identity-copy'(msg) {
    if (!['full_name', 'email', 'phone', 'address'].includes(msg.field)) throw badParams('Bad field');
    const url = requireSecureFormUrl(await tabUrl(msg.tabId));
    const res = await callNew(() => withUnlock(() => agent('identities.fill', { url, id: itemId(msg.id) }), promptFor(msg)));
    if (msg.field !== 'address') return { value: String(res?.[msg.field] || '') };
    const place = [res?.postal_code, res?.city].filter(Boolean).join(' ');
    return { value: [res?.address1, res?.address2, res?.address3, place, res?.region, res?.country].filter(Boolean).join(', ') };
  },

  /** Search box: the whole vault (`logins.search`, at least 2 characters). Never returns a secret. */
  async 'popup.search'(msg) {
    const query = typeof msg.query === 'string' ? msg.query.trim() : '';
    if (query.length < 2 || query.length > 128) throw badParams('Search for 2 to 128 characters');
    const params = { query, limit: SEARCH_LIMIT };
    const url = msg.tabId !== undefined ? await tabUrl(msg.tabId).catch(() => '') : '';
    if (isWebUrl(url)) params.url = url;
    return callNew(() => agent('logins.search', params));
  },

  /**
   * The desktop app copies the value itself (out of clipboard history; it never comes to the browser). `own`: the
   * tab's own login, counted as a fill. A `lookalike` result's secret is copied only after the user says yes.
   */
  async 'popup.copy-item'(msg, sender) {
    if (!['username', 'password', 'totp'].includes(msg.field)) throw badParams('Bad field');
    const id = itemId(msg.id);
    const params = { id, field: msg.field };
    const url = msg.tabId !== undefined ? await tabUrl(msg.tabId).catch(() => '') : '';
    if (isWebUrl(url)) params.url = url;
    const own = msg.own === true && !!params.url;
    const lookalike = lookalikeDomain(msg.lookalike);
    if (lookalike && !own && msg.field !== 'username' && params.url) {
      await askUser('lookalike', { url: params.url, lookalike, title: typeof msg.title === 'string' ? msg.title : '' });
    }
    const notice = COPY_NOTICE[msg.field];
    const res = await copyWithFeedback(msg, sender,
      () => callNew(() => withUnlock(() => agent('logins.copy', params), own ? { ...promptFor(msg), forItem: id } : promptFor(msg))),
      { done: () => t(notice.done), notDone: t(notice.notDone) });
    if (own && msg.field === 'password') recordFill(Number(msg.tabId), id);
    return res;
  },

  /** The frame with the login form asks the agent itself (`logins.fill_cross`, with its own URL). */
  async 'popup.fill-cross'(msg) {
    const tabId = Number(msg.tabId);
    requireWebUrl(await tabUrl(tabId));
    tabState(tabId).crossFill = { id: itemId(msg.id), at: Date.now(), title: label(msg.title), domain: label(msg.domain),
      lookalike: lookalikeDomain(msg.lookalike) };
    return sendToFillFrame(tabId, { type: 'cmd.fill-cross', id: String(msg.id) });
  },

  async 'popup.find'(msg) {
    return agent('logins.find', { url: requireWebUrl(msg.url) });
  },

  /** Website icons from the desktop app's cache, only for logins of the tab's page or a lookup; nothing is fetched here. */
  async 'popup.icons'(msg) {
    if (Array.isArray(msg.ids)) {
      // Search results: the agent answers only for logins its last searches returned.
      const ids = msg.ids.slice(0, SEARCH_LIMIT).map((id) => itemId(id));
      return agent('icons.get', { ids });
    }
    const url = requireWebUrl(msg.url ? msg.url : await tabUrl(msg.tabId));
    return agent('icons.get', { url });
  },

  async 'popup.fill'(msg) {
    const tabId = Number(msg.tabId);
    return sendToFillFrame(tabId, { type: 'cmd.fill-item', id: String(msg.id) });
  },

  async 'popup.copy'(msg, sender) {
    const url = requireWebUrl(msg.url ? msg.url : await tabUrl(msg.tabId));
    // The popup copies the value itself, so for a popup the prompt closed the notice is "not copied".
    const notDone = t(COPY_NOTICE[msg.field === 'username' ? 'username' : 'password'].notDone);
    const res = await copyWithFeedback(msg, sender,
      () => withUnlock(() => agent('logins.fill', { url, id: String(msg.id) }), { ...promptFor(msg), forItem: String(msg.id) }),
      { done: () => notDone, notDone });
    // A fill-only login's password is for the page only, never the clipboard, whatever asks.
    if (msg.field !== 'username' && res?.vault?.can_reveal === false) {
      throw new PassError(ErrorCode.FILL_ONLY, 'This login can be filled but not shown or copied');
    }
    if (!msg.url) recordFill(Number(msg.tabId), String(msg.id));
    return { value: msg.field === 'username' ? res.username : res.password };
  },

  async 'popup.totp'(msg) {
    const url = requireWebUrl(msg.url ? msg.url : await tabUrl(msg.tabId));
    const params = { url };
    if (msg.id) params.id = String(msg.id);
    return withUnlock(() => agent('totp.get', params), { ...promptFor(msg), forItem: params.id });
  },

  /** The desktop app's own unlock prompt. It takes the focus, so the fill or copy the popup was unlocking for (`then`) is finished here. */
  async 'popup.unlock'(msg, sender) {
    const res = await agent('unlock').catch((err) => { copyNotDone(msg, sender); throw err; });
    refreshActiveBadges();
    return finishAfterUnlock(msg, sender, res);
  },

  /** Locks the vault; extension pages only, no content script can reach it. */
  async 'popup.lock'() {
    const res = await callNew(() => agent('lock'));
    broadcastToActiveTabs({ type: 'lock_state', locked: true });
    refreshActiveBadges();
    return res;
  },

  async 'popup.unlock-options'() {
    return unlockOptions();
  },

  /** The popup's unlock form and the in-page menu's master password frame; the password goes to the agent once and is not kept. */
  async 'popup.unlock-password'(msg, sender) {
    const password = typeof msg.password === 'string' ? msg.password : '';
    if (!password || password.length > MAX_MASTER_PASSWORD) throw new PassError(ErrorCode.INVALID_PARAMS, 'No master password');
    const forItem = unlockForPage(msg, sender);
    if (await inBrowserMode()) {
      if (await linkedBrowserVault()) {
        const { grant } = await accountKeys.unlockVault(accountPasswordParams(msg));
        unlockGrant = forItem && grant ? { grant, id: forItem, at: Date.now() } : null;
        return { locked: false };
      }
      // The browser vault: its grant makes this unlock the check of the one login it was for.
      const { grant } = await local.unlock(password);
      unlockGrant = forItem && grant ? { grant, id: forItem, at: Date.now() } : null;
      await recordMasterTip(password);
      return { locked: false };
    }
    const res = await unlockCall('unlock.password', { password, ...forParams(forItem) });
    unlockedHere();
    return res;
  },

  /** Windows Hello takes the focus, which closes the popup: the fill or copy it was unlocking for (`then`) is finished here. */
  async 'popup.unlock-hello'(msg, sender) {
    const res = await helloUnlock(msg.then?.fill?.id ?? unlockForPage(msg, sender))
      .catch((err) => { copyNotDone(msg, sender); throw err; });
    return finishAfterUnlock(msg, sender, res);
  },

  async 'popup.unlock-cancel'() {
    return helloCancel();
  },

  async 'popup.generate'(msg) {
    return contentHandlers.generate(msg);
  },

  // The extension never sees the alias tokens or the user's addresses, only the generated value.

  async 'popup.generate-username'() {
    return callNew(() => agent('generate.username', {}));
  },

  async 'popup.generate-options'() {
    return callNew(() => agent('generate.options', {}));
  },

  /** `kind`: plus | catch_all | alias; `service`: an alias service id; `website`: the user ticked it. */
  async 'popup.generate-email'(msg) {
    if (!['plus', 'catch_all', 'alias'].includes(msg.kind)) throw new PassError(ErrorCode.INVALID_PARAMS, 'unknown kind', Reason.BAD_REQUEST);
    const url = requireWebUrl(await tabUrl(msg.tabId));
    const params = { kind: msg.kind, url };
    if (msg.website === true) params.website = true;
    if (msg.kind === 'alias' && typeof msg.service === 'string' && /^[a-z0-9_-]{1,64}$/.test(msg.service)) params.service = msg.service;
    return callNew(() => withUnlock(() => agent('generate.email', params), promptFor(msg)));
  },

  async 'clipboard.copied'(msg) {
    return clipboardCopied(msg);
  },

  /**
   * The edit frame's starting values. The captured password only when the tab's page has the origin it was
   * typed into (by the tab URL the browser reports); otherwise the field starts empty.
   */
  async 'save.edit-get'(msg, sender) {
    const save = editFrameSave(msg, sender);
    if (!save) throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
    save.edits = null;
    const out = { username: save.username, check: save.check ?? null };
    // Never the password of a fill-only login (filled just before): the field starts empty, "keep it".
    if (!save.noReveal && isWebUrl(sender.tab.url) && safeOrigin(sender.tab.url) === safeOrigin(save.url)) out.password = save.password;
    return out;
  },

  async 'save.edit-set'(msg, sender) {
    const save = editFrameSave(msg, sender);
    if (!save) throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to save', Reason.NOTHING_TO_SAVE);
    const edited = editedValues({ username: msg.username ?? '', password: msg.password ?? '' }, save);
    save.edits = edited;
    return { check: await checkOf(save, edited) };
  },

  // Login editor: the page is always the tab's URL from tabs.get, and the agent rechecks that the login
  // belongs to it. Nothing passing through here is stored.

  async 'popup.edit-get'(msg) {
    const url = requireWebUrl(await tabUrl(msg.tabId));
    return editCall('logins.get_for_edit', { url, id: itemId(msg.id) }, promptFor(msg));
  },

  async 'popup.edit-save'(msg) {
    const url = requireWebUrl(await tabUrl(msg.tabId));
    const fields = editFields(msg.fields);
    const createParams = { url, fields };
    if (typeof msg.vault === 'string' && msg.vault && msg.vault.length <= 128) createParams.vault = msg.vault;
    const res = msg.id
      ? await editCall('logins.update', { url, id: itemId(msg.id), fields }, promptFor(msg))
      : await editCall('logins.create', createParams, promptFor(msg));
    refreshActiveBadges();
    return res;
  },

  async 'popup.rule-hint'(msg) {
    const url = typeof msg.url === 'string' ? msg.url.trim() : '';
    if (!url || url.length > MAX_URL) throw badParams('Bad website');
    return callNew(() => agent('sites.rule_hint', { url }));
  },

  async 'popup.site-suggest'(msg) {
    const query = typeof msg.query === 'string' ? msg.query.trim() : '';
    if (!query || query.length > MAX_SITE_QUERY) throw badParams('Bad query');
    return callNew(() => agent('sites.suggest', { query, limit: SITE_SUGGESTIONS }));
  },

  async 'popup.site-name'(msg) {
    const url = typeof msg.url === 'string' ? msg.url.trim() : '';
    if (!url || url.length > MAX_URL) throw badParams('Bad website');
    return callNew(() => agent('sites.name_for', { url }));
  },

  async 'popup.edit-move'(msg) {
    requireWebUrl(await tabUrl(msg.tabId));
    const res = await editCall('items.move', { id: itemId(msg.id), vault: vaultId(msg.vault) }, promptFor(msg));
    refreshActiveBadges();
    return res;
  },

  async 'popup.edit-delete'(msg) {
    const url = requireWebUrl(await tabUrl(msg.tabId));
    const res = await editCall('logins.delete', { url, id: itemId(msg.id) }, promptFor(msg));
    refreshActiveBadges();
    return res;
  },

  async 'popup.edit-restore'(msg) {
    const url = requireWebUrl(await tabUrl(msg.tabId));
    const res = await editCall('logins.restore', { url, id: itemId(msg.id) }, promptFor(msg));
    refreshActiveBadges();
    return res;
  },

  async 'popup.totp-check'(msg) {
    const url = requireWebUrl(await tabUrl(msg.tabId));
    return editCall('totp.set', { url, totp: totpParam(msg.totp, false) }, promptFor(msg));
  },

  /** "Scan QR on this page": a screenshot of the visible tab goes to the agent, which reads the QR code. */
  async 'popup.totp-scan'(msg) {
    const { url, image } = await captureTab(msg.tabId);
    return editCall('totp.from_image', { url, image }, promptFor(msg));
  },

  /** A 2FA link the popup decoded from a QR code (the screenshot never comes here) goes to a login of the tab's site. */
  async 'popup.totp-attach'(msg) {
    const url = requireWebUrl(await tabUrl(msg.tabId));
    const res = await editCall('totp.set', { url, id: itemId(msg.id), totp: totpParam(msg.totp, false) }, promptFor(msg));
    refreshActiveBadges();
    return res;
  },

  async 'popup.note-create'(msg) {
    const res = await editCall('notes.create', { fields: noteFields(msg.fields) }, promptFor(msg));
    return { id: res?.id, title: res?.title };
  },

  async 'popup.generate-copy'(msg) {
    return contentHandlers['generate.copy'](msg);
  },

  async 'popup.password-check'(msg) {
    const url = await tabUrl(msg.tabId).catch(() => '');
    return passwordCheck({ password: msg.password, username: msg.username, url, title: msg.title,
      id: typeof msg.id === 'string' ? msg.id : null });
  },

  async 'popup.vaults'() {
    if (await inBrowserMode()) return null;
    const status = await agent('status');
    const features = Array.isArray(status.features) ? status.features : [];
    if (!features.includes('vaults')) return null;
    return agent('vaults.list').catch(() => null);
  },

  async 'popup.pins'() {
    return callNew(() => agent('vaults.pins'));
  },

  /** Saves the pinned vaults in order. Browser mode passes `known` (shared vaults opened beside the agent's own) so their pins stay. */
  async 'popup.set-pins'(msg) {
    const ids = (list) => {
      if (!Array.isArray(list) || list.length > MAX_PIN_IDS) throw badParams('Bad vault ids');
      return list.map(vaultId);
    };
    const params = { ids: ids(msg.ids) };
    const known = msg.known === undefined ? null : ids(msg.known);
    if (known && await inBrowserMode()) params.known = known;
    return callNew(() => agent('vaults.set_pins', params));
  },

  async 'popup.own-vaults'() {
    if (await inBrowserMode()) throw new PassError(ErrorCode.NOT_SUPPORTED, 'One vault in this browser');
    return callNew(() => agent('vaults.own'));
  },

  async 'popup.switch-vault'(msg) {
    if (await inBrowserMode()) throw new PassError(ErrorCode.NOT_SUPPORTED, 'One vault in this browser');
    return callNew(() => agent('vaults.switch', { id: vaultId(msg.id) }));
  },

  async 'support.open'(msg, sender) {
    const used = await openSupport({
      browserMode: await inBrowserMode(),
      getStatus: () => agent('status'),
      getBase: () => account.base(),
      navigate: async (url) => {
        let tabId = sender?.tab?.id;
        if (typeof tabId !== 'number') [{ id: tabId } = {}] = await ext.tabs.query({ active: true, lastFocusedWindow: true });
        if (typeof tabId !== 'number') throw new Error('no tab');
        await ext.tabs.update(tabId, { url });
      },
      openWeb: (url) => ext.tabs.create({ url }),
    });
    return { via: used.via };
  },

  async 'popup.show-teams'(msg) {
    const section = ['shared', 'invites', 'confirm', 'members', 'notices'].includes(msg.section) ? msg.section : '';
    return agent('app.show_teams', section ? { section } : {});
  },

  async 'popup.show-item'(msg) {
    const url = requireWebUrl(await tabUrl(msg.tabId));
    return editCall('app.show_item', { url, id: itemId(msg.id) }, promptFor(msg));
  },

  /**
   * The native host starts the desktop app only when it is spawned and finds no agent, so this closes the
   * port and asks again; the fresh host waits up to ~15 s for Passyble.
   */
  async 'popup.start'() {
    client.disconnect();
    unavailableUntil = 0;
    const status = await agent('status');
    refreshActiveBadges();
    return status;
  },

  /**
   * Hands a `pass+server://` link or a server address to the desktop app (`server.pair`), checked here first
   * so bad input never leaves the browser. A link's token passes through once, never logged or stored.
   */
  async 'popup.server-pair'(msg) {
    if (await inBrowserMode()) throw new PassError(ErrorCode.NOT_SUPPORTED, 'Passyble Server sync for the vault in this browser comes later');
    const text = typeof msg.link === 'string' ? msg.link.trim() : '';
    const address = !!text && !/^pass\+server:/i.test(text);
    let info;
    let link;
    if (address) {
      info = normalizeServerAddress(text); // throws invalid_params
      link = info.url;
    } else {
      info = parsePairingLink(text); // throws invalid_params
      link = text;
    }
    let res;
    try {
      res = await agent('server.pair', { link });
    } catch (err) {
      const e = PassError.from(err);
      // An older desktop app answers "unknown method server.pair".
      if (e.code === ErrorCode.INVALID_PARAMS && /unknown method/i.test(e.message)) {
        throw new PassError(ErrorCode.NOT_SUPPORTED, 'This Passyble desktop app is too old to add a Passyble Server', Reason.NEEDS_UPDATE);
      }
      throw e;
    }
    if (address) {
      return { shown: res?.shown !== false, host: String(res?.host || info.host), user: null, sign_in: true, address: true };
    }
    return { shown: res?.shown !== false, host: String(res?.host || info.host), user: String(res?.user || info.username),
      sign_in: info.kind === 'invite' };
  },
};

const popupStateCore = pageHandlers['popup.state'];

pageHandlers['popup.state'] = async function popupState(msg, sender) {
  account.syncWithApp().catch(() => {});
  if (!(await inBrowserMode())) {
    const core = await popupStateCore(msg, sender);
    const offer = await moveOffer().catch(() => null);
    return offer && core && typeof core === 'object' ? { ...core, move_offer: offer } : core;
  }
  const url = await tabUrl(msg.tabId).catch(() => '');
  const status = await agent('status');
  if (status.vault === false) return { url, supported: isWebUrl(url), locked: true, no_vault: true, browser: true };
  const opened = !!pendingAsk && !!unlockAsk && unlockAsk.tabId === Number(msg.tabId) && Date.now() - unlockAsk.at < UNLOCK_ASK_TTL_MS;
  const core = await popupStateCore(msg, sender);
  const extras = await browserPopupExtras();
  if (extras.ask && pendingAsk) pendingAsk.shown = true;
  return { ...core, ...extras, ask_opened: opened && !!extras.ask };
};

async function moveOffer() {
  if (!browserVaultSupported()) return null;
  const rec = await storedBrowserVault();
  const move = rec ? await moveRecord(rec.id) : null;
  return moveOfferDue(move, { mode: await getVaultMode(), hasVault: !!rec }) ? { count: move.count } : null;
}

Object.assign(pageHandlers, {
  async 'update.state'() {
    const gate = await versionCheck.state();
    const dismissed = await versionCheck.dismissed();
    return {
      required: gate.required === true,
      recommended: gate.recommended === true && !!gate.recommendedVersion && dismissed !== gate.recommendedVersion,
      minimum: gate.minimum ?? null,
      recommended_version: gate.recommendedVersion ?? null,
      message: typeof gate.message === 'string' ? gate.message : '',
      version: ownVersion(ext),
    };
  },

  async 'update.dismiss'() {
    const gate = await versionCheck.state();
    if (gate.recommendedVersion) await versionCheck.dismiss(gate.recommendedVersion);
    return { dismissed: true };
  },

  async 'update.apply'() {
    const gate = await versionCheck.state();
    return applyUpdate({ ext, platform: gate.platform, waitReady: waitUpdateReady });
  },
});

/** Whether the Passyble app owns the account: app mode, or nothing chosen and the first run found an app. */
async function accountAppMode() {
  if (!browserVaultSupported()) return true;
  await detecting.catch(() => {});
  const mode = await getVaultMode();
  if (mode) return mode !== VaultMode.BROWSER;
  const got = await ext.storage.local.get(HOST_SEEN_KEY).catch(() => ({}));
  return got?.[HOST_SEEN_KEY] !== 'missing';
}

/** The desktop app's account calls (app mode only); any failure makes account.js use the extension's own account. */
async function appAccountCall(method, params = {}) {
  if (await inBrowserMode()) throw new PassError(ErrorCode.NOT_SUPPORTED, 'browser mode');
  return agent(method, params, { automatic: true });
}

const appAccount = {
  status: () => appAccountCall('account.status'),
  show: (params) => appAccountCall('app.show_account', params),
};

const PEER_TIMEOUT_MS = 15_000;

/**
 * The same-computer handoff with the Passyble app, straight to the native host (agent() would ask the browser
 * vault in browser mode). Never when no host was found for this browser, nor right after it was unavailable.
 */
const appPeer = {
  async call(method, params = {}) {
    const got = await ext.storage.local.get(HOST_SEEN_KEY).catch(() => ({}));
    if (got?.[HOST_SEEN_KEY] === 'missing' || Date.now() < unavailableUntil) {
      throw new PassError(ErrorCode.AGENT_UNAVAILABLE, 'Passyble desktop app is not running');
    }
    try {
      return await client.request(method, params, { timeoutMs: PEER_TIMEOUT_MS });
    } catch (err) {
      const e = PassError.from(err);
      if (e.code === ErrorCode.AGENT_UNAVAILABLE) unavailableUntil = Date.now() + BACKOFF_MS;
      throw e;
    }
  },
  end() {
    inBrowserMode().then((browser) => { if (browser) client.disconnect(); }).catch(() => {});
  },
};

const account = createAccount({
  ext, appMode: accountAppMode, app: appAccount, peer: appPeer,
  // The Passyble app signed this browser out: the shared vaults of that account close.
  onSignedOut: () => teamsInstance?.signedOut(),
});

/** The browser vault's account keys (a linked vault opens with the Passyble password); sends nothing until the user acts. */
const accountKeys = createAccountKeys({
  glue: async () => (await loadWasm((p) => ext.runtime.getURL(p))).glue,
  account,
  local,
  store: defaultKeyStore(),
  session: ext.storage.session,
});

async function linkedBrowserVault() {
  return !!(await accountKeys.vaultLink().catch(() => null));
}

async function requireAccountKeys() {
  if (await accountAppMode()) throw new PassError(ErrorCode.NOT_SUPPORTED, 'The Passyble app on this computer holds the account key');
}

/** The Passyble password and what comes with it, from a page's message (never kept here). */
function accountPasswordParams(msg) {
  const password = typeof msg.password === 'string' ? msg.password : '';
  if (!password || [...password].length > MAX_ACCOUNT_PASSWORD) throw new PassError(ErrorCode.INVALID_PARAMS, 'No Passyble password');
  return {
    password,
    secretKey: typeof msg.secret_key === 'string' ? msg.secret_key.slice(0, 128) : '',
    shared: msg.shared === true,
    email: typeof msg.email === 'string' ? msg.email.slice(0, 254) : '',
  };
}

const TEAMS_SEEN_KEY = `teamsSeen`; // backticks: not a message name (test/i18n.test.js)
let teamsInstance = null;

/** The browser vault's Teams and Family, built on first use; sends no request without a signed-in account with shared vaults. */
function browserTeams() {
  teamsInstance ??= createBrowserTeams({
    glue: async () => (await loadWasm((p) => ext.runtime.getURL(p))).glue,
    local,
    account,
    orgApi: createOrgApi({ account }),
    files: createCloudFiles(),
    sends: createSendClient({ account }),
    store: defaultTeamsStore(),
    seen: {
      get: async () => (await ext.storage.local.get(TEAMS_SEEN_KEY).catch(() => ({})))?.[TEAMS_SEEN_KEY] || {},
      set: (v) => ext.storage.local.set({ [TEAMS_SEEN_KEY]: v }),
    },
    deviceName: () => 'Browser',
    homeName: () => t('bannerMyVault'),
    settings: async () => vaultConfig(),
    cloudState: ext.storage?.session ? {
      get: async () => (await ext.storage.session.get(TEAMS_CLOUD_KEY))?.[TEAMS_CLOUD_KEY] ?? null,
      set: async (v) => ext.storage.session.set({ [TEAMS_CLOUD_KEY]: v }),
      remove: async () => ext.storage.session.remove(TEAMS_CLOUD_KEY),
    } : undefined,
    cloudAlarm: setCloudAlarm,
    online: () => globalThis.navigator?.onLine !== false,
  });
  return teamsInstance;
}

// The Cloud device and the check times: storage.session (memory, extension pages only) outlives a sleeping worker.
const TEAMS_CLOUD_KEY = `teamsCloud`; // backticks: not a message name (test/i18n.test.js)

/** The minute alarm of quick Passyble Cloud checks; on only while the plan is live and the vault unlocked. */
async function setCloudAlarm(on) {
  if (!ext.alarms) return;
  if (!on) { await ext.alarms.clear?.(CLOUD_SYNC_ALARM); return; }
  if (!(await ext.alarms.get?.(CLOUD_SYNC_ALARM))) await ext.alarms.create(CLOUD_SYNC_ALARM, { periodInMinutes: CLOUD_SYNC_PERIOD_MIN });
}

/** A quick check of the shared vault files (browser mode); the desktop app keeps its own cadence. */
function cloudPull(reason) {
  return (async () => {
    if (!(await inBrowserMode()) || !(await account.current().catch(() => null))) return setCloudAlarm(false);
    return browserTeams().pull(reason);
  })().catch((err) => console.debug?.('[Passyble] cloud check', err?.code || err));
}

Object.assign(pageHandlers, {
  async 'teams.model'(msg) {
    if (!(await inBrowserMode())) return null;
    if (!(await account.current().catch(() => null))) return null;
    const out = await browserTeams().refresh({ force: msg?.force === true });
    cloudPull('popup');
    return out;
  },
  /** A quick key confirmation from the popup, after the user compared the fingerprint. */
  async 'teams.confirm'(msg) {
    if (!(await inBrowserMode())) throw new PassError(ErrorCode.NOT_SUPPORTED, 'Confirm people in the Passyble app');
    return browserTeams().confirm(String(msg.org || ''), String(msg.account || ''), String(msg.fingerprint || ''));
  },
  /** The manager who signed a shared vault's members list, verified after the user compared the fingerprint with them. */
  async 'teams.verify-signer'(msg) {
    if (!(await inBrowserMode())) throw new PassError(ErrorCode.NOT_SUPPORTED, 'Compare fingerprints in the Passyble app');
    return browserTeams().verifySigner(String(msg.vault || ''), String(msg.fingerprint || ''));
  },
  /** Secure send from the popup (browser mode): a text sealed here, the key only in the link. */
  async 'teams.send-create'(msg) {
    if (!(await inBrowserMode())) throw new PassError(ErrorCode.NOT_SUPPORTED, 'Use the Passyble app');
    return browserTeams().sendCreate({ text: msg.text, days: msg.days, maxViews: msg.maxViews, password: msg.password });
  },
  /** "Sync now": every vault that syncs, one sync at a time. `{ synced, failed: [{ vault, reason }], no_sync, browser }`. */
  async 'popup.sync'() {
    return vaultSync.syncNow();
  },
});

/** Whether the browser vault has anything that syncs: only shared vaults of Teams and Family (its own vault never does). */
async function browserCanSync() {
  try {
    return hasTeamsApi((await loadWasm((p) => ext.runtime.getURL(p))).glue);
  } catch {
    return false;
  }
}

const vaultSync = createSync({
  browserMode: inBrowserMode,
  appSync: () => callNew(() => agent('sync.now', {})),
  browserSync: async () => {
    const none = { synced: 0, failed: [], no_sync: true };
    if (!(await browserCanSync()) || !(await account.current().catch(() => null))) return none;
    const info = await local.info();
    if (!info.hasVault) throw new PassError(ErrorCode.NO_VAULT, 'No vault in this browser yet');
    // The shared vaults open with the keys of the vault here: unlocked first.
    if (info.locked) throw new PassError(ErrorCode.LOCKED, 'Vault is locked');
    const res = await browserTeams().syncNow();
    return { synced: res.synced, no_sync: res.none,
      failed: res.failed.map((f) => ({ vault: f.vault, reason: t(teamsErrorKey(f.code)) })) };
  },
});

Object.assign(pageHandlers, {
  /** Signed in or not, and as whom; no token ever leaves the background. */
  async 'account.status'() {
    return account.statusWithApp();
  },
  async 'account.sign-in'() {
    return account.signIn();
  },
  /** A password sign-in made here: the password and the Secret Key never leave the browser. */
  async 'account.password-sign-in'(msg) {
    await requireAccountKeys();
    const { password, secretKey, shared, email } = accountPasswordParams(msg);
    const res = await accountKeys.signIn({ email, password, secretKey, shared });
    if (res.unlocked) refreshActiveBadges();
    return { ...(await account.status()), unlocked: res.unlocked };
  },
  async 'account.keys-state'() {
    const browser = !(await accountAppMode());
    return { available: browser, linked: browser ? await accountKeys.unlockInfo().catch(() => null) : null };
  },
  async 'account.approval-start'(msg) {
    await requireAccountKeys();
    return accountKeys.approvalStart({ email: typeof msg.email === 'string' ? msg.email.slice(0, 254) : '', shared: msg.shared === true });
  },
  /** The request's state: waiting, code (the 6 digits), check (the keys arrived: their fingerprint), denied, expired. */
  async 'account.approval-poll'() {
    await requireAccountKeys();
    return accountKeys.approvalPoll();
  },
  /** `matches` keeps the arrived keys after the user compared fingerprints; anything else drops them. */
  async 'account.approval-confirm'(msg) {
    await requireAccountKeys();
    const res = await accountKeys.approvalConfirm({ matches: msg.matches === true });
    if (res.state === 'done' && res.unlocked) refreshActiveBadges();
    return res;
  },
  async 'account.approval-cancel'() {
    return accountKeys.approvalCancel();
  },

  async 'account.sign-out'(msg) {
    const out = await account.signOut({ alsoApp: msg?.also_app === true });
    await teamsInstance?.signedOut().catch(() => {});
    return out;
  },
  async 'account.use-app-account'() {
    return account.useAppAccount();
  },
});

Object.assign(pageHandlers, {
  async 'vault.state'(msg) {
    if (msg?.probe === true) await lookForApp({ every: 15_000 }).catch(() => {});
    return vaultState();
  },

  /** To the app: the browser vault is locked and kept. To the browser: only while the Passyble app isn't installed here. */
  async 'vault.set-mode'(msg) {
    if (msg.mode === VaultMode.BROWSER) {
      requireBrowserVault();
      await requireBrowserModeOffered();
      if (!(await vaultState()).has_vault) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser yet');
    } else if (msg.mode !== VaultMode.APP) {
      throw badParams('Bad mode');
    }
    await setVaultMode(msg.mode);
    if (msg.mode === VaultMode.BROWSER) await ext.storage.local.set({ [APP_GONE_KEY]: false }).catch(() => {});
    await onModeChanged();
    return vaultState();
  },

  /** The encrypted vault file (base64url) and its name; it also counts as the backup the delete guard asks for. */
  async 'vault.export'() {
    requireBrowserVault();
    if (!(await inBrowserMode())) throw new PassError(ErrorCode.NOT_SUPPORTED, 'The vault in this browser is not in use');
    const file = await local.exportVault();
    if (!file) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser yet');
    return { file: b64urlEncode(file), name: backupFileName() };
  },

  /** Deletes the browser vault: only with a copy downloaded in the last hour, and with the master password. */
  async 'vault.delete'(msg) {
    requireBrowserVault();
    if (!(await inBrowserMode())) throw new PassError(ErrorCode.NOT_SUPPORTED, 'The vault in this browser is not in use');
    const password = masterPassword(msg.password);
    const info = await local.info();
    if (!info.hasVault) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser yet');
    if (!(info.backedUpAt > 0 && Date.now() - info.backedUpAt < DELETE_BACKUP_MS)) {
      throw new PassError(ErrorCode.INVALID_STATE, 'Download a backup first', Reason.BACKUP_FIRST);
    }
    if (await linkedBrowserVault()) {
      const params = accountPasswordParams(msg);
      if (info.locked) await accountKeys.unlockVault(params);
      else await accountKeys.verify(params);
    } else if (info.locked) {
      await local.unlock(password);
    } else {
      await local.verifyPassword(password);
    }
    await local.deleteVault();
    await updateMasterTips(info.vaultId, clearMasterTip).catch(() => {});
    return vaultState();
  },

  async 'vault.settings'(msg) {
    const patch = sanitizeVaultSettings(msg.settings || {});
    if (Object.keys(patch).length) await ext.storage.local.set(patch);
    await applyVaultSettings();
    return getVaultSettings();
  },

  async 'vault.move'(msg) {
    await moveToApp(msg);
    return vaultState();
  },

  async 'vault.move-targets'() {
    if (await inBrowserMode()) return { vaults: [] };
    const list = await agent('vaults.list').catch(() => null);
    const vaults = (Array.isArray(list?.vaults) ? list.vaults : [])
      .filter((v) => v && typeof v.id === 'string' && v.can_edit !== false && v.open !== false)
      .map((v) => ({ id: v.id, name: typeof v.name === 'string' ? v.name.slice(0, 256) : '', home: v.home === true }));
    return { vaults };
  },

  async 'vault.move-later'() {
    const rec = await storedBrowserVault();
    const move = rec ? await moveRecord(rec.id) : null;
    if (move?.state === MoveState.OFFER) await ext.storage.local.set({ [MOVE_KEY]: { ...move, state: MoveState.LATER } });
    return vaultState();
  },

  /** Deletes the browser vault after a move, only when every item is in the Passyble app ('moved'). */
  async 'vault.delete-moved'(msg) {
    requireBrowserVault();
    if (msg.confirmed !== true) throw badParams('Not confirmed');
    if (await inBrowserMode()) throw new PassError(ErrorCode.INVALID_STATE, 'The vault in this browser is in use');
    const rec = await storedBrowserVault();
    if (!rec?.id) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser');
    if ((await moveRecord(rec.id))?.state !== MoveState.MOVED) {
      throw new PassError(ErrorCode.INVALID_STATE, 'Move the items into the Passyble app first');
    }
    await local.deleteVault();
    await updateMasterTips(rec.id, clearMasterTip).catch(() => {});
    await ext.storage.local.remove(MOVE_KEY).catch(() => {});
    return vaultState();
  },

  /** The core's master password rule for a new password being typed (no secrets in the answer); never logged or kept. */
  async 'vault.check-master'(msg) {
    requireBrowserVault();
    const password = typeof msg.password === 'string' ? msg.password : '';
    if (password.length > MAX_MASTER_PASSWORD) throw badParams('Bad master password');
    return masterPasswordRule(password, msg.names);
  },

  /** Creates a vault kept only in this browser. The master password is never kept and must pass the rule (pass-wasm checks it again). */
  async 'vault.create'(msg) {
    requireBrowserVault();
    await requireBrowserModeOffered();
    const password = masterPassword(msg.password, { create: true });
    if (!(await masterPasswordRule(password, msg.names)).ok) {
      throw new PassError(ErrorCode.INVALID_PARAMS, 'This master password is too easy to guess');
    }
    const res = await local.create(password);
    await updateMasterTips(res.vault_id, clearMasterTip).catch(() => {});
    await useBrowserVault();
    return { vault_id: res.vault_id };
  },

  async 'vault.file-access'(msg) {
    requireBrowserVault();
    const access = await local.fileAccess(vaultFileOf(msg.file));
    if (access?.kind !== 'account') return { kind: access?.kind || 'password' };
    return { kind: 'account', ...(await accountKeys.fileInfo(String(access.account || ''), String(access.ak_id || ''))) };
  },

  async 'vault.open-file'(msg) {
    requireBrowserVault();
    await requireBrowserModeOffered();
    const file = vaultFileOf(msg.file);
    const access = await local.fileAccess(file);
    if (access?.kind === 'account') {
      const res = await accountKeys.openFile(file, access, accountPasswordParams(msg));
      await useBrowserVault();
      return { vault_id: res.vault_id };
    }
    const password = masterPassword(msg.password);
    const res = await local.openFile(file, password);
    await recordMasterTip(password);
    await useBrowserVault();
    return { vault_id: res.vault_id };
  },

  async 'vault.master-tip-dismiss'() {
    if (!(await inBrowserMode())) throw new PassError(ErrorCode.NOT_SUPPORTED, 'The vault in this browser is not in use');
    const info = await local.info();
    if (info.hasVault) await updateMasterTips(info.vaultId, dismissMasterTip);
    return vaultState();
  },

  async 'vault.reminder-dismiss'() {
    if (!(await inBrowserMode())) throw new PassError(ErrorCode.NOT_SUPPORTED, 'The vault in this browser is not in use');
    const info = await local.info();
    if (isLocalOnlyVault(info)) {
      await ext.storage.local.set({ [LOCAL_REMINDER_KEY]: dismissLocalReminder(await reminderDismissals(), info.vaultId) });
    }
    return vaultFlags(info);
  },

  async 'vault.check-app'() {
    return checkForApp();
  },

  async 'popup.ask-get'() {
    if (!pendingAsk) return null;
    pendingAsk.shown = true;
    return publicAsk();
  },

  /** The popup's answer to askUser by its token: `cancel`, the master password for `verify`, or `yes`. */
  async 'popup.ask-answer'(msg) {
    const ask = pendingAsk;
    if (!ask || typeof msg.token !== 'string' || msg.token !== ask.token) throw new PassError(ErrorCode.NOT_FOUND, 'Nothing to answer');
    if (msg.cancel === true) { ask.reject(cancelledError()); return { done: true }; }
    if (ask.kind === 'verify') {
      const { grant } = await linkedBrowserVault()
        ? await accountKeys.verify(accountPasswordParams(msg))
        : await local.verifyPassword(masterPassword(msg.password));
      ask.resolve({ grant });
      return { done: true };
    }
    if ((ask.kind === 'card' || ask.kind === 'cross' || ask.kind === 'lookalike') && msg.yes === true) { ask.resolve({ yes: true }); return { done: true }; }
    throw badParams('Bad answer');
  },
});

const SEARCH_LIMIT = 20;
// The popup's notes list: the agent's largest page (a note is a title, so this stays small).
const NOTES_LIMIT = 200;
const FIELD_LIMITS = Object.freeze({ title: 256, username: 512, password: 4096, notes: 20_000 });
const MAX_URLS = 32;
const MAX_URL = 2048;
const URL_RULES = ['subdomains', 'host', 'never'];
const MAX_SITE_QUERY = 256;
const SITE_SUGGESTIONS = 6;
const MAX_TOTP = 2048;
// The native host takes messages up to 8 MiB; leave room for the envelope.
const MAX_CAPTURE = 7 * 1024 * 1024;
// `vaults.set_pins`: the agent takes at most 5 ids of vaults it knows; a few unknown ones may ride along.
const MAX_PIN_IDS = 32;

function badParams(what) {
  return new PassError(ErrorCode.INVALID_PARAMS, what, Reason.BAD_REQUEST);
}

function vaultId(id) {
  if (typeof id !== 'string' || !id || id.length > 128) throw badParams('Bad vault id');
  return id;
}

function itemId(id) {
  if (typeof id !== 'string' || !id || id.length > 128) throw badParams('Bad item id');
  return id;
}

function totpParam(value, allowEmpty) {
  if (value === null && allowEmpty) return null;
  if (typeof value !== 'string' || value.length > MAX_TOTP || (!allowEmpty && !value.trim())) throw badParams('Bad 2FA secret');
  return value;
}

/** Only the editable fields, with their types and lengths checked (the agent checks them again). */
function editFields(input) {
  const src = input && typeof input === 'object' ? input : {};
  const out = {};
  for (const [key, max] of Object.entries(FIELD_LIMITS)) {
    if (src[key] === undefined) continue;
    if (typeof src[key] !== 'string' || src[key].length > max) throw badParams(`Bad ${key}`);
    out[key] = src[key];
  }
  if (src.urls !== undefined) {
    if (!Array.isArray(src.urls) || src.urls.length > MAX_URLS ||
      !src.urls.every((u) => typeof u === 'string' && u.length <= MAX_URL)) throw badParams('Bad websites');
    out.urls = [...src.urls];
  }
  if (src.totp !== undefined) out.totp = totpParam(src.totp, true);
  if (src.url_rules !== undefined) {
    if (!Array.isArray(src.url_rules) || src.url_rules.length > MAX_URLS || !src.url_rules.every((r) => r && typeof r.url === 'string' &&
      r.url.length <= MAX_URL && URL_RULES.includes(r.rule))) throw badParams('Bad website rules');
    out.url_rules = src.url_rules.map(({ url, rule }) => ({ url, rule }));
  }
  return out;
}

function noteFields(input) {
  const src = input && typeof input === 'object' ? input : {};
  const title = typeof src.title === 'string' ? src.title.trim() : '';
  const notes = typeof src.notes === 'string' ? src.notes : '';
  if (!title || title.length > FIELD_LIMITS.title) throw badParams('Bad title');
  if (src.notes !== undefined && typeof src.notes !== 'string') throw badParams('Bad notes');
  if (notes.length > FIELD_LIMITS.notes) throw badParams('Bad notes');
  return { title, notes };
}

async function editCall(method, params, unlockOpts) {
  try {
    return await withUnlock(() => agent(method, params), unlockOpts);
  } catch (err) {
    const e = PassError.from(err);
    if (e.code === ErrorCode.INVALID_PARAMS && /unknown method/i.test(e.message)) {
      throw new PassError(ErrorCode.NOT_SUPPORTED, 'This Passyble desktop app is too old to edit logins', Reason.NEEDS_UPDATE);
    }
    throw e;
  }
}

/** `data:image/png;base64,…` → base64url without padding, the protocol's form for binary values. */
function dataUrlToB64url(dataUrl) {
  const comma = typeof dataUrl === 'string' ? dataUrl.indexOf(',') : -1;
  if (comma < 0 || !/;base64$/i.test(dataUrl.slice(0, comma))) throw new PassError(ErrorCode.CANT_READ_PAGE, "Can't read this page");
  return dataUrl.slice(comma + 1).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** A screenshot of the active tab (PNG, or JPEG when too big for the native host), sent to the agent once and not kept. */
async function captureTab(tabId) {
  const tab = await ext.tabs.get(Number(tabId));
  requireWebUrl(tab?.url);
  if (!tab.active) throw new PassError(ErrorCode.OPEN_QR_PAGE_FIRST, 'Open the page with the QR code first');
  let dataUrl;
  try {
    dataUrl = await ext.tabs.captureVisibleTab(tab.windowId, { format: 'png' });
    if (dataUrl.length > MAX_CAPTURE) dataUrl = await ext.tabs.captureVisibleTab(tab.windowId, { format: 'jpeg', quality: 92 });
  } catch {
    throw new PassError(ErrorCode.CANT_READ_PAGE, "Can't read this page");
  }
  if (typeof dataUrl !== 'string' || dataUrl.length > MAX_CAPTURE) throw new PassError(ErrorCode.PAGE_TOO_LARGE, t('bgPageTooLarge'));
  return { url: tab.url, image: dataUrlToB64url(dataUrl) };
}

const UI_FONT_FILES = [
  ['src/ui/fonts/space-grotesk-latin-wght-normal.woff2', 'U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC, U+0304, U+0308, U+0329, U+2000-206F, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD'],
  ['src/ui/fonts/space-grotesk-latin-ext-wght-normal.woff2', 'U+0100-02BA, U+02BD-02C5, U+02C7-02CC, U+02CE-02D7, U+02DD-02FF, U+1D00-1DBF, U+1E00-1E9F, U+1EF2-1EFF, U+2020, U+20A0-20AB, U+20AD-20C0, U+2113, U+2C60-2C7F, U+A720-A7FF'],
];
let uiFontPromise = null;

function uiFont() {
  if (!uiFontPromise) {
    uiFontPromise = Promise.all(UI_FONT_FILES.map(async ([path, range]) => {
      const res = await fetch(ext.runtime.getURL(path));
      if (!res.ok) throw new Error(`font ${res.status}`);
      const bytes = new Uint8Array(await res.arrayBuffer());
      let bin = '';
      for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      return { data: btoa(bin), range };
    })).then((faces) => ({ faces })).catch((err) => { uiFontPromise = null; throw err; });
  }
  return uiFontPromise;
}

const cardSave = createCardSave({
  agent, withUnlock, getSettings, agentFeatures, tabState, tabs, frameUrl,
  isNeverSave: (url) => isNeverSave(url, NEVER_SAVE_CARDS_KEY),
  addNeverSave: (url) => addNeverSave(url, NEVER_SAVE_CARDS_KEY),
  sendToTop: (tabId, message) => ext.tabs.sendMessage(tabId, message, { frameId: 0 }),
  extensionUrl: (path) => ext.runtime.getURL(path),
});
Object.assign(contentHandlers, cardSave.contentHandlers);
Object.assign(pageHandlers, cardSave.pageHandlers);

const noteClip = createNoteClip({ ext, agent, editCall, noteFields, itemId });
Object.assign(pageHandlers, noteClip.pageHandlers);

// Read-only below the minimum version (forced updates): content scripts get only these, extension pages lose
// these too, and agent() refuses the rest of what isn't view or copy.
const CONTENT_WHILE_READ_ONLY = new Set(['ui.font', 'menu.target', 'clipboard.copied']);
const REFUSED_WHILE_READ_ONLY = new Set([
  'popup.fill', 'popup.fill-cross', 'popup.copy', 'popup.totp', 'popup.edit-get', 'popup.edit-save', 'popup.edit-move', 'popup.edit-delete',
  'popup.edit-restore', 'popup.totp-check', 'popup.totp-scan', 'popup.totp-attach', 'popup.note-create', 'popup.generate-email', 'popup.server-pair',
  'popup.identity-copy', 'clip.append', 'clip.create', 'save.edit-get', 'save.edit-set', 'card.edit-get', 'card.edit-set', 'vault.create', 'vault.open-file',
]);

ext.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || typeof msg.type !== 'string' || sender.id !== ext.runtime.id) return false;
  let handler = null;
  if (isExtensionPage(sender)) handler = pageHandlers[msg.type];
  else if (sender.tab && typeof sender.tab.id === 'number') handler = contentHandlers[msg.type];
  if (!handler) return false;
  const page = isExtensionPage(sender);
  Promise.resolve()
    .then(async () => {
      const refused = page ? REFUSED_WHILE_READ_ONLY.has(msg.type) : !CONTENT_WHILE_READ_ONLY.has(msg.type);
      if (refused && await versionCheck.blocked()) throw extensionUpdateError();
      return handler(msg, sender);
    })
    .then((result) => sendResponse({ ok: true, result: result ?? null }),
      (err) => sendResponse({ ok: false, error: PassError.from(err).toJSON() }));
  return true; // async response
});

function focusFrame(tabId) {
  const f = tabs.get(tabId)?.focus;
  return f && Date.now() - f.at < FOCUS_TTL_MS ? f.frameId : 0;
}

async function sendToFrame(tabId, message, frameId) {
  return ext.tabs.sendMessage(tabId, message, { frameId });
}

/** Sends a fill command to the frame that last had a login field focused (else the top frame). */
async function sendToFillFrame(tabId, message) {
  const frameId = focusFrame(tabId);
  if (frameId !== 0) {
    try {
      const res = await sendToFrame(tabId, message, frameId);
      if (res?.ok) return res;
    } catch { /* frame gone: fall back to the top frame */ }
  }
  try {
    return await sendToFrame(tabId, message, 0);
  } catch {
    // No content script (tab opened before install): inject, then wait for main.js to load.
    await injectContentScripts(tabId);
    for (let i = 0; i < 10; i++) {
      await new Promise((r) => setTimeout(r, 150));
      try { return await sendToFrame(tabId, message, 0); } catch { /* not ready yet */ }
    }
    throw new PassError(ErrorCode.CANNOT_RUN_HERE, t('bgCannotRunHere'));
  }
}

const commands = createCommands({
  ext,
  isWebUrl,
  blocked: () => versionCheck.blocked(),
  sendToFillFrame,
  notify: (tabId, text) => sendToFrame(tabId, { type: 'cmd.notice', text }, 0),
  lock: () => pageHandlers['popup.lock'](),
  generate: async (url) => {
    const symbols = !(url && await prefersNoSymbols(url).catch(() => false));
    try {
      const res = await contentHandlers.generate({ length: DEFAULT_LENGTH, ...(symbols ? {} : { symbols: false }) });
      if (typeof res?.password === 'string' && res.password && (symbols || isPlainPassword(res.password))) {
        return { password: res.password, byAgent: res.local !== true };
      }
    } catch { /* the desktop app is not running: generated here */ }
    return { password: generatePassword({ length: DEFAULT_LENGTH, symbols }), byAgent: false };
  },
  copy: async (password, byAgent) => {
    if (byAgent) {
      try {
        await contentHandlers['generate.copy']({ password });
        return { ok: true, byApp: true };
      } catch { /* an older desktop app: the browser's clipboard */ }
    }
    const ok = await writeClipboard(ext, password).catch(() => false);
    if (ok) await clipboardClearer.schedule(password).catch(() => {});
    return { ok, byApp: false };
  },
  sync: () => vaultSync.syncNow(),
  syncText: (outcome) => syncOutcome(outcome).text,
  t,
  errorText: (err) => friendlyError(PassError.from(err)),
});

ext.commands?.onCommand.addListener((command, tab) => {
  commands.handle(command, tab).catch((err) => console.warn('[Passyble] command failed', err));
});

const MENU_ID = 'pass-fill';
const MENU_GENERATE = 'pass-generate';
const MENU_GENERATE_PLAIN = 'pass-generate-plain';
const MENU_USERNAME = 'pass-generate-username';
const MENU_ALIAS = 'pass-generate-alias';
const WEB_PAGES = ['http://*/*', 'https://*/*'];

async function createMenus() {
  try { await ext.contextMenus.removeAll(); } catch { /* none yet */ }
  ext.contextMenus.create({ id: MENU_ID, title: t('ctxFill'), contexts: ['editable'],
    documentUrlPatterns: WEB_PAGES }, () => void ext.runtime.lastError);
  // Hidden until a content script reports a right-click on a password field ('menu.target').
  generateMenuVisible = false;
  for (const [id, title] of [[MENU_GENERATE, t('ctxGenerate')], [MENU_GENERATE_PLAIN, t('ctxGenerateNoSymbols')]]) {
    ext.contextMenus.create({ id, title, contexts: ['editable'], documentUrlPatterns: WEB_PAGES, visible: false },
      () => void ext.runtime.lastError);
  }
  // Hidden until a username or e-mail field is right-clicked and the desktop app can (setUsernameMenusVisible).
  for (const [id, title] of [[MENU_USERNAME, t('ctxGenerateUsername')], [MENU_ALIAS, t('ctxGenerateAlias')]]) {
    menuVisible.set(id, false);
    ext.contextMenus.create({ id, title, contexts: ['editable'], documentUrlPatterns: WEB_PAGES, visible: false },
      () => void ext.runtime.lastError);
  }
  ext.contextMenus.create({ id: MENU_SAVE_SELECTION, title: t('ctxSaveSelection'), contexts: ['selection'],
    documentUrlPatterns: WEB_PAGES }, () => void ext.runtime.lastError);
}

/**
 * Context menus can't be limited to one kind of input, so the generate items are shown or hidden on each
 * right-click (`menu.target`). The browser may build the menu before the update lands; the frame checks the click again.
 */
let generateMenuVisible = false;
function setGenerateMenuVisible(visible) {
  if (visible === generateMenuVisible) return;
  generateMenuVisible = visible;
  for (const id of [MENU_GENERATE, MENU_GENERATE_PLAIN]) {
    try {
      ext.contextMenus.update(id, { visible }, () => void ext.runtime.lastError);
    } catch { /* menu not created yet */ }
  }
}

const menuVisible = new Map();
const ALIAS_OPTIONS_TTL_MS = 30_000;
let aliasOptions = null;
let usernameMenusSeq = 0; // only the latest right-click decides
async function setUsernameMenusVisible(usernameField) {
  const seq = ++usernameMenusSeq;
  let username = false;
  let alias = false;
  if (usernameField) {
    try {
      const features = await agentFeatures({ automatic: true });
      username = features.includes('generate.username');
      alias = features.includes('generate.email') && (await aliasServicesSetUp());
    } catch { /* Passyble not running: nothing to offer */ }
  }
  if (seq !== usernameMenusSeq) return;
  setMenuVisible(MENU_USERNAME, username);
  setMenuVisible(MENU_ALIAS, alias);
}

async function aliasServicesSetUp() {
  if (aliasOptions && Date.now() - aliasOptions.at < ALIAS_OPTIONS_TTL_MS) return aliasOptions.any;
  try {
    const opts = await agent('generate.options', {}, { automatic: true });
    aliasOptions = { at: Date.now(), any: Array.isArray(opts?.aliases) && opts.aliases.length > 0 };
  } catch {
    return aliasOptions?.any ?? false; // locked: what the last answer said
  }
  return aliasOptions.any;
}

function setMenuVisible(id, visible) {
  if ((menuVisible.get(id) ?? false) === visible) return;
  menuVisible.set(id, visible);
  try {
    ext.contextMenus.update(id, { visible }, () => void ext.runtime.lastError);
  } catch { /* menu not created yet */ }
}

// "Generate e-mail alias" was clicked in this frame: its `generate.email` may create one alias.
const ALIAS_CLICK_TTL_MS = 60_000;
let aliasClick = null;

async function sendToFrameInjecting(tabId, message, frameId) {
  try {
    return await sendToFrame(tabId, message, frameId);
  } catch {
    await injectContentScripts(tabId);
    for (let i = 0; i < 10; i++) {
      await new Promise((r) => setTimeout(r, 150));
      try { return await sendToFrame(tabId, message, frameId); } catch { /* not ready yet */ }
    }
    throw new PassError(ErrorCode.CANNOT_RUN_HERE, t('bgCannotRunHere'));
  }
}

ext.contextMenus.onClicked.addListener(async (info, tab) => {
  if (!tab?.id) return;
  if (await versionCheck.blocked()) return; // read-only until updated: nothing fills or generates into a page
  if (info.menuItemId === MENU_SAVE_SELECTION) {
    noteClip.onMenuClick(info, tab).catch(() => console.warn('[Passyble] the note chooser did not open'));
    return;
  }
  if (info.menuItemId === MENU_GENERATE || info.menuItemId === MENU_GENERATE_PLAIN) {
    // The frame that was right-clicked fills the field it remembers from the `contextmenu` event.
    const symbols = info.menuItemId === MENU_GENERATE;
    sendToFrameInjecting(tab.id, { type: 'cmd.generate-here', symbols }, info.frameId ?? 0)
      .catch((err) => console.warn('[Passyble] context menu generate failed', err));
    return;
  }
  if (info.menuItemId === MENU_USERNAME || info.menuItemId === MENU_ALIAS) {
    const kind = info.menuItemId === MENU_ALIAS ? 'alias' : 'username';
    const frameId = info.frameId ?? 0;
    if (kind === 'alias') aliasClick = { tabId: tab.id, frameId, at: Date.now() };
    sendToFrameInjecting(tab.id, { type: 'cmd.generate-username-here', kind }, frameId)
      .catch((err) => console.warn('[Passyble] context menu generate failed', err));
    return;
  }
  if (info.menuItemId !== MENU_ID) return;
  sendToFrame(tab.id, { type: 'cmd.fill-login', fromContextMenu: true }, info.frameId ?? 0)
    .catch(() => sendToFillFrame(tab.id, { type: 'cmd.fill-login', fromContextMenu: true }))
    .catch((err) => console.warn('[Passyble] context menu fill failed', err));
});

/** Injects content scripts into tabs that were open before install / update. */
async function injectContentScripts(tabId) {
  const target = { tabId, allFrames: true };
  try {
    await ext.scripting.executeScript({ target, files: ['src/content/bridge.js'] });
    await ext.scripting.executeScript({ target, files: ['src/content/webauthn-main.js'], world: 'MAIN' });
    await ext.scripting.executeScript({ target, files: ['src/content/loader.js'] });
  } catch { /* restricted page (store, settings) or tab gone */ }
}

async function showWelcomeOnce() {
  const { welcomeShown } = await ext.storage.local.get({ welcomeShown: false });
  if (welcomeShown) return;
  await ext.storage.local.set({ welcomeShown: true });
  await openWelcome();
}

ext.runtime.onInstalled.addListener(async (details) => {
  createMenus();
  // Removes stale settings. Backticks: not message names (test/i18n.test.js looks at quoted strings).
  Promise.resolve().then(() => ext.storage.local.remove(`revealFilled`)).catch(() => {});
  Promise.resolve().then(() => ext.storage.local.remove(`vaultAppTip`)).catch(() => {});
  // Firefox reports 'install' each time a temporary add-on is loaded, so `welcomeShown` keeps it to one tab.
  if (details?.reason === 'install') {
    detecting = detectMode().catch(() => {});
    showWelcomeOnce().catch(() => {});
  } else if (details?.reason === 'update') {
    lookForApp({ every: 0 }).catch(() => {});
  }
  versionCheck.check().catch(() => {});
  const open = await ext.tabs.query({ url: ['http://*/*', 'https://*/*'] });
  for (const tab of open) injectContentScripts(tab.id);
});
ext.runtime.onStartup?.addListener(() => {
  createMenus();
  versionCheck.check().catch(() => {});
  lookForApp({ every: 0 }).catch(() => {});
});
// A Chromium service worker starts often: the stored decision at once, a check when one is due.
versionCheck.start().catch(() => {});

// The count is drawn into the icon (the browser's badge covers half of it), falling back to the badge
// without OffscreenCanvas.
const ICON_SIZES = [16, 24, 32];
const iconCache = new Map();
let baseIcon = null;

// The count's characters as strokes in a 1 x 1 box (no text rendering: fillText in a service
// worker's OffscreenCanvas can take the worker down, and then every message to it fails).
const GLYPHS = {
  0: [[[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]]],
  1: [[[0.2, 0.2], [0.55, 0], [0.55, 1]]],
  2: [[[0, 0], [1, 0], [1, 0.5], [0, 0.5], [0, 1], [1, 1]]],
  3: [[[0, 0], [1, 0], [1, 1], [0, 1]], [[0.15, 0.5], [1, 0.5]]],
  4: [[[0, 0], [0, 0.55], [1, 0.55]], [[0.8, 0], [0.8, 1]]],
  5: [[[1, 0], [0, 0], [0, 0.5], [1, 0.5], [1, 1], [0, 1]]],
  6: [[[1, 0], [0, 0], [0, 1], [1, 1], [1, 0.5], [0, 0.5]]],
  7: [[[0, 0], [1, 0], [0.45, 1]]],
  8: [[[0, 0], [1, 0], [1, 1], [0, 1], [0, 0]], [[0, 0.5], [1, 0.5]]],
  9: [[[1, 0.5], [0, 0.5], [0, 0], [1, 0], [1, 1], [0, 1]]],
  '+': [[[0.5, 0.1], [0.5, 0.9]], [[0.1, 0.5], [0.9, 0.5]]],
};

function drawGlyphs(g, text, cx, cy, h) {
  const w = h * 0.6;
  const gap = h * 0.3;
  let x = cx - (text.length * w + (text.length - 1) * gap) / 2;
  const top = cy - h / 2;
  for (const ch of text) {
    for (const line of GLYPHS[ch] || []) {
      g.beginPath();
      line.forEach(([px, py], i) => (i ? g.lineTo : g.moveTo).call(g, x + px * w, top + py * h));
      g.stroke();
    }
    x += w + gap;
  }
}

async function countIcon(n, otp) {
  const key = `${n}:${otp ? 1 : 0}`;
  if (iconCache.has(key)) return iconCache.get(key);
  baseIcon ??= fetch(ext.runtime.getURL('icons/icon-128.png')).then((r) => r.blob()).then((b) => createImageBitmap(b));
  const logo = await baseIcon;
  const out = {};
  for (const size of ICON_SIZES) {
    const canvas = new OffscreenCanvas(size, size);
    const g = canvas.getContext('2d');
    g.imageSmoothingQuality = 'high';
    g.drawImage(logo, 0, 0, size, size);
    if (n > 0) {
      const text = n > 9 ? '9+' : String(n);
      const r = size * (text.length > 1 ? 0.3 : 0.25);
      const cx = size - r;
      const cy = r;
      g.beginPath();
      g.arc(cx, cy, r + Math.max(1, size / 16), 0, Math.PI * 2);
      g.fillStyle = '#ffffff';
      g.fill();
      g.beginPath();
      g.arc(cx, cy, r, 0, Math.PI * 2);
      g.fillStyle = otp ? '#b45309' : '#111111';
      g.fill();
      g.strokeStyle = '#ffffff';
      g.lineWidth = Math.max(1, size / 14);
      g.lineCap = 'round';
      g.lineJoin = 'round';
      drawGlyphs(g, text, cx, cy, r * (text.length > 1 ? 0.8 : 1.05));
    }
    out[size] = g.getImageData(0, 0, size, size);
  }
  iconCache.set(key, out);
  return out;
}

async function showCount(action, tabId, n, otp) {
  if (typeof OffscreenCanvas === 'function' && typeof createImageBitmap === 'function' && action.setIcon) {
    try {
      await action.setIcon({ tabId, imageData: await countIcon(n, otp) });
      action.setBadgeText({ tabId, text: '' }).catch(() => {});
      return;
    } catch { /* fall back to the badge */ }
  }
  action.setBadgeText({ tabId, text: n ? String(n) : '' }).catch(() => {});
  action.setBadgeBackgroundColor?.({ tabId, color: otp ? '#b45309' : '#111111' })?.catch?.(() => {});
}

async function updateBadge(tabId, url) {
  const action = ext.action;
  if (!action) return;
  const set = (n, title, otp = false) => {
    showCount(action, tabId, n, otp);
    action.setTitle({ tabId, title }).catch(() => {});
  };
  if (!isWebUrl(url)) { set(0, t('actionTitle')); return; }
  try {
    const found = await agent('logins.find', { url }, { automatic: true });
    const n = (found.items || []).length;
    const title = n ? tp(found.locked ? 'badgeLoginsLocked' : 'badgeLogins', n) : found.locked ? t('badgeLocked') : t('actionTitle');
    set(n, title, !!found.pending_otp);
  } catch (err) {
    const code = PassError.from(err).code;
    set(0, code === ErrorCode.LOCKED ? t('badgeLocked') : code === ErrorCode.AGENT_UNAVAILABLE ? t('badgeNotRunning') : t('actionTitle'));
  }
}

async function refreshActiveBadges() {
  try {
    for (const tab of await ext.tabs.query({ active: true })) updateBadge(tab.id, tab.url);
  } catch { /* ignore */ }
}

async function broadcastToActiveTabs(message) {
  try {
    for (const tab of await ext.tabs.query({ active: true })) {
      ext.tabs.sendMessage(tab.id, message).catch(() => {});
    }
  } catch { /* ignore */ }
}

ext.tabs.onActivated.addListener(async ({ tabId }) => {
  try { updateBadge(tabId, (await ext.tabs.get(tabId)).url); } catch { /* tab gone */ }
});
ext.tabs.onUpdated.addListener((tabId, info, tab) => {
  if (info.status === 'complete' && tab.active) updateBadge(tabId, tab.url);
});
