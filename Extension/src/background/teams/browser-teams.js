// Teams and Family in browser mode: the shared vaults of the user's organisations and direct shares, opened
// with the home vault's keyset and used beside it. Only for a signed-in Passyble account that has any.
//
// A vault key is only ever wrapped to contact keys this user verified (pins in the home vault). The account
// service's "confirmed" or "replaced" flags are never verification: unpinned or changed keys are left out of
// every member change until the user compares fingerprints.
//
// Shared vaults are open only while the home vault is unlocked; nothing decrypted is ever stored.
//
// This browser can't add or remove a vault's own password (that stays in the apps), so a Team rule of
// `second_password` keeps that Team's vaults read-only here until the vault with its keys has one.
import { ErrorCode, PassError } from '../../shared/errors.js';
import { afterCheck, cadenceOf, cloudLive, PLAN_CODES, shouldCheck, TRANSIENT_CODES } from './cloud-cadence.js';
import {
  applyFields, groupsJson, homeRef, mergeFind, mergeSaveCheck, mergeSearch, newLoginItem, sharedRef, urlRulesOf, vaultIdOf, withoutRules,
  withRights,
} from './multi.js';
import { consoleUrl, corePolicy, passwordMode, TeamsHttpError } from './org-api.js';
import { createBody, linkBaseOf, sealOptions, sendView, SEND_MAX_BYTES } from './send-client.js';
import { totpCode, totpInfo } from './totp.js';

const REFRESH_MS = 5 * 60_000;
const SEARCH_LIMIT = 20;
const UPLOAD_TRIES = 3;
const PASSWORD_MODES = Object.freeze(['choice', 'second_password', 'one_password']);
export const PIN_SCOPE = 'personal';
const PIN_STATUSES = Object.freeze(['pinned', 'not_pinned', 'changed']);

export function hasPinApi(agent) {
  return !!agent && ['pinContact', 'contactPinStatus', 'unpinnedChanges'].every((f) => typeof agent[f] === 'function');
}

/** Letters and digits only, upper case, O as 0 and I or L as 1 (as the core's normalize_fingerprint). */
export function normalizeFingerprint(text) {
  return String(text || '').toUpperCase().replace(/[^A-Z0-9]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
}

function pinStatusOf(answer) {
  if (!answer || !PIN_STATUSES.includes(answer.status)) return null;
  return answer.status === 'changed'
    ? { status: 'changed', pinned_fingerprint: String(answer.pinned_fingerprint || '') }
    : { status: answer.status };
}

function accountOfChange(change) {
  return String(change?.keys?.account ?? change?.account ?? '');
}

export const ACROSS_VAULTS = Object.freeze(new Set([
  'logins.find', 'logins.search', 'logins.fill', 'logins.fill_cross', 'logins.copy', 'totp.get', 'totp.popup',
  'logins.save_check', 'logins.save', 'logins.create', 'logins.get_for_edit', 'logins.update', 'logins.delete',
]));

export function hasTeamsApi(glue) {
  return !!glue && ['multiForUrl', 'multiSearch', 'multiDefaultSaveVault', 'policyCheck', 'publicKeysCheck', 'sendSeal', 'sendLink']
    .every((f) => typeof glue[f] === 'function');
}

export function envelope(text) {
  let out;
  try { out = JSON.parse(text); } catch { throw new PassError(ErrorCode.INTERNAL, 'unreadable answer'); }
  if (out?.error) throw new PassError(typeof out.error.code === 'string' ? out.error.code : ErrorCode.INTERNAL, out.error.message);
  return out?.result;
}

/** The `teams_errors` code of an openShared failure. The WebAssembly gives only the core's English message. */
function openErrorCode(err) {
  const text = String(err?.message || err || '');
  if (/not a member|removed|no longer/i.test(text)) return 'not_a_member';
  if (/older|rollback|roll back/i.test(text)) return 'rollback';
  if (/keyset|other keys|keys? (?:do|does)n.t match|mismatch/i.test(text)) return 'keys_mismatch';
  if (/trust|verify|signature|signed/i.test(text)) return 'untrusted';
  return 'internal';
}

function membersNotices(vaultId, name, notice) {
  if (!notice || typeof notice !== 'object') return [];
  const out = [];
  for (const kind of ['reapplied', 'dropped']) {
    const list = notice[kind];
    if (Array.isArray(list) && list.length) out.push({ id: `${kind}:${vaultId}:${Date.now()}`, kind, vault: vaultId, name, count: list.length });
  }
  if (notice.rotated_after_leave) out.push({ id: `rotated:${vaultId}:${Date.now()}`, kind: 'rotated', vault: vaultId, name });
  return out;
}

function ruleOf(r) {
  return { mode: PASSWORD_MODES.includes(r?.mode) ? r.mode : 'choice',
    teams: Array.isArray(r?.teams) ? r.teams.filter((id) => typeof id === 'string') : [] };
}

/**
 * The vaults a Team password rule looks at: `keys` holds the Team's keys, `counted` is what `one_password`
 * checks. `ownPassword()` is true with its own master password, false when linked, null when unknown.
 */
export function teamRuleVaults(local) {
  const home = {
    vault: 'home',
    ownPassword: async () => {
      const access = await local.vaultAccess().catch(() => null);
      return access ? access.kind === 'password' : null;
    },
  };
  return { keys: home, counted: [home] };
}

/** Where the Cloud device and the check times outlive a restarted service worker (storage.session in the extension). */
export function memoryCloudState() {
  let value = null;
  return { get: async () => value, set: async (v) => { value = structuredClone(v); }, remove: async () => { value = null; } };
}

export function createBrowserTeams({ glue, local, account, orgApi, files, sends, store, seen, deviceName, homeName,
  settings = async () => ({ auto_lock_secs: null, verify_each_fill: false }), now = () => Date.now(), log = console,
  cloudState = memoryCloudState(), cloudAlarm = async () => {}, online = () => true, random = Math.random }) {
  let orgs = [];
  let sharingKeys = null;
  let device = null;
  let deviceError = '';
  let deviceWaiting = null;
  let held = [];
  let invites = 0;
  let shared = [];
  let status = 'off';
  let lastError = '';
  let refreshedAt = 0;
  let refreshing = null;
  let generation = -1;
  const open = new Map();
  const errors = new Map();
  const syncedAt = new Map();
  let notices = [];
  let pending = [];
  let policyNotes = [];
  let myFingerprint = '';
  let passwordRule = null;
  let rulePasswords = null;
  let reported = '';
  let pulling = null;
  let filesTurn = Promise.resolve();

  const teamsOn = async () => hasTeamsApi(await glue().catch(() => null));

  function closeAll() {
    for (const o of open.values()) { try { o.sv.free?.(); } catch { /* freed */ } }
    open.clear();
    forgetLists();
  }

  // Lists kept between requests: re-reading every vault's summaries on each popup keystroke is too slow.
  let homeList = null;
  let index = null;

  function forgetLists() {
    homeList = null;
    forgetIndex();
  }

  function homeSummaries(agent) {
    const stamp = typeof agent.homeStamp === 'function' ? agent.homeStamp() : undefined;
    if (stamp && homeList?.stamp === stamp) return homeList.summaries;
    const summaries = envelope(agent.homeSummaries());
    homeList = stamp ? { stamp, summaries } : null;
    return summaries;
  }

  /** A SearchIndex of the lists of `ctx`, kept while the lists are the same objects; null without the API. */
  function indexOf(ctx, g) {
    if (typeof g.SearchIndex !== 'function') return null;
    const lists = ctx.lists;
    if (index && index.lists.length === lists.length && index.lists.every((l, i) => l === lists[i])) return index;
    forgetIndex();
    const flat = ctx.groups.flatMap((group) => (group.summaries || []).map((summary) => ({ vault_id: group.vault_id, summary })));
    index = { lists, index: new g.SearchIndex(groupsJson(ctx.groups)), flat };
    return index;
  }

  function forgetIndex() {
    if (index) { try { index.index.free?.(); } catch { /* freed */ } }
    index = null;
  }

  function lock() {
    closeAll();
    generation = -1;
    Promise.resolve().then(() => cloudAlarm(false)).catch(() => {});
  }

  /** Opens the shared vaults for the current BrowserAgent instance (again after a restart or an unlock). */
  async function ensureOpen() {
    if (!shared.length && !(await store.all().catch(() => [])).length) return false;
    const acc = await account.current().catch(() => null);
    if (!acc?.id) return false;
    const g = await glue();
    if (!hasTeamsApi(g)) return false;
    const recs = await store.all().catch(() => []);
    passwordRule ??= (await seenState()).rule;
    rulePasswords ??= await ruleVaultPasswords();
    return local.withAgent(async (agent, meta) => {
      if (meta.locked) { if (open.size) lock(); return false; }
      if (meta.generation === generation && open.size) return true;
      closeAll();
      generation = meta.generation;
      for (const rec of recs) {
        const entry = shared.find((e) => e.vault_path === rec.path) || rec.entry;
        if (!entry) continue;
        try {
          openOne(agent, rec.file, acc.id, entry, rec.path, rec.etag);
        } catch (err) {
          errors.set(entry.vault_id, openErrorCode(err));
        }
      }
      return open.size > 0;
    });
  }

  function openOne(agent, file, accountId, entry, path, etag) {
    const sv = agent.openShared(file, accountId);
    const o = { sv, entry, path, etag, summaries: null, info: null, ref: null };
    readVault(o);
    open.set(o.info?.vault_id || entry.vault_id, o);
    errors.delete(entry.vault_id);
    const notice = safeEnvelope(sv.takeNotice());
    addNotices(membersNotices(o.ref.id, o.ref.name, notice));
    return o;
  }

  function safeEnvelope(text) {
    try { return envelope(text); } catch { return null; }
  }

  function readVault(o) {
    o.info = envelope(o.sv.info());
    o.summaries = envelope(o.sv.summaries());
    o.ref = refOf(o);
    o.signer = signerOf(o);
  }

  /** What the pins say about the manager who signed the current members list, or null. */
  function signerOf(o) {
    if (typeof o.sv.signerStatus !== 'function') return null;
    const status = pinStatusOf(safeEnvelope(o.sv.signerStatus()));
    if (!status) return null;
    return { ...status, account: String(o.info?.signed_by || ''), fingerprint: String(o.info?.signer_fingerprint || '') };
  }

  function refOf(o) {
    const writable = !['view', 'fill'].includes(o.entry?.role) && errors.get(o.entry?.vault_id) !== 'subscription_inactive'
      && !waitsForSecondPassword(o.entry?.org);
    return sharedRef(o.summaries, o.entry, { writable });
  }

  function waitsForSecondPassword(org) {
    return rulePasswords?.keys !== true && !!passwordRule?.teams.includes(org);
  }

  async function ruleVaultPasswords() {
    const scope = teamRuleVaults(local);
    const counted = await Promise.all(scope.counted.map((v) => v.ownPassword()));
    return { keys: await scope.keys.ownPassword(), counted: counted.includes(true) ? true : counted.includes(null) ? null : false };
  }

  async function context() {
    if (!(await ensureOpen())) return null;
    const home = await local.withAgent(async (agent, meta) => (meta.locked ? null : homeSummaries(agent)));
    if (!home) { forgetLists(); return null; }
    const refs = [homeRef(home, homeName())];
    const groups = [withRights(home, refs[0])];
    const lists = [home];
    const byVault = new Map();
    for (const [id, o] of open) {
      refs.push(o.ref);
      groups.push(withRights(o.summaries, o.ref));
      lists.push(o.summaries);
      byVault.set(id, o);
    }
    return { refs, groups, lists, byVault, homeId: refs[0].id };
  }

  /** The secret item of a shared vault, or null. Callers drop it as soon as they used it. */
  function itemOf(o, id) {
    const text = o.sv.item(id);
    try { return JSON.parse(String(text)); } catch { return null; }
  }

  /** Matches the page whatever its website rules: a hidden login is still filled when the user picks it. */
  async function onPage(ctx, vaultId, id, url) {
    const g = await glue();
    const group = ctx.groups.find((x) => x.vault_id === vaultId);
    const hits = envelope(g.multiForUrl(groupsJson([withoutRules(group)]), String(url || '')));
    return (hits || []).some((h) => h.summary?.id === id);
  }

  /** Stores and uploads a changed shared vault (If-Match; a newer remote copy is merged first). */
  async function upload(o) {
    let file = await local.withAgent(async () => o.sv.save());
    await store.put({ path: o.path, vault_id: o.ref.id, file, etag: o.etag, dirty: true, saved_at: now(), entry: o.entry });
    if (!device) return false;
    for (let i = 0; i < UPLOAD_TRIES; i++) {
      let res;
      try {
        res = await files.upload(device, o.path, file, o.etag);
      } catch (err) {
        errors.set(o.ref.id, err?.code || 'network');
        return false;
      }
      if (!res.conflict) {
        o.etag = res.etag || null;
        await store.put({ path: o.path, vault_id: o.ref.id, file, etag: o.etag, dirty: false, saved_at: now(), entry: o.entry });
        errors.delete(o.ref.id);
        syncedAt.set(o.ref.id, now());
        return true;
      }
      const dl = await files.download(device, o.path, null);
      file = await local.withAgent(async () => {
        const merged = envelope(o.sv.merge(dl.file));
        addNotices(membersNotices(o.ref.id, o.ref.name, merged?.notice));
        readVault(o);
        return o.sv.save();
      });
      o.etag = dl.etag || null;
    }
    errors.set(o.ref.id, 'network');
    return false;
  }

  async function seenState() {
    const s = await seen.get().catch(() => null);
    return { vaults: Array.isArray(s?.vaults) ? s.vaults : [], dismissed: Array.isArray(s?.dismissed) ? s.dismissed : [],
      rule: ruleOf(s?.rule) };
  }

  async function saveSeen(patch) {
    await seen.set({ ...(await seenState()), ...patch }).catch(() => {});
  }

  function addNotices(list) {
    for (const n of list) if (!notices.some((x) => x.kind === n.kind && x.vault === n.vault && x.kind !== 'reapplied')) notices.push(n);
  }

  async function signedOut() {
    closeAll();
    orgs = [];
    shared = [];
    device = null;
    pending = [];
    notices = [];
    policyNotes = [];
    status = 'off';
    passwordRule = null;
    reported = '';
    await store.clear().catch(() => {});
    await saveSeen({ rule: null });
    await cloudState.remove().catch(() => {});
    await Promise.resolve(cloudAlarm(false)).catch(() => {});
  }

  async function publishKeys(acc) {
    const made = await local.withAgent(async (agent, meta) => (meta.locked ? null : envelope(agent.ensureKeyset(acc.id))));
    if (!made) return;
    myFingerprint = made.fingerprint || '';
    if (sharingKeys?.fingerprint === made.fingerprint) return;
    try {
      const res = await orgApi.putKeys(made.public_keys);
      sharingKeys = { fingerprint: res?.fingerprint || made.fingerprint };
    } catch (err) {
      // `reauth_required`: other keys are registered; replacing them needs a fresh sign-in on the website.
      lastError = err?.serviceCode || err?.code || 'internal';
    }
  }

  /** Downloads the shared vaults that changed and uploads unsent changes; the failures, `[{ code, retryAfterMs }]`. */
  function syncFiles(acc, opts) {
    const run = filesTurn.then(() => syncFilesNow(acc, opts));
    filesTurn = run.catch(() => {});
    return run;
  }

  /** A vault whose plan is not live (uploads refused): a quick check skips it, the 5 minute refresh doesn't. */
  function planBlocked(vaultId) {
    return PLAN_CODES.includes(errors.get(vaultId));
  }

  async function syncFilesNow(acc, { fast = false } = {}) {
    const failed = [];
    if (!device) return failed;
    const stored = new Map((await store.all().catch(() => [])).map((r) => [r.path, r]));
    const listed = new Set(shared.map((e) => e.vault_path));
    for (const [path, rec] of stored) {
      if (listed.has(path)) continue;
      const o = [...open.values()].find((x) => x.path === path);
      if (o) { try { o.sv.free?.(); } catch { /* freed */ } open.delete(o.ref.id); }
      await store.remove(path).catch(() => {});
    }
    for (const entry of shared) {
      if (fast && planBlocked(entry.vault_id)) continue;
      const rec = stored.get(entry.vault_path);
      const o = open.get(entry.vault_id) || [...open.values()].find((x) => x.path === entry.vault_path);
      if (o) o.entry = entry;
      let dl;
      try {
        dl = await files.download(device, entry.vault_path, rec?.dirty ? null : rec?.etag || o?.etag || null);
      } catch (err) {
        const code = err?.code || 'network';
        errors.set(entry.vault_id, code);
        failed.push({ code, retryAfterMs: Number(err?.retryAfterMs) || 0 });
        // A busy server is asked again later; a revoked device is replaced at the next refresh.
        if (code === 'busy') return failed;
        if (code === 'signed_out') { await forgetDevice(); return failed; }
        continue;
      }
      if (dl.unchanged) {
        syncedAt.set(entry.vault_id, now());
        if (TRANSIENT_CODES.includes(errors.get(entry.vault_id))) errors.delete(entry.vault_id);
        if (o) readVault(o);
        continue;
      }
      await store.put({ path: entry.vault_path, vault_id: entry.vault_id, file: dl.file, etag: dl.etag, dirty: false, saved_at: now(), entry });
      const opened = await local.withAgent(async (agent, meta) => {
        if (meta.locked) return null;
        if (generation !== meta.generation) { closeAll(); generation = meta.generation; }
        const cur = open.get(entry.vault_id);
        if (cur) {
          const merged = envelope(cur.sv.merge(dl.file));
          addNotices(membersNotices(cur.ref.id, cur.ref.name, merged?.notice));
          cur.etag = dl.etag;
          readVault(cur);
          return merged?.dirty && cur.ref.can_edit ? cur : null;
        }
        try {
          openOne(agent, dl.file, acc.id, entry, entry.vault_path, dl.etag);
        } catch (err) {
          errors.set(entry.vault_id, openErrorCode(err));
        }
        return null;
      });
      syncedAt.set(entry.vault_id, now());
      if (opened) await upload(opened);
    }
    const dirty = new Set((await store.all().catch(() => [])).filter((r) => r.dirty).map((r) => r.path));
    for (const o of open.values()) {
      if (dirty.has(o.path) && o.ref.can_edit) await upload(o);
    }
    return failed;
  }

  async function applyPasswordRule(acc) {
    passwordRule = ruleOf({ mode: passwordMode(orgs),
      teams: orgs.filter((o) => o.kind === 'team' && o.policy?.password_mode === 'second_password').map((o) => o.id) });
    rulePasswords = await ruleVaultPasswords();
    for (const o of open.values()) o.ref = refOf(o);
    const has = rulePasswords.counted;
    if (has === null || !orgs.some((o) => o.kind === 'team')) return;
    const answer = `${acc.id}:${has}`;
    if (answer === reported) return;
    try {
      await orgApi.secondPassword(has);
      reported = answer;
    } catch { /* offline, or refused: sent again at the next refresh */ }
  }

  function unmetRule() {
    if (passwordRule?.mode === 'second_password' && rulePasswords?.keys !== true) return 'second_password';
    if (passwordRule?.mode === 'one_password' && rulePasswords?.counted === true) return 'one_password';
    return null;
  }

  async function loadPending() {
    const out = [];
    for (const org of orgs) {
      try {
        const res = await orgApi.confirmations(org.id);
        for (const p of Array.isArray(res?.pending) ? res.pending : []) {
          if (!p || typeof p.account_id !== 'string') continue;
          out.push({ org: org.id, org_name: String(org.name || ''), org_kind: org.kind, account_id: p.account_id, email: String(p.email || ''),
            fingerprint: String(p.fingerprint || ''), keys: p.keys || null, replaced: p.replaced === true,
            previous_fingerprint: p.previous_fingerprint || null, vaults: Array.isArray(p.vaults) ? p.vaults.map(String) : [] });
        }
      } catch { /* not allowed, offline: nothing to confirm from here */ }
    }
    // Only the pins count: `changed` means other keys than the ones this user verified.
    await local.withAgent(async (agent, meta) => {
      if (meta.locked || !hasPinApi(agent)) return;
      for (const p of out) {
        if (p.keys) p.pin = pinStatusOf(safeEnvelope(agent.contactPinStatus(JSON.stringify(p.keys), PIN_SCOPE)));
      }
    }).catch(() => {});
    pending = out;
  }

  async function checkPolicies() {
    const g = await glue();
    const s = await settings().catch(() => ({}));
    const out = [];
    for (const org of orgs) {
      const policy = corePolicy(org.policy);
      if (!policy) continue;
      const localSec = { auto_lock_secs: s.auto_lock_secs || null, two_step_enabled: org.sign_in_ok !== false };
      if (Number.isFinite(s.master_password_score)) localSec.master_password_score = s.master_password_score;
      try {
        for (const v of envelope(g.policyCheck(JSON.stringify(policy), JSON.stringify(localSec))) || []) {
          out.push({ org: org.id, org_name: String(org.name || ''), rule: String(v.rule || ''), message: String(v.message || '') });
        }
      } catch { /* a policy this build can't read: nothing to say */ }
    }
    policyNotes = out;
  }

  function useDevice(d) {
    device = d || null;
    const entries = Array.isArray(device?.shared) ? device.shared.filter((e) => e && typeof e.vault_path === 'string' && typeof e.vault_id === 'string') : [];
    held = entries.filter((e) => e.held === true).map((e) => ({ name: String(e.label || ''), reason: String(e.hold_reason || '') }));
    shared = entries.filter((e) => e.held !== true);
  }

  async function loadCloud() {
    const raw = await cloudState.get().catch(() => null);
    return raw && typeof raw === 'object' ? raw : {};
  }

  async function saveCloud(patch) {
    await cloudState.set({ ...(await loadCloud()), ...patch }).catch(() => {});
  }

  async function lastDevice(acc) {
    const saved = await loadCloud();
    return saved.account === acc.id && saved.device ? saved.device : null;
  }

  async function forgetDevice() {
    device = null;
    await saveCloud({ device: null });
  }

  /** The vaults whose plan is not live, kept with the device for a restarted service worker. */
  function planCodes() {
    return Object.fromEntries(shared.filter((e) => planBlocked(e.vault_id)).map((e) => [e.vault_id, errors.get(e.vault_id)]));
  }

  async function checked(failed) {
    const saved = await loadCloud();
    await saveCloud({ cadence: afterCheck(cadenceOf(saved.cadence), failed, now(), random) });
  }

  async function liveNow() {
    const locked = (await local.info().catch(() => ({ locked: true }))).locked;
    const vaults = shared.map((e) => e.vault_id);
    return cloudLive({ device, locked, vaults, blocked: vaults.filter(planBlocked) });
  }

  /** The quick check alarm runs only while the Cloud plan is live and the vault unlocked. */
  async function armAlarm() {
    const live = await liveNow();
    await Promise.resolve(cloudAlarm(live)).catch(() => {});
    return live;
  }

  /**
   * A quick check of the shared vault files for `reason` (unlock, online, popup, alarm): conditional GETs only,
   * and the full refresh once the account service's 5 minutes are up. Nothing without a Cloud device.
   */
  function pull(reason) {
    pulling ??= pullOnce(reason).finally(() => { pulling = null; });
    return pulling;
  }

  async function pullOnce(reason) {
    const stop = async (skipped) => { await Promise.resolve(cloudAlarm(false)).catch(() => {}); return { skipped }; };
    if (!(await teamsOn())) return stop('off');
    const acc = await account.current().catch(() => null);
    if (!acc?.id) return stop('signed_out');
    if ((await local.info().catch(() => ({ locked: true }))).locked) return stop('locked');
    let saved = await loadCloud();
    if (saved.account && saved.account !== acc.id) { await cloudState.remove().catch(() => {}); saved = {}; }
    const mine = saved.account === acc.id;
    if (!device && mine && saved.device) {
      useDevice(saved.device);
      for (const [id, code] of Object.entries(saved.plan || {})) if (PLAN_CODES.includes(code) && !errors.has(id)) errors.set(id, code);
    }
    if (!device && !(await store.all().catch(() => [])).length) return stop('no_cloud');
    if (!online()) return { skipped: 'offline' };
    if (!shouldCheck(cadenceOf(mine ? saved.cadence : null), reason, now())) return { skipped: 'wait' };
    if (refreshing) { await refreshing; return { checked: true, live: await liveNow() }; }
    // A refresh that failed waits its 5 minutes too; the files are still checked with the device known.
    const accountAt = Math.max(refreshedAt, mine ? Number(saved.at) || 0 : 0, mine ? Number(saved.triedAt) || 0 : 0);
    if (!accountAt || now() - accountAt >= REFRESH_MS) {
      const before = refreshedAt;
      await saveCloud({ account: acc.id, triedAt: now() });
      await refresh({ force: true });
      if (refreshedAt !== before) return { checked: true, live: await liveNow() };
    }
    if (!(await liveNow())) return stop('not_live');
    await ensureOpen().catch(() => false);
    await checked(await syncFiles(acc, { fast: true }));
    return { checked: true, live: await armAlarm() };
  }

  async function doRefresh() {
    if (!(await teamsOn())) { status = 'off'; return; }
    const acc = await account.current().catch(() => null);
    if (!acc?.id) { await signedOut(); return; }
    lastError = '';
    let me;
    try {
      me = await orgApi.orgs();
    } catch (err) {
      if (err?.code === 'signed_out') { await signedOut(); return; }
      lastError = err?.code || 'network';
      status = open.size ? 'ready' : 'error';
      return;
    }
    orgs = Array.isArray(me?.organisations) ? me.organisations.filter((o) => o && typeof o.id === 'string') : [];
    sharingKeys = me?.sharing_keys || null;
    await applyPasswordRule(acc);
    try {
      invites = ((await orgApi.invites())?.invites || []).length;
    } catch {
      invites = 0;
    }
    let renewed;
    try {
      renewed = await orgApi.cloudDevice(deviceName());
      deviceError = '';
      deviceWaiting = null;
    } catch (err) {
      renewed = null;
      deviceError = err?.serviceCode || err?.code || 'network';
      deviceWaiting = deviceError === 'device_approval_required' ? (err?.data?.approval || {}) : null;
      // Not reached: the last device stays valid until another one replaces it.
      if (err?.status === 0 || err?.status === 429 || err?.status >= 500) renewed = await lastDevice(acc);
    }
    useDevice(renewed);
    if (!orgs.length && !shared.length && !invites) {
      closeAll();
      await store.clear().catch(() => {});
      status = 'none';
      notices = [];
      pending = [];
      policyNotes = [];
      await saveCloud({ account: acc.id, device, at: now(), plan: {} });
      await armAlarm();
      return;
    }
    status = 'ready';
    const unlocked = !(await local.info()).locked;
    if (unlocked) await publishKeys(acc);
    const s = await seenState();
    const ids = shared.map((e) => e.vault_id);
    for (const e of shared) if (!s.vaults.includes(e.vault_id)) addNotices([{ id: `shared:${e.vault_id}`, kind: 'shared', vault: e.vault_id, name: String(e.label || '') }]);
    for (const id of s.vaults) if (!ids.includes(id)) addNotices([{ id: `removed:${id}`, kind: 'removed', vault: id, name: '' }]);
    await saveSeen({ vaults: ids, rule: passwordRule });
    if (device && unlocked) await checked(await syncFiles(acc));
    for (const org of orgs) {
      if (org.keys === 'pending') addNotices([{ id: `awaiting:${org.id}`, kind: 'awaiting', org: org.id, name: String(org.name || '') }]);
    }
    for (const o of open.values()) {
      if (o.info && o.info.anchored === false) {
        addNotices([{ id: `unanchored:${o.ref.id}`, kind: 'unanchored', vault: o.ref.id, name: o.ref.name,
          signed_by: String(o.info.signed_by || ''), fingerprint: String(o.info.signer_fingerprint || '') }]);
      }
    }
    await loadPending();
    await checkPolicies();
    refreshedAt = now();
    await saveCloud({ account: acc.id, device, at: refreshedAt, plan: planCodes() });
    await armAlarm();
  }

  async function refresh({ force = false } = {}) {
    if (!force && refreshedAt && now() - refreshedAt < REFRESH_MS) return model();
    refreshing ??= doRefresh().catch((err) => { lastError = err?.code || 'internal'; log.debug?.('[Passyble] teams refresh', lastError); })
      .finally(() => { refreshing = null; });
    await refreshing;
    return model();
  }

  /** Refresh now and report which shared vaults were reached; `none` when nothing here syncs. */
  async function syncNow() {
    if (refreshing) await refreshing;
    const started = now();
    await refresh({ force: true });
    if (status === 'off' || status === 'none') return { synced: 0, failed: [], none: true };
    if (!shared.length) {
      return status === 'error' ? { synced: 0, failed: [{ vault: '', code: lastError || 'network' }], none: false }
        : { synced: 0, failed: [], none: true };
    }
    let synced = 0;
    const failed = [];
    for (const e of shared) {
      const at = syncedAt.get(e.vault_id);
      const o = open.get(e.vault_id);
      const reached = typeof at === 'number' && at >= started;
      if (reached && (o || !errors.has(e.vault_id))) { synced++; continue; }
      failed.push({ vault: o?.ref?.name || String(e.label || ''), code: errors.get(e.vault_id) || lastError || deviceError || 'network' });
    }
    return { synced, failed, none: false };
  }

  async function model() {
    if (status === 'off' || status === 'none' || (status === 'error' && !orgs.length && !shared.length)) return null;
    const s = await seenState();
    const vaults = [];
    for (const e of shared) {
      const o = open.get(e.vault_id);
      const ref = o?.ref || sharedRef({ vault_id: e.vault_id, role: e.role, can_edit: false, can_reveal: e.role !== 'fill' }, e, { writable: false });
      const code = errors.get(e.vault_id) || '';
      vaults.push({ ...ref, items: o ? (o.summaries?.summaries || []).filter((x) => !x.kind || x.kind === 'login').length : 0,
        open: !!o, error: code ? { code, message: '' } : null, last_sync: syncedAt.get(e.vault_id) ?? null, signer: o?.signer ?? null });
    }
    const shown = notices.filter((n) => !s.dismissed.includes(n.id));
    const confirmable = pending.filter((p) => !waitsForSecondPassword(p.org));
    return {
      vaults,
      teams: { invites, to_confirm: confirmable.length, notices: shown.length },
      browser: {
        status,
        error: lastError || deviceError || '',
        cloud: !!device,
        device_waiting: deviceWaiting,
        held,
        orgs: await Promise.all(orgs.map(async (o) => ({ id: o.id, kind: o.kind === 'family' ? 'family' : 'team', name: String(o.name || ''),
          role: String(o.role || ''), admin: ['owner', 'admin'].includes(o.role), console_url: consoleUrl(await account.base(), o),
          keys: String(o.keys || '') }))),
        fingerprint: myFingerprint || sharingKeys?.fingerprint || '',
        notices: shown,
        policy: policyNotes,
        password_rule: unmetRule(),
        confirm: confirmable.map(({ keys, pin, ...p }) => ({ ...p, vaults: p.vaults.length, pin: pin?.status || null,
          keys_changed: pin?.status === 'changed' || p.replaced })),
        send: orgs.length > 0,
      },
    };
  }

  async function dismiss(id) {
    const s = await seenState();
    if (typeof id === 'string' && id && !s.dismissed.includes(id)) s.dismissed = [...s.dismissed.slice(-199), id];
    notices = notices.filter((n) => n.id !== id);
    await saveSeen({ dismissed: s.dismissed });
    return model();
  }

  /** Pins `keys` after the user compared `typed` (inside withAgent). Without the pin API it refuses. */
  function pinKeys(agent, meta, keys, typed) {
    if (meta.locked) throw new PassError(ErrorCode.LOCKED, 'The vault is locked');
    if (!hasPinApi(agent)) throw new PassError(ErrorCode.NOT_SUPPORTED, 'this build cannot verify keys');
    try {
      return envelope(agent.pinContact(JSON.stringify(keys), PIN_SCOPE, String(typed || '')));
    } catch (err) {
      if (err?.code === ErrorCode.INTERNAL) throw new PassError('fingerprint_mismatch', 'the fingerprint does not match these keys');
      throw err;
    }
  }

  /** Applies member `changes`, leaving out adds and replace_keys whose keys aren't pinned (`left_out`). */
  function changeMembersPinned(agent, o, changes) {
    if (!hasPinApi(agent)) throw new PassError(ErrorCode.NOT_SUPPORTED, 'this build cannot verify keys');
    const problems = (envelope(agent.unpinnedChanges(JSON.stringify(changes))) || [])
      .map((x) => ({ account: String(x?.account || ''), fingerprint: String(x?.fingerprint || ''), ...pinStatusOf(x) }));
    const out = new Set(problems.map((x) => x.account));
    const kept = changes.filter((c) => !out.has(accountOfChange(c)));
    if (kept.length) {
      try {
        envelope(o.sv.changeMembers(JSON.stringify(kept)));
      } catch (err) {
        if (err?.code === ErrorCode.INTERNAL) throw new PassError('keys_not_verified', String(err.message || 'keys not verified'));
        throw err;
      }
      readVault(o);
    }
    return { applied: kept.length, left_out: problems };
  }

  /**
   * Pins the person's keys (the only thing that makes them verified), adds them to the members lists this
   * account manages, uploads, then records the confirmation. With anyone left out it is not recorded.
   */
  async function confirm(orgId, accountId, fingerprint) {
    const p = pending.find((x) => x.org === orgId && x.account_id === accountId);
    if (!p) throw new PassError(ErrorCode.NOT_FOUND, 'nobody waits for this confirmation');
    if (waitsForSecondPassword(orgId)) throw readOnly();
    const typed = String(fingerprint || '').trim();
    if (!typed || normalizeFingerprint(typed) !== normalizeFingerprint(p.fingerprint)) {
      throw new PassError('fingerprint_mismatch', 'the fingerprint changed');
    }
    const g = await glue();
    const check = envelope(g.publicKeysCheck(JSON.stringify(p.keys || {})));
    if (!check?.valid || normalizeFingerprint(check.fingerprint) !== normalizeFingerprint(p.fingerprint) || p.keys?.account !== accountId) {
      throw new PassError('keys_mismatch', 'the keys do not match their fingerprint');
    }
    await ensureOpen();
    await local.withAgent(async (agent, meta) => { pinKeys(agent, meta, p.keys, typed); });
    let regs = [];
    try { regs = (await orgApi.orgVaults(orgId))?.vaults || []; } catch { regs = []; }
    let added = 0;
    let skipped = 0;
    const leftOut = new Map();
    for (const reg of regs) {
      if (!p.vaults.includes(String(reg.id)) && !p.vaults.includes(String(reg.vault_id))) continue;
      const o = open.get(String(reg.vault_id));
      const role = (reg.people || []).find((x) => x.account_id === accountId)?.role;
      if (!o || o.info?.role !== 'manage' || !['manage', 'edit', 'view', 'fill'].includes(role)) { skipped++; continue; }
      const member = (o.info.members || []).find((m) => m.account === accountId);
      let change = null;
      if (!member) change = { op: 'add', keys: p.keys, role };
      else if (normalizeFingerprint(member.fingerprint) !== normalizeFingerprint(p.fingerprint)) change = { op: 'replace_keys', keys: p.keys };
      if (change) {
        const res = await local.withAgent(async (agent) => changeMembersPinned(agent, o, [change]));
        for (const x of res.left_out) leftOut.set(x.account, x);
        if (!res.applied) continue;
        if (!(await upload(o))) throw new PassError('network', 'the vault could not be uploaded');
      }
      added++;
    }
    const left_out = [...leftOut.values()];
    if (left_out.length) return { added, skipped, left_out };
    await orgApi.confirm(orgId, accountId, p.fingerprint);
    pending = pending.filter((x) => x !== p);
    return { added, skipped, left_out };
  }

  /**
   * The member side: pins the keys of the manager who signed a shared vault's members list. The keys must be
   * the very ones in the list, and the core checks the typed fingerprint against them.
   */
  async function verifySigner(vaultId, fingerprint) {
    await ensureOpen();
    const o = open.get(String(vaultId || ''));
    if (!o) throw new PassError(ErrorCode.NOT_FOUND, 'no such vault');
    const account = String(o.info?.signed_by || '');
    const expected = String(o.info?.signer_fingerprint || '');
    if (!account || !expected) throw new PassError(ErrorCode.NOT_FOUND, 'the manager who signed it left');
    const typed = String(fingerprint || '').trim();
    if (!typed || normalizeFingerprint(typed) !== normalizeFingerprint(expected)) {
      throw new PassError('fingerprint_mismatch', 'the fingerprint does not match');
    }
    const org = String(o.entry?.org || o.info?.org || '');
    if (!org) throw new PassError(ErrorCode.NOT_SUPPORTED, 'compare it in the Passyble app');
    const keys = (await orgApi.personKeys(org, account))?.keys || null;
    const g = await glue();
    const check = envelope(g.publicKeysCheck(JSON.stringify(keys || {})));
    if (!check?.valid || keys?.account !== account || normalizeFingerprint(check.fingerprint) !== normalizeFingerprint(expected)) {
      throw new PassError('keys_mismatch', 'the keys do not match the members list');
    }
    await local.withAgent(async (agent, meta) => {
      pinKeys(agent, meta, keys, typed);
      for (const x of open.values()) x.signer = signerOf(x);
    });
    return { vault: o.ref.id, signer: o.signer };
  }

  async function sendCreate({ text, days, maxViews, password }) {
    const g = await glue();
    const data = new TextEncoder().encode(String(text || ''));
    if (!data.length) throw new PassError(ErrorCode.INVALID_PARAMS, 'nothing to send');
    if (data.length > SEND_MAX_BYTES) throw new PassError(ErrorCode.INVALID_PARAMS, 'too large');
    const options = sealOptions({ days, maxViews, password }, now());
    const sealed = g.sendSeal(data, JSON.stringify(options));
    data.fill(0);
    const res = await sends.create(createBody(sealed));
    const id = String(res?.id || '');
    if (!id) throw new PassError(ErrorCode.INTERNAL, 'no send id');
    const link = envelope(g.sendLink(linkBaseOf(res, await sends.linkBase()), id, sealed.key))?.link || '';
    return { id, link, ...sendView({ ...res, id, expires_at: res?.expires_at ?? options.expires_at, max_views: res?.max_views ?? options.max_views }, now()) };
  }

  async function sendList() {
    const res = await sends.list();
    return { sends: (Array.isArray(res?.sends) ? res.sends : []).map((s) => sendView(s, now())).filter((s) => s.id) };
  }

  async function sendRevoke(id) {
    await sends.revoke(id);
    return sendList();
  }

  function readOnly() {
    return new PassError(ErrorCode.READ_ONLY, "You can use this vault's logins but not change them");
  }
  function fillOnly() {
    return new PassError(ErrorCode.FILL_ONLY, 'This login can be filled but not shown or copied');
  }

  async function sharedFill(ctx, o, params, { cross = false, confirmed = false, grant = null }) {
    const id = String(params.id);
    if (cross ? !confirmed : !(await onPage(ctx, o.ref.id, id, params.url))) {
      throw cross ? new PassError(ErrorCode.CANCELLED, 'not confirmed') : new PassError(ErrorCode.URL_MISMATCH, 'not a login of this page');
    }
    if ((await settings().catch(() => ({}))).verify_each_fill && !grant) {
      throw new PassError(ErrorCode.VERIFICATION_REQUIRED, 'confirm with the master password');
    }
    const item = itemOf(o, id);
    if (!item) throw new PassError(ErrorCode.NOT_FOUND, 'no such login');
    const totp = item.totp ? await totpCode(item.totp, now()) : null;
    const out = { username: item.username || '', password: item.password || '', totp, skips_2fa: false, vault: o.ref };
    item.password = '';
    return out;
  }

  async function editAnswer(o, item) {
    const out = { id: item.id, title: item.title || '', username: item.username || '', password: item.password || '',
      urls: Array.isArray(item.urls) ? item.urls : [], url_rules: urlRulesOf(item), notes: item.notes || '',
      totp: item.totp ? await totpInfo(item.totp, now()) : null, vault: o.ref };
    if (!o.ref.can_edit) out.read_only = true;
    return out;
  }

  function summaryAnswer(o, id) {
    const s = (o.summaries?.summaries || []).find((x) => x.id === id) || {};
    return { id, title: s.title || '', username: s.username || '', has_totp: !!s.has_totp,
      has_passkey: Array.isArray(s.passkeys) && s.passkeys.length > 0, vault: o.ref };
  }

  async function saveTo(o, item) {
    if (!o.ref.can_edit) throw readOnly();
    const res = await local.withAgent(async () => { const r = envelope(o.sv.upsert(JSON.stringify(item))); readVault(o); return r; });
    item.password = '';
    await upload(o);
    return res?.id;
  }

  async function defaultVault(ctx, url) {
    const g = await glue();
    try { return envelope(g.multiDefaultSaveVault(groupsJson(ctx.groups), url || undefined, undefined))?.vault_id ?? ctx.homeId; } catch { return ctx.homeId; }
  }

  /** One request across the open vaults; anything else, or with no shared vault open, goes to `next`. */
  async function handle(method, params = {}, next, { confirmed = false, grant = null } = {}) {
    if (!ACROSS_VAULTS.has(method)) return next(params);
    const ctx = await context().catch(() => null);
    if (!ctx) return next(params);
    const g = await glue();
    const sharedOf = (id) => (typeof id === 'string' ? ctx.byVault.get(vaultIdOf(ctx.groups.slice(1), id)) : null);
    switch (method) {
      case 'logins.find': {
        const home = await next(params);
        if (home?.locked) return home;
        const url = String(params.url || '');
        const kept = indexOf(ctx, g);
        const hits = envelope(kept ? kept.index.forUrl(url) : g.multiForUrl(groupsJson(ctx.groups), url));
        return mergeFind(hits, home, ctx.refs);
      }
      case 'logins.search': {
        const home = await next(params);
        if (home?.locked) return home;
        const limit = Math.min(SEARCH_LIMIT, Number(params.limit) || SEARCH_LIMIT);
        const query = String(params.query || '');
        const kept = indexOf(ctx, g);
        const hits = kept
          ? Array.from(kept.index.searchPositions(query), (i) => kept.flat[i])
          : envelope(g.multiSearch(groupsJson(ctx.groups), query));
        return mergeSearch(hits, home, ctx.refs, limit);
      }
      case 'logins.fill':
      case 'logins.fill_cross': {
        const o = sharedOf(params.id);
        if (!o) return next(params);
        return sharedFill(ctx, o, params, { cross: method === 'logins.fill_cross', confirmed, grant });
      }
      case 'totp.get': {
        const o = sharedOf(params.id);
        if (!o) return next(params);
        if (!(await onPage(ctx, o.ref.id, String(params.id), params.url))) throw new PassError(ErrorCode.URL_MISMATCH, 'not a login of this page');
        const item = itemOf(o, String(params.id));
        const code = item?.totp ? await totpCode(item.totp, now()) : null;
        if (!code) throw new PassError(ErrorCode.NOT_FOUND, 'no 2FA code');
        return { ...code, vault: o.ref };
      }
      case 'totp.popup': {
        if (!sharedOf(params.id)) return next(params);
        throw new PassError(ErrorCode.NOT_SUPPORTED, 'not here');
      }
      case 'logins.copy': {
        const o = sharedOf(params.id);
        if (!o) return next(params);
        const field = params.field;
        if (field === 'password' && !o.ref.can_reveal) throw fillOnly();
        const item = itemOf(o, String(params.id));
        if (!item) throw new PassError(ErrorCode.NOT_FOUND, 'no such login');
        let text = '';
        if (field === 'username') text = item.username || '';
        else if (field === 'password') text = item.password || '';
        else if (field === 'totp') text = item.totp ? (await totpCode(item.totp, now()))?.code || '' : '';
        item.password = '';
        if (!text) throw new PassError(ErrorCode.NOT_FOUND, 'nothing to copy');
        local.releaseCopy(text);
        return { copied: true, field };
      }
      case 'logins.save_check': {
        const home = await next(params);
        const url = String(params.url || '');
        const username = String(params.username || '');
        const found = [];
        // Hidden logins count too: one filled by hand is not offered as new.
        for (const o of ctx.byVault.values()) {
          const hits = envelope(g.multiForUrl(groupsJson([withoutRules(withRights(o.summaries, o.ref))]), url)) || [];
          for (const h of hits) {
            const s = h.summary;
            if (!s || (s.kind && s.kind !== 'login')) continue;
            if (username && String(s.username || '').trim().toLowerCase() !== username.trim().toLowerCase()) continue;
            const item = itemOf(o, s.id);
            found.push({ ref: o.ref, id: s.id, title: s.title || '', username: s.username || '', same: !!item && item.password === params.password });
            if (item) item.password = '';
          }
        }
        return mergeSaveCheck(home, found, { refs: ctx.refs, username, defaultVault: await defaultVault(ctx, url) });
      }
      case 'logins.save': {
        const o = sharedOf(params.id);
        if (o) {
          const item = itemOf(o, String(params.id));
          if (!item) throw new PassError(ErrorCode.NOT_FOUND, 'no such login');
          if (params.update === 'username') item.username = String(params.username || '');
          else item.password = String(params.password || '');
          const id = await saveTo(o, item);
          return { id, ...summaryAnswer(o, id) };
        }
        if (params.id) return next(stripVault(params));
        const target = typeof params.vault === 'string' && params.vault ? params.vault : await defaultVault(ctx, params.url);
        if (target === ctx.homeId) return withHome(await next(stripVault(params)), ctx);
        const to = ctx.byVault.get(target);
        if (!to) throw new PassError(ErrorCode.NOT_FOUND, 'no such vault');
        const id = await saveTo(to, newLoginItem({ url: params.url, username: params.username, password: params.password }));
        return { id, ...summaryAnswer(to, id) };
      }
      case 'logins.create': {
        const target = typeof params.vault === 'string' && params.vault ? params.vault : ctx.homeId;
        if (target === ctx.homeId) return withHome(await next(stripVault(params)), ctx);
        const to = ctx.byVault.get(target);
        if (!to) throw new PassError(ErrorCode.NOT_FOUND, 'no such vault');
        const f = params.fields || {};
        const id = await saveTo(to, applyFields(newLoginItem({ url: params.url }), f));
        return { id, ...summaryAnswer(to, id) };
      }
      case 'logins.get_for_edit': {
        const o = sharedOf(params.id);
        if (!o) return withHome(await next(params), ctx);
        if (!o.ref.can_reveal) throw fillOnly();
        const item = itemOf(o, String(params.id));
        if (!item) throw new PassError(ErrorCode.NOT_FOUND, 'no such login');
        return editAnswer(o, item);
      }
      case 'logins.update': {
        const o = sharedOf(params.id);
        if (!o) return next(params);
        if (!o.ref.can_edit) throw readOnly();
        const item = itemOf(o, String(params.id));
        if (!item) throw new PassError(ErrorCode.NOT_FOUND, 'no such login');
        const id = await saveTo(o, applyFields(item, params.fields || {}));
        return { id, ...summaryAnswer(o, id) };
      }
      case 'logins.delete': {
        const o = sharedOf(params.id);
        if (!o) return next(params);
        if (!o.ref.can_edit) throw readOnly();
        await local.withAgent(async () => { envelope(o.sv.delete(String(params.id))); readVault(o); });
        await upload(o);
        return { deleted: true, vault: o.ref };
      }
      default:
        return next(params);
    }
  }

  function stripVault(params) {
    const { vault, ...rest } = params;
    return rest;
  }

  function withHome(res, ctx) {
    return res && typeof res === 'object' ? { ...res, vault: ctx.refs[0] } : res;
  }

  function policies() {
    return orgs.map((o) => corePolicy(o.policy)).filter(Boolean);
  }

  return {
    refresh, syncNow, pull, model, handle, lock, dismiss, confirm, verifySigner, policies, ensureOpen,
    sendCreate, sendList, sendRevoke,
    signedOut,
    get active() { return open.size > 0; },
  };
}

export { TeamsHttpError };
