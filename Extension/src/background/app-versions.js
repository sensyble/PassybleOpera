// Version check for forced and recommended updates. Fetches a public list with no credentials,
// cookies or referrer. The last good answer is cached; with none, nothing is blocked.
// The resulting gate is written to storage.local and names its version, so a stale gate never blocks
// a newer build.
import {
  STORE_URLS, UPDATE_GATE_KEY, evaluateVersions, gateBlocks, isVersionsResponse, parseOwnVersion,
} from '../shared/app-versions.js';

export const VERSIONS_URL = 'https://account.passyble.com/api/app-versions';
export const VERSIONS_PATH = '/api/app-versions';
export const VERSIONS_ALARM = 'pass-app-versions';
export const CHECK_PERIOD_MIN = 6 * 60;
export const FETCH_TIMEOUT_MS = 10_000;
// A failed check is tried again on the next background start after this long (the alarm keeps 6 hours).
const RETRY_AFTER_MS = 15 * 60_000;
// storage.local: { at, data } of the last good answer, and { at, ok } of the last try.
export const CACHE_KEY = `appVersionsCache`;
export const TRIED_KEY = `appVersionsTried`;
export const DISMISSED_KEY = `appVersionDismissed`;
const MAX_BODY = 64 * 1024;

const NO_GATE = Object.freeze({ required: false, recommended: false, minimum: null, recommendedVersion: null, message: '' });

export function createVersionCheck({ ext, version, platform, fetch: fetchFn = (...a) => globalThis.fetch(...a),
  url = async () => VERSIONS_URL, now = () => Date.now(), timeoutMs = FETCH_TIMEOUT_MS }) {
  let gate = null;
  let running = null;
  const listeners = new Set();

  const enabled = () => !!parseOwnVersion(version());

  async function read(key) {
    try { return (await ext.storage.local.get(key))?.[key] ?? null; } catch { return null; }
  }

  async function write(obj) {
    try { await ext.storage.local.set(obj); } catch { /* storage gone: the next check writes again */ }
  }

  async function fetchVersions() {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
      const res = await fetchFn(await url(), {
        method: 'GET',
        credentials: 'omit',
        cache: 'no-cache',
        referrerPolicy: 'no-referrer',
        redirect: 'follow',
        signal: ctrl.signal,
      });
      if (!res || !res.ok) throw new Error(`app-versions: HTTP ${res?.status}`);
      const text = await res.text();
      if (text.length > MAX_BODY) throw new Error('app-versions: answer too large');
      const data = JSON.parse(text);
      if (!isVersionsResponse(data)) throw new Error('app-versions: unexpected answer');
      return { v: 1, platforms: data.platforms };
    } finally {
      clearTimeout(timer);
    }
  }

  async function evaluate() {
    const current = version();
    if (!enabled()) return { ...NO_GATE };
    const key = await platform().catch(() => null);
    if (!key) return { ...NO_GATE };
    const cache = await read(CACHE_KEY);
    const decided = evaluateVersions(cache?.data, key, current);
    const next = { ...decided, version: current, platform: key, fetchedAt: typeof cache?.at === 'number' ? cache.at : null };
    const before = await read(UPDATE_GATE_KEY);
    if (JSON.stringify(before) !== JSON.stringify(next)) await write({ [UPDATE_GATE_KEY]: next });
    return next;
  }

  function refresh() {
    const p = evaluate();
    gate = p.catch(() => ({ ...NO_GATE }));
    p.then((g) => { for (const fn of listeners) { try { fn(g); } catch { /* a listener's own problem */ } } }, () => {});
    return gate;
  }

  function check() {
    if (!enabled()) return Promise.resolve({ ...NO_GATE });
    if (running) return running;
    running = (async () => {
      let ok = false;
      try {
        const data = await fetchVersions();
        await write({ [CACHE_KEY]: { at: now(), data } });
        ok = true;
      } catch {
        // Offline or a bad answer: keep the cached one.
      }
      await write({ [TRIED_KEY]: { at: now(), ok } });
      return refresh();
    })().finally(() => { running = null; });
    return running;
  }

  async function start() {
    if (!enabled()) return;
    refresh();
    try {
      const alarm = await ext.alarms?.get?.(VERSIONS_ALARM);
      if (!alarm) await ext.alarms?.create?.(VERSIONS_ALARM, { delayInMinutes: CHECK_PERIOD_MIN, periodInMinutes: CHECK_PERIOD_MIN });
    } catch { /* no alarms: checks at each start only */ }
    const tried = await read(TRIED_KEY);
    const since = typeof tried?.at === 'number' ? now() - tried.at : Infinity;
    if (!(since >= 0) || since >= (tried?.ok === false ? RETRY_AFTER_MS : CHECK_PERIOD_MIN * 60_000)) check();
  }

  return {
    start,
    check,
    state: () => (enabled() ? (gate ?? refresh()) : Promise.resolve({ ...NO_GATE })),
    async blocked() {
      if (!enabled()) return false;
      return gateBlocks(await (gate ?? refresh()), version());
    },
    onAlarm(alarm) {
      if (alarm?.name === VERSIONS_ALARM) check().catch(() => {});
    },
    onChange(fn) { listeners.add(fn); return () => listeners.delete(fn); },
    async dismissed() {
      const v = await read(DISMISSED_KEY);
      return typeof v === 'string' ? v : '';
    },
    async dismiss(recommendedVersion) {
      if (typeof recommendedVersion === 'string' && recommendedVersion) await write({ [DISMISSED_KEY]: recommendedVersion.slice(0, 64) });
    },
  };
}

export function storeUrl(platform) {
  return STORE_URLS[platform] || STORE_URLS['extension-chrome'];
}

/**
 * Asks the browser for an update and reloads into it when there is one; otherwise (none yet, throttled, or no
 * requestUpdateCheck in Firefox and Safari) opens the store page. Answers before the reload ends the popup.
 */
export async function applyUpdate({ ext, platform, waitReady = async () => {}, schedule = (fn) => setTimeout(fn, 50) }) {
  const rt = ext.runtime;
  if (typeof rt?.requestUpdateCheck === 'function') {
    let status = null;
    try {
      const res = await rt.requestUpdateCheck();
      status = Array.isArray(res) ? res[0] : typeof res === 'string' ? res : res?.status;
    } catch { /* fall back to the store */ }
    if (status === 'update_available' && typeof rt.reload === 'function') {
      schedule(async () => {
        try { await waitReady(30_000); } catch { /* reload anyway */ }
        try { rt.reload(); } catch { /* nothing to do */ }
      });
      return { reloading: true };
    }
  }
  const url = storeUrl(platform);
  try { await ext.tabs.create({ url }); } catch { /* no tabs API: nothing else to open */ }
  return { store: url };
}
