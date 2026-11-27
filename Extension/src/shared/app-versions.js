// Forced and recommended updates: the pure part every context shares (fetch and cache live in background/app-versions.js).
// A missing or malformed value never blocks. The admin's message is plain text, shown with textContent only.

/** The platform keys of this extension (Brave and every other Chromium browser count as Chrome). */
export const Platform = Object.freeze({
  CHROME: 'extension-chrome',
  EDGE: 'extension-edge',
  FIREFOX: 'extension-firefox',
  OPERA: 'extension-opera',
});

/** Where each browser's "Update" goes; the server never sends an update URL. */
export const STORE_URLS = Object.freeze({
  [Platform.CHROME]: 'https://chromewebstore.google.com/search/Passyble',
  [Platform.EDGE]: 'https://microsoftedge.microsoft.com/addons/search/Passyble',
  [Platform.FIREFOX]: 'https://addons.mozilla.org/firefox/addon/passyble/',
  [Platform.OPERA]: 'https://addons.opera.com/en/search/?query=Passyble',
});

/** storage.local key for the background's decision for this extension version (see gateBlocks). */
export const UPDATE_GATE_KEY = `appVersionGate`;

const MAX_MESSAGE = 280;

/** The agent methods a read-only Passyble still answers; `cards.fill` only as a copy (see allowedWhileReadOnly). */
const READ_ONLY_METHODS = Object.freeze(new Set([
  'status', 'unlock', 'unlock.options', 'unlock.password', 'unlock.hello', 'unlock.cancel', 'lock',
  'logins.search', 'logins.copy', 'cards.list', 'identities.list', 'notes.list', 'notes.get', 'app.show_item', 'icons.get',
  'password.check', 'generate', 'generate.options', 'generate.username', 'generate.copy',
  'account.status', 'app.show_account',
]));

export function allowedWhileReadOnly(method, params) {
  if (READ_ONLY_METHODS.has(method)) return true;
  return method === 'cards.fill' && params?.purpose === 'copy' && typeof params?.field === 'string' && params.field !== '';
}

/** Firefox by `runtime.getBrowserInfo` (only Gecko has it); Edge and Opera by brands or UA tokens; other Chromium is Chrome. */
export async function detectPlatform({ api = globalThis.browser ?? globalThis.chrome, nav = globalThis.navigator } = {}) {
  const getInfo = api?.runtime?.getBrowserInfo;
  if (typeof getInfo === 'function') {
    try { await getInfo.call(api.runtime); } catch { /* still Gecko: no other browser has it */ }
    return Platform.FIREFOX;
  }
  return chromiumPlatform(nav);
}

export function chromiumPlatform(nav = globalThis.navigator) {
  let brands = [];
  try { brands = Array.isArray(nav?.userAgentData?.brands) ? nav.userAgentData.brands : []; } catch { /* none */ }
  const names = brands.map((b) => String(b?.brand || ''));
  if (names.some((n) => /^Microsoft Edge\b/i.test(n))) return Platform.EDGE;
  if (names.some((n) => /^Opera\b/i.test(n))) return Platform.OPERA;
  const ua = String(nav?.userAgent || '');
  if (/\bEdg(?:e|A|iOS)?\//.test(ua)) return Platform.EDGE;
  if (/\bOPR\//.test(ua)) return Platform.OPERA;
  return Platform.CHROME;
}

const STRICT_RE = /^(\d{1,9})\.(\d{1,9})\.(\d{1,9})(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseVersion(value) {
  if (typeof value !== 'string') return null;
  const m = STRICT_RE.exec(value);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

/** This extension's manifest version as three numbers; null when unreadable (then nothing is ever blocked). */
export function parseOwnVersion(value) {
  if (typeof value !== 'string') return null;
  const m = /^(\d{1,9})(?:\.(\d{1,9}))?(?:\.(\d{1,9}))?(?:\.\d{1,9})?(?:[-+][0-9A-Za-z.+-]*)?$/.exec(value.trim());
  return m ? [Number(m[1]), Number(m[2] || 0), Number(m[3] || 0)] : null;
}

export function compareVersions(a, b) {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i] ? -1 : 1;
  }
  return 0;
}

export function cleanMessage(value) {
  if (typeof value !== 'string') return '';
  const text = value.replace(/\r\n?/g, '\n').replace(/[\u0000-\u0009\u000B-\u001F\u007F]/g, ' ').trim();
  return Array.from(text).slice(0, MAX_MESSAGE).join('').trim();
}

export function isVersionsResponse(data) {
  return !!data && typeof data === 'object' && data.v === 1 &&
    !!data.platforms && typeof data.platforms === 'object' && !Array.isArray(data.platforms);
}

const NONE = Object.freeze({ required: false, recommended: false, minimum: null, recommendedVersion: null, message: '' });

/** What `data` means for `platform` at `current`: `{ required, recommended, minimum, recommendedVersion, message }`. */
export function evaluateVersions(data, platform, current) {
  if (!isVersionsResponse(data) || typeof platform !== 'string') return { ...NONE };
  const entry = Object.hasOwn(data.platforms, platform) ? data.platforms[platform] : null;
  const own = parseOwnVersion(current);
  if (!entry || typeof entry !== 'object' || Array.isArray(entry) || !own) return { ...NONE };
  const min = parseVersion(entry.minimum);
  const rec = parseVersion(entry.recommended);
  const required = !!min && compareVersions(own, min) < 0;
  const recommended = !required && !!rec && compareVersions(own, rec) < 0;
  return {
    required,
    recommended,
    minimum: min ? min.join('.') : null,
    recommendedVersion: rec ? rec.join('.') : null,
    message: cleanMessage(entry.message),
  };
}

/** A gate written for another version never blocks, so an extension update clears the block at once. */
export function gateBlocks(gate, version) {
  return !!gate && typeof gate === 'object' && gate.required === true &&
    typeof version === 'string' && version !== '' && gate.version === version;
}

export function ownVersion(api = globalThis.browser ?? globalThis.chrome) {
  try {
    const v = api?.runtime?.getManifest?.()?.version;
    return typeof v === 'string' ? v : '';
  } catch {
    return '';
  }
}

export async function extensionBlocked(api = globalThis.browser ?? globalThis.chrome) {
  const version = ownVersion(api);
  if (!version) return false;
  try {
    const got = await api.storage.local.get(UPDATE_GATE_KEY);
    return gateBlocks(got?.[UPDATE_GATE_KEY], version);
  } catch {
    return false;
  }
}

export function onExtensionBlockedChange(fn, api = globalThis.browser ?? globalThis.chrome) {
  const onChanged = api?.storage?.onChanged;
  if (!onChanged?.addListener) return () => {};
  const listener = (changes, area) => {
    if (area !== 'local' || !changes || !Object.hasOwn(changes, UPDATE_GATE_KEY)) return;
    fn(gateBlocks(changes[UPDATE_GATE_KEY]?.newValue, ownVersion(api)));
  };
  onChanged.addListener(listener);
  return () => { try { onChanged.removeListener?.(listener); } catch { /* gone */ } };
}
