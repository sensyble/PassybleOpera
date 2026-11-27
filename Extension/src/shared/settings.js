import { ext } from './api.js';

// The keys are also read by content/bridge.js (a classic script): keep them in sync.
export const DEFAULT_SETTINGS = Object.freeze({
  inlineMenu: true,
  autoFillOtp: true, // same site, within 3 minutes
  passkeys: true,
  autoPasskey: true,
  saveBanner: true,
  autoGenerate: true,
  autoSuggest: true,
  formFill: true,
  cardSave: true,
  mentionWebsite: false,
});

// Synced via chrome.storage.sync (no secrets); everything else stays in chrome.storage.local.
const SYNC_KEYS = new Set(['autoGenerate', 'autoSuggest', 'autoPasskey']);
const keysFor = (sync) => Object.keys(DEFAULT_SETTINGS).filter((k) => SYNC_KEYS.has(k) === sync);

async function read(area, keys) {
  try {
    const store = ext.storage?.[area];
    if (!store) return {};
    return (await store.get(keys)) || {};
  } catch {
    return {};
  }
}

export async function getSettings() {
  // Synced keys are read from local too: setSettings falls back to it when sync is unavailable.
  const all = Object.keys(DEFAULT_SETTINGS);
  const [local, sync] = await Promise.all([read('local', all), read('sync', keysFor(true))]);
  return { ...DEFAULT_SETTINGS, ...sanitize(local, all), ...sanitize(sync, keysFor(true)) };
}

export async function setSettings(patch) {
  const local = sanitize(patch, keysFor(false));
  const sync = sanitize(patch, keysFor(true));
  if (Object.keys(local).length) await ext.storage.local.set(local);
  if (Object.keys(sync).length) {
    // storage.sync can be unavailable (some Firefox setups, policies): keep the value locally then.
    try { await ext.storage.sync.set(sync); } catch { await ext.storage.local.set(sync); }
  }
}

export function onSettingsChanged(callback) {
  const listener = (changes, area) => {
    if (area !== 'local' && area !== 'sync') return;
    if (Object.keys(changes).some((k) => k in DEFAULT_SETTINGS)) getSettings().then(callback);
  };
  ext.storage.onChanged.addListener(listener);
  return () => ext.storage.onChanged.removeListener(listener);
}

function sanitize(obj, keys) {
  const out = {};
  for (const key of keys) {
    if (obj && typeof obj[key] === 'boolean') out[key] = obj[key];
  }
  return out;
}
