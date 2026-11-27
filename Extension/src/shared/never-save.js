// Keyed by origin: without a public-suffix list a registrable domain cannot be computed reliably (co.uk, github.io).
// Written by the background (from the sender URL the browser reports) and by the options page (removal).
import { ext } from './api.js';

export const NEVER_SAVE_KEY = 'neverSave';
export const NEVER_SAVE_CARDS_KEY = 'neverSaveCards';

/** The origin of an http(s) URL, or '' for anything else (including an opaque "null" origin). */
function siteOf(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'http:' || u.protocol === 'https:' ? u.origin : '';
  } catch {
    return '';
  }
}

function clean(list) {
  const out = new Set();
  for (const v of Array.isArray(list) ? list : []) {
    const site = typeof v === 'string' ? siteOf(v) : '';
    if (site && site === v) out.add(site);
  }
  return [...out].sort();
}

export async function getNeverSave(key = NEVER_SAVE_KEY) {
  try {
    const got = await ext.storage.local.get(key);
    return clean(got?.[key]);
  } catch {
    return [];
  }
}

export async function isNeverSave(url, key = NEVER_SAVE_KEY) {
  const site = siteOf(url);
  return !!site && (await getNeverSave(key)).includes(site);
}

export async function addNeverSave(url, key = NEVER_SAVE_KEY) {
  const site = siteOf(url);
  if (!site) return '';
  const list = await getNeverSave(key);
  if (!list.includes(site)) {
    list.push(site);
    await ext.storage.local.set({ [key]: clean(list) });
  }
  return site;
}

export async function removeNeverSave(site, key = NEVER_SAVE_KEY) {
  const list = (await getNeverSave(key)).filter((s) => s !== site);
  await ext.storage.local.set({ [key]: list });
  return list;
}
