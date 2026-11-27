// A site is its registrable domain as far as it can be told without a public-suffix list; a wrong guess (two sites
// under `github.io`) only shares a default, never a secret. Nothing stored here is secret.
import { ext } from './api.js';
import {
  DEFAULT_LENGTH, MIN_LENGTH, MAX_LENGTH, PASSPHRASE_DEFAULT_WORDS, PASSPHRASE_MIN_WORDS, PASSPHRASE_MAX_WORDS,
} from './generator.js';

export const NO_SYMBOLS_KEY = `generateNoSymbols`; // backticks: not a message name (test/i18n.test.js)
export const MAX_SITES = 200;
export const OPTIONS_KEY = `generateOptions`;

export const DEFAULT_OPTIONS = Object.freeze({
  mode: 'password', length: DEFAULT_LENGTH, lowercase: true, uppercase: true, digits: true, words: PASSPHRASE_DEFAULT_WORDS,
});

// Second levels under a country code that are a public suffix themselves (co.uk, com.au, or.jp, gob.mx).
const SECOND_LEVELS = new Set(['ac', 'co', 'com', 'edu', 'go', 'gob', 'gov', 'ltd', 'mil', 'ne', 'net', 'nic', 'or', 'org', 'plc', 'sch']);

export function siteKeyOf(url) {
  let host;
  try {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return '';
    host = u.hostname.toLowerCase().replace(/\.$/, '');
  } catch {
    return '';
  }
  if (!host) return '';
  if (host.startsWith('[') || /^\d+(?:\.\d+){3}$/.test(host)) return host; // IPv6 / IPv4
  const labels = host.split('.');
  if (labels.length <= 2) return host;
  const n = labels.length;
  const take = labels[n - 1].length === 2 && SECOND_LEVELS.has(labels[n - 2]) ? 3 : 2;
  return labels.slice(-take).join('.');
}

function clean(list) {
  const out = [];
  for (const v of Array.isArray(list) ? list : []) {
    if (typeof v === 'string' && v && v.length <= 253 && !out.includes(v)) out.push(v);
  }
  return out.slice(-MAX_SITES);
}

async function read() {
  try {
    const got = await ext.storage.local.get([NO_SYMBOLS_KEY]);
    return clean(got?.[NO_SYMBOLS_KEY]);
  } catch {
    return [];
  }
}

export async function prefersNoSymbols(url) {
  const site = siteKeyOf(url);
  return !!site && (await read()).includes(site);
}

export async function rememberSymbols(url, symbols) {
  const site = siteKeyOf(url);
  if (!site || typeof symbols !== 'boolean') return;
  const list = await read();
  const at = list.indexOf(site);
  if (symbols) {
    if (at < 0) return;
    list.splice(at, 1);
  } else {
    if (at === list.length - 1 && at >= 0) return;
    if (at >= 0) list.splice(at, 1);
    list.push(site);
  }
  try {
    await ext.storage.local.set({ [NO_SYMBOLS_KEY]: clean(list) });
  } catch { /* storage unavailable: nothing remembered */ }
}

const intIn = (v, min, max, fallback) => (Number.isInteger(v) && v >= min && v <= max ? v : fallback);

export function cleanOptions(options) {
  const o = options && typeof options === 'object' ? options : {};
  const flag = (name) => (typeof o[name] === 'boolean' ? o[name] : DEFAULT_OPTIONS[name]);
  return {
    mode: o.mode === 'passphrase' ? 'passphrase' : 'password',
    length: intIn(o.length, MIN_LENGTH, MAX_LENGTH, DEFAULT_OPTIONS.length),
    lowercase: flag('lowercase'),
    uppercase: flag('uppercase'),
    digits: flag('digits'),
    words: intIn(o.words, PASSPHRASE_MIN_WORDS, PASSPHRASE_MAX_WORDS, DEFAULT_OPTIONS.words),
  };
}

const sameOptions = (a, b) => Object.keys(DEFAULT_OPTIONS).every((k) => a[k] === b[k]);

export async function generatorOptions() {
  try {
    const got = await ext.storage.local.get([OPTIONS_KEY]);
    return cleanOptions(got?.[OPTIONS_KEY]);
  } catch {
    return cleanOptions(null);
  }
}

export async function rememberOptions(options) {
  if (!options || typeof options !== 'object') return;
  const next = cleanOptions(options);
  if (sameOptions(next, await generatorOptions())) return;
  try {
    await ext.storage.local.set({ [OPTIONS_KEY]: next });
  } catch { /* storage unavailable: nothing remembered */ }
}
