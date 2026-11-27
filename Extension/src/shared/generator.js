// Same rules as the core's `generate_password` / `generate_passphrase`, for when the agent can't be reached.
// Randomness: crypto.getRandomValues with rejection sampling (no modulo bias).
import { t } from './i18n.js';

const AMBIGUOUS = 'Il1O0o';
const strip = (s) => [...s].filter((c) => !AMBIGUOUS.includes(c)).join('');

export const CHARSETS = Object.freeze({
  lowercase: strip('abcdefghijklmnopqrstuvwxyz'),
  uppercase: strip('ABCDEFGHIJKLMNOPQRSTUVWXYZ'),
  digits: strip('0123456789'),
  symbols: '!@#$%^&*()-_=+[]{};:,.?/~',
});

export const DEFAULT_LENGTH = 20;
export const MIN_LENGTH = 8;
export const MAX_LENGTH = 128;
/** Passphrase words, as in the core (PASSPHRASE_MIN_WORDS, _DEFAULT_WORDS, _MAX_WORDS). */
export const PASSPHRASE_MIN_WORDS = 4;
export const PASSPHRASE_DEFAULT_WORDS = 6;
export const PASSPHRASE_MAX_WORDS = 20;
/** The EFF large wordlist has 7,776 words: about 12.9 bits each. */
export const PASSPHRASE_LIST_SIZE = 7776;

function randomBelow(n, rng) {
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    rng(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

const defaultRng = (buf) => globalThis.crypto.getRandomValues(buf);

export function isPlainPassword(password) {
  return typeof password === 'string' && /^[A-Za-z0-9]+$/.test(password);
}

/** A random password with at least one character of every class asked for, shuffled. */
export function generatePassword({ length = DEFAULT_LENGTH, lowercase = true, uppercase = true, digits = true, symbols = true,
  rng = defaultRng } = {}) {
  const wanted = { lowercase, uppercase, digits, symbols };
  let classes = Object.keys(CHARSETS).filter((k) => wanted[k] !== false).map((k) => CHARSETS[k]);
  if (!classes.length) classes = [CHARSETS.lowercase, CHARSETS.uppercase, CHARSETS.digits];
  const n = Math.min(MAX_LENGTH, Math.max(MIN_LENGTH, Math.floor(Number(length) || DEFAULT_LENGTH)));
  const all = classes.join('');
  const chars = classes.map((set) => set[randomBelow(set.length, rng)]);
  while (chars.length < n) chars.push(all[randomBelow(all.length, rng)]);
  shuffle(chars, rng);
  return chars.join('');
}

function shuffle(list, rng) {
  for (let i = list.length - 1; i > 0; i--) { // Fisher-Yates
    const j = randomBelow(i + 1, rng);
    [list[i], list[j]] = [list[j], list[i]];
  }
}

export function wordsOf(text) {
  return String(text || '').split(/\s+/).filter(Boolean);
}

/** Like the core's `generate_passphrase`; `plain` capitalizes each word and drops separators and hyphens. */
export function generatePassphrase(list, { words = PASSPHRASE_DEFAULT_WORDS, plain = false, rng = defaultRng } = {}) {
  if (!Array.isArray(list) || !list.length) throw new Error('no wordlist');
  const n = Math.min(PASSPHRASE_MAX_WORDS, Math.max(PASSPHRASE_MIN_WORDS, Math.floor(Number(words) || PASSPHRASE_DEFAULT_WORDS)));
  const digitAt = randomBelow(n, rng);
  const out = [];
  for (let i = 0; i < n; i++) {
    let word = list[randomBelow(list.length, rng)];
    if (plain) word = word.replace(/-/g, '').replace(/^./, (c) => c.toUpperCase());
    if (i === digitAt) word += String(randomBelow(10, rng));
    out.push(word);
  }
  return out.join(plain ? '' : '-');
}

export function passphraseStrength(passphrase, words) {
  const n = Math.max(1, Math.floor(Number(words) || 1));
  const bits = Math.round(n * Math.log2(PASSPHRASE_LIST_SIZE) + Math.log2(10 * n));
  return { bits, label: strengthLabel(bits), length: [...String(passphrase || '')].length };
}

function strengthLabel(bits) {
  return t(bits >= 100 ? 'strengthVeryStrong' : bits >= 75 ? 'strengthStrong' : bits >= 50 ? 'strengthFair' : 'strengthWeak');
}

/** Rough entropy from length and character classes; only for the generator preview. */
export function passwordStrength(password) {
  const s = String(password || '');
  let pool = 0;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += 26;
  if (/[0-9]/.test(s)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(s)) pool += 33;
  const length = [...s].length;
  const bits = pool ? Math.round(length * Math.log2(pool)) : 0;
  return { bits, label: strengthLabel(bits), length };
}
