// What a new-password field says about allowed passwords (`passwordrules`, `pattern`, minlength /
// maxlength), as far as the generator cares. Only clear cases count; anything else says nothing.
import { DEFAULT_LENGTH } from '../shared/generator.js';

const OPEN_CLASSES = new Set(['special', 'ascii-printable', 'unicode']);
const CLASS = String.raw`(?:\[(?:\\[dw]|[A-Za-z0-9_-])+\]|\\[dw])`;
const QUANT = String.raw`(?:[+*?]|\{\d+(?:,\d*)?\})?`;
const LOOKAHEAD = String.raw`\(\?=\.\*${CLASS}\)`;
const ATOM_RE = new RegExp(`^(?:${LOOKAHEAD}|${CLASS}${QUANT})`);
const MAIN_RE = new RegExp(`^${CLASS}(${QUANT})$`);

function int(v) {
  const n = Number.parseInt(String(v ?? '').trim(), 10);
  return Number.isFinite(n) && n > 0 ? n : undefined;
}

/** `passwordrules`: { symbols?: false, minLength?, maxLength? } */
export function parsePasswordRules(text) {
  const out = {};
  if (typeof text !== 'string' || !text.trim()) return out;
  let classes = false;
  let open = false;
  for (const part of text.split(';')) {
    const at = part.indexOf(':');
    if (at < 0) continue;
    const name = part.slice(0, at).trim().toLowerCase();
    const value = part.slice(at + 1).trim();
    if (name === 'required' || name === 'allowed') {
      classes = true;
      for (const token of value.split(',')) if (OPEN_CLASSES.has(token.trim().toLowerCase())) open = true;
    } else if (name === 'minlength') {
      out.minLength = int(value);
    } else if (name === 'maxlength') {
      out.maxLength = int(value);
    }
  }
  if (classes && !open) out.symbols = false;
  return out;
}

/** `pattern`: { symbols?: false, minLength?, maxLength? } for the clear cases only. */
export function parsePattern(pattern) {
  if (typeof pattern !== 'string') return {};
  let rest = pattern.trim().replace(/^\^/, '').replace(/\$$/, '');
  if (!rest) return {};
  const main = [];
  while (rest) {
    const m = ATOM_RE.exec(rest);
    if (!m) return {};
    if (!m[0].startsWith('(?=')) main.push(m[0]);
    rest = rest.slice(m[0].length);
  }
  if (!main.length) return {};
  const out = { symbols: false };
  if (main.length === 1) {
    const q = /\{(\d+)(?:(,)(\d*))?\}$/.exec(MAIN_RE.exec(main[0])?.[1] || '');
    if (q) {
      out.minLength = int(q[1]);
      out.maxLength = q[2] ? int(q[3]) : int(q[1]);
    }
  }
  return out;
}

/** { symbols?: false, minLength?, maxLength? }. maxLength only when 8 or more, minLength capped at 128 like the generator. */
export function passwordLimitsOf(el) {
  if (!el?.getAttribute) return {};
  const rules = parsePasswordRules(el.getAttribute('passwordrules'));
  const pattern = parsePattern(el.getAttribute('pattern'));
  const maxes = [rules.maxLength, pattern.maxLength, int(el.getAttribute('maxlength'))].filter((n) => n >= 8);
  const mins = [rules.minLength, pattern.minLength, int(el.getAttribute('minlength'))].filter(Boolean);
  const out = {};
  if (rules.symbols === false || pattern.symbols === false) out.symbols = false;
  if (mins.length) out.minLength = Math.min(128, Math.max(...mins));
  if (maxes.length) out.maxLength = Math.min(...maxes);
  return out;
}

/** `length` (the generator's) made to fit `limits` (passwordLimitsOf): never under 8. */
export function fitLength(length, limits = {}) {
  let n = length;
  if (limits.minLength) n = Math.max(n, limits.minLength);
  if (limits.maxLength) n = Math.min(n, limits.maxLength);
  return Math.max(8, n);
}

/** { symbols?: false, length? }: the generator's length fitted to the field. */
export function passwordRulesOf(el) {
  const limits = passwordLimitsOf(el);
  const length = fitLength(DEFAULT_LENGTH, limits);
  const out = {};
  if (limits.symbols === false) out.symbols = false;
  if (length !== DEFAULT_LENGTH) out.length = length;
  return out;
}
