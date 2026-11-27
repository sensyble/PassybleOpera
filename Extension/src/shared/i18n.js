// The catalog's own locale (message `catalogLocale`) drives plurals and `lang`; numbers and dates use the browser's UI language.

const PLURAL_CATEGORIES = Object.freeze(['zero', 'one', 'two', 'few', 'many', 'other']);

function api() {
  const ext = globalThis.browser ?? globalThis.chrome;
  return ext?.i18n ?? globalThis.__passI18n; // __passI18n: test/helpers/i18n-setup.js only
}

/** The message, or '' when the catalog has none (the browser falls back to English by itself). */
function raw(key, subs) {
  try {
    const list = subs?.length ? subs.map((s) => (typeof s === 'number' ? formatNumber(s) : String(s ?? ''))) : undefined;
    return api()?.getMessage(key, list) || '';
  } catch {
    return '';
  }
}

/** A missing message comes back as the key itself (the i18n test catches it), never as ''. */
export function t(key, ...subs) {
  return raw(key, subs) || key;
}

let pluralRules = null;
function pluralCategory(count) {
  try {
    pluralRules ??= new Intl.PluralRules(messageLocale());
    return pluralRules.select(Number(count));
  } catch {
    return Number(count) === 1 ? 'one' : 'other';
  }
}

/** `${key}_${category}` for the plural category of `count`, else `${key}_other`; the formatted count is $1. */
export function tp(key, count, ...subs) {
  const all = [formatNumber(count), ...subs];
  const cat = pluralCategory(count);
  return (PLURAL_CATEGORIES.includes(cat) && raw(`${key}_${cat}`, all)) || raw(`${key}_other`, all) || `${key}_other`;
}

export function uiLanguage() {
  try { return api()?.getUILanguage?.() || 'en'; } catch { return 'en'; }
}

export function messageLocale() {
  const tag = raw('catalogLocale');
  try {
    if (tag && Intl.getCanonicalLocales(tag).length) return tag;
  } catch { /* not a language tag */ }
  return uiLanguage();
}

export function textDirection() {
  return raw('@@bidi_dir') === 'rtl' ? 'rtl' : 'ltr';
}

export function formatNumber(n, opts) {
  try { return new Intl.NumberFormat(uiLanguage(), opts).format(n); } catch { return String(n); }
}

const ATTRS = Object.freeze({ 'data-i18n-title': 'title', 'data-i18n-placeholder': 'placeholder', 'data-i18n-aria-label': 'aria-label' });

/** Translates `data-i18n`, `data-i18n-title`, `-placeholder` and `-aria-label` under `root`; sets `lang`/`dir` on a document. */
export function applyI18n(root = globalThis.document) {
  if (!root) return;
  const doc = root.ownerDocument || root;
  if (root === doc && doc.documentElement) {
    doc.documentElement.lang = messageLocale();
    doc.documentElement.dir = textDirection();
  }
  for (const el of root.querySelectorAll('[data-i18n]')) {
    const text = raw(el.getAttribute('data-i18n'));
    if (text) el.textContent = text;
  }
  for (const [data, attr] of Object.entries(ATTRS)) {
    for (const el of root.querySelectorAll(`[${data}]`)) {
      const text = raw(el.getAttribute(data));
      if (text) el.setAttribute(attr, text);
    }
  }
}
