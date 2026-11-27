// Stand-in for `chrome.i18n` backed by _locales/en/messages.json, loaded for every test file with
// --import (package.json). src/shared/i18n.js falls back to `globalThis.__passI18n`.
import { readFileSync } from 'node:fs';

/** The catalog of `locale` (_locales/<locale>/messages.json). */
export function loadCatalog(locale = 'en') {
  return JSON.parse(readFileSync(new URL(`../../_locales/${locale}/messages.json`, import.meta.url), 'utf8'));
}

/**
 * `getMessage(name, substitutions)` as the browsers implement it: names are case-insensitive, named
 * placeholders ($NAME$) become their `content` (usually $1…$9), then $1…$9 become the substitutions
 * (missing ones: ''), and $$ is a literal $. Unknown names give ''.
 */
export function makeGetMessage(catalog) {
  const byName = new Map(Object.entries(catalog).map(([k, v]) => [k.toLowerCase(), v]));
  return function getMessage(name, substitutions) {
    const entry = byName.get(String(name).toLowerCase());
    if (!entry) return '';
    const subs = substitutions === undefined ? [] : Array.isArray(substitutions) ? substitutions : [substitutions];
    if (subs.length > 9) return undefined;
    const placeholders = new Map(Object.entries(entry.placeholders || {}).map(([k, v]) => [k.toLowerCase(), v.content]));
    const named = entry.message.replace(/\$([A-Za-z0-9_@]+)\$/g, (m, n) => (placeholders.has(n.toLowerCase()) ? placeholders.get(n.toLowerCase()) : m));
    return named.replace(/\$(\$|[1-9])/g, (m, d) => (d === '$' ? '$' : String(subs[Number(d) - 1] ?? '')));
  };
}

const getMessage = makeGetMessage(loadCatalog('en'));
globalThis.__passI18n = Object.freeze({
  getMessage: (name, subs) => (name === '@@bidi_dir' ? 'ltr' : name === '@@ui_locale' ? 'en' : getMessage(name, subs)),
  getUILanguage: () => 'en',
});
