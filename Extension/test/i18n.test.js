import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, readdirSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { JSDOM } from 'jsdom';
import { loadCatalog, makeGetMessage } from './helpers/i18n-setup.js';
import { manifestMessageNames } from '../scripts/make-firefox-manifest.mjs';
import { ICONS } from '../src/shared/icons.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const en = loadCatalog('en');
const enLower = new Map(Object.keys(en).map((k) => [k.toLowerCase(), k]));
const locales = readdirSync(path.join(root, '_locales')).filter((d) => statSync(path.join(root, '_locales', d)).isDirectory()).sort();
const others = locales.filter((l) => l !== 'en');
const PLURAL = ['zero', 'one', 'two', 'few', 'many', 'other'];
const PLURAL_RE = new RegExp(`^(.+)_(${PLURAL.join('|')})$`);
const NAME_RE = /^[A-Za-z0-9_]+$/;
const PLACEHOLDER_REF_RE = /\$([A-Za-z0-9_@]+)\$/g;

function walk(dir, exts, out = []) {
  for (const name of readdirSync(dir)) {
    const p = path.join(dir, name);
    if (statSync(p).isDirectory()) walk(p, exts, out);
    else if (exts.some((e) => name.endsWith(e))) out.push(p);
  }
  return out;
}
const srcJs = walk(path.join(root, 'src'), ['.js']);
const srcHtml = walk(path.join(root, 'src'), ['.html']);
const rel = (p) => path.relative(root, p).split(path.sep).join('/');
const read = (p) => readFileSync(p, 'utf8');
const manifest = JSON.parse(read(path.join(root, 'manifest.json')));

/** Plural base name of a key ("badgeLogins_one" -> "badgeLogins"), or null. */
const pluralBase = (key) => PLURAL_RE.exec(key)?.[1] ?? null;
const enPluralBases = new Set(Object.keys(en).map(pluralBase).filter(Boolean));
const prefixes = new Set(Object.keys(en).map((k) => /^[a-z]+/.exec(k)[0]));
/** A string literal that names a message: a known prefix, then camelCase (optionally a plural suffix). */
const KEY_LITERAL_RE = new RegExp(`^(?:${[...prefixes].join('|')})[A-Z0-9][A-Za-z0-9]*(?:_(?:${PLURAL.join('|')}))?$`);

/** Every quoted string in the source code that looks like a message name (t('…'), tp('…'), key maps). */
function keyLiterals() {
  const found = new Map(); // key -> [file]
  for (const file of srcJs) {
    for (const m of read(file).matchAll(/'([A-Za-z0-9_]+)'|"([A-Za-z0-9_]+)"/g)) {
      const key = m[1] ?? m[2];
      if (!KEY_LITERAL_RE.test(key) || Object.hasOwn(ICONS, key)) continue; // icon names are not messages
      if (!found.has(key)) found.set(key, new Set());
      found.get(key).add(rel(file));
    }
  }
  return found;
}

/** data-i18n* keys of the HTML pages: [{ file, attr, key }]. */
function htmlKeys() {
  const out = [];
  for (const file of srcHtml) {
    for (const m of read(file).matchAll(/\b(data-i18n(?:-title|-placeholder|-aria-label)?)="([^"]*)"/g)) out.push({ file: rel(file), attr: m[1], key: m[2] });
  }
  return out;
}

const exists = (key) => Object.hasOwn(en, key) || enPluralBases.has(key);

test('message names are valid and unique (browsers compare them case-insensitively)', () => {
  for (const locale of locales) {
    const seen = new Map();
    for (const key of Object.keys(loadCatalog(locale))) {
      assert.match(key, NAME_RE, `${locale}: "${key}" may only use A-Z, a-z, 0-9 and _`);
      assert.ok(!key.startsWith('@@'), `${locale}: ${key} is reserved`);
      assert.ok(!seen.has(key.toLowerCase()), `${locale}: ${key} and ${seen.get(key.toLowerCase())} differ only in case`);
      seen.set(key.toLowerCase(), key);
    }
  }
});

test('locale folders are browser locale codes, and each catalog says which one it is (catalogLocale)', () => {
  assert.ok(locales.includes('en'), 'English is the default locale');
  for (const locale of locales) {
    assert.match(locale, /^[a-z]{2,3}(?:_[A-Z]{2})?$/, `_locales/${locale}`);
    const tag = loadCatalog(locale).catalogLocale?.message;
    assert.equal(tag, locale.replace('_', '-'), `${locale}: catalogLocale must be "${locale.replace('_', '-')}" (used for plural rules and lang)`);
    assert.deepEqual(Intl.PluralRules.supportedLocalesOf([tag]).length, 1, `${locale}: Intl knows ${tag}`);
  }
});

test('English catalog: every message has text and a description for translators; placeholders are named and used', () => {
  for (const [key, entry] of Object.entries(en)) {
    assert.equal(typeof entry.message, 'string', key);
    assert.ok(entry.message.trim(), `${key}: empty message`);
    assert.ok(typeof entry.description === 'string' && entry.description.trim().length >= 8, `${key}: needs a description`);
    const refs = new Set([...entry.message.matchAll(PLACEHOLDER_REF_RE)].map((m) => m[1].toLowerCase()));
    const defined = Object.keys(entry.placeholders || {});
    assert.deepEqual([...refs].sort(), defined.map((d) => d.toLowerCase()).sort(), `${key}: $NAME$ references and "placeholders" must match`);
    assert.ok(!/\$[1-9]/.test(entry.message), `${key}: use named placeholders ($SITE$), not $1, so translators see names`);
    assert.ok(!entry.message.replace(PLACEHOLDER_REF_RE, '').replace(/\$\$/g, '').includes('$'), `${key}: a literal $ is written $$`);
    for (const [name, ph] of Object.entries(entry.placeholders || {})) {
      assert.match(ph.content, /^\$[1-9]$/, `${key}.${name}: content is $1…$9`);
      assert.ok(ph.example, `${key}.${name}: needs an example`);
    }
  }
});

test('English catalog: plural messages come as _one and _other (and nothing English does not use)', () => {
  const enCats = new Intl.PluralRules('en').resolvedOptions().pluralCategories;
  for (const base of enPluralBases) {
    const cats = PLURAL.filter((c) => Object.hasOwn(en, `${base}_${c}`));
    assert.deepEqual(cats.sort(), [...enCats].sort(), `${base}: English needs exactly ${enCats.join(', ')}`);
    assert.ok(!Object.hasOwn(en, base), `${base}: a plural message has no plain key`);
    const phs = (c) => JSON.stringify(en[`${base}_${c}`].placeholders || {}, ['count', 'content']);
    assert.equal(phs('one').includes('"$1"'), true, `${base}: the count is $1`);
  }
});

test('store listing: extName at most 75 and extDescription at most 132 characters in every locale', () => {
  for (const locale of locales) {
    const cat = loadCatalog(locale);
    for (const [key, max] of [['extName', 75], ['extDescription', 132], ['actionTitle', 75]]) {
      const text = cat[key]?.message ?? en[key].message;
      assert.ok([...text].length <= max, `${locale}: ${key} is ${[...text].length} characters (max ${max})`);
    }
  }
});

test('every key the code uses (t, tp, key maps) is in the English catalog', () => {
  const missing = [];
  for (const [key, files] of keyLiterals()) if (!exists(key)) missing.push(`${key} (${[...files].join(', ')})`);
  assert.deepEqual(missing, []);
});

test('every data-i18n key in the HTML is in the English catalog', () => {
  const keys = htmlKeys();
  assert.ok(keys.length > 50, 'popup and options pages are translated');
  for (const { file, attr, key } of keys) assert.ok(Object.hasOwn(en, key), `${file}: ${attr}="${key}"`);
});

test('every manifest __MSG_ name is in the English catalog', () => {
  const names = manifestMessageNames(manifest);
  assert.ok(names.includes('extName') && names.includes('extDescription'));
  for (const name of names) assert.ok(enLower.has(name.toLowerCase()), name);
});

test('no unused messages in the English catalog', () => {
  const used = new Set([...keyLiterals().keys(), ...htmlKeys().map((k) => k.key), ...manifestMessageNames(manifest), 'catalogLocale']);
  const unused = Object.keys(en).filter((key) => !used.has(key) && !used.has(pluralBase(key)));
  assert.deepEqual(unused, []);
});

test('other locales: every English message, only English keys, no empty messages, the same placeholders, valid plural sets', () => {
  // Every problem is listed at once, so a translator can fix a whole file in one go.
  const problems = [];
  const check = (ok, text) => { if (!ok) problems.push(text); };
  const names = (e) => Object.entries(e.placeholders || {}).map(([n, p]) => `${n.toLowerCase()}=${p.content}`).sort().join(', ');
  for (const locale of others) {
    const cat = loadCatalog(locale);
    const tag = locale.replace('_', '-');
    const cats = new Intl.PluralRules(tag).resolvedOptions().pluralCategories;
    // The categories a translation needs: the ones its language picks for 0…1000.
    const needed = new Set();
    const rules = new Intl.PluralRules(tag);
    for (let n = 0; n <= 1000; n++) needed.add(rules.select(n));
    for (const [key, entry] of Object.entries(cat)) {
      const base = pluralBase(key);
      const ref = en[key] ?? (base && enPluralBases.has(base) ? en[`${base}_other`] : null);
      if (!ref) { problems.push(`${locale}: ${key} is not an English message`); continue; }
      if (typeof entry.message !== 'string' || !entry.message.trim()) { problems.push(`${locale}: ${key} is empty`); continue; }
      check(names(entry) === names(ref), `${locale}: ${key} must keep the placeholders of English (${names(ref) || 'none'}), has ${names(entry) || 'none'}`);
      const refs = new Set([...entry.message.matchAll(PLACEHOLDER_REF_RE)].map((m) => m[1].toLowerCase()));
      for (const n of Object.keys(entry.placeholders || {})) check(refs.has(n.toLowerCase()), `${locale}: ${key} must use $${n.toUpperCase()}$`);
      for (const n of refs) check(Object.keys(entry.placeholders || {}).some((p) => p.toLowerCase() === n), `${locale}: ${key} uses undefined $${n.toUpperCase()}$`);
    }
    // Every plain English key is translated (plural messages are checked below: a language may lack some categories).
    for (const key of Object.keys(en)) check(pluralBase(key) || Object.hasOwn(cat, key), `${locale}: ${key} is missing (add it to _locales/${locale}/messages.json)`);

    for (const base of enPluralBases) {
      const present = PLURAL.filter((c) => Object.hasOwn(cat, `${base}_${c}`));
      if (!present.length) continue; // not translated yet: English is used
      check(present.includes('other'), `${locale}: ${base}_other is required`);
      for (const c of present) check(cats.includes(c), `${locale}: ${base}_${c} is not a plural category of ${tag} (${cats.join(', ')})`);
      for (const c of needed) check(present.includes(c), `${locale}: ${base}_${c} is missing (${tag} uses ${[...needed].join(', ')})`);
    }
  }
  assert.deepEqual(problems, []);
});

test('the HTML pages: every visible text and every title / placeholder / aria-label comes from a message', () => {
  const BRAND = new Set(['Passyble', 'Passyble Server', '-']);
  for (const file of srcHtml) {
    if (file.includes('offscreen')) continue; // no visible UI
    const { document } = new JSDOM(read(file)).window;
    const walker = document.createTreeWalker(document.documentElement, 4 /* NodeFilter.SHOW_TEXT */);
    for (let node = walker.nextNode(); node; node = walker.nextNode()) {
      const text = node.textContent.trim();
      if (!text || BRAND.has(text) || node.parentElement.closest('script, style')) continue;
      assert.ok(node.parentElement.closest('[data-i18n]'), `${rel(file)}: "${text}" has no data-i18n`);
    }
    for (const attr of ['title', 'placeholder', 'aria-label']) {
      for (const el of document.querySelectorAll(`[${attr}]`)) {
        const value = el.getAttribute(attr);
        if (BRAND.has(value) || /^[a-z0-9.-]+\.[a-z]{2,}$/.test(value)) continue; // brand, example domain
        if (el.matches('button.info') && attr === 'aria-label') continue; // "About <setting>": options.js
        assert.ok(el.hasAttribute(`data-i18n-${attr}`), `${rel(file)}: ${attr}="${value}" has no data-i18n-${attr}`);
      }
    }
  }
});

test('no user-visible English hard-coded in the UI code', () => {
  // Strings that reach the user directly: text content, tooltips, labels, notices. Brand names, keys
  // and code identifiers are fine; detection heuristics, logs and protocol errors are not UI.
  const SKIP = new Set(['src/shared/i18n.js', 'src/shared/icons.js', 'src/content/detect.js', 'src/content/webauthn-main.js']);
  const ALLOWED = /^(?:Passyble|[a-z0-9.-]+\.[a-z]{2,}|[•\s]*)$/;
  const patterns = [
    /\b(?:textContent|title|placeholder)\s*=\s*(['"`])((?:(?!\1).)*)\1/g,
    /['"]?(?:title|aria-label|placeholder|label|heading|message|subtitle|text|detail|action)['"]?:\s*(['"`])((?:(?!\1).)*[A-Za-z]{2}(?:(?!\1).)*)\1/g,
    /\b(?:snack|showNotice|flash|setMessage|setUnlockMsg|setEmpty|message|again|showAgentStatus|done)\(\s*(?:[\w$]+,\s*)?(['"`])((?:(?!\1).)*[A-Za-z]{2}(?:(?!\1).)*)\1/g,
    /\bh\('(?:span|div|button|p|label)',\s*\{[^}]*\},\s*(['"`])((?:(?!\1).)*[A-Za-z]{2}(?:(?!\1).)*)\1/g,
    /\bel\('(?:span|div|button|p|li|label)',\s*\{[^}]*\},\s*(['"`])((?:(?!\1).)*[A-Za-z]{2}(?:(?!\1).)*)\1/g,
  ];
  const found = [];
  for (const file of srcJs) {
    if (SKIP.has(rel(file))) continue;
    const src = read(file).replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    for (const re of patterns) {
      for (const m of src.matchAll(re)) {
        const value = m[2];
        if (ALLOWED.test(value) || !/[A-Za-z]{2}/.test(value)) continue;
        // Protocol errors ({ code, message }) are mapped to messages by friendlyError, never shown as such.
        if (/\bcode:\s*'[a-z_]+',\s*$/.test(src.slice(Math.max(0, m.index - 40), m.index))) continue;
        if (/^[a-z][\w.-]*$/.test(value) && !/\s/.test(value)) continue; // identifiers, message types, CSS classes
        found.push(`${rel(file)}: ${m[0].trim().slice(0, 100)}`);
      }
    }
  }
  assert.deepEqual(found, []);
});

test('the MAIN-world script shows no text (it has no chrome.i18n); its errors mirror the browser\'s own WebAuthn errors', () => {
  const src = read(path.join(root, 'src/content/webauthn-main.js'));
  assert.ok(!/\b(?:textContent|innerText|innerHTML|alert|confirm|prompt)\b\s*[=(]/.test(src), 'no DOM text in the page world');
  assert.ok(!/createElement\(/.test(src), 'no UI elements in the page world');
});

/** Loads a fresh copy of i18n.js against `catalog` with UI language `ui`. */
async function withCatalog(catalog, ui, fn) {
  const saved = globalThis.__passI18n;
  const getMessage = makeGetMessage(catalog);
  globalThis.__passI18n = { getMessage: (n, s) => (n === '@@bidi_dir' ? (catalog['@@bidi'] ? 'rtl' : 'ltr') : getMessage(n, s)), getUILanguage: () => ui };
  try {
    return await fn(await import(`../src/shared/i18n.js?case=${Math.random()}`));
  } finally {
    globalThis.__passI18n = saved;
  }
}

test('t: named placeholders in order; a missing key comes back as the key; numbers are formatted', async () => {
  const { t } = await import('../src/shared/i18n.js');
  assert.equal(t('serverCheckWindow', 'pass.example.com', 'ada'), 'Check the Passyble window to finish connecting to pass.example.com as ada.');
  assert.equal(t('popupLookUp', 'github.com'), 'Look up github.com');
  assert.equal(t('noSuchMessage'), 'noSuchMessage');
  await withCatalog({ catalogLocale: { message: 'de' }, n: { message: 'Noch $N$', placeholders: { n: { content: '$1' } } } }, 'de-DE', ({ t: tt }) => {
    assert.equal(tt('n', 12345), 'Noch 12.345');
  });
});

test('tp: plural category of the catalog language, $1 is the count, fallback to _other', async () => {
  const { tp } = await import('../src/shared/i18n.js');
  assert.equal(tp('badgeLogins', 1), 'Passyble: 1 login for this site');
  assert.equal(tp('badgeLogins', 3), 'Passyble: 3 logins for this site');
  assert.equal(tp('badgeLogins', 0), 'Passyble: 0 logins for this site');
  assert.equal(tp('menuPasswordStrength', 20, 'Strong'), 'Strong · 20 characters');
  const ph = { placeholders: { count: { content: '$1' } } };
  const pl = {
    catalogLocale: { message: 'pl' },
    x_one: { message: '$COUNT$ plik', ...ph }, x_few: { message: '$COUNT$ pliki', ...ph },
    x_many: { message: '$COUNT$ plików', ...ph }, x_other: { message: '$COUNT$ pliku', ...ph },
    y_other: { message: 'tylko $COUNT$', ...ph },
  };
  await withCatalog(pl, 'en-US', ({ tp: tpp, messageLocale }) => {
    assert.equal(messageLocale(), 'pl', 'plurals follow the catalog, not the UI language');
    assert.equal(tpp('x', 1), '1 plik');
    assert.equal(tpp('x', 3), '3 pliki');
    assert.equal(tpp('x', 5), '5 plików');
    assert.equal(tpp('x', 1.5), '1.5 pliku');
    assert.equal(tpp('y', 1), 'tylko 1', 'no _one: _other');
  });
  // Japanese has only "other".
  await withCatalog({ catalogLocale: { message: 'ja' }, z_other: { message: '$COUNT$ 件', ...ph } }, 'ja', ({ tp: tpj }) => {
    assert.equal(tpj('z', 1), '1 件');
  });
});

test('applyI18n: text and attributes from data-i18n*, English kept for unknown keys, lang and dir set', async () => {
  const { applyI18n } = await import('../src/shared/i18n.js');
  const { document } = new JSDOM(`<!doctype html><html><head><title data-i18n="optionsPageTitle">x</title></head><body>
    <h1 data-i18n="optionsTitle">x</h1><input data-i18n-placeholder="popupSearch" data-i18n-aria-label="popupSearchLabel">
    <button data-i18n-title="commonMore">⋯</button><p data-i18n="noSuchKey">Fallback</p></body></html>`).window;
  applyI18n(document);
  assert.equal(document.title, 'Passyble settings');
  assert.equal(document.querySelector('h1').textContent, 'Settings');
  assert.equal(document.querySelector('input').placeholder, 'Search');
  assert.equal(document.querySelector('input').getAttribute('aria-label'), 'Search logins');
  assert.equal(document.querySelector('button').title, 'More');
  assert.equal(document.querySelector('p').textContent, 'Fallback');
  assert.equal(document.documentElement.lang, 'en');
  assert.equal(document.documentElement.dir, 'ltr');
});

test('formatNumber follows the UI language', async () => {
  await withCatalog({ catalogLocale: { message: 'en' } }, 'de-DE', ({ formatNumber, uiLanguage }) => {
    assert.equal(uiLanguage(), 'de-DE');
    assert.equal(formatNumber(1234.5), '1.234,5');
  });
});

test('the test harness getMessage behaves like the browsers (case-insensitive names, $$, missing substitutions)', () => {
  const gm = makeGetMessage({ Hello: { message: '$$5 for $WHO$ $X$', placeholders: { who: { content: '$1' }, x: { content: '$2' } } } });
  assert.equal(gm('hello', ['Ada']), '$5 for Ada ');
  assert.equal(gm('HELLO', 'Ada'), '$5 for Ada ');
  assert.equal(gm('nope'), '');
});
