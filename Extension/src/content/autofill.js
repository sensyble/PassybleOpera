// Fills cards and identities into detectFormFields groups, in each field's own format. Only fields
// visible right now get a value, whatever detection said earlier.
import { fillInput } from './fill.js';
import { CardField, IdentityField, isVisible as defaultVisible } from './detect.js';
import { brandName } from '../shared/cards.js';

function viewOf(el) {
  return el.ownerDocument?.defaultView || globalThis;
}

function expiryParts(month, year) {
  const m = Number(month);
  const y = Number(year);
  return {
    MM: String(m).padStart(2, '0'),
    M: String(m),
    YYYY: String(y).padStart(4, '0'),
    YY: String(y % 100).padStart(2, '0'),
  };
}

/** `format` with MM / M / YYYY / YY replaced: formatExpiry(4, 2029, 'MM / YY') → "04 / 29". */
export function formatExpiry(month, year, format = 'MM/YY') {
  const p = expiryParts(month, year);
  return format.replace(/YYYY|YY|MM|M/g, (t) => p[t]);
}

// Placeholders use localized letters: JJ (de, nl: Jahr / jaar), AA (fr, es, it, pt: année / año / anno).
const PLACEHOLDER_FORMAT_RE = /(mm|m|\d{1,2})(\s*[/\-. ]?\s*)(yyyy|yy|jjjj|jj|aaaa|aa|\d{4}|\d{2})/i;

/** The format of a combined expiry field, from its placeholder, labels or size. Default "MM/YY". */
export function expiryFormatOf(el) {
  if ((el.getAttribute('type') || '').toLowerCase() === 'month') return 'YYYY-MM';
  const texts = [el.getAttribute('placeholder'), el.getAttribute('aria-label'), el.getAttribute('title'),
    el.getAttribute('data-placeholder')];
  try { for (const label of el.labels || []) texts.push(label.textContent); } catch { /* no labels */ }
  for (const text of texts) {
    const m = PLACEHOLDER_FORMAT_RE.exec(String(text || ''));
    if (!m) continue;
    const sep = m[2];
    const y4 = m[3].length === 4;
    return `MM${sep}${y4 ? 'YYYY' : 'YY'}`;
  }
  const ml = Number.parseInt(el.getAttribute('maxlength') || '', 10);
  if (ml === 4) return 'MMYY';
  if (ml === 6) return 'MMYYYY';
  if (ml === 7) return 'MM/YYYY';
  if (ml >= 9) return 'MM / YYYY';
  return 'MM/YY';
}

/** A separate month box: "04", or "4" when it is a one-character box / its placeholder says "M". */
export function monthValueFor(el, month) {
  const p = expiryParts(month, 2000);
  const placeholder = (el.getAttribute('placeholder') || '').trim();
  return el.getAttribute('maxlength') === '1' || /^m$/i.test(placeholder) ? p.M : p.MM;
}

/** A separate year box: "29" for a two-character box (or a YY / JJ / AA placeholder), else "2029". */
export function yearValueFor(el, year) {
  const p = expiryParts(1, year);
  const placeholder = (el.getAttribute('placeholder') || '').trim();
  const ml = Number.parseInt(el.getAttribute('maxlength') || '', 10);
  return ml === 2 || /^(yy|jj|aa|\d{2})$/i.test(placeholder) ? p.YY : p.YYYY;
}

const norm = (s) => String(s ?? '').normalize('NFKD').replace(/[̀-ͯ]/g, '').trim().toLowerCase();

function usableOptions(select) {
  return [...select.options].filter((o) => !o.disabled);
}

/** Sets a <select> to `option` so frameworks notice (native setter, input + change). */
function setSelectOption(select, option) {
  if (!option) return false;
  const view = viewOf(select);
  const desc = Object.getOwnPropertyDescriptor(view.HTMLSelectElement.prototype, 'value');
  try { select.focus({ preventScroll: true }); } catch { /* not focusable */ }
  if (desc?.set) desc.set.call(select, option.value);
  else select.value = option.value;
  option.selected = true;
  select.dispatchEvent(new view.Event('input', { bubbles: true, composed: true }));
  select.dispatchEvent(new view.Event('change', { bubbles: true }));
  return select.value === option.value;
}

/** The first option whose value or text equals one of `candidates` (case and accents ignored), then
 * the first whose text starts with one (at least 3 characters). */
export function findOption(select, candidates) {
  const wanted = candidates.map(norm).filter(Boolean);
  if (!wanted.length) return null;
  const options = usableOptions(select);
  for (const w of wanted) {
    const hit = options.find((o) => norm(o.value) === w || norm(o.text) === w);
    if (hit) return hit;
  }
  for (const w of wanted) {
    if (w.length < 3) continue;
    const hit = options.find((o) => norm(o.text).startsWith(w));
    if (hit) return hit;
  }
  return null;
}

function monthNames(locales) {
  const out = [];
  for (const locale of locales) {
    for (const month of ['long', 'short']) {
      try {
        const fmt = new Intl.DateTimeFormat(locale, { month, timeZone: 'UTC' });
        out.push(Array.from({ length: 12 }, (_, i) => norm(fmt.format(new Date(Date.UTC(2020, i, 15)))).replace(/\.$/, '')));
      } catch { /* unknown locale */ }
    }
  }
  return out;
}

function pageLocales(el) {
  const lang = el.ownerDocument?.documentElement?.getAttribute('lang');
  return [...new Set([lang, globalThis.navigator?.language, 'en'].filter(Boolean))];
}

/** The option for month 1-12: value or leading number ("4", "04", "04 - April"), else the month's name. */
export function monthOption(select, month) {
  const options = usableOptions(select);
  const num = (s) => { const m = /^\s*0?(\d{1,2})\b/.exec(String(s)); return m ? Number(m[1]) : NaN; };
  const byValue = options.find((o) => /^\s*\d{1,2}\s*$/.test(o.value) && Number(o.value) === month);
  if (byValue) return byValue;
  const byText = options.find((o) => num(o.text) === month && o.value !== '');
  if (byText) return byText;
  for (const names of monthNames(pageLocales(select))) {
    const name = names[month - 1];
    const hit = options.find((o) => norm(o.text) === name || norm(o.text).startsWith(name));
    if (hit) return hit;
  }
  return null;
}

/** The option for a four-digit year: "2029" or "29" as value or text. */
export function yearOption(select, year) {
  const options = usableOptions(select);
  const full = String(year);
  const short = String(year % 100).padStart(2, '0');
  return options.find((o) => o.value.trim() === full) || options.find((o) => o.text.trim() === full) ||
    options.find((o) => o.value.trim() === short) || options.find((o) => o.text.trim() === short) || null;
}

let regionNames = null;
/** English and page-language names of an ISO 3166 code, or the code of a country name (both ways). */
function countryCandidates(country, el) {
  const value = String(country || '').trim();
  if (!value) return [];
  const out = [value];
  const locales = pageLocales(el);
  try {
    if (/^[a-z]{2}$/i.test(value)) {
      for (const locale of locales) out.push(new Intl.DisplayNames([locale], { type: 'region' }).of(value.toUpperCase()));
    } else {
      if (!regionNames) {
        regionNames = new Map();
        const en = new Intl.DisplayNames(['en'], { type: 'region' });
        const A = 65;
        for (let i = 0; i < 26; i++) {
          for (let j = 0; j < 26; j++) {
            const code = String.fromCharCode(A + i, A + j);
            const name = en.of(code);
            if (name && name !== code) regionNames.set(norm(name), code);
          }
        }
      }
      const code = regionNames.get(norm(value));
      if (code) out.push(code);
    }
  } catch { /* no Intl.DisplayNames */ }
  return [...new Set(out.filter(Boolean))];
}

/** The display name of a country entered as an ISO code ("GB" → "United Kingdom"), else as entered. */
export function countryName(country, el) {
  const value = String(country || '').trim();
  if (!/^[a-z]{2}$/i.test(value)) return value;
  return countryCandidates(value, el)[1] || value;
}

function put(el, value, visible) {
  if (!el || value === undefined || value === null || value === '') return false;
  if (!visible(el)) return false;
  if (el.tagName === 'SELECT') return setSelectOption(el, findOption(el, [String(value)]));
  return fillInput(el, String(value));
}

function first(group, kind) {
  return group.fields.get(kind)?.[0] || null;
}

function splitName(name) {
  const parts = String(name || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length < 2) return { given: parts[0] || '', family: '' };
  return { given: parts.slice(0, -1).join(' '), family: parts.at(-1) };
}

/** Fills the boxes of a split card number by their sizes (4-4-4-4, 4-6-5 for Amex, …). */
function fillSplitNumber(els, digits, visible) {
  if (!els.every(visible)) return false;
  let at = 0;
  let ok = true;
  els.forEach((el, i) => {
    const size = Number.parseInt(el.getAttribute('maxlength') || '', 10) || 4;
    const part = i === els.length - 1 ? digits.slice(at) : digits.slice(at, at + size);
    at += part.length;
    ok = fillInput(el, part) && ok;
  });
  return ok;
}

/** Fills a card group. Returns how many fields got a value. */
export function fillCardGroup(group, card, { isVisible: visible = defaultVisible } = {}) {
  let filled = 0;
  const count = (ok) => { if (ok) filled++; };
  const number = String(card.number || '').replace(/[\s-]/g, '');
  const numberEls = group.fields.get(CardField.NUMBER) || [];
  if (numberEls.length > 1) count(fillSplitNumber(numberEls, number, visible));
  else count(put(numberEls[0], number, visible));
  count(put(first(group, CardField.NAME), card.cardholder_name, visible));
  const name = splitName(card.cardholder_name);
  count(put(first(group, CardField.GIVEN_NAME), name.given, visible));
  count(put(first(group, CardField.FAMILY_NAME), name.family, visible));
  const month = Number(card.expiry_month);
  const year = Number(card.expiry_year);
  const known = month >= 1 && month <= 12 && year > 0;
  if (known) {
    const exp = first(group, CardField.EXP);
    if (exp && visible(exp)) count(fillInput(exp, formatExpiry(month, year, expiryFormatOf(exp))));
    const m = first(group, CardField.EXP_MONTH);
    if (m && visible(m)) count(m.tagName === 'SELECT' ? setSelectOption(m, monthOption(m, month)) : fillInput(m, monthValueFor(m, month)));
    const y = first(group, CardField.EXP_YEAR);
    if (y && visible(y)) count(y.tagName === 'SELECT' ? setSelectOption(y, yearOption(y, year)) : fillInput(y, yearValueFor(y, year)));
  }
  count(put(first(group, CardField.CSC), card.security_code, visible));
  const type = first(group, CardField.TYPE);
  if (type && card.brand && visible(type)) {
    const brand = String(card.brand);
    const names = [brand, brandName(brand), { amex: 'Amex', mastercard: 'Master Card', diners: 'Diners' }[brand], { mastercard: 'MC', amex: 'AX' }[brand]];
    count(type.tagName === 'SELECT' ? setSelectOption(type, findOption(type, names.filter(Boolean))) : fillInput(type, brandName(brand)));
  }
  return filled;
}

/** Fills an identity group, skipping empty values. Returns how many fields got a value. */
export function fillIdentityGroup(group, identity, { isVisible: visible = defaultVisible } = {}) {
  let filled = 0;
  const count = (ok) => { if (ok) filled++; };
  const id = identity || {};
  const full = id.full_name || [id.first_name, id.middle_name, id.last_name].filter(Boolean).join(' ');
  const simple = {
    [IdentityField.NAME]: full,
    [IdentityField.GIVEN_NAME]: id.first_name,
    [IdentityField.ADDITIONAL_NAME]: id.middle_name,
    [IdentityField.FAMILY_NAME]: id.last_name,
    [IdentityField.HONORIFIC]: id.honorific,
    [IdentityField.ORGANIZATION]: id.company,
    [IdentityField.EMAIL]: id.email,
    [IdentityField.TEL]: id.phone,
    [IdentityField.LINE1]: id.address1,
    [IdentityField.LINE2]: id.address2,
    [IdentityField.LINE3]: id.address3,
    [IdentityField.CITY]: id.city,
    [IdentityField.POSTAL]: id.postal_code,
  };
  for (const [kind, value] of Object.entries(simple)) count(put(first(group, kind), value, visible));
  const street = first(group, IdentityField.STREET);
  if (street) {
    const lines = [id.address1, id.address2, id.address3].filter(Boolean);
    count(put(street, lines.join(street.tagName === 'TEXTAREA' ? '\n' : ', '), visible));
  }
  const region = first(group, IdentityField.REGION);
  if (region && id.region && visible(region)) {
    count(region.tagName === 'SELECT' ? setSelectOption(region, findOption(region, [id.region])) : fillInput(region, id.region));
  }
  for (const kind of [IdentityField.COUNTRY, IdentityField.COUNTRY_NAME]) {
    const el = first(group, kind);
    if (!el || !id.country || !visible(el)) continue;
    if (el.tagName === 'SELECT') count(setSelectOption(el, findOption(el, countryCandidates(id.country, el))));
    // autocomplete="country" asks for the code as entered; a country-name box for a name.
    else count(fillInput(el, kind === IdentityField.COUNTRY ? id.country : countryName(id.country, el)));
  }
  return filled;
}
