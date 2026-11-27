// Shared by content/card-capture.js and background/card-save.js (which checks again whatever the page sent).
// The security code is not handled here on purpose: it is never read, kept or saved.

const MAX_HOLDER = 256;

export function cardDigits(value) {
  if (typeof value !== 'string' || value.length > 64) return '';
  if (!/^[\d\s.-]*$/.test(value)) return '';
  return value.replace(/\D/g, '');
}

export function luhnValid(digits) {
  if (typeof digits !== 'string' || !/^\d+$/.test(digits)) return false;
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (double) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    double = !double;
  }
  return sum % 10 === 0;
}

export function validCardNumber(value) {
  const digits = cardDigits(value);
  return digits.length >= 12 && digits.length <= 19 && luhnValid(digits) ? digits : '';
}

export function cardMonth(value) {
  const m = typeof value === 'number' ? value : Number.parseInt(String(value ?? '').trim(), 10);
  return Number.isInteger(m) && m >= 1 && m <= 12 ? m : 0;
}

export function cardYear(value) {
  const text = String(value ?? '').trim();
  if (!/^\d{2}$|^\d{4}$/.test(text)) return 0;
  const y = Number(text);
  const year = text.length === 2 ? 2000 + y : y;
  return year >= 2000 && year <= 2099 ? year : 0;
}

/** Month and year of a typed expiry ("04/29", "4 / 2029", "0429", `type=month`'s "2029-04"), or null. */
export function parseExpiry(text, { monthInput = false } = {}) {
  const s = String(text ?? '').trim();
  if (!s || s.length > 16) return null;
  let m;
  let month = 0;
  let year = 0;
  if (monthInput || /^\d{4}-\d{1,2}$/.test(s)) {
    m = /^(\d{4})-(\d{1,2})$/.exec(s);
    if (m) { year = cardYear(m[1]); month = cardMonth(m[2]); }
  } else if ((m = /^(\d{1,2})\s*[/\-. ]\s*(\d{2}|\d{4})$/.exec(s))) {
    month = cardMonth(m[1]);
    year = cardYear(m[2]);
  } else if ((m = /^(\d{2})(\d{2}|\d{4})$/.exec(s))) {
    month = cardMonth(m[1]);
    year = cardYear(m[2]);
  }
  return month && year ? { month, year } : null;
}

export function cleanHolder(value) {
  if (typeof value !== 'string') return '';
  const s = value.replace(/[\u0000-\u001f\u007f]+/g, ' ').replace(/\s+/g, ' ').trim();
  return s.length <= MAX_HOLDER ? s : '';
}

export function cleanTitle(value) {
  if (typeof value !== 'string') return null;
  if (/[\u0000-\u001f\u007f]/.test(value)) return null;
  const s = value.trim();
  return s.length <= 256 ? s : null;
}

/** Card network from the leading digits, as pass-core `card_brand` names it; only used while the vault is locked. */
export function cardBrand(digits) {
  const d = typeof digits === 'string' ? digits.replace(/\D/g, '') : '';
  const p = (n) => (d.length >= n ? Number(d.slice(0, n)) : -1);
  if (d.length < 2) return d.startsWith('4') ? 'visa' : '';
  if (p(4) >= 2200 && p(4) <= 2204) return 'mir';
  if (d[0] === '4') return 'visa';
  if (p(2) === 34 || p(2) === 37) return 'amex';
  if ((p(2) >= 51 && p(2) <= 55) || (p(4) >= 2221 && p(4) <= 2720)) return 'mastercard';
  if (p(4) === 6011 || (p(3) >= 644 && p(3) <= 649) || p(2) === 65 || (p(6) >= 622126 && p(6) <= 622925)) return 'discover';
  if (p(4) >= 3528 && p(4) <= 3589) return 'jcb';
  if ((p(3) >= 300 && p(3) <= 305) || [36, 38, 39].includes(p(2))) return 'diners';
  if (p(2) === 62 || p(2) === 81) return 'unionpay';
  if (p(2) === 50 || (p(2) >= 56 && p(2) <= 58) || p(2) === 63 || p(2) === 67) return 'maestro';
  return '';
}
