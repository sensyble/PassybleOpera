// Reads a card from a submitted checkout form for the save-card banner. Never reads the security code.
// Only the top frame or a same-origin frame: a payment provider's cross-origin iframe is the provider's
// page, not the shop's. The background re-checks with the browser's sender info (background/card-save.js).
import { CardField, detectFormFields, isVisible as defaultVisible } from './detect.js';
import { isSecureFormUrl } from '../shared/cards.js';
import { cardMonth, cardYear, cleanHolder, parseExpiry, validCardNumber } from '../shared/card-rules.js';

/** Whether this frame may offer to save a card: the top frame, or one of the top page's origin. */
export function captureFrameAllowed(win = globalThis.window) {
  try {
    if (!win || win.location.origin === 'null') return false;
    if (win.top === win) return true;
    // Reading another origin's location throws: a cross-origin frame.
    return win.top.location.origin === win.location.origin;
  } catch {
    return false;
  }
}

/** The card group `el` belongs to (its form, or the group's container), else the page's only one. */
export function cardGroupFor(el, groups) {
  if (!groups?.length) return null;
  if (el) {
    const form = el.closest?.('form') || (el.tagName === 'FORM' ? el : null);
    const inForm = form && groups.find((g) => g.form === form);
    if (inForm) return inForm;
    const containing = groups.find((g) => g.container?.contains?.(el) || el.contains?.(g.container));
    if (containing) return containing;
  }
  return groups.length === 1 ? groups[0] : null;
}

const norm = (s) => String(s ?? '').normalize('NFKD').replace(/[̀-ͯ]/g, '').trim().toLowerCase();

function monthNames(doc) {
  const locales = ['en', doc?.documentElement?.lang, globalThis.navigator?.language].filter(Boolean);
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

/** A field's value: an <input>'s text, or a <select>'s chosen option (value, then its text). */
function valuesOf(el) {
  if (el?.tagName === 'SELECT') {
    const option = el.options?.[el.selectedIndex];
    return option ? [option.value, option.text] : [];
  }
  return [typeof el?.value === 'string' ? el.value : ''];
}

function monthOf(el) {
  for (const v of valuesOf(el)) {
    const m = cardMonth(v) || cardMonth(/^\s*(\d{1,2})\b/.exec(String(v))?.[1]);
    if (m) return m;
  }
  if (el?.tagName !== 'SELECT') return 0;
  const text = norm(valuesOf(el)[1]).replace(/\.$/, '');
  if (!text) return 0;
  for (const names of monthNames(el.ownerDocument)) {
    const i = names.indexOf(text);
    if (i >= 0) return i + 1;
  }
  return 0;
}

function yearOf(el) {
  for (const v of valuesOf(el)) {
    const y = cardYear(v) || cardYear(/\b(\d{4}|\d{2})\s*$/.exec(String(v))?.[1]);
    if (y) return y;
  }
  return 0;
}

/** `{ number, expiry_month, expiry_year, cardholder_name }` (expiry 0 when unreadable), or null without a valid number. */
export function readCard(group) {
  const fields = group?.fields;
  if (!fields) return null;
  const first = (kind) => fields.get(kind)?.[0] || null;
  const numberEls = fields.get(CardField.NUMBER) || [];
  const number = validCardNumber(numberEls.map((el) => valuesOf(el)[0] || '').join(''));
  if (!number) return null;
  let month = 0;
  let year = 0;
  const exp = first(CardField.EXP);
  if (exp) {
    const monthInput = (exp.getAttribute?.('type') || '').toLowerCase() === 'month';
    const parsed = parseExpiry(valuesOf(exp)[0], { monthInput });
    if (parsed) ({ month, year } = parsed);
  } else {
    const monthEl = first(CardField.EXP_MONTH);
    const yearEl = first(CardField.EXP_YEAR);
    if (monthEl && yearEl) {
      month = monthOf(monthEl);
      year = yearOf(yearEl);
      if (!month || !year) month = year = 0;
    }
  }
  const name = first(CardField.NAME);
  let holder = name ? cleanHolder(valuesOf(name)[0]) : '';
  if (!holder) {
    const given = first(CardField.GIVEN_NAME);
    const family = first(CardField.FAMILY_NAME);
    holder = cleanHolder([given, family].map((el) => (el ? valuesOf(el)[0] : '')).filter(Boolean).join(' '));
  }
  return { number, expiry_month: month, expiry_year: year, cardholder_name: holder };
}

/** The card submitted from around `el`, or null. Secure pages, top or same-origin frames only. */
export function captureCardFrom(el, { root = globalThis.document, win = globalThis.window, isVisible = defaultVisible } = {}) {
  if (!captureFrameAllowed(win)) return null;
  if (!isSecureFormUrl(win?.location?.href)) return null;
  let cards;
  try { ({ cards } = detectFormFields(root, { isVisible })); } catch { return null; }
  return readCard(cardGroupFor(el, cards));
}

// Pay button text in the extension's languages: a click submits the card form even when it isn't a submit button.
export const PAY_TEXT_RE = /(\bpay\b|pay now|place (your )?order|purchase|\bbuy\b|checkout|check out|complete (order|purchase)|subscribe|donate|bezahlen|zahlen|kaufen|bestellen|jetzt kaufen|payer|acheter|commander|valider|pagar|comprar|realizar pedido|finalizar|bayar|beli|pesan|भुगतान|खरीद|支払|購入|注文|支付|付款|购买|下单|결제|구매|주문)/i;
