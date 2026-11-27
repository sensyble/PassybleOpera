// Reading a submitted card for the "Save card to Passyble?" banner (src/content/card-capture.js) in jsdom:
// never the security code; only on secure pages, in the top frame or a same-origin frame. Test card numbers only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import { CardField, detectFormFields, isVisibleNoLayout } from '../src/content/detect.js';
import { PAY_TEXT_RE, captureCardFrom, captureFrameAllowed, cardGroupFor, readCard } from '../src/content/card-capture.js';

const opts = { isVisible: isVisibleNoLayout };

function page(html, url = 'https://shop.example/checkout') {
  const { window, document } = makeDom(html, { url });
  const set = (sel, value) => {
    const el = document.querySelector(sel);
    if (el.tagName === 'SELECT') el.value = value;
    else el.value = value;
  };
  return { window, document, set };
}

const CHECKOUT = `<form id="pay">
  <input name="ccname" autocomplete="cc-name">
  <input name="cardnumber" autocomplete="cc-number" inputmode="numeric">
  <input name="exp" autocomplete="cc-exp" placeholder="MM / YY">
  <input name="cvc" autocomplete="cc-csc">
  <button type="submit">Pay</button></form>`;

test('a checkout form: number, expiry and holder; the security code is never read', () => {
  const { window, document, set } = page(CHECKOUT);
  set('[name=ccname]', '  Ada Lovelace ');
  set('[name=cardnumber]', '4242 4242 4242 4242');
  set('[name=exp]', '04 / 29');
  set('[name=cvc]', '737');
  const { cards } = detectFormFields(document, opts);
  const group = cardGroupFor(document.querySelector('button'), cards);
  assert.ok(group);
  // Any read of the security code field's value from here on is a failure.
  const csc = group.fields.get(CardField.CSC)[0];
  let cscReads = 0;
  Object.defineProperty(csc, 'value', { get() { cscReads++; return '737'; }, configurable: true });
  const card = readCard(group);
  assert.deepEqual(card, { number: '4242424242424242', expiry_month: 4, expiry_year: 2029, cardholder_name: 'Ada Lovelace' });
  assert.equal(cscReads, 0, 'the security code is never read');
  assert.ok(!JSON.stringify(card).includes('737'));
  // The same through the submit path.
  const captured = captureCardFrom(document.getElementById('pay'), { root: document, win: window, ...opts });
  assert.deepEqual(captured, card);
});

test('expiry: month / year selects (by value, text or month name), MMYY boxes, type=month', () => {
  const selects = page(`<form>
    <label>Card number <input name="cardNumber"></label>
    <label>Month <select name="m"><option value="">MM</option><option value="7">07 - July</option></select></label>
    <label>Year <select name="y"><option value="">YYYY</option><option value="2031">2031</option></select></label>
    </form>`);
  selects.set('[name=cardNumber]', '5555555555554444');
  selects.set('[name=m]', '7');
  selects.set('[name=y]', '2031');
  let card = captureCardFrom(selects.document.querySelector('form'), { root: selects.document, win: selects.window, ...opts });
  assert.equal(card.number, '5555555555554444');
  assert.deepEqual([card.expiry_month, card.expiry_year], [7, 2031]);

  const names = page(`<form>
    <input name="cardnumber" autocomplete="cc-number">
    <select name="m" autocomplete="cc-exp-month"><option>Select</option><option value="mar">March</option></select>
    <select name="y" autocomplete="cc-exp-year"><option value="30">30</option></select>
    </form>`);
  names.set('[name=cardnumber]', '378282246310005');
  names.document.querySelector('[name=m]').selectedIndex = 1;
  card = captureCardFrom(names.document.querySelector('form'), { root: names.document, win: names.window, ...opts });
  assert.deepEqual([card.expiry_month, card.expiry_year], [3, 2030]);

  const compact = page(`<form><input name="cardnumber" autocomplete="cc-number"><input name="exp" autocomplete="cc-exp" maxlength="4"></form>`);
  compact.set('[name=cardnumber]', '6011111111111117');
  compact.set('[name=exp]', '1130');
  card = captureCardFrom(compact.document.querySelector('form'), { root: compact.document, win: compact.window, ...opts });
  assert.deepEqual([card.expiry_month, card.expiry_year], [11, 2030]);

  const month = page(`<form><input name="cardnumber" autocomplete="cc-number"><input name="exp" type="month" autocomplete="cc-exp"></form>`);
  month.set('[name=cardnumber]', '4242424242424242');
  month.set('[name=exp]', '2029-04');
  card = captureCardFrom(month.document.querySelector('form'), { root: month.document, win: month.window, ...opts });
  assert.deepEqual([card.expiry_month, card.expiry_year], [4, 2029]);

  const unreadable = page(CHECKOUT);
  unreadable.set('[name=cardnumber]', '4242424242424242');
  unreadable.set('[name=exp]', 'soon');
  card = captureCardFrom(unreadable.document.querySelector('form'), { root: unreadable.document, win: unreadable.window, ...opts });
  assert.deepEqual([card.expiry_month, card.expiry_year], [0, 0], 'no expiry, still a card');
});

test('a number split over four boxes', () => {
  const { window, document } = page(`<form>
    <label for="n1">Card number</label><input id="n1" name="cc1" maxlength="4" autocomplete="cc-number">
    <input name="cc2" maxlength="4"><input name="cc3" maxlength="4"><input name="cc4" maxlength="4">
    <input name="exp" autocomplete="cc-exp" placeholder="MM/YY"></form>`);
  ['4242', '4242', '4242', '4242'].forEach((v, i) => { document.querySelector(`[name=cc${i + 1}]`).value = v; });
  document.querySelector('[name=exp]').value = '04/29';
  const card = captureCardFrom(document.querySelector('form'), { root: document, win: window, ...opts });
  assert.equal(card?.number, '4242424242424242');
});

test('nothing without a valid number, on an insecure page, or outside a card form', () => {
  const bad = page(CHECKOUT);
  bad.set('[name=cardnumber]', '4242 4242 4242 4241');
  assert.equal(captureCardFrom(bad.document.querySelector('form'), { root: bad.document, win: bad.window, ...opts }), null, 'Luhn');
  bad.set('[name=cardnumber]', '4242 4242');
  assert.equal(captureCardFrom(bad.document.querySelector('form'), { root: bad.document, win: bad.window, ...opts }), null, 'short');

  const http = page(CHECKOUT, 'http://shop.example/checkout');
  http.set('[name=cardnumber]', '4242424242424242');
  assert.equal(captureCardFrom(http.document.querySelector('form'), { root: http.document, win: http.window, ...opts }), null, 'http');
  const local = page(CHECKOUT, 'http://localhost:8080/checkout');
  local.set('[name=cardnumber]', '4242424242424242');
  assert.ok(captureCardFrom(local.document.querySelector('form'), { root: local.document, win: local.window, ...opts }), 'http on this device');

  const login = page(`<form><input name="user" autocomplete="username"><input type="password" name="pw"></form>`);
  assert.equal(captureCardFrom(login.document.querySelector('form'), { root: login.document, win: login.window, ...opts }), null);
});

test('frames: the top frame and same-origin frames read cards, a cross-origin payment iframe never', () => {
  const { window, document, set } = page(CHECKOUT, 'https://js.stripe.example/elements-inner-card.html');
  set('[name=cardnumber]', '4242424242424242');
  assert.equal(captureFrameAllowed(window), true, 'jsdom: a top window');
  const loc = { origin: 'https://js.stripe.example', href: 'https://js.stripe.example/elements-inner-card.html' };
  const crossOrigin = { location: loc, get top() { return { get location() { throw new Error('SecurityError'); } }; } };
  assert.equal(captureFrameAllowed(crossOrigin), false);
  assert.equal(captureCardFrom(document.querySelector('form'), { root: document, win: crossOrigin, ...opts }), null);
  const otherOrigin = { location: loc, top: { location: { origin: 'https://shop.example' } } };
  assert.equal(captureFrameAllowed(otherOrigin), false);
  const sameOrigin = { location: loc, top: { location: { origin: 'https://js.stripe.example' } } };
  assert.equal(captureFrameAllowed(sameOrigin), true);
  assert.ok(captureCardFrom(document.querySelector('form'), { root: document, win: sameOrigin, ...opts }));
  const opaque = { location: { origin: 'null', href: 'about:srcdoc' }, top: null };
  assert.equal(captureFrameAllowed(opaque), false, 'a sandboxed frame');
});

test('pay buttons in several languages count as a submit', () => {
  for (const text of ['Pay now', 'Place order', 'Buy now', 'Jetzt bezahlen', 'Payer', 'Pagar', 'Bayar', '支払う', '결제하기', '立即支付']) {
    assert.ok(PAY_TEXT_RE.test(text), text);
  }
  for (const text of ['Apply coupon', 'Back', 'Repayment plan details']) assert.ok(!PAY_TEXT_RE.test(text), text);
});
