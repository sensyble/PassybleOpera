import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://shop.example/checkout', pretendToBeVisual: true });
const w = dom.window;
const doc = w.document;

w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};
const shadowRoots = new Map();
const attachShadow = w.Element.prototype.attachShadow;
w.Element.prototype.attachShadow = function (init) {
  const root = attachShadow.call(this, init);
  shadowRoots.set(this, root);
  return root;
};

const sent = [];
let runtimeListener;
let features = { cards: true, identities: true };
const CARDS = [
  { id: 'visa', title: 'Work card', cardholder_name: 'Ada Lovelace', brand: 'visa', last4: '4242', expiry_month: 4, expiry_year: 2029 },
  { id: 'mc', title: '', cardholder_name: 'Ada Lovelace', brand: 'mastercard', last4: '4444', expiry_month: 12, expiry_year: 2030 },
];
const responses = {
  'otp.context': () => ({ ok: true, result: { pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] } }),
  'forms.features': () => ({ ok: true, result: features }),
  'cards.list': () => ({ ok: true, result: { items: CARDS, locked: false } }),
  'cards.fill': (msg) => ({ ok: true, result: { cardholder_name: 'Ada Lovelace', number: msg.id === 'visa' ? '4242424242424242' : '5555555555554444',
    expiry_month: 4, expiry_year: 2029, security_code: '737', brand: 'visa' } }),
  'identities.list': () => ({ ok: true, result: { items: [{ id: 'home', title: 'Home', full_name: 'Ada Lovelace', email: 'ada@example.org', company: '' }], locked: false } }),
  'identities.fill': () => ({ ok: true, result: { first_name: 'Ada', last_name: 'Lovelace', full_name: 'Ada Lovelace', email: 'ada@example.org',
    phone: '+44 20 7946 0000', address1: "12 St James's Square", address2: '', address3: '', city: 'London', region: '', postal_code: 'SW1Y 4JH', country: 'GB', company: '' } }),
  'logins.find': () => ({ ok: true, result: { items: [{ id: 'gh', title: 'Shop', username: 'ada@example.org', has_totp: false, has_passkey: false }], pending_otp: null, locked: false } }),
  'save.query': () => ({ ok: true, result: null }),
};

let main;
let ui;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : { ok: true, result: {} };
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: { local: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  main = await import('../src/content/main.js');
  ui = await import('../src/content/ui-common.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true, button: 0 }));
const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));
const rootOf = (tag) => shadowRoots.get(doc.querySelector(tag));
const entries = () => (doc.querySelector('pass-menu') ? [...rootOf('pass-menu').querySelectorAll('.item')] : []);
const count = (type) => sent.filter((m) => m.type === type).length;
const v = (name) => doc.querySelector(`[name=${name}]`).value;

const CARD_FORM = `<form id="pay"><input name="holder" autocomplete="cc-name"><input name="number" autocomplete="cc-number">
  <input name="exp" autocomplete="cc-exp" placeholder="MM / YY"><input name="cvc" autocomplete="cc-csc">
  <input name="cvc2" autocomplete="cc-csc" style="display:none"><button>Pay</button></form>`;

async function focusByUser(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(30);
}

async function load(html) {
  doc.querySelector('pass-menu')?.remove();
  doc.body.innerHTML = html;
  await tick(300);
}

test('a card field: the icon, and the menu with the cards (brand, last four digits, expiry) when the user clicks in', async () => {
  await load(CARD_FORM);
  sent.length = 0;
  await focusByUser(doc.querySelector('[name=number]'));
  assert.ok(doc.querySelector('pass-icon'), 'the Passyble icon');
  assert.ok(doc.querySelector('pass-menu'), 'the menu opened on its own');
  const root = rootOf('pass-menu');
  assert.equal(root.querySelector('.head').textContent, 'Passyble · Cards');
  assert.deepEqual(entries().map((e) => e.querySelector('.title').textContent), ['Work card', 'Mastercard •••• 4444 · 12/30']);
  assert.deepEqual(entries().map((e) => e.querySelector('.sub').textContent), ['Visa •••• 4242 · 04/29', 'Mastercard •••• 4444 · 12/30']);
  assert.equal(entries()[0].querySelector('.avatar').textContent, 'VISA');
  assert.ok(sent.some((m) => m.type === 'cards.list' && m.automatic === true));
  assert.ok(sent.every((m) => m.url === undefined), 'content scripts never name a URL');
  assert.equal(count('cards.fill'), 0, 'nothing filled on its own');
});

test('only a trusted click on a menu that was on screen for a moment fills; Enter needs the same', async () => {
  // Opened just now: a click (or Enter) at once doesn't count.
  await click(entries()[0]);
  await key(doc.querySelector('[name=number]'), 'ArrowDown');
  await key(doc.querySelector('[name=number]'), 'Enter');
  await tick(10);
  assert.equal(count('cards.fill'), 0);
  // A script's click never counts.
  await tick(ui.MIN_VISIBLE_MS + 30);
  entries()[0].dispatchEvent(new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true }));
  await tick(10);
  assert.equal(count('cards.fill'), 0);

  await click(entries()[0]);
  await tick(30);
  assert.deepEqual(sent.filter((m) => m.type === 'cards.fill'), [{ type: 'cards.fill', id: 'visa' }]);
  assert.deepEqual([v('holder'), v('number'), v('exp'), v('cvc')], ['Ada Lovelace', '4242424242424242', '04 / 29', '737']);
  assert.equal(v('cvc2'), '', 'a hidden field is never filled');
  assert.equal(doc.querySelector('pass-menu'), null, 'the menu closed');
});

test('an agent without cards: no icon, no menu, no list', async () => {
  features = { cards: false, identities: true };
  await runtimeListener({ type: 'lock_state', locked: false }, { id: 'pass-ext' }, () => {}); // forgets the page's answer
  await load(CARD_FORM);
  sent.length = 0;
  await focusByUser(doc.querySelector('[name=holder]'));
  assert.equal(doc.querySelector('pass-menu'), null);
  assert.equal(count('cards.list'), 0);
  features = { cards: true, identities: true };
  await runtimeListener({ type: 'lock_state', locked: false }, { id: 'pass-ext' }, () => {});
});

test('an address form: the identities, and picking one fills the whole form', async () => {
  await load(`<form><input name="fname" autocomplete="given-name"><input name="lname" autocomplete="family-name">
    <input name="street" autocomplete="address-line1"><input name="city" autocomplete="address-level2"><input name="zip" autocomplete="postal-code">
    <select name="country" autocomplete="country"><option value="">--</option><option value="GB">United Kingdom</option></select></form>`);
  sent.length = 0;
  await focusByUser(doc.querySelector('[name=fname]'));
  assert.equal(rootOf('pass-menu').querySelector('.head').textContent, 'Passyble · Addresses');
  assert.deepEqual(entries().map((e) => e.querySelector('.sub').textContent), ['Ada Lovelace · ada@example.org']);
  await tick(ui.MIN_VISIBLE_MS + 30);
  await click(entries()[0]);
  await tick(30);
  assert.deepEqual(sent.filter((m) => m.type === 'identities.fill'), [{ type: 'identities.fill', id: 'home' }]);
  assert.deepEqual(['fname', 'lname', 'street', 'city', 'zip', 'country'].map(v), ['Ada', 'Lovelace', "12 St James's Square", 'London', 'SW1Y 4JH', 'GB']);
});

test('a click on a card field with the icon opens its menu again after Esc; not without cards', async () => {
  await load(CARD_FORM);
  const number = doc.querySelector('[name=number]');
  await focusByUser(number);
  assert.ok(doc.querySelector('pass-menu'), 'opened on focus');
  await key(number, 'Escape');
  assert.equal(doc.querySelector('pass-menu'), null);
  await click(number);
  await tick(30);
  assert.ok(doc.querySelector('pass-menu'), 'the click reopened it');
  assert.equal(rootOf('pass-menu').querySelector('.head').textContent, 'Passyble · Cards');
  assert.equal(rootOf('pass-menu').querySelector('.item.active'), null, 'nothing preselected');
  await key(number, 'Escape');
  const list = responses['cards.list'];
  responses['cards.list'] = () => ({ ok: true, result: { items: [], locked: false } });
  try {
    await click(number);
    await tick(30);
    assert.equal(doc.querySelector('pass-menu'), null, 'no cards: nothing to offer');
  } finally {
    responses['cards.list'] = list;
  }
  number.blur();
});

test('login fields keep the login menu, even inside a form with names', async () => {
  await load(`<form><h1>Create account</h1><input name="first_name" placeholder="First name"><input name="last_name" placeholder="Last name">
    <input type="email" name="email" autocomplete="username"><input type="password" name="password"><button>Sign in</button></form>`);
  sent.length = 0;
  await focusByUser(doc.querySelector('[name=email]'));
  assert.equal(count('identities.list'), 0);
  assert.ok(count('logins.find') >= 1);
  assert.notEqual(rootOf('pass-menu')?.querySelector('.head').textContent, 'Passyble · Addresses');
});

test('a card form in a page that is not secure gets nothing (the agent would refuse it too)', async () => {
  const { isSecureFormUrl } = await import('../src/shared/cards.js');
  assert.equal(isSecureFormUrl('http://shop.example/checkout'), false);
  assert.equal(isSecureFormUrl('http://localhost:3000/'), true);
  assert.equal(isSecureFormUrl('https://js.stripe.com/v3/'), true);
  assert.equal(isSecureFormUrl('chrome-extension://x/popup.html'), false);
});
