// "Save card to Passyble?" in the page (src/content/main.js, card-capture.js, banner.js) in jsdom: never the security
// code sent, never the number shown; the banner's buttons send its token only. Test card numbers only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM(`<!doctype html><html><body>
  <form id="pay" action="/pay">
    <input name="ccname" autocomplete="cc-name">
    <input name="cardnumber" autocomplete="cc-number" inputmode="numeric">
    <input name="exp" autocomplete="cc-exp" placeholder="MM / YY">
    <input name="cvc" autocomplete="cc-csc">
    <button type="button" id="paybtn">Pay now</button>
  </form></body></html>`, { url: 'https://shop.example/checkout', pretendToBeVisual: true });
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

const ORIGIN = 'chrome-extension://pass-ext';
const sent = [];
let query = () => null;
const responses = {
  'otp.context': () => ({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ({ items: [], pending_otp: null }),
  'save.query': () => null,
  'card.query': (msg) => query(msg),
  'card.commit': () => ({ id: 'new-card', action: 'save_new' }),
  'card.never': () => ({ site: 'https://shop.example' }),
};

let main;
let runtimeListener;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `${ORIGIN}/${p}`,
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return { ok: true, result: fn ? fn(msg) : {} };
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: { local: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  globalThis.__passBridge = { alive: () => true, hasConditional: () => false, onConditionalChange: () => () => {}, completeConditional: async () => ({ ok: true }) };
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (fn, ms = 2000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = fn(); if (v) return v; await tick(20); }
  return fn();
};
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));
const bannerRoot = () => shadowRoots.get(doc.querySelector('pass-banner'));
const offer = (extra = {}) => new Promise((resolve) => {
  if (!runtimeListener({ type: 'card.offer', ...extra }, { id: 'pass-ext' }, resolve)) resolve(undefined);
});
const set = (name, value) => { doc.querySelector(`[name=${name}]`).value = value; };

test('a click on "Pay now" sends the card, never its security code', async () => {
  set('ccname', 'Ada Lovelace');
  set('cardnumber', '4242 4242 4242 4242');
  set('exp', '04 / 29');
  set('cvc', '737');
  await click(doc.getElementById('paybtn'));
  const captured = await waitFor(() => sent.find((m) => m.type === 'card.capture'));
  assert.deepEqual(captured, { type: 'card.capture', number: '4242424242424242', expiry_month: 4, expiry_year: 2029, cardholder_name: 'Ada Lovelace' });
  assert.ok(!sent.some((m) => JSON.stringify(m).includes('737')), 'the security code goes nowhere');
  // The same card right after (click and submit): sent once.
  await dispatchTrusted(doc.getElementById('pay'), new w.Event('submit', { bubbles: true, cancelable: true }));
  assert.equal(sent.filter((m) => m.type === 'card.capture').length, 1);
});

test('a bad number is not sent', async () => {
  set('cardnumber', '4242 4242 4242 4241');
  set('exp', '05 / 31');
  await dispatchTrusted(doc.getElementById('pay'), new w.Event('submit', { bubbles: true, cancelable: true }));
  await tick(20);
  assert.equal(sent.filter((m) => m.type === 'card.capture').length, 1);
});

test('card.offer shows "Save card to Passyble?" with the last four digits; Save sends the token only', async () => {
  query = () => ({ mode: 'save', host: 'shop.example', brand: 'visa', last4: '4242', expiry_month: 4, expiry_year: 2029,
    token: 'card-tok', editable: true });
  await offer();
  const host = await waitFor(() => doc.querySelector('pass-banner'));
  assert.ok(host);
  const root = bannerRoot();
  const text = root.textContent;
  assert.ok(text.includes('Save card to Passyble?'), text);
  assert.ok(text.includes('Visa •••• 4242 · 04/29'), text);
  assert.ok(text.includes("The security code isn't saved. You can add it to the card in Passyble."), text);
  assert.ok(text.includes('shop.example'));
  assert.ok(!doc.documentElement.outerHTML.includes('Visa •••• 4242'), 'inside the closed shadow root only');
  await click(root.querySelector('button.edit'));
  const frame = root.querySelector('iframe.edit-frame');
  assert.equal(frame.getAttribute('src'), `${ORIGIN}/src/save/card-edit.html`);
  assert.equal(frame.title, 'Passyble card details');
  await click(root.querySelector('button.edit')); // folded away again
  await tick(1100); // the click guard: a banner only just shown takes no clicks
  const save = [...root.querySelectorAll('button')].find((b) => b.textContent === 'Save');
  await click(save);
  const commit = await waitFor(() => sent.find((m) => m.type === 'card.commit'));
  assert.deepEqual(commit, { type: 'card.commit', token: 'card-tok' });
  assert.ok(await waitFor(() => bannerRoot()?.textContent.includes('Card saved to Passyble.')));
});

test('an answer without a card shows nothing; { close } removes a banner shown while locked', async () => {
  await waitFor(() => !doc.querySelector('pass-banner'), 3000);
  query = () => ({});
  await offer();
  await tick(30);
  assert.equal(doc.querySelector('pass-banner'), null, 'no token, no banner');
  query = () => ({ mode: 'update', host: 'shop.example', brand: 'visa', last4: '4242', expiry_month: 5, expiry_year: 2031,
    title: 'Visa •••• 4242', token: 'card-tok-2', editable: true });
  await offer();
  const root = shadowRoots.get(await waitFor(() => doc.querySelector('pass-banner')));
  assert.ok(root.textContent.includes('Update card expiry?'));
  assert.ok(root.textContent.includes('Visa •••• 4242 · 05/31'));
  query = () => ({ close: true });
  await offer({ recheck: true });
  assert.deepEqual(sent.filter((m) => m.type === 'card.query').at(-1), { type: 'card.query', recheck: true });
  await waitFor(() => !doc.querySelector('pass-banner'));
  assert.equal(doc.querySelector('pass-banner'), null);
});
