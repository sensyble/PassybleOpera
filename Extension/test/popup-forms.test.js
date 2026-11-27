import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
const clipboard = [];

const CARDS = [
  { id: 'visa', title: 'Work card', cardholder_name: 'Ada Lovelace', brand: 'visa', last4: '4242', expiry_month: 4, expiry_year: 2029 },
  { id: 'mc', title: 'Mastercard •••• 4444', cardholder_name: 'Ada Lovelace', brand: 'mastercard', last4: '4444', expiry_month: 0, expiry_year: 0 },
];
const IDENTITIES = [{ id: 'home', title: 'Home', full_name: 'Ada Lovelace', email: 'ada@example.org', company: 'Engines' }];

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = dom.window;
  dom.window.close = () => {};
  Object.defineProperty(globalThis, 'navigator', {
    value: { clipboard: { writeText: async (t) => { clipboard.push(t); } } }, configurable: true,
  });
  messages.length = 0;
  clipboard.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function type($, text) {
  $('search').value = text;
  $('search').dispatchEvent(new globalThis.Event('input'));
}

const formsReply = (state = {}) => (msg) => {
  if (msg.type === 'popup.state') {
    return { ok: true, result: { url: 'https://shop.example/checkout', supported: true, locked: false, items: [], pending_otp: null,
      can_edit: true, can_search: false, can_cards: true, can_identities: true, ...state } };
  }
  if (msg.type === 'popup.forms') return { ok: true, result: { cards: CARDS, identities: IDENTITIES, locked: false } };
  if (msg.type === 'popup.card-copy') return { ok: true, result: { value: msg.field === 'number' ? '4242424242424242' : '737' } };
  if (msg.type === 'popup.identity-copy') return { ok: true, result: { value: msg.field === 'email' ? 'ada@example.org' : 'Ada Lovelace' } };
  if (msg.type === 'clipboard.copied') return { ok: true, result: { scheduled: true } };
  return { ok: true, result: null };
};

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, url: 'https://shop.example/checkout' }] },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('the search finds cards (brand, last four digits, expiry) and identities; no secret is listed', async () => {
  reply = formsReply();
  const { $ } = await openPopup();
  type($, 'v');
  await wait(20);
  assert.equal($('forms').hidden, true, 'one character: nothing yet');
  assert.ok(!messages.some((m) => m.type === 'popup.forms'));
  type($, 'visa');
  await wait(20);
  assert.equal($('forms').hidden, false);
  const rows = [...$('forms-list').children];
  assert.deepEqual(rows.map((r) => r.dataset.id), ['visa']);
  assert.equal(rows[0].querySelector('.title').textContent, 'Work card');
  assert.equal(rows[0].querySelector('.sub').textContent, 'Visa •••• 4242 · 04/29');
  assert.equal(rows[0].querySelector('.avatar').textContent, 'VISA');
  assert.deepEqual(messages.filter((m) => m.type === 'popup.forms'), [{ type: 'popup.forms', tabId: 1 }]);

  type($, 'card');
  await wait(20);
  assert.deepEqual([...$('forms-list').children].map((r) => r.dataset.id), ['visa', 'mc'], 'every card for "card"');
  assert.equal($('forms-list').querySelector('[data-id="mc"] .sub').textContent, 'Mastercard •••• 4444');
  type($, 'ada eng');
  await wait(20);
  assert.deepEqual([...$('forms-list').children].map((r) => r.dataset.id), ['home']);
  assert.equal($('forms-list').querySelector('.sub').textContent, 'Ada Lovelace · ada@example.org');
  assert.equal(messages.filter((m) => m.type === 'popup.forms').length, 1, 'listed once per popup');
  assert.ok(!messages.some((m) => m.type === 'popup.card-copy'), 'nothing fetched before a copy');
});

test('copying a card number or security code fetches it then; it is cleared from the clipboard after 45 s', async () => {
  reply = formsReply();
  const { $ } = await openPopup();
  type($, 'work');
  await wait(20);
  const row = $('forms-list').querySelector('[data-id="visa"]');
  const button = (label) => [...row.querySelectorAll('.icon-btn')].find((b) => b.title === label);
  button('Copy card number').click();
  await wait(10);
  assert.deepEqual(messages.find((m) => m.type === 'popup.card-copy'), { type: 'popup.card-copy', tabId: 1, id: 'visa', field: 'number' });
  assert.deepEqual(clipboard, ['4242424242424242']);
  assert.deepEqual(messages.find((m) => m.type === 'clipboard.copied'), { type: 'clipboard.copied', value: '4242424242424242' });
  assert.match($('snack').textContent, /Card number copied \(clears in 45 s\)/);

  button('Copy security code').click();
  await wait(10);
  assert.equal(clipboard.at(-1), '737');
  // The expiry is in the list: copied without asking the desktop app.
  const before = messages.filter((m) => m.type === 'popup.card-copy').length;
  button('Copy expiry date').click();
  await wait(10);
  assert.equal(clipboard.at(-1), '04/29');
  assert.equal(messages.filter((m) => m.type === 'popup.card-copy').length, before);
  // The row's own click copies the number too.
  row.querySelector('button.item-main').click();
  await wait(10);
  assert.equal(messages.filter((m) => m.type === 'popup.card-copy').at(-1).field, 'number');
});

test('declined in the desktop app (quiet: the user said no there), or an older desktop app (a message): nothing copied', async () => {
  reply = (msg) => (msg.type === 'popup.card-copy'
    ? { ok: false, error: { code: messages.filter((m) => m.type === 'popup.card-copy').length > 1 ? 'not_supported' : 'cancelled', message: 'declined' } }
    : formsReply()(msg));
  const { $ } = await openPopup();
  type($, 'work');
  await wait(20);
  const row = $('forms-list').querySelector('[data-id="visa"]');
  row.querySelector('button.item-main').click();
  await wait(10);
  assert.equal($('snack').textContent, '');
  row.querySelector('button.item-main').click();
  await wait(10);
  assert.match($('snack').textContent, /Update the Passyble desktop app/);
  assert.deepEqual(clipboard, []);
});

test('an identity\'s e-mail and name are copied on demand (plain values, not cleared)', async () => {
  reply = formsReply();
  const { $ } = await openPopup();
  type($, 'home');
  await wait(20);
  const row = $('forms-list').querySelector('[data-id="home"]');
  row.querySelector('button.item-main').click();
  await wait(10);
  assert.deepEqual(messages.find((m) => m.type === 'popup.identity-copy'), { type: 'popup.identity-copy', tabId: 1, id: 'home', field: 'email' });
  assert.deepEqual(clipboard, ['ada@example.org']);
  assert.ok(!messages.some((m) => m.type === 'clipboard.copied'));
});

test('a desktop app without cards and addresses (or the setting off): no section, no list', async () => {
  reply = formsReply({ can_cards: false, can_identities: false });
  const { $ } = await openPopup();
  type($, 'visa');
  await wait(20);
  assert.equal($('forms').hidden, true);
  assert.ok(!messages.some((m) => m.type === 'popup.forms'));
});
