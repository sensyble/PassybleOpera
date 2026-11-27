// The in-page generator's options card (src/content/gen-options.js, main.js, menu.js) in jsdom with a fake runtime.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';
import { CHARSETS } from '../src/shared/generator.js';
const OPTIONS_KEY = 'generateOptions'; // shared/generate-prefs.js (imported before chrome exists, it would pin no API)

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://shop.example/account/create', pretendToBeVisual: true });
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

const AGENT_PW = 'Agent-Generated-Pw-123!';
const sent = [];
let local = {};
const ok = (result) => ({ ok: true, result });
const defaults = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ok({ items: [], pending_otp: null }),
  // The desktop app honours the length it is asked for (its default 20: AGENT_PW).
  generate: (msg) => ok({ password: msg.length === 20 ? AGENT_PW : `Ag3!${'k'.repeat(msg.length - 4)}` }),
  'save.query': () => ok(null),
  'draft.save': () => ok({ id: 'draft-1', created: true, title: 'shop.example' }),
};
let responses = { ...defaults };

let main;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : ok({});
      },
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: { get: async (keys) => Object.fromEntries(keys.filter((k) => k in local).map((k) => [k, structuredClone(local[k])])) },
      sync: { get: async () => ({}) },
      onChanged: { addListener: () => {} },
    },
  };
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const VISIBLE = 520; // clicks count once the UI was visible for 500 ms (ui-common.js)

const rootOf = (tag) => {
  const host = doc.querySelector(tag);
  return host ? shadowRoots.get(host) : null;
};
const card = () => rootOf('pass-gen-options');
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));
const key = (el, k, opts = {}) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true, ...opts }));

/** A trusted change of a control in the card: a slider moved, a chip or radio clicked. */
async function change(el, value) {
  if (el.type === 'range') {
    el.value = String(value);
    await dispatchTrusted(el, new w.Event('input', { bubbles: true, composed: true }));
  } else {
    el.checked = value;
    await dispatchTrusted(el, new w.Event('change', { bubbles: true, composed: true }));
  }
  await tick(30);
}

async function userFocus(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(20);
}

function reset(html, stored = {}) {
  doc.body.innerHTML = html;
  sent.length = 0;
  local = stored;
  responses = { ...defaults };
}

const signup = (attrs = '') => `<form><h1>Create your account</h1>
  <input type="email" name="email" autocomplete="email" value="me@x.test">
  <input type="password" name="password" autocomplete="new-password" ${attrs}>
  <input type="password" name="confirm" placeholder="Confirm password">
  <button type="submit">Create account</button></form>`;

/** Focuses the new-password field, closes the menu that opens on its own, then clicks the chevron. */
async function openFromChevron(attrs = '', stored = {}) {
  reset(signup(attrs), stored);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await key(pw, 'Escape');
  const more = rootOf('pass-icon').querySelector('.gen-more');
  assert.ok(more && !more.hidden, 'the options chevron is there');
  assert.equal(more.getAttribute('aria-expanded'), 'false');
  await tick(VISIBLE);
  await click(more);
  await tick(60);
  return { pw, more };
}

const filled = () => sent.filter((m) => m.type === 'generate.filled');
const chip = (name) => card().querySelector(`input[name=${name}]`);

test('the chevron fills a strong password at once and opens the card with it', async () => {
  const { pw, more } = await openFromChevron();
  assert.equal(pw.value, AGENT_PW, 'filled with the desktop app\'s password (default options)');
  assert.equal(doc.querySelector('[name=confirm]').value, AGENT_PW);
  const root = card();
  assert.ok(root, 'card open');
  assert.equal(more.getAttribute('aria-expanded'), 'true');
  const box = root.querySelector('[role=dialog]');
  assert.equal(box.getAttribute('aria-label'), 'Password generator');
  assert.equal(root.querySelector('input[value=password]').checked, true);
  assert.equal(root.querySelector('#g-length').value, '20');
  for (const name of ['uppercase', 'lowercase', 'digits', 'symbols']) assert.equal(chip(name).checked, true, name);
  // The value is CSS generated content, never text in the shadow root.
  assert.ok(!root.querySelector('.value').textContent.includes(AGENT_PW.slice(0, 6)));
  assert.match(root.querySelector('style:not(:first-child)')?.textContent || [...root.querySelectorAll('style')].map((s) => s.textContent).join(''), /content: "\\/);
  assert.ok(!sent.some((m) => m.type === 'draft.save'), 'not saved while the card is open');
  await key(box, 'Escape');
  assert.equal(card(), null, 'Escape closes it');
  assert.equal(doc.activeElement, pw, 'the focus is back in the field');
  await tick(20);
  assert.equal(sent.filter((m) => m.type === 'draft.save').length, 1, 'saved like the generate button');
  assert.equal(more.getAttribute('aria-expanded'), 'false');
});

test('length, character types and passphrase change the filled value live and are sent to be remembered', async () => {
  const { pw } = await openFromChevron();
  await change(card().querySelector('#g-length'), 32);
  assert.equal(pw.value.length, 32);
  assert.notEqual(pw.value, AGENT_PW);
  assert.deepEqual(filled().at(-1).options, { mode: 'password', length: 32, lowercase: true, uppercase: true, digits: true, words: 6 });

  await change(chip('symbols'), false);
  assert.match(pw.value, /^[A-Za-z0-9]{32}$/, 'no special characters');
  assert.equal(filled().at(-1).symbols, false, 'the site\'s "letters and numbers only" choice');

  await change(chip('uppercase'), false);
  await change(chip('digits'), false);
  assert.match(pw.value, /^[a-z]{32}$/, 'lower case only');
  assert.equal(chip('lowercase').disabled, true, 'the last type on stays on');
  for (const c of pw.value) assert.ok(CHARSETS.lowercase.includes(c));

  await change(card().querySelector('input[value=passphrase]'), true);
  assert.equal(card().querySelector('.part-password').hidden, true);
  assert.equal(card().querySelector('.part-passphrase').hidden, false);
  // Special characters are off for this site: a CamelCase passphrase, letters and one digit.
  assert.match(pw.value, /^(?:[A-Z][a-z]+\d?){6}$/, pw.value);
  await change(chip('hyphens'), true);
  assert.match(pw.value, /^[a-z-]+\d?(?:-[a-z-]+\d?){5}$/, pw.value);
  assert.equal((pw.value.match(/\d/g) || []).length, 1, 'one digit');
  await change(card().querySelector('#g-words'), 4);
  assert.equal(filled().at(-1).options.words, 4);
  assert.equal(filled().at(-1).options.mode, 'passphrase');
  assert.equal(doc.querySelector('[name=confirm]').value, pw.value, 'the confirmation follows');

  const before = pw.value;
  await tick(VISIBLE); // the card's buttons, like every in-page button, count once shown for a moment
  const regenerate = [...card().querySelectorAll('.btn')].find((b) => b.textContent === 'Regenerate');
  await click(regenerate);
  await tick(30);
  assert.notEqual(pw.value, before, 'a new one with the same options');
  const done = card().querySelector('.btn.primary');
  await click(done);
  await tick(20);
  assert.equal(card(), null);
  assert.deepEqual(sent.filter((m) => m.type === 'draft.save').map((m) => m.password), [pw.value], 'the last one saved');
});

test('the field\'s rules: special characters off and disabled, the length capped, each with a note', async () => {
  const { pw } = await openFromChevron('pattern="[A-Za-z0-9]{8,16}"');
  assert.match(pw.value, /^[A-Za-z0-9]{16}$/);
  assert.equal(chip('symbols').checked, false);
  assert.equal(chip('symbols').disabled, true);
  const notes = [...card().querySelectorAll('.note')].map((n) => n.textContent);
  assert.deepEqual(notes, ['This site doesn\'t take special characters.', 'This site takes at most 16 characters.']);
  assert.equal(card().querySelector('#g-length').max, '16');
  await change(card().querySelector('input[value=passphrase]'), true);
  assert.match(pw.value, /^[A-Za-z0-9]{16}$/, 'no passphrase fits 16 characters: still a password');
  assert.ok([...card().querySelectorAll('.note')].some((n) => /passphrase doesn't fit/.test(n.textContent)));
  await key(card().querySelector('[role=dialog]'), 'Escape');
});

test('untrusted events on the card change nothing', async () => {
  const { pw } = await openFromChevron();
  const length = card().querySelector('#g-length');
  length.value = '40';
  length.dispatchEvent(new w.Event('input', { bubbles: true, composed: true }));
  const symbols = chip('symbols');
  symbols.checked = false;
  symbols.dispatchEvent(new w.Event('change', { bubbles: true, composed: true }));
  await tick(30);
  assert.equal(pw.value, AGENT_PW);
  assert.equal(symbols.checked, true, 'drawn again as it was');
  card().querySelector('.btn.primary').dispatchEvent(new w.MouseEvent('click', { bubbles: true, composed: true }));
  await tick(20);
  assert.ok(card(), 'still open');
  await key(card().querySelector('[role=dialog]'), 'Escape', {});
});

test('typing in the field or a click outside closes the card', async () => {
  let { pw } = await openFromChevron();
  await key(pw, 'a');
  assert.equal(card(), null, 'typing: the user\'s own password');
  ({ pw } = await openFromChevron());
  await dispatchTrusted(doc.body, new w.MouseEvent('mousedown', { bubbles: true, composed: true }));
  assert.equal(card(), null, 'a click outside');
  await tick(20);
  assert.equal(sent.filter((m) => m.type === 'draft.save').length, 1, 'still saved');
});

test('the menu\'s "Password options" row opens the card with the focus inside, and Tab stays there', async () => {
  reset(signup());
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  const menuRoot = rootOf('pass-menu');
  const titles = [...menuRoot.querySelectorAll('.item .title')].map((el) => el.textContent);
  assert.deepEqual(titles.slice(0, 3), ['Generate strong password', 'Letters and numbers only', 'Password options']);
  await key(pw, 'ArrowDown');
  await key(pw, 'ArrowDown');
  await key(pw, 'Enter');
  await tick(60);
  const root = card();
  assert.ok(root, 'card open');
  assert.equal(pw.value, AGENT_PW, 'the menu\'s preview filled');
  assert.equal(root.activeElement, root.querySelector('input[value=password]'), 'the focus is on the switch');
  const box = root.querySelector('[role=dialog]');
  const order = [];
  for (let i = 0; i < 12; i++) {
    await key(box, 'Tab');
    order.push(root.activeElement?.getAttribute('aria-label') || root.activeElement?.textContent || root.activeElement?.id);
  }
  assert.ok(order.includes('Length') && order.includes('Regenerate') && order.includes('Done') && order.includes('Close'), order.join(', '));
  assert.ok(root.activeElement && root.contains(root.activeElement), 'Tab stays in the card');
  await key(box, 'Escape');
  assert.equal(doc.activeElement, pw);
  await tick(20);
  assert.ok(!sent.some((m) => m.type === 'draft.save'), 'from the menu, unchanged: nothing saved (the submit saves it)');
});

test('saved options decide what the generate button makes: a passphrase, made here', async () => {
  reset(signup(), { [OPTIONS_KEY]: { mode: 'passphrase', length: 20, lowercase: true, uppercase: true, digits: true, words: 5 } });
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await key(pw, 'Escape');
  await tick(VISIBLE);
  await click(rootOf('pass-icon').querySelector('.gen'));
  await tick(60);
  assert.match(pw.value, /^[a-z-]+\d?(?:-[a-z-]+\d?){4}$/, pw.value);
  assert.ok(!sent.some((m) => m.type === 'generate'), 'the desktop app makes passwords only');
  assert.equal(sent.find((m) => m.type === 'draft.save')?.password, pw.value);
  assert.equal(filled().at(-1).options, undefined, 'the button itself changes no options');
});
