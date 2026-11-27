// Real timers: each test waits a few seconds.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://shop.example/login', pretendToBeVisual: true });
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

const NOT_RUNNING = { ok: false, error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } };
const sent = [];
let running = false;
const responses = {
  'otp.context': () => ({ ok: true, result: { pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] } }),
  'forms.features': () => ({ ok: true, result: { cards: true, identities: false } }),
  'logins.find': () => (running
    ? { ok: true, result: { items: [{ id: 'shop', title: 'Shop', username: 'ada@example.org', has_totp: false, has_passkey: false }], pending_otp: null, locked: false } }
    : NOT_RUNNING),
  'cards.list': () => (running
    ? { ok: true, result: { items: [{ id: 'visa', title: 'Work card', brand: 'visa', last4: '4242', expiry_month: 4, expiry_year: 2029 }], locked: false } }
    : NOT_RUNNING),
  generate: () => NOT_RUNNING,
  'save.query': () => ({ ok: true, result: null }),
};

let main;
let t;
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
      onMessage: { addListener: () => {} },
    },
    storage: { local: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  main = await import('../src/content/main.js');
  ({ t } = await import('../src/shared/i18n.js'));
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));
const rootOf = (tag) => shadowRoots.get(doc.querySelector(tag));
const menuOpen = () => !!doc.querySelector('pass-menu')?.isConnected;
const titles = () => (menuOpen() ? [...rootOf('pass-menu').querySelectorAll('.item .title')].map((el) => el.textContent) : []);
const menuText = () => (menuOpen() ? [...rootOf('pass-menu').querySelectorAll('.msg')].map((el) => el.textContent).join(' ') : '');
const count = (type) => sent.filter((m) => m.type === type).length;

async function userFocus(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(30);
}

/** A click on the Passyble icon in the focused field. */
async function clickIcon() {
  const btn = rootOf('pass-icon').querySelector('.icon');
  await dispatchTrusted(btn, new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true, button: 0 }));
  await tick(30);
}

/** Every text the menu shows from now on (a "Loading" flash between two checks included). */
function watchMenu() {
  const seen = [];
  const observer = new w.MutationObserver(() => seen.push(menuText()));
  observer.observe(rootOf('pass-menu'), { subtree: true, childList: true, characterData: true });
  return { seen, stop: () => observer.disconnect() };
}

function reset(html) {
  running = false;
  doc.activeElement?.blur?.();
  if (menuOpen()) key(doc.body, 'Escape');
  doc.body.innerHTML = html;
}

test('the menu says Passyble isn\'t running, asks again quietly, and shows the logins once it answers', async () => {
  reset('<form><input type="email" name="email" autocomplete="username"><input type="password" name="password"><button>Sign in</button></form>');
  await tick(300);
  const email = doc.querySelector('[name=email]');
  await userFocus(email);
  await clickIcon();
  assert.ok(menuOpen(), 'the menu');
  assert.equal(menuText(), t('errAgentUnavailable'));
  const watch = watchMenu();
  const first = count('logins.find');
  await tick(2200);
  assert.equal(count('logins.find'), first + 1, 'asked again after 2 s');
  assert.equal(menuText(), t('errAgentUnavailable'), 'still not running');
  running = true;
  await tick(2100);
  watch.stop();
  assert.deepEqual(titles(), ['Shop'], 'the logins, in the same menu');
  assert.ok(!watch.seen.some((text) => text.includes(t('menuLoading'))), `no "Loading" in between: ${JSON.stringify(watch.seen)}`);
  const after = count('logins.find');
  await tick(2200);
  assert.equal(count('logins.find'), after, 'no more checks once it answered');
});

test('closing the menu stops the checks', async () => {
  reset('<form><input type="email" name="email" autocomplete="username"><input type="password" name="password"><button>Sign in</button></form>');
  await tick(300);
  const email = doc.querySelector('[name=email]');
  await userFocus(email);
  await clickIcon();
  assert.equal(menuText(), t('errAgentUnavailable'));
  await key(email, 'Escape');
  assert.ok(!menuOpen());
  const before = count('logins.find');
  await tick(2300);
  assert.equal(count('logins.find'), before, 'nothing asked for a closed menu');
});

test('a new-password field: the generator stays with the same password, and the logins follow when Passyble answers', async () => {
  reset(`<form><h1>Create your account</h1><input type="email" name="email" autocomplete="email">
    <input type="password" name="password" autocomplete="new-password"><input type="password" name="confirm" placeholder="Confirm password">
    <button type="submit">Create account</button></form>`);
  await tick(300);
  await userFocus(doc.querySelector('[name=password]'));
  await tick(1600); // the agent's generate fails: generated here
  assert.equal(menuText(), t('menuNotRunningGenerate'));
  assert.deepEqual(titles(), [t('menuGenerateEntry'), t('commonNoSymbols'), t('genOptionsEntry')]);
  const reveal = async () => {
    await dispatchTrusted(rootOf('pass-menu').querySelector('.reveal'), new w.MouseEvent('click', { bubbles: true, composed: true }));
    return rootOf('pass-menu').querySelector('.pw-val').textContent;
  };
  const password = await reveal();
  running = true;
  await tick(2300);
  assert.deepEqual(titles(), [t('menuGenerateEntry'), t('commonNoSymbols'), t('genOptionsEntry'), 'Shop']);
  assert.equal(menuText(), '', 'the not-running note is gone');
  assert.equal(await reveal(), password, 'the same generated password');
});

test('a card field: its menu shows the cards once Passyble answers', async () => {
  reset(`<form><input name="holder" autocomplete="cc-name"><input name="number" autocomplete="cc-number">
    <input name="exp" autocomplete="cc-exp"><input name="cvc" autocomplete="cc-csc"><button>Pay</button></form>`);
  await tick(300);
  await userFocus(doc.querySelector('[name=number]'));
  assert.ok(!menuOpen(), 'nothing on its own while Passyble is not running');
  await clickIcon();
  assert.equal(menuText(), t('errAgentUnavailable'));
  const before = count('cards.list');
  running = true;
  await tick(2300);
  assert.equal(count('cards.list'), before + 1);
  assert.equal(titles().length, 1);
  assert.equal(titles()[0], 'Work card');
});
