// Sign-in suggestions opening for the page's own focus (src/content/main.js in jsdom): never after a click or key
// in the page, nor later than 10 s. Windows Hello never starts from this. Demo data only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://app.example/', pretendToBeVisual: true });
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

let visibility = 'visible';
Object.defineProperty(doc, 'visibilityState', { configurable: true, get: () => visibility });
Object.defineProperty(doc, 'hidden', { configurable: true, get: () => visibility === 'hidden' });

const sent = [];
let runtimeListener;
const ITEMS = [{ id: 'a', title: 'Demo app', username: 'demo@example.com', has_totp: false, has_passkey: false }];
const ok = (result) => ({ ok: true, result });
let loginsFind = () => ok({ items: ITEMS, pending_otp: null });
const responses = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => loginsFind(),
  'logins.fill': () => ok({ username: 'demo@example.com', password: 'demo-password', totp: null }),
  'unlock.options': () => ok({ inline: true, locked: true, hello: true }),
  'save.query': () => ok(null),
};

const LOGIN = `<form><h1>Sign in</h1><input type="email" name="email" autocomplete="username" placeholder="Email">
  <input type="password" name="password" autocomplete="current-password"><button type="submit">Sign in</button></form>`;
const EMAIL_STEP = `<form><h1>Sign in</h1><input type="email" name="email" autocomplete="username" placeholder="Email">
  <button type="button">Next</button></form>`;
const PASSWORD_STEP = `<form><h1>Enter your password</h1><input type="password" name="password" autocomplete="current-password">
  <button type="button">Sign in</button></form>`;

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
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : ok({});
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: {
      local: { get: async () => ({}) },
      sync: { get: async () => ({}) },
      onChanged: { addListener: () => {} },
    },
  };
  doc.body.innerHTML = LOGIN;
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));
const press = (el) => dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
const menuRoot = () => {
  const host = doc.querySelector('pass-menu');
  return host ? shadowRoots.get(host) : null;
};
const titles = () => (menuRoot() ? [...menuRoot().querySelectorAll('.item .title')].map((el) => el.textContent) : []);
const count = (type) => sent.filter((m) => m.type === type).length;

/** Leaves the current field and menu, then an SPA navigation to `path` that renders `html`. */
async function navigate(path, html) {
  if (doc.querySelector('pass-menu')) await key(doc.activeElement, 'Escape');
  doc.activeElement?.blur?.();
  w.history.pushState({}, '', path);
  doc.body.innerHTML = html;
  await tick(300); // the scan sees the new route and its form
}

test('a script focus as the page loads opens the suggestions with the first login preselected, Enter fills it', async () => {
  await tick(30);
  assert.equal(doc.querySelector('pass-menu'), null, 'nothing focused yet: no menu');
  const email = doc.querySelector('[name=email]');
  email.focus(); // the site's script, after it rendered (no `autofocus` attribute)
  await tick(30);
  assert.deepEqual(titles(), ['Demo app']);
  assert.ok(menuRoot().querySelector('.item.active'), 'the first login is preselected');
  assert.equal(count('logins.fill'), 0, 'never filled on its own');
  await key(email, 'Enter');
  await tick(30);
  assert.equal(count('logins.fill'), 1, 'Enter fills the preselected login');
  assert.equal(email.value, 'demo@example.com');
});

test('after a click in the page, the page\'s focus opens nothing', async () => {
  await navigate('/account/login', LOGIN);
  await press(doc.body);
  await tick(1100); // the click ages out: it was not on the field
  doc.querySelector('[name=email]').focus();
  await tick(30);
  assert.ok(doc.querySelector('pass-icon'), 'icon');
  assert.equal(doc.querySelector('pass-menu'), null, 'not the page\'s initial focus');
});

test('a focus later than 10 s after the step started opens nothing', async () => {
  await navigate('/late', LOGIN);
  const realNow = Date.now;
  Date.now = () => realNow() + 11_000;
  try {
    doc.querySelector('[name=email]').focus();
    await tick(30);
  } finally {
    Date.now = realNow;
  }
  assert.equal(doc.querySelector('pass-menu'), null);
});

test('identifier-first: the password step\'s own focus opens it once; typing closes it', async () => {
  await navigate('/signin', EMAIL_STEP);
  const fillsBefore = count('logins.fill');
  const email = doc.querySelector('[name=email]');
  email.focus();
  await tick(30);
  assert.deepEqual(titles(), ['Demo app'], 'the e-mail step (an SPA navigation)');
  // The user types the e-mail address and presses Enter; the site shows the password step and focuses it.
  await key(email, 'o');
  email.value = 'demo@example.com';
  await dispatchTrusted(email, new w.Event('input', { bubbles: true, composed: true }));
  await key(email, 'Escape');
  await key(email, 'Enter');
  doc.body.innerHTML = PASSWORD_STEP;
  const password = doc.querySelector('[name=password]');
  password.focus();
  await tick(30);
  assert.deepEqual(titles(), ['Demo app'], 'the password step');
  assert.ok(menuRoot().querySelector('.item.active'), 'the first login is preselected');
  await key(password, 'x');
  password.value = 'x';
  await dispatchTrusted(password, new w.Event('input', { bubbles: true, composed: true }));
  await tick(10);
  assert.equal(doc.querySelector('pass-menu'), null, 'typing in the password field closes it');
  password.value = '';
  password.blur();
  password.focus();
  await tick(30);
  assert.equal(doc.querySelector('pass-menu'), null, 'once per field');
  assert.equal(count('logins.fill'), fillsBefore);
});

test('logins that come late (Passyble starting) open the suggestions while the field keeps the focus', async () => {
  loginsFind = () => ({ ok: false, error: { code: 'agent_unavailable', message: 'Passyble desktop app is not running' } });
  await navigate('/starting', LOGIN);
  const email = doc.querySelector('[name=email]');
  email.focus();
  await tick(50);
  assert.equal(doc.querySelector('pass-menu'), null, 'not running yet');
  loginsFind = () => ok({ items: ITEMS, pending_otp: null });
  await tick(2100);
  assert.deepEqual(titles(), ['Demo app'], 'opened once the logins came');
  assert.ok(menuRoot().querySelector('.item.active'), 'first login preselected');
});

test('late logins: not after the user typed, clicked or left the field', async () => {
  loginsFind = () => ({ ok: false, error: { code: 'agent_unavailable', message: 'Passyble desktop app is not running' } });
  await navigate('/starting-2', LOGIN);
  const email = doc.querySelector('[name=email]');
  email.focus();
  await tick(50);
  await press(doc.querySelector('h1')); // the user clicks the page meanwhile (the field keeps the focus here)
  loginsFind = () => ok({ items: ITEMS, pending_otp: null });
  await tick(2100);
  assert.equal(doc.querySelector('pass-menu'), null);
});

test('fully locked: nothing on its own, no Windows Hello; unlocked meanwhile, the logins open', async () => {
  loginsFind = () => ({ ok: false, error: { code: 'locked', message: 'Vault is locked' } });
  const before = count('unlock.options') + count('unlock.hello') + count('unlock');
  await navigate('/locked', LOGIN);
  const email = doc.querySelector('[name=email]');
  email.focus();
  await tick(50);
  assert.equal(doc.querySelector('pass-menu'), null, 'no unlock choices on their own');
  loginsFind = () => ok({ items: ITEMS, pending_otp: null });
  await new Promise((resolve) => runtimeListener({ type: 'lock_state', locked: false }, { id: 'pass-ext' }, resolve));
  await tick(30);
  assert.deepEqual(titles(), ['Demo app']);
  assert.ok(menuRoot().querySelector('.item.active'), 'first login preselected');
  assert.equal(count('unlock.options') + count('unlock.hello') + count('unlock'), before, 'never asked to unlock');
});

test('soft-locked: the kept list opens under the locked heading', async () => {
  loginsFind = () => ok({ items: ITEMS, pending_otp: null, locked: true });
  await navigate('/soft', LOGIN);
  doc.querySelector('[name=email]').focus();
  await tick(30);
  assert.deepEqual(titles(), ['Demo app']);
  assert.equal(count('unlock.hello'), 0);
  loginsFind = () => ok({ items: ITEMS, pending_otp: null });
});

test('a background tab: nothing while hidden, the suggestions open when it shows', async () => {
  await navigate('/background', LOGIN);
  visibility = 'hidden';
  doc.dispatchEvent(new w.Event('visibilitychange'));
  const finds = count('logins.find');
  doc.querySelector('[name=email]').focus();
  await tick(50);
  assert.equal(doc.querySelector('pass-menu'), null, 'no menu in a hidden tab');
  assert.equal(count('logins.find'), finds, 'not even asked while hidden');
  await tick(200);
  visibility = 'visible';
  doc.dispatchEvent(new w.Event('visibilitychange'));
  await tick(30);
  assert.deepEqual(titles(), ['Demo app'], 'opened once the tab shows');
});

test('a field the page focused before its form was known opens the suggestions once the form is complete', async () => {
  await navigate('/render', '<div id="late"><input type="text" name="field1"></div>');
  const login = doc.querySelector('[name=field1]');
  login.focus();
  await tick(30);
  assert.equal(doc.querySelector('pass-menu'), null, 'nothing knows the field yet');
  doc.getElementById('late').insertAdjacentHTML('beforeend', '<input type="password" name="password"><button type="submit">Sign in</button>');
  await tick(350);
  assert.deepEqual(titles(), ['Demo app']);
  assert.ok(menuRoot().querySelector('.item.active'), 'first login preselected');
});

test('the preselected login: a page-made Enter fills nothing, Enter with the menu closed is the page\'s', async () => {
  await navigate('/enter-guard', LOGIN);
  const fillsBefore = count('logins.fill');
  const email = doc.querySelector('[name=email]');
  email.focus();
  await tick(30);
  assert.ok(menuRoot().querySelector('.item.active'), 'first login preselected');
  email.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, composed: true, cancelable: true }));
  await tick(30);
  assert.equal(count('logins.fill'), fillsBefore, 'an untrusted Enter never fills');
  await key(email, 'Escape');
  const notCancelled = await key(email, 'Enter');
  await tick(30);
  assert.equal(notCancelled, true, 'menu closed: Enter reaches the page');
  assert.equal(count('logins.fill'), fillsBefore);
});
