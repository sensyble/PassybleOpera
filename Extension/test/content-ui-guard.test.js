// Clickjacking guards: a click only counts on UI that was visible for a moment and not made
// see-through by the page.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://github.com/login', pretendToBeVisual: true });
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
let conditional = false;
const completed = [];
const responses = {
  'otp.context': () => ({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ({ items: [
    { id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: true },
    { id: 'gh2', title: 'GitHub work', username: 'octo-work', has_totp: false, has_passkey: false },
  ], pending_otp: null }),
  'logins.fill': () => ({ username: 'octo', password: 'hunter2', totp: null }),
  'save.query': () => null,
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
        return { ok: true, result: fn ? fn(msg) : {} };
      },
      onMessage: { addListener: () => {} },
    },
    storage: { local: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  // The isolated-world end of the WebAuthn channel (bridge.js), as main.js sees it.
  globalThis.__passBridge = {
    alive: () => true,
    hasConditional: () => conditional,
    onConditionalChange: () => () => {},
    completeConditional: async (id) => { completed.push(id); return { ok: true }; },
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
const entries = () => [...rootOf('pass-menu').querySelectorAll('.item')];
const fills = () => sent.filter((m) => m.type === 'logins.fill').length;
const LOGIN = '<form><h1>Sign in</h1><input type="email" name="email" autocomplete="username webauthn"><input type="password" name="password"><button>Sign in</button></form>';

test('menu: a click right after the entries appear, or on a see-through menu, fills nothing', async () => {
  doc.body.innerHTML = LOGIN;
  await tick(300);
  const email = doc.querySelector('[name=email]');
  await dispatchTrusted(email, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  email.focus();
  await tick(20);
  const host = doc.querySelector('pass-menu');
  assert.ok(host, 'menu opened on its own with the site logins (user focus)');
  assert.ok(rootOf('pass-menu').querySelector('.item.active'), 'suggestions: the first login preselected');
  const login = entries().find((el) => el.textContent.includes('GitHub work'));

  await click(login);
  await tick(10);
  assert.equal(fills(), 0, 'swapped in under the cursor: too soon to count');

  await tick(ui.MIN_VISIBLE_MS + 50);
  host.style.setProperty('opacity', '0', 'important'); // the page hides the menu behind a decoy
  await click(login);
  host.style.removeProperty('opacity');
  doc.documentElement.style.opacity = '0.02'; // or the whole page, our host included
  await click(login);
  doc.documentElement.style.opacity = '';
  host.style.setProperty('filter', 'opacity(0)');
  await click(login);
  host.style.removeProperty('filter');
  await tick(10);
  assert.equal(fills(), 0, 'invisible menu: no fill');
  assert.equal(email.value, '');

  await click(login);
  await tick(20);
  assert.equal(fills(), 1, 'visible for a moment: the click fills');
  assert.equal(email.value, 'octo');
  assert.equal(doc.querySelector('[name=password]').value, 'hunter2');
  doc.activeElement?.blur();
});

test('menu opened for a page passkey request (script focus): nothing preselected, Enter stays the page\'s', async () => {
  conditional = true;
  doc.body.innerHTML = LOGIN.replace('<form>', '<form id="f2">');
  await tick(300);
  const email = doc.querySelector('[name=email]');
  email.focus(); // by a script, no user gesture
  await tick(20);
  assert.ok(doc.querySelector('pass-menu'), 'menu opened for the conditional request');
  assert.equal(entries()[0].textContent.includes('Sign in with passkey'), true);
  assert.equal(rootOf('pass-menu').querySelector('.item.active'), null, 'no entry preselected');
  email.value = 'octo';
  const notCancelled = await key(email, 'Enter');
  await tick(10);
  assert.equal(notCancelled, true, 'Enter reaches the page (submits the typed username)');
  assert.equal(completed.length, 0, 'no passkey request completed');
  assert.equal(fills(), 1, 'no login filled');

  await key(email, 'ArrowDown');
  assert.ok(entries()[0].classList.contains('active'), 'ArrowDown picks the first entry');
  await key(email, 'Enter');
  await tick(10);
  assert.deepEqual(completed, ['gh'], 'an explicit choice still works');
  conditional = false;
});

test('save banner: Save on a just-shown or see-through banner is ignored', async () => {
  const { showSaveBanner } = await import('../src/content/banner.js');
  let saves = 0;
  showSaveBanner({ mode: 'update', host: 'github.com', username: 'octo', title: 'GitHub', onSave: async () => { saves++; }, onDismiss: () => {} });
  const host = doc.querySelector('pass-banner');
  const save = [...shadowRoots.get(host).querySelectorAll('button')].find((b) => b.textContent === 'Update');
  await click(save);
  assert.equal(saves, 0, 'too soon');
  await tick(ui.MIN_VISIBLE_MS + 50);
  host.style.setProperty('opacity', '0.01', 'important');
  await click(save);
  host.style.removeProperty('opacity');
  host.style.setProperty('clip-path', 'inset(50%)');
  await click(save);
  host.style.removeProperty('clip-path');
  assert.equal(saves, 0, 'hidden by the page');
  await click(save);
  await tick(10);
  assert.equal(saves, 1);
});

test('save banner: "Update username" mode', async () => {
  const { showSaveBanner } = await import('../src/content/banner.js');
  let saves = 0;
  showSaveBanner({ mode: 'username', host: 'github.com', username: 'octo@example.com', title: 'GitHub', onSave: async () => { saves++; }, onDismiss: () => {} });
  const host = [...doc.querySelectorAll('pass-banner')].at(-1);
  const root = shadowRoots.get(host);
  assert.equal(root.querySelector('.title').textContent, 'Update username?');
  assert.equal(root.querySelector('.sub').textContent, 'github.com', 'the site on its own line, as for Save');
  assert.equal(root.querySelector('.who .user').textContent, 'GitHub · octo@example.com', 'the login and its account');
  const update = [...root.querySelectorAll('button')].find((b) => b.textContent === 'Update');
  await tick(ui.MIN_VISIBLE_MS + 50);
  await click(update);
  await tick(10);
  assert.equal(saves, 1);
  assert.equal(root.querySelector('.status').textContent, 'Username updated.');
});

test('save banner: a red note on a lookalike of a saved site, a quiet one on an international address', async () => {
  const { showSaveBanner } = await import('../src/content/banner.js');
  const last = () => shadowRoots.get([...doc.querySelectorAll('pass-banner')].at(-1));
  showSaveBanner({ mode: 'save', host: 'paypa1.example', username: 'me', lookalike: 'paypal.com', onSave: async () => {}, onDismiss: () => {} });
  let root = last();
  assert.equal(root.querySelector('.lookalike').getAttribute('role'), 'alert');
  assert.equal(root.querySelector('.lookalike').textContent, 'paypa1.example is not paypal.com, but its address looks like it. Save only if you trust this site.');
  assert.equal(root.querySelector('.intl'), null);
  showSaveBanner({ mode: 'save', host: 'www.xn--bcher-kva.example', username: 'me', onSave: async () => {}, onDismiss: () => {} });
  root = last();
  assert.equal(root.querySelector('.lookalike'), null);
  assert.equal(root.querySelector('.intl').textContent, 'International address');
  showSaveBanner({ mode: 'save', host: 'github.com', username: 'me', onSave: async () => {}, onDismiss: () => {} });
  root = last();
  assert.equal(root.querySelector('.lookalike'), null);
  assert.equal(root.querySelector('.intl'), null);
});

test('OTP toast: "Show on desktop" needs a visible toast too', async () => {
  const { showOtpToast } = await import('../src/content/toast.js');
  let shown = 0;
  const t = showOtpToast({ title: 'GitHub', initial: { code: '123456', period: 30, remaining_secs: 20 },
    refresh: async () => ({ code: '123456', period: 30, remaining_secs: 30 }), onShowDesktop: async () => { shown++; } });
  const host = [...doc.querySelectorAll('pass-toast')].at(-1);
  const btn = [...shadowRoots.get(host).querySelectorAll('button')].find((b) => b.textContent.includes('Open in Passyble'));
  await click(btn);
  await tick(ui.MIN_VISIBLE_MS + 50);
  host.style.setProperty('opacity', '0', 'important');
  await click(btn);
  host.style.removeProperty('opacity');
  assert.equal(shown, 0);
  await click(btn);
  assert.equal(shown, 1);
  t.close();
});

test('uiIntact: dark-mode filters on the page are fine, washing it out is not', () => {
  const host = doc.createElement('pass-probe');
  doc.documentElement.append(host);
  assert.equal(ui.uiIntact(host), true);
  doc.documentElement.style.filter = 'invert(1) hue-rotate(180deg)';
  assert.equal(ui.uiIntact(host), true, 'dark-mode filter');
  doc.documentElement.style.filter = 'brightness(50)';
  assert.equal(ui.uiIntact(host), false);
  doc.documentElement.style.filter = '';
  host.remove();
  assert.equal(ui.uiIntact(host), false, 'detached');
});

test('pageHasEffects: a dark-mode filter or a transform on <html> (IntersectionObserver v2 then sees nothing)', () => {
  const host = doc.createElement('pass-probe');
  doc.documentElement.append(host);
  assert.equal(ui.pageHasEffects(host), false);
  doc.documentElement.style.filter = 'invert(1) hue-rotate(180deg)';
  assert.equal(ui.pageHasEffects(host), true);
  doc.documentElement.style.filter = '';
  doc.documentElement.style.transform = 'scale(1.1)';
  assert.equal(ui.pageHasEffects(host), true);
  doc.documentElement.style.transform = '';
  assert.equal(ui.pageHasEffects(host), false);
  host.remove();
});
