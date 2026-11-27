import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM(`<!doctype html><html><body>
  <form id="login"><h1>Sign in</h1><input type="email" name="email" autocomplete="username"><input type="password" name="password"><button>Sign in</button></form>
</body></html>`, { url: 'https://github.com/login', pretendToBeVisual: true });
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

const APP_REFUSED = { ok: false, error: { code: 'update_required', message: 'Update the Passyble app to keep filling' } };
const sent = [];
let runtimeListener = null;
const responses = {
  'otp.context': () => ({ ok: true, result: { pending: null, offer: false, autoFillOtp: true, otpFieldElsewhere: false, items: [] } }),
  'logins.find': () => APP_REFUSED,
  'logins.fill': () => APP_REFUSED,
  'passkey.find': () => APP_REFUSED,
  'save.query': () => ({ ok: true, result: null }),
};

let main;
let t;
let createPasskeyFlow;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getManifest: () => ({ version: '0.1.0' }),
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
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
  ({ t } = await import('../src/shared/i18n.js'));
  ({ createPasskeyFlow } = await import('../src/content/passkey-flow.js'));
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const rootOf = (el) => shadowRoots.get(el);
const menuOpen = () => !!doc.querySelector('pass-menu')?.isConnected;
const menuText = () => (menuOpen() ? [...rootOf(doc.querySelector('pass-menu')).querySelectorAll('.msg')].map((el) => el.textContent).join(' ') : '');
const noticeText = () => [...doc.querySelectorAll('pass-notice')].map((el) => rootOf(el)?.textContent || '').join(' ');

async function userFocus(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(30);
}

test('the English text for the desktop app\'s update_required', () => {
  assert.equal(t('errAppUpdateRequired'), 'Update the Passyble app to keep filling.');
});

test('the menu says so where the suggestions would have opened (once on its own), and again on a click', async () => {
  const email = doc.querySelector('[name=email]');
  await userFocus(email);
  assert.ok(menuOpen(), 'the menu opened on its own');
  assert.equal(menuText(), t('errAppUpdateRequired'));
  assert.ok(!sent.some((m) => m.type === 'logins.fill'));
  await dispatchTrusted(email, new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true, cancelable: true }));
  await tick(10);
  assert.equal(menuOpen(), false);
  // The password field: not again on its own on this page.
  await userFocus(doc.querySelector('[name=password]'));
  assert.equal(menuOpen(), false);
  // A click on the field: the line again.
  await dispatchTrusted(doc.querySelector('[name=password]'), new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));
  await tick(30);
  assert.ok(menuOpen());
  assert.equal(menuText(), t('errAppUpdateRequired'));
});

test('the fill shortcut: a notice instead of a silent failure', async () => {
  await new Promise((resolve) => runtimeListener({ type: 'cmd.fill-login' }, { id: 'pass-ext' }, resolve));
  await tick(10);
  assert.match(noticeText(), /Update the Passyble app to keep filling\./);
  assert.equal(doc.querySelector('[name=email]').value, '');
});

test('a page\'s passkey request: the browser\'s own WebAuthn at once, with the notice, no card', async () => {
  for (const notice of doc.querySelectorAll('pass-notice')) notice.remove();
  const ended = [];
  const flow = createPasskeyFlow({
    bg: async () => { throw Object.assign(new Error('Update the Passyble app to keep filling'), { code: 'update_required' }); },
    bridge: () => ({ hasModal: () => true, endModal: (rid, outcome) => { ended.push([rid, outcome]); return true; }, passModal: () => true }),
  });
  for (const kind of ['get', 'create']) {
    assert.equal(flow.handle({ rid: `r-${kind}`, kind, rpId: 'github.com', allowCredentials: [], excludeCredentials: [], user: { name: 'octo' }, userActivated: true }), true);
    await tick(10);
  }
  assert.deepEqual(ended, [['r-get', 'fallback'], ['r-create', 'fallback']]);
  assert.equal(flow.active, false, 'no card');
  assert.match(noticeText(), /Update the Passyble app to keep filling\./);
});
