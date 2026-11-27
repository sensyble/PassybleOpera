import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';
import { MAIN_SRC, BRIDGE_SRC, GET_OPTIONS, CREATE_OPTIONS } from './helpers/webauthn-env.js';

const dom = new JSDOM(`<!doctype html><html><body>
  <form id="login"><h1>Sign in</h1><input type="email" name="email" autocomplete="username"><input type="password" name="password"><button>Sign in</button></form>
</body></html>`, { url: 'https://github.com/login', pretendToBeVisual: true });
const w = dom.window;
const doc = w.document;
w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};

const BLOCKED = { required: true, version: '0.1.0', minimum: '0.2.0' };
const store = { appVersionGate: BLOCKED };
const sent = [];
const storageListeners = [];
let runtimeListener = null;
const responses = {
  'otp.context': () => ({ pending: null, offer: false, autoFillOtp: true, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ({ items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false }], pending_otp: null }),
  'logins.fill': () => ({ username: 'octo', password: 'hunter2', totp: null }),
  'save.query': () => null,
};

function setGate(gate) {
  const oldValue = store.appVersionGate;
  store.appVersionGate = gate;
  for (const fn of storageListeners) fn({ appVersionGate: { oldValue, newValue: gate } }, 'local');
}

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
      getManifest: () => ({ version: '0.1.0' }),
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return { ok: true, result: fn ? fn(msg) : {} };
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: {
      local: { get: async (key) => (typeof key === 'string' ? (Object.hasOwn(store, key) ? { [key]: store[key] } : {}) : {}) },
      onChanged: { addListener: (f) => storageListeners.push(f), removeListener: (f) => { const i = storageListeners.indexOf(f); if (i >= 0) storageListeners.splice(i, 1); } },
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
const passUi = () => doc.querySelectorAll('pass-icon, pass-menu, pass-banner, pass-toast, pass-notice');
const command = (msg) => new Promise((resolve) => {
  if (!runtimeListener) { resolve('no listener'); return; }
  const async = runtimeListener(msg, { id: 'pass-ext' }, resolve);
  if (!async) resolve('ignored');
});

async function userFocus(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));
  await tick(30);
}

test('blocked: nothing starts in the page, nothing is asked of the background', async () => {
  await userFocus(doc.querySelector('[name=email]'));
  await dispatchTrusted(doc.querySelector('[name=email]'), new w.KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true, cancelable: true }));
  doc.querySelector('[name=password]').value = 'typed-secret';
  doc.querySelector('#login').dispatchEvent(new w.Event('submit', { bubbles: true, cancelable: true }));
  await tick(50);
  assert.deepEqual(sent, [], 'no logins.find, otp.context, save.capture or focus report');
  assert.equal(passUi().length, 0, 'no icon, menu, banner or toast');
  assert.equal(await command({ type: 'cmd.fill-item', id: 'gh' }), 'no listener', 'commands find no content script');
  assert.equal(doc.querySelector('[name=email]').value, '');
});

test('a gate for another version (the extension updated since) does not block: the content script starts', async () => {
  setGate({ ...BLOCKED, version: '0.0.9' });
  await tick(30);
  assert.ok(sent.some((m) => m.type === 'otp.context'), 'started');
  doc.querySelector('[name=email]').blur();
  await userFocus(doc.querySelector('[name=email]'));
  assert.ok(doc.querySelector('pass-icon'), 'the icon is back');
  assert.deepEqual(await command({ type: 'cmd.fill-item', id: 'gh' }), { ok: true });
  assert.equal(doc.querySelector('[name=email]').value, 'octo');
});

test('a block while the page is open: everything stops at once, commands are ignored', async () => {
  setGate(BLOCKED);
  await tick(10);
  assert.equal(passUi().length, 0, 'the icon and menu are gone');
  sent.length = 0;
  doc.querySelector('[name=email]').value = '';
  doc.querySelector('[name=email]').blur();
  await userFocus(doc.querySelector('[name=email]'));
  assert.equal(await command({ type: 'cmd.fill-item', id: 'gh' }), 'ignored');
  await tick(20);
  assert.deepEqual(sent, []);
  assert.equal(doc.querySelector('[name=email]').value, '');
  assert.equal(passUi().length, 0);
});

// Passkeys: the bridge leaves every request to the browser.

function makePasskeyPage(gate, version = '0.1.0') {
  const page = new JSDOM('<!doctype html><html><body></body></html>', { runScripts: 'outside-only', url: 'https://example.com/' });
  const pw = page.window;
  pw.eval(`
    window.__native = [];
    class CredentialsContainer {
      create(o) { window.__native.push(['create', o]); return Promise.resolve({ native: 'create' }); }
      get(o) { window.__native.push(['get', o]); return Promise.resolve({ native: 'get' }); }
    }
    window.CredentialsContainer = CredentialsContainer;
    Object.defineProperty(navigator, 'credentials', { value: new CredentialsContainer(), configurable: true });
    window.PublicKeyCredential = class PublicKeyCredential {
      static isConditionalMediationAvailable() { return Promise.resolve(false); }
    };
    window.AuthenticatorAttestationResponse = class AuthenticatorAttestationResponse {};
    window.AuthenticatorAssertionResponse = class AuthenticatorAssertionResponse {};
  `);
  const toBackground = [];
  pw.chrome = {
    runtime: {
      id: 'pass-test',
      getManifest: () => ({ version }),
      sendMessage: async (msg) => { toBackground.push(msg); return { ok: false, error: { code: 'update_required', message: 'x' } }; },
    },
    storage: { local: { get: async (defaults) => ({ ...defaults, passkeys: true, appVersionGate: gate }) } },
  };
  pw.eval(BRIDGE_SRC);
  pw.eval(MAIN_SRC);
  return { window: pw, toBackground, run: (code) => pw.eval(code) };
}

test('passkeys while blocked: get() and create() go to the browser\'s own WebAuthn, nothing to Passyble', async () => {
  const page = makePasskeyPage(BLOCKED);
  assert.equal((await page.run(`navigator.credentials.get(${GET_OPTIONS})`)).native, 'get');
  assert.equal((await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`)).native, 'create');
  assert.equal(await page.run('PublicKeyCredential.isConditionalMediationAvailable()'), false, 'the browser\'s own answer');
  assert.deepEqual(page.toBackground, []);
  assert.deepEqual([...page.window.__native].map((n) => n[0]), ['get', 'create']);
});

test('passkeys: a gate for another version does not block; a refusal with update_required still ends in the browser\'s WebAuthn', async () => {
  const page = makePasskeyPage({ ...BLOCKED, version: '0.0.9' });
  // No content script in this page: the request goes to the background, which answers update_required
  // (the desktop app is read-only): the browser's own WebAuthn takes over.
  const cred = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(cred.native, 'get');
  assert.equal(page.toBackground[0]?.type, 'passkey.get');
});
