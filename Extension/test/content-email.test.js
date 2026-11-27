import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM(`<!doctype html><html><body>
  <form class="form-signin"><h1>Please sign in</h1>
    <label for="inputEmail" class="sr-only">Email address</label>
    <input type="email" class="form-control" name="username" id="inputEmail" placeholder="name@example.com" autofocus="">
    <label for="inputPassword" class="sr-only">Password</label>
    <input type="password" class="form-control" name="password" id="inputPassword" placeholder="Password">
    <div class="checkbox"><label><input type="checkbox" value="remember-me"> Remember me</label></div>
    <button class="btn" type="submit">Sign in</button></form>
</body></html>`, { url: 'https://app.example/', pretendToBeVisual: true });
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
const ok = (result) => ({ ok: true, result });
const responses = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ok({ items: [{ id: 'a', title: 'App', username: 'alice@example.com', has_totp: false, has_passkey: false }], pending_otp: null }),
  'logins.fill': () => ok({ username: 'alice@example.com', password: 'hunter2', totp: null }),
  'save.query': () => ok(null),
};

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
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: { get: async () => ({}) },
      sync: { get: async () => ({}) },
      onChanged: { addListener: () => {} },
    },
  };
  // `autofocus`: the page focused the e-mail field before the content script attached.
  doc.getElementById('inputEmail').focus();
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));
const menuRoot = () => {
  const host = doc.querySelector('pass-menu');
  return host ? shadowRoots.get(host) : null;
};

test('field focused before start(): suggestions open for it, nothing preselected or filled', async () => {
  await tick(30);
  const email = doc.getElementById('inputEmail');
  assert.equal(doc.activeElement, email);
  assert.ok(doc.querySelector('pass-icon'), 'icon');
  assert.ok(menuRoot(), 'suggestions opened for the autofocused field');
  assert.deepEqual([...menuRoot().querySelectorAll('.item .title')].map((el) => el.textContent), ['App']);
  assert.ok(menuRoot().querySelector('.item.active'), 'the first login is preselected');
  assert.equal(email.value, '');
  assert.ok(sent.some((m) => m.type === 'focus' && m.kind === 'username'));
});

test('picking the login fills the e-mail field with the username and the password', async () => {
  const email = doc.getElementById('inputEmail');
  await key(email, 'ArrowDown');
  await key(email, 'Enter');
  await tick(20);
  assert.equal(email.value, 'alice@example.com');
  assert.equal(doc.getElementById('inputPassword').value, 'hunter2');
  assert.equal(doc.querySelector('pass-menu'), null);
});

test('after a click, a script focus on a later autofocus field opens nothing', async () => {
  await dispatchTrusted(doc.body, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  doc.activeElement?.blur();
  doc.body.innerHTML = `<form><h1>Sign in</h1><input type="email" id="e2" placeholder="Email address" autofocus>
    <input type="password" id="p2"><button type="submit">Sign in</button></form>`;
  await tick(1100); // the click ages out; still not the page's first focus
  doc.getElementById('e2').focus();
  await tick(30);
  assert.ok(doc.querySelector('pass-icon'), 'icon');
  assert.equal(doc.querySelector('pass-menu'), null, 'not the page\'s initial focus: no menu');
});
