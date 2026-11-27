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

const ORIGIN = 'chrome-extension://pass-ext';
const sent = [];
let runtimeListener;
let locked = true;
let options = { inline: true, locked: true, hello: false };
const ITEMS = [
  { id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false },
  { id: 'work', title: 'GitHub work', username: 'alice@corp.example', has_totp: false, has_passkey: false },
];
const responses = {
  'otp.context': () => ({ ok: true, result: { pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] } }),
  'logins.find': () => ({ ok: true, result: { items: ITEMS, pending_otp: null, locked } }),
  'logins.fill': (msg) => (locked
    ? { ok: false, error: { code: 'locked', message: 'Vault is locked' } }
    : { ok: true, result: { username: msg.id === 'work' ? 'alice@corp.example' : 'octo', password: 'hunter2', totp: null } }),
  'unlock.options': () => ({ ok: true, result: { ...options, locked } }),
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
      getURL: (p) => `${ORIGIN}/${p}`,
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
const titles = () => entries().map((el) => el.querySelector('.title').textContent);
const frame = () => rootOf('pass-menu')?.querySelector('iframe.unlock-frame') || null;
const LOGIN = (id) => `<form id="${id}"><h1>Sign in</h1><input type="email" name="email" autocomplete="username"><input type="password" name="password"><button>Sign in</button></form>`;

async function openFor(formId) {
  doc.body.innerHTML = LOGIN(formId);
  await tick(300);
  const email = doc.querySelector('[name=email]');
  await dispatchTrusted(email, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  email.focus();
  await tick(30);
  assert.ok(doc.querySelector('pass-menu'), 'the suggestions');
  return email;
}

async function pick(title) {
  await tick(ui.MIN_VISIBLE_MS + 30);
  const entry = entries().find((el) => el.querySelector('.title').textContent === title);
  assert.ok(entry, `entry ${title} in ${titles()}`);
  await click(entry);
  await tick(20);
}

/** A message on the page's window, as the frame (or someone else) would post it. */
function post(data, { source = frame()?.contentWindow, origin = ORIGIN } = {}) {
  w.dispatchEvent(new w.MessageEvent('message', { data, origin, source }));
}

function closeMenu(email) {
  if (doc.querySelector('pass-menu')) key(email, 'Escape');
  doc.activeElement?.blur?.();
}

test('locked: a picked login shows the master password frame in the menu; it fills once the frame unlocked', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: false };
  const email = await openFor('a');
  await pick('GitHub');
  const el = frame();
  assert.ok(el, 'the frame');
  assert.equal(el.getAttribute('src'), `${ORIGIN}/src/unlock/frame.html?focus=1`, 'it takes the focus: the user asked to fill');
  assert.equal(el.title, 'Passyble master password');
  assert.deepEqual(titles(), ['Open Passyble'], 'no popup detour, no Windows Hello when not offered');
  assert.equal(rootOf('pass-menu').querySelector('input'), null, 'no password field of our own in the page');
  post({ passybleUnlock: 'ready', height: 70 });
  assert.equal(el.style.height, '70px');
  assert.equal(doc.activeElement, doc.querySelector('pass-menu'), 'the frame has the focus once it is ready');
  // Someone else's message (the page, another frame) does nothing.
  locked = false;
  post({ passybleUnlock: 'unlocked' }, { origin: 'https://github.com' });
  post({ passybleUnlock: 'unlocked' }, { source: w });
  await tick(20);
  assert.equal(email.value, '', 'nothing filled for a fake message');
  post({ passybleUnlock: 'unlocked' });
  await tick(20);
  assert.equal(email.value, 'octo');
  assert.equal(doc.querySelector('[name=password]').value, 'hunter2');
  assert.equal(doc.querySelector('pass-menu'), null);
  closeMenu(email);
});


/** Lets promise callbacks run, but no timer: what happens here happens "at once". */
async function microtasks(n = 200) {
  for (let i = 0; i < n; i++) await Promise.resolve();
}

test('the login fills the moment the frame says it unlocked (no timer in between)', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: false };
  const email = await openFor('now');
  await pick('GitHub work');
  post({ passybleUnlock: 'ready', height: 70 });
  locked = false;
  const from = sent.length;
  post({ passybleUnlock: 'unlocked' });
  await microtasks();
  // ('focus' is the frame-focus bookkeeping, sent at most every 2 s: when it falls here is timing.)
  assert.equal(sent.slice(from).filter((m) => m.type !== 'focus')[0]?.type, 'logins.fill', 'the fill is the next request');
  assert.equal(email.value, 'alice@corp.example');
  assert.equal(doc.querySelector('[name=password]').value, 'hunter2');
  closeMenu(email);
});

test('locked with Windows Hello offered: Cancel in Hello shows Hello on top, then the frame, then the other entries', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: true };
  const email = await openFor('b');
  // Cancelled Hello: the frame and Hello again.
  responses['unlock.hello'] = () => ({ ok: false, error: { code: 'cancelled', message: 'unlock cancelled' } });
  await pick('GitHub work');
  await tick(20);
  const el = frame();
  assert.ok(el);
  post({ passybleUnlock: 'ready', height: 66 });
  assert.deepEqual(titles(), ['Unlock with Windows Hello', 'Open Passyble']);
  const box = rootOf('pass-menu').querySelector('.menu');
  const order = [...box.children].map((n) => n.className || n.tagName);
  assert.ok(order.indexOf('unlock-frame') < order.indexOf('item'), `frame before the entries: ${order}`);
  // Hello again, cancelled again: the frame again.
  await pick('Unlock with Windows Hello');
  await tick(20);
  assert.ok(frame());
  assert.match(rootOf('pass-menu').textContent, /Windows Hello was cancelled/);
  delete responses['unlock.hello'];
  locked = false;
  await new Promise((resolve) => runtimeListener({ type: 'lock_state', locked: false }, { id: 'pass-ext' }, resolve));
  await tick(20);
  assert.equal(email.value, 'alice@corp.example');
  closeMenu(email);
});

test('Esc in the frame closes the menu and gives the focus back to the field', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: false };
  const email = await openFor('c');
  await pick('GitHub');
  assert.ok(frame());
  post({ passybleUnlock: 'ready' });
  post({ passybleUnlock: 'escape' });
  await tick(5);
  assert.equal(doc.querySelector('pass-menu'), null);
  assert.equal(doc.activeElement, email);
  closeMenu(email);
});

test('a frame that never loads: "Enter master password" (the popup) instead, for the rest of the page', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: false };
  const email = await openFor('d');
  await pick('GitHub');
  assert.ok(frame());
  await tick(3100);
  assert.equal(frame(), null);
  assert.deepEqual(titles(), ['Enter master password', 'Open Passyble']);
  closeMenu(email);
  // Next time on this page: no frame tried again.
  const again = await openFor('e');
  await pick('GitHub');
  assert.equal(frame(), null);
  assert.deepEqual(titles(), ['Enter master password', 'Open Passyble']);
  closeMenu(again);
});

test('the menu drawn again keeps the same frame element where it was (moving it would reload it)', async () => {
  const { InlineMenu } = await import('../src/content/menu.js');
  doc.body.innerHTML = '<input id="f">';
  const field = doc.getElementById('f');
  const m = new InlineMenu({ onIconClick() {}, onSelect() {}, onGenerateClick() {} });
  const el = doc.createElement('iframe');
  el.className = 'unlock-frame';
  const entry = (title) => ({ kind: 'x', title, icon: 'lock' });
  m.open(field, { status: 'message', message: 'One', frame: el, entries: [entry('A')] });
  const root = shadowRoots.get(doc.querySelector('pass-menu'));
  const box = root.querySelector('.menu');
  let moved = 0;
  const remove = el.remove.bind(el);
  el.remove = () => { moved += 1; remove(); };
  m.update({ status: 'message', message: 'Two', frame: el, entries: [entry('B'), entry('C')] });
  assert.equal(moved, 0);
  assert.equal(root.querySelector('iframe'), el);
  const order = [...box.children].map((n) => (n === el ? 'frame' : n.className.split(' ')[0]));
  assert.deepEqual(order, ['head', 'msg', 'frame', 'item', 'item']);
  assert.match(box.querySelector('.msg').textContent, /Two/);
  m.update({ status: 'message', message: 'Three', entries: [entry('D')] });
  assert.equal(root.querySelector('iframe'), null, 'gone without a frame in the model');
  m.destroy();
});
