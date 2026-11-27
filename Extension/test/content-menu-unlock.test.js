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
let runtimeListener;
let locked = true;
let fully = false; // locked completely: no list
let options = { inline: true, locked: true, hello: true };
const ITEMS = [
  { id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false },
  { id: 'work', title: 'GitHub work', username: 'alice@corp.example', has_totp: false, has_passkey: false },
  { id: 'old', title: 'Old account', username: 'bob', has_totp: false, has_passkey: false },
];
const responses = {
  'otp.context': () => ({ ok: true, result: { pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] } }),
  'logins.find': () => (locked && fully
    ? { ok: false, error: { code: 'locked', message: 'Vault is locked' } }
    : { ok: true, result: { items: ITEMS, pending_otp: null, locked } }),
  'logins.fill': (msg) => (locked
    ? { ok: false, error: { code: 'locked', message: 'Vault is locked' } }
    : { ok: true, result: { username: msg.id === 'work' ? 'alice@corp.example' : 'octo', password: 'hunter2', totp: null } }),
  'unlock.options': () => ({ ok: true, result: { ...options, locked } }),
  'unlock.hello': () => { locked = false; return { ok: true, result: { locked: false } }; },
  'unlock.open-form': () => ({ ok: true, result: { opened: 'popup' } }),
  unlock: () => { locked = false; return { ok: true, result: { locked: false } }; },
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
const count = (type) => sent.filter((m) => m.type === type).length;
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

async function typeInto(el, text) {
  await key(el, text.slice(-1));
  el.value = text;
  await dispatchTrusted(el, new w.Event('input', { bubbles: true, composed: true }));
  await tick(5);
}

function closeMenu(email) {
  if (doc.querySelector('pass-menu')) key(email, 'Escape');
  doc.activeElement?.blur?.();
}

test('locked: a picked login starts Windows Hello at once; it unlocks and fills', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: true };
  const email = await openFor('a');
  const hellos = count('unlock.hello');
  await pick('GitHub');
  await tick(20);
  assert.equal(count('unlock.hello'), hellos + 1, 'Windows Hello without another click');
  assert.equal(count('unlock'), 0, "not the desktop app's own prompt");
  // The unlock says which login it is for (the desktop app counts it as that fill's check).
  assert.equal(sent.filter((m) => m.type === 'unlock.options').at(-1)?.for, 'gh');
  assert.equal(email.value, 'octo');
  assert.equal(doc.querySelector('[name=password]').value, 'hunter2');
  assert.equal(doc.querySelector('pass-menu'), null);
  closeMenu(email);
});

/** `unlock.hello` answers when the test says so. */
function holdHello() {
  const real = responses['unlock.hello'];
  let answer;
  responses['unlock.hello'] = () => new Promise((resolve) => { answer = resolve; });
  return {
    restore: () => { responses['unlock.hello'] = real; },
    cancel: () => answer({ ok: false, error: { code: 'cancelled', message: 'unlock cancelled' } }),
    unlock: () => { locked = false; answer({ ok: true, result: { locked: false } }); },
  };
}


/** Lets promise callbacks run, but no timer: what happens here happens "at once". */
async function microtasks(n = 200) {
  for (let i = 0; i < n; i++) await Promise.resolve();
}

test('locked: the picked login fills the moment Windows Hello answers (no timer, no other request first)', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: true };
  const hello = holdHello();
  const email = await openFor('now');
  await pick('GitHub');
  assert.equal(email.value, '');
  const from = sent.length;
  hello.unlock();
  await microtasks();
  hello.restore();
  assert.deepEqual(sent.slice(from).map((m) => m.type).slice(0, 1), ['logins.fill'], 'the fill is the next request');
  assert.equal(email.value, 'octo');
  assert.equal(doc.querySelector('[name=password]').value, 'hunter2');
  closeMenu(email);
});

test('fully locked: the logins show the moment Windows Hello answers, without asking the desktop app again', async () => {
  locked = true;
  fully = true;
  options = { inline: true, locked: true, hello: true };
  const hello = holdHello();
  const email = await lockedPage('now2');
  email.focus();
  await dispatchTrusted(email, new w.KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true, cancelable: true }));
  await tick(40);
  const from = sent.length;
  const prompts = count('unlock');
  hello.unlock();
  await microtasks();
  hello.restore();
  assert.equal(count('unlock'), prompts, 'no `unlock` round trip first');
  assert.equal(sent.slice(from)[0]?.type, 'logins.find');
  assert.deepEqual(titles(), ['GitHub', 'GitHub work', 'Old account']);
  fully = false;
  closeMenu(email);
});

test('locked: while Windows Hello is up the menu offers the master password; Cancel in Hello shows it too', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: true };
  const hello = holdHello();
  const email = await openFor('a2');
  await pick('GitHub');
  assert.deepEqual(titles(), ['Use master password instead']);
  assert.match(rootOf('pass-menu').textContent, /Unlock to fill GitHub\. Confirm with Windows Hello/);
  assert.equal(rootOf('pass-menu').querySelector('input'), null, 'no password field in the page');
  hello.cancel();
  await tick(20);
  assert.deepEqual(titles(), ['Unlock with Windows Hello', 'Enter master password', 'Open Passyble']);
  assert.match(rootOf('pass-menu').textContent, /Windows Hello was cancelled\. Enter your master password/);
  assert.equal(email.value, '', 'nothing filled');
  // Windows Hello again from the choices, and this time it unlocks.
  await pick('Unlock with Windows Hello');
  hello.unlock();
  await tick(20);
  hello.restore();
  assert.equal(email.value, 'octo');
  closeMenu(email);
});

test('locked: "Use master password instead" calls Windows Hello off and keeps the password choices', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: true };
  const hello = holdHello();
  const email = await openFor('a3');
  await pick('GitHub work');
  await pick('Use master password instead');
  assert.equal(count('unlock.cancel'), 1);
  assert.deepEqual(titles(), ['Unlock with Windows Hello', 'Enter master password', 'Open Passyble']);
  // The cancelled Hello answers late: the choices stay as they are.
  hello.cancel();
  await tick(20);
  hello.restore();
  assert.doesNotMatch(rootOf('pass-menu').textContent, /was cancelled/);
  assert.deepEqual(titles(), ['Unlock with Windows Hello', 'Enter master password', 'Open Passyble']);
  // Unlocked elsewhere (the popup's form): the login fills.
  locked = false;
  await new Promise((resolve) => runtimeListener({ type: 'lock_state', locked: false }, { id: 'pass-ext' }, resolve));
  await tick(20);
  assert.equal(email.value, 'alice@corp.example');
  closeMenu(email);
});

test('locked: "Enter master password" opens the extension\'s form; the login fills when Passyble unlocks', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: false };
  const email = await openFor('b');
  const fills = count('logins.fill');
  await pick('GitHub work');
  assert.deepEqual(titles(), ['Enter master password', 'Open Passyble'], 'no Windows Hello when the app does not offer it');
  await pick('Enter master password');
  assert.equal(count('unlock.open-form'), 1);
  assert.match(rootOf('pass-menu').textContent, /Unlock in the Passyble app/);
  assert.equal(email.value, '', 'nothing filled while locked');
  // The popup unlocked Passyble: the background tells the page.
  locked = false;
  await new Promise((resolve) => runtimeListener({ type: 'lock_state', locked: false }, { id: 'pass-ext' }, resolve));
  await tick(20);
  assert.equal(email.value, 'alice@corp.example');
  assert.equal(doc.querySelector('[name=password]').value, 'hunter2');
  await new Promise((resolve) => runtimeListener({ type: 'lock_state', locked: false }, { id: 'pass-ext' }, resolve));
  await tick(20);
  assert.equal(count('logins.fill'), fills + 1);
  closeMenu(email);
});

test('locked: "Open Passyble" uses the desktop app\'s prompt, then fills', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: false };
  const email = await openFor('c');
  await pick('GitHub');
  await pick('Open Passyble');
  await tick(20);
  assert.ok(count('unlock') >= 1);
  assert.equal(email.value, 'octo');
  closeMenu(email);
});

test('an older desktop app (no inline unlock): picking a login asks the desktop app, as before', async () => {
  locked = true;
  options = { inline: false, locked: true, hello: false };
  const email = await openFor('d');
  const fills = count('logins.fill');
  const newWays = count('unlock.open-form') + count('unlock.hello');
  // The background unlocks through the desktop app's prompt, then fills.
  const fill = responses['logins.fill'];
  responses['logins.fill'] = (msg) => { locked = false; return fill(msg); };
  await pick('GitHub');
  responses['logins.fill'] = fill;
  assert.equal(count('logins.fill'), fills + 1, 'straight to the fill');
  assert.equal(count('unlock.open-form') + count('unlock.hello'), newWays, 'no unlock choices for an older desktop app');
  assert.equal(email.value, 'octo');
  closeMenu(email);
});

test('typing filters the logins by username and title, best matches first; Esc closes', async () => {
  locked = false;
  const email = await openFor('e');
  assert.deepEqual(titles(), ['GitHub', 'GitHub work', 'Old account']);
  await typeInto(email, 'AL');
  assert.deepEqual(titles(), ['GitHub work'], 'case-insensitive, the username');
  await typeInto(email, 'git');
  assert.deepEqual(titles(), ['GitHub', 'GitHub work'], 'the title, usage order kept');
  await typeInto(email, 'acc');
  assert.deepEqual(titles(), ['Old account'], 'a word of the title');
  await typeInto(email, 'zzz');
  assert.deepEqual(titles(), []);
  assert.match(rootOf('pass-menu').textContent, /No logins match/);
  await typeInto(email, '');
  assert.deepEqual(titles(), ['GitHub', 'GitHub work', 'Old account'], 'empty: all of them');
  const fills = count('logins.fill');
  await typeInto(email, 'bo');
  assert.equal(count('logins.fill'), fills, 'typing fills nothing');
  await key(email, 'ArrowDown');
  await key(email, 'Enter');
  await tick(20);
  assert.equal(count('logins.fill'), fills + 1, 'ArrowDown + Enter pick from the filtered list');
  assert.equal(sent.filter((m) => m.type === 'logins.fill').at(-1).id, 'old');
  closeMenu(email);
});

test('a value already in the field filters the menu as it opens', async () => {
  locked = false;
  doc.body.innerHTML = LOGIN('f');
  await tick(300);
  const email = doc.querySelector('[name=email]');
  email.value = 'octo';
  email.focus();
  await dispatchTrusted(email, new w.KeyboardEvent('keydown', { key: 'ArrowDown', altKey: true, bubbles: true, composed: true, cancelable: true }));
  await tick(30);
  assert.deepEqual(titles(), ['GitHub']);
  await key(email, 'Escape');
  assert.equal(doc.querySelector('pass-menu'), null);
  closeMenu(email);
});

const activeTitle = () => rootOf('pass-menu')?.querySelector('.item.active .title')?.textContent ?? null;

async function lockedPage(formId) {
  doc.body.innerHTML = LOGIN(formId);
  await tick(300);
  return doc.querySelector('[name=email]');
}

/** A real click into `field` (press, focus, click), as onFieldClick sees it. */
async function clickInto(field) {
  await dispatchTrusted(field, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  field.focus();
  await click(field);
  await tick(40);
}

test('fully locked: ArrowDown starts Windows Hello at once; unlocked, the logins show with the first preselected', async () => {
  locked = true;
  fully = true;
  options = { inline: true, locked: true, hello: true };
  const email = await lockedPage('g');
  email.focus();
  const hellos = count('unlock.hello');
  await dispatchTrusted(email, new w.KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true, cancelable: true }));
  await tick(40);
  assert.equal(count('unlock.hello'), hellos + 1, 'Windows Hello without another click');
  assert.deepEqual(titles(), ['GitHub', 'GitHub work', 'Old account'], 'the logins, nothing filled');
  assert.equal(activeTitle(), 'GitHub', 'the first one preselected: Enter fills it');
  assert.equal(email.value, '');
  await key(email, 'Enter');
  await tick(20);
  assert.equal(email.value, 'octo');
  fully = false;
  closeMenu(email);
});

test('fully locked: a click into the field starts Windows Hello once; Cancel brings the master password; not again on its own right after', async () => {
  locked = true;
  fully = true;
  options = { inline: true, locked: true, hello: true };
  const hello = holdHello();
  const email = await lockedPage('h');
  const hellos = count('unlock.hello');
  await clickInto(email);
  assert.equal(count('unlock.hello'), hellos + 1, 'one click: Windows Hello');
  assert.deepEqual(titles(), ['Use master password instead']);
  assert.match(rootOf('pass-menu').textContent, /Unlock to see your logins\. Confirm with Windows Hello/);
  hello.cancel();
  await tick(20);
  assert.deepEqual(titles(), ['Unlock with Windows Hello', 'Enter master password', 'Open Passyble']);
  assert.match(rootOf('pass-menu').textContent, /Windows Hello was cancelled\. Enter your master password/);
  assert.equal(count('unlock.hello'), hellos + 1, 'once');
  // The background says the user declined it (hello_auto false): the next click shows the choices.
  await key(email, 'Escape');
  options = { inline: true, locked: true, hello: true, hello_auto: false };
  await clickInto(email);
  assert.deepEqual(titles(), ['Unlock with Windows Hello', 'Enter master password', 'Open Passyble']);
  assert.equal(count('unlock.hello'), hellos + 1, 'no new Windows Hello right after a cancel');
  await pick('Unlock with Windows Hello');
  assert.equal(count('unlock.hello'), hellos + 2);
  hello.unlock();
  await tick(40);
  hello.restore();
  assert.deepEqual(titles(), ['GitHub', 'GitHub work', 'Old account']);
  fully = false;
  closeMenu(email);
});

test('fully locked: Windows Hello never starts on its own (a script focus or click, a lock change while the menu is open)', async () => {
  locked = true;
  fully = true;
  options = { inline: true, locked: true, hello: true };
  const email = await lockedPage('i');
  const hellos = count('unlock.hello');
  email.focus();
  email.dispatchEvent(new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));
  await tick(40);
  assert.deepEqual(titles(), [], 'nothing opened');
  assert.equal(count('unlock.hello'), hellos);
  // Opened by the user while Windows Hello isn't offered, then the lock state changes: the menu
  // refreshes by itself, without Windows Hello.
  options = { inline: true, locked: true, hello: false };
  await dispatchTrusted(email, new w.KeyboardEvent('keydown', { key: 'ArrowDown', bubbles: true, composed: true, cancelable: true }));
  await tick(40);
  assert.deepEqual(titles(), ['Enter master password', 'Open Passyble']);
  options = { inline: true, locked: true, hello: true };
  await new Promise((resolve) => runtimeListener({ type: 'lock_state', locked: true }, { id: 'pass-ext' }, resolve));
  await tick(40);
  assert.deepEqual(titles(), ['Unlock with Windows Hello', 'Enter master password', 'Open Passyble']);
  assert.equal(count('unlock.hello'), hellos, 'no Windows Hello without the user asking for it');
  fully = false;
  closeMenu(email);
});

test('soft-locked: the suggestions that open on their own start nothing; a pick right after a cancel shows the choices first', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: true, hello_auto: false };
  const hellos = count('unlock.hello');
  const email = await openFor('j');
  assert.equal(count('unlock.hello'), hellos, 'the list alone asks for nothing');
  await pick('GitHub');
  assert.deepEqual(titles(), ['Unlock with Windows Hello', 'Enter master password', 'Open Passyble']);
  assert.equal(count('unlock.hello'), hellos);
  // A Windows Hello already up (started in the popup) is joined at once.
  options = { inline: true, locked: true, hello: true, hello_auto: false, hello_pending: true };
  await key(email, 'Escape');
  const again = await openFor('j2');
  await pick('GitHub work');
  assert.equal(count('unlock.hello'), hellos + 1);
  await tick(20);
  assert.equal(again.value, 'alice@corp.example');
  closeMenu(again);
});

test('the vault in this browser (`browser`): the master password only, no "Open Passyble"', async () => {
  locked = true;
  options = { inline: true, locked: true, hello: false, browser: true };
  const email = await openFor('b');
  await pick('GitHub work');
  assert.deepEqual(titles(), ['Enter master password']);
  closeMenu(email);
  options = { inline: true, locked: true, hello: true };
});
