// Login form combinations, table-driven. Sites often mark a sign-in's only password field as a new
// password (autocomplete="new-password"): with just a username or e-mail before it, or alone, that
// form is still a sign-in.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { makeDom, dispatchTrusted } from './helpers/dom.js';
import { detectFields, isVisibleNoLayout, FieldKind } from '../src/content/detect.js';
import { fillLoginGroup } from '../src/content/fill.js';

const U = FieldKind.USERNAME;
const CUR = FieldKind.CURRENT_PASSWORD;
const NEW = FieldKind.NEW_PASSWORD;
const OTP = FieldKind.OTP;
const GEN = 'Generate strong password';
const LOGIN = 'Demo Bank';
const SAVED = { username: 'ana@example.com', password: 'Saved-Pw-1', totp: null };

/**
 * `kinds`: every field's kind (null: no login field). `click`: the password field the user focuses.
 * `first`: the dropdown's first entry there. `auto`: the fields a fill without a picked field puts the
 * stored password in. `pick`: the fields it goes in when the user picks the saved login on `click`.
 */
const CASES = [
  {
    name: 'email + current-password',
    html: `<form><h1>Sign in</h1><input id="u" type="email" name="email" autocomplete="username">
      <input id="p" type="password" name="password" autocomplete="current-password"><button>Sign in</button></form>`,
    intent: 'login', kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'email + new-password, no wording at all (the reported bank login)',
    html: `<form><input id="u" type="email" name="email"><input id="p" type="password" name="password" autocomplete="new-password">
      <button type="submit">Next</button></form>`,
    path: '/', intent: null, kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'email + new-password with login wording',
    html: `<form><h1>Log in to your bank</h1><label for="u">Email</label><input id="u" type="email" name="email">
      <label for="p">Password</label><input id="p" type="password" name="password" autocomplete="new-password">
      <button>Continue</button></form>`,
    path: '/', intent: 'login', kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'email + new-password with a "Log in" button',
    html: `<form><input id="u" type="email" name="email" placeholder="Email">
      <input id="p" type="password" name="password" autocomplete="new-password"><button type="submit">Log in</button></form>`,
    path: '/', intent: 'login', kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'email + a password field named "newPassword" with a "Log in" button',
    html: `<form><input id="u" type="email" name="email"><input id="p" type="password" name="newPassword">
      <button type="submit">Log in</button></form>`,
    path: '/', intent: 'login', kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'username + new-password',
    html: `<form><input id="u" name="username" placeholder="Username">
      <input id="p" type="password" name="password" autocomplete="new-password"><button>Sign in</button></form>`,
    path: '/', intent: 'login', kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'email + new-password + OTP',
    html: `<form><input id="u" type="email" name="email"><input id="p" type="password" name="password" autocomplete="new-password">
      <input id="otp" name="otp" autocomplete="one-time-code"><button>Next</button></form>`,
    path: '/', intent: null, kinds: { u: U, p: CUR, otp: OTP }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'password-only new-password (a sign-in\'s second step)',
    html: `<form><p>Welcome back, ana@example.com</p><input id="p" type="password" name="password" autocomplete="new-password">
      <button>Continue</button></form>`,
    path: '/', intent: null, kinds: { p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'password-only, "Enter your new password" (a reset): stays new',
    html: `<form><h1>Enter your new password</h1><input id="p" type="password" name="password" autocomplete="new-password">
      <button>Continue</button></form>`,
    path: '/', intent: null, kinds: { p: NEW }, click: 'p', first: GEN, auto: [], pick: ['p'],
  },
  {
    name: 'email + new-password + "Create account" button (a one-field sign-up): stays new',
    html: `<form><input id="u" type="email" name="email"><input id="p" type="password" name="password" autocomplete="new-password">
      <button>Create account</button></form>`,
    path: '/', intent: 'signup', kinds: { u: U, p: NEW }, click: 'p', first: GEN, auto: [], pick: ['p'],
  },
  {
    name: 'email + new-password + "Choose a password" label: stays new',
    html: `<form><input id="u" type="email" name="email"><label for="p">Choose a password</label>
      <input id="p" type="password" name="password" autocomplete="new-password"><button>Continue</button></form>`,
    path: '/', intent: null, kinds: { u: U, p: NEW }, click: 'p', first: GEN, auto: [], pick: ['p'],
  },
  {
    name: 'name + email + new-password, no wording (another field): stays new',
    html: `<form><input id="n" name="full_name" placeholder="Full name"><input id="u" type="email" name="email">
      <input id="p" type="password" name="password" autocomplete="new-password"><button>Continue</button></form>`,
    path: '/', intent: null, kinds: { n: null, u: U, p: NEW }, click: 'p', first: GEN, auto: [], pick: ['p'],
  },
  {
    name: 'an admin\'s "Add user" form: email + new-password: stays new',
    html: `<form><input id="u" type="email" name="email"><input id="p" type="password" name="password" autocomplete="new-password">
      <button>Add user</button></form>`,
    path: '/', intent: null, kinds: { u: U, p: NEW }, click: 'p', first: GEN, auto: [], pick: ['p'],
  },
  {
    name: 'a form named "signup": email + new-password: stays new',
    html: `<form id="signup"><input id="u" type="email" name="email"><input id="p" type="password" name="password" autocomplete="new-password">
      <button>Continue</button></form>`,
    path: '/', intent: null, kinds: { u: U, p: NEW }, click: 'p', first: GEN, auto: [], pick: ['p'],
  },
  {
    name: 'email + password + confirm (sign-up)',
    html: `<form><h1>Create your account</h1><input id="u" type="email" name="email">
      <input id="p" type="password" name="password"><input id="c" type="password" name="confirm" placeholder="Confirm password">
      <button>Sign up</button></form>`,
    path: '/', intent: 'signup', kinds: { u: U, p: NEW, c: NEW }, click: 'p', first: GEN, auto: [], pick: ['p', 'c'],
  },
  {
    name: 'current + new + confirm (change password)',
    html: `<form><h1>Change password</h1><label for="o">Current password</label><input id="o" type="password" autocomplete="current-password">
      <label for="n">New password</label><input id="n" type="password" autocomplete="new-password">
      <label for="c">Confirm new password</label><input id="c" type="password" autocomplete="new-password">
      <button>Update password</button></form>`,
    path: '/settings', intent: null, kinds: { o: CUR, n: NEW, c: NEW }, click: 'n', first: GEN, auto: ['o'], pick: ['o', 'n'],
  },
  {
    name: 'new + confirm with no username',
    html: `<form><input id="p" type="password" autocomplete="new-password"><input id="c" type="password" autocomplete="new-password">
      <button>Continue</button></form>`,
    path: '/', intent: null, kinds: { p: NEW, c: NEW }, click: 'p', first: GEN, auto: [], pick: ['p', 'c'],
  },
  {
    name: 'a password with no autocomplete and ambiguous labels',
    html: `<div class="box"><input id="u" type="text" placeholder="ID"><input id="p" type="password" placeholder="Key">
      <button>Go</button></div>`,
    path: '/', intent: null, kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'email + password + OTP',
    html: `<form><h1>Sign in</h1><input id="u" type="email" name="email"><input id="p" type="password" name="password">
      <input id="otp" name="otp" autocomplete="one-time-code"><button>Sign in</button></form>`,
    intent: 'login', kinds: { u: U, p: CUR, otp: OTP }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'a login with "Forgot password?" and "Create account" links: stays login',
    html: `<form><input id="u" type="email" name="email"><input id="p" type="password" name="password">
      <a href="/forgot">Forgot password?</a> <a href="/signup">Create account</a><button>Continue</button></form>`,
    path: '/', intent: null, kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'the same login with autocomplete="new-password": stays login',
    html: `<form><input id="u" type="email" name="email"><input id="p" type="password" name="password" autocomplete="new-password">
      <a href="/forgot">Forgot password?</a> <a href="/signup">Create account</a><button>Continue</button></form>`,
    path: '/', intent: null, kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'a sign-up with "Already have an account? Log in"',
    html: `<form><h1>Create your account</h1><input id="u" type="email" name="email">
      <input id="p" type="password" name="password" autocomplete="new-password">
      <p>Already have an account? <a href="/login">Log in</a></p><button>Continue</button></form>`,
    path: '/', intent: 'signup', kinds: { u: U, p: NEW }, click: 'p', first: GEN, auto: [], pick: ['p'],
  },
  {
    name: 'no <form>: email + new-password + "Log in"',
    html: `<div><input id="u" type="email" placeholder="Email"><input id="p" type="password" autocomplete="new-password">
      <button>Log in</button></div>`,
    path: '/', intent: 'login', kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'no <form>: a sign-up with a password and "Repeat password"',
    html: `<div><h2>Sign up</h2><input id="u" type="email" placeholder="Email"><input id="p" type="password" placeholder="Password">
      <input id="c" type="password" placeholder="Repeat password"><button>Sign up</button></div>`,
    path: '/', intent: 'signup', kinds: { u: U, p: NEW, c: NEW }, click: 'p', first: GEN, auto: [], pick: ['p', 'c'],
  },
  {
    name: 'Norwegian login: "Logg inn", "E-post", "Passord", new-password, "Ny bruker" link',
    html: `<form><h1>Logg inn</h1><label for="u">E-post</label><input id="u" name="epost">
      <label for="p">Passord</label><input id="p" type="password" name="passord" autocomplete="new-password">
      <a href="#">Glemt passord?</a> <a href="/registrer">Ny bruker? Registrer deg</a><button>Logg inn</button></form>`,
    path: '/', intent: 'login', kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'Norwegian: "E-post" + new-password + "Neste"',
    html: `<form><label for="u">E-post</label><input id="u" name="epost"><label for="p">Passord</label>
      <input id="p" type="password" autocomplete="new-password"><button>Neste</button></form>`,
    path: '/', intent: null, kinds: { u: U, p: CUR }, click: 'p', first: LOGIN, auto: ['p'], pick: ['p'],
  },
  {
    name: 'Norwegian sign-up: "Ny bruker", "Gjenta passord", "Registrer"',
    html: `<form><h1>Ny bruker</h1><label for="u">E-post</label><input id="u" type="email" name="epost">
      <label for="p">Passord</label><input id="p" type="password" name="passord">
      <label for="c">Gjenta passord</label><input id="c" type="password" name="passord2"><button>Registrer</button></form>`,
    path: '/', intent: 'signup', kinds: { u: U, p: NEW, c: NEW }, click: 'p', first: GEN, auto: [], pick: ['p', 'c'],
  },
  {
    name: 'Norwegian: "E-post" + one password + "Registrer" (a one-field sign-up)',
    html: `<form><label for="u">E-post</label><input id="u" type="email"><label for="p">Passord</label>
      <input id="p" type="password" autocomplete="new-password"><button>Registrer</button></form>`,
    path: '/', intent: 'signup', kinds: { u: U, p: NEW }, click: 'p', first: GEN, auto: [], pick: ['p'],
  },
];

const ORIGIN = 'https://bank.example';
const urlOf = (c) => `${ORIGIN}${c.path ?? '/login'}`;

/** The ids of the fields that hold the stored password. */
function holding(document, c) {
  return [...document.querySelectorAll('input[type=password]')].filter((el) => el.value === SAVED.password).map((el) => el.id);
}

for (const c of CASES) {
  test(`detect + fill: ${c.name}`, () => {
    const scan = () => {
      const dom = makeDom(c.html, { url: urlOf(c) });
      return { document: dom.document, ...detectFields(dom.document, { isVisible: isVisibleNoLayout }) };
    };
    const { document, fields } = scan();
    const $ = (id) => document.getElementById(id);
    for (const [id, kind] of Object.entries(c.kinds)) {
      assert.equal(fields.get($(id))?.kind ?? null, kind, `kind of #${id}`);
    }
    const group = fields.get($(c.click)).group;
    assert.equal(group.intent, c.intent, 'intent');

    // A fill nobody aimed at a field (no pick): never a stored password into a real sign-up form.
    fillLoginGroup(group, SAVED);
    assert.deepEqual(holding(document, c), c.auto, 'fill without a picked field');

    // The user picked the saved login for their password field.
    const again = scan();
    const g2 = again.fields.get(again.document.getElementById(c.click)).group;
    const r = fillLoginGroup(g2, SAVED, { field: again.document.getElementById(c.click) });
    assert.equal(r.password, true);
    assert.deepEqual(holding(again.document, c), c.pick, 'fill for the picked field');
    if (g2.username) assert.equal(g2.username.value, SAVED.username);
  });
}

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: `${ORIGIN}/login`, pretendToBeVisual: true });
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
const ok = (result) => ({ ok: true, result });
const responses = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ok({ items: [{ id: 'bank', title: LOGIN, username: SAVED.username, has_totp: false, has_passkey: false }], pending_otp: null }),
  'logins.fill': () => ok(SAVED),
  generate: () => ok({ password: 'Generated-Pw-123456!' }),
  'save.query': () => ok(null),
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
        return fn ? fn(msg) : ok({});
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: { local: { get: async () => ({}) }, sync: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
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
const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true, button: 0 }));
const command = (msg) => new Promise((resolve) => runtimeListener(msg, { id: 'pass-ext' }, resolve));
const menuRoot = () => { const host = doc.querySelector('pass-menu'); return host ? shadowRoots.get(host) : null; };
const items = () => (menuRoot() ? [...menuRoot().querySelectorAll('.item')] : []);
const titles = () => items().map((el) => el.querySelector('.title').textContent.trim());

async function load(c) {
  doc.activeElement?.blur?.();
  if (menuRoot()) await key(doc.body, 'Escape');
  w.history.replaceState(null, '', c.path ?? '/login');
  doc.body.innerHTML = c.html;
  await tick(300);
}

async function userFocus(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(30);
}

for (const c of CASES) {
  test(`dropdown + pick: ${c.name}`, async () => {
    await load(c);
    const field = doc.getElementById(c.click);
    await userFocus(field);
    assert.ok(menuRoot(), 'the dropdown opened on the user\'s focus');
    assert.equal(titles()[0], c.first, `first entry (${titles().join(', ')})`);
    assert.ok(titles().includes(LOGIN), 'the saved login is listed');

    await tick(ui.MIN_VISIBLE_MS + 30);
    await click(items().find((el) => el.querySelector('.title').textContent.trim() === LOGIN));
    await tick(30);
    assert.deepEqual(holding(doc, c), c.pick, 'picked: the stored password went into');
    const user = Object.keys(c.kinds).find((id) => c.kinds[id] === U);
    if (user) assert.equal(doc.getElementById(user).value, SAVED.username);
  });
}

// Fills from the popup: aimed at the focused field, or at nothing.

const SIGNUP = CASES.find((c) => c.name.startsWith('email + password + confirm'));
const BANK = CASES.find((c) => c.name.startsWith('email + new-password, no wording'));

test('popup fill with no field focused: a sign-up form never gets the stored password', async () => {
  await load(SIGNUP);
  await command({ type: 'cmd.fill-item', id: 'bank' });
  await tick(20);
  assert.deepEqual(holding(doc, SIGNUP), []);
});

test('popup fill with the focus in a sign-up\'s password field: the user\'s choice, password and confirmation', async () => {
  await load(SIGNUP);
  doc.getElementById('p').focus();
  await tick(20);
  await command({ type: 'cmd.fill-item', id: 'bank' });
  await tick(20);
  assert.deepEqual(holding(doc, SIGNUP), ['p', 'c']);
});

test('popup fill and the shortcut on the bank login with no field focused: the password goes in', async () => {
  await load(BANK);
  await command({ type: 'cmd.fill-item', id: 'bank' });
  await tick(20);
  assert.deepEqual(holding(doc, BANK), ['p']);
  await load(BANK);
  await command({ type: 'cmd.fill-login' });
  await tick(20);
  assert.deepEqual(holding(doc, BANK), ['p']);
  assert.equal(doc.getElementById('u').value, SAVED.username);
});
