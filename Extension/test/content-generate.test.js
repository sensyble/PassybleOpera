import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';
import { CHARSETS } from '../src/shared/generator.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://shop.example/account/create', pretendToBeVisual: true });
const w = dom.window;
const doc = w.document;

w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};
// The UI uses closed shadow roots; keep a handle on them so the test can look inside.
const shadowRoots = new Map();
const attachShadow = w.Element.prototype.attachShadow;
w.Element.prototype.attachShadow = function (init) {
  const root = attachShadow.call(this, init);
  shadowRoots.set(this, root);
  return root;
};

const AGENT_PW = 'Agent-Generated-Pw-123!';
const sent = [];
let settingsListener = null;
let syncStore = {};
const ok = (result) => ({ ok: true, result });
const fail = (code) => ({ ok: false, error: { code, message: code } });
const defaults = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ok({ items: [{ id: 'old', title: 'Shop', username: 'someone@else.test', has_totp: false, has_passkey: false }], pending_otp: null }),
  generate: () => ok({ password: AGENT_PW }),
  'save.query': () => ok(null),
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
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : ok({});
      },
      onMessage: { addListener: () => {} },
    },
    storage: {
      local: { get: async () => ({}) },
      sync: { get: async () => ({ ...syncStore }) },
      onChanged: { addListener: (f) => { settingsListener = f; } },
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

function setBody(html) {
  doc.body.innerHTML = html;
}

/** A click / tap on `el`, then the focus it causes. */
async function userFocus(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(20);
}

const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));

function menuRoot() {
  const host = doc.querySelector('pass-menu');
  return host ? shadowRoots.get(host) : null;
}

function menuEntries() {
  const root = menuRoot();
  return root ? [...root.querySelectorAll('.item')].map((el) => el.querySelector('.title').textContent) : [];
}

function blurAll() {
  doc.activeElement?.blur?.();
  menuRoot() && key(doc.body, 'Escape');
}

const SIGNUP = `<form id="f"><h1>Create your account</h1>
  <input type="email" name="email" autocomplete="email">
  <input type="password" name="password" autocomplete="new-password">
  <input type="password" name="confirm" placeholder="Confirm password">
  <p>Already have an account? <a href="/login">Sign in</a></p>
  <button type="submit">Create account</button></form>`;

test('focusing a new-password field by a click opens the menu with "Generate strong password" first', async () => {
  setBody(SIGNUP);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  assert.ok(doc.querySelector('pass-menu'), 'menu opened on its own');
  const entries = menuEntries();
  assert.equal(entries[0], 'Generate strong password');
  assert.ok(entries.includes('Shop'), 'saved logins still listed after the generator');
  assert.ok(sent.some((m) => m.type === 'generate' && m.automatic === true && m.length === 20));

  const root = menuRoot();
  const value = root.querySelector('.pw-val');
  assert.equal(value.textContent, '•'.repeat(AGENT_PW.length), 'masked by default');
  assert.match(root.querySelector('.strength').textContent, /Very strong · 23 characters/);
  assert.equal(root.querySelector('.item.gen .avatar svg').getAttribute('data-icon'), 'dice', 'stroke icon avatar');
  const reveal = root.querySelector('.reveal');
  assert.equal(reveal.title, 'Show password');
  assert.equal(reveal.querySelector('svg').getAttribute('data-icon'), 'eye');
  await dispatchTrusted(reveal, new w.MouseEvent('click', { bubbles: true, composed: true }));
  assert.equal(value.textContent, AGENT_PW, 'Show reveals the generated password');
  assert.equal(reveal.title, 'Hide password');
  assert.equal(reveal.querySelector('svg').getAttribute('data-icon'), 'eyeOff');
  assert.ok(doc.querySelector('pass-menu'), 'revealing does not pick the entry');
  assert.equal(pw.value, '');
});

test('picking the generated password fills password + confirmation; submit captures it for the save banner', async () => {
  const pw = doc.querySelector('[name=password]');
  const confirm = doc.querySelector('[name=confirm]');
  doc.querySelector('[name=email]').value = 'new@user.test';
  await key(pw, 'Enter'); // active entry = the generator
  await tick(10);
  assert.equal(pw.value, AGENT_PW);
  assert.equal(confirm.value, AGENT_PW);
  assert.equal(doc.querySelector('pass-menu'), null, 'menu closed after filling');

  // fetch()-submitted sign-up: the page prevents navigation and swaps the form out afterwards.
  doc.getElementById('f').addEventListener('submit', (e) => e.preventDefault());
  responses['save.query'] = (msg) => ok(msg.sameDocument ? { mode: 'save', host: 'shop.example', username: 'new@user.test', title: null, token: 't1' } : null);
  await dispatchTrusted(doc.getElementById('f'), new w.Event('submit', { bubbles: true, cancelable: true }));
  const capture = sent.filter((m) => m.type === 'save.capture').at(-1);
  assert.deepEqual(capture, { type: 'save.capture', username: 'new@user.test', password: AGENT_PW, kind: 'signup' });

  setBody('<h1>Welcome!</h1><p>Your account is ready.</p>');
  await tick(1000); // form-gone check -> save.query (same document) -> banner
  const q = sent.filter((m) => m.type === 'save.query').at(-1);
  assert.equal(q.sameDocument, true);
  const banner = doc.querySelector('pass-banner');
  assert.ok(banner, 'save banner shown without a navigation');
  assert.match(shadowRoots.get(banner).textContent, /Save login to Passyble\?/);
  assert.match(shadowRoots.get(banner).textContent, /shop\.example/, 'the site on its own line');
  assert.match(shadowRoots.get(banner).textContent, /new@user\.test/, 'the account under it');
  responses['save.query'] = defaults['save.query'];
  const later = [...shadowRoots.get(banner).querySelectorAll('button')].find((b) => b.textContent === 'Not now');
  await dispatchTrusted(later, new w.MouseEvent('click', { bubbles: true, composed: true }));
  assert.equal(doc.querySelector('pass-banner'), null);
  assert.ok(sent.some((m) => m.type === 'save.dismiss'));
});

test('sign-in field with saved logins: suggestions open on their own (no generator, nothing preselected)', async () => {
  setBody(`<form><h1>Sign in</h1><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>`);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await tick(20);
  assert.ok(doc.querySelector('pass-menu'), 'opened on its own');
  assert.deepEqual(menuEntries(), ['Shop'], 'the site logins, no generator on a sign-in field');
  assert.ok(menuRoot().querySelector('.item.active'), 'the first login is preselected');
  assert.ok(doc.querySelector('pass-icon'), 'the icon is there too');
  await key(pw, 'Escape');
  assert.equal(doc.querySelector('pass-menu'), null, 'Esc closes it');
  pw.blur();
  await userFocus(pw);
  await tick(20);
  assert.equal(doc.querySelector('pass-menu'), null, 'on focus: once per field and page load (a click reopens it, below)');
  blurAll();
});

/** Typing by the user: the key, the new value, the `input` event. */
async function typeInto(el, text) {
  await key(el, text.slice(-1));
  el.value = text;
  await dispatchTrusted(el, new w.Event('input', { bubbles: true, composed: true }));
  await tick(5);
}

test('sign-in field: typing filters the suggestions (a password field: closes them); no saved logins or a script focus: nothing opens', async () => {
  setBody(`<form><h1>Sign in</h1><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>`);
  await tick(300);
  const email = doc.querySelector('[name=email]');
  await userFocus(email);
  await tick(20);
  assert.ok(doc.querySelector('pass-menu'));
  await typeInto(email, 'x');
  assert.ok(doc.querySelector('pass-menu'), 'typing in the e-mail field keeps the suggestions');
  assert.match(menuRoot().textContent, /No logins match/);
  assert.deepEqual(menuEntries(), []);
  await typeInto(email, 'some');
  assert.deepEqual(menuEntries(), ['Shop'], 'the login whose username starts with it');
  assert.equal(email.value, 'some', 'typing never fills');
  assert.equal(doc.querySelector('[name=password]').value, '');
  blurAll();

  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await tick(20);
  assert.ok(doc.querySelector('pass-menu'), 'suggestions on the password field');
  await key(pw, 'a');
  assert.equal(doc.querySelector('pass-menu'), null, 'typing a password closes them');
  blurAll();

  await tick(1100); // the last click ages out
  setBody(`<form id="s2"><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>`);
  await tick(300);
  doc.querySelector('[name=email]').focus(); // a script, no gesture
  await tick(20);
  assert.equal(doc.querySelector('pass-menu'), null, 'never on script focus');
  blurAll();

  responses['logins.find'] = () => ok({ items: [], pending_otp: null });
  setBody(`<form id="s3"><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>`);
  await tick(300);
  await userFocus(doc.querySelector('[name=password]'));
  await tick(20);
  assert.equal(doc.querySelector('pass-menu'), null, 'nothing to suggest: no menu');
  assert.ok(doc.querySelector('pass-icon'), 'the icon is still there');
  responses = { ...defaults };
  blurAll();
});

test('setting "Open suggestions automatically" off: sign-in fields stay closed until ArrowDown', async () => {
  syncStore = { autoSuggest: false };
  settingsListener({ autoSuggest: { newValue: false } }, 'sync');
  await tick(10);
  setBody(`<form id="s4"><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>`);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await tick(20);
  assert.equal(doc.querySelector('pass-menu'), null);
  await key(pw, 'ArrowDown');
  await tick(20);
  assert.deepEqual(menuEntries(), ['Shop']);
  await key(pw, 'Escape');
  syncStore = {};
  settingsListener({ autoSuggest: { newValue: true } }, 'sync');
  await tick(10);
  blurAll();
});

test('no auto-open when a script focuses the field (no user gesture)', async () => {
  setBody(SIGNUP);
  await tick(1100); // let the last click age out
  doc.querySelector('[name=password]').focus();
  await tick(20);
  assert.equal(doc.querySelector('pass-menu'), null);
  doc.activeElement.blur();
});

test('Esc dismisses; the field (and its confirmation) does not reopen on the next focus', async () => {
  setBody(SIGNUP);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  const confirm = doc.querySelector('[name=confirm]');
  await userFocus(pw);
  assert.ok(doc.querySelector('pass-menu'));
  await key(pw, 'Escape');
  assert.equal(doc.querySelector('pass-menu'), null, 'Esc closed it');
  pw.blur();
  await userFocus(pw);
  assert.equal(doc.querySelector('pass-menu'), null, 'not again for the same field');
  await userFocus(confirm);
  assert.equal(doc.querySelector('pass-menu'), null, 'nor for the confirmation field of the same form');
  confirm.blur();
});

test('typing dismisses the auto-opened menu and it stays closed', async () => {
  setBody(SIGNUP.replace('id="f"', 'id="f2"'));
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  assert.ok(doc.querySelector('pass-menu'));
  await key(pw, 'h');
  assert.equal(doc.querySelector('pass-menu'), null);
  pw.value = 'h';
  pw.blur();
  await userFocus(pw);
  assert.equal(doc.querySelector('pass-menu'), null);
  pw.blur();
});

test('desktop app missing and vault locked: the password is generated locally, filled, and captured', async () => {
  responses.generate = () => fail('agent_unavailable');
  responses['logins.find'] = () => fail('locked');
  setBody(SIGNUP.replace('id="f"', 'id="f3"'));
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  assert.deepEqual(menuEntries(), ['Generate strong password', 'Letters and numbers only', 'Password options', 'Unlock Passyble']);
  assert.equal(menuRoot().querySelectorAll('.item')[3].querySelector('.avatar svg').getAttribute('data-icon'), 'lock');
  await key(pw, 'Enter');
  await tick(10);
  const local = pw.value;
  assert.equal(local.length, 20);
  assert.notEqual(local, AGENT_PW);
  const all = Object.values(CHARSETS).join('');
  assert.ok([...local].every((c) => all.includes(c)), 'same character rules as the core');
  for (const set of Object.values(CHARSETS)) assert.ok([...local].some((c) => set.includes(c)), `has one of ${set}`);
  assert.equal(doc.querySelector('[name=confirm]').value, local);

  // The page clears the password fields before its own submit handler runs: the capture still has it.
  doc.querySelector('[name=email]').value = 'locked@user.test';
  pw.value = '';
  doc.querySelector('[name=confirm]').value = '';
  await dispatchTrusted(doc.getElementById('f3'), new w.Event('submit', { bubbles: true, cancelable: true }));
  const capture = sent.filter((m) => m.type === 'save.capture').at(-1);
  assert.deepEqual(capture, { type: 'save.capture', username: 'locked@user.test', password: local, kind: 'signup' });
  responses = { ...defaults };
});

test('setting off: no auto-open, but the generator is still in the menu behind ArrowDown', async () => {
  syncStore = { autoGenerate: false };
  settingsListener({ autoGenerate: { newValue: false } }, 'sync');
  await tick(10);
  setBody(SIGNUP.replace('id="f"', 'id="f4"'));
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  assert.equal(doc.querySelector('pass-menu'), null, 'auto-open is off');
  await key(pw, 'ArrowDown');
  await tick(20);
  assert.equal(menuEntries()[0], 'Generate strong password');
  await key(pw, 'Escape');
});

test('Passyble not running: the menu says so in plain words, with what to do', async () => {
  responses['logins.find'] = () => fail('agent_unavailable');
  setBody('<form><h1>Sign in</h1><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>');
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await key(pw, 'ArrowDown');
  await tick(20);
  assert.equal(menuRoot().querySelector('.msg').textContent, "Passyble isn't running.");
  responses['logins.find'] = () => ({ ok: false, error: { code: 'agent_unavailable', message: 'Specified native messaging host not found.' } });
  await key(pw, 'Escape');
  await key(pw, 'ArrowDown');
  await tick(20);
  assert.match(menuRoot().querySelector('.msg').textContent, /^Can't connect to Passyble\./);
  await key(pw, 'Escape');
  responses = { ...defaults };
});

/** A full click / tap on `el`: press, focus (when it hasn't got it yet), release, click. */
async function userClick(el) {
  const mouse = (type) => dispatchTrusted(el, new w.MouseEvent(type, { bubbles: true, composed: true, cancelable: true, button: 0, detail: 1 }));
  await mouse('mousedown');
  if (doc.activeElement !== el) el.focus();
  await mouse('mouseup');
  await mouse('click');
  await tick(20);
}

const SIGNIN = (id) => `<form id="${id}"><h1>Sign in</h1><input type="text" name="username" autocomplete="username"><input type="password" name="password"><button>Sign in</button></form>`;

test('sign-in field: a click opens the menu again after Esc, typing or a fill, every time, with the first login preselected', async () => {
  setBody(SIGNIN('c1'));
  await tick(300);
  const user = doc.querySelector('[name=username]');
  const pw = doc.querySelector('[name=password]');
  await userClick(user);
  assert.deepEqual(menuEntries(), ['Shop'], 'opened by the first click');
  await key(user, 'Escape');
  assert.equal(doc.querySelector('pass-menu'), null);
  await userClick(user);
  assert.deepEqual(menuEntries(), ['Shop'], 'click, Esc, click: open again');
  assert.ok(menuRoot().querySelector('.item.active'), 'first login preselected');
  await userClick(user);
  assert.ok(doc.querySelector('pass-menu'), 'a click on its field leaves an open menu open');
  await key(user, 'Escape');
  await userClick(user);
  assert.ok(doc.querySelector('pass-menu'), 'not suppressed for good');
  await key(user, 'Escape');

  await userClick(pw);
  assert.ok(doc.querySelector('pass-menu'));
  await key(pw, 'a');
  pw.value = 'a';
  assert.equal(doc.querySelector('pass-menu'), null, 'typing a password closes it');
  await userClick(pw);
  assert.deepEqual(menuEntries(), ['Shop'], 'and the next click opens it, even with a value');

  // A fill closes it; a click brings it back (to pick another account).
  responses['logins.fill'] = () => ok({ username: 'someone@else.test', password: 'pw', totp: null });
  await tick(400); // entries must be on screen for a moment before a pick counts
  await key(pw, 'ArrowDown');
  await key(pw, 'Enter');
  await tick(20);
  assert.equal(user.value, 'someone@else.test');
  assert.equal(doc.querySelector('pass-menu'), null, 'closed by the fill');
  await userClick(pw);
  assert.deepEqual(menuEntries(), ['Shop']);
  responses = { ...defaults };
  blurAll();
});

test('a click on a filled username field lists every login of the site, until the user types', async () => {
  responses['logins.find'] = () => ok({ items: [
    { id: 'a', title: 'Shop', username: 'someone@else.test', has_totp: false, has_passkey: false },
    { id: 'b', title: 'Shop (me)', username: 'me@here.test', has_totp: false, has_passkey: false },
  ], pending_otp: null });
  setBody(SIGNIN('c2'));
  await tick(300);
  const user = doc.querySelector('[name=username]');
  user.value = 'me@here.test';
  await userClick(user);
  assert.deepEqual(menuEntries(), ['Shop', 'Shop (me)'], 'not filtered by the value already there');
  await typeInto(user, 'some');
  assert.deepEqual(menuEntries(), ['Shop'], 'typing filters again');
  responses = { ...defaults };
  blurAll();
});

test('a click that selects text, a script focus or a script click opens nothing', async () => {
  setBody(SIGNIN('c3'));
  await tick(1100); // the last click ages out
  const user = doc.querySelector('[name=username]');
  user.value = 'someone@else.test';
  user.focus(); // a script
  user.click(); // a script's click (untrusted)
  await tick(20);
  assert.equal(doc.querySelector('pass-menu'), null, 'nothing from a script');
  // A drag over the text (or a double-click on a word): the click ends with a selection.
  await dispatchTrusted(user, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  user.setSelectionRange(0, 7);
  await dispatchTrusted(user, new w.MouseEvent('click', { bubbles: true, composed: true, button: 0, detail: 2 }));
  await tick(20);
  assert.equal(doc.querySelector('pass-menu'), null, 'selecting text is not asking for the menu');
  user.setSelectionRange(3, 3);
  await userClick(user);
  assert.ok(doc.querySelector('pass-menu'), 'a plain click still opens it');
  blurAll();
});

test('a click opens nothing when there is nothing to offer; locked: the unlock choice; setting off: nothing', async () => {
  responses['logins.find'] = () => ok({ items: [], pending_otp: null, locked: false });
  setBody(SIGNIN('c4'));
  await tick(300);
  const user = doc.querySelector('[name=username]');
  await userClick(user);
  await userClick(user);
  assert.equal(doc.querySelector('pass-menu'), null, 'no logins for this site: no menu');

  responses['logins.find'] = () => fail('locked');
  await userClick(user);
  assert.deepEqual(menuEntries(), ['Unlock Passyble'], 'locked: how to unlock');
  await key(user, 'Escape');
  responses = { ...defaults };

  syncStore = { autoSuggest: false };
  settingsListener({ autoSuggest: { newValue: false } }, 'sync');
  await tick(10);
  await userClick(user);
  assert.equal(doc.querySelector('pass-menu'), null, '"Open suggestions automatically" off');
  syncStore = {};
  settingsListener({ autoSuggest: { newValue: true } }, 'sync');
  await tick(10);
  blurAll();
});

test('new-password field: a click on the empty field opens the generator again; not once it has a value', async () => {
  setBody(SIGNUP.replace('id="f"', 'id="c5"'));
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userClick(pw);
  assert.equal(menuEntries()[0], 'Generate strong password');
  await key(pw, 'Escape');
  assert.equal(doc.querySelector('pass-menu'), null);
  await userClick(pw);
  assert.equal(menuEntries()[0], 'Generate strong password', 'reopened by the click');
  await key(pw, 'Escape');
  pw.value = 'typed-already';
  await userClick(pw);
  assert.equal(doc.querySelector('pass-menu'), null, 'a field with a password keeps it');
  pw.value = '';

  syncStore = { autoGenerate: false };
  settingsListener({ autoGenerate: { newValue: false } }, 'sync');
  await tick(10);
  await userClick(pw);
  assert.equal(doc.querySelector('pass-menu'), null, '"Suggest strong passwords" off');
  syncStore = {};
  settingsListener({ autoGenerate: { newValue: true } }, 'sync');
  await tick(10);
  blurAll();
});
