import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body><p>Loading</p></body></html>', { url: 'https://cms.example/wp-admin/post.php', pretendToBeVisual: true });
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

const CMS = `<form id="post"><h1>Edit post</h1>
    <label for="title">Title</label><input id="title" name="post_title">
    <textarea name="content"></textarea>
    <label for="pub">Publish</label><input id="pub" name="publish" placeholder="Immediately">
    <label for="pw">Password</label><input id="pw" type="password" name="post_password">
    <button type="submit" id="go">Publish</button></form>`;
const LOGIN = `<form id="f"><h1>Sign in</h1><input id="u" name="f1"><input id="p" type="password" name="f2"><button id="b">Sign in</button></form>`;

const sent = [];
const ONE = [{ id: 'a', title: 'Site', username: 'alice', has_totp: false, has_passkey: false }];
let findError = null;
let items = ONE;
const responses = {
  'otp.context': () => ({ ok: true, result: { pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] } }),
  'logins.find': () => (findError ? { ok: false, error: { code: findError } } : { ok: true, result: { items, pending_otp: null } }),
  'logins.fill': () => ({ ok: true, result: { username: 'alice', password: 'hunter2', totp: null } }),
  'save.query': () => ({ ok: true, result: null }),
};

let main;
let runtimeListener;
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
    storage: { local: { get: async () => ({}) }, sync: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const $ = (id) => doc.getElementById(id);
const command = (msg) => new Promise((resolve) => runtimeListener(msg, { id: 'pass-ext' }, resolve));
const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));

/** A click or tap on `el`: the press, the focus it causes, the click. */
async function userClick(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(10);
  await dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));
  await tick(20);
}

/** The Tab key into `el`: the user's focus, without a click. */
async function userTab(el) {
  await key(doc.body, 'Tab');
  el.focus();
  await tick(20);
}

const menuRoot = () => {
  const host = doc.querySelector('pass-menu');
  return host ? shadowRoots.get(host) : null;
};

async function page(html) {
  doc.activeElement?.blur?.();
  await tick(0);
  doc.body.innerHTML = html;
  await tick(300); // the rescan after the DOM change
  sent.length = 0;
  findError = null;
  items = ONE;
}

test('CMS editor: focusing or clicking the Publish field gets no icon, no menu, no lookup', async () => {
  await page(CMS);
  await userClick($('pub'));
  assert.equal(doc.querySelector('pass-icon'), null);
  assert.equal(menuRoot(), null);
  assert.equal(sent.filter((m) => m.type === 'logins.find').length, 0);
  await key($('pub'), 'ArrowDown');
  await tick(10);
  assert.equal(menuRoot(), null, 'ArrowDown too');
  await userClick($('title'));
  assert.equal(menuRoot(), null);
});

test('CMS editor: the post password does not open on Tab or a script focus; a click opens it; the pick fills only it', async () => {
  await page(CMS);
  await userTab($('pw'));
  assert.ok(doc.querySelector('pass-icon'), 'the icon shows, so it can be asked for');
  assert.equal(menuRoot(), null, 'no opening on its own');
  doc.activeElement.blur();
  await tick(5);
  await userClick($('pw'));
  assert.ok(menuRoot(), 'a click opens it');
  assert.deepEqual([...menuRoot().querySelectorAll('.item .title')].map((el) => el.textContent), ['Site']);
  assert.ok(menuRoot().querySelector('.item.active'), 'first login preselected');
  await key($('pw'), 'ArrowDown');
  await key($('pw'), 'Enter');
  await tick(20);
  assert.equal($('pw').value, 'hunter2');
  assert.equal($('pub').value, '');
  assert.equal($('title').value, '');
});

test('CMS editor, fully locked: a click on the post password starts no unlock; ArrowDown still asks', async () => {
  await page(CMS);
  findError = 'locked';
  await userClick($('pw'));
  assert.equal(menuRoot(), null);
  assert.equal(sent.filter((m) => m.type === 'unlock.options' || m.type === 'unlock.hello').length, 0);
  await key($('pw'), 'ArrowDown');
  await tick(20);
  assert.ok(menuRoot(), 'the user asked');
});

test('CMS editor: the shortcut, the context menu and the popup never fill from the Publish field', async () => {
  await page(CMS);
  $('pub').value = 'tomorrow';
  $('pub').focus();
  await tick(10);
  await command({ type: 'cmd.fill-login' });
  await tick(10);
  assert.equal($('pub').value, 'tomorrow');
  assert.equal($('pw').value, '', 'the post password is no login form to fill from elsewhere');
  assert.equal(menuRoot(), null);
  const res = await command({ type: 'cmd.fill-item', id: 'a' });
  assert.equal(res.ok, false, 'the popup hears nothing was filled');
  assert.equal($('pw').value, '');
  assert.equal($('pub').value, 'tomorrow');
  assert.equal(sent.filter((m) => m.type === 'logins.fill').length, 0);
});

test('CMS editor: with the focus in the post password the shortcut and the popup fill it, alone', async () => {
  await page(CMS);
  $('pw').focus();
  await tick(10);
  await command({ type: 'cmd.fill-login' });
  await tick(20);
  assert.equal($('pw').value, 'hunter2');
  assert.equal($('pub').value, '');
  $('pw').value = '';
  await command({ type: 'cmd.fill-item', id: 'a' });
  await tick(20);
  assert.equal($('pw').value, 'hunter2');
  assert.equal($('title').value, '');
});

test('CMS editor: publishing with a post password offers no login to save', async () => {
  await page(CMS);
  $('pub').value = 'tomorrow';
  $('pw').value = 'secret-post';
  $('go').addEventListener('click', (e) => e.preventDefault());
  await dispatchTrusted($('go'), new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));
  await dispatchTrusted($('post'), new w.Event('submit', { bubbles: true, cancelable: true }));
  await tick(10);
  assert.equal(sent.filter((m) => m.type === 'save.capture').length, 0);
});

test('password-only form with a stray text field elsewhere: the stray field keeps its text, the capture has no username', async () => {
  await page(`<div><input id="stray" name="publish_slug" value="my-post"></div>
    <form id="f"><h1>Confirm it's you</h1><input id="p" type="password"><button id="b">Sign in</button></form>`);
  await userClick($('p'));
  assert.ok(menuRoot(), 'a sign-in field: the menu opens');
  await key($('p'), 'ArrowDown');
  await key($('p'), 'Enter');
  await tick(20);
  assert.equal($('p').value, 'hunter2');
  assert.equal($('stray').value, 'my-post');
  // Typed by hand: saved with no username (the background may add the identifier step's).
  await page(`<form id="f"><h1>Sign in</h1><input id="stray" name="publish_slug" value="my-post"><input id="n" name="other" value="x"><input id="p" type="password"><button id="b">Sign in</button></form>`);
  $('p').value = 'typed';
  await dispatchTrusted($('f'), new w.Event('submit', { bubbles: true, cancelable: true }));
  await tick(10);
  const capture = sent.find((m) => m.type === 'save.capture');
  assert.equal(capture.username, '');
  assert.equal(capture.password, 'typed');
});

test('the unlabelled classic login form: menu on its text field, username and password filled, username saved', async () => {
  await page(LOGIN);
  await userClick($('u'));
  assert.ok(menuRoot());
  await key($('u'), 'ArrowDown');
  await key($('u'), 'Enter');
  await tick(20);
  assert.equal($('u').value, 'alice');
  assert.equal($('p').value, 'hunter2');
  await page(LOGIN);
  $('u').value = 'bob';
  $('p').value = 'typed';
  await dispatchTrusted($('f'), new w.Event('submit', { bubbles: true, cancelable: true }));
  await tick(10);
  assert.equal(sent.find((m) => m.type === 'save.capture').username, 'bob');
});

test('a real sign-in form next to a post password: the shortcut goes to the sign-in form', async () => {
  await page(`${CMS}<form id="f"><h1>Sign in</h1><input id="u" name="login"><input id="p" type="password"><button>Sign in</button></form>`);
  await command({ type: 'cmd.fill-login' });
  await tick(20);
  assert.equal($('u').value, 'alice');
  assert.equal($('p').value, 'hunter2');
  assert.equal($('pw').value, '');
  assert.equal($('pub').value, '');
});

test('sign-up: the generator still opens on its own on a new password', async () => {
  await page('<form><h1>Create your account</h1><input type="email" id="e" name="email"><input id="p" type="password" name="pw" autocomplete="new-password"><button>Sign up</button></form>');
  await userClick($('p'));
  assert.ok(menuRoot(), 'opened');
  assert.ok([...menuRoot().querySelectorAll('.item .title')].length >= 1);
});

test('a post password marked new-password: the generator waits for the click', async () => {
  await page(`<form id="post"><textarea name="content"></textarea><input id="t" name="post_title"><input id="pw" type="password" name="post_password" autocomplete="new-password"><button>Publish</button></form>`);
  await userTab($('pw'));
  assert.equal(menuRoot(), null, 'not on its own');
  doc.activeElement.blur();
  await tick(5);
  await userClick($('pw'));
  assert.ok(menuRoot(), 'on a click');
});

test('the save capture carries the head canonical link of the https top frame, read at submit', async () => {
  const submit = async (user, prepare = () => {}) => {
    await page(LOGIN);
    prepare();
    sent.length = 0;
    $('u').value = user;
    $('p').value = 'typed';
    await dispatchTrusted($('f'), new w.Event('submit', { bubbles: true, cancelable: true }));
    await tick(10);
    return sent.find((m) => m.type === 'save.capture');
  };
  assert.equal('canonical' in (await submit('nolink')), false);
  const link = doc.createElement('link');
  link.setAttribute('rel', 'Canonical');
  link.setAttribute('href', '/welcome');
  try {
    // In the head: resolved against the page (the agent decides whether that host may share the login).
    doc.head.append(link);
    assert.equal((await submit('withlink')).canonical, 'https://cms.example/welcome');
    // A link in the body isn't the page's canonical address.
    link.remove();
    assert.equal('canonical' in (await submit('inbody', () => doc.body.append(link))), false);
  } finally {
    link.remove();
  }
});
