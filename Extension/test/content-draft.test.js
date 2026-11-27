import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://shop.example/account/create', pretendToBeVisual: true });
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

const AGENT_PW = 'Agent-Generated-Pw-123!';
const sent = [];
const copied = [];
let runtimeListener = null;
const ok = (result) => ({ ok: true, result });
const fail = (code) => ({ ok: false, error: { code, message: code } });
const defaults = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ok({ items: [], pending_otp: null }),
  generate: () => ok({ password: AGENT_PW }),
  'save.query': () => ok(null),
  'draft.save': () => ok({ id: 'draft-1', created: true, title: 'shop.example' }),
  'draft.undo': () => ok({ deleted: true }),
};
let responses = { ...defaults };

let main;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  Object.defineProperty(globalThis.navigator, 'clipboard', {
    configurable: true, value: { writeText: async (text) => { copied.push(text); } },
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
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
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const VISIBLE = 520; // clicks count once the UI was visible for 500 ms (ui-common.js)

function reset(html) {
  doc.body.innerHTML = html;
  sent.length = 0;
  copied.length = 0;
  responses = { ...defaults };
}

/** The background asks this frame to do something (context menu, popup). */
function command(msg) {
  return new Promise((resolve) => {
    const async = runtimeListener(msg, { id: 'pass-ext' }, resolve);
    if (!async) resolve(undefined);
  });
}

const rootOf = (tag) => {
  const host = doc.querySelector(tag);
  return host ? shadowRoots.get(host) : null;
};
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));

async function userFocus(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(20);
}

async function rightClick(el) {
  await dispatchTrusted(el, new w.MouseEvent('contextmenu', { bubbles: true, composed: true, button: 2 }));
}

const SIGNUP = `<form id="f"><h1>Create your account</h1>
  <input type="email" name="email" autocomplete="email" value="me@x.test">
  <input type="password" name="password" autocomplete="new-password">
  <input type="password" name="confirm" placeholder="Confirm password">
  <textarea name="bio"></textarea>
  <div id="rich" contenteditable="true">notes</div>
  <button type="submit">Create account</button></form>`;

test('new-password fields get a generate button beside the Passyble icon; sign-in fields do not', async () => {
  reset(SIGNUP);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  const slot = rootOf('pass-icon');
  assert.ok(slot, 'icon host');
  const gen = slot.querySelector('.gen');
  assert.ok(gen && !gen.hidden, 'generate button shown');
  assert.match(gen.getAttribute('aria-label'), /generate/i);
  doc.querySelector('[name=email]').blur();

  reset('<form><input type="text" name="user" autocomplete="username"><input type="password" name="pw" autocomplete="current-password"><button>Sign in</button></form>');
  await tick(300);
  await userFocus(doc.querySelector('[name=pw]'));
  const signIn = rootOf('pass-icon');
  assert.ok(signIn.querySelector('.gen').hidden, 'no generate button on a sign-in field');
});

test('the generate button fills password + confirmation and saves at once, with Undo', async () => {
  reset(SIGNUP);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  const confirm = doc.querySelector('[name=confirm]');
  await userFocus(pw);
  // Escape the auto-opened menu; the button is the explicit way.
  await dispatchTrusted(pw, new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true }));
  const gen = rootOf('pass-icon').querySelector('.gen');

  // Too soon after it appeared, or untrusted: ignored.
  gen.dispatchEvent(new w.MouseEvent('click', { bubbles: true, composed: true }));
  await tick(10);
  assert.ok(!sent.some((m) => m.type === 'draft.save'));

  await tick(VISIBLE);
  await click(gen);
  await tick(50);
  assert.equal(pw.value, AGENT_PW);
  assert.equal(confirm.value, AGENT_PW);
  const save = sent.find((m) => m.type === 'draft.save');
  assert.deepEqual(save, { type: 'draft.save', username: 'me@x.test', password: AGENT_PW, kind: 'signup' });

  const toast = rootOf('pass-action-toast');
  assert.ok(toast, 'toast shown');
  assert.match(toast.querySelector('.title').textContent, /Saved to Passyble/);
  const undo = toast.querySelector('.btn.primary');
  assert.equal(undo.textContent, 'Undo');
  await tick(VISIBLE);
  await click(undo);
  await tick(20);
  assert.deepEqual(sent.find((m) => m.type === 'draft.undo'), { type: 'draft.undo', id: 'draft-1' });
  assert.match(toast.querySelector('.title').textContent, /Removed from Passyble/);
});

test('Undo when the draft is already gone: "nothing to undo", not "nothing saved for this site"', async () => {
  reset(SIGNUP);
  responses['draft.undo'] = () => ({ ok: false, error: { code: 'not_found', message: 'Nothing to undo', reason: 'nothing_to_undo' } });
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await dispatchTrusted(pw, new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true }));
  await tick(VISIBLE);
  await click(rootOf('pass-icon').querySelector('.gen'));
  await tick(50);
  const toast = rootOf('pass-action-toast');
  await tick(VISIBLE);
  await click(toast.querySelector('.btn.primary'));
  await tick(20);
  assert.equal(toast.querySelector('.title').textContent, "There's nothing to undo anymore.");
  responses = { ...defaults };
});

test('generate button: locked or older desktop app still fills; says it will be offered on submit', async () => {
  reset(SIGNUP);
  responses['draft.save'] = () => fail('not_supported');
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await dispatchTrusted(pw, new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true }));
  await tick(VISIBLE);
  await click(rootOf('pass-icon').querySelector('.gen'));
  await tick(50);
  assert.equal(pw.value, AGENT_PW);
  const notice = rootOf('pass-notice');
  assert.match(notice.textContent, /offers to save it on submit/);
  notice.querySelector('.x').click();
  doc.querySelector('pass-notice')?.remove();
});

test('context menu "Generate password" on a new-password field: both fields, saved as a draft', async () => {
  reset(SIGNUP);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await rightClick(pw);
  const res = await command({ type: 'cmd.generate-here' });
  assert.deepEqual(res, { ok: true });
  assert.equal(pw.value, AGENT_PW);
  assert.equal(doc.querySelector('[name=confirm]').value, AGENT_PW);
  assert.equal(sent.find((m) => m.type === 'draft.save').kind, 'signup');
});

test('right-click reports whether the target is a password field (the background shows "Generate password" only then)', async () => {
  reset(SIGNUP);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await dispatchTrusted(pw, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 2 }));
  await rightClick(pw);
  await rightClick(doc.querySelector('[name=email]'));
  await rightClick(doc.querySelector('[name=bio]'));
  // A revealed password ("show password" turned it into a text field) is still a password field.
  pw.blur();
  assert.deepEqual(sent.filter((m) => m.type === 'menu.target').map((m) => m.password), [true, true, false, false]);
  // Untrusted events (the page) report nothing.
  sent.length = 0;
  pw.dispatchEvent(new w.MouseEvent('contextmenu', { bubbles: true, composed: true, button: 2 }));
  assert.ok(!sent.some((m) => m.type === 'menu.target'));
});

test('context menu "Generate password" on anything but a password field is ignored', async () => {
  reset(SIGNUP);
  await tick(300);
  for (const target of [doc.querySelector('[name=bio]'), doc.getElementById('rich'), doc.querySelector('[name=email]')]) {
    await rightClick(target);
    const res = await command({ type: 'cmd.generate-here' });
    assert.deepEqual(res, { ok: false });
  }
  assert.equal(doc.querySelector('[name=bio]').value, '');
  assert.equal(doc.querySelector('[name=password]').value, '');
  assert.equal(doc.getElementById('rich').textContent, 'notes');
  assert.deepEqual(copied, []);
  assert.ok(!sent.some((m) => m.type === 'draft.save' || m.type === 'generate'), 'nothing generated or saved');
});

test("the editable save banner: Edit opens the extension's frame; Save asks it to store its edits, then commits the token only", async () => {
  reset('<p>Welcome</p>');
  doc.querySelectorAll('pass-banner').forEach((n) => n.remove());
  responses['save.query'] = () => ok({ mode: 'save', host: 'shop.example', username: 'typo@x.test', editable: true, title: null, token: 't1' });
  responses['save.commit'] = () => ok({ id: 'n1', action: 'save_new' });
  history.pushState({}, '', '/account/welcome');
  await tick(400); // SPA navigation → checkSaveBanner(true)
  const root = rootOf('pass-banner');
  assert.ok(root, 'banner shown');
  await tick(VISIBLE);
  await click(root.querySelector('button.edit'));
  const frame = root.querySelector('iframe.edit-frame');
  assert.ok(frame, 'the edit frame');
  assert.equal(root.querySelectorAll('input').length, 0, 'no in-page inputs');
  // jsdom gives a frame in a shadow root no window: a stand-in window for the extension page.
  const source = frame.contentWindow || new JSDOM('<!doctype html>').window;
  if (!frame.contentWindow) Object.defineProperty(frame, 'contentWindow', { configurable: true, value: source });
  const toFrame = [];
  source.postMessage = (data, targetOrigin) => toFrame.push([data, targetOrigin]);
  const origin = 'chrome-extension://pass-ext';
  const fromFrame = (data) => w.dispatchEvent(new w.MessageEvent('message', { data, origin, source }));
  fromFrame({ passybleSave: 'ready', height: 100 });
  assert.deepEqual(toFrame.at(-1), [{ passybleSave: 'init', token: 't1' }, origin]);
  fromFrame({ passybleSave: 'loaded', height: 100 });
  root.querySelector('.btn.primary').dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  assert.ok(!sent.some((m) => m.type === 'save.commit'));
  await click(root.querySelector('.btn.primary'));
  await tick(20);
  const flush = toFrame.find(([d]) => d.passybleSave === 'flush');
  assert.ok(flush, 'the frame is asked to store what it shows');
  assert.ok(toFrame.some(([d]) => d.passybleSave === 'disable'), 'then no more edits');
  assert.ok(!sent.some((m) => m.type === 'save.commit'), 'not before the frame stored its values');
  fromFrame({ passybleSave: 'flushed', seq: flush[0].seq, ok: true });
  await tick(20);
  assert.deepEqual(sent.find((m) => m.type === 'save.commit'), { type: 'save.commit', token: 't1' }, 'the token only');
  assert.match(root.querySelector('.status').textContent, /Saved to Passyble/);
});

test('banner: Enter in the edit frame saves, through the same click guard', async () => {
  doc.querySelectorAll('pass-banner').forEach((n) => n.remove());
  sent.length = 0;
  responses['save.query'] = () => ok({ mode: 'update', host: 'shop.example', username: 'me', editable: true, title: 'Shop', token: 't2' });
  responses['save.commit'] = () => ok({ id: 'x', action: 'update_password' });
  history.pushState({}, '', '/account/other');
  await tick(400);
  const root = rootOf('pass-banner');
  await tick(VISIBLE);
  await click(root.querySelector('button.edit'));
  const frame = root.querySelector('iframe.edit-frame');
  const source = frame.contentWindow || new JSDOM('<!doctype html>').window;
  if (!frame.contentWindow) Object.defineProperty(frame, 'contentWindow', { configurable: true, value: source });
  const toFrame = [];
  source.postMessage = (data) => toFrame.push(data);
  const origin = 'chrome-extension://pass-ext';
  // Messages posted by a frame are trusted events, as in a browser.
  const message = (data, from = source, o = origin) => dispatchTrusted(w, new w.MessageEvent('message', { data, origin: o, source: from }));
  await message({ passybleSave: 'ready' });
  await message({ passybleSave: 'loaded' });
  // The page can't press Enter for the user: a 'submit' from the page's window or another origin is ignored.
  await message({ passybleSave: 'submit' }, w);
  await message({ passybleSave: 'submit' }, source, 'https://shop.example');
  await tick(20);
  assert.ok(!toFrame.some((d) => d.passybleSave === 'flush'));
  await message({ passybleSave: 'submit' });
  await tick(20);
  const flush = toFrame.find((d) => d.passybleSave === 'flush');
  assert.ok(flush);
  await message({ passybleSave: 'flushed', seq: flush.seq, ok: true });
  await tick(20);
  assert.deepEqual(sent.find((m) => m.type === 'save.commit'), { type: 'save.commit', token: 't2' });
});

test('banner: "Never for this site" asks the background (token only), says so, and closes', async () => {
  doc.querySelectorAll('pass-banner').forEach((n) => n.remove());
  sent.length = 0;
  responses['save.query'] = () => ok({ mode: 'save', host: 'shop.example', username: 'me', editable: true, title: null, token: 't3' });
  responses['save.never'] = () => ok({ site: 'https://shop.example' });
  history.pushState({}, '', '/account/never');
  await tick(400);
  const root = rootOf('pass-banner');
  assert.ok(root, 'banner shown');
  const never = root.querySelector('button.never');
  assert.equal(never.textContent, 'Never for this site');
  // Untrusted click and a click before the banner was visible long enough: ignored.
  never.dispatchEvent(new w.MouseEvent('click', { bubbles: true }));
  await click(never);
  assert.ok(!sent.some((m) => m.type === 'save.never'), 'not a click the user could have meant');
  await tick(VISIBLE);
  await click(never);
  await tick(20);
  assert.deepEqual(sent.find((m) => m.type === 'save.never'), { type: 'save.never', token: 't3' }, 'no site in the message: the background knows it');
  assert.ok(!sent.some((m) => m.type === 'save.commit'));
  assert.match(root.querySelector('.status').textContent, /Won't ask again on this site/);
  assert.equal(root.querySelector('.btn.primary').disabled, true);
  await tick(2700);
  assert.equal(doc.querySelector('pass-banner'), null, 'closed');
});

test('a generated password is reported to the background when filled (its submit is saved without asking)', async () => {
  reset(SIGNUP);
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await dispatchTrusted(pw, new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true }));
  await tick(VISIBLE);
  await click(rootOf('pass-icon').querySelector('.gen'));
  await tick(50);
  assert.deepEqual(sent.find((m) => m.type === 'generate.filled'), { type: 'generate.filled', password: AGENT_PW, symbols: true });
  doc.querySelectorAll('pass-action-toast').forEach((n) => n.remove());
});

for (const [kind, text, undone] of [
  ['updated', 'Password updated in Passyble', 'Previous password restored.'],
  ['saved', 'Saved to Passyble', 'Removed from Passyble.'],
]) {
  test(`an auto-saved submit (${kind}): no banner, "${text}" with Undo (save.undo, token only)`, async () => {
    reset('<p>Welcome</p>');
    doc.querySelectorAll('pass-banner, pass-action-toast').forEach((n) => n.remove());
    responses['save.query'] = () => ok({ autosaved: kind, token: `auto-${kind}`, host: 'shop.example' });
    responses['save.undo'] = () => ok({ undone: kind });
    history.pushState({}, '', `/account/auto-${kind}`);
    await tick(400); // SPA navigation → checkSaveBanner(true)
    assert.equal(doc.querySelector('pass-banner'), null, 'no banner');
    const toast = rootOf('pass-action-toast');
    assert.ok(toast, 'notice shown');
    assert.equal(toast.querySelector('.title').textContent, text);
    await tick(VISIBLE);
    await click(toast.querySelector('.btn.primary'));
    await tick(20);
    assert.deepEqual(sent.find((m) => m.type === 'save.undo'), { type: 'save.undo', token: `auto-${kind}` });
    assert.equal(toast.querySelector('.title').textContent, undone);
    responses = { ...defaults };
  });
}

test('"Fill on this page" for another site\'s login: fills the form; cancelled in the desktop app shows nothing', async () => {
  reset('<form><input type="text" name="user" autocomplete="username"><input type="password" name="pw" autocomplete="current-password"><button>Sign in</button></form>');
  doc.querySelectorAll('pass-notice, pass-banner').forEach((n) => n.remove());
  await tick(300);
  responses['logins.fill_cross'] = () => ok({ username: 'octo', password: 'cross-pw', totp: null, cross: true });
  const res = await command({ type: 'cmd.fill-cross', id: 'gl' });
  assert.deepEqual(res, { ok: true });
  assert.equal(doc.querySelector('[name=user]').value, 'octo');
  assert.equal(doc.querySelector('[name=pw]').value, 'cross-pw');
  assert.ok(!sent.some((m) => m.type === 'fill.done'), 'not this site\'s login: no 2FA chain');

  doc.querySelector('[name=pw]').value = '';
  responses['logins.fill_cross'] = () => fail('cancelled');
  const cancelled = await command({ type: 'cmd.fill-cross', id: 'gl' });
  assert.deepEqual(cancelled, { ok: false });
  assert.equal(doc.querySelector('[name=pw]').value, '');
  assert.equal(doc.querySelector('pass-notice'), null);
});

test('right-click reports username and e-mail fields too ("Generate username" / "Generate e-mail alias")', async () => {
  reset(SIGNUP + '<input type="text" name="nick" autocomplete="username"><input type="text" name="city">');
  await tick(300);
  for (const name of ['email', 'password', 'nick', 'city', 'bio']) await rightClick(doc.querySelector(`[name=${name}]`));
  assert.deepEqual(sent.filter((m) => m.type === 'menu.target').map((m) => [m.password, m.username]),
    [[false, true], [true, false], [false, true], [false, false], [false, false]]);
});

test('context menu "Generate username" / "Generate e-mail alias": fills the right-clicked field, nothing saved', async () => {
  reset(SIGNUP);
  responses['generate.username'] = () => ok({ username: 'Swift-Otter' });
  responses['generate.email'] = () => ok({ email: 'x7k2@aleeas.test' });
  await tick(300);
  const email = doc.querySelector('[name=email]');
  let typed = 0;
  email.addEventListener('input', () => { typed += 1; });
  await rightClick(email);
  assert.deepEqual(await command({ type: 'cmd.generate-username-here', kind: 'username' }), { ok: true });
  assert.equal(email.value, 'Swift-Otter');
  assert.equal(typed, 1, 'the page sees it as typed');
  assert.deepEqual(await command({ type: 'cmd.generate-username-here', kind: 'alias' }), { ok: true });
  assert.equal(email.value, 'x7k2@aleeas.test');
  assert.deepEqual(sent.find((m) => m.type === 'generate.email'), { type: 'generate.email', kind: 'alias' });
  assert.ok(!sent.some((m) => m.type === 'draft.save'), 'nothing saved');
  doc.querySelectorAll('pass-notice').forEach((n) => n.remove());

  // A password field (the menu was built before `menu.target` hid the item): ignored.
  const pw = doc.querySelector('[name=password]');
  await rightClick(pw);
  sent.length = 0;
  assert.deepEqual(await command({ type: 'cmd.generate-username-here', kind: 'alias' }), { ok: false });
  assert.equal(pw.value, '');
  assert.ok(!sent.some((m) => m.type === 'generate.email' || m.type === 'generate.username'));
});

test('context menu "Generate e-mail alias" errors: a notice with the reason, the field unchanged', async () => {
  reset(SIGNUP);
  responses['generate.email'] = () => ({ ok: false, error: { code: 'not_found', message: 'no alias service set up' } });
  await tick(300);
  const email = doc.querySelector('[name=email]');
  await rightClick(email);
  assert.deepEqual(await command({ type: 'cmd.generate-username-here', kind: 'alias' }), { ok: false });
  assert.equal(email.value, 'me@x.test');
  assert.match(rootOf('pass-notice').textContent, /Set this up in the Passyble desktop app first/);
  doc.querySelectorAll('pass-notice').forEach((n) => n.remove());
});
