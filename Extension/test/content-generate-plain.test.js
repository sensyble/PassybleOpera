// "Letters and numbers only" in the page (src/content/main.js, password-rules.js, shared/generate-prefs.js) in jsdom.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';
import { isPlainPassword } from '../src/shared/generator.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://www.shop.example/account/create', pretendToBeVisual: true });
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

const STRONG_PW = 'Agent-Generated-Pw-123!';
const PLAIN_PW = 'AgentPlainPw23456789';
const sent = [];
let local = {};
let runtimeListener = null;
const ok = (result) => ({ ok: true, result });
const defaults = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ok({ items: [], pending_otp: null }),
  generate: (msg) => ok({ password: msg.symbols === false ? PLAIN_PW : STRONG_PW }),
  'save.query': () => ok(null),
  'draft.save': () => ok({ id: 'draft-1', created: true, title: 'shop.example' }),
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
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : ok({});
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: {
      local: { get: async (keys) => (Array.isArray(keys) ? Object.fromEntries(keys.filter((k) => k in local).map((k) => [k, local[k]])) : {}) },
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

function reset(html, { remembered = [] } = {}) {
  doc.querySelectorAll('pass-menu, pass-action-toast, pass-notice').forEach((n) => n.remove());
  doc.activeElement?.blur?.();
  doc.body.innerHTML = html;
  sent.length = 0;
  local = { generateNoSymbols: remembered };
  responses = { ...defaults };
}

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
const items = () => [...(rootOf('pass-menu')?.querySelectorAll('.item') || [])];
const titles = () => items().map((el) => el.querySelector('.title').textContent);
const subtitles = () => items().map((el) => el.querySelector('.sub')?.textContent || '');
const generateCalls = () => sent.filter((m) => m.type === 'generate');
const filled = () => sent.filter((m) => m.type === 'generate.filled');

async function userFocus(el) {
  await dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  el.focus();
  await tick(20);
}

const signup = (pw = '<input type="password" name="password" autocomplete="new-password">') => `<form><h1>Create your account</h1>
  <input type="email" name="email" autocomplete="email" value="me@x.test">
  ${pw}
  <input type="password" name="confirm" placeholder="Confirm password">
  <button type="submit">Create account</button></form>`;

test('the generator has a second row "Letters and numbers only": picking it fills a password without symbols, remembered for the site', async () => {
  reset(signup());
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  assert.deepEqual(titles(), ['Generate strong password', 'Letters and numbers only', 'Password options']);
  assert.deepEqual(subtitles(), ['', 'No special characters, for sites that reject them', 'Length, character types, passphrase']);
  assert.ok(items()[0].querySelector('.pw-val'), 'the preview is on the first row');
  assert.ok(!items()[1].querySelector('.pw-val'), 'the second one is generated when picked');
  assert.deepEqual(generateCalls().map((m) => m.symbols), [undefined], 'only the strong preview asked for');

  await tick(VISIBLE);
  await click(items()[1]);
  await tick(20);
  assert.equal(pw.value, PLAIN_PW);
  assert.equal(doc.querySelector('[name=confirm]').value, PLAIN_PW);
  assert.deepEqual(generateCalls().at(-1), { type: 'generate', length: 20, automatic: true, symbols: false });
  assert.deepEqual(filled(), [{ type: 'generate.filled', password: PLAIN_PW, symbols: false }]);
});

test('a site that last got letters and numbers: that row first with the preview, the strong one second', async () => {
  reset(signup(), { remembered: ['shop.example'] });
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  assert.deepEqual(titles(), ['Letters and numbers only', 'Generate strong password', 'Password options']);
  assert.deepEqual(subtitles(), ['', 'With special characters', 'Length, character types, passphrase']);
  assert.equal(generateCalls()[0].symbols, false);

  // Enter takes the preselected first row.
  await dispatchTrusted(pw, new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, composed: true, cancelable: true }));
  await tick(20);
  assert.equal(pw.value, PLAIN_PW);
  assert.deepEqual(filled().at(-1), { type: 'generate.filled', password: PLAIN_PW, symbols: false });

  // The strong one stays one click away (and forgets the site in the background).
  pw.value = '';
  doc.querySelector('[name=confirm]').value = '';
  await userFocus(pw);
  await click(pw);
  await tick(50);
  assert.deepEqual(titles(), ['Letters and numbers only', 'Generate strong password', 'Password options']);
  await tick(VISIBLE);
  await click(items()[1]);
  await tick(20);
  assert.equal(pw.value, STRONG_PW);
  assert.deepEqual(filled().at(-1), { type: 'generate.filled', password: STRONG_PW, symbols: true });
});

test('a field whose pattern allows only letters and digits: no symbols by default, at the length it allows', async () => {
  reset(signup('<input type="password" name="password" autocomplete="new-password" pattern="[A-Za-z0-9]{8,16}">'));
  responses.generate = (msg) => ok({ password: msg.symbols === false ? PLAIN_PW.slice(0, msg.length) : STRONG_PW });
  await tick(300);
  await userFocus(doc.querySelector('[name=password]'));
  assert.equal(titles()[0], 'Letters and numbers only');
  assert.deepEqual(generateCalls()[0], { type: 'generate', length: 16, automatic: true, symbols: false });
});

test('an older desktop app that ignores `symbols`: the password is generated here without them', async () => {
  reset(signup(), { remembered: ['shop.example'] });
  responses.generate = () => ok({ password: STRONG_PW });
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await dispatchTrusted(pw, new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, composed: true, cancelable: true }));
  await tick(20);
  assert.equal(pw.value.length, 20);
  assert.ok(isPlainPassword(pw.value), pw.value);
});

test('the generate button uses the site\'s choice; the context menu\'s second item always leaves symbols out', async () => {
  reset(signup(), { remembered: ['shop.example'] });
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await userFocus(pw);
  await dispatchTrusted(pw, new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true }));
  await tick(VISIBLE);
  await click(rootOf('pass-icon').querySelector('.gen'));
  await tick(50);
  assert.equal(pw.value, PLAIN_PW);
  assert.equal(sent.find((m) => m.type === 'draft.save').password, PLAIN_PW);

  reset(signup());
  await tick(300);
  const field = doc.querySelector('[name=password]');
  await dispatchTrusted(field, new w.MouseEvent('contextmenu', { bubbles: true, composed: true, button: 2 }));
  assert.deepEqual(await command({ type: 'cmd.generate-here', symbols: false }), { ok: true });
  assert.equal(field.value, PLAIN_PW);
  assert.deepEqual(filled(), [{ type: 'generate.filled', password: PLAIN_PW, symbols: false }]);

  field.value = '';
  sent.length = 0;
  await dispatchTrusted(field, new w.MouseEvent('contextmenu', { bubbles: true, composed: true, button: 2 }));
  assert.deepEqual(await command({ type: 'cmd.generate-here' }), { ok: true });
  assert.equal(field.value, STRONG_PW, '"Generate password": with symbols');
  assert.deepEqual(filled(), [{ type: 'generate.filled', password: STRONG_PW, symbols: true }]);
});

test('the Generate password shortcut (`focused`): the focused password field, with the site\'s choice; elsewhere it answers no', async () => {
  reset(signup(), { remembered: ['shop.example'] });
  await tick(300);
  const field = doc.querySelector('[name=password]');
  await userFocus(field);
  await dispatchTrusted(field, new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true }));
  sent.length = 0;
  assert.deepEqual(await command({ type: 'cmd.generate-here', focused: true }), { ok: true });
  assert.equal(field.value, PLAIN_PW, 'letters and numbers, as last time on this site');
  assert.deepEqual(filled(), [{ type: 'generate.filled', password: PLAIN_PW }], 'the site\'s choice stays as it was');
  assert.ok(sent.some((m) => m.type === 'draft.save'), 'saved like the generate button');

  // The focus in the e-mail field, even right after a right-click on the password field: nothing filled.
  reset(signup());
  await tick(300);
  const pw = doc.querySelector('[name=password]');
  await dispatchTrusted(pw, new w.MouseEvent('contextmenu', { bubbles: true, composed: true, button: 2 }));
  await userFocus(doc.querySelector('[name=email]'));
  sent.length = 0;
  assert.deepEqual(await command({ type: 'cmd.generate-here', focused: true }), { ok: false });
  assert.equal(pw.value, '');
  assert.equal(generateCalls().length, 0);
});
