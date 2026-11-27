import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
const stored = {};
let reply = () => ({ ok: true, result: null });
let instance = 0;

const ok = (result) => ({ ok: true, result });
const fail = (code, message = code) => ({ ok: false, error: { code, message } });

const ITEMS = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false }];
const STATE = { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null, items: ITEMS,
  can_edit: true, can_scan: false, can_generate_username: true, can_generate_email: true };
const EDIT = { id: 'gh', title: 'GitHub', username: 'octo', password: 'hunter2', notes: '', urls: ['https://github.com'], totp: null };
const OPTIONS = { plus: true, catch_all: true, aliases: [
  { id: 'addy', name: 'addy.io', default: false },
  { id: 'simplelogin', name: 'SimpleLogin', default: true },
] };

function agent(overrides = {}) {
  return (msg) => {
    if (overrides[msg.type]) return overrides[msg.type](msg);
    switch (msg.type) {
      case 'popup.state': return ok(STATE);
      case 'popup.edit-get': return ok(EDIT);
      case 'popup.edit-save': return ok({ id: msg.id || 'new', title: 'GitHub' });
      case 'popup.generate-options': return ok(OPTIONS);
      case 'popup.generate-username': return ok({ username: 'Swift-Otter' });
      case 'popup.generate-email': return ok({ email: `${msg.kind}@example.test` });
      default: return ok({});
    }
  };
}

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, document: dom.window.document, $ };
}

const flush = async (n = 4) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const sent = (type) => messages.filter((m) => m.type === type);

/** Opens the editor on the saved login. */
async function openEditor($) {
  const more = $('list').querySelector('button[title="More"]');
  more.click();
  $('row-edit').click();
  await flush();
}

/** Opens the username generator menu; returns its items' ids. */
async function openGenMenu($, document) {
  $('ed-username-generate').click();
  await flush();
  return [...document.querySelectorAll('.popover [role^="menuitem"]')].map((b) => b.id);
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }] },
    storage: {
      local: {
        get: async (keys) => Object.fromEntries((Array.isArray(keys) ? keys : Object.keys(stored)).filter((k) => k in stored).map((k) => [k, stored[k]])),
        set: async (o) => { Object.assign(stored, o); },
      },
      sync: { get: async () => ({}), set: async () => {} },
    },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('older desktop apps (no generate.* features): no username generator', async () => {
  reply = agent({ 'popup.state': () => ok({ ...STATE, can_generate_username: false, can_generate_email: false }) });
  const { $ } = await openPopup();
  await openEditor($);
  assert.ok($('ed-username'));
  assert.equal($('ed-username-generate'), null);
});

test('the menu: random username, plus, catch-all, aliases (default first), then "Mention this website" (off)', async () => {
  for (const k of Object.keys(stored)) delete stored[k];
  reply = agent();
  const { $, document } = await openPopup();
  await openEditor($);
  const gen = $('ed-username-generate');
  assert.equal(gen.title, 'Generate username');
  assert.equal(gen.getAttribute('aria-haspopup'), 'menu');
  const ids = await openGenMenu($, document);
  assert.deepEqual(ids, ['ed-gen-username', 'ed-gen-plus', 'ed-gen-catchall', 'ed-gen-alias-simplelogin', 'ed-gen-alias-addy', 'ed-gen-website']);
  assert.deepEqual(sent('popup.generate-options'), [{ type: 'popup.generate-options', tabId: 1 }]);
  assert.equal($('ed-gen-alias-simplelogin').textContent, 'E-mail alias (SimpleLogin)');
  assert.equal($('ed-gen-website').getAttribute('role'), 'menuitemcheckbox');
  assert.equal($('ed-gen-website').getAttribute('aria-checked'), 'false', 'off by default');

  let typed = 0;
  $('ed-username').addEventListener('input', () => { typed += 1; });
  $('ed-gen-username').click();
  await flush();
  assert.equal(document.querySelector('.popover'), null, 'menu closed');
  assert.deepEqual(sent('popup.generate-username'), [{ type: 'popup.generate-username' }]);
  assert.equal($('ed-username').value, 'Swift-Otter');
  assert.equal(typed, 1, 'an input event, as when typing');

  // Plus address without the website.
  await openGenMenu($, document);
  $('ed-gen-plus').click();
  await flush();
  assert.deepEqual(sent('popup.generate-email'), [{ type: 'popup.generate-email', tabId: 1, kind: 'plus' }]);
  assert.equal($('ed-username').value, 'plus@example.test');

  $('ed-save').click();
  await flush();
  assert.equal(sent('popup.edit-save')[0].fields.username, 'plus@example.test');
});

test('"Mention this website": the menu stays open, the choice is remembered and sent as website: true', async () => {
  for (const k of Object.keys(stored)) delete stored[k];
  reply = agent();
  const { $, document } = await openPopup();
  await openEditor($);
  await openGenMenu($, document);
  $('ed-gen-website').click();
  await flush();
  assert.ok(document.querySelector('.popover'), 'still open');
  assert.equal($('ed-gen-website').getAttribute('aria-checked'), 'true');
  assert.equal(stored.mentionWebsite, true, 'remembered in the settings');
  $('ed-gen-catchall').click();
  await flush();
  assert.deepEqual(sent('popup.generate-email').at(-1), { type: 'popup.generate-email', tabId: 1, kind: 'catch_all', website: true });

  // Next time it is still ticked; the alias goes to the picked service.
  await openGenMenu($, document);
  assert.equal($('ed-gen-website').getAttribute('aria-checked'), 'true');
  $('ed-gen-alias-addy').click();
  await flush();
  assert.deepEqual(sent('popup.generate-email').at(-1), { type: 'popup.generate-email', tabId: 1, kind: 'alias', service: 'addy', website: true });

  // Unticked again: no website.
  await openGenMenu($, document);
  $('ed-gen-website').click();
  await flush();
  assert.equal(stored.mentionWebsite, false);
  $('ed-gen-alias-simplelogin').click();
  await flush();
  assert.deepEqual(sent('popup.generate-email').at(-1), { type: 'popup.generate-email', tabId: 1, kind: 'alias', service: 'simplelogin' });
});

test('locked (or soft-locked): the options fail, only "Random username" is offered, no unlock form', async () => {
  reply = agent({ 'popup.state': () => ok({ ...STATE, can_unlock_inline: true }), 'popup.generate-options': () => fail('locked', 'vault is locked') });
  const { $, document } = await openPopup();
  await openEditor($);
  const ids = await openGenMenu($, document);
  assert.deepEqual(ids, ['ed-gen-username']);
  assert.equal($('view-edit').hidden, false, 'still in the editor: no unlock form for the options');
  $('ed-gen-username').click();
  await flush();
  assert.equal($('ed-username').value, 'Swift-Otter');
});

test('nothing set up for e-mail: only "Random username", no website checkbox', async () => {
  reply = agent({ 'popup.generate-options': () => ok({ plus: false, catch_all: false, aliases: [] }) });
  const { $, document } = await openPopup();
  await openEditor($);
  assert.deepEqual(await openGenMenu($, document), ['ed-gen-username']);
});

test('busy while the alias is created: the button is disabled and spins; the field fills when it is done', async () => {
  let finish;
  reply = agent({ 'popup.generate-email': () => new Promise((resolve) => { finish = () => resolve(ok({ email: 'x7k2@aleeas.test' })); }) });
  const { $, document } = await openPopup();
  await openEditor($);
  await openGenMenu($, document);
  $('ed-gen-alias-simplelogin').click();
  await flush();
  const gen = $('ed-username-generate');
  assert.equal(gen.disabled, true);
  assert.equal(gen.getAttribute('aria-busy'), 'true');
  assert.ok(gen.classList.contains('busy'));
  assert.equal($('snack').textContent, 'Creating the e-mail alias…');
  assert.equal($('ed-username').value, 'octo', 'unchanged while waiting');
  finish();
  await flush();
  assert.equal($('ed-username').value, 'x7k2@aleeas.test');
  assert.equal(gen.disabled, false);
  assert.equal(gen.getAttribute('aria-busy'), null);
});

test('errors: shown in the snackbar, the username stays as it was', async () => {
  const cases = [
    [fail('not_found', 'Set up the e-mail generator in Passyble: Settings, Generator.'), 'Set this up in the Passyble desktop app first: open Passyble → Settings.'],
    [fail('internal', "SimpleLogin didn't accept the API token: check it in Settings"), "SimpleLogin didn't accept the API token: check it in Settings."],
    [fail('invalid_params', 'The catch-all domain in Settings is not valid.'), 'The catch-all domain in Settings is not valid.'],
    [fail('rate_limited', 'Too many new aliases. Wait a minute.'), 'Too many new aliases. Wait a minute.'],
    // An older desktop app (the background's "unknown method" with reason needs_update), and a build
    // without alias services (its English text is not shown).
    [{ ok: false, error: { code: 'not_supported', message: 'unknown method', reason: 'needs_update' } }, 'This needs a newer Passyble app. Update Passyble, then try again.'],
    [fail('not_supported', 'This build has no e-mail alias services.'), "This Passyble app can't create e-mail aliases. Pick another option."],
    // The desktop app's own English answers to requests the extension shouldn't send: a generic text.
    [fail('invalid_params', 'unknown service nosuch'), 'Something went wrong. Try again.'],
    // An exception in the background: never its text.
    [{ ok: false, error: { code: 'internal', message: 'TypeError: x is undefined', reason: 'unexpected' } }, 'Something went wrong. Try again.'],
    [fail('timeout', 'Passyble did not answer "generate.email" in time'), null],
  ];
  for (const [answer, text] of cases) {
    reply = agent({ 'popup.generate-email': () => answer });
    const { $, document } = await openPopup();
    await openEditor($);
    await openGenMenu($, document);
    $('ed-gen-alias-simplelogin').click();
    await flush();
    if (text) assert.equal($('snack').textContent, text, answer.error.code);
    else assert.ok($('snack').textContent && $('snack').textContent !== 'Creating the e-mail alias…', answer.error.code);
    assert.equal($('ed-username').value, 'octo');
    assert.equal($('ed-username-generate').disabled, false);
  }
});
