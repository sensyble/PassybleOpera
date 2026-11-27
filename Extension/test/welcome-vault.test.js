import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { checkMasterPassword } from './helpers/fake-wasm.js';
import { MASTER_CHECK_DEBOUNCE_MS } from '../src/shared/master-password.js';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const flush = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => { for (let i = 0; i < 8; i++) await flush(); };
/** Typing paused: the debounced master password check went out and was answered. */
const paused = async () => { await new Promise((r) => setTimeout(r, MASTER_CHECK_DEBOUNCE_MS + 40)); await settle(); };
const sent = (type) => messages.filter((m) => m.type === type);
/** Every message that carried `secret` anywhere (a master password must go exactly once). */
const carrying = (secret) => messages.filter((m) => JSON.stringify(m).includes(secret));

async function openWelcome({ hash = '', userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } = {}) {
  const html = readFileSync(new URL('../src/welcome/welcome.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: `https://extension.test/src/welcome/welcome.html${hash}`, pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  Object.defineProperty(globalThis, 'navigator', { value: { userAgent, platform: /Windows/.test(userAgent) ? 'Win32' : 'MacIntel' }, configurable: true });
  globalThis.location = { hash };
  messages.length = 0;
  await import(`../src/welcome/welcome.js?vault=${++instance}`);
  await settle();
  const $ = (id) => dom.window.document.getElementById(id);
  const submit = async (id) => { $(id).dispatchEvent(new dom.window.Event('submit', { cancelable: true })); await settle(); };
  const click = async (id) => { $(id).click(); await settle(); };
  return { window: dom.window, document: dom.window.document, $, submit, click };
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      getManifest: () => ({ version: '1.2.3', host_permissions: ['<all_urls>'] }),
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
    },
    tabs: { create: async () => {} },
    storage: { local: { get: async () => ({}), set: async () => {} } },
    commands: { getAll: async () => [] },
    action: {},
  };
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (fn, ms, ...args) => (ms >= 1000 ? { unref() {} } : realSetTimeout(fn, ms, ...args));
});

afterEach(() => { delete globalThis.location; });

const PW = 'master pw 1';
const STATE = {
  mode: null, supported: true, host: 'missing', has_vault: false, locked: true, source: null,
  backed_up_at: 0, created_at: 0, name: null, settings: {}, local_only: false, drive_needs_app: false, reminder: false,
};

/** `state` once a vault kept only in this browser is open. */
const inBrowser = (state) => ({ ...state, mode: 'browser', has_vault: true, locked: false, source: null, local_only: true, drive_needs_app: false, reminder: true });

/**
 * A background: vault.state from `state` (a fresh copy each time, so the page can't change it),
 * vault.create / vault.open-file as the real one answers (the master password is `master pw 1`),
 * vault.check-master with the test stand-in of the master password rule (helpers/fake-wasm.js; `createError`:
 * what vault.create answers instead), vault.check-app with `app` ('missing' / 'installed' / 'connected'), and
 * account.status signed in as `email` when given.
 */
function background(state, { openError = null, app = 'missing', email = null, createError = null } = {}) {
  let current = structuredClone(state);
  const wrong = { ok: false, error: { code: 'wrong_password', message: 'x' } };
  reply = (msg) => {
    switch (msg.type) {
      case 'vault.state': return { ok: true, result: structuredClone(current) };
      case 'account.status': return { ok: true, result: { signed_in: !!email, email, app_mode: false } };
      case 'vault.check-master': return { ok: true, result: JSON.parse(checkMasterPassword(msg.password, JSON.stringify(msg.names))) };
      case 'vault.create':
        if (createError) return { ok: false, error: createError };
        current = inBrowser(current);
        return { ok: true, result: { vault_id: 'v3' } };
      case 'vault.open-file':
        if (msg.password !== PW) return wrong;
        if (openError) return { ok: false, error: openError };
        current = inBrowser(current);
        return { ok: true, result: { vault_id: 'v4' } };
      case 'vault.check-app': return { ok: true, result: { app } };
      case 'vault.set-mode': current = { ...current, mode: msg.mode }; return { ok: true, result: structuredClone(current) };
      case 'popup.status': return { ok: false, error: { code: 'agent_unavailable', message: 'Specified native messaging host not found.' } };
      default: return { ok: true, result: null };
    }
  };
}

/** The visible rows of the first choice, as their text. */
const choices = (document) => [...document.querySelectorAll('#vault-choice .choice-item')].filter((r) => !r.hidden).map((r) => (r.querySelector('.choice-title') || r).textContent.trim());

const NOTICE = 'Only on this device. If you lose this device you lose these passwords. You can turn on Google Drive backup now or later.';
const LOCAL_TITLE = 'This vault is only on this device';
const LOCAL_BODY = 'If this device is lost, stolen, broken or reset, the passwords in this vault are gone for good. Turn on sync or backup (Google Drive is free), or export a backup copy regularly.';

test('no Passyble app for this browser: Google Drive sync, Create a vault here, Open a vault file, Get the Windows app, Sign in; no app checklist, no polling', async () => {
  background(STATE);
  const { $, document } = await openWelcome();
  assert.equal($('vault').hidden, false);
  assert.equal($('vault-choice').hidden, false);
  assert.equal($('setup').hidden, true);
  assert.equal(sent('popup.status').length, 0, 'the app is not polled');
  assert.deepEqual(choices(document), ['Google Drive sync', 'Create a vault in this browser', 'Open a vault file', 'Get the Windows app', 'Sign in', 'Use your Passyble password']);
  assert.match($('choose-drive').textContent, /Needs the Passyble app on this computer\./);
  assert.match($('choose-create').textContent, /Kept only on this device\./);
  const shownText = [...$('vault-choice').querySelectorAll('p')].filter((p) => !p.closest('[hidden]'));
  assert.equal(shownText.length, 0, 'titles and captions only, no paragraphs');
  assert.equal(messages.some((m) => m.type.startsWith('drive.')), false, 'nothing about Google sign-in');
});

test('on macOS (or Linux) there is no "Get the Windows app" choice', async () => {
  background(STATE);
  const { document, $ } = await openWelcome({ userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0)' });
  assert.equal($('choose-app').hidden, true);
  assert.deepEqual(choices(document), ['Google Drive sync', 'Create a vault in this browser', 'Open a vault file', 'Sign in', 'Use your Passyble password']);
});

test('Google Drive sync: "needs the Passyble app on this computer", Download (passyble.com/download), Check again; no Google sign-in', async () => {
  background(STATE);
  const { $, document, click } = await openWelcome();
  await click('choose-drive');
  assert.equal($('vault-drive').hidden, false);
  assert.equal($('vault-choice').hidden, true);
  assert.equal($('vault-drive').querySelector('h3').textContent, 'Google Drive sync needs the Passyble app on this computer');
  assert.match($('vault-drive').textContent, /turn on Google Drive in the app/);
  assert.equal($('drive-move-hint').hidden, true, 'no vault here: nothing to take along');
  const download = $('drive-download');
  assert.equal(download.getAttribute('href'), 'https://www.passyble.com/download');
  assert.equal(download.getAttribute('target'), '_blank');
  assert.equal(download.textContent.trim(), 'Download the Passyble app');
  assert.equal($('drive-use-app').hidden, true);
  await click('drive-check');
  assert.deepEqual(sent('vault.check-app'), [{ type: 'vault.check-app' }]);
  assert.equal($('drive-check-msg').textContent, "The Passyble app isn't on this computer yet.");
  assert.equal($('drive-use-app').hidden, true);
  assert.equal(messages.some((m) => m.type.startsWith('drive.')), false);
  document.querySelector('#vault-drive [data-back]').click();
  assert.equal($('vault-choice').hidden, false);
});

test('Check again finds the Passyble app: "Use the app" switches to it, then the app checklist (with where to turn on Google Drive)', async () => {
  background(STATE, { app: 'installed' });
  const { $, click } = await openWelcome({ hash: '#sync' });
  assert.equal($('vault-drive').hidden, false, '#sync: straight to it');
  await click('drive-check');
  assert.equal($('drive-check-msg').textContent, 'The Passyble app is on this computer. Use it, then turn on Google Drive in the app.');
  assert.equal($('drive-use-app').hidden, false);
  await click('drive-use-app');
  assert.deepEqual(sent('vault.set-mode'), [{ type: 'vault.set-mode', mode: 'app' }]);
  assert.equal($('vault').hidden, true);
  assert.equal($('setup').hidden, false);
  assert.equal($('drive-in-app').textContent, 'For Google Drive sync, open Settings in the Passyble app, then Sync, and turn on Google Drive.');
});

test('older links (#drive, #move) open "Google Drive sync needs the Passyble app" too', async () => {
  for (const hash of ['#drive', '#move']) {
    background(inBrowser(STATE));
    const { $ } = await openWelcome({ hash });
    assert.equal($('vault-drive').hidden, false, hash);
    assert.equal($('drive-move-hint').hidden, false, `${hash}: a vault here: how to take it along`);
  }
});

/** The master password hint as shown: the red reasons, or the one "strong enough" line. */
const hint = (el) => {
  const items = [...el.querySelectorAll('.master-issues li')].map((li) => li.textContent);
  return items.length ? items : el.textContent;
};
const TOO_SHORT = 'Use at least 12 characters.';
const COMMON = 'This is one of the most common passwords. Choose something else.';
const NAME = "Leave out your e-mail address, username and the vault's name.";
const PATTERN = 'Avoid repeated characters, sequences like abcd or 1234 and keyboard rows like qwerty.';
const GUESSABLE = 'Too easy to guess. Add more words or random characters: four or more unrelated words work well.';

test('create a vault in this browser: the "only on this device" notice on the step with Set up sync; the master password rule live, the repeat; the password is created once', async () => {
  background(STATE);
  const { $, window, submit, click } = await openWelcome();
  await click('choose-create');
  assert.equal($('vault-create').hidden, false);
  assert.match($('vault-create').textContent, /can't reset your master password/);
  assert.equal($('create-local').hidden, false);
  assert.equal($('create-local').querySelector('p').textContent, NOTICE);
  assert.equal($('create-name'), null, 'no vault name (that was for the Drive list)');
  const pw = $('create-pw');
  const strength = $('create-strength');
  const type = (v) => { pw.value = v; pw.dispatchEvent(new window.Event('input')); };
  assert.equal(strength.textContent, '', 'nothing before typing');
  type('short');
  assert.equal(sent('vault.check-master').length, 0, 'debounced: nothing asked while typing');
  await paused();
  assert.deepEqual(sent('vault.check-master'), [{ type: 'vault.check-master', password: 'short', names: [] }]);
  assert.deepEqual(hint(strength), [TOO_SHORT, GUESSABLE], 'every reason, in the core\'s order');
  assert.equal(strength.dataset.state, 'refused');
  assert.equal(strength.querySelector('.master-issues').getAttribute('aria-label'), 'Password check');
  type('');
  assert.equal(strength.textContent, '', 'an empty field shows nothing at once');
  assert.equal(strength.dataset.state, undefined);
  // Typing on: only the last value is checked.
  const asked = sent('vault.check-master').length;
  for (const v of ['a', 'aa', 'aaaabbbbcccc1234']) type(v);
  await paused();
  assert.equal(sent('vault.check-master').length, asked + 1);
  assert.equal(sent('vault.check-master').at(-1).password, 'aaaabbbbcccc1234');
  assert.deepEqual(hint(strength), [PATTERN, GUESSABLE]);
  type('Longer Password 2026!');
  await paused();
  assert.equal(hint(strength), 'Strong: strong enough for a master password.');
  assert.equal(strength.dataset.state, 'ok');
  $('create-pw2').value = 'something else';
  await submit('vault-create');
  assert.equal($('create-msg').textContent, "The passwords don't match. Type them again.");
  assert.equal($('create-pw2').value, '');
  assert.equal(sent('vault.create').length, 0);
  $('create-pw2').value = 'Longer Password 2026!';
  await submit('vault-create');
  assert.deepEqual(sent('vault.create'), [{ type: 'vault.create', password: 'Longer Password 2026!', names: [] }]);
  const carried = carrying('Longer Password 2026!');
  assert.equal(carried.filter((m) => m.type === 'vault.create').length, 1, 'the vault was created once');
  assert.deepEqual([...new Set(carried.map((m) => m.type))].sort(), ['vault.check-master', 'vault.create'], 'and only checked otherwise');
  assert.equal(pw.value, '');
  assert.equal($('create-pw2').value, '');
  assert.equal(strength.textContent, '');
  // Ready, with the reminder: only on this device, Set up sync.
  assert.equal($('vault-ready').hidden, false);
  assert.equal($('ready-notice').hidden, false);
  assert.equal($('ready-notice-title').textContent, LOCAL_TITLE);
  assert.equal($('ready-notice-text').textContent, LOCAL_BODY);
  await click('ready-sync');
  assert.equal($('vault-drive').hidden, false);
  assert.equal($('drive-move-hint').hidden, false);
  $('vault-drive').querySelector('[data-back]').click();
  assert.equal($('vault-ready').hidden, false, 'Back: to the vault of this browser');
});

test('create: a master password the rule refuses is refused on submit with its first reason, also right after typing and when empty', async () => {
  background(STATE);
  const { $, window, submit } = await openWelcome({ hash: '#create' });
  const pw = $('create-pw');
  const type = (v) => { pw.value = v; pw.dispatchEvent(new window.Event('input')); };
  await submit('vault-create');
  assert.equal($('create-msg').textContent, TOO_SHORT, 'empty: the minimum length');
  assert.equal($('create-msg').className.includes('error'), true);
  for (const [value, first] of [['password2024!', COMMON], ['aaaabbbbcccc1234', PATTERN], ['longenough', TOO_SHORT]]) {
    type(value);
    $('create-pw2').value = value;
    await submit('vault-create'); // before the debounced check: the submit asks itself
    assert.equal($('create-msg').textContent, first, value);
    assert.equal($('create-strength').querySelector('.master-issues li')?.textContent, first, `${value}: the reasons show too`);
    assert.equal(document.activeElement, pw, 'back to the master password');
  }
  assert.equal(sent('vault.create').length, 0, 'nothing was created');
  await paused();
  assert.equal($('create-msg').textContent, TOO_SHORT, 'a late check changes nothing');
});

test('create: the signed-in account\'s e-mail address counts as known; a refusal from the background says why', async () => {
  background(STATE, { email: 'alex.smith@example.com' });
  const { $, window, submit } = await openWelcome({ hash: '#create' });
  const pw = $('create-pw');
  const type = (v) => { pw.value = v; pw.dispatchEvent(new window.Event('input')); };
  type('alexsmith-orbit-candle');
  await paused();
  assert.deepEqual(sent('vault.check-master').at(-1).names, ['alex.smith@example.com']);
  assert.deepEqual(hint($('create-strength')), [NAME, GUESSABLE]);
  $('create-pw2').value = 'alexsmith-orbit-candle';
  await submit('vault-create');
  assert.equal($('create-msg').textContent, NAME);
  assert.equal(sent('vault.create').length, 0);

  // The page's check passed, but the background (or pass-wasm's create) refuses: no vault, the reason.
  background(STATE, { createError: { code: 'invalid_params', message: 'This master password is too easy to guess' } });
  const again = await openWelcome({ hash: '#create' });
  again.$('create-pw').value = 'Longer Password 2026!';
  again.$('create-pw2').value = 'Longer Password 2026!';
  await again.submit('vault-create');
  assert.equal(sent('vault.create').length, 1);
  assert.equal(again.$('create-msg').textContent, GUESSABLE);
  assert.equal(again.$('vault-ready').hidden, true);
});

test('the create step\'s Set up sync: "Google Drive sync needs the Passyble app"; Back returns to the choice', async () => {
  background(STATE);
  const { $, click } = await openWelcome({ hash: '#create' });
  assert.equal($('vault-create').hidden, false, '#create: straight to it');
  await click('create-sync');
  assert.equal($('vault-drive').hidden, false);
  $('vault-drive').querySelector('[data-back]').click();
  assert.equal($('vault-choice').hidden, false);
});

test('open a vault file: needs the file and its master password; a wrong password or a non-vault file says so', async () => {
  background(STATE);
  const { $, submit, click } = await openWelcome();
  await click('choose-open');
  assert.equal($('vault-open').hidden, false);
  await submit('vault-open');
  assert.equal($('open-msg').textContent, 'Choose a vault file first.');
  Object.defineProperty($('open-file'), 'files', { value: [{ arrayBuffer: async () => new Uint8Array([1, 2, 3]).buffer }], configurable: true });
  await submit('vault-open');
  assert.equal($('open-msg').textContent, 'Enter your master password.');
  assert.equal(sent('vault.open-file').length, 0);
  $('open-pw').value = 'nope';
  await submit('vault-open');
  assert.match($('open-msg').textContent, /Wrong master password/);
  assert.equal($('open-pw').value, '');
  $('open-pw').value = PW;
  await submit('vault-open');
  assert.deepEqual(sent('vault.open-file').at(-1), { type: 'vault.open-file', file: 'AQID', password: PW });
  assert.equal(carrying(PW).length, 1);
  assert.equal($('open-pw').value, '');
  assert.equal($('vault-ready').hidden, false);
  assert.equal($('ready-notice-title').textContent, LOCAL_TITLE);

  background(STATE, { openError: { code: 'invalid_params', message: 'This is not a Passyble vault file' } });
  const again = await openWelcome({ hash: '#open' });
  assert.equal(again.$('vault-open').hidden, false, '#open: straight to it');
  Object.defineProperty(again.$('open-file'), 'files', { value: [{ arrayBuffer: async () => new ArrayBuffer(4) }], configurable: true });
  again.$('open-pw').value = PW;
  await again.submit('vault-open');
  assert.equal(again.$('open-msg').textContent, "This isn't a Passyble vault file.");
  assert.equal(again.$('vault-open').hidden, false);
});

test('browser mode with a vault kept only here: ready with "This vault is only on this device"; no app checklist', async () => {
  background(inBrowser(STATE));
  const { $ } = await openWelcome();
  assert.equal($('vault-ready').hidden, false);
  assert.equal($('ready-notice').hidden, false);
  assert.equal($('ready-notice-title').textContent, LOCAL_TITLE);
  assert.equal($('setup').hidden, true);
  assert.equal(sent('popup.status').length, 0);
});

test('browser mode with a vault record of the builds that synced Google Drive themselves: ready, "Google Drive sync needs the Passyble app"', async () => {
  background({ ...inBrowser(STATE), source: 'drive', local_only: false, drive_needs_app: true, reminder: false });
  const { $, click } = await openWelcome();
  assert.equal($('vault-ready').hidden, false);
  assert.equal($('ready-notice').hidden, false);
  assert.equal($('ready-notice-title').textContent, 'Google Drive sync needs the Passyble app on this computer');
  assert.match($('ready-notice-text').textContent, /synced with Google Drive in an older version/);
  await click('ready-sync');
  assert.equal($('vault-drive').hidden, false);
});

test('app mode: the app checklist as before (where to turn on Google Drive in the app), and a link to the vault choice instead', async () => {
  background({ ...STATE, mode: 'app', host: 'present' });
  const { $, window } = await openWelcome();
  assert.equal($('setup').hidden, false);
  assert.equal($('vault').hidden, true);
  assert.ok(sent('popup.status').length > 0, 'the checklist polls the app');
  assert.equal($('drive-in-app').closest('[hidden]'), null);
  assert.equal($('browser-link').hidden, false);
  assert.equal($('use-browser').textContent, 'Keep a vault in this browser instead');
  $('use-browser').dispatchEvent(new window.MouseEvent('click', { bubbles: true, cancelable: true }));
  assert.equal($('vault-choice').hidden, false);
  assert.equal($('setup').hidden, true);
});

test('app mode with a vault kept here (#browser from Options): "Use the vault in this browser" switches', async () => {
  background({ ...inBrowser(STATE), mode: 'app', host: 'present', locked: true });
  const { $, click } = await openWelcome({ hash: '#browser' });
  assert.equal($('vault-choice').hidden, false);
  assert.equal($('choose-existing').hidden, false);
  await click('choose-existing');
  assert.deepEqual(sent('vault.set-mode'), [{ type: 'vault.set-mode', mode: 'browser' }]);
  assert.equal($('vault-ready').hidden, false);
  assert.equal($('ready-notice-title').textContent, LOCAL_TITLE);
});

test('an older background without vault.state (or Firefox): the app checklist only', async () => {
  reply = (msg) => (msg.type === 'popup.status' ? { ok: true, result: { locked: false } } : { ok: true, result: null });
  const { $ } = await openWelcome();
  assert.equal($('setup').hidden, false);
  assert.equal($('vault').hidden, true);
  assert.equal($('browser-link').hidden, true);
});

// The Passyble app always wins.

test('a fresh install with the Passyble app installed: no mode choice, the app checklist, and one line that says why', async () => {
  for (const hash of ['', '#browser', '#create', '#open', '#sync']) {
    background({ ...STATE, mode: 'app', host: 'present', app_installed: true });
    const { $ } = await openWelcome({ hash });
    assert.deepEqual(sent('vault.state')[0], { type: 'vault.state', probe: true }, 'a fresh look for the app');
    assert.equal($('setup').hidden, false, hash);
    assert.equal($('vault').hidden, true, `${hash}: no choice`);
    assert.equal($('browser-link').hidden, true, 'no "Keep a vault in this browser instead"');
    assert.equal($('app-installed-line').hidden, false);
    assert.equal($('app-installed-line').textContent, 'The Passyble app is installed on this computer, so Passyble uses it here.');
  }
});

test('Check again finds the app and the background switched: straight to the app checklist', async () => {
  let installed = false;
  background(STATE);
  const base = reply;
  reply = (msg) => {
    if (msg.type === 'vault.check-app') { installed = true; return { ok: true, result: { app: 'installed', mode: 'app' } }; }
    if (msg.type === 'vault.state' && installed) return { ok: true, result: { ...STATE, mode: 'app', host: 'present', app_installed: true } };
    return base(msg);
  };
  const { $, click } = await openWelcome({ hash: '#sync' });
  await click('drive-check');
  assert.equal($('setup').hidden, false);
  assert.equal($('vault').hidden, true);
  assert.equal($('app-installed-line').hidden, false);
});

test('the app gone (several checks): the choice again, with the vault kept here offered', async () => {
  background({ ...STATE, mode: 'app', host: 'missing', app_gone: true, has_vault: true });
  const { $ } = await openWelcome();
  assert.equal($('vault-choice').hidden, false);
  assert.equal($('choose-existing').hidden, false);
  assert.equal($('app-installed-line').hidden, true);
});
