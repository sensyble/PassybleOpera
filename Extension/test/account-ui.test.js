import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const flush = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => { for (let i = 0; i < 10; i++) await flush(); };
const sent = (type) => messages.filter((m) => m.type === type);

async function openPage(page) {
  const html = readFileSync(new URL(`../src/${page}/${page}.html`, import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: `https://extension.test/src/${page}/${page}.html`, pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  Object.defineProperty(globalThis, 'navigator', { value: { userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)', platform: 'Win32' }, configurable: true });
  globalThis.location = { hash: '' };
  messages.length = 0;
  await import(`../src/${page}/${page}.js?account=${++instance}`);
  await settle();
  return { $: (id) => dom.window.document.getElementById(id), document: dom.window.document };
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
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
    commands: { getAll: async () => [] },
    action: {},
  };
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (fn, ms, ...args) => (ms >= 1000 ? { unref() {} } : realSetTimeout(fn, ms, ...args));
});

afterEach(() => { delete globalThis.location; });

const FIRST_RUN = { mode: null, supported: true, host: 'missing', has_vault: false, locked: true, source: null,
  backed_up_at: 0, created_at: 0, name: null, settings: {}, local_only: false, drive_needs_app: false, reminder: false };

/** A background with an account that signs in as ada@example.com (or fails with `signInError`). */
function background({ state = FIRST_RUN, signInError = null } = {}) {
  let signedIn = false;
  reply = (msg) => {
    switch (msg.type) {
      case 'vault.state': return { ok: true, result: structuredClone(state) };
      case 'account.status': return { ok: true, result: { signed_in: signedIn, email: signedIn ? 'ada@example.com' : null, app_mode: false } };
      case 'account.sign-in':
        if (signInError) return { ok: false, error: signInError };
        signedIn = true;
        return { ok: true, result: { signed_in: true, email: 'ada@example.com', app_mode: false } };
      case 'account.sign-out': signedIn = false; return { ok: true, result: { signed_in: false, email: null, app_mode: false } };
      case 'popup.status': return { ok: false, error: { code: 'agent_unavailable', message: 'Specified native messaging host not found.' } };
      default: return { ok: true, result: null };
    }
  };
}

test('setup: "Google Drive sync" first, "Sign in" last (titles only); signed in, it says as whom and that Cloud is coming', async () => {
  background();
  const { $, document } = await openPage('welcome');
  const rows = [...document.querySelectorAll('#vault-choice .choice-item')].filter((r) => !r.hidden);
  assert.deepEqual(rows.map((r) => (r.querySelector('.choice-title') || r).textContent.trim()), ['Google Drive sync', 'Create a vault in this browser', 'Open a vault file', 'Get the Windows app', 'Sign in', 'Use your Passyble password']);
  assert.equal($('cloud-soon').hidden, true, 'nothing about Cloud before signing in');
  $('choose-signin').click();
  await settle();
  assert.equal(sent('account.sign-in').length, 1);
  assert.equal($('choose-signin').hidden, true);
  assert.equal($('signed-in').hidden, false);
  assert.equal($('signed-in-as').textContent, 'Signed in as ada@example.com');
  assert.equal($('cloud-soon').hidden, false);
  assert.equal($('cloud-soon').querySelector('p').textContent, 'Passyble Cloud storage is coming soon.');
  assert.equal($('cloud-use-drive').textContent.trim(), 'Use Google Drive');
  assert.equal($('vault-choice').hidden, false, 'the vault choice stays: the account is not a vault');
  assert.ok(!JSON.stringify(messages).includes('token'), 'the page sends no token');

  $('cloud-use-drive').click();
  await settle();
  assert.equal(messages.some((m) => m.type.startsWith('drive.')), false, 'no Google sign-in in the extension');
  assert.equal($('vault-drive').hidden, false, 'Google Drive sync needs the Passyble app on this computer');
});

test('setup, signed in with a vault here already: no "Use Google Drive"', async () => {
  background({ state: { ...FIRST_RUN, mode: 'app', host: 'present', has_vault: true, local_only: true } });
  const { $ } = await openPage('welcome');
  $('choose-signin').click();
  await settle();
  assert.equal($('signed-in').hidden, false);
  assert.equal($('cloud-soon').hidden, true);
});

test('setup: closing the sign-in window says nothing; a failure says so in one line', async () => {
  background({ signInError: { code: 'cancelled', message: 'Sign in was cancelled' } });
  let page = await openPage('welcome');
  page.$('choose-signin').click();
  await settle();
  assert.equal(page.$('signin-msg').hidden, true);
  assert.equal(page.$('choose-signin').hidden, false);

  background({ signInError: { code: 'internal', message: 'token: invalid_grant' } });
  page = await openPage('welcome');
  page.$('choose-signin').click();
  await settle();
  assert.equal(page.$('signin-msg').hidden, false);
  assert.equal(page.$('signin-msg').textContent, "Couldn't sign in. Try again.");
});

test('setup with an older background: no Sign in', async () => {
  reply = (msg) => (msg.type === 'vault.state' ? { ok: true, result: FIRST_RUN } : { ok: false, error: { code: 'invalid_params', message: 'unknown' } });
  const { $ } = await openPage('welcome');
  assert.equal($('choose-signin').hidden, true);
  assert.equal($('signed-in').hidden, true);
});

test('Options: Account with Sign in; then "Signed in as …" with Sign out, which signs out', async () => {
  background({ state: { ...FIRST_RUN, mode: 'browser', has_vault: true, locked: false } });
  const { $ } = await openPage('options');
  assert.equal($('account-row').hidden, false);
  assert.equal($('account-name').textContent, 'Account');
  assert.equal($('account-signin').hidden, false);
  assert.equal($('account-signout').hidden, true);
  $('account-signin').click();
  await settle();
  assert.equal(sent('account.sign-in').length, 1);
  assert.equal($('account-name').textContent, 'Account');
  assert.equal($('account-email').textContent, 'ada@example.com', 'the e-mail as the caption');
  assert.equal($('account-email').hidden, false);
  assert.equal($('account-signin').hidden, true);
  assert.equal($('account-signout').hidden, false);
  $('account-signout').click();
  await settle();
  assert.equal(sent('account.sign-out').length, 1);
  assert.equal($('account-name').textContent, 'Account');
  assert.equal($('account-signin').hidden, false);
});

/**
 * App mode: the desktop app's account (`reachable`), or the extension's own when the app can't be reached. Sign in
 * with the app there hands over to it (`in_app`); the app signs in later (`appSignsIn()`).
 */
function appModeBackground({ reachable = true } = {}) {
  const st = { appSignedIn: false, ownSignedIn: false };
  const status = () => (reachable
    ? { signed_in: st.appSignedIn, email: st.appSignedIn ? 'ada@app.example' : null, app_mode: true, app_reachable: true }
    : { signed_in: st.ownSignedIn, email: st.ownSignedIn ? 'ada@example.com' : null, app_mode: true, app_reachable: false });
  reply = (msg) => {
    switch (msg.type) {
      case 'vault.state': return { ok: true, result: { ...FIRST_RUN, mode: 'app', host: 'present' } };
      case 'account.status': return { ok: true, result: status() };
      case 'account.sign-in':
        if (reachable) return { ok: true, result: { ...status(), in_app: true } };
        st.ownSignedIn = true;
        return { ok: true, result: status() };
      case 'account.sign-out': return { ok: true, result: { ...status(), in_app: reachable } };
      case 'popup.status': return { ok: true, result: { connected: true } };
      default: return { ok: true, result: null };
    }
  };
  return { appSignsIn: () => { st.appSignedIn = true; } };
}

/** Firefox's data consent: the manifest declares the optional categories; `asked` counts the requests. */
function firefoxConsent() {
  const consent = { asked: 0 };
  const getManifest = chrome.runtime.getManifest;
  chrome.runtime.getManifest = () => ({ ...getManifest(), browser_specific_settings: { gecko: { data_collection_permissions: {
    required: ['none'], optional: ['authenticationInfo', 'personallyIdentifyingInfo'] } } } });
  chrome.permissions = { request: async () => { consent.asked += 1; return true; } };
  consent.restore = () => { chrome.runtime.getManifest = getManifest; delete chrome.permissions; };
  return consent;
}

test('Options, app mode with the app: the app\'s account; Sign in goes to the app without a data consent, and the row follows', async () => {
  const consent = firefoxConsent();
  try {
    const app = appModeBackground();
    const { $, document } = await openPage('options');
    assert.equal($('account-signin').hidden, false);
    $('account-signin').click();
    await settle();
    assert.equal(sent('account.sign-in').length, 1);
    assert.equal(consent.asked, 0, 'the desktop app signs in: nothing to consent to in the browser');
    assert.equal($('account-signin').hidden, false, 'not signed in yet');
    // Signed in in the app's browser window; back to this page.
    app.appSignsIn();
    document.defaultView.dispatchEvent(new document.defaultView.Event('focus'));
    await settle();
    assert.equal($('account-email').textContent, 'ada@app.example');
    assert.equal($('account-signout').hidden, false);
    $('account-signout').click();
    await settle();
    assert.equal(sent('account.sign-out').length, 1, 'Sign out goes to the app too (its account screen)');
    assert.ok(!JSON.stringify(messages).includes('token'), 'the page sends no token');
  } finally {
    consent.restore();
  }
});

test('Options and setup, app mode without the app: Sign in here, with Firefox\'s data consent asked on the click', async () => {
  const consent = firefoxConsent();
  try {
    appModeBackground({ reachable: false });
    let page = await openPage('options');
    page.$('account-signin').click();
    await settle();
    assert.equal(consent.asked, 1);
    assert.equal(page.$('account-email').textContent, 'ada@example.com');

    appModeBackground({ reachable: false });
    page = await openPage('welcome');
    page.$('choose-signin').click();
    await settle();
    assert.equal(consent.asked, 2);
    assert.equal(page.$('signed-in-as').textContent, 'Signed in as ada@example.com');
  } finally {
    consent.restore();
  }
});

test('setup, app mode with the app: Sign in goes to the app, no consent; signed in there, the page says so on return', async () => {
  const consent = firefoxConsent();
  try {
    const app = appModeBackground();
    const { $, document } = await openPage('welcome');
    $('choose-signin').click();
    await settle();
    assert.equal(consent.asked, 0);
    assert.equal($('signin-msg').hidden, true, 'no error');
    app.appSignsIn();
    document.defaultView.dispatchEvent(new document.defaultView.Event('focus'));
    await settle();
    assert.equal($('signed-in-as').textContent, 'Signed in as ada@app.example');
  } finally {
    consent.restore();
  }
});

/**
 * Browser mode with the Passyble app on this computer signed in (the handoff, account.js): `sameAccount` when the
 * app is signed in to the extension's address, `viaApp` when the app signed the extension in.
 */
function peerBackground({ sameAccount = true, viaApp = false } = {}) {
  let signedIn = true;
  reply = (msg) => {
    switch (msg.type) {
      case 'vault.state': return { ok: true, result: { ...FIRST_RUN, mode: 'browser', has_vault: true, locked: false } };
      case 'account.status': return { ok: true, result: { signed_in: signedIn, email: signedIn ? 'ada@example.com' : null, app_mode: false,
        ...(signedIn && viaApp ? { via_app: true } : {}), app_peer: { signed_in: true, same_account: signedIn && sameAccount } } };
      case 'account.sign-out': signedIn = false; return { ok: true, result: { signed_in: false, email: null, app_mode: false } };
      case 'popup.status': return { ok: false, error: { code: 'agent_unavailable', message: 'not running' } };
      default: return { ok: true, result: null };
    }
  };
}

test('Options, the app signed in to the same account: Sign out asks, "also the Passyble app" ticked by default', async () => {
  for (const untick of [false, true]) {
    peerBackground();
    const { $ } = await openPage('options');
    assert.equal($('account-signout').hidden, false);
    $('account-signout').click();
    await settle();
    assert.equal(sent('account.sign-out').length, 0, 'nothing yet: the confirmation first');
    assert.equal($('account-signout-form').hidden, false);
    assert.equal($('account-signout').hidden, true);
    assert.equal($('account-signout-app').checked, true);
    assert.equal($('account-signout-app').closest('label').textContent.trim(), 'Also sign out of the Passyble app on this computer');
    if (untick) $('account-signout-app').checked = false;
    $('account-signout-confirm').click();
    await settle();
    assert.deepEqual(sent('account.sign-out').map((m) => m.also_app), [!untick]);
    assert.equal($('account-signout-form').hidden, true);
    assert.equal($('account-signin').hidden, false);
  }
});

test('Options: Cancel keeps both signed in; another account in the app (or none) signs out at once, no box', async () => {
  peerBackground();
  let page = await openPage('options');
  page.$('account-signout').click();
  await settle();
  page.$('account-signout-cancel').click();
  await settle();
  assert.equal(page.$('account-signout-form').hidden, true);
  assert.equal(page.$('account-signout').hidden, false);
  assert.equal(sent('account.sign-out').length, 0);

  peerBackground({ sameAccount: false });
  page = await openPage('options');
  page.$('account-signout').click();
  await settle();
  assert.equal(page.$('account-signout-form').hidden, true);
  assert.deepEqual(sent('account.sign-out').map((m) => m.also_app), [undefined]);
});

test('Options and setup: "Signed in through the Passyble app on this computer" when the app signed this browser in', async () => {
  peerBackground({ viaApp: true });
  let page = await openPage('options');
  assert.equal(page.$('account-via').hidden, false);
  assert.equal(page.$('account-via').textContent, 'Signed in through the Passyble app on this computer');
  page = await openPage('welcome');
  assert.equal(page.$('signed-in-via').hidden, false);
  assert.equal(page.$('signed-in-via').textContent, 'Signed in through the Passyble app on this computer');
  peerBackground();
  page = await openPage('options');
  assert.equal(page.$('account-via').hidden, true);
  page = await openPage('welcome');
  assert.equal(page.$('signed-in-via').hidden, true);
});

test('Options, app mode: the app and this browser on different accounts: a note naming both, and "Use the app\'s account"', async () => {
  let browserEmail = 'grace@example.com';
  reply = (msg) => {
    switch (msg.type) {
      case 'vault.state': return { ok: true, result: { ...FIRST_RUN, mode: 'app', host: 'present' } };
      case 'account.status': return { ok: true, result: { signed_in: true, email: 'ada@example.com', app_mode: true, app_reachable: true,
        ...(browserEmail ? { browser_email: browserEmail } : {}) } };
      case 'account.use-app-account':
        browserEmail = null;
        return { ok: true, result: { signed_in: true, email: 'ada@example.com', app_mode: true, app_reachable: true } };
      case 'popup.status': return { ok: true, result: { connected: true } };
      default: return { ok: true, result: null };
    }
  };
  const { $ } = await openPage('options');
  assert.equal($('account-email').textContent, 'ada@example.com');
  assert.equal($('account-other').hidden, false);
  assert.equal($('account-other-text').textContent, 'The Passyble app is signed in as ada@example.com; this browser as grace@example.com.');
  assert.equal($('account-use-app').textContent.trim(), 'Use the app\'s account');
  assert.equal(sent('account.use-app-account').length, 0, 'nothing happens until the click');
  $('account-use-app').click();
  await settle();
  assert.equal(sent('account.use-app-account').length, 1);
  assert.equal($('account-other').hidden, true);
  assert.equal($('account-email').textContent, 'ada@example.com');
});

test('Options: no such note in browser mode, or in app mode without a second account', async () => {
  peerBackground({ sameAccount: false });
  let page = await openPage('options');
  assert.equal(page.$('account-other').hidden, true);
  appModeBackground().appSignsIn();
  page = await openPage('options');
  assert.equal(page.$('account-email').textContent, 'ada@app.example');
  assert.equal(page.$('account-other').hidden, true);
});

test('Options: nothing about plans or prices', async () => {
  background();
  const { document } = await openPage('options');
  assert.doesNotMatch(document.body.textContent, /\b(plan|plans|price|prices|pricing|subscribe|subscription|premium|upgrade|checkout)\b/i);
});
