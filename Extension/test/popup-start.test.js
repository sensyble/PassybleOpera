import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
const created = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const NOT_RUNNING = { ok: false, error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } };
const HOST_MISSING = { ok: false, error: { code: 'agent_unavailable', message: 'Specified native messaging host not found.' } };

/** Loads a fresh popup (new DOM, new module instance). */
async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }], create: async (o) => { created.push(o); } },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('Passyble not running: friendly view with a Start Passyble button; starting reloads into the vault state', async () => {
  let started = false;
  reply = (msg) => {
    if (msg.type === 'popup.start') { started = true; return { ok: true, result: { version: '1.0.0', locked: true } }; }
    if (msg.type === 'popup.state') return started ? { ok: true, result: { url: 'https://github.com/login', supported: true, locked: true } } : NOT_RUNNING;
    return { ok: true, result: null };
  };
  const { $ } = await openPopup();
  assert.equal($('view-offline').hidden, false);
  assert.equal($('offline-title').textContent, "Passyble isn't running");
  assert.equal($('start').hidden, false);
  assert.equal($('retry').hidden, true);
  assert.equal($('lock-btn').hidden, true, 'no state in the header: the card says it');
  assert.equal($('offline-text').textContent, 'Start the Passyble app on this computer to fill your logins here.');

  $('start').click();
  assert.equal($('start').disabled, true, 'busy while the host starts Passyble');
  assert.equal($('start').textContent.trim(), 'Starting Passyble…');
  await flush();
  await flush();
  assert.ok(messages.some((m) => m.type === 'popup.start'));
  assert.equal($('view-locked').hidden, false, 'reloaded: Passyble is up (and locked)');
  assert.equal($('lock-btn').hidden, true, 'the locked view: the card says it, no lock in the header');
  const before = messages.filter((m) => m.type === 'popup.unlock').length;
  $('unlock').click();
  assert.equal(messages.filter((m) => m.type === 'popup.unlock').length, before + 1, 'the lock icon starts the unlock flow');
  assert.equal($('start').disabled, false);
  assert.equal($('start').textContent.trim(), 'Start Passyble');
});

test('Start Passyble that does not get Passyble up shows what to do instead', async () => {
  reply = (msg) => (msg.type === 'popup.start' || msg.type === 'popup.state' ? NOT_RUNNING : { ok: true, result: null });
  const { $ } = await openPopup();
  $('start').click();
  await flush();
  await flush();
  assert.equal($('view-offline').hidden, false);
  assert.equal($('start-msg').textContent,
    "Open Passyble from the Start menu.");
  assert.equal($('start').disabled, false);
});

test('host not registered: no Start button (it cannot help), the fix, and Try again', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? HOST_MISSING : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('view-offline').hidden, false);
  assert.equal($('offline-title').textContent, "Passyble can't be reached");
  assert.match($('offline-text').textContent, /^Check Passyble → Settings → Autofill/, 'what to do, not the heading again');
  assert.equal($('start').hidden, true);
  assert.equal($('retry').hidden, false);
  assert.equal($('offline-icon').querySelector('svg').getAttribute('data-icon'), 'alert');
  assert.ok($('retry').classList.contains('primary'), 'Try again is the one filled button');
  messages.length = 0;
  $('retry').click();
  await flush();
  // The update check's decision first (forced updates), then the state.
  assert.deepEqual(messages.map((m) => m.type), ['update.state', 'popup.state']);
});

test('Start Passyble that finds no host registration switches to that view', async () => {
  reply = (msg) => (msg.type === 'popup.start' ? HOST_MISSING : msg.type === 'popup.state' ? NOT_RUNNING : { ok: true, result: null });
  const { $ } = await openPopup();
  $('start').click();
  await flush();
  await flush();
  assert.equal($('offline-title').textContent, "Passyble can't be reached");
  assert.equal($('start').hidden, true);
});

test('a timeout (Passyble busy with a prompt) is not "not running": no offline view, no Start button', async () => {
  reply = (msg) => (msg.type === 'popup.state'
    ? { ok: false, error: { code: 'timeout', message: 'Passyble did not answer "logins.find" in time' } }
    : { ok: true, result: null });
  const { $ } = await openPopup();
  assert.equal($('view-offline').hidden, true);
  assert.equal($('start').hidden || $('view-offline').hidden, true);
  assert.match($('view-list').textContent, /Passyble didn't answer\. Check for an open Passyble window\./);
  assert.ok(!messages.some((m) => m.type === 'popup.start'));
});

test('icons: every placeholder is filled with a stroke icon; buttons have tooltips', async () => {
  reply = (msg) => (msg.type === 'popup.state'
    ? { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null,
      items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false }] } }
    : { ok: true, result: null });
  const { window, $ } = await openPopup();
  const placeholders = [...window.document.querySelectorAll('[data-icon]:not(svg)')];
  assert.ok(placeholders.length >= 10);
  for (const el of placeholders) {
    const svg = el.querySelector(':scope > svg');
    assert.ok(svg, el.id || el.className);
    assert.equal(svg.getAttribute('stroke'), 'currentColor');
    assert.equal(svg.getAttribute('fill'), 'none');
  }
  assert.equal($('menu-btn').title, 'More');
  assert.equal($('server-back').title, 'Back (Esc)');
  // The header: the wordmark, the vault switcher (hidden with one vault), Sync now, the lock (its icon is the state,
  // no dot) and one ⋯ button (no site name, no row of buttons).
  assert.deepEqual([...window.document.querySelectorAll('.top > *')].map((n) => n.id || n.className), ['logo', 'vault-switch', 'sync-btn', 'lock-btn', 'menu-btn']);
  assert.equal($('vault-switch').hidden, true);
  assert.equal($('sync-btn').title, 'Sync now');
  assert.equal($('sync-btn').getAttribute('aria-label'), 'Sync now');
  assert.ok($('sync-btn').querySelector('svg[data-icon="sync"]'), 'refresh icon');
  assert.equal($('lock-btn').title, 'Lock Passyble');
  assert.ok($('lock-btn').querySelector('svg[data-icon="lockOpen"]'), 'unlocked: the open lock');
  assert.ok($('logo').querySelector('svg.pass-logo'), 'the Passyble wordmark (its note)');
  assert.equal($('logo').getAttribute('aria-label'), 'Passyble');
  assert.equal($('status'), null, 'no state dot');
  $('menu-btn').click();
  const items = [...window.document.querySelectorAll('.popover .menu-item')];
  // The quick actions this state allows first (an app without editing or notes: Generate only).
  assert.deepEqual(items.map((b) => [b.textContent, b.querySelector('svg').getAttribute('data-icon')]),
    [['Generate a strong password', 'dice'], ['Settings', 'gear'], ['Setup guide', 'info'], ['Help and support', 'link'], ['Add Passyble Server', 'server']]);
  assert.equal(window.document.querySelectorAll('.popover .menu-sep').length, 2);
  $('menu-btn').click();
  assert.equal(window.document.querySelector('.popover'), null, 'the ⋯ button toggles the menu');
  // A row: one click fills; copy username / password and ⋯ on hover or focus.
  const row = $('list').querySelector('.item');
  assert.equal(row.querySelector('.item-main').title, 'Fill on this page');
  assert.equal(row.querySelector('.item-main').getAttribute('aria-label'), 'Fill GitHub');
  const actions = [...row.querySelectorAll('.actions .icon-btn')];
  assert.deepEqual(actions.map((b) => b.title), ['Copy username', 'Copy password', 'More']);
  assert.deepEqual(actions.map((b) => b.querySelector('svg').getAttribute('data-icon')), ['user', 'key', 'more']);
  actions[2].click();
  assert.deepEqual([...window.document.querySelectorAll('.popover .menu-item')].map((b) => b.textContent), ['Edit', 'Open in Passyble']);
  assert.equal(row.querySelector('.otp'), null, 'no 2FA: no code pill');
});

test('a page Passyble cannot fill: one line and "Search vault", which searches the whole vault', async () => {
  const messagesOf = (type) => messages.filter((m) => m.type === type);
  reply = (msg) => {
    if (msg.type === 'popup.state') return { ok: true, result: { url: 'chrome://extensions/', supported: false } };
    if (msg.type === 'popup.search') return { ok: true, result: { items: [{ id: 'gl', title: 'GitLab', username: 'me', domain: 'gitlab.com', has_totp: true }] } };
    return { ok: true, result: null };
  };
  const { window, $ } = await openPopup();
  assert.equal($('empty-state').hidden, false);
  assert.equal($('empty').textContent, 'No login form on this page');
  assert.equal($('search').closest('.search-row').hidden, true);
  assert.equal($('add-login').hidden, true);
  assert.equal($('lock-btn').hidden, true);
  assert.ok(!/extension|http/i.test(window.document.querySelector('.top').textContent), 'no page address or id in the header');
  $('search-vault').click();
  assert.equal($('empty-state').hidden, true);
  assert.equal($('search').closest('.search-row').hidden, false);
  $('search').value = 'git';
  $('search').dispatchEvent(new window.Event('input'));
  await new Promise((r) => setTimeout(r, 320));
  await flush();
  assert.deepEqual(messagesOf('popup.search'), [{ type: 'popup.search', query: 'git' }]);
  const row = $('result-list').querySelector('.item');
  assert.equal(row.querySelector('.item-main').title, 'Copy password', 'nothing to fill: the row copies (by the desktop app)');
  row.querySelector('.item-main').click();
  await flush();
  assert.deepEqual(messagesOf('popup.copy-item'), [{ type: 'popup.copy-item', tabId: 1, id: 'gl', field: 'password' }]);
});

test('a login with 2FA: the code is a compact pill under the username, copied on click', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.state') {
      return { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null,
        items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }] } };
    }
    if (msg.type === 'popup.totp') return { ok: true, result: { code: '123456', period: 30, remaining_secs: 20 } };
    return { ok: true, result: null };
  };
  const { $ } = await openPopup();
  await flush();
  const pill = $('list').querySelector('.item .otp');
  assert.ok(pill);
  assert.equal(pill.querySelector('.code .digits').textContent, '123 456');
  assert.equal(pill.querySelector('.code .mask').textContent, '2FA', 'at rest "2FA"; the digits on hover or focus');
  assert.equal(pill.getAttribute('aria-label'), '2FA code, click to copy');
});

test('"Made by Sensyble" is a small caption under Quick settings, which opens sensyble.net in a new tab', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? NOT_RUNNING : { ok: true, result: null });
  const { $ } = await openPopup();
  created.length = 0;
  assert.ok($('view-quick').contains($('sensyble')), 'in Quick settings, not in the menu');
  assert.equal($('sensyble').textContent, 'Made by Sensyble');
  $('sensyble').click();
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(created, [{ url: 'https://www.sensyble.net' }]);
});

test('Esc leaves "Add Passyble Server"; no password generator in the popup', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? NOT_RUNNING : { ok: true, result: null });
  const { window, $ } = await openPopup();
  $('menu-btn').click();
  $('add-server').click();
  assert.equal($('view-server').hidden, false);
  window.document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  await flush();
  assert.equal($('view-server').hidden, true);
  for (const id of ['gen', 'generate', 'length', 'gen-out']) assert.equal($(id), null, id);
  assert.ok(!messages.some((m) => m.type === 'popup.generate'));
});

test('2FA pill: "2FA" by default (digits only on hover / focus via CSS), click copies the real code (older desktop app)', async () => {
  const copied = [];
  Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText: async (t) => { copied.push(t); } } }, configurable: true });
  reply = (msg) => {
    if (msg.type === 'popup.state') {
      return { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null,
        items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }] } };
    }
    if (msg.type === 'popup.copy-item') return { ok: false, error: { code: 'not_supported', message: 'unknown method' } };
    if (msg.type === 'popup.totp') return { ok: true, result: { code: '123456', period: 30, remaining_secs: 20 } };
    return { ok: true, result: null };
  };
  const { window, $ } = await openPopup();
  await flush();
  const pill = $('list').querySelector('.otp');
  assert.ok(pill, '2FA pill');
  assert.equal(pill.getAttribute('aria-label'), '2FA code, click to copy');
  const code = pill.querySelector('.code');
  assert.equal(code.querySelector('.mask').textContent, '2FA', 'at rest: "2FA", no digits');
  assert.equal(code.querySelector('.digits').textContent, '123 456', 'digits layer exists for hover');
  assert.ok(!pill.getAttribute('aria-label').includes('123'), 'no digits in the accessible name');
  assert.equal(code.querySelector('.digits').getAttribute('aria-hidden'), 'true');
  const css = readFileSync(new URL('../src/popup/popup.css', import.meta.url), 'utf8');
  assert.match(css, /\.otp \.code \.digits \{ visibility: hidden; \}/, 'digits hidden by default');
  assert.match(css, /\.otp:is\(:hover, :focus-visible\) \.code \.digits \{ visibility: visible; \}/, 'digits shown on hover / focus');
  pill.click();
  await flush();
  assert.deepEqual(copied, ['123456']);
  assert.ok(window.document.querySelector('.otp .code .digits'), 'still the same markup after copy');
});

test('2FA pill and the pending code: the desktop app copies them; a pending code of another site is copied here', async () => {
  const copied = [];
  Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText: async (t) => { copied.push(t); } } }, configurable: true });
  reply = (msg) => {
    if (msg.type === 'popup.state') {
      return { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, pending_otp: { id: 'sso', title: 'SSO' },
        items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }] } };
    }
    if (msg.type === 'popup.copy-item') {
      return msg.id === 'sso'
        ? { ok: false, error: { code: 'url_mismatch', message: 'item does not belong to this site' } }
        : { ok: true, result: { copied: true, field: msg.field } };
    }
    if (msg.type === 'popup.totp') return { ok: true, result: { code: msg.id ? '123456' : '654321', period: 30, remaining_secs: 20 } };
    return { ok: true, result: null };
  };
  const { $ } = await openPopup();
  await flush();
  const pills = [...$('list').querySelectorAll('.otp')];
  assert.equal(pills.length, 2, 'the pending code and the login');
  const [pending, own] = pills;
  own.click();
  await flush();
  await flush();
  assert.deepEqual(copied, [], 'the desktop app copied it');
  assert.deepEqual(messages.filter((m) => m.type === 'popup.copy-item').at(-1), { type: 'popup.copy-item', tabId: 1, id: 'gh', field: 'totp', own: true });
  assert.ok(!messages.some((m) => m.type === 'clipboard.copied'));
  pending.click();
  await flush();
  await flush();
  assert.deepEqual(copied, ['654321'], "url_mismatch: the pending code (the tab's own) is copied here");
});

test('offline (not installed, not running or no vault yet): "Setup guide" opens the welcome page', async () => {
  for (const state of [NOT_RUNNING, HOST_MISSING]) {
    reply = (msg) => (msg.type === 'popup.state' ? state : { ok: true, result: null });
    const { $ } = await openPopup();
    assert.equal($('view-offline').hidden, false);
    assert.equal($('setup-guide').hidden, false);
    assert.equal($('setup-guide').textContent.trim(), 'Setup guide');
    assert.ok($('setup-guide').classList.contains('text-link'), 'a plain text link, no icon');
    created.length = 0;
    $('setup-guide').click();
    await flush();
    assert.deepEqual(created, [{ url: 'chrome-extension://pass-ext/src/welcome/welcome.html' }]);
  }
});

test('the ⋯ menu item "Setup guide and tips" opens the welcome page at its how-to cards', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? NOT_RUNNING : { ok: true, result: null });
  const { window, $ } = await openPopup();
  created.length = 0;
  $('menu-btn').click();
  $('help').click();
  await flush();
  assert.deepEqual(created, [{ url: 'chrome-extension://pass-ext/src/welcome/welcome.html' }]);
  assert.equal(window.document.querySelector('.popover'), null, 'the menu closed');
});
