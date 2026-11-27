// Options, Keyboard shortcuts in Firefox: Firefox has no shortcuts page an extension may open, so each row records
// its keys here (`commands.update`). Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const DEFAULTS = { _execute_action: 'Alt+Shift+P', 'fill-login': 'Ctrl+Shift+L', 'fill-otp': 'Alt+Shift+K', 'scan-qr': 'Alt+Shift+Q',
  'generate-password': '', 'new-note': '', lock: '', 'sync-now': '' };
let bound = {};
const updates = [];
const resets = [];
let refuse = false;

const flush = async (n = 6) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };

async function openOptions() {
  const html = readFileSync(new URL('../src/options/options.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'moz-extension://pass/src/options/options.html', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  await import(`../src/options/options.js?instance=${openOptions.n = (openOptions.n || 0) + 1}`);
  await flush();
  const document = dom.window.document;
  const row = (name) => document.querySelector(`#shortcuts li[data-command="${name}"]`);
  const keyText = (name) => row(name).querySelector('kbd, .not-set, .recording').textContent;
  const press = (code, mods = {}, key = code.replace(/^Key/, '').toLowerCase()) => {
    document.dispatchEvent(new dom.window.KeyboardEvent('keydown', { code, key, bubbles: true, cancelable: true, ...mods }));
  };
  return { window: dom.window, document, $: (id) => document.getElementById(id), row, keyText, press };
}

before(() => {
  Object.defineProperty(globalThis, 'navigator', { value: { userAgent: 'Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0', platform: 'Win32' }, configurable: true, writable: true });
  globalThis.browser = {
    runtime: {
      id: 'pass@sensyble.com',
      getBrowserInfo: async () => ({ name: 'Firefox', version: '140.0' }),
      sendMessage: async () => ({ ok: true, result: null }),
      onMessage: { addListener: () => {} },
      getManifest: () => ({ version: '1.2.3' }),
    },
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      sync: { get: async () => ({}), set: async () => {} },
    },
    tabs: { create: async () => { throw new Error('Firefox: no shortcuts page to open'); } },
    commands: {
      getAll: async () => Object.keys(DEFAULTS).map((name) => ({ name, description: name, shortcut: name in bound ? bound[name] : DEFAULTS[name] })),
      update: async ({ name, shortcut }) => {
        updates.push({ name, shortcut });
        if (refuse) throw new Error('Shortcut in use');
        bound[name] = shortcut;
      },
      reset: async (name) => { resets.push(name); delete bound[name]; },
    },
  };
});

test('Firefox: each row has Change and Reset, the help says how; no browser page to open', async () => {
  bound = {};
  const { $, document, row } = await openOptions();
  assert.equal($('shortcut-change').hidden, true);
  assert.equal($('shortcut-help-text').textContent, 'Click Change, then press the new keys. Esc cancels, Backspace removes the shortcut.');
  assert.equal(document.querySelectorAll('#shortcuts li').length, 8);
  const change = row('scan-qr').querySelector('.shortcut-record');
  assert.equal(change.textContent, 'Change');
  assert.equal(change.getAttribute('aria-label'), 'Change the shortcut for Scan QR code');
  assert.equal(row('scan-qr').querySelector('.shortcut-reset').getAttribute('aria-label'), 'Reset the shortcut for Scan QR code');
});

test('Firefox: Change, then the keys: saved with commands.update and shown; Shift alone or a bad key says why and keeps listening', async () => {
  bound = {};
  updates.length = 0;
  const { $, row, keyText, press } = await openOptions();
  row('generate-password').querySelector('.shortcut-record').click();
  assert.equal(keyText('generate-password'), 'Press the new keys');
  assert.equal(row('generate-password').querySelector('.shortcut-record').getAttribute('aria-pressed'), 'true');
  press('ShiftLeft', { shiftKey: true }, 'Shift');
  assert.equal(updates.length, 0, 'only a modifier so far');
  press('KeyG', { shiftKey: true });
  assert.match($('shortcut-msg').textContent, /^Hold Ctrl or Alt/);
  press('Backquote', { altKey: true }, '`');
  assert.match($('shortcut-msg').textContent, /^That key can't be used/);
  assert.equal(updates.length, 0);
  press('KeyG', { altKey: true, shiftKey: true });
  await flush();
  assert.deepEqual(updates, [{ name: 'generate-password', shortcut: 'Alt+Shift+G' }]);
  assert.equal(keyText('generate-password'), 'Alt+Shift+G');
  assert.equal($('shortcut-msg').textContent, '');
  // Recording ended: keys go to the page as usual.
  press('KeyH', { altKey: true, shiftKey: true });
  await flush();
  assert.equal(updates.length, 1);
});

test('Firefox: Esc cancels, Backspace removes the shortcut, Reset puts the manifest\'s key back', async () => {
  bound = {};
  updates.length = 0;
  resets.length = 0;
  const { row, keyText, press } = await openOptions();
  row('scan-qr').querySelector('.shortcut-record').click();
  press('Escape', {}, 'Escape');
  assert.equal(keyText('scan-qr'), 'Alt+Shift+Q');
  assert.equal(updates.length, 0);

  row('scan-qr').querySelector('.shortcut-record').click();
  press('Backspace', {}, 'Backspace');
  await flush();
  assert.deepEqual(updates, [{ name: 'scan-qr', shortcut: '' }]);
  assert.equal(keyText('scan-qr'), 'Not set');

  row('scan-qr').querySelector('.shortcut-reset').click();
  await flush();
  assert.deepEqual(resets, ['scan-qr']);
  assert.equal(keyText('scan-qr'), 'Alt+Shift+Q');
});

test('Firefox: a shortcut Firefox refuses (in use) says so and keeps the old one', async () => {
  bound = {};
  updates.length = 0;
  refuse = true;
  const { $, row, keyText, press } = await openOptions();
  row('lock').querySelector('.shortcut-record').click();
  press('KeyL', { ctrlKey: true, shiftKey: true });
  await flush();
  refuse = false;
  assert.deepEqual(updates, [{ name: 'lock', shortcut: 'Ctrl+Shift+L' }]);
  assert.equal($('shortcut-msg').textContent, 'Firefox didn\'t accept that shortcut. It may already be in use.');
  assert.equal(keyText('lock'), 'Not set');
});

test('Firefox without commands.update: no recording, the help says where Firefox changes them', async () => {
  const { update } = globalThis.browser.commands;
  delete globalThis.browser.commands.update;
  try {
    // isGecko and the commands API are read as options.js loads.
    const { $, document } = await openOptions();
    assert.equal(document.querySelectorAll('#shortcuts button').length, 0);
    assert.match($('shortcut-help-text').textContent, /about:addons/);
  } finally {
    globalThis.browser.commands.update = update;
  }
});
