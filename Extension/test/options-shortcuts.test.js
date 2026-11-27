// Options, Keyboard shortcuts (Chromium), and the helpers in src/shared/shortcuts.js. Firefox's in-page recording:
// options-shortcuts-firefox.test.js.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { COMMAND_ORDER, commandLabel, shortcutFromKeyEvent, shortcutsPageUrl, sortCommands } from '../src/shared/shortcuts.js';

const created = [];
let commands = [];

const flush = async (n = 6) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };

function setNavigator(nav) {
  Object.defineProperty(globalThis, 'navigator', { value: nav, configurable: true, writable: true });
}

async function openOptions() {
  const html = readFileSync(new URL('../src/options/options.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/src/options/options.html', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  created.length = 0;
  await import(`../src/options/options.js?instance=${openOptions.n = (openOptions.n || 0) + 1}`);
  await flush();
  const document = dom.window.document;
  return { window: dom.window, document, $: (id) => document.getElementById(id) };
}

const rows = (document) => [...document.querySelectorAll('#shortcuts li')].map((li) => [
  li.dataset.command, li.querySelector('.shortcut-name').textContent, li.querySelector('kbd, .not-set').textContent, !!li.querySelector('kbd')]);

// As Chrome reports them: the manifest's order, `_execute_action` without a description, unset keys ''.
const CHROME_COMMANDS = [
  { name: '_execute_action', description: '', shortcut: 'Alt+Shift+P' },
  { name: 'fill-login', description: 'Fill the login for this site', shortcut: 'Ctrl+Shift+L' },
  { name: 'fill-otp', description: 'Fill or show the 2FA code for this site', shortcut: 'Alt+Shift+K' },
  { name: 'generate-password', description: 'Generate a password', shortcut: '' },
  { name: 'lock', description: 'Lock Passyble', shortcut: 'Ctrl+Shift+9' },
  { name: 'new-note', description: 'New secure note' },
  { name: 'sync-now', description: 'Sync your vaults now', shortcut: '' },
  { name: 'scan-qr', description: 'Scan a 2FA QR code on this page', shortcut: 'Alt+Shift+Q' },
];

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async () => ({ ok: true, result: null }),
      onMessage: { addListener: () => {} },
      getManifest: () => ({ version: '1.2.3' }),
    },
    storage: {
      local: { get: async () => ({}), set: async () => {} },
      sync: { get: async () => ({}), set: async () => {} },
    },
    tabs: { create: async (opts) => { created.push(opts); } },
    commands: { getAll: async () => commands },
  };
});

test('every command with its key or "Not set", in Options\' order; Change shortcuts opens chrome://extensions/shortcuts', async () => {
  setNavigator({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36', platform: 'Win32' });
  commands = CHROME_COMMANDS;
  const { document, $ } = await openOptions();
  assert.equal($('h-shortcuts').textContent, 'Keyboard shortcuts');
  assert.deepEqual(rows(document), [
    ['_execute_action', 'Open Passyble and search', 'Alt+Shift+P', true],
    ['fill-login', 'Fill login', 'Ctrl+Shift+L', true],
    ['fill-otp', 'Fill or show 2FA code', 'Alt+Shift+K', true],
    ['scan-qr', 'Scan QR code', 'Alt+Shift+Q', true],
    ['generate-password', 'Generate password', 'Not set', false],
    ['new-note', 'New secure note', 'Not set', false],
    ['lock', 'Lock', 'Ctrl+Shift+9', true],
    ['sync-now', 'Sync now', 'Not set', false],
  ]);
  for (const li of document.querySelectorAll('#shortcuts li')) assert.ok(li.querySelector('.row-icon svg'), 'the keyboard icon');
  assert.equal(document.querySelectorAll('#shortcuts button').length, 0, 'Chromium: no recording in the page');
  const change = $('shortcut-change');
  assert.equal(change.hidden, false);
  change.click();
  await flush();
  assert.deepEqual(created, [{ url: 'chrome://extensions/shortcuts' }]);
});

test('Edge: Change shortcuts opens edge://extensions/shortcuts (by its brands, or its user agent)', async () => {
  commands = CHROME_COMMANDS;
  setNavigator({ userAgentData: { brands: [{ brand: 'Chromium', version: '131' }, { brand: 'Microsoft Edge', version: '131' }] }, userAgent: '' });
  let page = await openOptions();
  page.$('shortcut-change').click();
  await flush();
  assert.deepEqual(created, [{ url: 'edge://extensions/shortcuts' }]);
  setNavigator({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36 Edg/131.0.0.0' });
  page = await openOptions();
  page.$('shortcut-change').click();
  await flush();
  assert.deepEqual(created, [{ url: 'edge://extensions/shortcuts' }]);
});

test('a command Options doesn\'t know shows its description, after the known ones; no commands API: an empty list', async () => {
  setNavigator({ userAgent: 'Chrome/131' });
  commands = [{ name: 'future-thing', description: 'Something new', shortcut: '' }, { name: 'fill-login', shortcut: 'Ctrl+Shift+L' }];
  const { document } = await openOptions();
  assert.deepEqual(rows(document).map((r) => r.slice(0, 3)), [['fill-login', 'Fill login', 'Ctrl+Shift+L'], ['future-thing', 'Something new', 'Not set']]);
  commands = Promise.reject(new Error('no commands API'));
  commands.catch(() => {});
  const empty = await openOptions();
  assert.equal(empty.document.querySelectorAll('#shortcuts li').length, 0);
});

test('shortcuts.js: labels for every command, the order, and the shortcuts page', () => {
  for (const name of COMMAND_ORDER) assert.ok(commandLabel(name), name);
  assert.equal(commandLabel('nope'), '');
  assert.deepEqual(sortCommands([{ name: 'lock' }, { name: 'zz', description: 'Z' }, null, { name: '' }, { name: '_execute_action', shortcut: 'Alt+Shift+P' }]),
    [{ name: '_execute_action', label: 'Open Passyble and search', shortcut: 'Alt+Shift+P' }, { name: 'lock', label: 'Lock', shortcut: '' },
      { name: 'zz', label: 'Z', shortcut: '' }]);
  assert.deepEqual(sortCommands(undefined), []);
  assert.equal(shortcutsPageUrl({ gecko: true, nav: {} }), null, 'Firefox: none to open');
  assert.equal(shortcutsPageUrl({ nav: { userAgent: 'Chrome/131' } }), 'chrome://extensions/shortcuts');
  assert.equal(shortcutsPageUrl({ nav: { userAgent: 'Chrome/131 OPR/115' } }), 'chrome://extensions/shortcuts', 'Opera and Brave redirect it');
  assert.equal(shortcutsPageUrl({ nav: { userAgent: 'Chrome/131 Edg/131' } }), 'edge://extensions/shortcuts');
});

test('shortcutFromKeyEvent: Firefox\'s shortcut text, and what Firefox refuses', () => {
  const key = (code, mods = {}, keyName = 'x') => ({ code, key: keyName, ctrlKey: false, altKey: false, shiftKey: false, metaKey: false, ...mods });
  assert.deepEqual(shortcutFromKeyEvent(key('KeyQ', { altKey: true, shiftKey: true })), { shortcut: 'Alt+Shift+Q' });
  assert.deepEqual(shortcutFromKeyEvent(key('Digit5', { ctrlKey: true, shiftKey: true })), { shortcut: 'Ctrl+Shift+5' });
  assert.deepEqual(shortcutFromKeyEvent(key('ArrowUp', { ctrlKey: true, altKey: true })), { shortcut: 'Ctrl+Alt+Up' });
  assert.deepEqual(shortcutFromKeyEvent(key('Comma', { ctrlKey: true })), { shortcut: 'Ctrl+Comma' });
  assert.deepEqual(shortcutFromKeyEvent(key('F7')), { shortcut: 'F7' }, 'a function key alone');
  assert.deepEqual(shortcutFromKeyEvent(key('F7', { shiftKey: true })), { error: 'modifier' });
  assert.deepEqual(shortcutFromKeyEvent(key('KeyQ', { shiftKey: true })), { error: 'modifier' }, 'Shift alone is not enough');
  assert.deepEqual(shortcutFromKeyEvent(key('KeyQ')), { error: 'modifier' });
  assert.deepEqual(shortcutFromKeyEvent(key('KeyQ', { ctrlKey: true, altKey: true, shiftKey: true })), { error: 'modifier' }, 'two modifiers at most');
  assert.deepEqual(shortcutFromKeyEvent(key('Backquote', { ctrlKey: true })), { error: 'key' });
  assert.deepEqual(shortcutFromKeyEvent(key('ShiftLeft', { shiftKey: true }, 'Shift')), { shortcut: '' }, 'only a modifier so far');
  assert.deepEqual(shortcutFromKeyEvent(key('ControlLeft', { ctrlKey: true }, 'Control')), { shortcut: '' });
  // macOS: Command is "Command", Control is "MacCtrl", Option is "Alt".
  assert.deepEqual(shortcutFromKeyEvent(key('KeyQ', { metaKey: true, shiftKey: true }), { mac: true }), { shortcut: 'Command+Shift+Q' });
  assert.deepEqual(shortcutFromKeyEvent(key('KeyQ', { ctrlKey: true, shiftKey: true }), { mac: true }), { shortcut: 'MacCtrl+Shift+Q' });
  assert.deepEqual(shortcutFromKeyEvent(key('KeyP', { altKey: true, ctrlKey: true }), { mac: true }), { shortcut: 'MacCtrl+Alt+P' });
  assert.deepEqual(shortcutFromKeyEvent(key('KeyQ', { metaKey: true })), { error: 'modifier' }, 'the Windows key is no modifier for Firefox');
});
