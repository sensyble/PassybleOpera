// Setup guide in Firefox. A file of its own: src/shared/api.js decides isGecko once, when it is
// first imported.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

let permissions = null;
let instance = 0;
const flush = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => { for (let i = 0; i < 6; i++) await flush(); };

before(() => {
  globalThis.browser = {
    runtime: {
      id: 'pass-ext',
      getBrowserInfo: async () => ({ name: 'Firefox', version: '130.0' }),
      sendMessage: async (msg) => (msg.type === 'popup.status' ? { ok: true, result: { locked: false } } : { ok: true, result: null }),
      onMessage: { addListener: () => {} },
      getManifest: () => ({ version: '1.2.3', host_permissions: ['<all_urls>'] }),
      getURL: (p) => `moz-extension://pass-ext/${p}`,
    },
    tabs: { create: async () => {} },
    storage: { local: { get: async () => ({ guidePinned: true }), set: async () => {} } },
    commands: { getAll: async () => [] },
    action: {},
  };
  // The page polls every few seconds: never run those timers here.
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (fn, ms, ...args) => (ms >= 1000 ? { unref() {} } : realSetTimeout(fn, ms, ...args));
});

async function openWelcome() {
  const html = readFileSync(new URL('../src/welcome/welcome.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/src/welcome/welcome.html', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.browser.permissions = permissions ?? undefined;
  const mod = await import(`../src/welcome/welcome.js?instance=${++instance}`);
  await settle();
  return { $: (id) => dom.window.document.getElementById(id), mod };
}

test('Firefox: declined website access points to about:addons, in Firefox\'s words', async () => {
  permissions = { contains: async () => false, request: () => Promise.resolve(false), onAdded: { addListener: () => {} } };
  const { $, mod } = await openWelcome();
  assert.equal(mod.browserKind(), 'firefox');
  assert.equal($('step-access').hidden, false, 'Firefox asks for website access');
  $('allow-access').click();
  await settle();
  assert.equal($('access-msg').textContent,
    'Not allowed. Turn it on in about:addons → Passyble → Permissions.');
  assert.doesNotMatch($('access-msg').textContent, /chrome:\/\/|edge:\/\/|brave:\/\//);
  assert.match($('pin-how').textContent, /gear next to Passyble → Pin to Toolbar/);
});
