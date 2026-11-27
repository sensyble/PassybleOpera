import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

let instance = 0;
let optionsOpened = 0;
const local = {};
const sync = {};

const flush = () => new Promise((r) => setTimeout(r, 0));
const area = (store) => ({
  get: async (keys) => Object.fromEntries((Array.isArray(keys) ? keys : Object.keys(store)).filter((k) => k in store).map((k) => [k, store[k]])),
  set: async (obj) => { Object.assign(store, obj); },
});

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  return { window: dom.window, $: (id) => dom.window.document.getElementById(id) };
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async () => ({ ok: false, error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } }),
      onMessage: { addListener: () => {} },
      openOptionsPage: () => { optionsOpened++; },
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }], create: async () => {} },
    storage: { local: area(local), sync: area(sync) },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('Settings opens Quick settings with the common toggles, saved at once', async () => {
  local.saveBanner = false;
  const { window, $ } = await openPopup();
  $('menu-btn').click();
  $('options').click();
  await flush();
  assert.equal($('view-quick').hidden, false);
  const inputs = [...$('quick-list').querySelectorAll('input[data-key]')];
  assert.deepEqual(inputs.map((i) => i.dataset.key), ['inlineMenu', 'autoSuggest', 'autoGenerate', 'autoFillOtp', 'saveBanner']);
  assert.deepEqual(inputs.map((i) => i.checked), [true, true, true, true, false], 'stored values, defaults otherwise');
  for (const input of inputs) {
    const label = window.document.querySelector(`label[for="${input.id}"].qrow-name`);
    assert.ok(label && label.textContent.trim(), `${input.dataset.key} has a label`);
  }
  assert.equal(window.document.activeElement, inputs[0], 'keyboard focus starts on the first switch');

  // Same storage as the options page: autoSuggest syncs, saveBanner is local.
  const suggest = $('q-autoSuggest');
  suggest.checked = false;
  suggest.dispatchEvent(new window.Event('change', { bubbles: true }));
  const banner = $('q-saveBanner');
  banner.checked = true;
  banner.dispatchEvent(new window.Event('change', { bubbles: true }));
  await flush();
  assert.equal(sync.autoSuggest, false);
  assert.equal(local.saveBanner, true);
});

test('More settings opens the options page; the back arrow and Esc return to the list', async () => {
  const { window, $ } = await openPopup();
  $('menu-btn').click();
  $('options').click();
  await flush();
  optionsOpened = 0;
  $('quick-more').click();
  assert.equal(optionsOpened, 1);

  $('quick-back').click();
  await flush();
  assert.equal($('view-quick').hidden, true, 'back leaves quick settings');

  $('menu-btn').click();
  $('options').click();
  await flush();
  assert.equal($('view-quick').hidden, false);
  window.document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  await flush();
  assert.equal($('view-quick').hidden, true, 'Esc goes back');
});
