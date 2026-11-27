import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const PNG = 'data:image/png;base64,iVBORw0KGgo=';
const ITEMS = [
  { id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false },
  { id: 'gh2', title: 'Work', username: 'me', has_totp: false, has_passkey: false },
];

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

function state(extra = {}) {
  return { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, items: ITEMS, pending_otp: null, can_edit: true, ...extra } };
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
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('cached icons replace the letter for logins that have one', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.state') return state({ can_icons: true });
    if (msg.type === 'popup.icons') {
      // Not a PNG data URL: ignored, whatever the agent says.
      return { ok: true, result: { icons: { 'github.com': PNG, 'evil.com': 'https://evil.com/x.png' }, items: { gh: 'github.com', gh2: 'evil.com' } } };
    }
    return { ok: true, result: null };
  };
  const { $ } = await openPopup();
  const call = messages.find((m) => m.type === 'popup.icons');
  assert.deepEqual(call, { type: 'popup.icons', tabId: 1 }, 'the tab, never a URL from the popup');
  const [first, second] = $('list').querySelectorAll('.avatar');
  assert.ok(first.classList.contains('site-icon'));
  assert.equal(first.querySelector('img').getAttribute('src'), PNG);
  assert.equal(first.querySelector('img').getAttribute('alt'), '');
  assert.equal(second.textContent, 'W');
  assert.equal(second.querySelector('img'), null);

  first.querySelector('img').dispatchEvent(new globalThis.Event('error'));
  assert.equal(first.textContent, 'G');
  assert.ok(!first.classList.contains('site-icon'));
});

test('an older desktop app (no icons.get) or an error keeps the letters', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? state() : { ok: true, result: null });
  let { $ } = await openPopup();
  assert.ok(!messages.some((m) => m.type === 'popup.icons'), 'not advertised: not asked');
  assert.deepEqual([...$('list').querySelectorAll('.avatar')].map((a) => a.textContent), ['G', 'W']);

  reply = (msg) => {
    if (msg.type === 'popup.state') return state({ can_icons: true });
    if (msg.type === 'popup.icons') return { ok: false, error: { code: 'invalid_params', message: 'unknown method icons.get' } };
    return { ok: true, result: null };
  };
  ({ $ } = await openPopup());
  assert.ok(messages.some((m) => m.type === 'popup.icons'));
  assert.deepEqual([...$('list').querySelectorAll('.avatar')].map((a) => a.textContent), ['G', 'W']);
});
