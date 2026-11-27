import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const LINK = 'pass+server://pass.example.com/dav/alice/personal.vault?v=1&user=alice&token=pst_t0k3n&name=Laptop';
const messages = [];
let reply = () => ({ ok: true, result: null });

function page(rel) {
  const html = readFileSync(new URL(`../src/${rel}`, import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  return dom.window;
}

const flush = () => new Promise((r) => setTimeout(r, 0));

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
    commands: { getAll: async () => [] },
  };
  // popup.js ticks TOTP rings every second; keep the test process from hanging on it.
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('popup: the header button opens "Add Passyble Server" and Send reaches the background', async () => {
  reply = (msg) => (msg.type === 'popup.state'
    ? { ok: false, error: { code: 'agent_unavailable', message: 'not running' } }
    : { ok: true, result: { shown: true, host: 'pass.example.com', user: 'alice' } });
  const window = page('popup/popup.html');
  const $ = (id) => window.document.getElementById(id);
  await import('../src/popup/popup.js');
  await flush();
  assert.equal($('view-offline').hidden, false, 'works while the desktop app is unreachable');

  $('menu-btn').click();
  assert.equal($('menu-btn').getAttribute('aria-expanded'), 'true');
  $('add-server').click();
  assert.equal($('view-server').hidden, false);
  assert.equal($('view-offline').hidden, true);
  assert.equal(window.document.querySelector('.popover'), null, 'the menu closed');
  const input = $('server-pair').querySelector('.sp-input');
  input.value = LINK;
  input.dispatchEvent(new window.Event('input'));
  $('server-pair').querySelector('.sp-send').click();
  await flush();
  assert.deepEqual(messages.at(-1), { type: 'popup.server-pair', link: LINK });
  assert.match($('server-pair').querySelector('.sp-result').textContent, /Check the Passyble window/);
  assert.equal(input.value, '');

  $('server-back').click();
  await flush();
  assert.equal($('view-server').hidden, true);
});

test('options: the Passyble Server card sends the link and explains a missing desktop app', async () => {
  reply = (msg) => (msg.type === 'popup.server-pair'
    ? { ok: false, error: { code: 'agent_unavailable', message: 'Passyble desktop app is not running' } }
    : { ok: true, result: null });
  const window = page('options/options.html');
  const root = window.document.getElementById('server-pair');
  await import('../src/options/options.js');
  await flush();
  const input = root.querySelector('.sp-input');
  input.value = LINK;
  input.dispatchEvent(new window.Event('input'));
  assert.match(root.querySelector('.sp-preview').textContent, /Laptop/);
  root.querySelector('.sp-send').click();
  await flush();
  assert.deepEqual(messages.at(-1), { type: 'popup.server-pair', link: LINK });
  assert.match(root.querySelector('.sp-result').textContent, /Passyble isn't running/);
  assert.equal(input.value, '');
});

test('options: a plain server address goes to the desktop app; Check connection offers Start Passyble', async () => {
  let started = false;
  reply = (msg) => {
    if (msg.type === 'popup.server-pair') return { ok: true, result: { shown: true, host: 'pass.example.com', user: null, sign_in: true, address: true } };
    if (msg.type === 'popup.status') return started ? { ok: true, result: { version: '1.0.0', locked: false } }
      : { ok: false, error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } };
    if (msg.type === 'popup.start') { started = true; return { ok: true, result: { version: '1.0.0', locked: false } }; }
    return { ok: true, result: null };
  };
  const window = page('options/options.html');
  const $ = (id) => window.document.getElementById(id);
  await import('../src/options/options.js?address');
  await flush();
  const root = $('server-pair');
  const input = root.querySelector('.sp-input');
  input.value = 'pass.example.com';
  input.dispatchEvent(new window.Event('input'));
  input.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Enter' }));
  await flush();
  assert.deepEqual(messages.at(-1), { type: 'popup.server-pair', link: 'https://pass.example.com' });
  assert.equal(root.querySelector('.sp-result').textContent, 'Passyble opened the sign-in window. Finish there.');

  assert.ok(window.document.querySelector('.row-icon svg[data-icon="monitor"]'), 'row icons');
  $('check').click();
  await flush();
  assert.equal($('agent-status').textContent, "Passyble isn't running.");
  assert.equal($('start').hidden, false);
  $('start').click();
  await flush();
  assert.match($('agent-status').textContent, /^Connected · Passyble 1\.0\.0 · unlocked$/);
  assert.equal($('start').hidden, true);
});
