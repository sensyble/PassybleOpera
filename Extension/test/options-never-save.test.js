import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const store = {};
const writes = [];
const flush = () => new Promise((r) => setTimeout(r, 0));
let instance = 0;

async function openOptions() {
  const html = readFileSync(new URL('../src/options/options.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/src/options/options.html', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  await import(`../src/options/options.js?instance=${++instance}`);
  await flush();
  await flush();
  const document = dom.window.document;
  return { window: dom.window, document, $: (id) => document.getElementById(id) };
}

before(() => {
  globalThis.chrome = {
    runtime: { id: 'pass-ext', sendMessage: async () => ({ ok: true, result: null }), onMessage: { addListener: () => {} }, getManifest: () => ({ version: '1' }) },
    storage: {
      local: {
        get: async (keys) => {
          const list = typeof keys === 'string' ? [keys] : Array.isArray(keys) ? keys : Object.keys(store);
          return Object.fromEntries(list.filter((k) => k in store).map((k) => [k, structuredClone(store[k])]));
        },
        set: async (o) => { writes.push(o); Object.assign(store, structuredClone(o)); },
      },
      sync: { get: async () => ({}), set: async () => {} },
    },
    commands: { getAll: async () => [] },
  };
});

test('no exceptions: the section says how to add one', async () => {
  delete store.neverSave;
  const { $, document } = await openOptions();
  assert.equal(document.querySelector('#never-save h2').textContent, 'Never save');
  assert.equal($('never-list').children.length, 0);
  assert.equal($('never-empty').hidden, false);
});

test('lists the stored sites, each with a Remove button that removes only that site', async () => {
  store.neverSave = ['https://accounts.example.com', 'https://shop.test'];
  writes.length = 0;
  const { $, document } = await openOptions();
  const rows = [...$('never-list').querySelectorAll('.row')];
  assert.deepEqual(rows.map((r) => r.querySelector('.name').textContent), ['https://accounts.example.com', 'https://shop.test']);
  assert.equal($('never-empty').hidden, true);
  for (const row of rows) assert.equal(row.querySelectorAll(':scope > .row-icon > svg.pass-icon').length, 1, 'one leading icon');
  const remove = rows[0].querySelector('button');
  assert.equal(remove.getAttribute('aria-label'), 'Remove https://accounts.example.com');
  assert.ok(remove.querySelector('svg[data-icon="trash"]'));
  remove.click();
  await flush();
  await flush();
  assert.deepEqual(writes, [{ neverSave: ['https://shop.test'] }]);
  assert.deepEqual(store.neverSave, ['https://shop.test']);
  assert.deepEqual([...$('never-list').querySelectorAll('.name')].map((n) => n.textContent), ['https://shop.test']);
  assert.equal($('saved').textContent, 'Removed');
  document.querySelector('#never-list button').click();
  await flush();
  await flush();
  assert.deepEqual(store.neverSave, []);
  assert.equal($('never-list').children.length, 0);
  assert.equal($('never-empty').hidden, false, 'empty again');
});

test('junk in storage is ignored (only http(s) origins are listed)', async () => {
  store.neverSave = ['https://ok.test', 'javascript:alert(1)', 42, 'https://ok.test/path', null];
  const { $ } = await openOptions();
  assert.deepEqual([...$('never-list').querySelectorAll('.name')].map((n) => n.textContent), ['https://ok.test']);
});
