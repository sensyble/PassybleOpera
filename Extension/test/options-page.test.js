import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const KEYS = ['inlineMenu', 'autoSuggest', 'autoGenerate', 'autoFillOtp', 'saveBanner', 'formFill', 'passkeys', 'autoPasskey'];
const messages = [];
const stored = [];
let reply = () => ({ ok: true, result: null });

const flush = () => new Promise((r) => setTimeout(r, 0));

async function openOptions() {
  const html = readFileSync(new URL('../src/options/options.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/src/options/options.html', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  messages.length = 0;
  stored.length = 0;
  await import(`../src/options/options.js?instance=${openOptions.n = (openOptions.n || 0) + 1}`);
  await flush();
  await flush();
  const document = dom.window.document;
  return { window: dom.window, document, $: (id) => document.getElementById(id) };
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      getManifest: () => ({ version: '1.2.3' }),
    },
    storage: {
      local: { get: async () => ({ passkeys: false }), set: async (v) => { stored.push(['local', v]); } },
      sync: { get: async () => ({}), set: async (v) => { stored.push(['sync', v]); } },
    },
    commands: { getAll: async () => [{ name: 'fill-login', shortcut: 'Ctrl+Shift+L' }] },
  };
});

test('groups come in order, like the desktop Settings; every row has one leading icon', async () => {
  const { document } = await openOptions();
  const groups = [...document.querySelectorAll('main > section.group')];
  // The first two are about the vault in this browser (hidden until vault.state says it is offered); the
  // second, the vault's settings, sits under the first one's heading.
  assert.deepEqual(groups.map((s) => s.querySelector('h2')?.textContent.trim() ?? null), ['Vault', null, 'Autofill', 'Never save', 'Passkeys', 'Keyboard shortcuts', 'Passyble Server', 'About']);
  assert.equal(groups[1].getAttribute('aria-label'), 'Vault in this browser');
  groups.splice(0, 2);
  for (const row of document.querySelectorAll('.card > .row')) {
    const icons = row.querySelectorAll(':scope > .row-icon > svg.pass-icon');
    assert.equal(icons.length, 1, row.textContent.trim());
  }
  assert.ok(document.querySelector('.page-head svg.pass-logo'), 'the Passyble logo');
  assert.equal(groups[4].id, 'server');
  assert.ok(groups[4].querySelector('#server-pair .sp-input'), 'Add Passyble Server form is mounted');
  assert.deepEqual(
    [...groups[0].querySelectorAll('input[data-key]')].map((i) => i.dataset.key),
    ['inlineMenu', 'autoSuggest', 'autoGenerate', 'autoFillOtp', 'saveBanner', 'formFill', 'cardSave'],
  );
  assert.equal(document.querySelector('label[for="s-autoSuggest"]').textContent, 'Open suggestions automatically');
  assert.deepEqual([...groups[2].querySelectorAll('input[data-key]')].map((i) => i.dataset.key), ['passkeys', 'autoPasskey']);
  assert.equal(groups[1].id, 'never-save');
  assert.ok(groups[3].querySelector('#shortcuts li'), 'shortcuts list is filled');
  const change = groups[3].querySelector('#shortcut-change');
  assert.equal(change.hidden, false, 'Chromium: a Change button');
  assert.equal(change.textContent.trim(), 'Change shortcuts');
});

test('every section heading is translatable, including the Passyble Server one', async () => {
  const { document } = await openOptions();
  for (const h of document.querySelectorAll('main > section.group > h2')) {
    assert.ok(h.dataset.i18n, `heading "${h.textContent.trim()}" has no data-i18n`);
  }
  assert.equal(document.getElementById('h-server').dataset.i18n, 'optionsServerHeading');
});

test('footer: "Made by Sensyble" links to sensyble.net', async () => {
  const { document } = await openOptions();
  const link = document.querySelector('footer.credit a#sensyble');
  assert.equal(link.textContent, 'Made by Sensyble');
  assert.equal(link.href, 'https://www.sensyble.net/');
  assert.equal(link.target, '_blank');
  assert.match(link.rel, /noopener/);
  assert.ok(document.querySelector('main').lastElementChild === document.querySelector('footer.credit'), 'at the bottom of the page');
});

test('every setting is one row: one-line label, a short caption under it (no (i) toggle), switch', async () => {
  const { document } = await openOptions();
  for (const key of KEYS) {
    const inputs = document.querySelectorAll(`input[data-key="${key}"]`);
    assert.equal(inputs.length, 1, key);
    const input = inputs[0];
    const row = input.closest('.row');
    const label = row.querySelector(`label.name[for="${input.id}"]`);
    assert.ok(label, `${key} has a label for its input`);
    assert.ok(label.textContent.trim().length > 0 && label.textContent.trim().length <= 44 && !/[\n.]/.test(label.textContent.trim()), `${key} label is short`);
    assert.equal(row.querySelectorAll('small, .details + p, button.info').length, 0, 'no paragraph and no (i) button');
    const caption = row.querySelector('.row-text > .caption');
    assert.ok(caption && !caption.hidden, `${key}: a caption, always shown`);
    assert.ok(caption.textContent.trim().split(/\s+/).length <= 10, `${key}: one short sentence`);
    assert.ok(caption.id, `${key}: the caption has an id`);
    assert.equal(input.getAttribute('aria-describedby'), caption.id, `${key}: the switch is described by its caption`);
  }
});

test('settings load from storage and a change is saved with a flash', async () => {
  const { document, window, $ } = await openOptions();
  assert.equal(document.querySelector('input[data-key="passkeys"]').checked, false, 'stored value shown');
  assert.equal(document.querySelector('input[data-key="inlineMenu"]').checked, true, 'default shown');
  assert.equal(document.querySelector('input[data-key="autoSuggest"]').checked, true, 'suggestions open on their own by default');

  const input = document.querySelector('input[data-key="saveBanner"]');
  input.checked = false;
  input.dispatchEvent(new window.Event('change', { bubbles: true }));
  await flush();
  assert.deepEqual(stored, [['local', { saveBanner: false }]]);
  assert.equal($('saved').textContent, 'Saved');

  document.querySelector('input[data-key="autoGenerate"]').checked = false;
  document.querySelector('input[data-key="autoGenerate"]').dispatchEvent(new window.Event('change', { bubbles: true }));
  await flush();
  assert.deepEqual(stored.at(-1), ['sync', { autoGenerate: false }], 'synced key goes to storage.sync');
});

test('About: check connection shows the desktop app status; version is shown', async () => {
  reply = (msg) => (msg.type === 'popup.status' ? { ok: true, result: { version: '0.9.0', locked: true } } : { ok: true, result: null });
  const { $ } = await openOptions();
  assert.equal($('version').textContent, '1.2.3');
  assert.equal($('agent-status').textContent, 'Not checked yet');
  assert.equal($('start').hidden, true);
  $('check').click();
  await flush();
  assert.deepEqual(messages.find((m) => m.type === 'popup.status'), { type: 'popup.status' });
  assert.match($('agent-status').textContent, /Connected/);
  assert.match($('agent-status').textContent, /0\.9\.0/);
  assert.match($('agent-status').textContent, /locked/);
  assert.equal($('start').hidden, true);
});

test('About: unreachable desktop app offers Start, which asks the background', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.status') return { ok: false, error: { code: 'agent_unavailable', message: 'not running' } };
    if (msg.type === 'popup.start') return { ok: true, result: { version: '0.9.0', locked: false } };
    return { ok: true, result: null };
  };
  const { $ } = await openOptions();
  $('check').click();
  await flush();
  assert.ok($('agent-status').classList.contains('bad'));
  assert.equal($('start').hidden, false);
  $('start').click();
  await flush();
  assert.ok(messages.some((m) => m.type === 'popup.start'));
  assert.match($('agent-status').textContent, /Connected/);
  assert.equal($('start').hidden, true);
});

test('About: "Setup guide and tips" opens the welcome page in a new tab', async () => {
  const { $ } = await openOptions();
  const link = $('setup-guide');
  assert.ok(link.closest('#about'), 'in the About section');
  assert.equal(link.closest('.row').querySelector('.name').textContent, 'Setup guide');
  assert.equal(link.textContent.trim(), 'Open');
  assert.equal(link.href, 'https://extension.test/src/welcome/welcome.html');
  assert.equal(link.target, '_blank');
});
