// Moving a login to another vault from the popup's editor (real popup.html + popup.js + editor.js in jsdom): into a
// shared vault only after the popup's question. Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const ok = (result) => ({ ok: true, result });
const fail = (code, message = code) => ({ ok: false, error: { code, message } });

const HOME = { id: 'home', name: '', home: true, kind: 'personal', role: null, can_edit: true, can_reveal: true };
const ENG = { id: 'eng', name: 'Engineering', home: false, kind: 'org', role: 'edit', can_edit: true, can_reveal: true };
const FAM = { id: 'fam', name: 'Family', home: false, kind: 'org', role: 'manage', can_edit: true, can_reveal: true };
const SUP = { id: 'sup', name: 'Support', home: false, kind: 'org', role: 'view', can_edit: false, can_reveal: true };
const DEP = { id: 'dep', name: 'Deploy', home: false, kind: 'org', role: 'fill', can_edit: false, can_reveal: false };
const SHUT = { id: 'shut', name: 'Closed', home: false, kind: 'org', role: 'edit', can_edit: true, can_reveal: true };
const LIST = { vaults: [
  ...[HOME, ENG, FAM, SUP, DEP].map((v) => ({ ...v, items: 1, open: true, error: null })), { ...SHUT, items: 0, open: false, error: null },
], teams: null };

const GH = { id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false, vault_id: 'home' };
const GL = { id: 'gl', title: 'GitHub (work)', username: 'octo-work', has_totp: false, has_passkey: false, vault_id: 'eng' };
const OLD = { id: 'old', title: 'GitHub (old)', username: 'octo-old', has_totp: false, has_passkey: false, vault_id: 'shut' };
const STATE = { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null, can_edit: true, can_search: true,
  can_vaults: true, can_pins: true, can_move: true, vaults: [HOME, ENG, FAM] };
const editData = (item) => ({ id: item.id, title: item.title, username: item.username, password: 'hunter2', notes: '', urls: ['https://github.com'],
  has_passkey: false, totp: null, vault: [HOME, ENG, FAM, SHUT].find((v) => v.id === item.vault_id) });

/** The background: `items` is what popup.state lists (a move swaps the login's id); `over[type]` replaces one answer. */
function agent({ state = STATE, list = LIST, items = [GH, GL, OLD], over = {} } = {}) {
  const now = { items: [...items] };
  return (msg) => {
    if (over[msg.type]) return over[msg.type](msg, now);
    switch (msg.type) {
      case 'popup.state': return ok({ ...state, items: now.items });
      case 'popup.vaults': return ok(list);
      case 'popup.pins': return ok({ pins: ['fam'], max: 5 });
      case 'popup.edit-get': return ok(editData(now.items.find((i) => i.id === msg.id)));
      case 'popup.edit-save': return ok({ id: msg.id, title: msg.fields.title });
      case 'popup.edit-move': {
        const moved = { ...now.items.find((i) => i.id === msg.id), id: `${msg.id}-moved`, vault_id: msg.vault };
        now.items = now.items.map((i) => (i.id === msg.id ? moved : i));
        return ok({ id: moved.id, title: moved.title, kind: 'login', moved_from: msg.id, vault: [HOME, ENG, FAM].find((v) => v.id === msg.vault) });
      }
      default: return ok(null);
    }
  };
}

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = { close: () => {} };
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  return (id) => dom.window.document.getElementById(id);
}

const flush = async (n = 12) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const sent = (type) => messages.filter((m) => m.type === type);
const types = () => messages.map((m) => m.type);
const options = ($) => [...$('ed-vault').options].map((o) => o.textContent);

/** Opens the editor on the site's login `id` (its row's ⋯ menu, Edit). */
async function edit($, id) {
  $('list').querySelector(`[data-id="${id}"] button[title="More"]`).click();
  $('row-edit').click();
  await flush();
  assert.equal($('view-edit').hidden, false);
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
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

test('Vault: open vaults the user may edit, pinned first; to the home vault without a question; the new id is selected', async () => {
  reply = agent();
  const $ = await openPopup();
  await edit($, 'gl');
  assert.deepEqual(options($), ['Family', 'Personal', 'Engineering'], 'no view, fill or closed vault');
  assert.equal($('ed-vault').value, 'eng');
  $('ed-vault').value = 'home';
  $('ed-save').click();
  await flush();
  assert.equal($('ed-move-text'), null, 'the home vault: nobody else sees it');
  assert.deepEqual(types().filter((t) => t.startsWith('popup.edit-')), ['popup.edit-get', 'popup.edit-save', 'popup.edit-move']);
  assert.deepEqual(sent('popup.edit-move'), [{ type: 'popup.edit-move', tabId: 1, id: 'gl', vault: 'home' }]);
  assert.equal($('view-list').hidden, false);
  const row = $('list').querySelector('[data-id="gl-moved"]');
  assert.ok(row, 'the list shows the login under its new id');
  assert.equal(row.classList.contains('active'), true, 'and selects it');
  assert.equal($('snack').textContent, 'Moved to Personal');
});

test('into a shared vault: the popup asks first; Cancel saves nothing, Move saves and moves', async () => {
  reply = agent();
  const $ = await openPopup();
  await edit($, 'gh');
  $('ed-title').value = 'GitHub personal';
  $('ed-vault').value = 'eng';
  $('ed-save').click();
  await flush();
  assert.equal($('ed-move-text').textContent, 'Move GitHub personal to Engineering? Everyone with access to Engineering will see it.');
  assert.equal($('ed-save').closest('.ed-actions').hidden, true);
  assert.equal(sent('popup.edit-save').length, 0, 'nothing saved before the answer');
  $('ed-move-cancel').click();
  await flush();
  assert.equal($('ed-move-text'), null);
  assert.equal($('ed-save').closest('.ed-actions').hidden, false);
  assert.equal($('ed-save').disabled, false);
  assert.equal(sent('popup.edit-save').length + sent('popup.edit-move').length, 0);

  $('ed-save').click();
  await flush();
  $('ed-move-ok').click();
  await flush();
  assert.equal(sent('popup.edit-save')[0].fields.title, 'GitHub personal');
  assert.deepEqual(sent('popup.edit-move'), [{ type: 'popup.edit-move', tabId: 1, id: 'gh', vault: 'eng' }]);
  assert.equal($('snack').textContent, 'Moved to Engineering');
});

test('the same vault saves as before; a move the app declines keeps the saved fields and says why', async () => {
  reply = agent({ over: { 'popup.edit-move': () => fail('cancelled') } });
  const $ = await openPopup();
  await edit($, 'gl');
  $('ed-save').click();
  await flush();
  assert.equal(sent('popup.edit-move').length, 0);
  assert.equal($('snack').textContent, 'Saved');

  await edit($, 'gl');
  $('ed-vault').value = 'home';
  $('ed-save').click();
  await flush();
  assert.equal(sent('popup.edit-save').length, 2);
  assert.equal(sent('popup.edit-move').length, 1);
  assert.equal($('view-list').hidden, false);
  assert.equal($('snack').textContent, 'Cancelled.');
  assert.ok($('list').querySelector('[data-id="gl"]'), 'still where it was');
});

test('no Vault picker: without items.move, a login of a vault not offered, nothing else to move to, or nothing else to move to', async () => {
  reply = agent({ state: { ...STATE, can_move: false } });
  let $ = await openPopup();
  await edit($, 'gh');
  assert.equal($('ed-vault'), null, 'an agent without items.move');

  reply = agent();
  $ = await openPopup();
  await edit($, 'old');
  assert.equal($('ed-vault'), null, 'its vault is not open');

  reply = agent({ list: { vaults: [HOME, SUP, DEP].map((v) => ({ ...v, open: true, error: null })), teams: null }, items: [GH] });
  $ = await openPopup();
  await edit($, 'gh');
  assert.equal($('ed-vault'), null, 'only read-only and fill-only vaults besides it');

  reply = agent();
  $ = await openPopup();
  $('add-login').click();
  await flush();
  assert.ok($('ed-vault'), 'a new login chooses its vault too');
  assert.equal($('ed-vault').value, 'home', 'the home vault by default');
});
