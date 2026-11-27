// The popup's item-type filter and the secure note viewer (real popup.html + popup.js in jsdom). Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

let reply = () => ({ ok: true, result: null });
let instance = 0;
let store = {};
let storageBroken = false;

const ok = (result) => ({ ok: true, result });
const fail = (code, message = code) => ({ ok: false, error: { code, message } });
const HOME = { id: 'home', name: '', home: true, kind: 'personal', role: null, can_edit: true, can_reveal: true };
const ENG = { id: 'eng', name: 'Engineering', home: false, kind: 'org', role: 'edit', can_edit: true, can_reveal: true };
const ITEMS = [
  { id: 'a', title: 'Alpha', username: 'ann', vault_id: 'home' },
  { id: 'b', title: 'Bravo', username: 'bob', vault_id: 'home', has_totp: true },
  { id: 'c', title: 'Charlie', username: 'cat', vault_id: 'eng', has_totp: true, has_passkey: true },
  { id: 'd', title: 'Delta', username: 'dan', vault_id: 'home', has_passkey: true },
];
const CARD = { id: 'card1', title: 'Demo Visa', brand: 'visa', last4: '4242', expiry_month: 1, expiry_year: 2030, vault_id: 'home' };
const ADDRESS = { id: 'adr1', title: 'Home', full_name: 'Demo Person', email: 'demo@example.com', vault_id: 'home' };
const STATE = { url: 'https://example.com/login', supported: true, locked: false, pending_otp: null, items: ITEMS, can_edit: true,
  can_search: true, can_cards: true, can_identities: true, can_vaults: true, vaults: [HOME, ENG] };
const LIST = { vaults: [HOME, ENG].map((v) => ({ ...v, items: 1, open: true, error: null })), teams: null };

function agent({ state = STATE, extra = {} } = {}) {
  return (msg) => {
    if (Object.hasOwn(extra, msg.type)) return extra[msg.type](msg);
    switch (msg.type) {
      case 'popup.state': return ok(state);
      case 'popup.vaults': return ok(LIST);
      case 'popup.forms': return ok({ cards: [CARD], identities: [ADDRESS], locked: false });
      case 'popup.search': return ok({ items: [
        { id: 's1', title: 'Search plain', username: 'x', domain: 's1.test', vault_id: 'home' },
        { id: 's2', title: 'Search code', username: 'y', domain: 's2.test', vault_id: 'home', has_totp: true }], vaults: [HOME, ENG] });
      default: return ok(null);
    }
  };
}

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = { close: () => {} };
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  return (id) => dom.window.document.getElementById(id);
}

const flush = async (n = 12) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const shownRows = ($) => [...$('list').children].filter((li) => !li.hidden).map((li) => li.dataset.id);
/** Runs `read` with the Filter menu open, then closes it again. */
function withFilter(read) {
  document.getElementById('filter').click();
  try { return read(); } finally { if (document.querySelector('.popover')) document.getElementById('filter').click(); }
}
/** The Show section's choices, as named in the menu. */
const kindNames = () => withFilter(() => [...document.querySelectorAll('.popover [id^="type-"]')].map((b) => b.textContent));
/** Whether kind `kind` is the one shown (its menu entry checked): 'true' or 'false'. */
const checked = (kind) => withFilter(() => document.getElementById(`type-${kind}`).getAttribute('aria-checked'));
/** Picks kind `kind` in the Filter menu. */
async function press(kind) { document.getElementById('filter').click(); document.getElementById(`type-${kind}`).click(); await flush(); }

before(() => {
  globalThis.chrome = {
    runtime: { id: 'pass-ext', getURL: (p) => `chrome-extension://pass-ext/${p}`, sendMessage: async (msg) => reply(msg),
      onMessage: { addListener: () => {} }, openOptionsPage: () => {} },
    tabs: { query: async () => [{ id: 1, windowId: 7, url: 'https://example.com/login' }], create: async () => ({ id: 9 }) },
    storage: {
      local: {
        get: async (key) => {
          if (storageBroken) throw new Error('no storage');
          return typeof key === 'string' && key in store ? { [key]: store[key] } : {};
        },
        set: async (obj) => {
          if (storageBroken) throw new Error('no storage');
          Object.assign(store, obj);
        },
      },
      sync: { get: async () => ({}), set: async () => {} },
    },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('type filter: chips for the kinds the agent lists, All pressed first; a kind narrows the site logins', async () => {
  store = {}; storageBroken = false;
  reply = agent();
  const $ = await openPopup();
  assert.deepEqual(kindNames(), ['All', 'Logins', '2FA', 'Passkey', 'Cards', 'Addresses']);
  assert.equal(checked('all'), 'true');
  assert.equal(withFilter(() => document.querySelectorAll('.popover .menu-group')[1].getAttribute('aria-label')), 'Filter by type',
    'the Show section is a named group');
  assert.equal(document.querySelector('.type-chip, .type-bar'), null, 'no row of chips');
  assert.equal($('filter').textContent, 'Filter', 'nothing chosen: the button just says Filter');
  assert.deepEqual(shownRows($), ['a', 'b', 'c', 'd']);
  await press('twofa');
  assert.deepEqual(shownRows($), ['b', 'c']);
  assert.equal($('filter').textContent, '2FA', 'the button says what is shown');
  assert.equal($('filter-clear').hidden, false, 'and the x clears it');
  assert.equal(checked('twofa'), 'true');
  assert.equal(checked('all'), 'false');
  await press('passkeys');
  assert.deepEqual(shownRows($), ['c', 'd']);
  await press('logins');
  assert.deepEqual(shownRows($), ['a', 'b', 'c', 'd']);
  assert.equal(store.popupTypeFilter, 'logins', 'the last kind is kept');
});

test('type filter: combines with the search box and the vault filter; typing does not reset it', async () => {
  store = {}; storageBroken = false;
  reply = agent();
  const $ = await openPopup();
  await press('twofa');
  $('search').value = 'cha';
  $('search').dispatchEvent(new Event('input'));
  await new Promise((r) => setTimeout(r, 300));
  assert.deepEqual(shownRows($), ['c'], 'search and kind together');
  assert.equal(checked('twofa'), 'true', 'typing keeps the kind');
  assert.deepEqual([...$('result-list').children].map((li) => li.dataset.id), ['s2'], 'search results narrowed too');
  $('search').value = '';
  $('search').dispatchEvent(new Event('input'));
  await flush();
  document.getElementById('filter').click();
  document.getElementById('vault-eng').click();
  await flush();
  assert.deepEqual(shownRows($), ['c'], 'vault and kind together');
  assert.equal($('empty-state').hidden, true);
  assert.equal($('filter').textContent, 'Engineering · 2FA');
  // The x shows everything again, and the Filter button says so.
  $('filter-clear').click();
  await flush();
  assert.deepEqual(shownRows($), ['a', 'b', 'c', 'd']);
  assert.equal($('filter').textContent, 'Filter');
  assert.equal($('filter-clear').hidden, true);
  assert.equal(checked('all'), 'true');
});

test('type filter: Cards and Addresses show their lists without a search; other kinds hide them', async () => {
  store = {}; storageBroken = false;
  reply = agent();
  const $ = await openPopup();
  await press('cards');
  assert.deepEqual(shownRows($), []);
  assert.deepEqual([...$('forms-list').children].map((li) => li.dataset.id), ['card1']);
  assert.equal($('forms').hidden, false);
  await press('addresses');
  assert.deepEqual([...$('forms-list').children].map((li) => li.dataset.id), ['adr1']);
  await press('twofa');
  assert.equal($('forms').hidden, true);
});

test('type filter: the kind is restored in a new popup; Cards and Addresses only where the app has them', async () => {
  store = { popupTypeFilter: 'passkeys' }; storageBroken = false;
  reply = agent();
  let $ = await openPopup();
  assert.equal(checked('passkeys'), 'true');
  assert.deepEqual(shownRows($), ['c', 'd']);

  store = { popupTypeFilter: 'cards' };
  reply = agent({ state: { ...STATE, can_cards: false, can_identities: false } });
  $ = await openPopup();
  assert.deepEqual(kindNames(), ['All', 'Logins', '2FA', 'Passkey']);
  assert.equal(checked('all'), 'true', 'a kind that is not offered falls back to All');
});

test('type filter: a storage that fails is no problem', async () => {
  store = {}; storageBroken = true;
  reply = agent();
  const $ = await openPopup();
  await press('twofa');
  assert.deepEqual(shownRows($), ['b', 'c']);
  storageBroken = false;
});

// Favorites and Notes (the agent's `items.favorite` and `notes.list`).

const NOTES = [
  { id: 'n1', title: 'Recovery codes', favorite: true, updated: 1700000000000, vault_id: 'home' },
  { id: 'n2', title: 'Wifi at home', favorite: false, updated: 1700000000000, vault_id: 'home' },
];
const FULL = { ...STATE, items: ITEMS.map((i) => (i.id === 'b' ? { ...i, favorite: true } : i)), can_favorites: true, can_note_list: true };
const FAVORITE_CARD = { ...CARD, id: 'card2', title: 'Demo Mastercard', last4: '4444', favorite: true };

/** The agent of FULL, recording the popup's note requests in `sent`. */
function notesAgent(sent, { notes = NOTES, noteGet = (msg) => ok(msg.copy ? { copied: true }
  : { id: msg.id, title: 'Recovery codes', notes: '1111-2222\n3333-4444', favorite: true, updated: 1 }) } = {}) {
  return agent({ state: FULL, extra: {
    'popup.forms': () => ok({ cards: [CARD, FAVORITE_CARD], identities: [ADDRESS], locked: false }),
    'popup.notes': (msg) => { sent.push(msg); return ok({ items: notes, truncated: false, locked: false, vaults: [HOME] }); },
    'popup.note-get': (msg) => { sent.push(msg); return noteGet(msg); },
  } });
}

const ids = ($, list) => [...$(list).children].filter((li) => !li.hidden).map((li) => li.dataset.id);

test('type filter: Favorites and Notes only with an agent that lists them; a kept Notes falls back to All', async () => {
  store = {}; storageBroken = false;
  reply = notesAgent([]);
  await openPopup();
  assert.deepEqual(kindNames(), ['All', 'Favorites', 'Logins', '2FA', 'Passkey', 'Cards', 'Addresses', 'Notes']);

  store = { popupTypeFilter: 'notes' };
  reply = agent();
  const $ = await openPopup();
  assert.deepEqual(kindNames(), ['All', 'Logins', '2FA', 'Passkey', 'Cards', 'Addresses']);
  assert.equal(checked('all'), 'true');
  assert.equal($('notes').hidden, true);
});

test('type filter: Favorites shows the favorite logins, cards and notes without a search', async () => {
  store = {}; storageBroken = false;
  const sent = [];
  reply = notesAgent(sent);
  const $ = await openPopup();
  assert.equal($('notes').hidden, true, 'no notes under All');
  assert.equal(sent.length, 0, 'the notes list loads only when a chip needs it');
  await press('favorites');
  assert.deepEqual(shownRows($), ['b']);
  assert.deepEqual(ids($, 'forms-list'), ['card2'], 'only the favorite card; the address is no favorite');
  assert.deepEqual(ids($, 'notes-list'), ['n1']);
  assert.equal($('empty-state').hidden, true);
  assert.equal(JSON.stringify(sent), JSON.stringify([{ type: 'popup.notes' }]), 'the list asks for no text');
  await press('all');
  assert.equal($('notes').hidden, true);
  assert.deepEqual(shownRows($), ['a', 'b', 'c', 'd']);
});

test('type filter: Notes lists the notes; one opens in the viewer with Copy, and its text goes when it closes', async () => {
  store = {}; storageBroken = false;
  const sent = [];
  reply = notesAgent(sent);
  const $ = await openPopup();
  await press('notes');
  assert.deepEqual(shownRows($), [], 'no logins under Notes');
  assert.deepEqual(ids($, 'notes-list'), ['n1', 'n2']);
  assert.equal($('forms').hidden, true);
  assert.equal($('empty-state').hidden, true);

  $('search').value = 'wifi';
  $('search').dispatchEvent(new Event('input'));
  await flush();
  assert.deepEqual(ids($, 'notes-list'), ['n2']);
  $('search').value = '';
  $('search').dispatchEvent(new Event('input'));
  await flush();

  document.querySelector('#notes-list li[data-id="n1"] .item-main').click();
  await flush();
  assert.deepEqual(sent.at(-1), { type: 'popup.note-get', id: 'n1' });
  assert.equal($('view-note').hidden, false);
  assert.equal($('view-list').hidden, true);
  assert.equal($('note-heading').textContent, 'Recovery codes');
  assert.equal($('note-text').textContent, '1111-2222\n3333-4444');

  $('note-copy').click();
  await flush();
  assert.deepEqual(sent.at(-1), { type: 'popup.note-get', id: 'n1', copy: true });
  assert.equal($('snack').textContent, 'Note copied (clears in 45 s)');

  $('note-back').click();
  await flush();
  assert.equal($('view-list').hidden, false);
  assert.equal($('note-body').textContent, '', 'the text is gone with the viewer');

  // A row's Copy copies without showing the note.
  document.querySelector('#notes-list li[data-id="n2"] .actions button').click();
  await flush();
  assert.deepEqual(sent.at(-1), { type: 'popup.note-get', id: 'n2', copy: true });
  assert.equal($('view-list').hidden, false);
});

test('type filter: a note the agent does not show stays closed; no notes says so', async () => {
  store = {}; storageBroken = false;
  let $;
  for (const [code, snackText] of [['cancelled', ''], ['fill_only', null]]) {
    const sent = [];
    reply = notesAgent(sent, { noteGet: () => fail(code, 'This login can be filled but not shown or copied') });
    $ = await openPopup();
    $('snack').textContent = '';
    await press('notes');
    document.querySelector('#notes-list li[data-id="n1"] .item-main').click();
    await flush();
    assert.equal($('view-note').hidden, true, code);
    assert.equal($('view-list').hidden, false, code);
    if (snackText === '') assert.equal($('snack').textContent, '', 'a Cancel says nothing');
    else assert.notEqual($('snack').textContent, '', code);
  }

  store = {};
  reply = notesAgent([], { notes: [] });
  $ = await openPopup();
  await press('notes');
  assert.equal($('notes').hidden, true);
  assert.equal($('empty-state').hidden, false);
  assert.equal($('empty').textContent, 'Nothing of this kind here.');
});
