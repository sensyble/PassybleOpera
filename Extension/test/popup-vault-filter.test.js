// The popup's vault filter, pinned vaults and vault switcher (real popup.html + popup.js in jsdom). Pinning sends the
// agent's whole list (ids this browser doesn't show stay, at most 5). Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
let runtimeListener = null;

const ok = (result) => ({ ok: true, result });
const fail = (code, message = code) => ({ ok: false, error: { code, message } });

const HOME = { id: 'home', name: '', home: true, kind: 'personal', role: null, can_edit: true, can_reveal: true };
const ENG = { id: 'eng', name: 'Engineering', home: false, kind: 'org', role: 'edit', can_edit: true, can_reveal: true };
const FAM = { id: 'fam', name: 'Family', home: false, kind: 'org', role: 'manage', can_edit: true, can_reveal: true };
const ITEMS = [
  { id: 'gh', title: 'GitHub', username: 'octo', vault_id: 'home' },
  { id: 'gl', title: 'GitHub (work)', username: 'octo-work', vault_id: 'eng' },
  { id: 'wiki', title: 'GitHub (kids)', username: 'octo-kid', vault_id: 'fam' },
];
const STATE = { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null, items: ITEMS,
  can_edit: true, can_search: true, can_vaults: true, can_pins: true, vaults: [HOME, ENG, FAM] };
const LIST = { vaults: [HOME, ENG, FAM].map((v) => ({ ...v, items: 1, open: true, error: null })), teams: null };
const OWN = { vaults: [
  { id: 'f-home', vault_id: 'home', name: 'Personal stuff', location: 'C:\\Vaults\\personal.pass', active: true },
  { id: 'f-old', vault_id: null, name: 'Old', location: 'C:\\Vaults\\old.pass', active: false },
  { id: 'f-work', vault_id: 'work', name: 'Work', location: 'C:\\Vaults\\work.pass', active: false },
] };

/** The background: `pins` is the agent's stored list; `over[type]` replaces one answer. */
function agent({ state = STATE, list = LIST, pins = ['fam', 'not-in-this-browser'], own = fail('not_supported', 'unknown method'), over = {} } = {}) {
  const store = { pins: [...pins] };
  return (msg) => {
    if (over[msg.type]) return over[msg.type](msg, store);
    switch (msg.type) {
      case 'popup.state': return ok(state);
      case 'popup.vaults': return ok(list);
      case 'popup.pins': return ok({ pins: store.pins, max: 5 });
      case 'popup.set-pins': store.pins = msg.ids; return ok({ pins: store.pins, max: 5 });
      case 'popup.own-vaults': return typeof own === 'function' ? own() : own.ok === false ? own : ok(own);
      default: return ok(null);
    }
  };
}

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent', 'MouseEvent']) globalThis[k] = dom.window[k];
  globalThis.window = { close: () => {} };
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  return (id) => dom.window.document.getElementById(id);
}

const flush = async (n = 12) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const sent = (type) => messages.filter((m) => m.type === type);
const shownRows = ($) => [...$('list').children].filter((li) => !li.hidden).map((li) => li.dataset.id);
const menu = () => [...document.querySelectorAll('.popover .menu-item')];
/** An entry's name without the screen-reader-only "Pinned". */
const nameOf = (b) => [...b.childNodes].filter((n) => n.nodeType === 1 && n.tagName === 'SPAN' && !n.classList.contains('sr-only'))
  .map((n) => n.textContent).join('');
/** The Filter menu's Vaults section: [name, checked, pinned] of each entry. */
function vaultEntries($) {
  $('filter').click();
  const rows = [...document.querySelectorAll('.popover [id^="vault-"]')].map((b) => [nameOf(b), b.getAttribute('aria-checked'),
    !!b.closest('.menu-row.pinned')]);
  $('filter').click();
  return rows;
}
/** Picks vault `id` in the Filter menu ('all' for All vaults). */
async function pickVault($, id) {
  $('filter').click();
  $(`vault-${id}`).click();
  await flush();
}
/** Clicks the pin at the end of vault `id`'s row in the Filter menu. */
async function pinButton($, id) {
  $('filter').click();
  $(`vault-${id}`).closest('.menu-row').querySelector('.menu-pin').click();
  await flush();
}
/** Opens the vault filter's menu and picks the entry named `label`. */
async function pick($, button, label) {
  $(button).click();
  const entry = menu().find((b) => b.textContent === label);
  assert.ok(entry, `"${label}" in ${menu().map((b) => b.textContent)}`);
  entry.click();
  await flush();
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, windowId: 7, url: 'https://github.com/login' }], create: async () => ({ id: 9 }) },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('vault filter: the Filter menu lists the home vault, then the pinned vaults (unknown pins ignored), then the rest; no chips', async () => {
  reply = agent();
  const $ = await openPopup();
  assert.equal(document.querySelector('.vault-chip, .vault-bar, .type-chip'), null, 'no chips over the list');
  assert.deepEqual(vaultEntries($), [['All vaults', 'true', false], ['Personal', 'false', false], ['Family', 'false', true],
    ['Engineering', 'false', false]], 'the pin of a vault this browser does not show is not drawn');
  $('filter').click();
  const family = $('vault-fam');
  assert.equal(family.querySelector('.sr-only')?.textContent, 'Pinned', 'a screen reader hears "Pinned"');
  const pin = family.closest('.menu-row').querySelector('.menu-pin');
  assert.equal(pin.getAttribute('aria-label'), 'Unpin Family');
  assert.equal(pin.getAttribute('aria-pressed'), 'true');
  assert.ok(pin.querySelector('svg[data-icon="pin"]'));
  // The keyboard: ArrowRight from the entry to its pin, ArrowLeft back.
  family.focus();
  family.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowRight', bubbles: true }));
  assert.equal(document.activeElement, pin);
  pin.dispatchEvent(new KeyboardEvent('keydown', { key: 'ArrowLeft', bubbles: true }));
  assert.equal(document.activeElement, family);
  $('filter').click();

  await pickVault($, 'fam');
  assert.deepEqual(shownRows($), ['wiki']);
  assert.equal($('filter').textContent, 'Family');
  await pickVault($, 'eng');
  assert.deepEqual(shownRows($), ['gl']);
  await pickVault($, 'all');
  assert.deepEqual(shownRows($), ['gh', 'gl', 'wiki']);
  assert.equal($('filter').textContent, 'Filter');
});

test('vault filter: a vault without a login here says so; the search results follow the filter', async () => {
  const ONLY_HOME = { ...STATE, items: [ITEMS[0]] };
  reply = agent({ state: ONLY_HOME, over: { 'popup.search': () => ok({ items: [
    { id: 'gl2', title: 'GitLab', username: 'w', domain: 'gitlab.com', vault_id: 'eng' },
    { id: 'kid', title: 'Games', username: 'k', domain: 'games.example', vault_id: 'fam' }], vaults: [HOME, ENG, FAM] }) } });
  const $ = await openPopup();
  await pickVault($, 'eng');
  assert.equal($('empty').textContent, 'No logins for this site in Engineering');
  $('search').value = 'git';
  $('search').dispatchEvent(new Event('input'));
  await new Promise((r) => setTimeout(r, 300));
  await flush();
  assert.deepEqual([...$('result-list').children].map((li) => li.dataset.id), ['gl2']);
  await pickVault($, 'all');
  assert.deepEqual([...$('result-list').children].map((li) => li.dataset.id), ['gl2', 'kid']);
});

test('pins: the row pin sends the whole list with the new pin last (other pins kept), and again takes it out', async () => {
  reply = agent();
  const $ = await openPopup();
  await pinButton($, 'eng');
  assert.deepEqual(sent('popup.set-pins').map((m) => m.ids), [['fam', 'not-in-this-browser', 'eng']]);
  assert.equal('known' in sent('popup.set-pins')[0], false, 'app mode: no known');
  assert.deepEqual(vaultEntries($).map(([name, , pinned]) => [name, pinned]),
    [['All vaults', false], ['Personal', false], ['Family', true], ['Engineering', true]], 'in pin order, after the home vault');
  await pinButton($, 'eng');
  assert.deepEqual(sent('popup.set-pins').at(-1).ids, ['fam', 'not-in-this-browser']);
  // The row's context menu has it too.
  $('filter').click();
  $('vault-eng').dispatchEvent(new MouseEvent('contextmenu', { bubbles: true, cancelable: true }));
  assert.equal($('menu-pin-toggle').textContent, 'Pin vault');
  $('menu-pin-toggle').click();
  await flush();
  assert.deepEqual(sent('popup.set-pins').at(-1).ids, ['fam', 'not-in-this-browser', 'eng']);
});

test('pins in browser mode name the shared vaults opened here (`known`, also one that did not open)', async () => {
  const model = { vaults: [{ ...ENG, items: 1, open: true, error: null }, { ...FAM, items: 1, open: true, error: null },
    { id: 'broken', name: 'Broken', kind: 'org', role: 'edit', can_edit: true, can_reveal: true, open: false, error: { code: 'untrusted' } }],
  teams: null, browser: { status: 'ready', orgs: [], held: [], confirm: [] } };
  reply = agent({ state: { ...STATE, browser: true }, over: { 'teams.model': () => ok(model) } });
  const $ = await openPopup();
  await pinButton($, 'eng');
  assert.deepEqual(sent('popup.set-pins').map(({ ids, known }) => ({ ids, known })),
    [{ ids: ['fam', 'not-in-this-browser', 'eng'], known: ['eng', 'fam', 'broken'] }]);
});

test('pins: a sixth pin only says so (no request); the agent refusing one says why', async () => {
  reply = agent({ pins: ['fam', 'a', 'b', 'c', 'd'] });
  const $ = await openPopup();
  await pinButton($, 'eng');
  assert.equal(sent('popup.set-pins').length, 0);
  assert.equal($('snack').textContent, 'You can pin up to 5 vaults. Unpin one first.');

  reply = agent({ over: { 'popup.set-pins': () => fail('rate_limited') } });
  const $2 = await openPopup();
  await pinButton($2, 'eng');
  assert.match($2('snack').textContent, /Too many changes/);
  assert.deepEqual(vaultEntries($2).filter(([, , pinned]) => pinned).map(([name]) => name), ['Family'], 'the pins stay as they were');
});

test('an older desktop app: the filter without pins; one vault: no Vaults section at all', async () => {
  reply = agent({ state: { ...STATE, can_pins: false } });
  let $ = await openPopup();
  assert.equal(sent('popup.pins').length, 0);
  $('filter').click();
  assert.ok($('vault-eng'));
  assert.equal(document.querySelector('.popover .menu-pin'), null, 'no pins');
  $('filter').click();

  reply = agent({ over: { 'popup.pins': () => fail('invalid_params', 'unknown method vaults.pins') } });
  $ = await openPopup();
  $('filter').click();
  assert.equal(document.querySelector('.popover .menu-pin'), null, '"unknown method": no pin UI');
  $('filter').click();

  reply = agent({ state: { ...STATE, items: [ITEMS[0]], vaults: [HOME] }, list: { vaults: [{ ...HOME, open: true }], teams: null } });
  $ = await openPopup();
  $('filter').click();
  assert.equal($('vault-all'), null, 'one vault: nothing to pick');
  assert.ok($('type-all'), 'the Show section stays');
  $('filter').click();
});

test('switcher: the open vault in the header; its menu has the own vaults, the open one first and checked, then the pinned ones', async () => {
  reply = agent({ own: OWN, pins: ['work'] });
  const $ = await openPopup();
  assert.equal($('vault-switch').hidden, false);
  assert.equal($('vault-switch').textContent, 'Personal stuff');
  assert.equal($('vault-switch').title, 'Switch vault');
  $('vault-switch').click();
  assert.deepEqual(menu().map((b) => [nameOf(b), b.getAttribute('aria-checked'), !!b.closest('.menu-row.pinned')]),
    [['Personal stuff', 'true', false], ['Work', 'false', true], ['Old', 'false', false]], 'pins match by vault_id; Team vaults are not listed');
  assert.equal(menu()[2].closest('.menu-row'), null, 'a vault without a vault id has no pin');
  menu()[0].click();
  await flush();
  assert.equal(sent('popup.switch-vault').length, 0, 'the open one: nothing to do');
});

test('switcher: picking another vault asks the app to switch, says to unlock it there, and goes once it is open', async () => {
  let own = OWN;
  reply = agent({ own: () => ok(own), over: { 'popup.switch-vault': (msg) => ok({ switching: msg.id === 'f-work' }) } });
  const $ = await openPopup();
  assert.equal($('switch-tip').hidden, true);
  await pick($, 'vault-switch', 'Old');
  assert.deepEqual(sent('popup.switch-vault'), [{ type: 'popup.switch-vault', id: 'f-old' }]);
  assert.equal($('switch-tip').hidden, true, '`switching: false`: it was open already');
  await pick($, 'vault-switch', 'Work');
  assert.equal($('switch-tip').hidden, false);
  assert.equal($('switch-tip').textContent, 'Unlock Work in the Passyble app');
  // Still the same vault: the note stays when the popup loads again.
  runtimeListener({ type: 'lock_state', locked: false });
  await flush();
  assert.equal($('switch-tip').hidden, false);
  own = { vaults: OWN.vaults.map((v) => ({ ...v, active: v.id === 'f-work' })) };
  runtimeListener({ type: 'lock_state', locked: false });
  await flush();
  assert.equal($('switch-tip').hidden, true);
  assert.equal($('vault-switch').textContent, 'Work');
});

test('switcher: hidden with one own vault, a desktop app without it (asked once), and in browser mode', async () => {
  reply = agent({ own: { vaults: [OWN.vaults[0]] } });
  let $ = await openPopup();
  assert.equal($('vault-switch').hidden, true);

  reply = agent();
  $ = await openPopup();
  assert.equal($('vault-switch').hidden, true);
  runtimeListener({ type: 'lock_state', locked: false });
  await flush();
  assert.equal(sent('popup.own-vaults').length, 1, '`not_supported` once: not asked again');

  reply = agent({ state: { ...STATE, browser: true }, own: OWN });
  $ = await openPopup();
  assert.equal($('vault-switch').hidden, true);
  assert.equal(sent('popup.own-vaults').length, 0);
});
