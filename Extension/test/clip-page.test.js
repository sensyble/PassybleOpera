// The note chooser of "Save selection to Passyble note" (real src/clip/clip.html + clip.js in jsdom): it takes the
// selection once, lists the notes most recent first, adds to one or saves a new one, unlocks first, and tells an
// older desktop app apart.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const SELECTION = 'Demo quote from a page';
const URL_ = 'https://blog.example/post/42';
const NOTES = [
  { id: 'n-new', title: 'Reading list', updated: 3_000, vault_id: 'home' },
  { id: 'n-team', title: 'Team links', updated: 2_000, vault_id: 'team' },
  { id: 'n-ro', title: 'Policies', updated: 1_500, vault_id: 'view' },
  { id: 'n-old', title: 'Old ideas', updated: 1_000, vault_id: 'home' },
];
const VAULTS = [
  { id: 'home', name: '', home: true, can_edit: true },
  { id: 'team', name: 'Support', home: false, can_edit: true },
  { id: 'view', name: 'Handbook', home: false, can_edit: false },
];

let messages = [];
let replies = {};
let instance = 0;
let listener = null;

function ok(result) { return { ok: true, result }; }
function fail(code, reason) { return { ok: false, error: { code, message: code, ...(reason ? { reason } : {}) } }; }

function defaults(over = {}) {
  return {
    'clip.take': () => ok({ text: SELECTION, url: URL_, site: 'blog.example', title: 'Demo post' }),
    'clip.state': () => ok({ can_append: true, can_create: true, locked: false, notes: NOTES, vaults: VAULTS }),
    'clip.append': (msg) => ok({ id: msg.id, title: NOTES.find((n) => n.id === msg.id)?.title }),
    'clip.create': (msg) => ok({ id: 'n-made', title: msg.title }),
    'clip.unlock': () => ok({ locked: false }),
    ...over,
  };
}

const flush = async () => { for (let i = 0; i < 6; i++) await new Promise((r) => setTimeout(r, 0)); };

async function open(over = {}, search = '?clip=token-1') {
  replies = defaults(over);
  messages = [];
  listener = null;
  const html = readFileSync(new URL('../src/clip/clip.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: `https://extension.test/src/clip/clip.html${search}`, pretendToBeVisual: true });
  const closed = [];
  dom.window.close = () => closed.push(true);
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = dom.window;
  globalThis.location = dom.window.location;
  const mod = await import(`../src/clip/clip.js?instance=${++instance}`);
  await mod.ready;
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  const visible = () => ['loading', 'error', 'locked', 'pick', 'done'].filter((v) => !$(`view-${v}`).hidden);
  const rows = () => [...$('notes').querySelectorAll('button.clip-row')];
  return { window: dom.window, $, closed, visible, rows };
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return replies[msg.type]?.(msg) ?? fail('internal'); },
      onMessage: { addListener: (f) => { listener = f; } },
    },
  };
});

test('chooser: takes the selection once, shows it, lists the notes most recent first', async () => {
  const { $, visible, rows } = await open();
  assert.deepEqual(messages.slice(0, 2), [{ type: 'clip.take', token: 'token-1' }, { type: 'clip.state' }]);
  assert.deepEqual(visible(), ['pick']);
  assert.equal($('preview').textContent, SELECTION);
  assert.equal($('url-row').hidden, false);
  assert.equal($('with-url').checked, false, 'the page address is off by default');
  assert.deepEqual(rows().map((r) => r.dataset.id), ['n-new', 'n-team', 'n-ro', 'n-old']);
  assert.equal(rows()[1].querySelector('.clip-row-sub').textContent, 'Support', 'a shared vault says which');
  assert.equal(rows()[0].querySelector('.clip-row-sub'), null, 'the home vault says nothing');
  assert.equal(rows()[2].disabled, true, 'a view-only note cannot be chosen');
  assert.match(rows()[2].textContent, /can't change/);
  assert.equal($('new-form').hidden, true);
  assert.equal($('update-note').hidden, true);
});

test('chooser: the search narrows by title; nothing found says so', async () => {
  const { window: win, $, rows } = await open();
  $('search').value = 'read';
  $('search').dispatchEvent(new win.Event('input'));
  assert.deepEqual(rows().map((r) => r.dataset.id), ['n-new']);
  $('search').value = 'nothing like it';
  $('search').dispatchEvent(new win.Event('input'));
  assert.equal(rows().length, 0);
  assert.equal($('empty').hidden, false);
  assert.equal($('empty').textContent, 'No notes match.');
});

test('chooser: choosing a note adds the selection; with the box ticked the page address on the next line', async () => {
  const plain = await open();
  plain.rows()[0].click();
  await flush();
  assert.deepEqual(messages.at(-1), { type: 'clip.append', id: 'n-new', text: SELECTION });
  assert.deepEqual(plain.visible(), ['done']);
  assert.equal(plain.$('done-text').textContent, 'Added to Reading list');

  const withUrl = await open();
  withUrl.$('with-url').checked = true;
  withUrl.rows()[1].click();
  await flush();
  assert.deepEqual(messages.at(-1), { type: 'clip.append', id: 'n-team', text: `${SELECTION}\n${URL_}` });
  assert.equal(withUrl.$('done-text').textContent, 'Added to Team links');
});

test('chooser: New note saves the selection under the page title, which can be changed', async () => {
  const { $, visible } = await open();
  $('new-note').click();
  assert.equal($('new-form').hidden, false);
  assert.equal($('pick-list').hidden, true);
  assert.equal($('new-title').value, 'Demo post', 'prefilled with the page title');
  $('new-title').value = '  Quotes  ';
  $('new-save').click();
  await flush();
  assert.deepEqual(messages.at(-1), { type: 'clip.create', title: 'Quotes', text: SELECTION });
  assert.deepEqual(visible(), ['done']);
  assert.equal($('done-text').textContent, 'Saved as a new note');
});

test('chooser: New note can be left again for the list', async () => {
  const { $ } = await open();
  $('new-note').click();
  $('new-cancel').click();
  assert.equal($('new-form').hidden, true);
  assert.equal($('pick-list').hidden, false);
});

test('chooser: locked without a kept list shows Unlock first, then the notes', async () => {
  let locked = true;
  const { $, visible, rows } = await open({
    'clip.state': () => ok(locked
      ? { can_append: true, can_create: true, locked: true, notes: [] }
      : { can_append: true, can_create: true, locked: false, notes: NOTES, vaults: VAULTS }),
    'clip.unlock': () => { locked = false; return ok({ locked: false }); },
  });
  assert.deepEqual(visible(), ['locked']);
  $('unlock').click();
  await flush();
  assert.ok(messages.some((m) => m.type === 'clip.unlock'));
  assert.deepEqual(visible(), ['pick']);
  assert.equal(rows().length, 4);
});

test('chooser: an unlock the user declines leaves the locked view without an error', async () => {
  const { $, visible } = await open({
    'clip.state': () => ok({ can_append: true, can_create: true, locked: true, notes: [] }),
    'clip.unlock': () => fail('cancelled'),
  });
  $('unlock').click();
  await flush();
  assert.deepEqual(visible(), ['locked']);
  assert.equal($('unlock-msg').textContent, '');
  assert.equal($('unlock').disabled, false);
});

test('chooser: unlocked elsewhere while it waits reloads the notes', async () => {
  let locked = true;
  const { visible } = await open({
    'clip.state': () => ok(locked
      ? { can_append: true, can_create: true, locked: true, notes: [] }
      : { can_append: true, can_create: true, locked: false, notes: NOTES, vaults: VAULTS }),
  });
  assert.deepEqual(visible(), ['locked']);
  locked = false;
  listener({ type: 'lock_state', locked: false });
  await flush();
  assert.deepEqual(visible(), ['pick']);
});

test('chooser: a read-only vault and a full note are explained; a declined check says nothing', async () => {
  let answer = fail('read_only');
  const { $, visible, rows } = await open({ 'clip.append': () => answer });
  rows()[0].click();
  await flush();
  assert.deepEqual(visible(), ['pick']);
  assert.match($('msg').textContent, /not change them/);
  assert.ok($('msg').classList.contains('error'));
  assert.equal(rows()[0].disabled, false, 'buttons work again');

  answer = fail('invalid_params');
  rows()[0].click();
  await flush();
  assert.equal($('msg').textContent, 'That note is full. Save the selection as a new note.');

  answer = fail('cancelled');
  rows()[0].click();
  await flush();
  assert.equal($('msg').textContent, '');
});

test('chooser: an older desktop app offers New note only, with "Update the Passyble app"', async () => {
  const { $, visible } = await open({ 'clip.state': () => ok({ can_append: false, can_create: true, locked: false, notes: [] }) });
  assert.deepEqual(visible(), ['pick']);
  assert.equal($('update-note').hidden, false);
  assert.equal($('update-note').textContent, 'Update the Passyble app to add to a note.');
  assert.equal($('pick-list').hidden, true);
  assert.equal($('new-form').hidden, false);
  assert.equal($('new-cancel').hidden, true, 'nothing to go back to');
  $('new-save').click();
  await flush();
  assert.equal(messages.at(-1).type, 'clip.create');
});

test('chooser: an app that can neither add nor save notes says to update it', async () => {
  const { $, visible } = await open({ 'clip.state': () => ok({ can_append: false, can_create: false, locked: false, notes: [] }) });
  assert.deepEqual(visible(), ['error']);
  assert.equal($('error-text').textContent, 'Update the Passyble app to save notes from the browser.');
});

test('chooser: an append the app refuses as too new for it says to update', async () => {
  const { $, rows } = await open({ 'clip.append': () => fail('not_supported', 'needs_update') });
  rows()[0].click();
  await flush();
  assert.equal($('msg').textContent, 'Update the Passyble app to add to a note.');
});

test('chooser: a spent or unknown selection says to select the text again', async () => {
  const { $, visible } = await open({ 'clip.take': () => fail('not_found') });
  assert.deepEqual(visible(), ['error']);
  assert.match($('error-text').textContent, /Select the text again/);
  assert.ok(!messages.some((m) => m.type === 'clip.state'));
});

test('chooser: the desktop app not running is said in words; Close and Escape close the window', async () => {
  const { window: win, $, visible, closed } = await open({ 'clip.state': () => fail('agent_unavailable') });
  assert.deepEqual(visible(), ['error']);
  assert.ok($('error-text').textContent.length > 0);
  $('error-close').click();
  assert.equal(closed.length, 1);
  win.document.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape' }));
  assert.equal(closed.length, 2);
});

test('chooser: a selection too long for a new note is refused before anything is sent', async () => {
  const { $ } = await open({ 'clip.take': () => ok({ text: 'x'.repeat(20_001), url: '', site: '', title: '' }) });
  assert.equal($('url-row').hidden, true, 'no page address to add');
  $('new-note').click();
  $('new-save').click();
  await flush();
  assert.ok(!messages.some((m) => m.type === 'clip.create'));
  assert.equal($('msg').textContent, 'The selection is too long for a note.');
});
