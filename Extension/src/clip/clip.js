// The chooser of "Save selection to Passyble note". It takes the selection from the background once (its token is
// then spent), keeps it in this page's memory only and sends it to the agent: as a new line of a note
// (`clip.append`) or as a new note (`clip.create`). Nothing here logs or stores it.
import { ext } from '../shared/api.js';
import { applyI18n, t } from '../shared/i18n.js';
import { fillWordmark, hydrateIcons, icon } from '../shared/svg-icon.js';
import { friendlyError } from '../shared/messages.js';
import { MAX_NOTE_CHARS, charCount, clipText, titleMatches } from '../shared/note-clip.js';

export const CLOSE_AFTER_MS = 1600;
const VIEWS = ['loading', 'error', 'locked', 'pick', 'done'];

const page = globalThis.window;
const $ = (id) => document.getElementById(id);

let clip = null;  // { text, url, site, title }
let state = null; // clip.state: { can_append, can_create, locked, notes, vaults }
let vaults = new Map();
let busy = false;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children) if (c !== null && c !== undefined && c !== false) node.append(c);
  return node;
}

async function send(type, payload = {}) {
  const res = await ext.runtime.sendMessage({ type, ...payload });
  if (res?.ok) return res.result;
  const err = new Error(res?.error?.message || 'No response');
  err.code = res?.error?.code || 'internal';
  err.reason = res?.error?.reason;
  throw err;
}

function closeWindow() {
  try { page.close(); } catch { /* not a browser window (tests) */ }
}

function show(view) {
  for (const v of VIEWS) $(`view-${v}`).hidden = v !== view;
}

function say(text, error = false) {
  $('msg').textContent = text || '';
  $('msg').classList.toggle('error', !!error);
}

function fail(text) {
  $('error-text').textContent = text;
  show('error');
  $('error-close').focus();
}

function done(text) {
  $('done-text').textContent = text;
  show('done');
  $('done-close').focus();
  setTimeout(closeWindow, CLOSE_AFTER_MS);
}

function setBusy(on) {
  busy = on;
  for (const node of $('view-pick').querySelectorAll('button, input')) {
    if (on) {
      node.dataset.wasDisabled = node.disabled ? '1' : '';
      node.disabled = true;
    } else {
      node.disabled = node.dataset.wasDisabled === '1';
    }
  }
}

/** What goes into the note: the selection, and the page address when asked for. */
function textToSave() {
  return clipText(clip.text, clip.url, $('with-url').checked);
}

function errorText(err, append) {
  if (err?.code === 'not_supported') return append ? t('clipAppendNeedsUpdate') : t('qaNoteNeedsUpdate');
  // Lengths are checked here first: the agent's `invalid_params` is a note that is full, or a title it refused.
  if (err?.code === 'invalid_params') return append ? t('clipNoteFull') : t('clipTooLong');
  return friendlyError(err, { context: 'edit' });
}

const editable = (note) => vaults.get(note.vault_id)?.can_edit !== false;

function subline(note) {
  if (!editable(note)) return t('clipViewOnly');
  const vault = vaults.get(note.vault_id);
  return vault && !vault.home ? vault.name || '' : '';
}

function row(note) {
  const sub = subline(note);
  return el('li', {}, el('button', { class: 'clip-row', type: 'button', 'data-id': note.id, disabled: !editable(note),
    onclick: () => append(note) },
  el('span', { class: 'clip-row-icon', 'aria-hidden': 'true' }, icon('note')),
  el('span', { class: 'clip-row-text' }, el('span', { class: 'clip-row-title' }, note.title || t('popupUntitled')),
    sub ? el('span', { class: 'clip-row-sub' }, sub) : null)));
}

function renderNotes() {
  const all = state?.notes || [];
  const shown = all.filter((n) => titleMatches(n.title, $('search').value));
  $('notes').replaceChildren(...shown.map(row));
  $('empty').hidden = shown.length > 0;
  $('empty').textContent = all.length ? t('clipNoMatch') : t('clipNoNotes');
}

function showForm(on) {
  $('pick-list').hidden = on;
  $('new-form').hidden = !on;
  say('');
  if (on) {
    $('new-title').focus();
    $('new-title').select();
  } else {
    $('search').focus();
  }
}

function showPick() {
  vaults = new Map((state.vaults || []).map((v) => [v.id, v]));
  const onlyNew = !state.can_append;
  $('update-note').hidden = !onlyNew;
  $('update-note').textContent = onlyNew ? t('clipAppendNeedsUpdate') : '';
  $('new-cancel').hidden = onlyNew;
  renderNotes();
  show('pick');
  showForm(onlyNew);
}

async function load() {
  show('loading');
  try {
    state = await send('clip.state');
  } catch (err) {
    fail(friendlyError(err));
    return;
  }
  if (!state.can_append && !state.can_create) {
    fail(t('clipNeedsUpdate'));
    return;
  }
  // Locked without a kept list: unlock first. With one, choosing a note unlocks (the background asks).
  if (state.can_append && state.locked && !(state.notes || []).length) {
    $('unlock-msg').textContent = '';
    show('locked');
    $('unlock').focus();
    return;
  }
  showPick();
}

async function append(note) {
  if (busy) return;
  const text = textToSave();
  if (charCount(text) > MAX_NOTE_CHARS) { say(t('clipTooLong'), true); return; }
  say('');
  setBusy(true);
  try {
    const res = await send('clip.append', { id: note.id, text });
    done(t('clipAdded', res?.title || note.title || t('popupUntitled')));
  } catch (err) {
    setBusy(false);
    if (err?.code !== 'cancelled') say(errorText(err, true), true);
  }
}

async function create(event) {
  event?.preventDefault();
  if (busy) return;
  const text = textToSave();
  if (charCount(text) > MAX_NOTE_CHARS) { say(t('clipTooLong'), true); return; }
  const title = $('new-title').value.trim() || t('qaNoteUntitled');
  say('');
  setBusy(true);
  try {
    await send('clip.create', { title, text });
    done(t('clipSavedNew'));
  } catch (err) {
    setBusy(false);
    if (err?.code !== 'cancelled') say(errorText(err, false), true);
  }
}

async function unlock() {
  if (busy) return;
  busy = true;
  $('unlock').disabled = true;
  $('unlock-msg').textContent = '';
  try {
    await send('clip.unlock');
    busy = false;
    await load();
  } catch (err) {
    if (err?.code !== 'cancelled') $('unlock-msg').textContent = friendlyError(err, { context: 'unlock' });
  } finally {
    busy = false;
    $('unlock').disabled = false;
  }
}

async function start() {
  applyI18n();
  hydrateIcons(document.body);
  fillWordmark($('logo'));
  $('error-close').addEventListener('click', closeWindow);
  $('done-close').addEventListener('click', closeWindow);
  $('unlock').addEventListener('click', unlock);
  $('new-note').addEventListener('click', () => showForm(true));
  $('new-cancel').addEventListener('click', () => showForm(false));
  $('new-form').addEventListener('submit', create);
  $('search').addEventListener('input', renderNotes);
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !busy) closeWindow();
  });
  // Unlocked elsewhere (the desktop app, the popup) while this waits on its locked view.
  ext.runtime.onMessage?.addListener((msg) => {
    if (msg?.type === 'lock_state' && msg.locked === false && !busy && !$('view-locked').hidden) load();
  });
  const token = new URLSearchParams(globalThis.location?.search || '').get('clip') || '';
  try {
    clip = await send('clip.take', { token });
  } catch {
    fail(t('clipGone'));
    return;
  }
  $('preview').textContent = clip.text;
  $('url-row').hidden = !clip.url;
  $('new-title').value = clip.title || '';
  $('new-title').placeholder = t('qaNoteUntitled');
  await load();
}

export const ready = start();
