// Scan QR takes one screenshot of the visible tab (allowed by the toolbar click's `activeTab`); the image never leaves
// this page and is dropped at once. What the views hold lives in this page's memory only, never in extension storage.
import { ext } from '../shared/api.js';
import { icon } from '../shared/svg-icon.js';
import { t } from '../shared/i18n.js';
import { notesCounter } from './notes-counter.js';
import { friendlyError, MSG } from '../shared/messages.js';
import { generatePassword, isPlainPassword, DEFAULT_LENGTH } from '../shared/generator.js';
import { prefersNoSymbols, rememberSymbols } from '../shared/generate-prefs.js';
import { decodeQrImage } from '../shared/qr-decode.js';
import { matchLogins, newLoginFields, pickAuthenticator } from '../shared/otpauth.js';

/** The radio value of "New login for <site>" (login ids are UUIDs: never this). */
const NEW_LOGIN = 'passyble:new-login';
const MAX_NOTE = 20_000;

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
  return node;
}

function hostOf(url) {
  try { return new URL(url).hostname.replace(/^www\./, ''); } catch { return ''; }
}

const PROBLEMS = {
  none: () => t('qaNoQr'),
  not_otp: () => t('qaNotAuthenticator'),
  migration: () => t('qaMigration'),
  hotp: () => t('qaHotp'),
  invalid: () => t('qaInvalidQr'),
};

export function mountQuickActions({ row, body, setHeading, call, request, tab, state, ensureUnlocked, showView, onClose, snack, copy,
  decode = (dataUrl) => decodeQrImage(dataUrl), canEdit = () => true }) {
  let open = null; // 'scan' | 'note' | 'generate' while a view is open
  let busy = false;
  let scanState = null;
  let generated = null;

  const button = (id, name, label, title, onclick) => el('button', { class: 'btn tonal qa-btn', type: 'button', id, title, onclick },
    icon(name, { size: 16 }), el('span', {}, label));
  const scanBtn = button('qa-scan', 'qr', t('qaScanQr'), t('qaScanQrTitle'), () => scan());
  const noteBtn = button('qa-note', 'note', t('qaNewNote'), t('qaNewNoteTitle'), () => note());
  const genBtn = button('qa-generate', 'dice', t('qaGenerate'), t('qaGenerateTitle'), () => generator());
  row.replaceChildren(scanBtn, noteBtn, genBtn);
  row.setAttribute('role', 'group');
  row.setAttribute('aria-label', t('qaGroupLabel'));

  function render({ visible = true } = {}) {
    const st = state() || {};
    scanBtn.hidden = !st.can_edit;
    noteBtn.hidden = !st.can_notes;
    row.hidden = !visible;
  }

  function clear() {
    for (const input of body.querySelectorAll('input, textarea, output')) {
      if ('value' in input) input.value = '';
      input.textContent = '';
    }
    body.replaceChildren();
    open = null;
    busy = false;
    scanState = null;
    generated = null;
  }

  function close() {
    clear();
    onClose();
  }

  function setBusy(btn, on) {
    busy = on;
    btn.disabled = on;
    if (on) btn.setAttribute('aria-busy', 'true');
    else btn.removeAttribute('aria-busy');
  }

  function footer(primaryLabel, onPrimary, { id }) {
    const primary = el('button', { class: 'btn primary', type: 'submit', id }, primaryLabel);
    const cancel = el('button', { class: 'btn', type: 'button', onclick: () => close() }, t('commonCancel'));
    return { primary, bar: el('div', { class: 'ed-actions qa-actions' }, cancel, primary), onPrimary };
  }

  function mount(kind, heading, content, foot) {
    open = kind;
    setHeading(heading);
    const form = el('form', { class: 'ed qa-form', autocomplete: 'off', novalidate: true, onsubmit: (e) => { e.preventDefault(); if (!foot.primary.disabled) foot.onPrimary(foot.primary); } },
      el('div', { class: 'ed-scroll' }, el('div', { class: 'ed-body' }, content)), foot.bar);
    body.replaceChildren(form);
    showView();
  }

  async function scan() {
    if (busy) return;
    const current = tab();
    setBusy(scanBtn, true);
    let texts = null;
    try {
      // The visible tab of the popup's window, as an image only this page sees.
      let shot = await ext.tabs.captureVisibleTab(current.windowId, { format: 'png' });
      try { texts = await decode(shot); } finally { shot = null; }
    } catch {
      texts = null;
    } finally {
      setBusy(scanBtn, false);
    }
    if (!texts) { snack(t('editorCantReadPage')); return; }
    const found = pickAuthenticator(texts);
    if (!found.totp) { snack(PROBLEMS[found.problem]()); return; }
    try {
      await ensureUnlocked();
    } catch (err) {
      if (err?.code !== 'cancelled') snack(friendlyError(err));
      return;
    }
    showScan(found.totp);
  }

  function showScan(info) {
    const st = state() || {};
    const site = hostOf(st.url || tab()?.url || '');
    const logins = (Array.isArray(st.items) ? st.items : []).filter((i) => i && canEdit(i));
    const { candidates, preselect } = matchLogins(logins, info);
    const name = [info.issuer, info.account].filter(Boolean);
    const summary = el('div', { class: 'qa-found' },
      el('span', { class: 'avatar', 'aria-hidden': 'true' }, icon('qr', { size: 18 })),
      el('span', { class: 'item-text' },
        el('span', { class: 'title', id: 'qa-found-title' }, name[0] || t('qaUnnamedCode')),
        name[1] ? el('span', { class: 'sub', id: 'qa-found-account' }, name[1]) : null));
    const choice = el('p', { class: 'ed-note qa-hint', id: 'qa-hint', 'aria-live': 'polite' });
    const radio = (value, title, sub, extra = null) => {
      const input = el('input', { type: 'radio', name: 'qa-target', value, id: `qa-target-${value === NEW_LOGIN ? 'new' : value}` });
      input.addEventListener('change', update);
      return el('li', {}, el('label', { class: 'qa-option' }, input,
        el('span', { class: 'item-text' }, el('span', { class: 'title' }, title, extra), sub ? el('span', { class: 'sub' }, sub) : null)));
    };
    const options = [
      ...candidates.map((i) => radio(i.id, i.title || t('popupUntitledLogin'), i.username || t('commonNoUsername'),
        i.has_totp ? el('span', { class: 'tag' }, t('qaHasTotp')) : null)),
      radio(NEW_LOGIN, t('qaNewLoginFor', site || t('qaThisSite')), info.account || null),
    ];
    const list = el('ul', { class: 'qa-options', role: 'radiogroup', 'aria-labelledby': 'qa-add-to' }, options);
    const preset = preselect || (candidates.length ? null : NEW_LOGIN);
    const presetInput = [...list.querySelectorAll('input')].find((i) => i.value === preset);
    if (presetInput) presetInput.checked = true;
    const foot = footer(t('qaAddTotp'), (btn) => saveTotp(btn, info, site), { id: 'qa-save' });

    function selected() {
      return list.querySelector('input[name="qa-target"]:checked')?.value || null;
    }
    function update() {
      const value = selected();
      foot.primary.disabled = !value;
      const item = candidates.find((i) => i.id === value);
      choice.textContent = !value ? t('qaPickHint') : item?.has_totp ? t('qaReplacesTotp') : '';
    }
    mount('scan', t('qaAddTotpHeading'), [summary,
      el('div', { class: 'ed-field' }, el('span', { class: 'ed-label', id: 'qa-add-to' }, t('qaAddTo')), list, choice)], foot);
    scanState = { candidates, selected };
    update();
    (list.querySelector('input:checked') || list.querySelector('input'))?.focus();
  }

  async function saveTotp(btn, info, site) {
    const target = scanState?.selected();
    if (!target || busy) return;
    setBusy(btn, true);
    const tabId = tab().id;
    try {
      if (target === NEW_LOGIN) {
        const fields = newLoginFields(info, site);
        const res = await call('popup.edit-save', { tabId, fields });
        snack(t('qaTotpSavedNew', res?.title || fields.title || site));
      } else {
        const item = scanState.candidates.find((i) => i.id === target);
        const res = await call('popup.totp-attach', { tabId, id: target, totp: info.uri });
        snack(t('qaTotpAdded', res?.title || item?.title || t('popupUntitledLogin')));
      }
      close();
    } catch (err) {
      if (err?.code === 'cancelled') { setBusy(btn, false); return; }
      snack(err?.code === 'invalid_params' ? t('editorTotpInvalid')
        : err?.code === 'not_supported' ? MSG.editNeedsUpdate : friendlyError(err, { context: 'edit' }));
      setBusy(btn, false);
    }
  }

  async function note() {
    if (busy) return;
    try {
      await ensureUnlocked();
    } catch (err) {
      if (err?.code !== 'cancelled') snack(friendlyError(err));
      return;
    }
    const site = hostOf(state()?.url || tab()?.url || '');
    const title = el('input', { id: 'qa-note-title', type: 'text', autocomplete: 'off', spellcheck: 'false', maxlength: 256,
      placeholder: t('qaNoteUntitled'), 'aria-label': t('qaNoteTitle') });
    const text = el('textarea', { id: 'qa-note-text', class: 'qa-mono', rows: 8, autocomplete: 'off', spellcheck: 'false',
      autocapitalize: 'off', maxlength: MAX_NOTE, placeholder: t('qaNoteTextPlaceholder'), 'aria-label': t('qaNoteText') });
    const suggest = el('button', { class: 'chip qa-suggest', type: 'button', id: 'qa-note-recovery',
      onclick: () => { title.value = site ? t('qaNoteRecoveryFor', site) : t('qaNoteRecovery'); text.focus(); } },
    icon('key', { size: 12 }), t('qaNoteRecovery'));
    const foot = footer(t('commonSave'), (btn) => saveNote(btn, title, text), { id: 'qa-note-save' });
    const update = () => { foot.primary.disabled = !text.value.trim(); };
    text.addEventListener('input', update);
    mount('note', t('qaNoteHeading'), [
      el('div', { class: 'ed-field' }, el('span', { class: 'ed-label', 'aria-hidden': 'true' }, t('qaNoteTitle')),
        el('div', { class: 'ed-box' }, title), el('div', { class: 'qa-suggestions' }, suggest)),
      el('div', { class: 'ed-field' }, el('span', { class: 'ed-label', 'aria-hidden': 'true' }, t('qaNoteText')), text, notesCounter(text)),
      el('p', { class: 'ed-note' }, t('qaNoteHint')),
    ], foot);
    update();
    title.focus();
  }

  async function saveNote(btn, titleEl, textEl) {
    if (busy || !textEl.value.trim()) return;
    setBusy(btn, true);
    try {
      await call('popup.note-create', { fields: { title: titleEl.value.trim() || t('qaNoteUntitled'), notes: textEl.value } });
      snack(t('qaNoteSaved'));
      close();
    } catch (err) {
      if (err?.code !== 'cancelled') snack(err?.code === 'not_supported' ? t('qaNoteNeedsUpdate') : friendlyError(err, { context: 'edit' }));
      setBusy(btn, false);
    }
  }

  let seq = 0; // the latest New password / checkbox change wins

  async function newPassword(out, symbols = true) {
    const mine = ++seq;
    let password = '';
    let byAgent = false;
    try {
      // A plain request: generating never asks to unlock (locked, or no answer: generated here).
      const res = await request('popup.generate', { length: DEFAULT_LENGTH, ...(symbols ? {} : { symbols: false }) });
      if (typeof res?.password === 'string' && res.password && (symbols || isPlainPassword(res.password))) {
        password = res.password;
        byAgent = res.local !== true;
      }
    } catch { /* generated here below */ }
    if (open !== 'generate' || mine !== seq) return;
    if (!password) password = generatePassword({ length: DEFAULT_LENGTH, symbols });
    generated = { password, byAgent };
    out.textContent = password;
  }

  async function generator() {
    if (busy) return;
    const site = tab()?.url || '';
    const out = el('output', { class: 'qa-password qa-mono', id: 'qa-password', 'aria-label': t('qaGeneratedLabel'), 'aria-live': 'polite' });
    const plain = el('input', { type: 'checkbox', id: 'qa-no-symbols' });
    const symbols = () => !plain.checked;
    plain.addEventListener('change', () => {
      rememberSymbols(site, symbols()).catch(() => {});
      newPassword(out, symbols());
    });
    const again = el('button', { class: 'icon-btn', type: 'button', id: 'qa-regenerate', title: t('qaRegenerate'), 'aria-label': t('qaRegenerate'),
      onclick: () => newPassword(out, symbols()) }, icon('sync'));
    const foot = footer(t('qaCopy'), (btn) => copyPassword(btn), { id: 'qa-copy' });
    plain.checked = await prefersNoSymbols(site).catch(() => false);
    mount('generate', t('qaGenerateHeading'), [
      el('div', { class: 'qa-generated' }, out, again),
      el('label', { class: 'gen-plain' }, plain, el('span', {}, t('commonNoSymbols'))),
      el('p', { class: 'ed-note' }, t('qaGenerateHint')),
    ], foot);
    await newPassword(out, symbols());
    foot.primary.focus();
  }

  async function copyPassword(btn) {
    const got = generated;
    if (!got?.password || busy) return;
    setBusy(btn, true);
    try {
      if (got.byAgent) {
        try {
          await request('popup.generate-copy', { password: got.password });
          snack(t('popupCopiedByAppPassword'));
          return;
        } catch { /* an older desktop app, or none: the browser's clipboard */ }
      }
      await copy(got.password, 'password');
    } finally {
      setBusy(btn, false);
    }
  }

  // Never leave a note, a scanned link or a password behind (popup closed or put in the back/forward cache).
  document.defaultView?.addEventListener('pagehide', clear);

  /** The More menu's entry or a keyboard shortcut (background/commands.js) for `kind`: the same as its button, also where the row is hidden. */
  function run(kind) {
    const st = state() || {};
    if (st.read_only) return Promise.resolve();
    if (kind === 'scan') {
      if (st.supported === false) { snack(t('editorCantReadPage')); return Promise.resolve(); }
      if (!st.can_edit) { snack(MSG.editNeedsUpdate); return Promise.resolve(); }
      return scan();
    }
    if (kind === 'note') {
      if (st.can_notes === false) { snack(t('qaNoteNeedsUpdate')); return Promise.resolve(); }
      return note();
    }
    if (kind === 'generate') return generator();
    return Promise.resolve();
  }

  return {
    render,
    run,
    get isOpen() { return open !== null; },
    clear,
    back: close,
  };
}
