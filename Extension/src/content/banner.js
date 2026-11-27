// Save / update login banner, shown in the top frame after a form submission.
// It never holds the password: a closed shadow root hides an input's value, not its key events, so
// "Edit" fields live in an extension-origin frame (src/save/edit.html) that talks to the background.
// The banner only passes that frame a one-time token; if it can't load there is no Edit section.
import { ext } from '../shared/api.js';
import { createHost, createClickGuard, h, passWordmark, uiIcon, uiIntact } from './ui-common.js';
import { friendlyError } from '../shared/messages.js';
import { t } from '../shared/i18n.js';
import { issueTexts } from '../shared/password-issues.js';

const EDIT_PATH = 'src/save/edit.html';
const FRAME_READY_MS = 3000; // the frame has its values by then, or the Edit section goes away
const FLUSH_MS = 5000;       // the frame stored its values for Save by then, or Save fails

const CSS = `
/* The header (logo, title, the site, the account with Edit), the check, the Edit fields, then Not now and
   Save side by side (equal pills), Never. */
.banner { position: fixed; top: 12px; right: 12px; width: 340px; max-width: calc(100vw - 24px); padding: 16px 16px 12px;
  animation: in .16s ease-out; }
@keyframes in { from { transform: translateY(-6px); opacity: 0; } to { transform: none; opacity: 1; } }
.row { display: flex; align-items: flex-start; gap: 12px; }
.brand { display: flex; align-items: center; justify-content: space-between; margin: -2px -6px 10px 0; }
.text { flex: 1; min-width: 0; }
.title { font-weight: 700; font-size: 17px; line-height: 1.25; letter-spacing: -0.02em; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
/* The site: never cut (it wraps); the account: one line, cut at the end. */
.sub { margin-top: 2px; color: var(--text-2); font-size: var(--fs-body); overflow-wrap: anywhere; }
.who { display: flex; align-items: center; gap: 10px; min-width: 0; color: var(--text-2); font-size: var(--fs-body); }
.vault { display: flex; align-items: center; gap: 8px; margin-top: 4px; color: var(--text-2); font-size: var(--fs-body); }
.vault-select { min-width: 0; max-width: 220px; font: inherit; color: var(--text); background: var(--surface-raised);
  border: 1px solid var(--border, rgba(127, 127, 127, .35)); border-radius: 6px; padding: 2px 6px; }
.user { min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }

.fields { margin: 12px 0 0; }
.edit-frame { display: block; width: 100%; height: 140px; border: 0; margin: 0; padding: 0; background: transparent; color-scheme: normal; }
/* Edit: a 13px semibold text button after the account; the fields open under the header. */
.edit { flex: none; display: inline-flex; align-items: center; gap: 2px; min-height: 22px; margin: 0; padding: 0 2px; border: 0; border-radius: 4px;
  background: none; color: var(--accent); font-size: var(--fs-body); font-weight: 600; }
.edit:hover { text-decoration: underline; text-underline-offset: 3px; }
.edit:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 2px; }
.edit svg { transition: transform .12s; }
.edit[aria-expanded="true"] svg { transform: rotate(180deg); }
.actions { display: grid; grid-template-columns: 1fr 1fr; gap: 8px; margin: 14px 0 0; }
.actions > .btn { min-height: 40px; font-size: var(--fs-md); }
/* Never for this site: the tertiary link style, centred under the buttons. */
.never { display: block; min-height: 30px; margin: 8px auto 0; padding: 0 4px; border: 0; border-radius: 4px; background: none;
  color: var(--accent); font-size: var(--fs-body); font-weight: 600; text-decoration: underline; text-underline-offset: 4px;
  text-decoration-thickness: 1.5px; cursor: pointer; }
.never:hover { text-decoration-thickness: 2px; }
.never:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 2px; }
.never:disabled { opacity: .5; cursor: default; }
/* The password check: secondary text on a neutral inset, a small icon per line. */
.issues { display: grid; gap: 4px; margin: 12px 0 0; padding: 8px 12px; border-radius: 10px; background: var(--inset); list-style: none;
  color: var(--text-2); font-size: var(--fs-body); }
.issues[hidden] { display: none; }
.issues li { display: flex; align-items: flex-start; gap: 8px; overflow-wrap: anywhere; text-wrap: pretty; }
.issues li svg { flex: none; margin-top: 2px; }
/* The page looks like one of the user's sites without being it: the danger colours, above the check. */
.lookalike { display: flex; align-items: flex-start; gap: 8px; margin: 12px 0 0; padding: 8px 12px; border-radius: 10px;
  background: var(--danger-soft); color: var(--danger); font-size: var(--fs-body); overflow-wrap: anywhere; text-wrap: pretty; }
.lookalike svg { flex: none; margin-top: 2px; }
/* An international (xn--) address: a calm note under the site, no alarm. */
.intl { color: var(--text-3); font-size: var(--fs-sm); margin-top: 2px; }
.status { color: var(--text-2); font-size: var(--fs-sm); margin: 10px 0 0; text-align: center; }
.status:empty { display: none; }
`;

function isPunycodeHost(host) {
  return typeof host === 'string' && host.toLowerCase().split('.').some((label) => label.startsWith('xn--'));
}

function extensionOrigin() {
  try { return String(ext.runtime.getURL('') || '').replace(/\/+$/, ''); } catch { return ''; }
}

function flushTag() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
}

/** `mode`: 'save' | 'update' | 'username'. `labels`: text overrides for the card banner. */
export function showSaveBanner({ mode, host, username, token = '', editable = false, title, onSave, onDismiss, onNever, check = null,
  onCheck = null, lookalike = '', timeoutMs = 45_000, vaults = null, vault_name: vaultName = null, labels = null,
  editPath = EDIT_PATH }) {
  const ui = createHost('banner', CSS);
  const logo = passWordmark();
  const update = mode === 'update' || mode === 'username';
  const heading = labels?.heading || t({ update: 'bannerUpdatePassword', username: 'bannerUpdateUsername' }[mode] || 'bannerSave');
  const doneText = labels?.done || t({ update: 'bannerPasswordUpdated', username: 'bannerUsernameUpdated' }[mode] || 'bannerSaved');
  const status = h('div', { class: 'status', role: 'status' });
  const saveBtn = h('button', { class: 'btn primary', type: 'button' }, update ? t('bannerUpdate') : t('commonSave'));
  const laterBtn = h('button', { class: 'btn', type: 'button' }, t('bannerNotNow'));
  const closeBtn = h('button', { class: 'icon-btn x', type: 'button', title: t('bannerNotNow'), 'aria-label': t('commonClose') }, uiIcon('close'));
  const subtitle = host;
  const who = username || t('commonNoUsername');
  const origin = extensionOrigin();

  const fields = editable && typeof token === 'string' && token && origin ? h('div', { class: 'fields', hidden: true }) : null;
  const editBtn = fields
    ? h('button', { class: 'edit', type: 'button', 'aria-expanded': 'false' }, t('bannerEdit'), uiIcon('chevronDown', { size: 12 }))
    : null;
  const neverBtn = onNever ? h('button', { class: 'never', type: 'button' }, t('bannerNever')) : null;
  const issuesEl = h('ul', { class: 'issues', 'aria-label': t('issueListLabel'), hidden: true });
  const showIssues = (result) => {
    const list = issueTexts(result);
    issuesEl.replaceChildren(...list.map((i) => h('li', { class: i.severity }, uiIcon('alert', { size: 14 }), h('span', {}, i.text))));
    issuesEl.hidden = list.length === 0 || (!!fields && !fields.hidden);
  };
  showIssues(check);
  const subEl = h('div', { class: 'sub' }, subtitle);
  subEl.title = t('bannerUserOnSite', who, host);
  const whoText = typeof labels?.who === 'string' ? labels.who : update && title ? `${title} · ${who}` : who;
  const userEl = h('span', { class: 'user', title: whoText }, whoText);
  const whoEl = h('div', { class: 'who' }, userEl, editBtn);
  const noteEl = typeof labels?.note === 'string' && labels.note ? h('div', { class: 'intl' }, labels.note) : null;
  const lookalikeEl = typeof lookalike === 'string' && lookalike
    ? h('div', { class: 'lookalike', role: 'alert' }, uiIcon('alert', { size: 14 }), h('span', {}, t('bannerLookalike', host, lookalike)))
    : null;
  const intlEl = !lookalikeEl && isPunycodeHost(host) ? h('div', { class: 'intl' }, t('commonIntlAddress')) : null;
  // The background only accepts a vault it offered; an update stays in its login's vault.
  const choices = vaults && Array.isArray(vaults.vaults) && vaults.vaults.length > 1 ? vaults : null;
  const vaultSel = choices
    ? h('select', { class: 'vault-select', 'aria-label': t('bannerSaveIn') },
      ...choices.vaults.map((v) => h('option', { value: String(v.id), ...(v.id === choices.selected ? { selected: '' } : {}) },
        String(v.name || t('bannerMyVault')))))
    : null;
  const vaultEl = vaultSel
    ? h('label', { class: 'vault' }, h('span', {}, t('bannerSaveIn')), vaultSel)
    : (update && typeof vaultName === 'string' && vaultName ? h('div', { class: 'vault' }, t('bannerInVault', vaultName)) : null);
  const box = h('div', { class: 'banner card', role: 'dialog', 'aria-label': 'Passyble' },
    h('div', { class: 'brand' }, logo, closeBtn),
    h('div', { class: 'row' },
      h('div', { class: 'text' },
        h('div', { class: 'title' }, heading),
        subEl,
        intlEl,
        whoEl,
        noteEl,
        vaultEl)),
    lookalikeEl,
    issuesEl,
    fields,
    h('div', { class: 'actions' }, laterBtn, saveBtn),
    neverBtn,
    status);
  ui.root.append(h('div', { class: 'pass-ui' }, box));
  let guard = null; // clickjacking guard, created on mount

  let done = false;
  let saving = false;
  let checkSeq = 0;
  let timer = setTimeout(() => { onDismiss(); close(); }, timeoutMs);

  let frame = null;      // { el, loaded, timer, watch, flushes: Map<tag, { resolve, reject, timer }> }
  let frameUsed = false; // the background may hold edits for Save

  const post = (data) => {
    // targetOrigin: only the extension page in the frame can read it, never the page.
    try { frame?.el.contentWindow?.postMessage(data, origin); } catch { /* gone */ }
  };

  const makeFrame = () => {
    const el = h('iframe', { class: 'edit-frame', title: labels?.frameTitle || t('bannerEditFrameTitle') });
    el.src = ext.runtime.getURL(editPath);
    const made = { el, loaded: false, timer: 0, watch: 0, flushes: new Map() };
    // A page that blocks extension frames gets no Edit section; Save still works.
    made.timer = setTimeout(() => { if (frame === made && !made.loaded) editFailed(); }, FRAME_READY_MS);
    // The page must not draw over the banner or make it see-through while something is typed in it.
    made.watch = setInterval(() => {
      if (frame !== made || done) return;
      if (!el.isConnected || (!fields.hidden && !uiIntact(ui.host, box))) editFailed();
    }, 250);
    frame = made;
    fields.append(el);
  };

  const dropFrame = () => {
    if (!frame) return;
    const gone = frame;
    frame = null;
    clearTimeout(gone.timer);
    clearInterval(gone.watch);
    for (const f of gone.flushes.values()) {
      clearTimeout(f.timer);
      f.reject(Object.assign(new Error('The edit fields went away'), { code: 'internal' }));
    }
    gone.el.remove();
  };

  /** Drops the Edit section; what the frame already stored still counts for Save. */
  function editFailed() {
    dropFrame();
    fields.hidden = true;
    editBtn.hidden = true;
    editBtn.setAttribute('aria-expanded', 'false');
    refreshIssues();
  }

  const focusFrame = () => {
    if (!frame?.loaded) return;
    try { frame.el.focus({ preventScroll: true }); } catch { /* gone */ }
    post({ passybleSave: 'focus' });
  };

  /** Asks the frame to store what it shows, so Save right after typing saves what was typed. */
  const flush = () => {
    if (!frame?.loaded) return Promise.resolve();
    const { flushes } = frame;
    const tag = flushTag();
    return new Promise((resolve, reject) => {
      const f = { resolve, reject, timer: 0 };
      f.timer = setTimeout(() => {
        flushes.delete(tag);
        reject(Object.assign(new Error('timeout'), { code: 'timeout' }));
      }, FLUSH_MS);
      flushes.set(tag, f);
      post({ passybleSave: 'flush', seq: tag });
    });
  };

  function refreshIssues() {
    if (done) return;
    if (!frameUsed || !onCheck) { showIssues(check); return; }
    const seq = ++checkSeq;
    flush().then(() => onCheck()).catch(() => null)
      .then((result) => { if (seq === checkSeq && !done) showIssues(result); });
  }

  const onFrameMessage = (e) => {
    if (!frame || e.source !== frame.el.contentWindow || e.origin !== origin) return;
    const data = e.data && typeof e.data === 'object' ? e.data : {};
    const height = Number(data.height);
    if (height > 0) frame.el.style.height = `${Math.min(260, Math.max(40, Math.ceil(height)))}px`;
    const what = data.passybleSave;
    if (what === 'ready') {
      post({ passybleSave: 'init', token });
    } else if (what === 'loaded') {
      frame.loaded = true;
      frameUsed = true;
      clearTimeout(frame.timer);
      if (!fields.hidden) focusFrame();
    } else if (what === 'flushed') {
      const f = frame.flushes.get(typeof data.seq === 'string' ? data.seq : '');
      if (!f) return;
      frame.flushes.delete(data.seq);
      clearTimeout(f.timer);
      if (data.ok === true) f.resolve();
      else f.reject(Object.assign(new Error('Not stored'), { code: typeof data.code === 'string' ? data.code : 'internal' }));
    } else if (what === 'submit') {
      save(e); // Enter in the fields, through the same guard
    } else if (what === 'escape') {
      if (!done && !saving) { onDismiss(); close(); }
    }
  };
  if (fields) window.addEventListener('message', onFrameMessage);

  editBtn?.addEventListener('mousedown', (e) => e.preventDefault());
  editBtn?.addEventListener('click', (e) => {
    if (!e.isTrusted || done) return;
    const open = fields.hidden;
    fields.hidden = !open;
    editBtn.setAttribute('aria-expanded', String(open));
    if (open) {
      clearTimeout(timer);
      issuesEl.hidden = true; // the frame shows its own check
      if (!frame) makeFrame();
      else focusFrame();
    } else {
      refreshIssues();
    }
  });

  const close = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    dropFrame();
    if (fields) window.removeEventListener('message', onFrameMessage);
    guard?.disconnect();
    ui.remove();
  };

  const disableAll = () => {
    saveBtn.disabled = laterBtn.disabled = true;
    if (neverBtn) neverBtn.disabled = true;
    if (editBtn) editBtn.disabled = true;
    post({ passybleSave: 'disable' });
  };

  const save = async (e) => {
    // A Save the user didn't see (transparent or covered banner) could overwrite a stored password.
    if (done || saving || !guard?.allows(e)) return;
    saving = true;
    clearTimeout(timer);
    status.textContent = t('bannerSaving');
    try {
      const stored = flush(); // before 'disable'
      disableAll();
      await stored;
      const res = await onSave(vaultSel ? vaultSel.value : undefined);
      status.textContent = res?.unchanged ? t('bannerAlreadySaved')
        : (labels?.results?.[res?.action] || (labels ? '' : resultText(res?.action)) || doneText);
      setTimeout(close, 1400);
    } catch (err) {
      status.textContent = err?.code === 'cancelled' ? t('errCancelled') : t('bannerSaveFailed', friendlyError(err));
      setTimeout(close, err?.code === 'cancelled' ? 3000 : 7000);
    }
  };
  saveBtn.addEventListener('click', save);
  const dismiss = (e) => {
    if (!e.isTrusted) return;
    onDismiss();
    close();
  };
  laterBtn.addEventListener('click', dismiss);
  neverBtn?.addEventListener('click', async (e) => {
    if (done || saving || !e.isTrusted || !guard?.allows(e)) return;
    saving = true;
    disableAll();
    clearTimeout(timer);
    try {
      await onNever();
      status.textContent = labels?.neverDone || t('bannerNeverDone');
      setTimeout(close, 2600);
    } catch (err) {
      status.textContent = t('bannerNeverFailed', friendlyError(err));
      setTimeout(close, 5000);
    }
  });
  closeBtn.addEventListener('click', dismiss);
  ui.mount();
  guard = createClickGuard(ui.host, box);
  return { close };
}

/** The outcome when edits led the agent to another action than the banner offered. */
function resultText(action) {
  const key = { update_password: 'bannerPasswordUpdated', update_username: 'bannerUsernameUpdated', save_new: 'bannerSaved' }[action];
  return key ? t(key) : '';
}

const CROSS_CSS = `
.cross-actions { display: grid; gap: 8px; margin: 14px 0 0; }
.cross-actions > .btn { min-height: 38px; font-size: var(--fs-md); }
.cross-actions > .btn.ghost { border-color: transparent; background: transparent; color: var(--accent); }
.cross-actions > .btn.ghost:hover { background: var(--fill-hover); }
.hint { margin: 10px 0 0; color: var(--text-3); font-size: var(--fs-sm); text-wrap: pretty; }
`;

/** After another site's login was filled here. No `onDismiss` on timeout: the card comes back after submit. */
export function showCrossBanner({ host, site = '', username = '', title = '', lookalike = '', can_add: canAdd = true,
  can_copy: canCopy = true, onAdd, onCopy, onDismiss, timeoutMs = 45_000 }) {
  const ui = createHost('banner', CSS + CROSS_CSS);
  const like = typeof lookalike === 'string' ? lookalike : '';
  const who = `${username || t('commonNoUsername')} · ${t('crossSavedFor', site || title || '?')}`;
  const status = h('div', { class: 'status', role: 'status' });
  const addBtn = canAdd ? h('button', { class: like ? 'btn' : 'btn primary', type: 'button' }, t('crossAdd', host)) : null;
  const copyBtn = canCopy ? h('button', { class: 'btn', type: 'button' }, t('crossCopy', host)) : null;
  const laterBtn = h('button', { class: 'btn ghost', type: 'button' }, t('bannerNotNow'));
  const closeBtn = h('button', { class: 'icon-btn x', type: 'button', title: t('bannerNotNow'), 'aria-label': t('commonClose') }, uiIcon('close'));
  const lookalikeEl = like
    ? h('div', { class: 'lookalike', role: 'alert' }, uiIcon('alert', { size: 14 }), h('span', {}, t('crossLookalike', host, like)))
    : null;
  const intlEl = !lookalikeEl && isPunycodeHost(host) ? h('div', { class: 'intl' }, t('commonIntlAddress')) : null;
  const box = h('div', { class: 'banner card', role: 'dialog', 'aria-label': 'Passyble' },
    h('div', { class: 'brand' }, passWordmark(), closeBtn),
    h('div', { class: 'row' },
      h('div', { class: 'text' },
        h('div', { class: 'title', title: t('crossTitle', host) }, t('crossTitle', host)),
        intlEl,
        h('div', { class: 'who' }, h('span', { class: 'user', title: who }, who)))),
    lookalikeEl,
    h('div', { class: 'cross-actions' }, addBtn, copyBtn, laterBtn),
    canAdd && canCopy ? h('p', { class: 'hint' }, t('crossHint')) : null,
    status);
  ui.root.append(h('div', { class: 'pass-ui' }, box));
  return runActionCard(ui, box, { status, closeBtn, laterBtn, onDismiss, timeoutMs, actions: [
    [addBtn, onAdd, (res) => t('crossAdded', host, res?.title || title || site)],
    [copyBtn, onCopy, (res) => (res?.unchanged ? t('bannerAlreadySaved') : t('crossCopied'))],
  ] });
}

/** Wires and mounts a cross / changed card. `actions`: [button or null, action, doneText(result)]. */
function runActionCard(ui, box, { status, closeBtn, laterBtn, onDismiss, timeoutMs, actions }) {
  let guard = null;
  let done = false;
  let busy = false;
  const timer = setTimeout(() => close(), timeoutMs);

  const close = () => {
    if (done) return;
    done = true;
    clearTimeout(timer);
    guard?.disconnect();
    ui.remove();
  };
  const run = (action, doneText) => async (e) => {
    // Changes the vault: only a trusted click on a visible card.
    if (done || busy || !guard?.allows(e)) return;
    busy = true;
    clearTimeout(timer);
    for (const b of [...actions.map(([btn]) => btn), laterBtn]) if (b) b.disabled = true;
    status.textContent = t('bannerSaving');
    try {
      const res = await action();
      status.textContent = doneText(res);
      setTimeout(close, 1600);
    } catch (err) {
      status.textContent = err?.code === 'cancelled' ? t('errCancelled') : t('bannerSaveFailed', friendlyError(err));
      setTimeout(close, err?.code === 'cancelled' ? 3000 : 7000);
    }
  };
  for (const [btn, action, doneText] of actions) btn?.addEventListener('click', run(action, doneText));
  const dismiss = (e) => {
    if (!e.isTrusted || done || busy) return;
    onDismiss();
    close();
  };
  laterBtn.addEventListener('click', dismiss);
  closeBtn.addEventListener('click', dismiss);
  ui.mount();
  guard = createClickGuard(ui.host, box);
  return { close };
}

const CHANGED_CSS = `
.changes { display: grid; gap: 4px; margin: 12px 0 0; padding: 8px 12px; border-radius: 10px; background: var(--inset); list-style: none;
  color: var(--text); font-size: var(--fs-body); }
.changes li { display: flex; align-items: flex-start; gap: 8px; overflow-wrap: anywhere; text-wrap: pretty; }
.changes li svg { flex: none; margin-top: 2px; color: var(--text-2); }
.note { margin: 10px 0 0; color: var(--text-2); font-size: var(--fs-body); overflow-wrap: anywhere; text-wrap: pretty; }
`;

/** After a submit with other values than Passyble filled; never shows the password itself. */
export function showChangedBanner({ host, title = '', username = '', new_username: newUsername = '', password_changed: passwordChanged = false,
  cross = false, site = '', lookalike = '', can_update: canUpdate = true, can_copy: canCopy = true, read_only: readOnly = false,
  onUpdate, onSaveNew, onDismiss, timeoutMs = 45_000 }) {
  const ui = createHost('banner', CSS + CROSS_CSS + CHANGED_CSS);
  const like = typeof lookalike === 'string' ? lookalike : '';
  const heading = t('changedTitle');
  const whoName = username || t('commonNoUsername');
  const who = title ? `${title} · ${whoName}` : whoName;
  const status = h('div', { class: 'status', role: 'status' });
  const updateBtn = canUpdate ? h('button', { class: like ? 'btn' : 'btn primary', type: 'button' }, t('changedUpdate')) : null;
  const newBtn = canCopy
    ? h('button', { class: like || canUpdate ? 'btn' : 'btn primary', type: 'button' }, t('changedSaveNew'))
    : null;
  const laterBtn = h('button', { class: 'btn ghost', type: 'button' }, t('bannerNotNow'));
  const closeBtn = h('button', { class: 'icon-btn x', type: 'button', title: t('bannerNotNow'), 'aria-label': t('commonClose') }, uiIcon('close'));
  const changes = [];
  if (newUsername) changes.push(t('changedUsername', newUsername));
  if (passwordChanged) changes.push(t('changedPassword'));
  const changesEl = changes.length
    ? h('ul', { class: 'changes', 'aria-label': heading }, ...changes.map((text) => h('li', {}, uiIcon('edit', { size: 14 }), h('span', {}, text))))
    : null;
  const lookalikeEl = like
    ? h('div', { class: 'lookalike', role: 'alert' }, uiIcon('alert', { size: 14 }), h('span', {}, t('changedLookalike', host, like)))
    : null;
  const intlEl = !lookalikeEl && isPunycodeHost(host) ? h('div', { class: 'intl' }, t('commonIntlAddress')) : null;
  const notes = [];
  if (cross && canUpdate) notes.push(t('changedFromSite', site || title || '?', host));
  if (readOnly) notes.push(t('changedReadOnly'));
  const box = h('div', { class: 'banner card', role: 'dialog', 'aria-label': 'Passyble' },
    h('div', { class: 'brand' }, passWordmark(), closeBtn),
    h('div', { class: 'row' },
      h('div', { class: 'text' },
        h('div', { class: 'title', title: heading }, heading),
        h('div', { class: 'sub' }, host),
        intlEl,
        h('div', { class: 'who' }, h('span', { class: 'user', title: who }, who)))),
    changesEl,
    ...notes.map((text) => h('p', { class: 'note' }, text)),
    lookalikeEl,
    h('div', { class: 'cross-actions' }, updateBtn, newBtn, laterBtn),
    status);
  ui.root.append(h('div', { class: 'pass-ui' }, box));
  return runActionCard(ui, box, { status, closeBtn, laterBtn, onDismiss, timeoutMs, actions: [
    [updateBtn, onUpdate, () => t('changedUpdated')],
    [newBtn, onSaveNew, (res) => (res?.unchanged ? t('bannerAlreadySaved') : t('changedSavedNew'))],
  ] });
}
