// Passkey cards shown top right, in the top layer and a closed shadow root the page can't read.
// Every action needs a real click on a card that was plainly visible (createClickGuard).
import { createHost, createClickGuard, h, passWordmark, uiIcon, uiIntact } from './ui-common.js';
import { t } from '../shared/i18n.js';

const CSS = `
.card-box { position: fixed; top: 12px; right: 12px; width: 340px; max-width: calc(100vw - 24px); padding: 16px 16px 14px;
  animation: in .16s ease-out; }
@keyframes in { from { transform: translateY(-6px); opacity: 0; } to { transform: none; opacity: 1; } }
.row { display: flex; align-items: flex-start; gap: 12px; }
.brand { display: flex; align-items: center; justify-content: space-between; margin: -2px -6px 10px 0; }
.text { flex: 1; min-width: 0; }
.title { font-weight: 700; font-size: 17px; line-height: 1.25; letter-spacing: -0.02em; overflow-wrap: anywhere; }
.sub { margin-top: 2px; color: var(--text-2); font-size: var(--fs-body); overflow-wrap: anywhere; }
/* The accounts: the fill menu's rows (32px tile, title and account, hairlines inset, a 10px hover). */
.list { display: grid; margin: 10px -6px 0; padding: 0; max-height: 204px; overflow: auto; overscroll-behavior: contain; }
.list:empty { display: none; }
.acct { position: relative; display: flex; align-items: center; gap: 12px; width: 100%; min-height: 50px; margin: 0; padding: 7px 10px; border: 0;
  border-radius: var(--r); background: none; color: var(--text); text-align: start; }
.acct + .acct::before { content: ""; position: absolute; top: 0; left: 10px; right: 10px; height: 1px; background: var(--border); }
button.acct:hover { background: var(--fill-hover); }
.chev { flex: none; margin-left: auto; color: var(--text-3); }
button.acct:hover .chev { color: var(--text); }
button.acct:hover::before, button.acct:hover + .acct::before { opacity: 0; }
button.acct:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: -2px; }
button.acct:disabled { opacity: .55; cursor: default; }
.avatar { flex: none; width: 32px; height: 32px; border-radius: var(--r); background: var(--fill-selected); color: var(--text-2);
  display: grid; place-items: center; font-weight: 700; font-size: var(--fs-md); }
.name { font-weight: 600; font-size: var(--fs-md); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.acct .sub { margin: 1px 0 0; font-size: var(--fs-sm); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.field-cap { color: var(--text-2); font-size: var(--fs-sm); margin-top: 2px; }
.field { display: grid; gap: 4px; margin: 12px 0 0; }
.field > label { color: var(--text); font-size: var(--fs-sm); font-weight: 600; }
.select-wrap { position: relative; display: block; }
select { font: inherit; color: var(--text); background: var(--input-bg); height: 40px; min-width: 0; width: 100%;
  border: 1px solid var(--border-strong); border-radius: 12px; padding: 0 36px 0 12px; cursor: pointer; -webkit-appearance: none; appearance: none; }
.select-chev { position: absolute; top: 50%; right: 12px; transform: translateY(-50%); color: var(--text-2); pointer-events: none; }
select:focus-visible { outline: 2px solid transparent; border-color: var(--field-focus); box-shadow: var(--focus-field); }
.note { margin: 12px 0 0; color: var(--text-2); font-size: var(--fs-sm); display: flex; gap: 6px; align-items: flex-start; }
.note svg { flex: none; margin-top: 2px; }
/* Not now / Cancel and the one primary, side by side, full width. */
.actions { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; margin: 14px 0 0; }
.actions > * { flex: 1 1 0; min-width: 0; }
.actions .btn { padding-inline: 10px; white-space: nowrap; }
/* The primary carries the longer label ("Unlock and sign in"): a little more of the row. */
.actions > .btn.primary { flex-grow: 1.4; }
.actions .btn { min-height: 40px; font-size: var(--fs-md); }
.alt { margin: 8px 0 0; text-align: center; }
.status { color: var(--text-2); font-size: var(--fs-sm); margin: 10px 0 0; overflow-wrap: anywhere; }
.status:empty { display: none; }
.unlock { margin: 14px 0 0; display: grid; gap: var(--sp-2); }
.unlock[hidden] { display: none; }
.unlock .msg { color: var(--text-2); font-size: var(--fs-sm); overflow-wrap: anywhere; }
.unlock .msg:empty { display: none; }
.unlock .buttons { display: flex; flex-wrap: wrap; justify-content: flex-end; align-items: center; gap: var(--sp-2); }
.unlock .buttons .link { margin-right: auto; }
/* The master password field (src/unlock/frame.html), an extension page the page can't read. */
.unlock-frame { display: block; width: 100%; height: 112px; border: 0; margin: 0; padding: 0; background: transparent; color-scheme: normal; }
`;

const NONE_CSS = `
.none-box { position: fixed; top: 12px; right: 12px; width: max-content; min-width: 220px; max-width: min(360px, calc(100vw - 24px));
  padding: 8px 8px 8px 14px; animation: in .16s ease-out; }
@keyframes in { from { transform: translateY(-6px); opacity: 0; } to { transform: none; opacity: 1; } }
.row { display: flex; align-items: center; gap: 10px; min-height: 30px; }
.row .wordmark { font-size: 16px; }
.title { flex: 1; min-width: 0; font-weight: 500; overflow-wrap: anywhere; }
`;
export const NONE_NOTICE_MS = 5000;
// Same corner as the cards, so a card closes it.
let noneShown = null;

export function passkeyAccount(pk) {
  return String(pk?.user_name || pk?.user_display_name || pk?.title || '').trim() || t('commonNoUsername');
}

function cardShell({ heading, sub, body, label = 'Passyble' }) {
  const ui = createHost('passkey', CSS);
  const logo = passWordmark();
  const closeBtn = h('button', { class: 'icon-btn x', type: 'button', title: t('commonClose'), 'aria-label': t('commonClose') }, uiIcon('close'));
  const status = h('div', { class: 'status', role: 'status' });
  const unlockMsg = h('div', { class: 'msg', role: 'status' });
  const unlockSlot = h('div', { class: 'slot' });
  const unlockButtons = h('div', { class: 'buttons' });
  const unlockBox = h('div', { class: 'unlock', hidden: true }, unlockMsg, unlockSlot, unlockButtons);
  const box = h('div', { class: 'card-box card', role: 'dialog', 'aria-label': label },
    h('div', { class: 'brand' }, logo, closeBtn),
    h('div', { class: 'row' },
      h('div', { class: 'text' }, h('div', { class: 'title' }, heading), sub ? h('div', { class: 'sub', title: sub }, sub) : null)),
    ...body, unlockBox, status);
  ui.root.append(h('div', { class: 'pass-ui' }, box));
  return { ui, box, closeBtn, status, unlockBox, unlockMsg, unlockSlot, unlockButtons };
}

/** `buttons()` are disabled while busy, except those in `keep`. */
function cardController(shell, { actions, buttons, keep = [], onDismiss }) {
  const { ui, box, closeBtn, status, unlockBox, unlockMsg, unlockSlot, unlockButtons } = shell;
  let done = false;
  let busy = false;
  let guard = null;
  let unlockCancel = null;
  const close = () => {
    if (done) return;
    done = true;
    guard?.disconnect();
    ui.remove();
  };
  const setBusy = (on) => {
    busy = on;
    for (const b of buttons()) b.disabled = on && !keep.includes(b);
  };
  const dismiss = (e) => {
    if (done || !e.isTrusted) return;
    close();
    onDismiss();
  };
  closeBtn.addEventListener('click', dismiss);
  box.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    e.preventDefault();
    if (!unlockBox.hidden && unlockCancel) { if (e.isTrusted) unlockCancel(); return; }
    dismiss(e);
  });

  const controller = {
    close,
    get closed() { return done; },
    get busy() { return busy; },
    intact: () => !done && uiIntact(ui.host, box),
    setStatus(text) { if (!done) status.textContent = text || ''; },
    /** The same `frame` stays in place when shown again, so nothing typed is lost. */
    showUnlock({ message = '', frame = null, choices = [], onCancel = null } = {}) {
      if (done) return;
      unlockCancel = onCancel;
      unlockMsg.textContent = message;
      if (frame) {
        if (frame.parentNode !== unlockSlot) { unlockSlot.replaceChildren(frame); }
      } else {
        unlockSlot.replaceChildren();
      }
      unlockButtons.replaceChildren(...choices.map((c) => {
        const b = h('button', { class: c.link ? 'link' : `btn${c.primary ? ' primary' : ''}`, type: 'button' }, c.label);
        b.addEventListener('click', (e) => { if (!done && e.isTrusted) c.onClick(); });
        return b;
      }));
      actions.hidden = true;
      unlockBox.hidden = false;
      status.textContent = '';
    },
    hideUnlock() {
      if (done) return;
      unlockCancel = null;
      unlockSlot.replaceChildren();
      unlockButtons.replaceChildren();
      unlockMsg.textContent = '';
      unlockBox.hidden = true;
      actions.hidden = false;
    },
  };

  /** Runs `act` for a guarded click: `{ done }` closes, `{ message }` stays. */
  const run = async (e, act) => {
    // A choice on a see-through or covered card must not count.
    if (done || busy || !guard?.allows(e)) return;
    setBusy(true);
    let res = null;
    try {
      res = await act();
    } catch (err) {
      res = { message: err?.message || t('errGeneric') };
    }
    if (done) return;
    controller.hideUnlock();
    if (res?.done) { close(); return; }
    setBusy(false);
    status.textContent = res?.message || '';
  };

  const mount = () => {
    noneShown?.close();
    ui.mount();
    guard = createClickGuard(ui.host, box);
  };
  const allows = (e) => !done && !!e?.isTrusted && !!guard?.allows(e);
  return { controller, run, dismiss, mount, allows, setStatusNow: (text) => { status.textContent = text; } };
}

// Guarded so a page can't bring the browser's passkey dialog up with a click meant for something else.
function elsewhereButton(onElsewhere, allows, { primary = false } = {}) {
  if (!onElsewhere) return null;
  const b = h('button', { class: primary ? 'btn primary' : 'link', type: 'button' }, t('passkeyElsewhere'));
  b.addEventListener('click', (e) => { if (allows(e)) onElsewhere(); });
  return b;
}

/** `passkeys` is empty when fully locked; `modal` is a page's own `get()`. */
export function showPasskeyPrompt({ site, passkeys, locked = false, modal = false, onPick, onElsewhere = null, onDismiss }) {
  const list = passkeys.slice(0, 20);
  const several = list.length > 1;
  const none = list.length === 0;
  const heading = none ? t('passkeyPromptTitleLocked') : several ? t('passkeyPromptChoose') : t('passkeyPromptTitle');
  const laterBtn = h('button', { class: 'btn', type: 'button' }, modal ? t('commonCancel') : t('bannerNotNow'));
  const signInBtn = several ? null
    : h('button', { class: 'btn primary', type: 'button' }, locked ? t(none ? 'passkeyUnlock' : 'passkeyPromptUnlockSignIn') : t('passkeyPromptSignIn'));

  const accountRow = (pk, clickable) => {
    const account = passkeyAccount(pk);
    const body = [
      h('span', { class: 'avatar' }, (String(pk.title || account).trim().charAt(0) || '?').toUpperCase()),
      pk.title && pk.title !== account
        ? h('span', { class: 'text' }, h('div', { class: 'name', title: pk.title }, pk.title), h('div', { class: 'sub', title: account }, account))
        : h('span', { class: 'text' }, h('div', { class: 'name', title: account }, account)),
    ];
    if (!clickable) return h('div', { class: 'acct' }, ...body);
    return h('button', { class: 'acct', type: 'button', 'aria-label': t('passkeyPromptSignInAs', account) }, ...body,
      h('span', { class: 'chev', 'aria-hidden': 'true' }, uiIcon('chevronRight', { size: 16 })));
  };
  const rows = list.map((pk) => accountRow(pk, several));
  let shell;
  let controller;
  let wired = null;
  const elsewhere = elsewhereButton(onElsewhere, (e) => !!wired?.allows(e));
  const actions = h('div', {}, h('div', { class: 'actions' }, laterBtn, signInBtn), elsewhere ? h('div', { class: 'alt' }, elsewhere) : null);
  shell = cardShell({
    heading,
    sub: site,
    body: [
      h('div', { class: 'list', role: several ? 'group' : null, 'aria-label': several ? heading : null }, ...rows),
      locked && none ? h('div', { class: 'note' }, uiIcon('lock', { size: 14 }), h('span', {}, t('passkeyPromptLockedFull'))) : null,
      actions,
    ],
  });
  wired = cardController(shell, {
    actions,
    buttons: () => [laterBtn, signInBtn, elsewhere, ...(several ? rows : [])].filter(Boolean),
    keep: [laterBtn, elsewhere],
    onDismiss,
  });
  controller = wired.controller;
  const pick = (e, pk) => wired.run(e, () => {
    wired.setStatusNow(locked ? t('passkeyPromptUnlocking') : t('passkeyPromptSigningIn'));
    return onPick(pk, controller);
  });
  if (signInBtn) signInBtn.addEventListener('click', (e) => pick(e, list[0] || null));
  if (several) rows.forEach((row, i) => row.addEventListener('click', (e) => pick(e, list[i])));
  laterBtn.addEventListener('click', wired.dismiss);
  wired.mount();
  return controller;
}

function vaultText(vault) {
  return /vault$/i.test(String(vault).trim()) ? t('passkeySaveVaultNamed', vault) : t('passkeySaveVault', vault);
}

function loginLabel(c) {
  const title = String(c?.title || '').trim();
  const user = String(c?.username || '').trim();
  if (title && user) return t('passkeySaveLoginUser', title, user);
  return title || user || t('commonNoUsername');
}

/** For a page's `create()`; `onSave(itemId)` gets null for a new login. */
export function showPasskeySave({ site, account, detail = '', candidates = [], suggested = null, vault = null, vaults = null, locked = false, onSave, onElsewhere = null, onDismiss }) {
  const offered = candidates.slice(0, 50);
  const cancelBtn = h('button', { class: 'btn', type: 'button' }, t('commonCancel'));
  const saveBtn = h('button', { class: 'btn primary', type: 'button' }, locked ? t('passkeySaveUnlock') : t('passkeySaveButton'));
  const name = String(account || '').trim() || t('commonNoUsername');
  let select = null;
  if (offered.length) {
    select = h('select', { id: 'keep', 'aria-label': t('passkeySaveKeepWith') },
      ...offered.map((c) => h('option', { value: c.id }, loginLabel(c))),
      h('option', { value: '' }, t('passkeySaveNewLogin')));
    select.value = offered.some((c) => c.id === suggested) ? suggested : '';
  }
  const vaultChoice = vaults && Array.isArray(vaults.vaults) && vaults.vaults.length > 1 ? vaults : null;
  const vaultSelect = vaultChoice
    ? h('select', { id: 'vault', 'aria-label': t('bannerSaveIn') },
      ...vaultChoice.vaults.map((v) => h('option', { value: String(v.id) }, String(v.name || t('bannerMyVault')))))
    : null;
  if (vaultSelect) vaultSelect.value = vaultChoice.selected;
  const vaultField = vaultSelect
    ? h('div', { class: 'field' }, h('label', { for: 'vault' }, t('bannerSaveIn')),
      h('span', { class: 'select-wrap' }, vaultSelect, h('span', { class: 'select-chev', 'aria-hidden': 'true' }, uiIcon('chevronDown', { size: 16 }))))
    : null;
  // An existing login keeps its own vault.
  const syncVault = () => { if (vaultField) vaultField.hidden = !!select?.value; };
  select?.addEventListener('change', syncVault);
  syncVault();
  let controller;
  let wired = null;
  const elsewhere = elsewhereButton(onElsewhere, (e) => !!wired?.allows(e));
  const actions = h('div', {}, h('div', { class: 'actions' }, cancelBtn, saveBtn), elsewhere ? h('div', { class: 'alt' }, elsewhere) : null);
  const who = detail && detail !== name ? `${name} (${detail})` : name;
  const shell = cardShell({
    heading: t('passkeySaveShort'),
    sub: t('bannerUserOnSite', who, site),
    label: t('passkeySaveTitle', site),
    body: [
      select ? h('div', { class: 'field' }, h('label', { for: 'keep' }, t('passkeySaveKeepWith')),
        // Inline SVG chevron: a data: URL could be blocked by the page's CSP.
        h('span', { class: 'select-wrap' }, select, h('span', { class: 'select-chev', 'aria-hidden': 'true' }, uiIcon('chevronDown', { size: 16 }))),
        vault ? h('div', { class: 'field-cap' }, vaultText(vault)) : null) : null,
      !select && vault && !vaultField ? h('div', { class: 'note' }, uiIcon('folder', { size: 14 }), h('span', {}, vaultText(vault))) : null,
      vaultField,
      actions,
    ],
  });
  wired = cardController(shell, {
    actions,
    buttons: () => [cancelBtn, saveBtn, elsewhere, select, vaultSelect].filter(Boolean),
    keep: [cancelBtn, elsewhere],
    onDismiss,
  });
  controller = wired.controller;
  saveBtn.addEventListener('click', (e) => wired.run(e, () => {
    wired.setStatusNow(locked ? t('passkeyPromptUnlocking') : t('passkeySaveSaving'));
    return onSave(select?.value || null, controller, !select?.value && vaultSelect ? vaultSelect.value : null);
  }));
  cancelBtn.addEventListener('click', wired.dismiss);
  wired.mount();
  return controller;
}

/** A notice for a page's own passkey request; shows nothing of the vault. */
export function showPasskeyNotice({ heading, site = '', note = '', noteIcon = 'info', action = null, onElsewhere = null, onDismiss }) {
  const cancelBtn = h('button', { class: 'btn', type: 'button' }, t('commonCancel'));
  const actionBtn = action ? h('button', { class: 'btn primary', type: 'button' }, action.label) : null;
  let wired = null;
  const elsewhere = elsewhereButton(onElsewhere, (e) => !!wired?.allows(e), { primary: !actionBtn });
  const row = h('div', { class: 'actions' }, cancelBtn, actionBtn || elsewhere);
  const actions = h('div', {}, row, actionBtn && elsewhere ? h('div', { class: 'alt' }, elsewhere) : null);
  const shell = cardShell({
    heading,
    sub: site,
    body: [
      note ? h('div', { class: 'note' }, uiIcon(noteIcon, { size: 14 }), h('span', {}, note)) : null,
      actions,
    ],
  });
  wired = cardController(shell, {
    actions,
    buttons: () => [cancelBtn, actionBtn, elsewhere].filter(Boolean),
    keep: [cancelBtn, elsewhere],
    onDismiss,
  });
  const { controller } = wired;
  if (actionBtn) {
    actionBtn.addEventListener('click', (e) => wired.run(e, () => {
      if (action.busyText) wired.setStatusNow(action.busyText);
      return action.run(controller);
    }));
  }
  cancelBtn.addEventListener('click', wired.dismiss);
  wired.mount();
  return controller;
}

/** "No passkey for <site> in Passyble": the request went straight to the browser. Never takes focus. */
export function showPasskeyNone(site, ms = NONE_NOTICE_MS) {
  noneShown?.close();
  const ui = createHost('passkey-none', NONE_CSS);
  const logo = passWordmark();
  const closeBtn = h('button', { class: 'icon-btn x', type: 'button', title: t('commonDismiss'), 'aria-label': t('commonDismiss') }, uiIcon('close'));
  ui.root.append(h('div', { class: 'pass-ui' }, h('div', { class: 'none-box card', role: 'status', 'aria-live': 'polite' },
    h('div', { class: 'row' }, logo, h('div', { class: 'title' }, t('passkeyNoneNotice', site || location.hostname)), closeBtn))));
  let closed = false;
  const notice = {
    close() {
      if (closed) return;
      closed = true;
      clearTimeout(timer);
      ui.remove();
      if (noneShown === notice) noneShown = null;
    },
    get closed() { return closed; },
  };
  closeBtn.addEventListener('click', (e) => { if (e.isTrusted) notice.close(); });
  const timer = setTimeout(() => notice.close(), ms);
  ui.mount();
  noneShown = notice;
  return notice;
}
