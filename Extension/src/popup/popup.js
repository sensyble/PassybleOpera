// Passyble toolbar popup: lock state, the tab's logins, vault search, unlock form and login editor.
// Every request goes through the background script, which takes the tab URL from the browser itself.
import { ext } from '../shared/api.js';
import { formatCode, secondsLeft } from '../shared/otp-logic.js';
import { mountServerPair } from '../ui/server-pair.js';
import { openMenu, closeMenu } from '../ui/popover.js';
import { attachTooltip } from '../ui/tooltip.js';
import { SENSYBLE_URL } from '../shared/credit.js';
import { friendlyError, isHostMissing, MSG } from '../shared/messages.js';
import { icon, hydrateIcons, fillWordmark } from '../shared/svg-icon.js';
import { getSettings, setSettings } from '../shared/settings.js';
import { mountEditor } from './editor.js';
import { mountQuickActions } from './quick-actions.js';
import { brandBadge, brandName, cardSummary, identitySummary, shortExpiry } from '../shared/cards.js';
import { applyI18n, t, tp } from '../shared/i18n.js';
import { restoreBrowserAutofill, turnOffOnFirstPopup } from '../shared/browser-autofill.js';
import { openWelcome } from '../shared/welcome-link.js';
import { browserVaultSupported } from '../shared/vault-mode.js';
import { ACCOUNT_DATA, askDataConsent } from '../shared/data-consent.js';
import { filterVaults, itemRights, moveTargets, passwordPolicy, pinnedFirst, pinsOf, sharedWithMe, teamsSection, vaultLabel, vaultTable } from '../shared/vaults.js';
import { syncOutcome } from '../shared/sync.js';
import { mountVaultFilter, vaultName } from './vault-filter.js';
import { mountTypeFilter } from './type-filter.js';
import { mountFilterMenu } from './filter-menu.js';
import { mountNoteViewer } from './note-viewer.js';
import { mountVaultSwitch } from './vault-switch.js';

applyI18n(document);
hydrateIcons(document.body);
fillWordmark(document.getElementById('logo'));

const $ = (id) => document.getElementById(id);

$('main').addEventListener('scroll', () => $('main').classList.toggle('scrolled', $('main').scrollTop > 0), { passive: true });
const views = ['loading', 'locked', 'offline', 'list', 'server', 'quick', 'edit', 'novault', 'ask', 'update', 'readonly', 'qa', 'note'];
let currentView = 'loading';
const SVG_NS = 'http://www.w3.org/2000/svg';
const R = 6;
const CIRC = 2 * Math.PI * R;

let tab = null;
let state = null;
let updateInfo = null; // update.state: { required, recommended, recommended_version, message, ... }
let readOnlyOpen = false;
let vaultOnly = false; // not a web page: no site logins, the search goes to the vault
const totps = new Map(); // key -> { codeEl, bar, data, fetchedAt, refreshing, fetcher }

// A window opened by the in-page menu's "Enter master password" (where the popup can't be opened).
const unlockOnly = new URLSearchParams(globalThis.location?.search || '').get('unlock') === '1';
// A window opened for one question of the browser vault (askUser in the background).
const askOnly = new URLSearchParams(globalThis.location?.search || '').get('ask') === '1';

// The background knows a popup is open while this port is; it also brings the outcome of a copy that finished after
// the last popup closed: `{ type: 'feedback', text }`.
try {
  ext.runtime.connect?.({ name: 'passyble-popup' })?.onMessage?.addListener((msg) => {
    if (msg?.type === 'feedback' && typeof msg.text === 'string' && msg.text) snack(msg.text.slice(0, 300));
  });
} catch { /* tests: no ports */ }

/** True when this page runs in a browser tab rather than as the toolbar popup, which only the user's click opens. */
async function inTab() {
  try {
    return !!(await ext.tabs.getCurrent?.());
  } catch {
    return false;
  }
}

function closePopup() {
  try { window.close(); } catch { /* not a browser window (tests) */ }
}

async function send(type, payload = {}) {
  const res = await ext.runtime.sendMessage({ type, ...payload });
  if (res?.ok) return res.result;
  const err = new Error(res?.error?.message || 'No response');
  err.code = res?.error?.code || 'internal';
  err.reason = res?.error?.reason;
  throw err;
}

let lastStatus = null; // the last setStatus kind, drawn again when the view changes (show)

function show(view) {
  currentView = view;
  closeMenu();
  for (const v of views) $(`view-${v}`).hidden = v !== view;
  $('menu-btn').hidden = view === 'edit';
  if (lastStatus !== null) setStatus(lastStatus);
  renderSyncButton(view);
  if (view !== 'edit' && editor?.isOpen) editor.clear();
  // A quick action's view stays while the unlock form asks for it (its Cancel comes back to it).
  if (view !== 'qa' && view !== 'locked' && quick?.isOpen) quick.clear();
  // A note's text leaves the page as soon as its viewer does (an unlock asked before it opens shows no text).
  if (view !== 'note' && noteViewer?.isOpen) noteViewer.clear();
}

function setStatus(kind) {
  lastStatus = kind;
  const btn = $('lock-btn');
  const soft = kind === 'locked' && currentView !== 'locked';
  btn.hidden = !(kind === 'ok' || soft);
  if (btn.hidden) return;
  const label = kind === 'ok' ? t('popupLock') : t(state?.browser ? 'popupStatusLockedBrowser' : 'popupStatusLocked');
  const name = kind === 'ok' ? 'lockOpen' : 'lock';
  btn.classList.toggle('locked', kind !== 'ok');
  btn.title = label;
  btn.setAttribute('aria-label', label);
  if (btn.getAttribute('data-icon') !== name) {
    btn.setAttribute('data-icon', name);
    btn.replaceChildren();
    hydrateIcons(btn.parentElement);
  }
}

let snackTimer = 0;
function snack(text, { action = null, onAction = null } = {}) {
  const node = $('snack');
  node.replaceChildren(text);
  if (action) {
    node.append(' ', el('button', { class: 'snack-action', type: 'button', onclick: () => {
      node.classList.remove('show');
      onAction?.();
    } }, action));
  }
  node.classList.toggle('actionable', !!action);
  node.classList.add('show');
  clearTimeout(snackTimer);
  snackTimer = setTimeout(() => node.classList.remove('show'), action ? 8000 : Math.max(1600, text.length * 55));
}

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

function svgEl(tag, attrs, children = []) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  for (const c of children) node.append(c);
  return node;
}

function iconButton(name, label, onclick, { ariaLabel = label } = {}) {
  return el('button', { class: 'icon-btn', type: 'button', title: label, 'aria-label': ariaLabel, onclick }, icon(name));
}

function moreButton(label, items) {
  const btn = el('button', { class: 'icon-btn', type: 'button', title: t('commonMore'), 'aria-label': t('popupMoreFor', label),
    'aria-haspopup': 'menu', 'aria-expanded': 'false' }, icon('more'));
  btn.addEventListener('click', (e) => { e.stopPropagation(); openMenu(btn, items(), { label }); });
  return btn;
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch { return ''; }
}

function isPunycodeHost(host) {
  return typeof host === 'string' && host.toLowerCase().split('.').some((label) => label.startsWith('xn--'));
}

function renderHostNote() {
  const note = $('host-note');
  if (!note) return;
  const host = vaultOnly ? '' : hostOf(state?.url || '');
  const intl = isPunycodeHost(host);
  note.hidden = !intl;
  note.textContent = intl ? t('popupIntlHost', host) : '';
}

function letter(item) {
  return (item.title || '?').trim().charAt(0).toUpperCase() || '?';
}

/** `clears`: the background clears the clipboard after 45 s (secret kinds only). */
const COPIED = {
  username: { done: () => t('popupCopiedUsername') },
  password: { done: () => t('popupCopiedPassword'), clears: () => t('popupCopiedPasswordClears'), byApp: () => t('popupCopiedByAppPassword') },
  totp: { done: () => t('popupCopiedOtp'), clears: () => t('popupCopiedOtpClears'), byApp: () => t('popupCopiedByAppOtp') },
  expiry: { done: () => t('popupCopiedExpiry'), clears: () => t('popupCopiedExpiryClears') },
  note: { done: () => t('popupCopiedNote'), clears: () => t('popupCopiedNoteClears') },
  number: { done: () => t('popupCopiedCardNumber'), clears: () => t('popupCopiedCardNumberClears'), none: () => t('popupCardNoNumber') },
  security_code: { done: () => t('popupCopiedSecurityCode'), clears: () => t('popupCopiedSecurityCodeClears'), none: () => t('popupCardNoSecurityCode') },
  full_name: { done: () => t('popupCopiedName'), none: () => t('popupNoNameSaved') },
  email: { done: () => t('popupCopiedEmail'), none: () => t('popupNoEmailSaved') },
  phone: { done: () => t('popupCopiedPhone'), none: () => t('popupNoPhoneSaved') },
  address: { done: () => t('popupCopiedAddress'), none: () => t('popupNoAddressSaved') },
};

// Secrets are copied by the desktop app where it can: it keeps them out of Windows clipboard history and the cloud
// clipboard (navigator.clipboard can't), and the value never comes to the popup. False once an older app said `not_supported`.
let appCopies = true;

/** Resolves false where the desktop app can't copy (`not_supported`, or one of `fallBackOn`): the caller copies the old way. */
async function copyByApp(id, field, { fallBackOn = [] } = {}) {
  if (!appCopies) return false;
  const req = { tabId: tab.id, id, field, own: true };
  try {
    await unlocking((inline) => send('popup.copy-item', { ...req, ...inlineFlag(inline) }),
      { forItem: id, then: { copy: { type: 'popup.copy-item', ...req } } });
  } catch (err) {
    if (err?.code === 'not_supported') { appCopies = false; return false; }
    if (fallBackOn.includes(err?.code)) return false;
    throw err;
  }
  snack(COPIED[field].byApp());
  return true;
}

/** The browser's clipboard: for non-secrets, and for secrets only with an older desktop app (cleared after 45 s). */
async function copy(text, kind, { secret = true } = {}) {
  try {
    await navigator.clipboard.writeText(text);
  } catch {
    snack(t('popupCopyFailed'));
    return;
  }
  let clears = false;
  if (secret && text) {
    try { clears = !!(await send('clipboard.copied', { value: text }))?.scheduled; } catch { /* still copied */ }
  }
  const what = COPIED[kind];
  snack(clears && what.clears ? what.clears() : what.done());
}

/** The code is masked until hovered or keyboard-focused (CSS); a click copies it without revealing it. */
function otpPill(key, fetcher, { pending = false, locked = false, itemId = null, byApp = false, fallBackOn = [] } = {}) {
  const copyCode = async (code) => {
    if (byApp && itemId && await copyByApp(itemId, 'totp', { fallBackOn })) return;
    await copy(typeof code === 'function' ? await code() : code, 'totp');
  };
  const codeEl = el('span', { class: 'code' });
  setCode(codeEl, '');
  const bar = svgEl('circle', { class: 'bar', cx: 8, cy: 8, r: R, fill: 'none', 'stroke-width': 2.5, 'stroke-linecap': 'round', 'stroke-dasharray': CIRC.toFixed(2) });
  const ring = svgEl('svg', { class: 'ring', viewBox: '0 0 16 16', width: 16, height: 16, 'aria-hidden': 'true' }, [
    svgEl('circle', { class: 'track', cx: 8, cy: 8, r: R, fill: 'none', 'stroke-width': 2.5 }), bar]);
  const pill = el('button', { class: 'otp', type: 'button', title: t('popupCopyOtp'), 'aria-label': t('popupOtpPillLabel') },
    ring, pending ? el('span', { class: 'step' }, t('popupOtpStep')) : null, codeEl, icon('copy', { size: 14 }));
  if (locked) {
    // Soft-locked: no code until unlocked. A click unlocks, then copies.
    pill.classList.add('locked');
    pill.title = t('popupOtpLockedTitle');
    pill.setAttribute('aria-label', t('popupOtpLockedLabel'));
    pill.addEventListener('click', async () => {
      try {
        await copyCode(async () => (await unlocking((inline) => fetcher(inlineFlag(inline)), { forItem: itemId })).code);
      } catch (err) {
        report(err);
      }
    });
    return pill;
  }
  const entry = { codeEl, bar, data: null, fetchedAt: 0, refreshing: false, fetcher };
  pill.addEventListener('click', async () => {
    if (!entry.data) return;
    const shown = entry.data.code;
    try {
      await copyCode(shown);
    } catch (err) {
      report(err);
    }
  });
  totps.set(key, entry);
  refreshTotp(entry);
  return pill;
}

function setCode(codeEl, digits) {
  if (!codeEl.querySelector('.digits')) {
    codeEl.replaceChildren(el('span', { class: 'mask', 'aria-hidden': 'true' }, t('commonBadge2fa')), el('span', { class: 'digits', 'aria-hidden': 'true' }));
  }
  codeEl.querySelector('.digits').textContent = digits || '';
}

async function refreshTotp(entry) {
  if (entry.refreshing) return;
  entry.refreshing = true;
  try {
    entry.data = await entry.fetcher();
    entry.fetchedAt = Date.now();
    entry.codeEl.classList.remove('error');
  } catch (err) {
    entry.codeEl.textContent = friendlyError(err);
    entry.codeEl.classList.add('error');
    entry.data = null;
  } finally {
    entry.refreshing = false;
  }
  renderTotp(entry);
}

function renderTotp(entry) {
  if (!entry.data) return;
  const period = entry.data.period || 30;
  const left = secondsLeft(entry.data, entry.fetchedAt, Date.now());
  setCode(entry.codeEl, formatCode(entry.data.code));
  entry.bar.setAttribute('stroke-dashoffset', (CIRC * (1 - left / period)).toFixed(2));
  entry.bar.classList.toggle('low', left <= 5);
  if (left <= 0) refreshTotp(entry);
}

setInterval(() => { for (const entry of totps.values()) renderTotp(entry); }, 1000);

/** Every vault the answers named so far (home first): items name theirs by `vault_id`. */
let vaults = new Map();

function noteVaults(list) {
  vaults = vaultTable([...vaults.values()], list);
}

function vaultTag(item) {
  const name = vaultLabel(item, vaults);
  return name ? { vault: name } : null;
}

const passkeyTag = (item) => (item.has_passkey ? { icon: 'key', label: t('commonPasskey') } : null);

let vaultsInfo = null;
let vaultsSeq = 0;

/** Browser mode's Teams and Family list only the shared vaults, so the home vault comes from the answers. */
function answersHome() {
  return (state?.vaults || []).filter((v) => v?.home);
}

function filtersChanged() {
  filterMenu.render();
  renderSimilar(); applyFilter(); renderResults(); setActive(-1); renderForms(); renderNotes();
}
const vaultFilter = mountVaultFilter({
  send, snack, onChange: filtersChanged, onPins: () => filterMenu.render(),
  // Browser mode: the shared vaults of background/teams/ (also those that didn't open), so their pins stay.
  known: () => (state?.browser ? (vaultsInfo?.vaults || []).filter((v) => v && !v.home && typeof v.id === 'string').map((v) => v.id) : []),
});
const typeFilter = mountTypeFilter({ onChange: filtersChanged });
const filterMenu = mountFilterMenu($('filter'), $('filter-clear'), { vaults: vaultFilter, types: typeFilter, onChange: filtersChanged });
const vaultSwitch = mountVaultSwitch($('vault-switch'), $('switch-tip'), { send, snack, pins: () => vaultFilter.pins,
  pinOf: (id, name) => vaultFilter.pinOf(id, name) });

/** How many shared vaults are open is not said: the line shows only when something waits. */
async function renderVaults() {
  const seq = ++vaultsSeq;
  $('teams-line')?.remove();
  $('teams-rule')?.remove();
  $('teams-confirm')?.remove();
  $('teams-signers')?.remove();
  const browserMode = !!state?.browser;
  const linked = (browserMode || state?.can_vaults) && !state?.locked;
  // Browser mode: the browser vault's own Teams and Family (signed-in Passyble account only).
  const [raw, pins] = await Promise.all([
    linked ? send(browserMode ? 'teams.model' : 'popup.vaults').catch(() => null) : null,
    state?.can_pins && !state.locked ? send('popup.pins').then(pinsOf, () => null) : null,
  ]);
  if (seq !== vaultsSeq) return;
  vaultsInfo = raw;
  vaultFilter.update(filterVaults(raw?.vaults, answersHome()), pins);
  const model = sharedWithMe(raw);
  const rule = passwordRuleNotice(raw, browserMode);
  const browserNote = browserMode && (raw?.browser?.device_waiting || raw?.browser?.held?.length);
  if (!model.show && !browserNote && !rule) return;
  if (browserMode) renderBrowserTeams(model, raw);
  else renderAppTeams(model);
  if (rule) {
    if ($('teams-line')) $('teams-line').after(rule);
    else $('list').before(rule);
  }
}

async function showTeams(params) {
  try {
    await send('popup.show-teams', params);
    closePopup();
  } catch (err) {
    snack(err.code === 'not_supported' ? t('teamsNeedsUpdate') : friendlyError(err));
  }
}

function teamsParts(model) {
  const parts = [];
  if (model.errors) parts.push(tp('teamsLineErrors', model.errors));
  if (model.toConfirm) parts.push(tp('teamsLineConfirm', model.toConfirm));
  if (model.invites) parts.push(tp('teamsLineInvites', model.invites));
  return parts;
}

function renderAppTeams(model) {
  const parts = teamsParts(model);
  if (!parts.length) return;
  const open = el('button', { class: 'btn ghost small', type: 'button', onclick: () => showTeams({ section: teamsSection(model) }) },
    t('teamsOpenInPassyble'));
  const line = el('div', { id: 'teams-line', class: 'teams-line', role: 'status' },
    icon('user'), el('span', { class: 'grow' }, parts.join(' · ')), open);
  $('list').before(line);
}

/** Browser mode: this browser can't give its vault a second password or take one away, so the notice says where. */
function passwordRuleNotice(raw, browserMode) {
  let text = null;
  if (!browserMode) text = passwordPolicy(raw);
  else if (raw?.browser?.password_rule === 'second_password') text = { title: t('teamsRuleSecondTitle'), message: t('teamsRuleSecondBrowser') };
  else if (raw?.browser?.password_rule === 'one_password') {
    text = { title: t('teamsRuleOneTitle'), message: t('teamsRuleOneBrowser', t('bannerMyVault')) };
  }
  if (!text) return null;
  const open = browserMode ? null
    : el('button', { class: 'btn ghost small', type: 'button', onclick: () => showTeams({}) }, t('teamsOpenInPassyble'));
  return el('div', { id: 'teams-rule', class: 'teams-rule', role: 'status' }, icon('shield'),
    el('span', { class: 'grow' }, el('span', { class: 'title' }, text.title), text.message ? el('span', { class: 'sub' }, text.message) : null),
    open);
}

/** Browser mode: the fingerprint the person reads out is typed and compared here. */
function renderBrowserTeams(model, raw) {
  const parts = teamsParts(model);
  const held = Array.isArray(raw?.browser?.held) ? raw.browser.held.length : 0;
  if (held) parts.push(tp('teamsLineHeld', held));
  if (raw?.browser?.device_waiting) parts.push(t('teamsLineDeviceWaiting'));
  const admin = (raw?.browser?.orgs || []).find((o) => o.admin && typeof o.console_url === 'string' && /^https:\/\//.test(o.console_url));
  const consoleBtn = admin
    ? el('button', { class: 'btn ghost small', type: 'button', onclick: () => { ext.tabs.create({ url: admin.console_url }); closePopup(); } },
      t('teamsOpenConsole'))
    : null;
  if (parts.length) {
    $('list').before(el('div', { id: 'teams-line', class: 'teams-line', role: 'status' },
      icon('user'), el('span', { class: 'grow' }, parts.join(' · ')), consoleBtn));
  }
  const signers = signerRows(raw);
  if (signers.length) $('list').before(el('ul', { id: 'teams-signers', class: 'teams-confirm', 'aria-label': t('teamsSignerList') }, ...signers));
  const waiting = Array.isArray(raw?.browser?.confirm) ? raw.browser.confirm.slice(0, 3) : [];
  if (!waiting.length) return;
  const rows = waiting.map((p) => {
    const person = String(p.email || p.account_id || '');
    const input = el('input', { class: 'input small', type: 'text', spellcheck: 'false', autocomplete: 'off',
      'aria-label': t('teamsConfirmTyped', person), placeholder: t('teamsConfirmPlaceholder') });
    const go = el('button', { class: 'btn small', type: 'button', onclick: async () => {
      try {
        const res = await send('teams.confirm', { org: p.org, account: p.account_id, fingerprint: input.value });
        // Someone a change had to leave out (keys not verified on this device): nothing was recorded for them.
        const left = Array.isArray(res?.left_out) ? res.left_out : [];
        snack(left.length ? t(left.some((x) => x?.status === 'changed') ? 'teamsKeysChanged' : 'teamsLeftOut', person)
          : t('teamsConfirmed', person));
        renderVaults();
      } catch (err) {
        snack(pinErrorText(err, person));
      }
    } }, t('teamsConfirm'));
    // Other keys than the ones verified here, or new keys of a member: said loudly, before anything is typed.
    const changed = p.keys_changed === true;
    return el('li', { class: `teams-confirm-row${changed ? ' warn' : ''}`, role: changed ? 'alert' : null },
      el('span', { class: 'title' }, person),
      changed ? el('span', { class: 'sub warn-text' }, t('teamsKeysChanged', person)) : null,
      el('span', { class: 'sub' }, t('teamsConfirmHint')), input, go);
  });
  $('list').before(el('ul', { id: 'teams-confirm', class: 'teams-confirm', 'aria-label': t('teamsConfirmList') }, ...rows));
}

function pinErrorText(err, person) {
  switch (err?.code) {
    case 'fingerprint_mismatch': return t('teamsFingerprintMismatch');
    case 'keys_mismatch': return t('teamsKeysWrong');
    case 'keys_not_verified': return t('teamsLeftOut', person);
    default: return friendlyError(err);
  }
}

function signerRows(raw) {
  const vaults = (Array.isArray(raw?.vaults) ? raw.vaults : [])
    .filter((v) => v?.open && ['not_pinned', 'changed'].includes(v.signer?.status) && v.signer.fingerprint);
  vaults.sort((a, b) => Number(b.signer.status === 'changed') - Number(a.signer.status === 'changed'));
  return vaults.slice(0, 3).map((v) => {
    const changed = v.signer.status === 'changed';
    const name = vaultName(v);
    const go = el('button', { class: 'btn small', type: 'button', onclick: async () => {
      try {
        await send('teams.verify-signer', { vault: v.id, fingerprint: v.signer.fingerprint });
        snack(t('teamsSignerVerified', name));
        renderVaults();
      } catch (err) {
        snack(pinErrorText(err, name));
      }
    } }, t('teamsSignerVerify'));
    return el('li', { class: `teams-confirm-row${changed ? ' warn' : ''}`, role: changed ? 'alert' : null, 'data-vault': v.id },
      el('span', { class: 'title' }, t(changed ? 'teamsSignerChanged' : 'teamsSignerUnverified', name)),
      el('span', { class: `sub${changed ? ' warn-text' : ''}` }, t(changed ? 'teamsSignerChangedHint' : 'teamsSignerHint')),
      el('code', { class: 'fingerprint' }, v.signer.fingerprint), go);
  });
}

function tagEl(tag) {
  if (typeof tag === 'string') return el('span', { class: 'tag' }, tag);
  if (tag.vault) return el('span', { class: 'tag tag-vault', title: tag.vault }, tag.vault);
  return el('span', { class: 'tag tag-icon', title: tag.label, role: 'img', 'aria-label': tag.label }, icon(tag.icon, { size: 12 }));
}

function row({ item, sub, main, actions, otp = null, pending = false, tag = null, attrs = {}, avatar = null }) {
  const tags = (Array.isArray(tag) ? tag : [tag]).filter(Boolean);
  const mainBtn = el('button', { class: 'item-main', type: 'button', title: main.title, 'aria-label': main.ariaLabel || main.title,
    onclick: main.onclick },
  // `avatar`: fixed (card brand, identity icon), never replaced by a site icon.
  avatar || el('span', { class: 'avatar', 'data-item': item.id }, letter(item)),
  el('span', { class: 'item-text' },
    el('span', { class: 'title' }, item.title || t('popupUntitled')),
    el('span', { class: 'sub-line' }, el('span', { class: 'sub' }, sub), tags.length ? el('span', { class: 'tags' }, tags.map(tagEl)) : null)));
  return el('li', { class: `item${pending ? ' pending' : ''}`, 'data-vault': typeof item.vault_id === 'string' ? item.vault_id : null, ...attrs },
    mainBtn, otp, el('div', { class: 'actions' }, actions));
}

function itemRow(item, { pending = false, lookupUrl = null } = {}) {
  const label = item.title || t('popupUntitledLogin');
  // A view member's login opens read-only; a fill member's login is filled, never shown or copied.
  const rights = itemRights(item, vaults);
  const menuItems = () => [
    lookupUrl || !rights.edit ? null : { id: 'row-edit', icon: 'edit', label: t('popupEdit'), onSelect: () => openEditor(item) },
    item.has_totp ? { icon: 'clock', label: t('popupCopyOtp'), onSelect: () => copyTotp(item, lookupUrl) } : null,
    // Editing and showing are bound to the tab's site (the agent checks it).
    lookupUrl || state?.browser ? null : { icon: 'external', label: t('commonOpenInPassyble'), onSelect: () => showItem(item) },
  ].filter(Boolean);
  const actions = [iconButton('user', t('popupCopyUsername'), () => copyField(item, 'username', lookupUrl))];
  if (!lookupUrl && rights.reveal) actions.push(iconButton('key', t('popupCopyPassword'), () => copyField(item, 'password', lookupUrl)));
  if (menuItems().length) actions.push(moreButton(label, menuItems));
  let otp = null;
  if (item.has_totp) {
    const key = `${lookupUrl || 'tab'}:${item.id}`;
    const fetcher = (extra = {}) => send('popup.totp', { ...(lookupUrl ? { url: lookupUrl, id: item.id } : { tabId: tab.id, id: item.id }), ...extra });
    otp = otpPill(key, fetcher, { pending, locked: !!state?.soft_locked, itemId: item.id, byApp: !lookupUrl });
  }
  const main = lookupUrl
    ? (rights.reveal
      ? { title: t('popupCopyPassword'), ariaLabel: t('popupCopyPasswordOf', label), onclick: () => copyField(item, 'password', lookupUrl) }
      : { title: t('popupCopyUsername'), ariaLabel: t('popupCopyUsername'), onclick: () => copyField(item, 'username', lookupUrl) })
    : { title: t('popupFillHere'), ariaLabel: t('popupFillItem', label), onclick: () => fill(item) };
  const tags = [passkeyTag(item), vaultTag(item), rights.reveal ? null : t('teamsFillOnly')];
  const li = row({ item, sub: item.username || t('commonNoUsername'), main, actions, otp, pending, tag: tags });
  li.dataset.search = `${item.title || ''} ${item.username || ''}`.toLowerCase();
  li.dataset.id = item.id;
  if (item.has_totp) li.dataset.totp = '1';
  if (item.has_passkey) li.dataset.passkey = '1';
  if (item.favorite) li.dataset.favorite = '1';
  return li;
}

const ICON_URL_RE = /^data:image\/png;base64,[A-Za-z0-9+/]+={0,2}$/;

/** Website icons come from the desktop app's icon cache only; nothing is fetched from the web. */
async function showIcons(list, params) {
  if (!state?.can_icons) return;
  if (!list.isConnected) return;
  let res;
  try {
    res = await send('popup.icons', params);
  } catch {
    return;
  }
  for (const avatar of list.querySelectorAll('.avatar[data-item]')) {
    const src = res?.icons?.[res?.items?.[avatar.dataset.item]];
    if (typeof src !== 'string' || !ICON_URL_RE.test(src)) continue;
    const text = avatar.textContent;
    const img = el('img', { src, alt: '', draggable: 'false' });
    img.addEventListener('error', () => { avatar.classList.remove('site-icon'); avatar.replaceChildren(text); }, { once: true });
    avatar.classList.add('site-icon');
    avatar.replaceChildren(img);
  }
}

async function fill(item) {
  try {
    // Soft-locked: unlock here first, or the page's fill would ask the desktop app.
    if (state?.soft_locked && state.can_unlock_inline) {
      const unlocked = await askUnlock({
        then: { fill: { tabId: tab.id, id: item.id } } });
      // Windows Hello: the background filled already (the popup may have closed).
      if (unlocked?.filled) { closePopup(); return; }
    }
    const res = await send('popup.fill', { tabId: tab.id, id: item.id });
    if (res && res.ok === false) throw Object.assign(new Error(res.error?.message || 'Nothing to fill'), { code: res.error?.code, reason: res.error?.reason });
    closePopup();
  } catch (err) {
    if (err.code === UNLOCK_CANCELLED) return;
    snack(err.code ? friendlyError(err) : t('commonNoLoginForm'));
  }
}

async function copyField(item, field, lookupUrl) {
  // Soft-locked: the username is in the list the desktop app kept, so it copies without unlocking.
  if (field === 'username' && state?.soft_locked) {
    await copy(item.username || '', 'username', { secret: false });
    return;
  }
  try {
    if (!lookupUrl && field === 'password' && await copyByApp(item.id, field)) return;
    const params = lookupUrl ? { url: lookupUrl, id: item.id, field } : { tabId: tab.id, id: item.id, field };
    const { value } = await unlocking((inline) => send('popup.copy', { ...params, ...inlineFlag(inline) }),
      { forItem: item.id });
    await copy(value || '', field, { secret: field !== 'username' });
  } catch (err) {
    report(err);
  }
}

async function copyTotp(item, lookupUrl) {
  try {
    if (!lookupUrl && await copyByApp(item.id, 'totp')) return;
    const params = lookupUrl ? { url: lookupUrl, id: item.id } : { tabId: tab.id, id: item.id };
    const res = await unlocking((inline) => send('popup.totp', { ...params, ...inlineFlag(inline) }), { forItem: item.id });
    await copy(res.code, 'totp');
  } catch (err) {
    report(err);
  }
}

function renderList() {
  const list = $('list');
  list.replaceChildren();
  noteVaults(state.vaults);
  const items = [...(state.items || [])];
  const pendingId = state.pending_otp?.id;
  items.sort((a, b) => (b.id === pendingId) - (a.id === pendingId));
  for (const item of items) list.append(itemRow(item, { pending: item.id === pendingId }));
  if (items.length) showIcons(list, { tabId: tab.id });
  // A pending OTP for an item that is not among the matches (e.g. a redirect to another domain).
  if (state.pending_otp && !items.some((i) => i.id === pendingId)) {
    const pending = { id: pendingId, title: state.pending_otp.title };
    list.prepend(el('li', { class: 'item pending' },
      el('div', { class: 'item-main' },
        el('span', { class: 'avatar' }, letter(pending)),
        el('span', { class: 'item-text' }, el('span', { class: 'title' }, pending.title || t('popupOtpCode')), el('span', { class: 'sub' }, t('popupNextStepOtp')))),
      // A login of another site (a redirect): the desktop app may refuse to copy it for this page
      // (`url_mismatch`), while the pending code itself is the tab's: copied here then.
      otpPill(`pending:${pendingId}`, () => send('popup.totp', { tabId: tab.id }),
        { pending: true, itemId: pendingId, byApp: true, fallBackOn: ['url_mismatch'] })));
  }
  renderHostNote();
  typeFilter.update({ cards: !!state?.can_cards, addresses: !!state?.can_identities, favorites: !!state?.can_favorites,
    notes: !!state?.can_note_list });
  filterMenu.render();
  renderSimilar();
  applyFilter();
}

/** Logins of similar sites (never a lookalike) are other sites' logins: "Fill on this page" asks in the desktop app first. */
function renderSimilar() {
  const list = $('similar-list');
  const items = (state?.items || []).length ? []
    : (state?.similar?.items || []).filter((i) => i && typeof i.id === 'string' && vaultFilter.matches(i.vault_id) && typeFilter.matches(i));
  noteVaults(state?.similar?.vaults);
  list.replaceChildren(...items.slice(0, 3).map((item) => resultRow(item)));
  if (items.length) showIcons(list, { ids: items.map((i) => i.id) });
}

function setEmpty(text, { iconName = 'key', addLogin = false, searchVault = false, caption = '' } = {}) {
  const box = $('empty-state');
  box.hidden = !text;
  $('empty').textContent = text || '';
  $('empty-text').textContent = text ? caption : '';
  const iconEl = $('empty-icon');
  if (iconEl.getAttribute('data-icon') !== iconName) { iconEl.setAttribute('data-icon', iconName); hydrateIcons(box); }
  $('search-vault').hidden = !searchVault;
  const add = $('add-login');
  add.className = addLogin && text ? 'btn primary add-login' : 'btn ghost add-login';
  if (addLogin && text) box.append(add);
  else $('list').after(add);
}

const SEARCH_DEBOUNCE_MS = 250;
let searchTimer = 0;
let searchSeq = 0;
let searchFound = null;

function scheduleSearch() {
  clearTimeout(searchTimer);
  if (!state?.can_search) return;
  const q = $('search').value.trim();
  if (q.length < 2) {
    searchSeq++;
    searchFound = null;
    $('results').hidden = true;
    $('result-list').replaceChildren();
    return;
  }
  searchTimer = setTimeout(() => runSearch(q), SEARCH_DEBOUNCE_MS);
}

async function runSearch(query) {
  const seq = ++searchSeq;
  const list = $('result-list');
  const msg = $('results-msg');
  let res;
  try {
    // The tab: results whose site this page looks like without being it come back marked (`lookalike`).
    res = await send('popup.search', { query, ...(vaultOnly || tab?.id === undefined ? {} : { tabId: tab.id }) });
  } catch (err) {
    if (seq !== searchSeq) return;
    searchFound = null;
    $('results').hidden = false;
    list.replaceChildren();
    msg.hidden = false;
    msg.textContent = err.code === 'not_supported' ? t('popupSearchNeedsUpdate') : friendlyError(err);
    return;
  }
  if (seq !== searchSeq) return; // a newer query is on its way
  noteVaults(res?.vaults);
  searchFound = Array.isArray(res?.items) ? res.items.filter(Boolean) : [];
  renderResults();
}

function renderResults() {
  if (!searchFound) return;
  const list = $('result-list');
  const msg = $('results-msg');
  const here = new Set((state?.items || []).map((i) => i.id));
  // The vault search also finds this site's own logins (typos, words in any order): show them above.
  const found = new Set(searchFound.map((i) => i.id));
  for (const li of $('list').children) if (li.hidden && found.has(li.dataset.id) && vaultFilter.matches(li.dataset.vault) && typeFilter.matchesRow(li)) li.hidden = false;
  const items = typeFilter.noLogins ? [] : searchFound.filter((i) => !here.has(i.id) && vaultFilter.matches(i.vault_id) && typeFilter.matches(i));
  list.replaceChildren(...items.map((item) => resultRow(item)));
  $('results').hidden = false;
  $('results-title').hidden = vaultOnly;
  msg.hidden = items.length > 0;
  msg.textContent = items.length ? '' : t('popupNoOtherMatches');
  if (typeFilter.noLogins) $('results').hidden = true; // cards, addresses or notes only: their lists below show
  setActive(-1);
  if (items.length && state?.can_icons) showIcons(list, { ids: items.map((i) => i.id) });
}

/** A login of another site: its secrets stay in the desktop app (copy, fill after a confirmation there). */
function resultRow(item) {
  const label = item.title || t('popupUntitledLogin');
  const rights = itemRights(item, vaults);
  const menuItems = () => [
    item.has_totp ? { icon: 'clock', label: t('popupCopyOtp'), onSelect: () => copyItem(item, 'totp') } : null,
    vaultOnly || state?.browser ? null : { icon: 'external', label: t('commonOpenInPassyble'), onSelect: () => showItem(item) },
  ].filter(Boolean);
  const actions = [
    iconButton('user', t('popupCopyUsername'), () => copyItem(item, 'username')),
    vaultOnly || !rights.reveal ? null : iconButton('key', t('popupCopyPassword'), () => copyItem(item, 'password')),
    menuItems().length ? moreButton(label, menuItems) : null,
  ].filter(Boolean);
  // Not a web page: nothing to fill, the row copies the password (by the desktop app); a fill-only
  // member's login copies the username instead.
  const main = vaultOnly
    ? (rights.reveal
      ? { title: t('popupCopyPassword'), ariaLabel: t('popupCopyPasswordOf', label), onclick: () => copyItem(item, 'password') }
      : { title: t('popupCopyUsername'), ariaLabel: t('popupCopyUsername'), onclick: () => copyItem(item, 'username') })
    : { title: t('popupFillHereConfirm'), ariaLabel: t('popupFillItemHere', label), onclick: () => fillCross(item) };
  const sub = [item.username || t('commonNoUsername'), item.domain].filter(Boolean).join(' · ');
  const tags = [item.has_totp ? t('commonBadge2fa') : null, passkeyTag(item), vaultTag(item),
    rights.reveal ? null : t('teamsFillOnly')];
  const li = row({ item, sub, main, actions, tag: tags, attrs: { role: 'option', 'data-id': item.id } });
  // This page looks like the login's site without being it (`logins.search`): a red tag, and filling
  // or copying the password asks first.
  const like = lookalikeOf(item);
  if (like) {
    const tagEl = el('span', { class: 'tag danger', title: t('popupLookalikeHint', hostOf(state?.url || ''), like) }, t('popupLookalikeTag'));
    li.querySelector('.title')?.append(tagEl);
    li.classList.add('lookalike');
  }
  return li;
}

function lookalikeOf(item) {
  const domain = item?.lookalike?.domain;
  return typeof domain === 'string' ? domain : '';
}

/** The desktop app copies it (cleared after 45 s, kept out of clipboard history); nothing comes here. */
async function copyItem(item, field) {
  const what = COPIED[field];
  // A page that looks like the login's site: the background asks before the password or code is copied.
  const like = lookalikeOf(item);
  const warn = like ? { lookalike: like, title: item.title || '' } : {};
  const req = { tabId: tab.id, id: item.id, field, ...warn };
  try {
    await unlocking((inline) => send('popup.copy-item', { ...req, ...inlineFlag(inline) }),
      { then: { copy: { type: 'popup.copy-item', ...req } } });
    snack(field === 'username' ? what.done() : what.byApp());
  } catch (err) {
    if (err.code === UNLOCK_CANCELLED || err.code === 'cancelled') return;
    snack(err.code === 'not_supported' ? t('popupCopyNeedsUpdate') : friendlyError(err));
  }
}

/** "Fill on this page": the Passyble desktop app asks first (another site's login: phishing risk). */
async function fillCross(item) {
  // The vault in this browser asks here (the ask view); the desktop app asks in its window.
  if (!state?.browser) snack(t('popupConfirmFill'));
  try {
    const like = lookalikeOf(item);
    const label = state?.browser ? { title: item.title || '', domain: item.domain || '', ...(like ? { lookalike: like } : {}) } : {};
    const res = await send('popup.fill-cross', { tabId: tab.id, id: item.id, ...label });
    if (res && res.ok === false) {
      if (res.error?.code && res.error.code !== 'cancelled') snack(friendlyError(res.error));
      return;
    }
    window.close();
  } catch (err) {
    snack(friendlyError(err));
  }
}

async function showItem(item) {
  try {
    await send('popup.show-item', { tabId: tab.id, id: item.id });
    snack(t('commonOpenedInPassyble'));
  } catch (err) {
    snack(friendlyError(err, { context: 'edit' }));
  }
}

let formsData = null;    // { cards, identities, locked } for this popup, loaded with the first search
let formsLoading = null;

/** Lists the vault's cards and identities once (no secrets), for the search. */
async function loadForms() {
  if (formsData) return formsData;
  formsLoading ??= send('popup.forms', { tabId: tab.id }).then((res) => {
    formsData = { cards: Array.isArray(res?.cards) ? res.cards : [], identities: Array.isArray(res?.identities) ? res.identities : [] };
    return formsData;
  }, () => {
    formsLoading = null;
    return { cards: [], identities: [] };
  });
  return formsLoading;
}

function cardSearchText(c) {
  return `card ${t('popupSearchKeywordsCard')} ${c.title || ''} ${c.cardholder_name || ''} ${brandName(c.brand)} ${c.brand || ''} ${c.last4 || ''}`.toLowerCase();
}

function identitySearchText(i) {
  return `address identity ${t('popupSearchKeywordsIdentity')} ${i.title || ''} ${i.full_name || ''} ${i.email || ''} ${i.company || ''}`.toLowerCase();
}

async function renderForms() {
  const box = $('forms');
  const list = $('forms-list');
  const q = $('search').value.trim().toLowerCase();
  if (vaultOnly || !(state?.can_cards || state?.can_identities) || (q.length < 2 && !typeFilter.browses)) {
    box.hidden = true;
    list.replaceChildren();
    settleFavoritesEmpty();
    return;
  }
  const data = await loadForms();
  if ($('search').value.trim().toLowerCase() !== q) return; // typed on meanwhile
  const words = q.split(/\s+/).filter(Boolean);
  const hit = (text, entry) => vaultFilter.matches(entry.vault_id) && typeFilter.keeps(entry) && words.every((w) => text.includes(w));
  const rows = [
    ...(typeFilter.showsForms('cards') ? data.cards.filter((c) => hit(cardSearchText(c), c)).map(cardRow) : []),
    ...(typeFilter.showsForms('addresses') ? data.identities.filter((i) => hit(identitySearchText(i), i)).map(identityRow) : []),
  ];
  list.replaceChildren(...rows);
  box.hidden = rows.length === 0;
  if (typeFilter.formsOnly) setEmpty(rows.length ? '' : t('popupNoFilterMatches'), { iconName: 'search' });
  settleFavoritesEmpty();
}

function cardRow(card) {
  const label = card.title || cardSummary(card);
  const exp = shortExpiry(card.expiry_month, card.expiry_year);
  const actions = [
    iconButton('creditCard', t('popupCopyCardNumber'), () => copyCard(card, 'number')),
    exp ? iconButton('timer', t('popupCopyExpiry'), () => copy(exp, 'expiry')) : null,
    iconButton('shield', t('popupCopySecurityCode'), () => copyCard(card, 'security_code')),
  ].filter(Boolean);
  return row({
    item: { id: card.id, title: label, vault_id: card.vault_id }, sub: cardSummary(card), actions,
    main: { title: t('popupCopyCardNumber'), ariaLabel: t('popupCopyNumberOf', label), onclick: () => copyCard(card, 'number') },
    avatar: el('span', { class: 'avatar brand' }, brandBadge(card.brand)),
    attrs: { 'data-kind': 'card', 'data-id': card.id },
  });
}

function identityRow(identity) {
  const label = identity.title || identity.full_name || t('commonIdentity');
  const menuItems = () => [
    { icon: 'phone', label: t('popupCopyPhone'), onSelect: () => copyIdentity(identity, 'phone') },
    { icon: 'mapPin', label: t('popupCopyAddress'), onSelect: () => copyIdentity(identity, 'address') },
  ];
  const actions = [
    iconButton('user', t('popupCopyName'), () => copyIdentity(identity, 'full_name')),
    iconButton('mail', t('popupCopyEmail'), () => copyIdentity(identity, 'email')),
    moreButton(label, menuItems),
  ];
  const main = identity.email
    ? { title: t('popupCopyEmail'), ariaLabel: t('popupCopyEmailOf', label), onclick: () => copyIdentity(identity, 'email') }
    : { title: t('popupCopyName'), ariaLabel: t('popupCopyNameOf', label), onclick: () => copyIdentity(identity, 'full_name') };
  return row({
    item: { id: identity.id, title: label, vault_id: identity.vault_id }, sub: identitySummary(identity) || t('commonNameAndAddress'), actions, main,
    avatar: el('span', { class: 'avatar' }, icon('idCard')),
    attrs: { 'data-kind': 'identity', 'data-id': identity.id },
  });
}

/** The desktop app asks first, then copies it itself; an older one sends the value, copied here. Cleared after 45 s either way. */
async function copyCard(card, field) {
  const what = COPIED[field];
  const req = { tabId: tab.id, id: card.id, field };
  try {
    const res = await unlocking((inline) => send('popup.card-copy', { ...req, ...inlineFlag(inline) }),
      { then: { copy: { type: 'popup.card-copy', ...req } } });
    if (res?.copied === true) { snack(what.clears()); return; }
    const value = res?.value;
    if (!value) { snack(what.none()); return; }
    await copy(value, field);
  } catch (err) {
    if (err?.code === UNLOCK_CANCELLED) return;
    snack(err?.code === 'not_supported' ? t('popupCardsNeedUpdate') : friendlyError(err));
  }
}

async function copyIdentity(identity, field) {
  const what = COPIED[field];
  try {
    const { value } = await unlocking((inline) => send('popup.identity-copy', { tabId: tab.id, id: identity.id, field, ...inlineFlag(inline) }));
    if (!value) { snack(what.none()); return; }
    await copy(value, field, { secret: false });
  } catch (err) {
    report(err);
  }
}

let notesData = null;    // the vault's notes (no text) for this popup, loaded when Favorites or Notes is chosen
let notesLoading = null;

/** Titles, favorites and vaults only; never a note's text. */
async function loadNotes() {
  if (notesData) return notesData;
  notesLoading ??= send('popup.notes').then((res) => {
    notesData = Array.isArray(res?.items) ? res.items.filter((n) => n && typeof n.id === 'string') : [];
    noteVaults(res?.vaults);
    return notesData;
  }, () => {
    notesLoading = null;
    return [];
  });
  return notesLoading;
}

async function renderNotes() {
  const box = $('notes');
  const list = $('notes-list');
  if (vaultOnly || !state?.can_note_list || !typeFilter.showsNotes) {
    box.hidden = true;
    list.replaceChildren();
    return;
  }
  const q = $('search').value.trim().toLowerCase();
  const notes = await loadNotes();
  if ($('search').value.trim().toLowerCase() !== q || !typeFilter.showsNotes) return; // changed meanwhile
  const words = q.split(/\s+/).filter(Boolean);
  const rows = notes
    .filter((n) => vaultFilter.matches(n.vault_id) && typeFilter.keeps(n) && words.every((w) => (n.title || '').toLowerCase().includes(w)))
    .map(noteRow);
  list.replaceChildren(...rows);
  box.hidden = rows.length === 0;
  if (typeFilter.noLogins && !typeFilter.formsOnly) setEmpty(rows.length ? '' : t('popupNoFilterMatches'), { iconName: 'search' });
  settleFavoritesEmpty();
}

function noteRow(note) {
  const label = note.title || t('popupUntitled');
  return row({
    item: { id: note.id, title: label, vault_id: note.vault_id }, sub: t('popupSecureNote'), tag: vaultTag(note),
    actions: [iconButton('copy', t('popupCopyNote'), () => noteViewer.copy(note), { ariaLabel: t('popupCopyNoteOf', label) })],
    main: { title: t('popupShowNote'), ariaLabel: t('popupShowNoteOf', label), onclick: () => noteViewer.open(note) },
    avatar: el('span', { class: 'avatar' }, icon('note')),
    attrs: { 'data-kind': 'note', 'data-id': note.id },
  });
}

function settleFavoritesEmpty() {
  if (vaultOnly || !typeFilter.browses || typeFilter.noLogins) return;
  if ($('search').value.trim() && state?.can_search) return;
  const shown = (id) => [...$(id).children].some((li) => !li.hidden);
  const any = shown('list') || (!$('forms').hidden && shown('forms-list')) || (!$('notes').hidden && shown('notes-list'));
  setEmpty(any ? '' : t('popupNoFilterMatches'), { iconName: 'search' });
}

let activeIndex = -1;

function selectableRows() {
  return [...$('list').children, ...$('result-list').children, ...$('forms-list').children, ...$('notes-list').children]
    .filter((li) => !li.hidden && li.classList.contains('item') && li.querySelector('button.item-main'));
}

function setActive(i) {
  const rows = selectableRows();
  activeIndex = rows.length ? Math.max(-1, Math.min(rows.length - 1, i)) : -1;
  rows.forEach((r, n) => {
    r.classList.toggle('active', n === activeIndex);
    r.setAttribute('aria-selected', String(n === activeIndex));
  });
  rows[activeIndex]?.scrollIntoView?.({ block: 'nearest' });
}

function applyFilter() {
  const q = $('search').value.trim().toLowerCase();
  const words = q.split(/\s+/).filter(Boolean);
  let visible = 0;
  for (const li of $('list').children) {
    // Every word somewhere (title or username), in any order, in the vault the filter shows (a pending 2FA code always).
    const match = !li.dataset.search || ((!q || words.every((w) => li.dataset.search.includes(w))) && vaultFilter.matches(li.dataset.vault) && typeFilter.matchesRow(li));
    li.hidden = !match;
    if (match) visible++;
  }
  if (!vaultOnly) {
    // Typing searches the vault too: no "no matches" here while the results come.
    if (visible || typeFilter.noLogins) setEmpty('');
    else if (q && state?.can_search) setEmpty('');
    else if (typeFilter.browses) settleFavoritesEmpty();
    else if (typeFilter.active) setEmpty(t('popupNoFilterMatches'), { iconName: 'search' });
    else if (q) setEmpty(t('popupNoSiteMatches'), { iconName: 'search' });
    else if (vaultFilter.selected) setEmpty(t('popupNoLoginsInVault', vaultName(vaultFilter.selected)), { addLogin: true, caption: t('popupNoSiteLoginsText') });
    else setEmpty(siteHost() ? t('commonNoLoginsFor', siteHost()) : t('popupNoSiteLogins'), { addLogin: true, caption: t('popupNoSiteLoginsText') });
    $('add-login').hidden = !!q || typeFilter.active; // a search shows results, not "Add login"
  }
  $('similar').hidden = vaultOnly || !!q || visible > 0 || !$('similar-list').children.length;
  $('site-title').hidden = !(q && visible && !vaultOnly && state?.can_search);
  const lookup = $('lookup');
  const site = q.replace(/^https?:\/\//, '').split('/')[0];
  // With the vault search, typing a site finds its logins already.
  const looksLikeSite = !state?.can_search && /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(site) && site !== hostOf(state?.url || '');
  lookup.hidden = !looksLikeSite;
  if (looksLikeSite) {
    lookup.replaceChildren(el('button', { class: 'btn', type: 'button', onclick: () => lookupSite(site) }, icon('search'), el('span', {}, t('popupLookUp', site))));
  }
}

function siteHost() {
  return hostOf(state?.url || '').replace(/^www\./, '');
}

async function lookupSite(site) {
  const url = `https://${site}/`;
  const other = $('other');
  const list = $('other-list');
  other.hidden = false;
  $('other-title').textContent = t('popupLoginsFor', site);
  list.replaceChildren(el('li', { class: 'muted results-msg' }, t('popupLookingUp')));
  try {
    const res = await send('popup.find', { url });
    list.replaceChildren();
    if (!res.items?.length) list.append(el('li', { class: 'muted results-msg' }, t('popupNothingForSite')));
    for (const item of res.items || []) list.append(itemRow(item, { lookupUrl: url }));
    if (res.items?.length) showIcons(list, { url });
  } catch (err) {
    list.replaceChildren(el('li', { class: 'muted results-msg' }, friendlyError(err)));
  }
}

async function load() {
  totps.clear();
  show('loading');
  if (unlockOnly) { await loadUnlockOnly(); return; }
  if (askOnly) { await loadAskOnly(); return; }
  [tab] = await ext.tabs.query({ active: true, currentWindow: true });
  updateInfo = await send('update.state').catch(() => null);
  await typeFilter.ready;
  if (updateInfo?.required && !readOnlyOpen) { showUpdateRequired(); return; }
  let failure = null;
  try {
    state = await send('popup.state', { tabId: tab.id });
  } catch (err) {
    if (err.code === 'agent_unavailable') {
      showOffline(isHostMissing(err) ? 'host' : 'stopped');
      return;
    }
    if (err.code === 'locked') {
      state = { locked: true };
    } else {
      state = { supported: false };
      failure = err;
    }
  }
  if (state.no_vault) { showNoVault(); return; }
  if (state.browser) vaultSwitch.hide();
  else vaultSwitch.refresh();
  renderVaultExtras();
  renderVaults();
  vaultOnly = false;
  $('search').closest('.search-row').hidden = false;
  $('add-login').hidden = true;
  $('results').hidden = true;
  $('result-list').replaceChildren();
  searchFound = null;
  $('similar').hidden = true;
  $('similar-list').replaceChildren();
  $('forms').hidden = true;
  $('forms-list').replaceChildren();
  formsData = null;
  formsLoading = null;
  $('notes').hidden = true;
  $('notes-list').replaceChildren();
  notesData = null;
  notesLoading = null;
  if (state.supported === false) {
    setStatus('');
    placeQuickRow(null);
    show('list');
    $('list').replaceChildren();
    $('search').closest('.search-row').hidden = true;
    if (failure) setEmpty(friendlyError(failure), { iconName: 'alert' });
    else {
      setEmpty(t('popupNothingHere'), { iconName: 'globe', searchVault: true, caption: t('popupNothingHereText') });
      $('search-vault').focus();
    }
    startQuickAction();
    return;
  }
  if (state.locked && (!state.soft_locked || state.ask_unlock)) {
    // Windows Hello starts at once when the user opened the popup on a locked vault. Not for `ask_unlock`
    // (the user chose the master password in the page's menu), nor in a tab (nobody clicked the toolbar button).
    showLocked(state.ask_unlock ? { cancellable: !!state.soft_locked } : { auto: !(await inTab()) });
    if (state.ask) showAsk(state.ask, { opened: !!state.ask_opened });
    else startQuickAction();
    return;
  }
  if (state.read_only || updateInfo?.required) { renderReadOnly(); return; }
  renderLoaded();
  if (state.ask) showAsk(state.ask, { opened: !!state.ask_opened });
  else startQuickAction();
}

function startQuickAction() {
  const kind = state?.quick_action;
  if (!kind || unlockOnly || askOnly) return;
  state = { ...state, quick_action: undefined };
  quick.run(kind).catch(() => {});
}

function renderLoaded() {
  // Soft-locked: the list stays (no secrets). Filling, copying a password or code, and editing unlock first.
  setStatus(state.soft_locked ? 'locked' : 'ok');
  show('list');
  placeQuickRow('list');
  renderUpdateTip();
  $('search').placeholder = t('popupSearch');
  if (typeof state.search === 'string' && state.search) $('search').value = state.search.slice(0, 128);
  renderList();
  if ($('search').value.trim().length >= 2) scheduleSearch();
  if ($('search').value.trim().length >= 2 || typeFilter.browses) renderForms();
  renderNotes();
  $('search').focus();
}

function startVaultSearch() {
  vaultOnly = true;
  state = { ...state, items: [], can_search: true };
  setEmpty('');
  $('similar').hidden = true;
  $('search').closest('.search-row').hidden = false;
  $('search').placeholder = t('popupSearchVault');
  $('search').focus();
}

function showUpdateRequired() {
  setStatus('');
  show('update');
  const message = typeof updateInfo?.message === 'string' ? updateInfo.message.trim() : '';
  // The admin's message: plain text only, never markup.
  $('update-message').textContent = message;
  $('update-message').hidden = !message;
  $('update-msg').textContent = '';
  $('update-msg').classList.remove('error');
  $('update-now').disabled = false;
  $('update-now').focus();
}

async function updateNow(button) {
  if (button.disabled) return;
  button.disabled = true;
  const msg = currentView === 'update' ? $('update-msg') : null;
  if (msg) { msg.textContent = t('updateChecking'); msg.classList.remove('error'); }
  try {
    const res = await send('update.apply');
    if (res?.reloading) { if (msg) msg.textContent = t('updateInstalling'); return; }
    closePopup();
  } catch (err) {
    button.disabled = false;
    if (msg) { msg.textContent = friendlyError(err); msg.classList.add('error'); } else snack(friendlyError(err));
  }
}

function renderUpdateTip() {
  $('update-tip').hidden = !(updateInfo?.recommended && !updateInfo.required);
}

function renderReadOnly() {
  const ours = !!updateInfo?.required;
  setStatus(state?.locked ? 'locked' : 'ok');
  show('readonly');
  $('ro-back').hidden = !ours;
  $('ro-note-text').textContent = ours ? t('updateReadOnlyNote') : t('errAppUpdateRequired');
  const canSearch = !!state?.can_search;
  $('ro-search-box').hidden = !canSearch;
  roSeq++;
  $('ro-list').replaceChildren();
  if (!canSearch) { setRoMsg(t('popupSearchNeedsUpdate')); return; }
  const q = $('ro-search').value.trim();
  if (q.length >= 2) runRoSearch(q);
  else setRoMsg(t('updateSearchHint'));
  $('ro-search').focus();
}

function setRoMsg(text) {
  $('ro-msg').textContent = text || '';
}

let roTimer = 0;
let roSeq = 0;

function scheduleRoSearch() {
  clearTimeout(roTimer);
  const q = $('ro-search').value.trim();
  if (q.length < 2) {
    roSeq++;
    $('ro-list').replaceChildren();
    setRoMsg(t('updateSearchHint'));
    return;
  }
  roTimer = setTimeout(() => runRoSearch(q), SEARCH_DEBOUNCE_MS);
}

async function runRoSearch(query) {
  const seq = ++roSeq;
  let res;
  try {
    res = await send('popup.search', { query });
  } catch (err) {
    if (seq !== roSeq) return;
    $('ro-list').replaceChildren();
    setRoMsg(err.code === 'not_supported' ? t('popupSearchNeedsUpdate') : friendlyError(err));
    return;
  }
  if (seq !== roSeq) return;
  const items = (res?.items || []).filter((i) => i && typeof i.id === 'string');
  $('ro-list').replaceChildren(...items.map((item) => readOnlyRow(item)));
  setRoMsg(items.length ? '' : t('menuNoMatches'));
  if (items.length && state?.can_icons) showIcons($('ro-list'), { ids: items.map((i) => i.id) });
}

function readOnlyRow(item) {
  const label = item.title || t('popupUntitledLogin');
  const actions = [
    iconButton('user', t('popupCopyUsername'), () => copyItem(item, 'username')),
    iconButton('key', t('popupCopyPassword'), () => copyItem(item, 'password')),
    item.has_totp ? iconButton('clock', t('popupCopyOtp'), () => copyItem(item, 'totp')) : null,
  ].filter(Boolean);
  const main = { title: t('popupCopyPassword'), ariaLabel: t('popupCopyPasswordOf', label), onclick: () => copyItem(item, 'password') };
  const sub = [item.username || t('commonNoUsername'), item.domain].filter(Boolean).join(' · ');
  return row({ item, sub, main, actions, tag: [item.has_totp ? t('commonBadge2fa') : null], attrs: { 'data-id': item.id } });
}

function backToUpdate() {
  readOnlyOpen = false;
  showUpdateRequired();
}

$('update-now').addEventListener('click', () => { updateNow($('update-now')); });
$('update-tip-now').addEventListener('click', () => { updateNow($('update-tip-now')); });
$('update-tip-close').addEventListener('click', () => {
  $('update-tip').hidden = true;
  if (updateInfo) updateInfo = { ...updateInfo, recommended: false };
  send('update.dismiss').catch(() => {});
});
$('update-view').addEventListener('click', () => { readOnlyOpen = true; load(); });
$('ro-back').addEventListener('click', backToUpdate);
$('ro-search').addEventListener('input', scheduleRoSearch);

const editor = mountEditor($('editor'), {
  send: (type, payload = {}) => unlocking((inline) => send(type, { ...payload, ...inlineFlag(inline) })),
  request: send,
  tab: () => tab,
  state: () => state,
  snack,
  tools: $('edit-tools'),
  setHeading: (text) => { $('edit-heading').textContent = text; },
  vaults: () => pinnedFirst(moveTargets(vaultsInfo?.vaults, answersHome()), vaultFilter.pins),
  onClose: (changed, info) => {
    if (!changed) { show('list'); return; }
    load().then(() => {
      if (info?.deleted) {
        const { id, title } = info.deleted;
        snack(t('popupDeleted', title), { action: t('commonUndo'), onAction: () => restore(id) });
      }
      // A moved login has a new id: its row is the selected one.
      if (info?.moved) {
        setActive(selectableRows().findIndex((li) => li.dataset.id === info.moved.id));
        snack(t('popupMovedTo', vaultName(info.moved.vault)));
      }
    });
  },
});

async function openEditor(item) {
  if (state?.can_edit === false) { snack(MSG.editNeedsUpdate); return; }
  if (await editor.open(item)) show('edit');
}

async function restore(id) {
  try {
    await send('popup.edit-restore', { tabId: tab.id, id });
    await load();
    snack(t('popupRestored'));
  } catch (err) {
    snack(friendlyError(err, { context: 'edit' }));
  }
}

async function ensureUnlocked() {
  if (!state?.locked) return;
  if (state.can_unlock_inline) {
    // From the unlock card itself: its Cancel goes back to the card (askUnlock would go to the list).
    const fromCard = currentView === 'locked';
    try { await askUnlock(); } catch (err) { if (fromCard) load(); throw err; }
  } else {
    await send('popup.unlock');
  }
  state = await send('popup.state', { tabId: tab.id });
  noteVaults(state?.vaults);
  if (state?.locked) throw Object.assign(new Error('Vault is locked'), { code: 'locked' });
}

const quick = mountQuickActions({
  row: $('qa-row'),
  body: $('qa-body'),
  setHeading: (text) => { $('qa-heading').textContent = text; },
  call: (type, payload = {}) => unlocking((inline) => send(type, { ...payload, ...inlineFlag(inline) })),
  request: send,
  tab: () => tab,
  state: () => state,
  ensureUnlocked,
  showView: () => show('qa'),
  onClose: () => { load(); },
  snack,
  copy,
  canEdit: (item) => itemRights(item, vaults).edit,
});

const noteViewer = mountNoteViewer({
  body: $('note-body'),
  setHeading: (text) => { $('note-heading').textContent = text; },
  call: (type, payload = {}) => unlocking((inline) => send(type, { ...payload, ...inlineFlag(inline) })),
  showView: () => show('note'),
  onClose: () => { show('list'); $('search').focus(); },
  snack,
  copy,
});
$('note-back').addEventListener('click', () => noteViewer.close());

let quickInMenu = false;

function placeQuickRow(where) {
  const row = $('qa-row');
  const on = !!where && !unlockOnly && !askOnly && state?.supported !== false && !state?.read_only && !updateInfo?.required;
  quickInMenu = on && where === 'list';
  if (on && where === 'locked') $('view-locked').append(row);
  quick.render({ visible: on && where === 'locked' });
}

function quickMenuItems() {
  if (!quickInMenu || currentView !== 'list') return [];
  const run = (kind) => () => { quick.run(kind).catch(() => {}); };
  return [
    state?.can_edit ? { id: 'menu-scan', icon: 'qr', label: t('qaScanQr'), detail: t('qaScanQrTitle'), onSelect: run('scan') } : null,
    state?.can_notes ? { id: 'menu-note', icon: 'note', label: t('qaNewNote'), onSelect: run('note') } : null,
    { id: 'menu-generate', icon: 'dice', label: t('qaGenerateTitle'), onSelect: run('generate') },
    'sep',
  ];
}

$('qa-back').addEventListener('click', () => quick.back());

$('add-login').addEventListener('click', () => openEditor(null));
$('edit-back').addEventListener('click', () => editor.close());
$('search-vault').addEventListener('click', startVaultSearch);
$('setup-guide').addEventListener('click', () => { openWelcome().catch(() => {}).finally(closePopup); });
$('browser-vault').addEventListener('click', () => { openWelcome('browser').catch(() => {}).finally(closePopup); });
$('novault-create').addEventListener('click', () => { openWelcome('create').catch(() => {}).finally(closePopup); });
$('novault-drive').addEventListener('click', () => { openWelcome('sync').catch(() => {}).finally(closePopup); });
$('novault-signin').addEventListener('click', () => { openWelcome('browser').catch(() => {}).finally(closePopup); });
$('drive-app-chip').addEventListener('click', () => { openWelcome('sync').catch(() => {}).finally(closePopup); });
const reminderTip = attachTooltip($('local-reminder-info'), t('localOnlyBody'));
$('local-reminder-sync').addEventListener('click', () => { openWelcome('sync').catch(() => {}).finally(closePopup); });
$('local-reminder-later').addEventListener('click', () => {
  reminderTip.hide();
  $('local-reminder').hidden = true;
  if (state) state.reminder = false;
  send('vault.reminder-dismiss').catch(() => {});
});
// The one-time move offer: either answer ends it here (Options keeps the move card).
$('move-tip-move').addEventListener('click', () => { send('vault.move-later').catch(() => {}); openOptions('move'); });
$('move-tip-close').addEventListener('click', () => {
  $('move-tip').hidden = true;
  if (state) state.move_offer = null;
  send('vault.move-later').catch(() => {});
});

function openOptions(section) {
  Promise.resolve(ext.tabs.create({ url: `${ext.runtime.getURL('src/options/options.html')}#${section}` })).catch(() => {}).finally(closePopup);
}

function showNoVault() {
  setStatus('');
  show('novault');
  $('novault-create').focus();
}

function renderVaultExtras() {
  const driveNeedsApp = !!(state?.browser && state.drive_needs_app);
  // Only while unlocked: never with the unlock form or a soft-locked list.
  $('local-reminder').hidden = !(state?.browser && state.local_only && state.reminder && !state.locked);
  if ($('local-reminder').hidden) reminderTip.hide();
  $('vault-foot').hidden = !driveNeedsApp;
  const offer = !state?.browser ? state?.move_offer : null;
  $('move-tip').hidden = !offer;
  if (offer) $('move-tip-text').textContent = Number.isInteger(offer.count) && offer.count > 0 ? tp('moveOffer', offer.count) : t('moveOfferAny');
}

/** `stopped`: Passyble isn't running. `host`: the browser has no native messaging host registration (Start can't help). */
function showOffline(kind) {
  $('browser-vault').hidden = !(kind === 'host' && browserVaultSupported());
  vaultSwitch.hide();
  setStatus('offline');
  show('offline');
  const host = kind === 'host';
  const iconEl = $('offline-icon');
  iconEl.setAttribute('data-icon', host ? 'alert' : 'monitor');
  hydrateIcons(iconEl.parentElement);
  $('offline-title').textContent = host ? t('popupHostTitle') : t('popupOfflineTitle');
  $('offline-text').textContent = host ? t('popupHostText') : t('popupOfflineText');
  $('offline-text').hidden = false;
  $('start').hidden = host;
  $('retry').hidden = !host;
  $('start-msg').textContent = '';
  (host ? $('retry') : $('start')).focus();
}

/** The background reopens the native host, which starts the desktop app (~15 s max). */
async function startPass() {
  const btn = $('start');
  const label = btn.querySelector('span');
  btn.disabled = true;
  label.textContent = t('popupStarting');
  $('start-msg').textContent = t('popupStartWait');
  try {
    await send('popup.start');
    $('start-msg').textContent = '';
    await load();
  } catch (err) {
    if (isHostMissing(err)) showOffline('host');
    else $('start-msg').textContent = err.code === 'agent_unavailable' ? MSG.startFailed : friendlyError(err);
  } finally {
    btn.disabled = false;
    label.textContent = t('popupStart');
  }
}

const UNLOCK_CANCELLED = 'cancelled';
let unlockWait = null; // { resolve, reject, then, prev } while the form stands in for an action
let unlockBusy = false;
let helloRun = 0;      // the popup's Windows Hello request that counts (typing the password calls it off)
let helloUp = false;   // that request is pending: the master password field stays usable meanwhile

function report(err) {
  if (err?.code !== UNLOCK_CANCELLED) snack(friendlyError(err));
}

function setUnlockMsg(text, error = false) {
  const node = $('unlock-msg');
  node.textContent = text || '';
  node.classList.toggle('error', !!text && error);
  node.setAttribute('role', error ? 'alert' : 'status');
  if (!!text && error) $('master').setAttribute('aria-invalid', 'true');
  else $('master').removeAttribute('aria-invalid');
}
$('master').addEventListener('input', () => { if ($('master').hasAttribute('aria-invalid')) setUnlockMsg(''); });

function setUnlockBusy(busy, text = '') {
  unlockBusy = busy;
  for (const id of ['master', 'unlock-email', 'unlock-secret-key', 'unlock-shared', 'unlock-submit', 'unlock-hello', 'unlock-app']) $(id).disabled = busy;
  if (busy) setUnlockMsg(text);
}

function showAccountFields(need = {}) {
  const linked = state?.browser ? state.account_unlock : null;
  const label = t(linked ? 'popupPassyblePassword' : 'popupMasterPassword');
  $('master').placeholder = label;
  $('master').setAttribute('aria-label', label);
  const secretKey = !!linked && (linked.secret_key_needed || need.secretKey === true);
  $('unlock-secret-key').hidden = !secretKey;
  $('unlock-shared-row').hidden = !secretKey;
  $('unlock-email').hidden = !(linked && (linked.email_needed || need.email === true));
  $('unlock-approve').hidden = !linked;
}

function accountFieldValues() {
  if (!(state?.browser && state.account_unlock)) return {};
  const out = {};
  if (!$('unlock-secret-key').hidden && $('unlock-secret-key').value.trim()) {
    out.secret_key = $('unlock-secret-key').value;
    out.shared = $('unlock-shared').checked;
  }
  if (!$('unlock-email').hidden && $('unlock-email').value.trim()) out.email = $('unlock-email').value.trim();
  return out;
}

$('unlock-approve').addEventListener('click', () => {
  Promise.resolve(ext.tabs.create({ url: ext.runtime.getURL('src/account/account.html#approve') })).catch(() => {}).finally(closePopup);
});

/** `auto`: the user asked for something that needs the vault, so Windows Hello starts at once unless declined moments ago. */
function showLocked({ cancellable = false, auto = false } = {}) {
  show('locked');
  setStatus('locked');
  const inline = !!state?.can_unlock_inline;
  $('unlock-form').hidden = !inline;
  $('unlock').hidden = inline;
  const browser = !!state?.browser;
  const linked = browser && !!state?.account_unlock;
  $('unlock-alt').hidden = (!inline || browser) && !cancellable && !linked;
  $('unlock-app').hidden = !inline || browser;
  $('unlock-hello').hidden = !(inline && state?.unlock_hello);
  $('unlock-cancel').hidden = !cancellable;
  // The quick actions on the unlock card; not while it stands in for an action or the in-page menu's unlock.
  placeQuickRow(cancellable || state?.ask_unlock ? null : 'locked');
  showAccountFields();
  setUnlockBusy(false);
  setUnlockMsg('');
  $('master').value = '';
  $('unlock-secret-key').value = '';
  (inline ? $('master') : $('unlock')).focus();
  if (auto && inline && state?.unlock_hello && (state.unlock_hello_auto || state.unlock_hello_pending)) startHello();
}

// Resolves once the vault is unlocked (Cancel rejects with `cancelled`). `then`: what the background finishes by itself
// after Windows Hello or "Open Passyble", which take the focus and so may close the popup.
function askUnlock({ then = null, forItem = null } = {}) {
  unlockWait?.reject(Object.assign(new Error('Cancelled'), { code: UNLOCK_CANCELLED }));
  return new Promise((resolve, reject) => {
    unlockWait = { resolve, reject, then, forItem: forItem || then?.fill?.id || null, prev: currentView === 'locked' ? 'list' : currentView };
    showLocked({ cancellable: true, auto: true });
  });
}

// With `inline` the background answers `locked` instead of opening the desktop app's prompt; the form asks and the request runs again.
async function unlocking(run, opts = {}) {
  if (!state?.can_unlock_inline) return run(false);
  try {
    return await run(true);
  } catch (err) {
    if (err?.code !== 'locked') throw err;
    const unlocked = await askUnlock(opts);
    // The background made the copy already (`then.copy`): its answer, not a second copy.
    if (opts.then?.copy && unlocked?.copy) return copyAnswer(unlocked.copy);
    return run(true);
  }
}

function copyAnswer({ result = null, error = null }) {
  if (!error) return result;
  const err = new Error(error.message || 'No response');
  err.code = error.code || 'internal';
  err.reason = error.reason;
  throw err;
}

function inlineFlag(inline) {
  return inline ? { inline: true } : {};
}

function unlockForFlag() {
  const id = unlockWait?.forItem;
  return typeof id === 'string' && id ? { for: id } : {};
}

function unlockDone(result = {}) {
  helloRun++;
  helloUp = false;
  setUnlockBusy(false);
  $('master').value = '';
  const forPage = !!state?.ask_unlock || !!(askState?.ask.kind === 'unlock' && askState.opened);
  if (askState?.ask.kind === 'unlock') askState = null; // the background saw the unlock itself
  if (state) state = { ...state, locked: false, soft_locked: false, ask_unlock: false };
  const wait = unlockWait;
  unlockWait = null;
  if (wait) {
    // Resolve first (a fill goes out before anything else), then show the previous view.
    wait.resolve(result);
    queueMicrotask(() => {
      setStatus('ok');
      show(wait.prev);
      if (wait.prev === 'list') renderList();
    });
    return;
  }
  // Opened by the in-page menu (popup or window): the page fills by itself now.
  if (unlockOnly || forPage) { closePopup(); return; }
  load();
}

function cancelUnlock() {
  if (unlockBusy) return;
  if (helloUp) dropHello();
  // The background waits for this unlock (the browser vault's `unlock`): it is cancelled.
  if (askState?.ask.kind === 'unlock') {
    const { opened } = askState;
    answerAsk({ cancel: true }).catch(() => {});
    askState = null;
    if (opened) { closePopup(); return; }
  }
  const wait = unlockWait;
  unlockWait = null;
  if (wait) {
    show(wait.prev);
    wait.reject(Object.assign(new Error('Cancelled'), { code: UNLOCK_CANCELLED }));
    return;
  }
  if (unlockOnly) { closePopup(); return; }
  state = { ...state, ask_unlock: false };
  renderLoaded();
}

function unlockFailed(err) {
  setUnlockBusy(false);
  if (err?.code === 'agent_unavailable') {
    showOffline(isHostMissing(err) ? 'host' : 'stopped');
    return;
  }
  setUnlockMsg(friendlyError(err, { context: 'unlock' }), err?.code !== 'cancelled');
}

$('unlock-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (unlockBusy) return;
  const input = $('master');
  const linked = !!(state?.browser && state.account_unlock);
  // Firefox's data consent must be asked on the click itself, before any await.
  const consent = linked ? askDataConsent(ACCOUNT_DATA).catch(() => false) : null;
  if (!input.value) {
    setUnlockMsg(t(linked ? 'popupUnlockEmptyAccount' : 'popupUnlockEmpty'), true);
    input.focus();
    return;
  }
  if (helloUp) dropHello();
  setUnlockBusy(true, t('popupUnlocking'));
  try {
    // The popup keeps nothing: the fields are cleared.
    if (consent) await consent;
    await send('popup.unlock-password', { password: input.value, ...accountFieldValues(), ...unlockForFlag() });
    $('unlock-secret-key').value = '';
    unlockDone({ via: 'password' });
  } catch (err) {
    unlockFailed(err);
    input.value = '';
    if (err?.reason === 'secret_key_needed' || err?.reason === 'bad_secret_key') {
      showAccountFields({ secretKey: true });
      $('unlock-secret-key').value = '';
    }
    if (err?.reason === 'email_needed') showAccountFields({ email: true });
    const next = err?.reason === 'email_needed' ? $('unlock-email')
      : err?.reason === 'bad_secret_key' ? $('unlock-secret-key') : input;
    next.focus();
  }
});

/** The desktop app shows Windows Hello over the browser, which may close the popup: the background finishes a pending fill then. */
async function startHello() {
  if (unlockBusy || helloUp) return;
  const run = ++helloRun;
  helloUp = true;
  $('unlock-hello').disabled = true;
  setUnlockMsg(t('popupHelloOrPassword'));
  try {
    const then = unlockWait?.then;
    const res = await send('popup.unlock-hello', { ...(then ? { then } : {}), ...unlockForFlag() });
    if (run !== helloRun) return;
    unlockDone({ via: 'hello', filled: !!res?.filled, ...(res?.copy ? { copy: res.copy } : {}) });
  } catch (err) {
    if (run !== helloRun) return;
    helloUp = false;
    $('unlock-hello').disabled = false;
    // Said no to it (or it can't now): it doesn't start by itself again in this popup.
    if (state && (err?.code === 'cancelled' || err?.code === 'not_supported')) state = { ...state, unlock_hello_auto: false, unlock_hello_pending: false };
    if (currentView !== 'locked') return;
    unlockFailed(err);
    // Not now (turned off, or the master password is due): the form stays for the password.
    if (err?.code === 'not_supported') $('unlock-hello').hidden = true;
    $('master').focus();
  }
}

function dropHello() {
  helloRun++;
  helloUp = false;
  $('unlock-hello').disabled = false;
  if (state) state = { ...state, unlock_hello_auto: false, unlock_hello_pending: false };
  setUnlockMsg('');
  send('popup.unlock-cancel').catch(() => {});
}

$('unlock-hello').addEventListener('click', () => { startHello(); });

$('master').addEventListener('input', () => {
  if (helloUp && $('master').value) dropHello();
});

$('unlock-app').addEventListener('click', async () => {
  if (unlockBusy) return;
  setUnlockBusy(true, t('popupWaitingWindow'));
  try {
    // The desktop app's window takes the focus, which may close the popup: the background finishes
    // the fill or copy the form stands in for (`then`), as after Windows Hello.
    const then = unlockWait?.then;
    const res = await send('popup.unlock', then ? { then } : {});
    unlockDone({ via: 'app', filled: !!res?.filled, ...(res?.copy ? { copy: res.copy } : {}) });
  } catch (err) {
    unlockFailed(err);
  }
});

$('unlock-cancel').addEventListener('click', cancelUnlock);

$('unlock').addEventListener('click', async () => {
  setUnlockMsg(t('popupWaitingWindow'));
  try {
    await send('popup.unlock');
    setUnlockMsg('');
    unlockDone({ via: 'app' });
  } catch (err) {
    setUnlockMsg(friendlyError(err));
  }
});


let syncing = false;

function renderSyncButton(view) {
  const st = state;
  const on = !unlockOnly && !askOnly && !!st && !st.no_vault && !st.read_only && !updateInfo?.required
    && ['list', 'locked', 'qa'].includes(view) && (!st.browser || st.can_sync === true);
  $('sync-btn').hidden = !on;
}

function setSyncBusy(on) {
  const btn = $('sync-btn');
  const label = on ? t('syncSyncing') : t('syncNow');
  btn.classList.toggle('busy', on);
  btn.title = label;
  btn.setAttribute('aria-label', label);
  if (on) btn.setAttribute('aria-busy', 'true');
  else btn.removeAttribute('aria-busy');
}

/** One at a time; the background joins a sync already under way. */
async function syncNow() {
  if (syncing) return;
  syncing = true;
  setSyncBusy(true);
  let outcome;
  try {
    outcome = { result: await unlocking(() => send('popup.sync')) };
  } catch (err) {
    outcome = err?.code === UNLOCK_CANCELLED ? null : { error: err };
  } finally {
    syncing = false;
    setSyncBusy(false);
  }
  if (!outcome) return;
  const { text, kind } = syncOutcome(outcome);
  if (kind === 'none' && outcome.result?.browser) {
    snack(text, { action: t('localOnlySetUpSync'), onAction: () => { openWelcome('sync').catch(() => {}).finally(closePopup); } });
  } else {
    snack(text);
  }
  if (outcome.result && currentView === 'list') renderVaults();
}

$('sync-btn').addEventListener('click', () => { syncNow(); });

$('lock-btn').addEventListener('click', async () => {
  const btn = $('lock-btn');
  if (btn.classList.contains('locked')) {
    if (!state?.can_unlock_inline) $('unlock').click();
    else if (currentView === 'locked') $('master').focus();
    else askUnlock().catch(() => {});
    return;
  }
  if (btn.disabled) return;
  btn.disabled = true;
  try {
    await send('popup.lock');
  } catch (err) {
    btn.disabled = false;
    if (err.code === 'agent_unavailable') { showOffline(isHostMissing(err) ? 'host' : 'stopped'); return; }
    snack(friendlyError(err));
    return;
  }
  btn.disabled = false;
  await load();
});

let askState = null; // { ask: { token, kind, host?, title?, domain?, card? }, prev, opened }
let askBusy = false;

async function checkAsk() {
  let ask = null;
  try { ask = await send('popup.ask-get'); } catch { return; }
  if (ask) showAsk(ask);
}

/** `opened`: the popup (or its small window) opened for the question, so it closes afterwards. */
function showAsk(ask, { opened = false } = {}) {
  const prev = currentView === 'ask' || currentView === 'locked' || currentView === 'loading' ? 'list' : currentView;
  askState = { ask, prev, opened: opened || askOnly };
  if (ask.kind === 'unlock') {
    showLocked({ cancellable: true });
    return;
  }
  const site = ask.host || '';
  // A lookalike page (pass-core's check): the fill or copy says so plainly, in the danger colour.
  const like = typeof ask.lookalike === 'string' ? ask.lookalike : '';
  const lookalikeText = (key, button) => ({ title: t('popupLookalikeTitle'), text: t(key, site, like), button: t(button), icon: 'alert', danger: true });
  const texts = {
    verify: { title: t('popupVerifyTitle'), text: site, button: t('popupAskConfirm'), icon: 'shield' },
    card: { title: t('popupCardConfirmTitle'), text: t('popupCardConfirmText', ask.card || t('popupThisCard'), site), button: t('popupAskFillButton'), icon: 'creditCard' },
    cross: like
      ? lookalikeText('popupLookalikeFillText', 'popupLookalikeFillButton')
      : { title: t('popupCrossConfirmTitle'), text: t('popupCrossConfirmText', ask.title || ask.domain || '', site), button: t('popupAskFillButton'), icon: 'alert' },
    lookalike: like ? lookalikeText('popupLookalikeCopyText', 'popupLookalikeCopyButton') : null,
  }[ask.kind];
  if (!texts) return;
  setStatus(ask.kind === 'verify' ? 'locked' : 'ok');
  show('ask');
  $('ask-title').textContent = texts.title;
  $('ask-text').textContent = texts.text;
  $('ask-text').classList.toggle('danger', !!texts.danger);
  $('ask-submit-label').textContent = texts.button;
  const iconEl = $('ask-icon');
  if (iconEl.getAttribute('data-icon') !== texts.icon) { iconEl.setAttribute('data-icon', texts.icon); hydrateIcons(iconEl.parentElement); }
  const verify = ask.kind === 'verify';
  $('ask-password').hidden = !verify;
  $('ask-password').value = '';
  setAskMsg('');
  // A lookalike warning starts on Cancel: Enter alone never fills or copies there.
  (verify ? $('ask-password') : texts.danger ? $('ask-cancel') : $('ask-submit')).focus();
}

function setAskMsg(text, error = false) {
  const node = $('ask-msg');
  node.textContent = text || '';
  node.classList.toggle('error', !!text && error);
}

async function answerAsk(answer) {
  const ask = askState?.ask;
  if (!ask) return false;
  await send('popup.ask-answer', { token: ask.token, ...answer });
  return true;
}

function askDone() {
  const done = askState;
  askState = null;
  if (!done) return;
  if (done.opened) { closePopup(); return; }
  if (state) setStatus(state.soft_locked ? 'locked' : 'ok');
  show(done.prev || 'list');
  if ((done.prev || 'list') === 'list' && state?.items) renderList();
}

$('ask-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (askBusy || !askState) return;
  const verify = askState.ask.kind === 'verify';
  const input = $('ask-password');
  if (verify && !input.value) { setAskMsg(t('popupUnlockEmpty'), true); input.focus(); return; }
  askBusy = true;
  $('ask-submit').disabled = true;
  if (verify) setAskMsg(t('popupUnlocking'));
  try {
    await answerAsk(verify ? { password: input.value } : { yes: true });
    input.value = '';
    askDone();
  } catch (err) {
    input.value = '';
    // Gone meanwhile (it timed out, or another question replaced it): nothing to answer any more.
    if (err?.code === 'not_found') { askDone(); return; }
    setAskMsg(friendlyError(err, { context: 'unlock' }), true);
    if (verify) input.focus();
  } finally {
    askBusy = false;
    $('ask-submit').disabled = false;
  }
});

$('ask-cancel').addEventListener('click', () => {
  answerAsk({ cancel: true }).catch(() => {});
  askDone();
});

async function loadAskOnly() {
  let ask = null;
  try { ask = await send('popup.ask-get'); } catch { /* none */ }
  if (!ask) { closePopup(); return; }
  if (ask.kind === 'unlock') {
    let opts = { inline: true, hello: false };
    try { opts = await send('popup.unlock-options'); } catch { /* the password form */ }
    state = { locked: true, can_unlock_inline: true, unlock_hello: false, browser: !!opts.browser };
  } else {
    state = { browser: true };
  }
  showAsk(ask, { opened: true });
}

async function loadUnlockOnly() {
  let opts;
  try {
    opts = await send('popup.unlock-options');
  } catch (err) {
    if (err.code === 'agent_unavailable') { showOffline(isHostMissing(err) ? 'host' : 'stopped'); return; }
    opts = { inline: false, locked: true, hello: false };
  }
  if (!opts.locked) { closePopup(); return; }
  state = { locked: true, can_unlock_inline: !!opts.inline, unlock_hello: !!opts.hello };
  showLocked({ cancellable: true });
}
$('start').addEventListener('click', startPass);
$('retry').addEventListener('click', load);

const serverPair = mountServerPair($('server-pair'), { send });
function openServer() {
  if (currentView === 'server') { serverPair.reset(); load(); return; }
  show('server');
  serverPair.focus();
}

// Saved at once through the options page's storage; content scripts and the background follow storage changes.
const quickInputs = () => [...document.querySelectorAll('#quick-list input[data-key]')];
async function openQuick() {
  show('quick');
  const settings = await getSettings();
  for (const input of quickInputs()) input.checked = !!settings[input.dataset.key];
  quickInputs()[0]?.focus();
}
for (const input of quickInputs()) {
  input.addEventListener('change', async () => {
    try { await setSettings({ [input.dataset.key]: input.checked }); } catch { /* the switch shows the stored value on reopen */ }
  });
}
$('quick-back').addEventListener('click', () => load());
$('quick-more').addEventListener('click', () => { ext.runtime.openOptionsPage(); });
$('menu-btn').addEventListener('click', () => openMenu($('menu-btn'), [
  ...quickMenuItems(),
  { id: 'options', icon: 'gear', label: t('popupSettings'), onSelect: openQuick },
  { id: 'help', icon: 'info', label: t('popupSetupGuide'), onSelect: () => { openWelcome().catch(() => {}).finally(closePopup); } },
  { id: 'support', icon: 'link', label: t('popupHelpSupport'), onSelect: () => { send('support.open').catch(() => {}).finally(closePopup); } },
  'sep',
  state?.browser
    ? { id: 'vault', icon: 'cloud', label: t('driveSyncTitle'), onSelect: () => { openWelcome('sync').catch(() => {}).finally(closePopup); } }
    : { id: 'add-server', icon: 'server', label: t('popupAddServer'), onSelect: openServer },
], { label: 'Passyble' }));
$('sensyble').addEventListener('click', () => { Promise.resolve(ext.tabs.create({ url: SENSYBLE_URL })).catch(() => {}); });
$('server-back').addEventListener('click', () => { serverPair.reset(); load(); });
document.addEventListener('keydown', (e) => {
  // Elsewhere the browser closes the popup on Esc as usual; the editor handles its own keys (editor.js onKey).
  if (e.key === 'Escape' && currentView === 'server') { e.preventDefault(); $('server-back').click(); }
  if (e.key === 'Escape' && currentView === 'quick') { e.preventDefault(); $('quick-back').click(); }
  if (e.key === 'Escape' && currentView === 'qa') { e.preventDefault(); quick.back(); }
  if (e.key === 'Escape' && currentView === 'note') { e.preventDefault(); noteViewer.close(); }
  if (e.key === 'Escape' && currentView === 'readonly' && !$('ro-back').hidden) { e.preventDefault(); backToUpdate(); }
  if (e.key === 'Escape' && currentView === 'locked' && !$('unlock-cancel').hidden) { e.preventDefault(); cancelUnlock(); }
});
$('search').addEventListener('input', () => { applyFilter(); setActive(-1); scheduleSearch(); renderForms(); renderNotes(); });
$('search').addEventListener('keydown', (e) => {
  if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
    e.preventDefault();
    const n = selectableRows().length;
    if (n) setActive(e.key === 'ArrowDown' ? (activeIndex + 1) % n : (activeIndex <= 0 ? n - 1 : activeIndex - 1));
    return;
  }
  if (e.key !== 'Enter') return;
  const selected = activeIndex >= 0 ? selectableRows()[activeIndex] : null;
  if (selected) {
    e.preventDefault();
    selected.querySelector('button.item-main')?.click();
    return;
  }
  if (!$('lookup').hidden) {
    $('lookup').querySelector('button')?.click();
    return;
  }
  const first = [...$('list').children].find((li) => !li.hidden && li.dataset.search);
  first?.querySelector('button.item-main')?.click();
});

ext.runtime.onMessage.addListener((msg) => {
  if (msg?.type === 'vault.ask') { checkAsk(); return; }
  if (msg?.type !== 'lock_state') return;
  // A reply of this popup's own unlock is on its way when busy or when its Windows Hello is up for an action the
  // background finishes (`then`): that reply says how it went, so the action isn't sent twice.
  if (currentView === 'locked' && msg.locked === false) {
    if (!unlockBusy && !(helloUp && unlockWait?.then)) unlockDone({ via: 'elsewhere' });
    return;
  }
  if (unlockOnly) return;
  if (currentView !== 'server' && currentView !== 'quick' && ((currentView !== 'edit' && currentView !== 'qa' && currentView !== 'note') || msg.locked)) load();
});

load();

turnOffOnFirstPopup().then((changed) => {
  if (!changed?.length) return;
  snack(t('browserAutofillOff'), {
    action: t('commonUndo'),
    onAction: () => restoreBrowserAutofill(changed).then(() => snack(t('browserAutofillBack'))),
  });
}).catch(() => {});
