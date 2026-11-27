import { ext, isGecko } from '../shared/api.js';
import { getSettings, setSettings } from '../shared/settings.js';
import { mountServerPair } from '../ui/server-pair.js';
import { friendlyError, isHostMissing, MSG } from '../shared/messages.js';
import { hydrateIcons, fillWordmark } from '../shared/svg-icon.js';
import { getNeverSave, removeNeverSave, NEVER_SAVE_KEY, NEVER_SAVE_CARDS_KEY } from '../shared/never-save.js';
import { applyI18n, t, tp } from '../shared/i18n.js';
import { AUTO_LOCK_CHOICES, DELETE_BACKUP_MS, lockOnComputerLockSupported } from '../shared/vault-mode.js';
import { downloadVaultFile } from '../shared/vault-file.js';
import { welcomeUrl } from '../shared/welcome-link.js';
import { ACCOUNT_DATA, askDataConsent } from '../shared/data-consent.js';
import { shortcutFromKeyEvent, shortcutsPageUrl, sortCommands } from '../shared/shortcuts.js';

applyI18n(document);
hydrateIcons(document.body);
const logoEl = document.getElementById('logo');
if (logoEl) fillWordmark(logoEl);

const $ = (id) => document.getElementById(id);

function buildNav() {
  const nav = $('side-nav');
  if (!nav) return;
  const groups = [...document.querySelectorAll('main > section.group')].filter((g) => !g.hidden && g.querySelector(':scope > h2'));
  nav.replaceChildren(...groups.map((g) => {
    const a = document.createElement('a');
    a.href = `#${g.id}`;
    a.dataset.section = g.id;
    a.textContent = g.querySelector(':scope > h2').textContent.trim();
    return a;
  }));
  markNav();
}

function markNav() {
  const nav = $('side-nav');
  if (!nav) return;
  const links = [...nav.querySelectorAll('a')];
  const view = document.defaultView;
  const atEnd = view && view.innerHeight + view.scrollY >= document.documentElement.scrollHeight - 2;
  let current = links[0];
  for (const a of links) {
    const top = $(a.dataset.section)?.getBoundingClientRect?.().top ?? 0;
    if (top <= 120) current = a;
  }
  if (atEnd && view.scrollY > 0) current = links[links.length - 1];
  for (const a of links) {
    if (a === current) a.setAttribute('aria-current', 'true');
    else a.removeAttribute('aria-current');
  }
}

buildNav();
try {
  const navWatch = new document.defaultView.MutationObserver(buildNav);
  for (const g of document.querySelectorAll('main > section.group')) navWatch.observe(g, { attributes: true, attributeFilter: ['hidden'] });
} catch { /* no MutationObserver: the nav stays as it was built */ }
document.defaultView?.addEventListener('scroll', markNav, { passive: true });

async function init() {
  const settings = await getSettings();
  for (const input of document.querySelectorAll('input[data-key]')) {
    input.checked = !!settings[input.dataset.key];
    input.addEventListener('change', async () => {
      await setSettings({ [input.dataset.key]: input.checked });
      flash(t('optionsSaved'));
    });
  }
  $('check').addEventListener('click', checkAgent);
  $('help-support').addEventListener('click', () => { send('support.open').catch(() => {}); });
  $('start').addEventListener('click', startPass);
  renderVersion();
  setupShortcuts();
  renderNeverSave();
  setupVault();
  setupAccount();
  try {
    ext.storage.onChanged?.addListener((changes, area) => { if (area === 'local' && (NEVER_SAVE_KEY in changes || NEVER_SAVE_CARDS_KEY in changes)) renderNeverSave(); });
  } catch { /* no change events */ }
}

async function renderNeverSave() {
  const list = $('never-list');
  const [logins, cards] = await Promise.all([getNeverSave(), getNeverSave(NEVER_SAVE_CARDS_KEY)]);
  const sites = [...logins.map((site) => ({ site, key: NEVER_SAVE_KEY })), ...cards.map((site) => ({ site, key: NEVER_SAVE_CARDS_KEY }))];
  list.replaceChildren(...sites.map(({ site, key }) => {
    const row = document.createElement('div');
    row.className = 'row never-site';
    const icon = document.createElement('span');
    icon.className = 'row-icon';
    icon.dataset.icon = 'globe';
    icon.dataset.iconSize = '20';
    const text = document.createElement('span');
    text.className = 'row-text';
    const name = document.createElement('span');
    name.className = 'name';
    name.textContent = site;
    name.title = site;
    text.append(name);
    if (key === NEVER_SAVE_CARDS_KEY) {
      const caption = document.createElement('span');
      caption.className = 'caption';
      caption.textContent = t('optionsNeverSaveCards');
      text.append(caption);
    }
    const remove = document.createElement('button');
    remove.className = 'btn';
    remove.type = 'button';
    remove.dataset.site = site;
    remove.dataset.icon = 'trash';
    remove.setAttribute('aria-label', t('optionsRemoveSite', site));
    remove.title = t('optionsRemoveSiteTitle', site);
    const label = document.createElement('span');
    label.textContent = t('optionsRemove');
    remove.append(label);
    remove.addEventListener('click', async () => {
      remove.disabled = true;
      try {
        await removeNeverSave(site, key);
        flash(t('optionsRemoved'));
      } catch {
        remove.disabled = false;
        flash(t('optionsRemoveFailed'));
      }
      renderNeverSave();
    });
    row.append(icon, text, remove);
    return row;
  }));
  hydrateIcons(list);
  $('never-empty').hidden = sites.length > 0;
}

function renderVersion() {
  let version = '';
  try { version = ext.runtime.getManifest?.().version || ''; } catch { /* no manifest */ }
  if (version) $('version').textContent = version;
}

async function send(type, payload = {}) {
  const res = await ext.runtime.sendMessage({ type, ...payload });
  if (res?.ok) return res.result;
  throw Object.assign(new Error(res?.error?.message || 'No response'), { code: res?.error?.code || 'internal', reason: res?.error?.reason });
}

let flashTimer = 0;
function flash(text) {
  $('saved').textContent = text;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => { $('saved').textContent = ''; }, 1500);
}

function showAgentStatus(kind, text) {
  const out = $('agent-status');
  out.className = `agent-status ${kind}`;
  out.textContent = text;
}

async function checkAgent() {
  showAgentStatus('muted', t('optionsChecking'));
  $('start').hidden = true;
  try {
    const status = await send('popup.status');
    showConnected(status);
  } catch (err) {
    showAgentStatus('bad', friendlyError(err));
    // Passyble not running: offer to start it (useless when the browser has no host registration).
    $('start').hidden = !(err.code === 'agent_unavailable' && !isHostMissing(err));
  }
}

function showConnected(status) {
  showAgentStatus('ok', t('optionsConnected', `Passyble${status?.version ? ` ${status.version}` : ''}`, t(status?.locked ? 'optionsStateLocked' : 'optionsStateUnlocked')));
  $('start').hidden = true;
}

async function startPass() {
  const btn = $('start');
  btn.disabled = true;
  showAgentStatus('muted', t('optionsStarting'));
  try {
    showConnected(await send('popup.start'));
  } catch (err) {
    showAgentStatus('bad', isHostMissing(err) || err.code !== 'agent_unavailable' ? friendlyError(err) : MSG.startFailed);
    $('start').hidden = isHostMissing(err);
  } finally {
    btn.disabled = false;
  }
}

// Chromium: Change opens the browser's shortcuts page. Firefox: Change records the keys here (`commands.update`), Reset uses `commands.reset`.
const canRecord = isGecko && typeof ext.commands?.update === 'function';
const onMac = /Mac/i.test(globalThis.navigator?.platform || '') || /Mac OS X/.test(globalThis.navigator?.userAgent || '');
let recording = null; // { name, key } while a Firefox row waits for its keys

function shortcutMessage(text) {
  const box = $('shortcut-msg');
  if (box) box.textContent = text || '';
}

function shortcutRow(c) {
  const li = document.createElement('li');
  li.dataset.command = c.name;
  const mark = document.createElement('span');
  mark.className = 'row-icon';
  mark.dataset.icon = 'keyboard';
  mark.dataset.iconSize = '20';
  const name = document.createElement('span');
  name.className = 'shortcut-name';
  name.textContent = c.label;
  const key = document.createElement(c.shortcut ? 'kbd' : 'span');
  if (!c.shortcut) key.className = 'muted not-set';
  key.textContent = c.shortcut || t('optionsShortcutNotSet');
  li.append(mark, name, key);
  if (canRecord) {
    const change = document.createElement('button');
    change.type = 'button';
    change.className = 'btn shortcut-record';
    change.textContent = t('optionsShortcutRecord');
    change.setAttribute('aria-label', t('optionsShortcutRecordLabel', c.label));
    change.addEventListener('click', () => startRecording(c, key, change));
    const reset = document.createElement('button');
    reset.type = 'button';
    reset.className = 'link-btn shortcut-reset';
    reset.textContent = t('optionsShortcutReset');
    reset.setAttribute('aria-label', t('optionsShortcutResetLabel', c.label));
    reset.addEventListener('click', () => resetShortcut(c.name));
    li.append(change, reset);
  }
  return li;
}

async function renderShortcuts() {
  const list = $('shortcuts');
  let commands = [];
  try { commands = sortCommands(await ext.commands.getAll()); } catch { /* commands API unavailable */ }
  recording = null;
  list.replaceChildren(...commands.map(shortcutRow));
  hydrateIcons(list);
}

function setupShortcuts() {
  const url = shortcutsPageUrl({ gecko: isGecko });
  if (url) {
    $('shortcut-change').hidden = false;
    $('shortcut-change').addEventListener('click', () => { Promise.resolve(ext.tabs.create({ url })).catch(() => {}); });
  } else {
    $('shortcut-help-text').textContent = t(canRecord ? 'optionsShortcutHelpFirefoxRecord' : 'optionsShortcutHelpFirefox');
  }
  if (canRecord) document.addEventListener('keydown', onRecordKey, true);
  renderShortcuts();
}

function stopRecording() {
  if (!recording) return;
  const { key, button, shortcut } = recording;
  recording = null;
  key.className = shortcut ? '' : 'muted not-set';
  key.textContent = shortcut || t('optionsShortcutNotSet');
  button.removeAttribute('aria-pressed');
}

function startRecording(c, key, button) {
  const again = recording?.name === c.name;
  stopRecording();
  shortcutMessage('');
  if (again) return; // a second click on Change cancels
  recording = { name: c.name, key, button, shortcut: c.shortcut };
  key.className = 'muted recording';
  key.textContent = t('optionsShortcutRecording');
  button.setAttribute('aria-pressed', 'true');
}

async function saveShortcut(name, shortcut) {
  try {
    await ext.commands.update({ name, shortcut });
    shortcutMessage('');
  } catch {
    shortcutMessage(t('optionsShortcutRefused'));
  }
  await renderShortcuts();
}

async function resetShortcut(name) {
  stopRecording();
  try {
    await ext.commands.reset(name);
    shortcutMessage('');
  } catch {
    shortcutMessage(t('optionsShortcutRefused'));
  }
  await renderShortcuts();
}

function onRecordKey(e) {
  if (!recording) return;
  const plain = !e.ctrlKey && !e.altKey && !e.metaKey && !e.shiftKey;
  if (e.key === 'Tab' && plain) { stopRecording(); return; } // keyboard users can leave the row
  e.preventDefault();
  e.stopPropagation();
  if (e.key === 'Escape' && plain) { stopRecording(); return; }
  const { name } = recording;
  if (e.key === 'Backspace' && plain) { stopRecording(); saveShortcut(name, ''); return; }
  const got = shortcutFromKeyEvent(e, { mac: onMac });
  if (got.error) { shortcutMessage(t(got.error === 'key' ? 'optionsShortcutBadKey' : 'optionsShortcutNeedsModifier')); return; }
  if (!got.shortcut) return; // only modifiers so far
  stopRecording();
  saveShortcut(name, got.shortcut);
}

let vault = null; // vault.state, or null (an older background: the cards stay hidden)

async function renderVault({ probe = false } = {}) {
  try { vault = await send('vault.state', probe ? { probe: true } : {}); } catch { vault = null; }
  const on = !!vault?.supported;
  $('vault-mode').hidden = !on;
  const browser = on && vault.mode === 'browser';
  $('vault').hidden = !(browser && vault.has_vault);
  // Browser mode: the Passyble Server card and the desktop app's status are about the app.
  $('server').hidden = browser;
  $('app-status-row').hidden = browser;
  if (!on) return;
  const icon = $('mode-icon');
  const want = browser ? 'shield' : 'monitor';
  if (icon.getAttribute('data-icon') !== want) { icon.setAttribute('data-icon', want); icon.replaceChildren(); hydrateIcons(icon.parentElement); }
  $('mode-name').textContent = browser ? t('optionsModeBrowser') : t('optionsModeApp');
  // While the Passyble app is installed it is used and the vault in this browser isn't offered; once it is gone (several checks) it is offered again.
  const installed = !browser && vault.app_installed === true;
  const gone = !browser && !installed && vault.app_gone === true;
  $('mode-text').textContent = browser
    ? (vault.has_vault ? (vault.locked ? t('optionsModeBrowserLocked') : t('optionsModeBrowserUnlocked')) : t('optionsModeBrowserNone'))
    : installed ? t('vaultAppInstalledHere') : gone ? t('optionsAppGone') : '';
  $('mode-text').hidden = !$('mode-text').textContent;
  $('mode-switch').hidden = installed;
  $('mode-switch-label').textContent = browser ? t('optionsUseApp') : t('optionsUseBrowserVault');
  renderMove();
  $('vault-mode').querySelector('.card').hidden = browser && !!vault.has_vault;
  if (browser && vault.has_vault) renderVaultCard();
}

let moveTargets = null; // vault.move-targets: { vaults, linked } once the form was opened

function renderMove() {
  const card = $('move');
  // Only while the app is installed (running or not): without it there is nowhere to move to.
  const move = vault?.supported && vault.mode !== 'browser' && vault.has_vault && vault.app_installed === true ? vault.move : null;
  card.hidden = !move;
  if (!move) return;
  const moved = move.state === 'moved';
  const partial = move.state === 'partial';
  $('move-title').textContent = moved ? t('moveDoneTitle') : partial ? t('movePartialTitle')
    : Number.isInteger(move.count) && move.count > 0 ? tp('moveOffer', move.count) : t('moveOfferAny');
  $('move-text').textContent = moved ? t('moveDoneText', String(move.added), String(move.skipped))
    : partial ? t('movePartialText', String(move.added), String(move.skipped), String(move.failed_count))
      : t('moveText');
  $('move-start').hidden = moved;
  $('move-start').querySelector('span').textContent = partial ? t('popupRetry') : t('moveStart');
  $('move-delete-start').hidden = !moved;
  const failed = $('move-failed');
  failed.hidden = !partial || !move.failed?.length;
  failed.replaceChildren(...(partial ? move.failed : []).map((title) => {
    const li = document.createElement('li');
    li.textContent = title;
    return li;
  }));
  if (moved) showMoveForm(false);
}

async function showMoveForm(open) {
  $('move-form').hidden = !open;
  $('move-start').disabled = open;
  $('move-pw').value = '';
  $('move-secret-key').value = '';
  setMoveMsg('');
  if (!open) return;
  showMoveDelete(false);
  $('move-pw').focus();
  try { moveTargets = await send('vault.move-targets'); } catch { moveTargets = null; }
  const linked = moveTargets?.linked || null;
  $('move-pw-label').textContent = t(linked ? 'popupPassyblePassword' : 'popupMasterPassword');
  $('move-pw').maxLength = linked ? 128 : 1024;
  $('move-sk-part').hidden = !linked?.secret_key_needed;
  const vaults = Array.isArray(moveTargets?.vaults) ? moveTargets.vaults : [];
  const select = $('move-vault');
  select.replaceChildren(...vaults.map((v) => {
    const opt = document.createElement('option');
    opt.value = v.id;
    opt.textContent = v.name || (v.home ? t('bannerMyVault') : v.id);
    return opt;
  }));
  $('move-vault-part').hidden = vaults.length < 2;
}

async function moveItems(e) {
  e.preventDefault();
  const pw = $('move-pw');
  const linked = !!moveTargets?.linked;
  if (!pw.value) { setMoveMsg(t(linked ? 'popupUnlockEmptyAccount' : 'popupUnlockEmpty'), 'error'); pw.focus(); return; }
  const payload = { password: pw.value };
  if (!$('move-vault-part').hidden && $('move-vault').value) payload.vault = $('move-vault').value;
  if (linked && !$('move-sk-part').hidden && $('move-secret-key').value.trim()) payload.secret_key = $('move-secret-key').value;
  $('move-confirm').disabled = true;
  setMoveMsg(t('moveMoving'));
  try {
    vault = await send('vault.move', payload);
    pw.value = '';
    $('move-secret-key').value = '';
    showMoveForm(false);
    flash(t('optionsSaved'));
    await renderVault();
  } catch (err) {
    pw.value = '';
    setMoveMsg(friendlyError(err, { context: 'unlock' }), 'error');
    pw.focus();
  } finally {
    $('move-confirm').disabled = false;
  }
}

function setMoveMsg(text, kind = '') {
  $('move-msg').textContent = text || '';
  $('move-msg').className = kind ? 'muted form-msg ' + kind : 'muted form-msg';
}

function showMoveDelete(open) {
  $('move-delete-form').hidden = !open;
  $('move-delete-start').disabled = open;
  $('move-delete-msg').textContent = '';
  if (open) $('move-delete-confirm').focus();
}

async function deleteMoved(e) {
  e.preventDefault();
  $('move-delete-confirm').disabled = true;
  try {
    vault = await send('vault.delete-moved', { confirmed: true });
    showMoveDelete(false);
    flash(t('optionsDeleted'));
    await renderVault();
  } catch (err) {
    $('move-delete-msg').textContent = friendlyError(err);
  } finally {
    $('move-delete-confirm').disabled = false;
  }
}

function renderVaultCard() {
  const select = $('v-autolock');
  if (!select.options.length) {
    for (const mins of AUTO_LOCK_CHOICES) {
      const opt = document.createElement('option');
      opt.value = String(mins);
      opt.textContent = mins ? t('optionsAutoLockMinutes', mins) : t('optionsAutoLockBrowserClose');
      select.append(opt);
    }
  }
  const settings = vault.settings || {};
  select.value = String(settings.vaultAutoLockMins ?? 15);
  for (const input of document.querySelectorAll('input[data-vault-key]')) input.checked = !!settings[input.dataset.vaultKey];
  // Only where the browser says when the computer locks (not Firefox, not Safari).
  const idleRow = $('v-lockOnIdle')?.closest('.row');
  if (idleRow) idleRow.hidden = !lockOnComputerLockSupported();
  const tipRow = $('master-tip-row');
  if (tipRow) tipRow.hidden = vault?.master_tip !== true;
  renderStorage();
}

async function dismissMasterTip() {
  const btn = $('master-tip-dismiss');
  btn.disabled = true;
  try {
    vault = await send('vault.master-tip-dismiss');
    $('master-tip-row').hidden = vault?.master_tip !== true;
  } catch (err) {
    flash(friendlyError(err));
  } finally {
    btn.disabled = false;
  }
}

function renderStorage() {
  const local = !!vault?.local_only;
  const drive = !!vault?.drive_needs_app;
  $('local-only-row').hidden = !(local || drive);
  $('local-only-title').textContent = local ? t('localOnlyTitle') : drive ? t('driveNeedsAppShort') : '';
  $('local-only-text').textContent = local ? t('localOnlyBody') : drive ? t('driveRecordText') : '';
}

async function saveVaultSetting(patch) {
  try {
    const settings = await send('vault.settings', { settings: patch });
    if (vault) vault.settings = settings;
    flash(t('optionsSaved'));
  } catch (err) {
    flash(friendlyError(err));
    await renderVault();
  }
}

async function downloadBackup() {
  const btn = $('backup-download');
  btn.disabled = true;
  try {
    downloadVaultFile(await send('vault.export'), document);
    flash(t('vaultCopySaved'));
    await renderVault();
  } catch (err) {
    flash(friendlyError(err));
  } finally {
    btn.disabled = false;
  }
}

/** Switching is the user's: to the app keeps this browser's vault (locked); to the browser needs a vault here (else setup). */
async function switchMode(e) {
  if (!vault) return;
  const btn = e?.currentTarget || $('mode-switch');
  if (vault.mode !== 'browser' && !vault.has_vault) {
    Promise.resolve(ext.tabs.create({ url: welcomeUrl('browser') })).catch(() => {});
    return;
  }
  btn.disabled = true;
  try {
    vault = await send('vault.set-mode', { mode: vault.mode === 'browser' ? 'app' : 'browser' });
    flash(t('optionsSaved'));
  } catch (err) {
    flash(friendlyError(err));
  } finally {
    btn.disabled = false;
    await renderVault();
  }
}

function showDelete(open) {
  $('delete-form').hidden = !open;
  $('delete-start').hidden = open;
  $('delete-pw').value = '';
  $('delete-msg').textContent = '';
  const recent = Number(vault?.backed_up_at) > 0 && Date.now() - vault.backed_up_at < DELETE_BACKUP_MS;
  $('delete-confirm').disabled = !recent;
  if (open) {
    $('delete-msg').textContent = recent ? '' : t('errBackupFirst');
    (recent ? $('delete-pw') : $('backup-download')).focus();
  }
}

async function deleteVault(e) {
  e.preventDefault();
  const pw = $('delete-pw');
  if (!pw.value) { $('delete-msg').textContent = t('popupUnlockEmpty'); pw.focus(); return; }
  $('delete-confirm').disabled = true;
  try {
    vault = await send('vault.delete', { password: pw.value });
    pw.value = '';
    showDelete(false);
    flash(t('optionsDeleted'));
    await renderVault();
  } catch (err) {
    pw.value = '';
    $('delete-msg').textContent = friendlyError(err, { context: 'unlock' });
    $('delete-confirm').disabled = false;
    pw.focus();
  }
}

function setupVault() {
  $('v-autolock').addEventListener('change', (e) => saveVaultSetting({ vaultAutoLockMins: Number(e.target.value) }));
  for (const input of document.querySelectorAll('input[data-vault-key]')) {
    input.addEventListener('change', () => saveVaultSetting({ [input.dataset.vaultKey]: input.checked }));
  }
  $('mode-switch').addEventListener('click', switchMode);
  $('use-app').addEventListener('click', switchMode);
  $('local-only-sync').addEventListener('click', () => { Promise.resolve(ext.tabs.create({ url: welcomeUrl('sync') })).catch(() => {}); });
  $('backup-download').addEventListener('click', downloadBackup);
  $('delete-start').addEventListener('click', () => showDelete(true));
  $('delete-cancel').addEventListener('click', () => showDelete(false));
  $('delete-form').addEventListener('submit', deleteVault);
  $('master-tip-dismiss').addEventListener('click', dismissMasterTip);
  $('move-start').addEventListener('click', () => showMoveForm(true));
  $('move-cancel').addEventListener('click', () => showMoveForm(false));
  $('move-form').addEventListener('submit', moveItems);
  $('move-delete-start').addEventListener('click', () => showMoveDelete(true));
  $('move-delete-cancel').addEventListener('click', () => showMoveDelete(false));
  $('move-delete-form').addEventListener('submit', deleteMoved);
  renderVault({ probe: true }).then(() => {
    const id = String(globalThis.location?.hash || '').replace(/^#/, '');
    if (id === 'vault' || id === 'vault-mode') $(id)?.scrollIntoView?.({ block: 'start' });
    if (id === 'move' && !$('move').hidden) {
      $('move').scrollIntoView?.({ block: 'start' });
      if (vault?.move?.state !== 'moved') showMoveForm(true);
    }
  });
}

let accountState = null;

// After Sign in or Sign out went to the Passyble app (`in_app`): the status again every few seconds for a while.
const ACCOUNT_POLL_MS = 3000;
const ACCOUNT_WATCH_MS = 5 * 60_000;
let accountWatch = null;
// The handoff check with the Passyble app still running (`app_syncing`): the status again in a moment.
const ACCOUNT_SYNC_RECHECK_MS = 2000;
let accountRecheck = null;

function signsInHere(st) {
  return st?.app_mode === false || st?.app_reachable === false;
}

function watchAccount() {
  clearTimeout(accountWatch);
  const before = !!accountState?.signed_in;
  const until = Date.now() + ACCOUNT_WATCH_MS;
  const tick = async () => {
    await renderAccount();
    if (!!accountState?.signed_in === before && Date.now() < until) accountWatch = setTimeout(tick, ACCOUNT_POLL_MS);
  };
  accountWatch = setTimeout(tick, ACCOUNT_POLL_MS);
}

async function renderAccount() {
  let st = null;
  try { st = await send('account.status'); } catch { st = null; }
  accountState = st;
  $('account-row').hidden = !st;
  if (!st) return;
  const signedIn = !!st.signed_in;
  $('account-name').textContent = t('accountTitle');
  $('account-email').textContent = signedIn ? st.email || '' : '';
  $('account-email').hidden = !signedIn || !st.email;
  $('account-email').title = signedIn ? t('accountSignedInAs', st.email) : '';
  $('account-via').hidden = !signedIn || st.via_app !== true;
  $('account-signin').hidden = signedIn;
  $('account-signout').hidden = !signedIn || !$('account-signout-form').hidden;
  if (!signedIn) showSignOutForm(false);
  $('account-password').hidden = !signsInHere(st);
  const other = signedIn && st.app_mode === true && typeof st.browser_email === 'string' && st.browser_email ? st.browser_email : '';
  $('account-other').hidden = !other;
  $('account-other-text').textContent = other ? t('accountOtherInBrowser', st.email || '', other) : '';
  clearTimeout(accountRecheck);
  if (st.app_syncing) accountRecheck = setTimeout(renderAccount, ACCOUNT_SYNC_RECHECK_MS);
}

function showSignOutForm(open) {
  $('account-signout-form').hidden = !open;
  $('account-signout').hidden = open || !accountState?.signed_in;
  if (open) {
    $('account-signout-app').checked = true;
    $('account-signout-confirm').focus();
  }
}

function signOutClicked() {
  if (accountState?.app_peer?.same_account === true) showSignOutForm(true);
  else accountAction('account.sign-out', $('account-signout'));
}

function signOutConfirmed(e) {
  e.preventDefault();
  const alsoApp = $('account-signout-app').checked;
  showSignOutForm(false);
  accountAction('account.sign-out', $('account-signout'), { also_app: alsoApp });
}

async function accountAction(type, btn, payload = {}) {
  // Firefox's data consent, asked on the click itself (before any await); only when the sign-in happens here.
  const consent = type === 'account.sign-in' && signsInHere(accountState) ? askDataConsent(ACCOUNT_DATA) : null;
  btn.disabled = true;
  let inApp = false;
  try {
    if (consent && !(await consent)) return;
    inApp = (await send(type, payload))?.in_app === true;
  } catch (err) {
    if (err.code !== 'cancelled') flash(type === 'account.sign-in' ? t('accountSignInFailed') : friendlyError(err));
  } finally {
    btn.disabled = false;
  }
  await renderAccount();
  if (inApp) watchAccount();
}

function setupAccount() {
  $('account-signin').addEventListener('click', () => accountAction('account.sign-in', $('account-signin')));
  $('account-signout').addEventListener('click', signOutClicked);
  $('account-signout-form').addEventListener('submit', signOutConfirmed);
  $('account-signout-cancel').addEventListener('click', () => showSignOutForm(false));
  $('account-use-app').addEventListener('click', () => accountAction('account.use-app-account', $('account-use-app')));
  document.defaultView?.addEventListener('focus', () => { renderAccount(); });
  renderAccount();
}

const serverPair = mountServerPair($('server-pair'), { send });
if (globalThis.location?.hash === '#server') serverPair.focus();
init();
