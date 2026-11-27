// Setup guide page: a live checklist for the app, or the vault choice when there is no Passyble app.
// Master passwords go to the background once and are cleared from the fields right away.
import { ext, isGecko } from '../shared/api.js';
import { friendlyError, isHostMissing, MSG } from '../shared/messages.js';
import { hydrateIcons, fillWordmark, icon } from '../shared/svg-icon.js';
import { applyI18n, t } from '../shared/i18n.js';
import { setupSteps, vaultStart } from './setup-steps.js';
import { MASTER_CHECK_DEBOUNCE_MS, masterIssueTexts, masterOkText, masterRefusal } from '../shared/master-password.js';
import { readVaultFile } from '../shared/vault-file.js';
import { ACCOUNT_DATA, askDataConsent } from '../shared/data-consent.js';

applyI18n(document);
hydrateIcons(document.body);
const logoEl = document.getElementById('logo');
if (logoEl) fillWordmark(logoEl);

const $ = (id) => document.getElementById(id);

$('all-set-done')?.addEventListener('click', async () => {
  try {
    const tab = await ext.tabs?.getCurrent?.();
    if (tab?.id !== undefined) { await ext.tabs.remove(tab.id); return; }
  } catch { /* not a tab of ours */ }
  try { globalThis.close?.(); } catch { /* ignore */ }
});

export const POLL_MS = 3000;
const POLL_DONE_MS = 15000;
const PIN_KEY = 'guidePinned';
// Independent steps can be done in any order; the others wait for the one before.
const INDEPENDENT = new Set(['access', 'pin']);

const obs = { agent: null, accessNeeded: false, access: true, pinned: false };
let pinnedManual = false;
let starting = false;
let polling = false;
let pollTimer = 0;
let lastError = null;

async function send(type, payload = {}) {
  const res = await ext.runtime.sendMessage({ type, ...payload });
  if (res?.ok) return res.result;
  throw Object.assign(new Error(res?.error?.message || 'No response'), { code: res?.error?.code || 'internal', reason: res?.error?.reason });
}

/** The manifest's host permissions: what Firefox may leave ungranted (MV3 opt-in). */
function hostOrigins() {
  try { return ext.runtime.getManifest?.().host_permissions || []; } catch { return []; }
}

async function hasHostAccess() {
  const origins = hostOrigins();
  if (!origins.length || typeof ext.permissions?.contains !== 'function') return null;
  try { return !!(await ext.permissions.contains({ origins })); } catch { return null; }
}

async function onToolbar() {
  if (typeof ext.action?.getUserSettings !== 'function') return null;
  try {
    const settings = await ext.action.getUserSettings();
    return typeof settings?.isOnToolbar === 'boolean' ? settings.isOnToolbar : null;
  } catch { return null; }
}

async function readPinnedManual() {
  try { return !!(await ext.storage.local.get(PIN_KEY))?.[PIN_KEY]; } catch { return false; }
}

async function poll() {
  // Start Passyble reopens the native port; its own poll follows.
  if (polling || starting) return;
  polling = true;
  clearTimeout(pollTimer);
  try {
    try {
      obs.agent = { status: await send('popup.status') };
      lastError = null;
    } catch (err) {
      obs.agent = { error: { code: err.code, message: err.message } };
      lastError = err;
    }
    const access = await hasHostAccess();
    if (access === false) obs.accessNeeded = true;
    obs.access = access !== false;
    pinnedManual = await readPinnedManual();
    obs.pinned = pinnedManual || (await onToolbar()) === true;
    render();
  } finally {
    polling = false;
    schedule();
  }
}

function schedule() {
  clearTimeout(pollTimer);
  if (globalThis.document?.hidden || !appGuide) return; // again when the tab is shown (or the app checklist)
  pollTimer = setTimeout(poll, setupSteps(obs).allDone ? POLL_DONE_MS : POLL_MS);
}

function shows(what, step, actionable) {
  switch (what) {
    case 'todo': return !step.done;
    case 'done': return step.done;
    case 'active': return !step.done && actionable;
    default: return step.done && step.detail === what; // locked / unlocked
  }
}

function render() {
  const { steps, allDone, checking } = setupSteps(obs);
  for (const step of steps) {
    const li = $(`step-${step.id}`);
    if (!li) continue;
    li.hidden = false;
    // Until the first status arrives (up to ~15 s if it starts Passyble), app steps show no buttons.
    const actionable = INDEPENDENT.has(step.id) || (!checking && step.current);
    li.dataset.state = step.done ? 'done' : step.current ? 'current' : 'todo';
    if (step.current) li.setAttribute('aria-current', 'step');
    else li.removeAttribute('aria-current');
    li.querySelector('[data-step-state]').textContent = step.done ? t('welcomeStepDone') : '';
    for (const part of li.querySelectorAll('[data-show]')) part.hidden = !shows(part.dataset.show, step, actionable);
  }
  $('pin-done').checked = pinnedManual;
  $('all-set').hidden = !allDone;
  const shown = steps.filter((st) => !$(`step-${st.id}`)?.hidden);
  const at = shown.findIndex((st) => st.current);
  $('step-count').textContent = !allDone && at >= 0 ? t('welcomeStepOf', at + 1, shown.length) : '';
  const status = $('check-status');
  if (checking) status.textContent = t('optionsChecking');
  else if (lastError && !isHostMissing(lastError) && lastError.code !== 'agent_unavailable') status.textContent = friendlyError(lastError);
  else status.textContent = '';
}

async function startPass() {
  if (starting) return;
  starting = true;
  const btn = $('start');
  const label = btn.querySelector('span');
  btn.disabled = true;
  label.textContent = t('popupStarting');
  $('start-msg').textContent = t('popupStartWait');
  try {
    await send('popup.start');
    $('start-msg').textContent = '';
  } catch (err) {
    $('start-msg').textContent = isHostMissing(err) || err.code !== 'agent_unavailable' ? friendlyError(err) : MSG.startFailed;
  } finally {
    starting = false;
    btn.disabled = false;
    label.textContent = t('popupStart');
  }
  await poll();
}

export function browserKind() {
  if (isGecko) return 'firefox';
  const nav = globalThis.navigator;
  const brands = nav?.userAgentData?.brands || [];
  if (brands.some((b) => /Edge/i.test(b.brand)) || /\bEdg\//.test(nav?.userAgent || '')) return 'edge';
  if (brands.some((b) => /Opera/i.test(b.brand)) || /\bOPR\//.test(nav?.userAgent || '')) return 'opera';
  // Brave's user agent says Chrome; it has navigator.brave and its own brand.
  if (nav?.brave || brands.some((b) => /Brave/i.test(b.brand))) return 'brave';
  return 'chrome';
}

function accessDeniedHelp() {
  switch (browserKind()) {
    case 'firefox': return t('welcomeAccessDeniedFirefox');
    case 'edge': return t('welcomeAccessDeniedChromium', 'edge://extensions');
    case 'brave': return t('welcomeAccessDeniedChromium', 'brave://extensions');
    case 'opera': return t('welcomeAccessDeniedChromium', 'opera://extensions');
    default: return t('welcomeAccessDeniedChromium', 'chrome://extensions');
  }
}

/** Asks for the host permissions. Called before any await so the click's user gesture is kept. */
function allowAccess() {
  let asked;
  try {
    asked = ext.permissions.request({ origins: hostOrigins() });
  } catch (err) {
    asked = Promise.reject(err);
  }
  Promise.resolve(asked).then((granted) => {
    $('access-msg').textContent = granted ? '' : accessDeniedHelp();
  }, () => {
    $('access-msg').textContent = accessDeniedHelp();
  }).finally(poll);
}

async function setPinnedManual(on) {
  pinnedManual = on;
  obs.pinned = on;
  render();
  try { await ext.storage.local.set({ [PIN_KEY]: on }); } catch { /* shown as ticked until the page closes */ }
  await poll();
}

function pinHelp() {
  const kind = browserKind();
  if (kind === 'firefox') return t('welcomePinFirefox');
  if (kind === 'opera') return t('welcomePinOpera');
  return kind === 'edge' ? t('welcomePinEdge') : t('welcomePinChrome');
}

const VAULT_PARTS = ['choice', 'create', 'open', 'drive', 'ready'];
let vaultInfo = null; // vault.state: { mode, supported, host, has_vault, local_only, drive_needs_app, ... } or null (older background)
let appGuide = true;  // the app checklist is on (polling popup.status)
let busy = false;

function showVaultPart(part, { app = false } = {}) {
  $('vault').hidden = !part;
  for (const p of VAULT_PARTS) $(`vault-${p}`).hidden = p !== part;
  setAppGuide(app);
  const focus = { create: 'create-pw', open: 'open-file', drive: 'drive-download' }[part];
  if (focus) $(focus).focus();
}

function setAppGuide(on) {
  appGuide = on;
  $('setup').hidden = !on;
  if (on) poll();
  else clearTimeout(pollTimer);
}

function setFormMsg(id, text, kind = '') {
  const node = $(id);
  node.textContent = text || '';
  node.className = `muted small form-msg${kind ? ` ${kind}` : ''}`;
}

function hasBrowserVault() {
  return vaultInfo?.mode === 'browser' && !!vaultInfo?.has_vault;
}

function back() {
  if (hasBrowserVault()) showReady();
  else showVaultPart('choice');
}

async function initVault() {
  // `probe`: the background looks whether the Passyble app was installed since; found, it is used here.
  try { vaultInfo = await send('vault.state', { probe: true }); } catch { vaultInfo = null; }
  const hash = String(globalThis.location?.hash || '').replace(/^#/, '');
  const start = vaultStart(vaultInfo, hash);
  if (!vaultInfo?.supported) { showVaultPart(null, { app: true }); return; }
  $('choose-app').hidden = !isWindows();
  // A vault kept here while the app was used: use it again (only while the app isn't installed).
  $('choose-existing').hidden = !(vaultInfo.has_vault && vaultInfo.mode !== 'browser' && !vaultInfo.app_installed);
  $('browser-link').hidden = !!vaultInfo.app_installed;
  $('app-installed-line').hidden = !vaultInfo.app_installed;
  if (start === 'drive') showDrive();
  else if (start === 'ready') showReady();
  else if (start === 'app') showVaultPart(null, { app: true });
  else showVaultPart(start);
}

async function recheckApp() {
  if (appGuide || busy || !vaultInfo?.supported) return;
  let info;
  try { info = await send('vault.state', { probe: true }); } catch { return; }
  if (info?.app_installed) await initVault();
}

function isWindows() {
  const nav = globalThis.navigator;
  return /win/i.test(nav?.userAgentData?.platform || nav?.platform || '') || /Windows/.test(nav?.userAgent || '');
}

function showReady() {
  const local = !!vaultInfo?.local_only;
  const drive = !!vaultInfo?.drive_needs_app;
  $('ready-notice').hidden = !(local || drive);
  $('ready-notice-title').textContent = local ? t('localOnlyTitle') : drive ? t('driveNeedsAppTitle') : '';
  $('ready-notice-text').textContent = local ? t('localOnlyBody') : drive ? t('driveRecordText') : '';
  showVaultPart('ready');
}

async function refreshInfo() {
  try { vaultInfo = await send('vault.state'); } catch { /* keep the last one */ }
}

function showDrive() {
  $('drive-move-hint').hidden = !vaultInfo?.has_vault;
  $('drive-use-app').hidden = true;
  setFormMsg('drive-check-msg', '');
  showVaultPart('drive');
}

async function checkApp() {
  if (busy) return;
  busy = true;
  $('drive-check').disabled = true;
  $('drive-use-app').hidden = true;
  setFormMsg('drive-check-msg', t('optionsChecking'));
  try {
    const { app, mode } = await send('vault.check-app');
    const found = app === 'connected' || app === 'installed';
    setFormMsg('drive-check-msg', found ? t('driveAppFound') : t('driveAppMissing'), found ? 'ok' : '');
    if (found && mode === 'app') {
      busy = false;
      await initVault();
      return;
    }
    // An older background that leaves the switch to the user.
    $('drive-use-app').hidden = !found;
    if (found) $('drive-use-app').focus();
  } catch (err) {
    setFormMsg('drive-check-msg', friendlyError(err), 'error');
  } finally {
    busy = false;
    $('drive-check').disabled = false;
  }
}

async function useApp() {
  if (busy) return;
  busy = true;
  $('drive-use-app').disabled = true;
  try {
    vaultInfo = await send('vault.set-mode', { mode: 'app' });
    showVaultPart(null, { app: true });
  } catch (err) {
    setFormMsg('drive-check-msg', friendlyError(err), 'error');
  } finally {
    busy = false;
    $('drive-use-app').disabled = false;
  }
}

let checkTimer = 0;
let checkSeq = 0; // the newest check asked for; older answers are dropped

function knownNames() {
  return accountState?.signed_in && typeof accountState.email === 'string' && accountState.email ? [accountState.email] : [];
}

function checkMaster(password) {
  return send('vault.check-master', { password, names: knownNames() });
}

function renderStrength(check = null) {
  const out = $('create-strength');
  const issues = masterIssueTexts(check);
  const okText = masterOkText(check);
  if (issues.length) {
    const list = document.createElement('ul');
    list.className = 'master-issues';
    list.setAttribute('aria-label', t('issueListLabel'));
    list.append(...issues.map((i) => {
      const li = document.createElement('li');
      const text = document.createElement('span');
      text.textContent = i.text;
      li.append(icon('alert', { size: 14 }), text);
      return li;
    }));
    out.replaceChildren(list);
    out.dataset.state = 'refused';
  } else if (okText) {
    const line = document.createElement('p');
    line.textContent = okText;
    out.replaceChildren(line);
    out.dataset.state = 'ok';
  } else {
    out.replaceChildren();
    delete out.dataset.state;
  }
}

function onMasterInput() {
  clearTimeout(checkTimer);
  const seq = ++checkSeq;
  const password = $('create-pw').value;
  if (!password) { renderStrength(null); return; }
  checkTimer = setTimeout(async () => {
    let check;
    try { check = await checkMaster(password); } catch { return; } // the submit says what went wrong
    if (seq === checkSeq) renderStrength(check);
  }, MASTER_CHECK_DEBOUNCE_MS);
}

function cancelMasterCheck() {
  clearTimeout(checkTimer);
  checkSeq++;
}

/** The master password must pass the rule first: refused, the first reason shows and nothing is created. */
async function createVault(e) {
  e.preventDefault();
  if (busy) return;
  const pw = $('create-pw');
  const pw2 = $('create-pw2');
  const password = pw.value;
  busy = true;
  $('create-submit').disabled = true;
  try {
    const check = password ? await checkMaster(password) : null;
    if (!check?.ok) {
      cancelMasterCheck();
      renderStrength(check);
      setFormMsg('create-msg', masterRefusal(check), 'error');
      pw.focus();
      return;
    }
    if (password !== pw2.value) { setFormMsg('create-msg', t('welcomePasswordsDiffer'), 'error'); pw2.value = ''; pw2.focus(); return; }
    setFormMsg('create-msg', t('welcomeCreating'));
    cancelMasterCheck();
    await send('vault.create', { password, names: knownNames() });
    pw.value = '';
    pw2.value = '';
    renderStrength(null);
    setFormMsg('create-msg', '');
    await refreshInfo();
    showReady();
  } catch (err) {
    const text = err.code === 'invalid_state' ? t('welcomeVaultExists')
      : err.code === 'invalid_params' ? t('vaultMasterGuessable') : friendlyError(err);
    setFormMsg('create-msg', text, 'error');
  } finally {
    busy = false;
    $('create-submit').disabled = false;
  }
}

async function openVaultFile(e) {
  e.preventDefault();
  if (busy) return;
  const file = $('open-file').files?.[0];
  const pw = $('open-pw');
  // A vault linked to a Passyble account may need the account service: Firefox's data consent, on the click.
  const consent = openLinked ? askDataConsent(ACCOUNT_DATA).catch(() => false) : null;
  if (!file) { setFormMsg('open-msg', t('welcomePickFile'), 'error'); $('open-file').focus(); return; }
  if (!pw.value) { setFormMsg('open-msg', t(openLinked ? 'popupUnlockEmptyAccount' : 'popupUnlockEmpty'), 'error'); pw.focus(); return; }
  busy = true;
  $('open-submit').disabled = true;
  setFormMsg('open-msg', t('popupUnlocking'));
  try {
    if (consent) await consent;
    const payload = { file: await readVaultFile(file), password: pw.value };
    if (openLinked) {
      if (!$('open-sk-part').hidden && $('open-secret-key').value.trim()) {
        Object.assign(payload, { secret_key: $('open-secret-key').value, shared: $('open-shared').checked });
      }
      if (!$('open-email-part').hidden && $('open-email').value.trim()) payload.email = $('open-email').value.trim();
    }
    await send('vault.open-file', payload);
    pw.value = '';
    $('open-secret-key').value = '';
    setFormMsg('open-msg', '');
    await refreshInfo();
    showReady();
  } catch (err) {
    pw.value = '';
    if (err.reason === 'secret_key_needed' || err.reason === 'bad_secret_key') {
      $('open-sk-part').hidden = false;
      $('open-secret-key').value = '';
    }
    if (err.reason === 'email_needed') $('open-email-part').hidden = false;
    const text = err.code === 'invalid_state' && !err.reason ? t('welcomeVaultExists')
      : err.code === 'invalid_params' && !err.reason ? t('welcomeNotVaultFile') : friendlyError(err, { context: 'unlock' });
    setFormMsg('open-msg', text, 'error');
    (err.reason === 'email_needed' ? $('open-email') : err.reason === 'secret_key_needed' || err.reason === 'bad_secret_key' ? $('open-secret-key') : pw).focus();
  } finally {
    busy = false;
    $('open-submit').disabled = false;
  }
}

let openLinked = false;

async function vaultFilePicked() {
  const file = $('open-file').files?.[0];
  let access = null;
  if (file) {
    try { access = await send('vault.file-access', { file: await readVaultFile(file) }); } catch { access = null; }
  }
  openLinked = access?.kind === 'account';
  $('open-pw-label').textContent = t(openLinked ? 'popupPassyblePassword' : 'popupMasterPassword');
  $('open-pw').maxLength = openLinked ? 128 : 1024;
  $('open-sk-part').hidden = !(openLinked && access.secret_key_needed);
  $('open-email-part').hidden = !(openLinked && access.email_needed);
  $('open-email').value = openLinked && access.email ? access.email : '';
}

let accountState = null;

// After Sign in went to the Passyble app (`in_app`): the status again every few seconds until signed in, for a while.
const ACCOUNT_POLL_MS = 3000;
const ACCOUNT_WATCH_MS = 5 * 60_000;
let accountWatch = null;
// `app_syncing` (the handoff check with the Passyble app still running): the status again after this long.
const ACCOUNT_SYNC_RECHECK_MS = 2000;
let accountRecheck = null;

function watchAccount() {
  clearTimeout(accountWatch);
  const until = Date.now() + ACCOUNT_WATCH_MS;
  const tick = async () => {
    await renderAccount();
    if (!accountState?.signed_in && Date.now() < until) accountWatch = setTimeout(tick, ACCOUNT_POLL_MS);
  };
  accountWatch = setTimeout(tick, ACCOUNT_POLL_MS);
}

function signsInHere(st) {
  return st?.app_mode === false || st?.app_reachable === false;
}

async function renderAccount() {
  let st = null;
  try { st = await send('account.status'); } catch { st = null; }
  accountState = st;
  const signedIn = !!st?.signed_in;
  $('choose-signin').hidden = !st || signedIn;
  $('signed-in').hidden = !signedIn;
  $('signed-in-as').textContent = signedIn ? t('accountSignedInAs', st.email) : '';
  $('signed-in-via').hidden = !signedIn || st.via_app !== true;
  $('choose-password').hidden = !signsInHere(st);
  $('cloud-soon').hidden = !signedIn || !!vaultInfo?.has_vault;
  clearTimeout(accountRecheck);
  if (st?.app_syncing) accountRecheck = setTimeout(renderAccount, ACCOUNT_SYNC_RECHECK_MS);
}

async function signIn() {
  if (busy) return;
  // Firefox's data consent, asked on the click itself (before any await); only when the sign-in happens here.
  const consent = signsInHere(accountState) ? askDataConsent(ACCOUNT_DATA) : null;
  busy = true;
  $('choose-signin').disabled = true;
  $('signin-msg').hidden = true;
  let inApp = false;
  try {
    if (consent && !(await consent)) return;
    inApp = (await send('account.sign-in'))?.in_app === true;
  } catch (err) {
    if (err.code !== 'cancelled') {
      $('signin-msg').textContent = t('accountSignInFailed');
      $('signin-msg').hidden = false;
    }
  } finally {
    busy = false;
    $('choose-signin').disabled = false;
  }
  await renderAccount();
  if (inApp) watchAccount();
}

async function useExisting() {
  try {
    await send('vault.set-mode', { mode: 'browser' });
    await refreshInfo();
    showReady();
  } catch (err) {
    $('choice-msg').textContent = friendlyError(err);
    $('choice-msg').hidden = false;
  }
}

$('choose-drive').addEventListener('click', showDrive);
$('cloud-use-drive').addEventListener('click', showDrive);
$('choose-create').addEventListener('click', () => showVaultPart('create'));
$('choose-open').addEventListener('click', () => showVaultPart('open'));
$('choose-signin').addEventListener('click', signIn);
$('choose-existing').addEventListener('click', useExisting);
$('choose-app').addEventListener('click', () => showVaultPart(null, { app: true }));
$('use-browser').addEventListener('click', (e) => { e.preventDefault(); showVaultPart('choice'); $('choose-drive').focus(); });
for (const btn of document.querySelectorAll('[data-back]')) btn.addEventListener('click', back);
$('drive-check').addEventListener('click', checkApp);
$('drive-use-app').addEventListener('click', useApp);
$('create-sync').addEventListener('click', showDrive);
$('ready-sync').addEventListener('click', showDrive);
$('vault-create').addEventListener('submit', createVault);
$('vault-open').addEventListener('submit', openVaultFile);
$('open-file').addEventListener('change', () => { vaultFilePicked(); });
$('create-pw').addEventListener('input', onMasterInput);

$('retry').addEventListener('click', () => poll());
$('start').addEventListener('click', startPass);
$('allow-access').addEventListener('click', allowAccess);
$('pin-done').addEventListener('change', (e) => setPinnedManual(e.target.checked));
$('pin-how').textContent = pinHelp();
document.addEventListener('visibilitychange', () => { if (!document.hidden) { if (appGuide) poll(); else recheckApp(); renderAccount(); } else clearTimeout(pollTimer); });
try { ext.permissions?.onAdded?.addListener(() => poll()); } catch { /* no permission events */ }
document.defaultView?.addEventListener('focus', () => { renderAccount(); });

render();
initVault().finally(renderAccount);
