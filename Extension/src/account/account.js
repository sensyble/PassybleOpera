// What is typed goes to the background once and the fields are cleared; the background never hands a key or a token
// to this page. In app mode the Passyble app holds the account key.
import { ext } from '../shared/api.js';
import { applyI18n, t } from '../shared/i18n.js';
import { friendlyError } from '../shared/messages.js';
import { fillWordmark } from '../shared/svg-icon.js';
import { ACCOUNT_DATA, askDataConsent } from '../shared/data-consent.js';

applyI18n(document);
const logoEl = document.getElementById('logo');
if (logoEl) fillWordmark(logoEl);

const $ = (id) => document.getElementById(id);
const POLL_MS = 2000;
const SVG_NS = 'http://www.w3.org/2000/svg';
let busy = false;
let pollTimer = null;

async function send(type, payload = {}) {
  const res = await ext.runtime.sendMessage({ type, ...payload });
  if (res?.ok) return res.result;
  throw Object.assign(new Error(res?.error?.message || 'No response'), { code: res?.error?.code || 'internal', reason: res?.error?.reason });
}

function say(id, text, kind = '') {
  const node = $(id);
  node.textContent = text || '';
  node.classList.toggle('error', kind === 'error' || kind === 'loud');
  node.classList.toggle('loud', kind === 'loud');
  node.setAttribute('role', kind ? 'alert' : 'status');
}

function signedInNote(email, unlocked) {
  const note = $('signed-in-note');
  note.textContent = unlocked ? t('accountSignedInUnlocked', email) : t('accountSignedInAs', email);
  note.hidden = !email;
}

async function passwordSignIn(e) {
  e.preventDefault();
  if (busy) return;
  // Firefox's data consent, asked on the click itself (before any await).
  const consent = askDataConsent(ACCOUNT_DATA);
  const email = $('pw-email');
  const password = $('pw-password');
  const secretKey = $('pw-secret-key');
  if (!email.value.trim()) { say('pw-msg', t('errEmailNeeded'), 'error'); email.focus(); return; }
  if (!password.value) { say('pw-msg', t('popupUnlockEmptyAccount'), 'error'); password.focus(); return; }
  busy = true;
  $('pw-submit').disabled = true;
  say('pw-msg', t('accountSigningIn'));
  try {
    if (!(await consent)) { say('pw-msg', ''); return; }
    const payload = { email: email.value.trim(), password: password.value };
    if (!$('pw-sk-part').hidden && secretKey.value.trim()) Object.assign(payload, { secret_key: secretKey.value, shared: $('pw-shared').checked });
    const res = await send('account.password-sign-in', payload);
    password.value = '';
    secretKey.value = '';
    $('pw-sk-part').hidden = true;
    say('pw-msg', '');
    signedInNote(res?.email || payload.email, res?.unlocked === true);
  } catch (err) {
    password.value = '';
    if (err.reason === 'secret_key_needed' || err.reason === 'bad_secret_key') {
      $('pw-sk-part').hidden = false;
      secretKey.value = '';
    }
    say('pw-msg', friendlyError(err, { context: 'unlock' }), 'error');
    (err.reason === 'secret_key_needed' || err.reason === 'bad_secret_key' ? secretKey : password).focus();
  } finally {
    busy = false;
    $('pw-submit').disabled = false;
  }
}

/** The QR (pass-wasm's one SVG path, quiet zone included), drawn without innerHTML. */
function drawQr(qr) {
  const box = $('ap-qr');
  box.replaceChildren();
  if (!qr?.size || !qr.path) return;
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', `0 0 ${qr.size} ${qr.size}`);
  svg.setAttribute('shape-rendering', 'crispEdges');
  svg.setAttribute('aria-hidden', 'true');
  const path = document.createElementNS(SVG_NS, 'path');
  path.setAttribute('d', qr.path);
  svg.append(path);
  box.append(svg);
}

function approvalStep(step) {
  $('ap-ask').hidden = step !== 'ask';
  $('ap-wait').hidden = step !== 'wait';
  $('ap-code-part').hidden = step !== 'code';
  $('ap-check-part').hidden = step !== 'check';
  $('ap-submit').hidden = step !== 'ask';
  $('ap-cancel').hidden = step !== 'wait' && step !== 'code';
}

function showCheck(fingerprint) {
  $('ap-fingerprint').textContent = String(fingerprint || '');
  approvalStep('check');
  say('ap-msg', '');
}

function showCode(code) {
  $('ap-code').textContent = String(code || '').replace(/^(\d{3})(\d{3})$/, '$1 $2');
}

function stopPolling() {
  clearTimeout(pollTimer);
  pollTimer = null;
}

function schedulePoll() {
  stopPolling();
  pollTimer = setTimeout(poll, POLL_MS);
}

async function poll() {
  pollTimer = null;
  let res;
  try {
    res = await send('account.approval-poll');
  } catch (err) {
    // A network hiccup: try again; anything else ends it.
    if (err.reason === 'account_offline') { schedulePoll(); return; }
    approvalStep('ask');
    say('ap-msg', friendlyError(err), 'error');
    return;
  }
  switch (res?.state) {
    case 'code':
      showCode(res.code);
      approvalStep('code');
      schedulePoll();
      break;
    case 'check':
      // Polled on while the user compares: it keeps the service worker that holds the keys up.
      if ($('ap-check-part').hidden) showCheck(res.fingerprint);
      schedulePoll();
      break;
    case 'denied':
      approvalStep('ask');
      say('ap-msg', t('accountApproveDenied'), 'error');
      break;
    case 'expired':
    case 'none':
      approvalStep('ask');
      say('ap-msg', t('accountApproveExpired'), 'error');
      break;
    default:
      schedulePoll();
  }
}

async function approvalStart(e) {
  e.preventDefault();
  if (busy) return;
  const consent = askDataConsent(ACCOUNT_DATA);
  const email = $('ap-email');
  if (!email.value.trim()) { say('ap-msg', t('errEmailNeeded'), 'error'); email.focus(); return; }
  busy = true;
  $('ap-submit').disabled = true;
  say('ap-msg', '');
  try {
    if (!(await consent)) return;
    const res = await send('account.approval-start', { email: email.value.trim(), shared: $('ap-shared').checked });
    drawQr(res?.qr);
    approvalStep('wait');
    say('ap-msg', t('accountApproveWaiting'));
    schedulePoll();
  } catch (err) {
    say('ap-msg', friendlyError(err), 'error');
  } finally {
    busy = false;
    $('ap-submit').disabled = false;
  }
}

async function approvalCancel() {
  stopPolling();
  const res = await send('account.approval-cancel').catch(() => null);
  approvalStep('ask');
  say('ap-msg', res?.dropped ? t('accountApproveCancelledNotKept') : '', res?.dropped ? 'loud' : '');
}

async function approvalAnswer(matches) {
  if (busy) return;
  busy = true;
  stopPolling();
  $('ap-match').disabled = true;
  $('ap-mismatch').disabled = true;
  try {
    const res = await send('account.approval-confirm', { matches });
    switch (res?.state) {
      case 'done':
        approvalStep('done');
        say('ap-msg', res.unlocked ? t('accountApproveDoneUnlocked') : t('accountApproveDone'));
        signedInNote(res.email || '', res.unlocked === true);
        break;
      case 'rejected':
        approvalStep('ask');
        say('ap-msg', t('accountApproveNotKept'), 'loud');
        break;
      default:
        approvalStep('ask');
        say('ap-msg', t('accountApproveExpired'), 'error');
    }
  } catch (err) {
    approvalStep('ask');
    say('ap-msg', friendlyError(err), 'error');
  } finally {
    busy = false;
    $('ap-match').disabled = false;
    $('ap-mismatch').disabled = false;
  }
}

async function init() {
  let st = null;
  try { st = await send('account.keys-state'); } catch { st = null; }
  const available = st?.available === true;
  $('in-app').hidden = available;
  $('pw-form').hidden = !available;
  $('approve').hidden = !available;
  $('app-only').hidden = !available;
  if (!available) return;
  const status = await send('account.status').catch(() => null);
  if (status?.signed_in && status.email) signedInNote(status.email, false);
  const known = st?.linked?.email || status?.email || '';
  if (known) { $('pw-email').value = known; $('ap-email').value = known; }
  approvalStep('ask');
  // A request this browser made before the page was (re)opened goes on.
  const going = await send('account.approval-poll').catch(() => null);
  if (going?.state === 'check') {
    showCheck(going.fingerprint);
    schedulePoll();
  } else if (going?.state === 'waiting' || going?.state === 'code') {
    approvalStep(going.state === 'code' ? 'code' : 'wait');
    if (going.state === 'code') showCode(going.code);
    else { drawQr(going.qr); say('ap-msg', t('accountApproveWaiting')); }
    schedulePoll();
  }
  if (globalThis.location?.hash === '#approve') {
    $('approve').scrollIntoView?.({ block: 'start' });
    $('ap-email').focus();
  } else {
    (known ? $('pw-password') : $('pw-email')).focus();
  }
}

$('pw-form').addEventListener('submit', passwordSignIn);
$('approve').addEventListener('submit', approvalStart);
$('ap-cancel').addEventListener('click', approvalCancel);
$('ap-match').addEventListener('click', () => approvalAnswer(true));
$('ap-mismatch').addEventListener('click', () => approvalAnswer(false));
document.defaultView?.addEventListener('pagehide', stopPolling);
init();
