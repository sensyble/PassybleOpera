// Master password field inside the in-page menu, an iframe so the page can't read or script it.
// The password goes to the background once and is not kept. postMessage to the menu carries no secret.
import { ext } from '../shared/api.js';
import { applyI18n, t } from '../shared/i18n.js';
import { friendlyError } from '../shared/messages.js';

const $ = (id) => document.getElementById(id);
const input = $('master');
const msg = $('msg');
const NOTE = t('unlockFrameNote');
let busy = false;

function tell(what) {
  try {
    window.parent.postMessage({ passybleUnlock: what, height: document.documentElement.scrollHeight }, '*');
  } catch { /* no parent */ }
}

function say(text, error = false) {
  msg.textContent = text || NOTE;
  msg.classList.toggle('error', !!error);
}

function setBusy(on) {
  busy = on;
  input.disabled = on;
  $('submit').disabled = on;
}

async function send(type, payload) {
  const res = await ext.runtime.sendMessage({ type, ...payload });
  if (res?.ok) return res.result;
  const err = new Error(res?.error?.message || 'No response');
  err.code = res?.error?.code || 'internal';
  err.reason = res?.error?.reason;
  throw err;
}

$('form').addEventListener('submit', async (e) => {
  e.preventDefault();
  if (busy) return;
  if (!input.value) {
    say(t('popupUnlockEmpty'), true);
    input.focus();
    return;
  }
  setBusy(true);
  say(t('popupUnlocking'));
  try {
    await send('popup.unlock-password', { password: input.value });
    input.value = '';
    say('');
    tell('unlocked');
  } catch (err) {
    input.value = '';
    say(friendlyError(err, { context: 'unlock' }), true);
  } finally {
    setBusy(false);
  }
  if (document.hasFocus()) input.focus();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { e.preventDefault(); tell('escape'); }
});

window.addEventListener('message', (e) => {
  if (e.source !== window.parent) return;
  if (e.data?.passybleUnlock === 'focus' && !busy) input.focus();
  if (e.data?.passybleUnlock === 'hello') $('submit').classList.toggle('primary', !e.data.on);
});

applyI18n(document);
say('');
send('account.keys-state').then((st) => {
  if (!st?.linked) return;
  const label = t('popupPassyblePassword');
  const lbl = document.querySelector('label[for="master"]');
  if (lbl) lbl.textContent = label;
  input.setAttribute('aria-label', label);
}).catch(() => {});
const params = new URLSearchParams(location.search);
if (params.get('hello') === '1') $('submit').classList.remove('primary');
if (params.get('focus') === '1') input.focus();
tell('ready');
