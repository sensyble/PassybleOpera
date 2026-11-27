// The card version of edit.js, with the same isolation and postMessage contract (banner.js drives both).
// The card number and security code never come here.
import { ext } from '../shared/api.js';
import { applyI18n, t } from '../shared/i18n.js';
import { icon } from '../shared/svg-icon.js';
import { brandName, shortExpiry } from '../shared/cards.js';
import { parseExpiry } from '../shared/card-rules.js';

const STORE_DEBOUNCE_MS = 400;
const $ = (id) => document.getElementById(id);
const holder = $('holder');
const expiry = $('expiry');
const title = $('title');
const titleField = $('title-field');
const issuesEl = $('issues');

let token = '';
let loading = false;
let wantFocus = false;
let disabled = false;
let timer = 0;
let chain = Promise.resolve();

function tell(what, extra = {}) {
  try {
    window.parent.postMessage({ passybleSave: what, height: document.documentElement.scrollHeight, ...extra }, '*');
  } catch { /* no parent */ }
}

async function send(type, payload) {
  const res = await ext.runtime.sendMessage({ type, ...payload });
  if (res?.ok) return res.result;
  const err = new Error(res?.error?.message || 'No response');
  err.code = res?.error?.code || 'internal';
  throw err;
}

function setDisabled(on) {
  holder.disabled = expiry.disabled = title.disabled = on;
}

function showExpiryHint(show) {
  if (show) {
    const li = document.createElement('li');
    const text = document.createElement('span');
    text.textContent = t('cardEditExpiryHint');
    li.append(icon('alert', { size: 14 }), text);
    issuesEl.replaceChildren(li);
  } else {
    issuesEl.replaceChildren();
  }
  issuesEl.hidden = !show;
  expiry.setAttribute('aria-invalid', String(show));
  tell('height');
}

function expiryOk() {
  const text = expiry.value.trim();
  return !text || !!parseExpiry(text);
}

async function load(candidate) {
  if (token || loading || typeof candidate !== 'string' || !candidate) return;
  loading = true;
  let res;
  try {
    res = await send('card.edit-get', { token: candidate });
  } catch {
    return; // not the banner's token (the page can post here too): wait for the right one
  } finally {
    loading = false;
  }
  token = candidate;
  holder.value = typeof res?.holder === 'string' ? res.holder : '';
  expiry.value = shortExpiry(res?.expiry_month, res?.expiry_year);
  const last4 = typeof res?.last4 === 'string' && /^\d{4}$/.test(res.last4) ? res.last4 : '';
  title.placeholder = last4 ? `${brandName(res?.brand)} •••• ${last4}` : brandName(res?.brand);
  titleField.hidden = res?.mode === 'update';
  setDisabled(disabled);
  if (wantFocus && !disabled) holder.focus();
  tell('loaded');
}

/** An unreadable expiry isn't stored. */
function store() {
  clearTimeout(timer);
  if (!token) return Promise.resolve({ ok: false, code: 'not_found' });
  if (!expiryOk()) { showExpiryHint(true); return Promise.resolve({ ok: false, code: 'invalid_params' }); }
  showExpiryHint(false);
  const values = { token, holder: holder.value, expiry: expiry.value, title: titleField.hidden ? '' : title.value };
  const run = chain.then(() => send('card.edit-set', values)).then(() => ({ ok: true }),
    (err) => ({ ok: false, code: err.code || 'internal' }));
  chain = run;
  return run;
}

for (const input of [holder, expiry, title]) {
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(store, STORE_DEBOUNCE_MS);
  });
  input.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    if (!token || disabled) return;
    const { ok } = await store();
    if (ok) tell('submit');
  });
}

$('form').addEventListener('submit', (e) => e.preventDefault());

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') { e.preventDefault(); tell('escape'); }
});

window.addEventListener('message', async (e) => {
  if (e.source !== window.parent) return;
  const what = e.data?.passybleSave;
  if (what === 'init') {
    load(e.data.token);
  } else if (what === 'flush') {
    const seq = typeof e.data.seq === 'string' ? e.data.seq.slice(0, 64) : '';
    const { ok, code } = await store();
    tell('flushed', ok ? { seq, ok } : { seq, ok, code });
  } else if (what === 'focus') {
    wantFocus = true;
    if (token && !disabled) holder.focus();
  } else if (what === 'disable') {
    disabled = true;
    clearTimeout(timer);
    setDisabled(true);
  }
});

applyI18n(document);
tell('ready');
