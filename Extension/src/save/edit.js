// Username and password fields of the "Save login?" banner, an iframe so the page around it can't read or
// script them. The page can read postMessage traffic, so messages to the banner carry no secret, and
// messages from the banner (window.parent, which the page could imitate) can't read a value.
import { ext } from '../shared/api.js';
import { applyI18n, t } from '../shared/i18n.js';
import { icon, hydrateIcons } from '../shared/svg-icon.js';
import { CHECK_DEBOUNCE_MS, issueTexts } from '../shared/password-issues.js';

const $ = (id) => document.getElementById(id);
const user = $('username');
const pw = $('password');
const reveal = $('reveal');
const issuesEl = $('issues');

let token = '';       // the banner's one-time token, once save.edit-get accepted it
let loading = false;
let wantFocus = false;
let disabled = false;
let timer = 0;
let storeSeq = 0;
let chain = Promise.resolve(); // save.edit-set calls, in order

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

function showIssues(check) {
  const list = issueTexts(check);
  issuesEl.replaceChildren(...list.map((i) => {
    const li = document.createElement('li');
    li.className = i.severity;
    const text = document.createElement('span');
    text.textContent = i.text;
    li.append(icon('alert', { size: 14 }), text);
    return li;
  }));
  issuesEl.hidden = list.length === 0;
  tell('height');
}

function setDisabled(on) {
  user.disabled = pw.disabled = reveal.disabled = on;
}

/** A wrong token gets nothing from the background. */
async function load(candidate) {
  if (token || loading || typeof candidate !== 'string' || !candidate) return;
  loading = true;
  let res;
  try {
    res = await send('save.edit-get', { token: candidate });
  } catch {
    return; // not the banner's token (the page can post here too): wait for the right one
  } finally {
    loading = false;
  }
  token = candidate;
  user.value = typeof res?.username === 'string' ? res.username : '';
  const hasPassword = typeof res?.password === 'string' && res.password !== '';
  pw.value = hasPassword ? res.password : '';
  pw.placeholder = hasPassword ? '' : t('bannerKeepPassword');
  showIssues(res?.check ?? null);
  setDisabled(disabled);
  if (wantFocus && !disabled) user.focus();
  tell('loaded');
}

function store() {
  clearTimeout(timer);
  if (!token) return Promise.resolve({ ok: false, code: 'not_found' });
  const seq = ++storeSeq;
  const values = { token, username: user.value, password: pw.value };
  const run = chain.then(() => send('save.edit-set', values)).then((res) => {
    if (seq === storeSeq) showIssues(res?.check ?? null);
    return { ok: true };
  }, (err) => ({ ok: false, code: err.code || 'internal' }));
  chain = run;
  return run;
}

for (const input of [user, pw]) {
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(store, CHECK_DEBOUNCE_MS);
  });
  input.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter') return;
    e.preventDefault();
    if (!token || disabled) return;
    await store();
    tell('submit');
  });
}

reveal.addEventListener('mousedown', (e) => e.preventDefault());
reveal.addEventListener('click', () => {
  const shown = pw.type === 'password';
  pw.type = shown ? 'text' : 'password';
  reveal.title = shown ? t('commonHidePassword') : t('commonShowPassword');
  reveal.setAttribute('aria-label', reveal.title);
  reveal.setAttribute('aria-pressed', String(shown));
  reveal.setAttribute('data-icon', shown ? 'eyeOff' : 'eye');
  hydrateIcons(reveal.parentNode);
});

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
    if (token && !disabled) user.focus();
  } else if (what === 'disable') {
    disabled = true;
    clearTimeout(timer);
    setDisabled(true);
  }
});

applyI18n(document);
hydrateIcons(document.body);
tell('ready');
