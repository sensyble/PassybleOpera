// Shows a just-generated password once in a callout under its field, until the user leaves the field.
//
// The field stays `type=password`: a text field would land in form history and the page could watch
// the type change. The password is never a text node or attribute, even in the shadow root, because
// Chromium's window.find() searches closed shadow roots and a page could guess it character by
// character. The characters are CSS escapes in generated content instead, which find() skips.
// The callout closes on blur, any key or edit, a click elsewhere, submit, navigation, scrolling out of
// view, a modal dialog, or REVEAL_TTL_MS.
import { copyText, createClickGuard, createHost, h, passNote, uiIcon } from './ui-common.js';
import { t } from '../shared/i18n.js';

export const REVEAL_TTL_MS = 30_000;
const CHECK_MS = 250;
const GAP = 6;
const FONT_MIN = 12;
const FONT_MAX = 24;
const FEEDBACK_MS = 1500;

const CSS = `
.reveal { position: absolute; left: 0; top: 0; width: max-content; max-width: min(480px, calc(100vw - 16px));
  padding: 12px 14px 14px; border-radius: var(--r-lg); pointer-events: none; user-select: none; -webkit-user-select: none;
  animation: in .12s ease-out; }
@keyframes in { from { opacity: 0; transform: translateY(-2px); } to { opacity: 1; transform: none; } }
.cap { display: flex; align-items: center; gap: 6px; font-size: var(--fs-xs); font-weight: 600; line-height: 16px; color: var(--text-2); }
.cap .pass-note { width: 13px; height: 15px; color: var(--lime-mark); }
.cap .text { margin-inline-end: 10px; }
.copy { margin-inline-start: auto; min-height: 26px; padding: 0 10px; gap: 4px; border-radius: 999px; font-size: var(--fs-sm);
  pointer-events: auto; }
.pw { margin-top: 8px; font-family: var(--mono); font-variant-numeric: tabular-nums; line-height: 1.35; color: var(--text); white-space: pre-wrap;
  overflow-wrap: anywhere; word-break: break-all; letter-spacing: .02em; }
.pw .d { color: var(--lime-ink); }
.pw .y { color: var(--text-2); }
.pw .s { color: var(--text-3); }
.tip { position: absolute; left: 14px; top: -5px; width: 8px; height: 8px; background: var(--surface-raised);
  transform: rotate(45deg); }
.reveal.above .tip { top: auto; bottom: -5px; transform: rotate(225deg); }
`;

/** A CSS string with every character escaped, e.g. `"\00006a\000068"`. */
export function cssEscapedString(text) {
  let out = '"';
  for (const ch of text) out += '\\' + ch.codePointAt(0).toString(16).padStart(6, '0');
  return out + '"';
}

/** Runs of 'l' letters, 'd' digits, 'y' symbols or 's' spaces (shown as ␣). */
export function charRuns(text) {
  const runs = [];
  for (const ch of text) {
    const kind = /\p{Nd}/u.test(ch) ? 'd' : /\p{L}|\p{M}/u.test(ch) ? 'l' : /\s/u.test(ch) ? 's' : 'y';
    const shown = kind === 's' ? '␣' : ch;
    const last = runs[runs.length - 1];
    if (last?.kind === kind) last.text += shown;
    else runs.push({ kind, text: shown });
  }
  return runs;
}

function focused(field) {
  try {
    const root = field.getRootNode();
    return root.activeElement === field;
  } catch {
    return false;
  }
}

const MODIFIER_KEYS = new Set(['Shift', 'Control', 'Alt', 'Meta', 'AltGraph', 'CapsLock', 'Fn', 'OS']);

/**
 * Shows `password` beside `field` while it keeps the focus. Null unless `field` is a connected, focused
 * type=password input holding exactly `password`. `onCopy` runs after a copy made here, not by the app.
 */
export function showGeneratedPassword(field, password, { ttlMs = REVEAL_TTL_MS, copyByApp = null, onCopy, onClose } = {}) {
  if (!field?.isConnected || field.tagName !== 'INPUT' || typeof password !== 'string' || !password) return null;
  if ((field.getAttribute('type') || '').toLowerCase() !== 'password' || field.type !== 'password') return null;
  if (field.value !== password || !focused(field)) return null;

  const doc = field.ownerDocument;
  const view = doc.defaultView || window;
  const href = view.location?.href;
  let secret = password;
  let closed = false;

  const ui = createHost('reveal', CSS);
  const sheet = h('style');
  const pw = h('div', { class: 'pw' });
  const runs = charRuns(secret);
  sheet.textContent = runs.map((run, i) => `.r${i}::before { content: ${cssEscapedString(run.text)}; }`).join('\n');
  runs.forEach((run, i) => pw.appendChild(h('span', { class: `r${i} ${run.kind}` })));
  const fontPx = Math.min(FONT_MAX, Math.max(FONT_MIN, parseFloat(view.getComputedStyle?.(field)?.fontSize) || 14));
  pw.style.fontSize = `${fontPx}px`;
  const logo = passNote();
  const copyLabel = h('span', {}, t('toastCopy'));
  // tabindex -1 so Tab leaves the field and closes the callout.
  const copyBtn = h('button', { class: 'btn copy', type: 'button', tabindex: '-1' }, uiIcon('copy', { size: 12 }), copyLabel);
  // Otherwise a screen reader reads the password out unasked.
  pw.setAttribute('aria-hidden', 'true');
  const box = h('div', { class: 'reveal card' },
    h('div', { class: 'tip' }),
    h('div', { class: 'cap' }, logo, h('span', { class: 'text' }, t('revealCaption')), copyBtn),
    pw);
  ui.root.append(sheet, h('div', { class: 'pass-ui' }, box));
  const guard = createClickGuard(ui.host, box);
  let copying = false;
  let keepOpen = false;
  let feedback = 0;

  const off = [];
  const on = (target, type, fn, opts) => {
    if (!target?.addEventListener) return;
    target.addEventListener(type, fn, opts);
    off.push(() => target.removeEventListener(type, fn, opts));
  };
  const dismiss = () => close();

  function close() {
    if (closed) return;
    closed = true;
    secret = null;
    clearTimeout(expiry);
    clearInterval(timer);
    clearTimeout(feedback);
    guard.disconnect();
    off.splice(0).forEach((fn) => fn());
    sheet.textContent = '';
    pw.replaceChildren();
    ui.remove();
    try { onClose?.(); } catch { /* ignore */ }
  }

  function layout() {
    if (closed) return;
    const vw = doc.documentElement.clientWidth || view.innerWidth;
    const vh = doc.documentElement.clientHeight || view.innerHeight;
    const r = field.getBoundingClientRect();
    // Closed for good, never shown again later.
    if (!r.width || !r.height || r.bottom < 0 || r.top > vh || r.right < 0 || r.left > vw || ui.blocked) { close(); return; }
    // CSSOM styles are allowed under a strict page CSP.
    box.style.minWidth = `${Math.round(Math.max(0, Math.min(r.width, 480, vw - 16)))}px`;
    const width = box.offsetWidth || 0;
    const height = box.offsetHeight || 0;
    let top = r.bottom + GAP;
    const above = height > 0 && top + height > vh - 4 && r.top - height - GAP > 0;
    if (above) top = r.top - height - GAP;
    box.classList.toggle('above', above);
    const left = Math.max(4, Math.min(r.left, vw - width - 4));
    ui.place(left, top);
  }

  async function copy() {
    const value = secret;
    copying = true;
    let ok = false;
    try {
      await copyByApp?.(value);
      ok = !!copyByApp;
    } catch { /* the app can't copy, so copy here */ }
    if (closed) return;
    if (!ok) {
      // The copyText fallback selects its own textarea, which steals focus from the field.
      keepOpen = true;
      ok = await copyText(value, ui.root);
      if (!closed && !focused(field) && (!doc.activeElement || doc.activeElement === doc.body)) field.focus();
      keepOpen = false;
      if (ok) try { onCopy?.(value); } catch { /* ignore */ }
    }
    copying = false;
    check();
    if (closed) return;
    copyLabel.textContent = t(ok ? 'toastCopied' : 'toastCopyFailed');
    layout();
    clearTimeout(feedback);
    feedback = setTimeout(() => { copyLabel.textContent = t('toastCopy'); layout(); }, FEEDBACK_MS);
  }

  // Keep focus in the field, or the blur would close the callout before the click lands.
  copyBtn.addEventListener('mousedown', (e) => e.preventDefault());
  copyBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (closed || copying || !guard.allows(e)) return;
    copy().catch(() => {});
  });

  function check() {
    if (closed) return;
    if (!field.isConnected || !focused(field) || field.value !== secret || field.type !== 'password' ||
        (href && view.location?.href !== href)) {
      close();
      return;
    }
    layout();
  }

  // Untrusted events count too: closing is always safe.
  on(field, 'blur', () => { if (!keepOpen) close(); });
  on(field, 'keydown', (e) => { if (!MODIFIER_KEYS.has(e.key)) close(); });
  for (const type of ['beforeinput', 'input', 'paste', 'cut', 'drop', 'compositionstart']) on(field, type, dismiss);
  // A press anywhere but the field or Copy. The rest of the callout passes clicks through to the page.
  for (const type of ['pointerdown', 'mousedown', 'touchstart']) {
    on(view, type, (e) => {
      const path = e.composedPath?.() || [e.target];
      if (!path.includes(field) && !path.includes(ui.host)) close();
    }, { capture: true, passive: true });
  }
  on(field.form, 'submit', dismiss, true);
  on(field.getRootNode(), 'submit', dismiss, true);
  on(view, 'submit', dismiss, true);
  for (const type of ['blur', 'pagehide', 'beforeunload', 'popstate', 'hashchange']) on(view, type, dismiss, true);
  on(doc, 'visibilitychange', () => { if (doc.visibilityState === 'hidden') close(); }, true);
  on(view, 'scroll', layout, { capture: true, passive: true });
  on(view, 'resize', layout, { passive: true });

  const timer = setInterval(check, CHECK_MS);
  const expiry = setTimeout(close, ttlMs);
  ui.onlayer = layout;
  ui.mount(field);
  layout();
  return { close, get closed() { return closed; } };
}
