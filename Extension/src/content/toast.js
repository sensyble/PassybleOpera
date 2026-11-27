// OTP toast, the fallback when no OTP field is found on the page. It never takes focus.
// Copy goes through the desktop app when it can, which keeps the code out of clipboard history.
import { createHost, createClickGuard, h, passWordmark, copyText, svgTree, uiIcon } from './ui-common.js';
import { secondsLeft, formatCode } from '../shared/otp-logic.js';
import { friendlyError } from '../shared/messages.js';
import { t, tp } from '../shared/i18n.js';

const CSS = `
.toast { position: fixed; top: 12px; right: 12px; width: max-content; min-width: 260px; max-width: min(420px, calc(100vw - 24px));
  padding: var(--sp-2) var(--sp-2) var(--sp-2) var(--sp-3); animation: in .16s ease-out; }
@keyframes in { from { transform: translateY(-6px); opacity: 0; } to { transform: none; opacity: 1; } }
.row { display: flex; align-items: center; gap: 10px; min-height: 30px; }
.row > .wordmark { font-size: 15px; margin-right: 2px; }
.title { flex: 1; min-width: 0; font-weight: 600; overflow: hidden; overflow-wrap: anywhere;
  display: -webkit-box; -webkit-box-orient: vertical; -webkit-line-clamp: 2; }
.title.wrap { display: block; font-weight: 500; }
.label { flex: 1; min-width: 0; display: flex; flex-direction: column; line-height: 1.2; }
.label .title { display: block; font-size: var(--fs-sm); font-weight: 600; color: var(--text-2); flex: none; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.code { font: 600 18px/1.2 var(--mono); letter-spacing: .05em; font-variant-numeric: tabular-nums; }
.ring { width: 20px; height: 20px; flex: none; }
.ring svg { display: block; transform: rotate(-90deg); }
.track { stroke: var(--border); }
.bar { stroke: var(--accent); transition: stroke-dashoffset .9s linear; }
.bar.low { stroke: var(--text); stroke-width: 3.5; }
.toast .btn { min-height: 30px; padding: 2px 12px; }
.note { color: var(--text-2); font-size: var(--fs-sm); margin: 4px 0 2px 28px; }
.note:empty { display: none; }
`;

const R = 8;
const CIRC = 2 * Math.PI * R;

/**
 * `copyByApp` rejects with `not_supported` where the desktop app can't copy (the toast then copies the
 * code itself); `onCopy(code)` gets null when the app copied. Returns { close }.
 */
export function showOtpToast({ title, initial, refresh, onShowDesktop, copyByApp = null, onCopy, onClose, ttlMs = 180_000 }) {
  const ui = createHost('toast', CSS);
  let current = initial;
  let fetchedAt = Date.now();
  let refreshing = false;
  let closed = false;

  const logo = passWordmark();
  const codeEl = h('div', { class: 'code', 'aria-live': 'polite' });
  const bar = svgTree(['circle', { class: 'bar', cx: 10, cy: 10, r: R, fill: 'none', 'stroke-width': 2.5,
    'stroke-linecap': 'round', 'stroke-dasharray': CIRC.toFixed(2) }]);
  const ring = svgTree(['svg', { viewBox: '0 0 20 20', width: 20, height: 20 }, [
    ['circle', { class: 'track', cx: 10, cy: 10, r: R, fill: 'none', 'stroke-width': 2.5 }]]]);
  ring.appendChild(bar);
  const ringEl = h('div', { class: 'ring' }, ring);
  const note = h('div', { class: 'note' });
  const copyLabel = h('span', {}, t('toastCopy'));
  const copyBtn = h('button', { class: 'btn', type: 'button', title: t('toastCopyTitle') }, uiIcon('copy', { size: 14 }), copyLabel);
  const desktopBtn = onShowDesktop
    ? h('button', { class: 'icon-btn', type: 'button', title: t('toastShowDesktopTitle'), 'aria-label': t('toastShowDesktopTitle') }, uiIcon('external'), h('span', { class: 'sr' }, t('toastShowDesktop')))
    : null;
  const closeBtn = h('button', { class: 'icon-btn x', type: 'button', title: t('commonDismiss'), 'aria-label': t('commonDismiss') }, uiIcon('close'));

  const box = h('div', { class: 'toast card', role: 'status' },
    h('div', { class: 'row' }, logo,
      h('div', { class: 'label' }, h('div', { class: 'title' }, t('toastOtpTitle', title || 'Passyble')), codeEl),
      ringEl, copyBtn, desktopBtn, closeBtn),
    note);
  ui.root.append(h('div', { class: 'pass-ui' }, box));
  let guard = null; // created on mount

  const render = () => {
    const period = current.period || 30;
    const left = secondsLeft(current, fetchedAt, Date.now());
    codeEl.textContent = formatCode(current.code);
    ringEl.title = tp('toastSecondsLeft', left);
    bar.setAttribute('stroke-dashoffset', (CIRC * (1 - left / period)).toFixed(2));
    bar.classList.toggle('low', left <= 5);
    if (left <= 0 && !refreshing) {
      refreshing = true;
      refresh().then((next) => { current = next; fetchedAt = Date.now(); render(); },
        (err) => { note.textContent = t('toastRefreshFailed', friendlyError(err)); })
        .finally(() => { refreshing = false; });
    }
  };

  const tick = setInterval(render, 1000);
  const expiry = setTimeout(() => close(), ttlMs);

  function close() {
    if (closed) return;
    closed = true;
    clearInterval(tick);
    clearTimeout(expiry);
    guard?.disconnect();
    ui.remove();
    onClose?.();
  }

  let copying = false;
  const copied = (ok) => {
    copyLabel.textContent = ok ? t('toastCopied') : t('toastCopyFailed');
    setTimeout(() => { copyLabel.textContent = t('toastCopy'); }, 1500);
  };
  copyBtn.addEventListener('click', async (e) => {
    if (copying || !guard?.allows(e)) return;
    copying = true;
    try {
      if (copyByApp) {
        try {
          await copyByApp();
          if (closed) return;
          note.textContent = '';
          copied(true);
          onCopy?.(null);
          return;
        } catch (err) {
          if (closed) return;
          if (err?.code !== 'not_supported') {
            note.textContent = friendlyError(err);
            copied(false);
            return;
          }
        }
      }
      // The desktop app can't copy, so use the page's clipboard API.
      const code = current.code;
      const ok = await copyText(code, ui.root);
      copied(ok);
      if (ok) onCopy?.(code);
    } finally {
      copying = false;
    }
  });
  desktopBtn?.addEventListener('click', (e) => {
    if (!guard?.allows(e)) return;
    onShowDesktop().then(() => { note.textContent = t('toastShownDesktop'); },
      (err) => { note.textContent = friendlyError(err); });
  });
  closeBtn.addEventListener('click', (e) => { if (e.isTrusted) close(); });

  render();
  ui.mount();
  guard = createClickGuard(ui.host, box);
  return { close, get closed() { return closed; } };
}

/** A short self-dismissing notice; longer messages stay up longer. */
export function showNotice(text, ms = Math.max(3500, String(text).length * 70)) {
  const ui = createHost('notice', CSS);
  const logo = passWordmark();
  const closeBtn = h('button', { class: 'icon-btn x', type: 'button', title: t('commonDismiss'), 'aria-label': t('commonDismiss') }, uiIcon('close'));
  const remove = () => { clearTimeout(timer); ui.remove(); };
  closeBtn.addEventListener('click', (e) => { if (e.isTrusted) remove(); });
  ui.root.append(h('div', { class: 'pass-ui' }, h('div', { class: 'toast card', role: 'status' },
    h('div', { class: 'row' }, logo, h('div', { class: 'title wrap' }, text), closeBtn))));
  ui.mount();
  const timer = setTimeout(remove, ms);
  return { close: remove };
}

/** A toast with one action, which needs a real click on the visible toast (ui-common.js). `onAction` gets `{ done(text) }`. */
export function showActionToast({ text, detail = null, action, onAction, onClose, ms = 10_000 }) {
  const ui = createHost('action-toast', CSS);
  const logo = passWordmark();
  const title = h('div', { class: 'title' }, text);
  if (detail) title.title = detail;
  const note = h('div', { class: 'note' });
  note.hidden = true;
  const actionBtn = h('button', { class: 'btn primary', type: 'button' }, action);
  const closeBtn = h('button', { class: 'icon-btn x', type: 'button', title: t('commonDismiss'), 'aria-label': t('commonDismiss') }, uiIcon('close'));
  const box = h('div', { class: 'toast card', role: 'status' },
    h('div', { class: 'row' }, logo, title, actionBtn, closeBtn),
    note);
  ui.root.append(h('div', { class: 'pass-ui' }, box));
  let closed = false;
  let guard = null;
  let timer = setTimeout(close, ms);

  function close() {
    if (closed) return;
    closed = true;
    clearTimeout(timer);
    guard?.disconnect();
    ui.remove();
    onClose?.();
  }

  actionBtn.addEventListener('click', async (e) => {
    if (closed || !guard?.allows(e)) return;
    actionBtn.disabled = true;
    clearTimeout(timer);
    await onAction?.({
      done(message) {
        title.textContent = message;
        actionBtn.hidden = true;
        note.hidden = true;
        clearTimeout(timer);
        timer = setTimeout(close, 3000);
      },
    });
  });
  closeBtn.addEventListener('click', (e) => { if (e.isTrusted) close(); });
  ui.mount();
  guard = createClickGuard(ui.host, box);
  return { close, get closed() { return closed; } };
}
