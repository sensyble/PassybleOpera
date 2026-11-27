// The in-page generator's options card under a new-password field. Every change makes and fills a new
// value at once (main.js). The value shows as CSS escapes in a closed shadow root (see reveal.js), and
// only trusted events on UI that is really visible count.
import { createClickGuard, createHost, h, passNote, uiIcon, uiIntact } from './ui-common.js';
import { cssEscapedString, charRuns } from './reveal.js';
import { t, tp } from '../shared/i18n.js';
import { MIN_LENGTH, PASSPHRASE_MIN_WORDS } from '../shared/generator.js';

/** Slider ranges (the generator itself takes up to 128 characters and 20 words). */
export const LENGTH_MAX = 64;
export const WORDS_MAX = 12;
const GAP = 6;
const WIDTH = 296;
const CHECK_MS = 250;

/** The character types in the order shown, with what the chips show (the same in every language). */
const TYPES = [
  { name: 'uppercase', chip: 'A-Z', label: 'genUppercase' },
  { name: 'lowercase', chip: 'a-z', label: 'genLowercase' },
  { name: 'digits', chip: '0-9', label: 'genDigits' },
  { name: 'symbols', chip: '!@#', label: 'genSymbols' },
];

const CSS = `
.gen-card { position: absolute; left: 0; top: 0; width: ${WIDTH}px; max-width: calc(100vw - 8px); padding: 12px 14px 14px;
  animation: in .12s ease-out; }
@keyframes in { from { opacity: 0; transform: translateY(-2px); } to { opacity: 1; transform: none; } }
.top { display: flex; align-items: center; gap: 6px; font-size: var(--fs-xs); font-weight: 600; color: var(--text-2); }
.top .pass-note { width: 13px; height: 15px; color: var(--lime-mark); }
.top .title { flex: 1; }
.top .icon-btn { width: 26px; height: 26px; margin: -4px -6px -4px 0; }
.value { margin-top: 8px; padding: 8px 10px; border-radius: var(--r); background: var(--inset); font: 13px/1.35 var(--mono);
  font-variant-numeric: tabular-nums; color: var(--text); overflow-wrap: anywhere; word-break: break-all; letter-spacing: .02em;
  user-select: none; -webkit-user-select: none; min-height: 34px; }
.value .d { color: var(--lime-ink); }
.value .y { color: var(--text-2); }
.value .s { color: var(--text-3); }
.strength { display: flex; align-items: center; gap: 6px; margin-top: 6px; font-size: var(--fs-sm); color: var(--text-2); }
.meter { flex: none; width: 32px; height: 4px; border-radius: 2px; background: var(--border); overflow: hidden; }
.meter i { display: block; height: 100%; background: var(--ok); }
.meter i.fair { background: var(--text); } .meter i.weak { background: var(--danger); }
.modes { display: flex; margin-top: 12px; padding: 2px; border-radius: 999px; background: var(--surface-2); }
.modes label { flex: 1; position: relative; display: grid; place-items: center; min-height: 28px; border-radius: 999px;
  font-size: var(--fs-sm); font-weight: 600; color: var(--text-2); cursor: pointer; }
.modes input { position: absolute; inset: 0; margin: 0; opacity: 0; cursor: pointer; }
.modes label:has(input:checked) { background: var(--surface-raised); color: var(--text); box-shadow: 0 1px 2px rgba(0, 0, 0, .12); }
.modes label:has(input:focus-visible) { outline: 2px solid var(--focus-ring); outline-offset: 1px; }
.row { display: flex; align-items: center; justify-content: space-between; margin-top: 12px; font-size: var(--fs-sm); font-weight: 600; }
.row output { font-variant-numeric: tabular-nums; color: var(--text-2); }
input[type=range] { display: block; width: 100%; margin: 6px 0 0; accent-color: var(--accent); cursor: pointer; }
input[type=range]:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 2px; border-radius: 4px; }
.types { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 10px; }
.chip { position: relative; display: inline-flex; align-items: center; min-height: 28px; padding: 0 12px; border-radius: 999px;
  border: 1px solid var(--border-strong); font: 600 var(--fs-sm)/1 var(--mono); color: var(--text-2); cursor: pointer; }
.chip input { position: absolute; inset: 0; margin: 0; opacity: 0; cursor: pointer; }
.chip:has(input:checked) { background: var(--accent); border-color: var(--accent); color: var(--accent-text); }
.chip:has(input:disabled) { cursor: not-allowed; opacity: .55; }
.chip:has(input:disabled) input { cursor: not-allowed; }
.chip:has(input:focus-visible) { outline: 2px solid var(--focus-ring); outline-offset: 2px; }
.chip.wide { font-family: var(--font); }
.notes { margin-top: 10px; display: flex; flex-direction: column; gap: 4px; }
.note { display: flex; gap: 6px; align-items: flex-start; font-size: var(--fs-sm); color: var(--text-2); }
.note .pass-icon { margin-top: 2px; color: var(--text-3); }
.actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 14px; }
.actions .btn { min-height: 32px; padding: 2px 14px; }
`;

/** Every element in the card that takes the focus, in Tab order. */
function focusables(root) {
  return [...root.querySelectorAll('button, input')].filter((el) => !el.disabled && !el.closest('[hidden]') &&
    !(el.type === 'radio' && !el.checked));
}

/**
 * Shows the options card for `field`. `generate(options, symbols)` makes and fills a new value and resolves
 * to the new `current`; `onClose({ reason, password })`, reason: done, escape, close, outside, typed, gone.
 */
export function showGeneratorOptions(field, { options, symbols, limits = {}, current, generate, focus = false, onClose }) {
  const doc = field.ownerDocument;
  const view = doc.defaultView || window;
  const href = view.location?.href;
  let state = { ...options };
  let withSymbols = symbols !== false;
  let shown = current;
  let closed = false;
  let busy = null;
  let again = false;

  const ui = createHost('gen-options', CSS);
  const sheet = h('style');
  const id = (name) => `g-${name}`;

  const value = h('div', { class: 'value', 'aria-hidden': 'true' });
  const bar = h('i');
  const strengthText = h('span', { id: id('strength'), 'aria-live': 'polite' });
  const closeBtn = h('button', { class: 'icon-btn', type: 'button', title: t('commonClose'), 'aria-label': t('commonClose') },
    uiIcon('close', { size: 14 }));

  const modeInput = (mode, label) => h('label', {},
    h('input', { type: 'radio', name: 'mode', value: mode, 'aria-label': label }), h('span', { 'aria-hidden': 'true' }, label));
  const modes = h('div', { class: 'modes', role: 'radiogroup', 'aria-label': t('genModeLabel') },
    modeInput('password', t('genModePassword')), modeInput('passphrase', t('genModePassphrase')));

  const lengthOut = h('output', { for: id('length') });
  const length = h('input', { id: id('length'), type: 'range', min: String(MIN_LENGTH), max: String(LENGTH_MAX), step: '1',
    'aria-label': t('genLength') });
  const wordsOut = h('output', { for: id('words') });
  const words = h('input', { id: id('words'), type: 'range', min: String(PASSPHRASE_MIN_WORDS), max: String(WORDS_MAX), step: '1',
    'aria-label': t('genWords') });

  const chips = new Map();
  const chip = (name, text, label, cls = 'chip') => {
    const input = h('input', { type: 'checkbox', name, 'aria-label': label, 'aria-describedby': id('notes') });
    chips.set(name, input);
    return h('label', { class: cls, title: label }, input, h('span', { 'aria-hidden': 'true' }, text));
  };
  const passwordPart = h('div', { class: 'part-password' },
    h('div', { class: 'row' }, h('label', { for: id('length') }, t('genLength')), lengthOut), length,
    h('div', { class: 'types', role: 'group', 'aria-label': t('genTypes') }, ...TYPES.map((x) => chip(x.name, x.chip, t(x.label)))));
  const passphrasePart = h('div', { class: 'part-passphrase' },
    h('div', { class: 'row' }, h('label', { for: id('words') }, t('genWords')), wordsOut), words,
    h('div', { class: 'types' }, chip('hyphens', t('genHyphensChip'), t('genHyphens'), 'chip wide')));

  const notes = h('div', { class: 'notes', id: id('notes'), 'aria-live': 'polite' });
  const regenerate = h('button', { class: 'btn', type: 'button' }, uiIcon('retry', { size: 14 }), t('genRegenerate'));
  const done = h('button', { class: 'btn primary', type: 'button' }, t('genDone'));

  const box = h('div', { class: 'gen-card card', role: 'dialog', 'aria-label': t('genOptionsTitle') },
    h('div', { class: 'top' }, passNote(), h('span', { class: 'title' }, t('genOptionsTitle')), closeBtn),
    value,
    h('div', { class: 'strength' }, h('span', { class: 'meter' }, bar), strengthText),
    modes, passwordPart, passphrasePart, notes,
    h('div', { class: 'actions' }, regenerate, done));
  ui.root.append(sheet, h('div', { class: 'pass-ui' }, box));
  const guard = createClickGuard(ui.host, box);

  function render() {
    const passphrase = state.mode === 'passphrase';
    for (const input of modes.querySelectorAll('input')) input.checked = input.value === state.mode;
    passwordPart.hidden = passphrase;
    passphrasePart.hidden = !passphrase;
    const minLength = Math.max(MIN_LENGTH, Math.min(LENGTH_MAX, limits.minLength || MIN_LENGTH));
    const maxLength = Math.max(minLength, Math.min(LENGTH_MAX, limits.maxLength || LENGTH_MAX));
    length.min = String(minLength);
    length.max = String(maxLength);
    length.value = String(Math.max(minLength, Math.min(maxLength, state.length)));
    lengthOut.textContent = length.value;
    words.value = String(state.words);
    wordsOut.textContent = words.value;
    const forbidden = limits.symbols === false;
    const on = { ...state, symbols: withSymbols && !forbidden };
    const count = ['uppercase', 'lowercase', 'digits', 'symbols'].filter((k) => on[k]).length;
    for (const { name } of TYPES) {
      const input = chips.get(name);
      input.checked = !!on[name];
      // The last type still on stays on; a type the field forbids stays off.
      input.disabled = (name === 'symbols' && forbidden) || (on[name] && count === 1);
    }
    const hyphens = chips.get('hyphens');
    hyphens.checked = on.symbols;
    hyphens.disabled = forbidden;
  }

  /** Shows what the field has now: the value (CSS escapes only), its strength and the notes. */
  function show(result) {
    shown = result;
    const runs = charRuns(result.password);
    sheet.textContent = runs.map((run, i) => `.r${i}::before { content: ${cssEscapedString(run.text)}; }`).join('\n');
    value.replaceChildren(...runs.map((run, i) => h('span', { class: `r${i} ${run.kind}` })));
    bar.className = result.bits >= 75 ? '' : result.bits >= 50 ? 'fair' : 'weak';
    bar.style.width = `${Math.max(10, Math.min(100, Math.round((result.bits / 128) * 100)))}%`;
    strengthText.textContent = tp('menuPasswordStrength', result.length, result.label);
    notes.replaceChildren(...(result.notes || []).map((n) => h('div', { class: 'note' }, uiIcon('info', { size: 12 }),
      h('span', {}, n.count === undefined ? t(n.key) : tp(n.key, n.count)))));
    layout();
  }

  /** A new one with the current options; changes made while one is being made wait for it. */
  async function refill() {
    if (busy) { again = true; return busy; }
    busy = (async () => {
      do {
        again = false;
        try {
          const result = await generate({ ...state }, withSymbols);
          if (closed) return;
          if (result?.password) show(result);
        } catch { /* nothing filled: the field keeps the last one */ }
      } while (again && !closed);
    })();
    try { await busy; } finally { busy = null; }
    return undefined;
  }

  /** A change the user made: trusted, on a card that is really there. */
  const real = (e) => e.isTrusted && !closed && uiIntact(ui.host, box);

  for (const input of modes.querySelectorAll('input')) {
    input.addEventListener('change', (e) => {
      if (!real(e) || !input.checked) return;
      state = { ...state, mode: input.value };
      render();
      refill();
    });
  }
  const onSlide = (input, key, out) => input.addEventListener('input', (e) => {
    if (!real(e)) return;
    state = { ...state, [key]: Number(input.value) };
    out.textContent = input.value;
    refill();
  });
  onSlide(length, 'length', lengthOut);
  onSlide(words, 'words', wordsOut);
  for (const [name, input] of chips) {
    input.addEventListener('change', (e) => {
      if (!real(e)) { render(); return; }
      if (name === 'symbols' || name === 'hyphens') withSymbols = input.checked;
      else state = { ...state, [name]: input.checked };
      render();
      refill();
    });
  }

  const click = (btn, fn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      if (closed || !guard.allows(e)) return;
      fn();
    });
  };
  click(regenerate, () => { refill(); });
  click(done, () => close('done'));
  click(closeBtn, () => close('close'));

  // Keyboard: Escape closes, Tab stays inside. The host stops keys from reaching the page (ui-common.js).
  box.addEventListener('keydown', (e) => {
    if (!e.isTrusted) return;
    if (e.key === 'Escape') {
      e.preventDefault();
      close('escape');
    } else if (e.key === 'Tab') {
      const list = focusables(ui.root);
      if (!list.length) return;
      const at = list.indexOf(ui.root.activeElement);
      const next = e.shiftKey ? (at <= 0 ? list.length - 1 : at - 1) : (at < 0 || at === list.length - 1 ? 0 : at + 1);
      e.preventDefault();
      list[next].focus();
    }
  });

  const off = [];
  const on = (target, type, fn, opts) => {
    if (!target?.addEventListener) return;
    target.addEventListener(type, fn, opts);
    off.push(() => target.removeEventListener(type, fn, opts));
  };

  function close(reason = 'close') {
    if (closed) return;
    closed = true;
    clearInterval(timer);
    guard.disconnect();
    off.splice(0).forEach((fn) => fn());
    sheet.textContent = '';
    value.replaceChildren();
    ui.remove();
    try { onClose?.({ reason, password: shown?.password || '' }); } catch { /* ignore */ }
  }

  function layout() {
    if (closed) return;
    const vw = doc.documentElement.clientWidth || view.innerWidth;
    const vh = doc.documentElement.clientHeight || view.innerHeight;
    const r = field.getBoundingClientRect();
    if (!field.isConnected || !r.width || !r.height || r.bottom < 0 || r.top > vh || ui.blocked) { close('gone'); return; }
    const width = box.offsetWidth || WIDTH;
    const height = box.offsetHeight || 0;
    let top = r.bottom + GAP;
    if (height > 0 && top + height > vh - 4 && r.top - height - GAP > 0) top = r.top - height - GAP;
    // Under the field's right end, where the generate button is.
    const left = Math.max(4, Math.min(r.right - width, vw - width - 4));
    ui.place(left, top);
  }

  function check() {
    if (closed) return;
    if (!field.isConnected || (href && view.location?.href !== href)) { close('gone'); return; }
    layout();
  }

  // The user types in the field: their own password, not this one.
  on(field, 'keydown', (e) => { if (e.isTrusted && (e.key.length === 1 || e.key === 'Backspace' || e.key === 'Delete')) close('typed'); });
  on(field, 'paste', (e) => { if (e.isTrusted) close('typed'); });
  // A press anywhere but the card, the field and Passyble's own button beside it.
  for (const type of ['pointerdown', 'mousedown', 'touchstart']) {
    on(view, type, (e) => {
      if (!e.isTrusted) return;
      const path = e.composedPath?.() || [e.target];
      if (path.includes(ui.host) || path.includes(field)) return;
      if (path.some((n) => n?.localName === 'pass-icon')) return;
      close('outside');
    }, { capture: true, passive: true });
  }
  for (const type of ['pagehide', 'popstate', 'hashchange']) on(view, type, () => close('gone'), true);
  on(doc, 'visibilitychange', () => { if (doc.visibilityState === 'hidden') close('gone'); }, true);
  on(view, 'scroll', layout, { capture: true, passive: true });
  on(view, 'resize', layout, { passive: true });

  const timer = setInterval(check, CHECK_MS);
  ui.onlayer = layout;
  ui.mount(field);
  render();
  show(current);
  if (focus) (modes.querySelector('input:checked') || closeBtn).focus();
  return {
    close,
    get closed() { return closed; },
  };
}
