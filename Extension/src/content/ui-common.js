// Shared in-page UI helpers. Each UI lives in a closed shadow root so page CSS and scripts cannot
// read or restyle it; handlers check `isTrusted` so page scripts cannot click for the user.
import { icon, wordmarkNote } from '../shared/svg-icon.js';
import { messageLocale, textDirection } from '../shared/i18n.js';

const hosts = new Set();

export function isOwnNode(node) {
  for (const h of hosts) if (h === node || h.contains(node)) return true;
  return false;
}

// Stopped at the host so the page's "click outside" handlers and shortcuts never see our UI's events.
const CONTAINED_EVENTS = ['pointerdown', 'pointerup', 'mousedown', 'mouseup', 'click', 'dblclick', 'auxclick',
  'touchstart', 'touchend', 'focusin', 'focusout', 'keydown', 'keyup', 'keypress'];

/**
 * Creates a fixed-position host with a closed shadow root. `mount(anchor)` shows it above the page;
 * `anchor` is the field the UI belongs to, none for page-level UI.
 */
export function createHost(name, css) {
  const host = document.createElement('pass-' + name);
  const st = host.style;
  // Also undoes the browser's own popover styles.
  for (const [k, v] of Object.entries({
    all: 'initial', position: 'fixed', 'z-index': '2147483647', top: '0', left: '0', right: 'auto', bottom: 'auto',
    width: '0', height: '0', 'max-width': 'none', 'max-height': 'none', margin: '0', padding: '0', border: '0',
    background: 'transparent', display: 'block', overflow: 'visible', 'pointer-events': 'auto',
  })) st.setProperty(k, v, 'important');
  host.setAttribute('lang', messageLocale());
  host.setAttribute('dir', textDirection());
  if (typeof host.showPopover === 'function') host.setAttribute('popover', 'manual');
  for (const type of CONTAINED_EVENTS) host.addEventListener(type, (e) => e.stopPropagation());
  loadUiFont();
  const root = host.attachShadow({ mode: 'closed' });
  const style = document.createElement('style');
  style.textContent = BASE_CSS + (css || '');
  root.appendChild(style);
  hosts.add(host);
  const layer = { host, root, anchor: null, below: new Set(), raisedSeq: -1, raisedAt: 0, popover: false,
    blocked: false, box: null, onlayer: null };
  layerState.set(host, layer);
  guardBackdrop(name);
  return {
    host,
    root,
    mount(anchor = null) {
      layer.anchor = anchor?.nodeType === 1 ? anchor : null;
      trackTopLayer(host.ownerDocument);
      mounted.add(layer);
      startLayerTimer();
      settle(layer, topLayerElements(host.ownerDocument), true);
    },
    remove() {
      mounted.delete(layer);
      stopLayerTimerIfIdle();
      host.remove();
      hosts.delete(host);
    },
    /** True when the anchor field is behind a modal dialog it isn't in (inert). */
    get blocked() { return layer.blocked; },
    set onlayer(fn) { layer.onlayer = fn; },
    place(left, top) {
      const x = Math.round(left);
      const y = Math.round(top);
      st.setProperty('left', `${x}px`, 'important');
      st.setProperty('top', `${y}px`, 'important');
      // Without the top layer, a transformed page dialog makes `position: fixed` relative to it.
      if (!layer.popover && host.parentNode && host.parentNode !== host.ownerDocument.documentElement) {
        const r = host.getBoundingClientRect();
        const dx = Math.round(r.left) - x;
        const dy = Math.round(r.top) - y;
        if (dx || dy) {
          st.setProperty('left', `${x - dx}px`, 'important');
          st.setProperty('top', `${y - dy}px`, 'important');
        }
      }
    },
  };
}

// The UI font's bytes come from the background (no web_accessible_resources, nothing fetched by the
// page) and load as a FontFace under a random per-page name, so it avoids clashing with page fonts.
const UI_FONT = `f${(globalThis.crypto?.randomUUID?.() || `${Math.random().toString(16).slice(2)}${Math.random().toString(16).slice(2)}`).replace(/-/g, '')}`;
let uiFontLoading = false;

function loadUiFont() {
  if (uiFontLoading) return;
  const fonts = document.fonts;
  const FF = globalThis.FontFace;
  if (!fonts || typeof fonts.add !== 'function' || typeof FF !== 'function') return;
  // Looked up lazily; shared/api.js would pin it at import time.
  const runtime = (globalThis.browser ?? globalThis.chrome)?.runtime;
  if (typeof runtime?.sendMessage !== 'function') return;
  uiFontLoading = true;
  Promise.resolve(runtime.sendMessage({ type: 'ui.font' })).then(async (res) => {
    const faces = res?.ok ? res.result?.faces : null;
    if (!Array.isArray(faces)) return;
    for (const f of faces) {
      if (typeof f?.data !== 'string') continue;
      const bin = atob(f.data);
      const bytes = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
      const face = new FF(UI_FONT, bytes.buffer, { weight: '300 700', style: 'normal', unicodeRange: f.range || 'U+0-10FFFF' });
      await face.load();
      fonts.add(face);
    }
  }).catch(() => { /* the system font stays */ });
}

// Layering: no z-index beats the top layer and a modal makes the rest inert, so each host is a manual
// popover, re-shown when covered. UI for a field in a top-layer element lives inside it (not inert, and
// no light-dismissing "click outside"); page-level UI goes into the topmost modal or fullscreen element.

const TOP_LAYER = ['dialog:modal', ':popover-open', ':fullscreen'];
const layerState = new WeakMap();
const mounted = new Set();
const openedAt = new WeakMap();   // page element -> topSeq when it entered the top layer
let topSeq = 0;
let tracked = null;
let layerTimer = 0;
let settlePending = false;
/** Throttles re-raising when a page keeps fighting for the top. */
const RAISE_MIN_MS = 100;

function matchesSafe(el, selector) {
  try { return el.matches(selector); } catch { return false; }
}

function flatParent(node) {
  return node.parentElement || node.parentNode?.host || null;
}

function composedContains(outer, node) {
  for (let n = node; n; n = flatParent(n)) if (n === outer) return true;
  return false;
}

/** The page's top-layer elements (never ours), in document order. */
function topLayerElements(doc = document) {
  const found = new Set();
  for (const selector of TOP_LAYER) {
    let list = [];
    try { list = doc.querySelectorAll(selector); } catch { /* not supported here */ }
    for (const el of list) if (!isOwnNode(el)) found.add(el);
  }
  return [...found].sort((a, b) => (a.compareDocumentPosition(b) & 4 ? -1 : 1)); // 4: b follows a
}

function topModal(top) {
  let best = null;
  let bestSeq = -1;
  for (const el of top) {
    if (!matchesSafe(el, 'dialog:modal') && !matchesSafe(el, ':fullscreen')) continue;
    const seq = openedAt.get(el) || 0;
    if (seq >= bestSeq) { best = el; bestSeq = seq; }
  }
  return best;
}

/** The anchor's nearest top-layer ancestor, the topmost modal, or <html>. */
function containerFor(layer, top) {
  const doc = layer.host.ownerDocument;
  const root = doc.documentElement || doc.body;
  if (layer.anchor) {
    for (let n = flatParent(layer.anchor); n; n = flatParent(n)) if (top.includes(n)) return n;
    return root;
  }
  return topModal(top) || root;
}

function rectsOverlap(page, ui) {
  return page.width > 0 && page.height > 0 &&
    page.left < ui.right && page.right > ui.left && page.top < ui.bottom && page.bottom > ui.top;
}

/** True when the page's top-layer element `el` was there before `host` was last shown (or contains it). */
function isBelow(host, el) {
  const layer = layerState.get(host);
  if (layer?.popover && matchesSafe(host, ':popover-open')) {
    return layer.below.has(el) && !((openedAt.get(el) || 0) > layer.raisedSeq);
  }
  return composedContains(el, host);
}

/** Re-shows the host so it is topmost in the top layer, keeping focus inside it. */
function raise(layer) {
  const { host, root } = layer;
  layer.raisedAt = Date.now();
  layer.popover = false;
  if (typeof host.showPopover === 'function') {
    const focused = root.activeElement;
    try {
      if (matchesSafe(host, ':popover-open')) host.hidePopover();
      host.showPopover();
      layer.popover = true;
    } catch { /* not connected, or no popover here: the z-index stays */ }
    if (focused && root.activeElement !== focused) {
      try { focused.focus({ preventScroll: true }); } catch { /* gone */ }
    }
  }
  layer.raisedSeq = topSeq;
  layer.below = new Set(topLayerElements(host.ownerDocument));
}

function settle(layer, top, opening = false) {
  const { host } = layer;
  const want = containerFor(layer, top);
  let raiseNow = false;
  if (host.parentNode !== want) {
    want.appendChild(host);
    raiseNow = true;
  } else if (typeof host.showPopover === 'function') {
    if (!matchesSafe(host, ':popover-open')) raiseNow = true;
    else {
      // Re-raise over anything newer that overlaps; when opening or with no known box, anything newer.
      let box = layer.box?.getBoundingClientRect();
      if (opening || !(box?.width > 0 && box?.height > 0)) box = null;
      const covered = top.some((el) => !isBelow(host, el) && (!box || rectsOverlap(el.getBoundingClientRect(), box)));
      if (covered) {
        if (Date.now() - layer.raisedAt >= RAISE_MIN_MS) raiseNow = true;
        else setTimeout(scheduleSettle, RAISE_MIN_MS);
      }
    }
  }
  if (raiseNow) raise(layer);
  if (layer.anchor) {
    const modal = topModal(top);
    const blocked = !!modal && !composedContains(modal, layer.anchor);
    if (blocked !== layer.blocked) {
      layer.blocked = blocked;
      try { layer.onlayer?.(); } catch { /* ignore */ }
    }
  }
}

function settleLayers() {
  settlePending = false;
  if (!mounted.size) return;
  const top = topLayerElements(tracked || document);
  for (const layer of [...mounted]) settle(layer, top);
}

function scheduleSettle() {
  if (settlePending || !mounted.size) return;
  settlePending = true;
  Promise.resolve().then(settleLayers);
}

function startLayerTimer() {
  if (!layerTimer) layerTimer = setInterval(settleLayers, 500);
}

function stopLayerTimerIfIdle() {
  if (mounted.size || !layerTimer) return;
  clearInterval(layerTimer);
  layerTimer = 0;
}

// Dialogs are seen via their `open` attribute, which the page cannot hide from a MutationObserver.
function trackTopLayer(doc) {
  if (tracked || !doc?.defaultView) return;
  tracked = doc;
  const view = doc.defaultView;
  const opened = (el) => {
    if (el && el.nodeType === 1 && !isOwnNode(el)) openedAt.set(el, ++topSeq);
  };
  view.addEventListener('beforetoggle', (e) => {
    if (e.newState === 'open') opened(e.target);
    scheduleSettle();
  }, true);
  doc.addEventListener('fullscreenchange', () => { opened(doc.fullscreenElement); scheduleSettle(); }, true);
  view.addEventListener('focusin', scheduleSettle, true);
  const MO = view.MutationObserver || globalThis.MutationObserver;
  if (MO) {
    new MO((records) => {
      for (const r of records) if (r.target.localName === 'dialog' && r.target.hasAttribute('open')) opened(r.target);
      scheduleSettle();
    }).observe(doc, { attributes: true, attributeFilter: ['open'], subtree: true });
  }
}

// A page's `::backdrop` rule would otherwise dim the page behind our popovers too.
const backdropNames = new Set();
let backdropSheet = null;
function guardBackdrop(name) {
  backdropNames.add(name);
  try {
    const doc = document;
    if (!backdropSheet) backdropSheet = new doc.defaultView.CSSStyleSheet();
    backdropSheet.replaceSync(`${[...backdropNames].map((n) => `pass-${n}::backdrop`).join(', ')} { display: none !important; }`);
    if (!doc.adoptedStyleSheets.includes(backdropSheet)) doc.adoptedStyleSheets = [...doc.adoptedStyleSheets, backdropSheet];
  } catch { /* no constructable stylesheets here: cosmetic only */ }
}

// Clickjacking guard: `isTrusted` proves a real click, not that the user saw the UI (the page can make
// hosts transparent under a decoy). Secret-handling clicks also need the UI shown for a moment, intact
// (no transparency, filter or clipping), not under the page's top layer, and not occluded (IO v2).

/** Clicks sooner than this after the UI appeared are ignored, like Chrome's autofill popup. */
export const MIN_VISIBLE_MS = 500;
// Dark-mode tools filter the whole page with these; they hide nothing.
const HARMLESS_FILTER_RE = /^(?:\s*(?:invert|hue-rotate|grayscale|sepia|saturate)\([^()]*\))+\s*$/;
const HOST_DEFAULTS = { 'clip-path': 'none', 'mask-image': 'none', '-webkit-mask-image': 'none', transform: 'none', 'mix-blend-mode': 'normal' };

/** True when nothing the page controls hides `host`. `box`: the visible element (the host is 0x0). */
export function uiIntact(host, box = host) {
  if (!host?.isConnected) return false;
  const view = host.ownerDocument?.defaultView;
  if (!view?.getComputedStyle) return false;
  for (let node = host; node && node.nodeType === 1; node = node.parentElement || node.getRootNode?.()?.host || null) {
    const cs = view.getComputedStyle(node);
    if (cs.display === 'none') return false;
    if (cs.opacity !== '' && Number(cs.opacity) < 1) return false;
    const filter = cs.filter || 'none';
    if (filter !== 'none' && (node === host || !HARMLESS_FILTER_RE.test(filter))) return false;
    if (node === host) {
      if (cs.visibility && cs.visibility !== 'visible') return false;
      for (const [prop, def] of Object.entries(HOST_DEFAULTS)) {
        const v = cs.getPropertyValue(prop);
        if (v && v !== def) return false;
      }
    }
  }
  // A pointer-events: none decoy in the page's top layer could hide the UI while clicks still reach it.
  const r = box.getBoundingClientRect();
  for (const el of topLayerElements(host.ownerDocument)) {
    if (isBelow(host, el)) continue;
    if (rectsOverlap(el.getBoundingClientRect(), r)) return false;
  }
  return true;
}

// Ancestor effects that make IntersectionObserver v2 report "not visible" regardless of occlusion.
const EFFECTS = { filter: 'none', 'backdrop-filter': 'none', transform: 'none', perspective: 'none',
  'mix-blend-mode': 'normal', 'clip-path': 'none', 'mask-image': 'none', '-webkit-mask-image': 'none' };

/** True when an ancestor of `host` has a visual effect, so IO v2 cannot judge occlusion. */
export function pageHasEffects(host) {
  const view = host?.ownerDocument?.defaultView;
  if (!view?.getComputedStyle) return false;
  for (let node = host.parentElement; node && node.nodeType === 1; node = node.parentElement) {
    const cs = view.getComputedStyle(node);
    for (const [prop, def] of Object.entries(EFFECTS)) {
      const v = cs.getPropertyValue(prop);
      if (v && v !== def) return true;
    }
    const zoom = cs.getPropertyValue('zoom');
    if (zoom && zoom !== '1' && zoom !== 'normal') return true;
  }
  return false;
}

function clickedOn(host, e) {
  try {
    return host.ownerDocument.elementFromPoint(e.clientX, e.clientY) === host;
  } catch {
    return false;
  }
}

/**
 * Guards clicks on one piece of in-page UI. `target`: the visible box in the shadow root. Call
 * `reset()` when the clickable entries change. Where page effects blind IO v2, the click must hit our host.
 */
export function createClickGuard(host, target = host) {
  let shownAt = Date.now();
  let occluded = false;
  const layer = layerState.get(host);
  if (layer && target !== host) layer.box = target;
  let io = null;
  try {
    const IO = globalThis.IntersectionObserver;
    if (IO && 'isVisible' in (globalThis.IntersectionObserverEntry?.prototype || {})) {
      io = new IO((entries) => { for (const en of entries) occluded = en.isVisible === false; },
        { trackVisibility: true, delay: 100 });
      io.observe(target);
    }
  } catch { io = null; }
  return {
    reset() { shownAt = Date.now(); },
    allows(e) {
      if (!e?.isTrusted) return false;
      // A re-raise restarts the visibility delay.
      if (Date.now() - Math.max(shownAt, layer?.raisedAt || 0) < MIN_VISIBLE_MS) return false;
      if (occluded && !(pageHasEffects(host) && clickedOn(host, e))) return false;
      return uiIntact(host, target);
    },
    disconnect() { io?.disconnect(); io = null; },
  };
}

/** Creates an element with attributes and children (strings become text nodes, never HTML). */
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/** Builds an SVG element from a [tag, attrs, children] tree (no innerHTML, so Trusted Types safe). */
export function svgTree([tag, attrs, children = []]) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs || {})) el.setAttribute(k, String(v));
  for (const c of children) el.appendChild(svgTree(c));
  return el;
}

/** Letters are CSS generated content, so nothing is fetched. Size with font-size. */
export function passWordmark() {
  const el = h('span', { class: 'wordmark', role: 'img', 'aria-label': 'Passyble' });
  el.appendChild(wordmarkNote({ doc: document }));
  return el;
}

export function passNote() {
  return wordmarkNote({ doc: document });
}

export function uiIcon(name, opts = {}) {
  return icon(name, { doc: document, ...opts });
}

export async function copyText(text, root) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.cssText = 'position:fixed;opacity:0;left:-9999px;top:0';
    (root || document.body).appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand('copy'); } catch { /* ignore */ }
    ta.remove();
    return ok;
  }
}

// Mirrors src/ui/tokens.css; closed shadow roots need their own copy.
const BASE_CSS = `
:host { all: initial; }
* { box-sizing: border-box; }
[hidden] { display: none !important; }
/* Reduced motion: cards appear in place, nothing slides or eases. */
@media (prefers-reduced-motion: reduce) {
  .pass-ui, .pass-ui * { animation: none !important; transition: none !important; }
}
.pass-ui {
  --surface: #ffffff; --surface-2: #f0f0f0; --surface-3: #e6e6e6; --border: #e4e4e4; --border-strong: #cfcfcf;
  --surface-raised: #ffffff; --fill-hover: rgba(17, 17, 17, .05); --fill-selected: rgba(17, 17, 17, .10);
  --text: #111111; --text-2: #555555; --text-3: #6b6b6b;
  --accent: #111111; --accent-hover: #2a2a2a; --accent-text: #ffffff; --accent-soft: #ececec; --tile: #f0f0f0;
  --lime: #c6f432; --lime-mark: #6e9a00; --lime-ink: #4f6b00; --lime-soft: #f1f9d9;
  --focus-ring: #111111; --ring: transparent;
  --focus: 0 0 0 0 transparent; /* focus is an outline now: 2px var(--focus-ring), 2px offset */
  --field-focus: #111111; --field-ring: rgba(17, 17, 17, .13); --focus-field: 0 0 0 1px var(--field-focus), 0 0 0 4px var(--field-ring);
  --danger: #b42318; --danger-soft: #fdecea; --ok: #4f6b00; --ok-soft: #f1f9d9; --warn: #555555; --warn-soft: #f0f0f0;
  --inset: #f0f0f0; --chip: #f0f0f0; --chip-text: #555555; --input-bg: #f0f0f0; --disabled-bg: #e6e6e6; --disabled-text: #6b6b6b;
  --shadow: 0 8px 24px rgba(0, 0, 0, .10), 0 1px 2px rgba(0, 0, 0, .06);
  --sp-1: 4px; --sp-2: 8px; --sp-3: 12px; --sp-4: 16px; --r-sm: 6px; --r: 10px; --r-lg: 14px;
  --fs-xs: 11px; --fs-sm: 12px; --fs-body: 13px; --fs-md: 14px;
  --mono: "Cascadia Mono", ui-monospace, Consolas, "SF Mono", Menlo, monospace;
  /* The UI font (loadUiFont), then an installed Space Grotesk, then the system font. */
  --font: "${UI_FONT}", "Space Grotesk", "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Roboto, "Helvetica Neue", Arial, "Noto Sans", "Nirmala UI", "Noto Sans Devanagari", "Microsoft YaHei UI", "PingFang SC", "Hiragino Sans", "Yu Gothic UI", "Malgun Gothic", "Apple SD Gothic Neo", "Noto Sans CJK SC", sans-serif;
  font: 13px/1.4 var(--font);
  color: var(--text); -webkit-font-smoothing: antialiased; letter-spacing: normal; text-align: start;
  color-scheme: light dark; /* native controls (the passkey card's select) follow the theme */
}
/* Same per-language font order as src/ui/tokens.css (Han glyph shapes differ by language). */
.pass-ui:lang(ja) { --font: "${UI_FONT}", "Space Grotesk", "Segoe UI Variable Text", "Segoe UI", "Yu Gothic UI", "Meiryo UI", "Hiragino Sans", "Hiragino Kaku Gothic ProN", "Noto Sans CJK JP", "Noto Sans JP", system-ui, sans-serif; }
.pass-ui:lang(ko) { --font: "${UI_FONT}", "Space Grotesk", "Segoe UI Variable Text", "Segoe UI", "Malgun Gothic", "Apple SD Gothic Neo", "Noto Sans CJK KR", "Noto Sans KR", system-ui, sans-serif; }
.pass-ui:lang(zh) { --font: "${UI_FONT}", "Space Grotesk", "Segoe UI Variable Text", "Segoe UI", "Microsoft YaHei UI", "Microsoft YaHei", "PingFang SC", "Noto Sans CJK SC", "Noto Sans SC", system-ui, sans-serif; }
.pass-ui:lang(zh-TW), .pass-ui:lang(zh-HK) { --font: "${UI_FONT}", "Space Grotesk", "Segoe UI Variable Text", "Segoe UI", "Microsoft JhengHei UI", "Microsoft JhengHei", "PingFang TC", "Noto Sans CJK TC", "Noto Sans TC", system-ui, sans-serif; }
.pass-ui:lang(hi) { --font: "${UI_FONT}", "Space Grotesk", "Segoe UI Variable Text", "Segoe UI", "Nirmala UI", "Kohinoor Devanagari", "Noto Sans Devanagari", system-ui, sans-serif; line-height: 1.6; }
@media (prefers-color-scheme: dark) {
  .pass-ui {
    --surface: #18181a; --surface-2: #212124; --surface-3: #2a2a2e; --border: #2a2a2d; --border-strong: #3a3a3e;
    --surface-raised: #222225; --fill-hover: rgba(237, 237, 237, .06); --fill-selected: rgba(237, 237, 237, .10);
    --text: #ededed; --text-2: #b4b4b8; --text-3: #8e8e93;
    --accent: #ededed; --accent-hover: #ffffff; --accent-text: #111111; --accent-soft: #2a2a2e; --tile: #212124;
    --lime: #c6f432; --lime-mark: #c6f432; --lime-ink: #c6f432; --lime-soft: rgba(198, 244, 50, .12);
    --focus-ring: #ededed; --ring: transparent; --field-focus: #ededed; --field-ring: rgba(237, 237, 237, .14);
    --danger: #ff8a80; --danger-soft: #3a1d1b; --ok: #c6f432; --ok-soft: rgba(198, 244, 50, .12); --warn: #b4b4b8; --warn-soft: #2a2a2e;
    --inset: #2a2a2e; --chip: #2a2a2e; --chip-text: #b4b4b8; --input-bg: #212124; --disabled-bg: #2a2a2e; --disabled-text: #8e8e93;
    /* Floating panels on dark pages: a faint 1px ring inside the shadow. */
    --shadow: 0 0 0 1px #3a3a3e, 0 12px 32px rgba(0, 0, 0, .55);
  }
}
/* Page CSS can't reach into the closed shadow root, but the browser's own form control styles can: reset them. */
button, input, select { font: inherit; color: inherit; margin: 0; text-transform: none; letter-spacing: inherit; }
button { cursor: pointer; -webkit-appearance: none; appearance: none; }
svg.pass-icon { display: block; flex: none; }
/* Cards over the page: a raised surface, 14px corners and a soft shadow, no outline. */
.card { background: var(--surface-raised); color: var(--text); border: 0; border-radius: var(--r-lg); box-shadow: var(--shadow); }
/* Pill buttons: one filled primary, the rest outlined. */
.btn { display: inline-flex; align-items: center; justify-content: center; gap: 6px; min-height: 36px; border: 1px solid var(--border-strong);
  border-radius: 999px; padding: 2px 16px; background: transparent; color: var(--text); font-weight: 600; font-size: var(--fs-body);
  line-height: 1.25; text-align: center; overflow-wrap: anywhere; transition: background-color .12s, border-color .12s; }
.btn:hover { background: var(--fill-hover); }
.btn.primary { background: var(--accent); color: var(--accent-text); border-color: var(--accent); font-weight: 600; }
.btn.primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
@media (prefers-color-scheme: dark) {
  .btn.primary { font-weight: 650; }
}
.btn:disabled { opacity: .45; cursor: not-allowed; }
.btn.primary:disabled { opacity: 1; background: var(--disabled-bg); border-color: transparent; color: var(--disabled-text); }
/* The one tertiary link style: 600, underlined, ink. */
.text-link, .link { display: inline-flex; align-items: center; min-height: 30px; padding: 0 4px; border: 0; border-radius: 4px; background: none;
  color: var(--accent); font-weight: 600; text-decoration: underline; text-underline-offset: 4px; text-decoration-thickness: 1.5px; cursor: pointer; }
.text-link:hover, .link:hover { text-decoration-thickness: 2px; }
.text-link:focus-visible, .link:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 2px; }
.text-link:disabled, .link:disabled { opacity: .5; cursor: default; }
.icon-btn { display: inline-grid; place-items: center; width: 30px; height: 30px; border: 0; background: none; color: var(--text-2); padding: 0;
  margin: 0; border-radius: 999px; flex: none; transition: background-color .12s, color .12s; }
.icon-btn:hover { background: var(--fill-selected); color: var(--text); }
.btn:focus-visible, .icon-btn:focus-visible { outline: 2px solid var(--focus-ring); outline-offset: 2px; }
/* A small tonal chip after a title (2FA, Passkey). */
.badge { display: inline-block; margin-left: 6px; padding: 0 7px; border-radius: 999px; background: var(--chip); color: var(--chip-text);
  font-size: var(--fs-xs); font-weight: 600; line-height: 17px; vertical-align: 1px; }
.sr { position: absolute; width: 1px; height: 1px; overflow: hidden; clip-path: inset(50%); white-space: nowrap; }
/* The wordmark: ink letters, the lime note (the same in both themes, the mark colour of each). */
.wordmark { display: inline-flex; align-items: center; flex: none; font-size: 20px; font-weight: 700; letter-spacing: -0.02em; line-height: 1;
  color: var(--text); white-space: nowrap; }
.wordmark::before { content: "Pass"; }
.wordmark::after { content: "ble"; }
.wordmark .pass-note { display: block; width: .9em; height: 1.08em; margin: .27em -.04em 0; color: var(--lime-mark); flex: none; }
`;
