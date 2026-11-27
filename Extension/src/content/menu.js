// Inline UI: the icon inside the focused login field (plus a generate button on new-password fields)
// and the dropdown below it.
import { createHost, createClickGuard, uiIntact, h, passNote, passWordmark, uiIcon } from './ui-common.js';
import { MSG } from '../shared/messages.js';
import { t, tp } from '../shared/i18n.js';

const ICON_CSS = `
.icon { position: absolute; width: 18px; height: 18px; padding: 0; margin: 0; border: 0; border-radius: 50%;
  background: var(--surface); box-shadow: inset 0 0 0 1px var(--border-strong); cursor: pointer; display: grid; place-items: center; outline: none; }
.icon:hover { box-shadow: inset 0 0 0 1px var(--text-3); }
/* On a field whose background is the other theme's: that theme's disc and note colours. */
.pass-ui.on-light { --surface: #ffffff; --border-strong: #cfcfcf; --text-3: #6b6b6b; --lime-mark: #6e9a00; --surface-2: #f0f0f0; --surface-3: #e6e6e6; --text-2: #555555; }
.pass-ui.on-dark { --surface: #18181a; --border-strong: #3a3a3e; --text-3: #8e8e93; --lime-mark: #c6f432; --surface-2: #212124; --surface-3: #2a2a2e; --text-2: #b4b4b8; }
/* The wordmark's note, lime: the compact Passyble mark in a login field. */
.icon .pass-note { width: 10px; height: 12px; margin-top: 1px; color: var(--lime-mark); }
.gen { position: absolute; width: 18px; height: 18px; padding: 0; margin: 0; border: 0; border-radius: 5px;
  background: var(--surface-2); color: var(--text-2); cursor: pointer; display: grid; place-items: center;
  box-shadow: inset 0 0 0 1px var(--border-strong); outline: none; }
.gen:hover { color: var(--accent); background: var(--surface-3); }
.gen[hidden] { display: none; }
/* With the options chevron: one split button, the dice on the left, the chevron on the right. */
.gen.split { border-start-end-radius: 0; border-end-end-radius: 0; }
.gen-more { position: absolute; width: 11px; padding: 0; margin: 0; border: 0; border-radius: 0 5px 5px 0; background: var(--surface-2);
  color: var(--text-2); cursor: pointer; display: grid; place-items: center; outline: none;
  box-shadow: inset 0 0 0 1px var(--border-strong); }
.gen-more:hover, .gen-more[aria-expanded="true"] { color: var(--accent); background: var(--surface-3); }
.gen-more[hidden] { display: none; }
`;

// Entries never take focus: the page's field keeps it and the keyboard moves the highlight.
const MENU_CSS = `
.menu { position: absolute; min-width: 260px; max-width: 360px; max-height: 312px; border-top-left-radius: 8px !important; overflow: auto; overscroll-behavior: contain;
  background: var(--surface-raised); border: 0; border-radius: var(--r-lg); box-shadow: var(--shadow); padding: 6px;
  outline: none; -webkit-tap-highlight-color: transparent; scrollbar-width: thin; }
.head { display: flex; align-items: center; gap: 8px; height: 32px; padding: 2px 10px 0; color: var(--text-2);
  font-size: var(--fs-sm); font-weight: 600; letter-spacing: 0; }
.head .wordmark { font-size: 17px; }
.head-label { display: inline-flex; align-items: center; height: 20px; padding: 0 8px; border-radius: 999px; background: var(--chip);
  color: var(--chip-text); font-size: var(--fs-xs); font-weight: 600; white-space: nowrap; }
/* Rows divided by hairlines inset from the edges; hover and the keyboard highlight hide the lines next to them. */
.item { position: relative; display: flex; align-items: center; gap: 12px; width: 100%; min-height: 50px; margin: 0; border: 0; background: none;
  color: var(--text); padding: 7px 10px; border-radius: var(--r); text-align: start; outline: none; box-shadow: none; }
.item + .item::before { content: ""; position: absolute; top: 0; left: 10px; right: 10px; height: 1px; background: var(--border); }
.item:is(:hover, .active)::before, .item:is(:hover, .active) + .item::before { opacity: 0; }
.item:hover { background: var(--fill-hover); }
/* The keyboard's entry: about 9% and bold; under the pointer it is only a hover (about 5%). */
.item.active { background: var(--fill-selected); }
.item.active .title { font-weight: 700; }
.menu.pointer .item.active { background: var(--fill-hover); }
.menu.pointer .item.active .title { font-weight: 600; }
.item:focus-visible { outline: 1px solid var(--border-strong); outline-offset: -1px; }
.avatar { flex: none; width: 32px; height: 32px; border-radius: var(--r); background: var(--fill-selected);
  color: var(--text-2); display: grid; place-items: center; font-weight: 700; font-size: var(--fs-md); }
.avatar.brand { font-size: 9px; font-weight: 700; letter-spacing: .02em; }
.text { min-width: 0; flex: 1; display: flex; flex-direction: column; gap: 1px; }
.title { font-weight: 600; font-size: var(--fs-md); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.sub { color: var(--text-2); font-size: var(--fs-sm); white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.msg { padding: 6px 10px 8px; color: var(--text-2); }
/* Locked, with the master password field: a title (it replaces the small head) and the line under it. */
.menu:has(.unlock-frame) { max-height: 460px; }
.menu.up { border-top-left-radius: var(--r-lg) !important; border-bottom-left-radius: 8px; }
.menu:has(.unlock-frame) .head-label { display: none; }
.menu:has(.unlock-frame) .msg { padding: 6px 10px 6px; color: var(--text); font-size: var(--fs-md); font-weight: 600; }
/* Windows Hello first: the one filled pill, then "or" and the password field. */
.item.hello-cta { justify-content: center; gap: 8px; width: calc(100% - 20px); min-height: 40px; margin: 4px 10px 0; padding: 0 16px; border-radius: 999px;
  background: var(--accent); color: var(--accent-text); font-size: var(--fs-md); font-weight: 600; }
.item.hello-cta:hover, .item.hello-cta.active, .menu.pointer .item.hello-cta.active { background: var(--accent-hover); }
.item.hello-cta::before, .item.hello-cta + .or + .unlock-frame + .item::before { display: none; }
.or { display: flex; align-items: center; gap: 10px; margin: 10px 10px 2px; color: var(--text-3); font-size: var(--fs-sm); }
.or::before, .or::after { content: ""; flex: 1; height: 1px; background: var(--border); }
.sep { height: 1px; background: var(--border); margin: 4px 10px; }
.sep + .item::before { display: none; }
/* A small label over a group of rows ("Similar sites"). */
.section { padding: 8px 10px 2px; color: var(--text-3); font-size: var(--fs-xs); font-weight: 600; }
.section + .item::before { display: none; }
.item.gen { cursor: pointer; }
/* Generated password: strength on the second line; the eye swaps in the password itself. */
.pw { display: flex; align-items: center; gap: 6px; min-width: 0; height: 18px; }
.pw-val { font: var(--fs-sm)/1 var(--mono); font-variant-numeric: tabular-nums; min-width: 0; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.pw-val.masked { display: none; }
.strength { display: flex; align-items: center; gap: 6px; flex: 1; min-width: 0; font-size: var(--fs-sm); color: var(--text-2); white-space: nowrap; }
.pw-val:not(.masked) + .strength { display: none; }
.meter { flex: none; width: 32px; height: 4px; border-radius: 2px; background: var(--border); overflow: hidden; }
.meter i { display: block; height: 100%; background: var(--ok); }
.meter i.fair { background: var(--text); } .meter i.weak { background: var(--danger); }
.reveal { width: 24px; height: 24px; margin-right: -2px; }
/* The master password field (src/unlock/frame.html), an extension page the page can't read. */
.unlock-frame { display: block; width: 100%; height: 112px; border: 0; margin: 0; padding: 0; background: transparent; color-scheme: normal; }
.unlock-frame + .item::before { display: none; }
.reveal:hover { color: var(--accent); }
`;

const ICON_SIZE = 18;

/** Whether the field's first opaque background is dark, or null when unknown. */
function fieldIsDark(field) {
  try {
    const view = field?.ownerDocument?.defaultView;
    for (let n = field; n && n.nodeType === 1; n = n.parentElement) {
      const m = /rgba?\(([^)]+)\)/.exec(view.getComputedStyle(n).backgroundColor || '');
      if (!m) continue;
      const [r, g, b, a = 1] = m[1].split(/[\s,/]+/).filter(Boolean).map(Number);
      if (!(a >= 0.5)) continue;
      return (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255 < 0.5;
    }
  } catch { /* unknown, use the system theme */ }
  return null;
}
const SLOT_GAP = 4;
/** Fields narrower than this get only the Passyble icon, no generate button. */
const MIN_WIDTH_FOR_GENERATE = 140;
/** The options chevron's width; it sits right of the generate button, touching it. */
const MORE_WIDTH = 11;

export class InlineMenu {
  constructor({ onIconClick, onSelect, onGenerateClick, onGenerateOptions }) {
    this.onIconClick = onIconClick;
    this.onSelect = onSelect;
    this.onGenerateClick = onGenerateClick;
    this.onGenerateOptions = onGenerateOptions;
    this.iconGenerate = false;
    this.iconField = null;
    this.field = null;
    this.entries = [];
    this.active = -1;
    this._shown = '';
    this._icon = null;
    this._menu = null;
    this._raf = 0;
    this._timer = 0;
    this._reposition = () => this._schedule();
    this._outside = (e) => this._onOutside(e);
  }

  get isOpen() {
    return !!this._menu && this._menu.host.isConnected;
  }

  /** `generate`: also show the generate button (a new-password field). */
  showIcon(field, { generate = false } = {}) {
    const wantGenerate = generate && !!this.onGenerateClick;
    if (this.iconField === field && this.iconGenerate === wantGenerate && this._icon?.host.isConnected) return;
    this.iconField = field;
    this.iconGenerate = wantGenerate;
    if (!this._icon) {
      const ui = createHost('icon', ICON_CSS);
      const btn = h('button', { class: 'icon', type: 'button', title: 'Passyble', 'aria-label': t('commonOpenPassyble'), tabindex: '-1' });
      btn.appendChild(passNote());
      // Keep focus in the page's field.
      btn.addEventListener('mousedown', (e) => e.preventDefault());
      btn.addEventListener('click', (e) => {
        if (!e.isTrusted) return;
        e.preventDefault();
        e.stopPropagation();
        if (this.iconField) this.onIconClick(this.iconField);
      });
      const gen = h('button', { class: 'gen', type: 'button', tabindex: '-1',
        title: t('menuGenerateTitle'), 'aria-label': t('menuGenerateLabel') },
      uiIcon('dice', { size: 13 }));
      gen.addEventListener('mousedown', (e) => e.preventDefault());
      gen.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        // Writes to the vault, so it needs the full click guard.
        if (!this._iconGuard?.allows(e)) return;
        if (this.iconField && this.iconGenerate) this.onGenerateClick(this.iconField);
      });
      const more = h('button', { class: 'gen-more', type: 'button', tabindex: '-1', 'aria-haspopup': 'dialog', 'aria-expanded': 'false',
        title: t('genOptionsButton'), 'aria-label': t('genOptionsButton') },
      uiIcon('chevronDown', { size: 10 }));
      more.addEventListener('mousedown', (e) => e.preventDefault());
      more.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        // It fills the field (and saves it like the generate button): the same guard.
        if (!this._iconGuard?.allows(e)) return;
        if (this.iconField && this.iconGenerate) this.onGenerateOptions?.(this.iconField);
      });
      const slot = h('div', { class: 'pass-ui' }, btn, gen, more);
      ui.root.append(slot);
      ui.onlayer = () => this._schedule();
      this._icon = ui;
      this._gen = gen;
      this._more = more;
      // Observed for occlusion: the button itself (the slot box is 0x0, its buttons are positioned).
      this._iconGuard = createClickGuard(ui.host, gen);
    }
    this._gen.hidden = !this.iconGenerate;
    this._more.hidden = !this.iconGenerate || !this.onGenerateOptions;
    // The in-field button follows the field's own background, which can differ from the system theme.
    const dark = fieldIsDark(field);
    const slotEl = this._icon.root.querySelector('.pass-ui');
    slotEl?.classList.toggle('on-dark', dark === true);
    slotEl?.classList.toggle('on-light', dark === false);
    this._iconGuard?.reset();
    this._icon.mount(field);
    this._track();
    this._layout();
  }

  hideIcon() {
    this.iconField = null;
    this.iconGenerate = false;
    this._iconGuard?.disconnect();
    this._iconGuard = null;
    this._icon?.remove();
    this._icon = null;
    this._gen = null;
    this._more = null;
    this._untrackIfIdle();
  }

  /** The options chevron says whether the generator's options card is open (aria-expanded). */
  setOptionsOpen(open) {
    this._more?.setAttribute('aria-expanded', String(!!open));
  }

  /**
   * Opens (or re-renders) the dropdown under `field`.
   * model = { status: 'loading'|'ok'|'locked'|'unavailable'|'message', message?, entries, frame?,
   *           preselect?, neverPreselect? }; `frame` is never moved once drawn.
   * Entry = { kind, id?, title, subtitle?, section?, badges?, avatar?, icon?, avatarClass?, primary?,
   *           guarded? (Enter needs the click guard too), preview?: { password, label, bits, length } }
   */
  open(field, model) {
    this.field = field;
    if (!this._menu) {
      const ui = createHost('menu', MENU_CSS);
      const box = h('div', { class: 'menu', role: 'listbox', 'aria-label': 'Passyble' });
      box.addEventListener('mousedown', (e) => e.preventDefault());
      ui.root.append(h('div', { class: 'pass-ui' }, box));
      ui.onlayer = () => this._schedule();
      this._menu = ui;
      this._box = box;
      this._guard = createClickGuard(ui.host, box);
      document.addEventListener('mousedown', this._outside, true);
    }
    this._render(model);
    this._menu.mount(field);
    this._track();
    this._layout();
  }

  update(model) {
    if (this.isOpen) {
      this._render(model);
      this._layout();
    }
  }

  close() {
    if (!this._menu) return;
    document.removeEventListener('mousedown', this._outside, true);
    this._guard?.disconnect();
    this._guard = null;
    this._menu.remove();
    this._menu = null;
    this._box = null;
    this.field = null;
    this.entries = [];
    this.active = -1;
    this._shown = '';
    this._untrackIfIdle();
  }

  destroy() {
    this.close();
    this.hideIcon();
  }

  /** True when focus is in the menu's master password frame. */
  hasFocus() {
    return !!this._menu && document.activeElement === this._menu.host;
  }

  /** See uiIntact. A menu we hid because its field scrolled away counts as intact. */
  intact() {
    if (!this._menu) return false;
    if (this._menu.host.style.getPropertyValue('display') === 'none') return true;
    return uiIntact(this._menu.host, this._box);
  }

  /** Returns true when the key was consumed. */
  handleKey(e) {
    if (!this.isOpen || !e.isTrusted) return false;
    const n = this.entries.length;
    switch (e.key) {
      case 'ArrowDown':
        if (n) this._setActive((this.active + 1) % n);
        return true;
      case 'ArrowUp':
        if (n) this._setActive(this.active < 0 ? n - 1 : (this.active - 1 + n) % n);
        return true;
      case 'Enter':
        // A see-through or covered menu must not turn the page's Enter into a fill; `guarded` entries need
        // everything a click needs.
        if (this._menu.host.style.getPropertyValue('display') === 'none') return false; // scrolled out of view
        if (this.active >= 0 && this.entries[this.active] && uiIntact(this._menu.host, this._box) &&
            (!this.entries[this.active].guarded || this._guard?.allows(e))) {
          this.onSelect(this.entries[this.active], this.field);
          return true;
        }
        return false;
      case 'Escape':
        this.close();
        return true;
      case 'Tab':
        this.close();
        return false;
      default:
        return false;
    }
  }

  _render(model) {
    const box = this._box;
    // Never move the master password iframe: moving an iframe reloads it and loses what was typed.
    const frame = model.frame || null;
    const kept = frame && frame.parentNode === box ? frame : null;
    for (const node of [...box.childNodes]) if (node !== kept) node.remove();
    let framePlaced = false;
    const put = (...nodes) => {
      for (const node of nodes) {
        if (kept && !framePlaced) box.insertBefore(node, kept);
        else box.append(node);
      }
    };
    this.entries = [];
    this.active = -1;
    // "Passyble · " is drawn as the wordmark but kept as screen reader text.
    const heading = model.heading || 'Passyble';
    const brand = /^Passyble\s*(·\s*)?/.exec(heading);
    const rest = brand ? heading.slice(brand[0].length) : heading;
    const mark = passWordmark();
    mark.setAttribute('aria-hidden', 'true');
    put(h('div', { class: 'head' }, mark, brand ? h('span', { class: 'sr' }, brand[0]) : null, rest ? h('span', { class: 'head-label' }, rest) : null));

    const message = (text, ...extra) => put(h('div', { class: 'msg' }, text), ...extra);
    switch (model.status) {
      case 'loading':
        message(t('menuLoading'));
        return;
      case 'unavailable':
        message(model.message || MSG.agentUnavailable);
        return;
      case 'message':
        message(model.message || '');
        break;
      default:
        break;
    }
    const entries = model.entries || [];
    if (model.status === 'ok' && !entries.length) message(model.message || t('menuNoLogins'));
    if (frame) {
      if (!kept) box.append(frame);
      framePlaced = true;
    }
    const hello = frame ? entries.find((e) => e.kind === 'unlock-hello') : null;
    const ordered = hello ? [hello, ...entries.filter((e) => e !== hello)] : entries;
    ordered.forEach((entry, i) => {
      if (entry === hello) {
        const cta = h('button', { class: 'item hello-cta', type: 'button', role: 'option', tabindex: '-1' }, uiIcon(entry.icon || 'hello'), h('span', { class: 'title' }, entry.title || ''));
        cta.addEventListener('click', (e) => {
          e.preventDefault();
          if (!this._guard?.allows(e)) return;
          this.onSelect(entry, this.field);
        });
        cta.addEventListener('mousemove', () => this._setActive(i, true));
        box.insertBefore(cta, frame);
        box.insertBefore(h('div', { class: 'or', 'aria-hidden': 'true' }, h('span', {}, t('commonOr'))), frame);
        this.entries.push(entry);
        return;
      }
      if (entry.separatorBefore && (i > 0 || frame)) put(h('div', { class: 'sep' }));
      if (entry.section) put(h('div', { class: 'section', role: 'presentation' }, entry.section));
      const avatar = h('span', { class: `avatar ${entry.avatarClass || ''}` },
        entry.icon ? uiIcon(entry.icon) : entry.avatar || (entry.title || '?').trim().charAt(0).toUpperCase() || '?');
      const title = h('div', { class: 'title' }, entry.title || '', ...(entry.badges || []).map((b) => h('span', { class: `badge ${b?.otp ? 'otp' : ''}` }, b?.text ?? b)));
      const btn = entry.preview
        ? h('div', { class: 'item gen', role: 'option', tabindex: '-1' }, avatar, h('span', { class: 'text' }, title, ...this._preview(entry.preview)))
        : h('button', { class: 'item', type: 'button', role: 'option', tabindex: '-1' },
          avatar, h('span', { class: 'text' }, title, entry.subtitle ? h('div', { class: 'sub' }, entry.subtitle) : null));
      btn.addEventListener('click', (e) => {
        e.preventDefault();
        if (!this._guard?.allows(e)) return; // untrusted, too soon, or made invisible by the page
        this.onSelect(entry, this.field);
      });
      btn.addEventListener('mousemove', () => this._setActive(i, true));
      put(btn);
      this.entries.push(entry);
    });
    // `preselect: false` (opened by something the page did): Enter does nothing until the user picks an entry.
    if (this.entries.length && model.preselect !== false && !model.neverPreselect) this._setActive(0);
    // New entries must be visible for a moment before a click counts; redrawing the same entries keeps their time.
    const shown = JSON.stringify(this.entries.map((e) => [e.kind, e.id || '', e.title || '', e.subtitle || '']));
    if (this.entries.length && shown !== this._shown) this._guard?.reset();
    this._shown = shown;
  }

  /** Masked until the user reveals it. preview = { password, label, bits, length } */
  _preview(preview) {
    const masked = '•'.repeat(Math.min(preview.length || preview.password.length, 24));
    const value = h('span', { class: 'pw-val masked', 'aria-label': t('menuGeneratedHidden') }, masked);
    const reveal = h('button', { class: 'icon-btn reveal', type: 'button', tabindex: '-1', 'aria-pressed': 'false',
      title: t('commonShowPassword'), 'aria-label': t('commonShowPassword') }, uiIcon('eye', { size: 14 }));
    let shown = false;
    reveal.addEventListener('mousedown', (e) => e.preventDefault());
    reveal.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation(); // don't pick the entry
      if (!e.isTrusted) return;
      shown = !shown;
      value.textContent = shown ? preview.password : masked;
      value.classList.toggle('masked', !shown);
      value.setAttribute('aria-label', shown ? t('menuGenerated') : t('menuGeneratedHidden'));
      reveal.replaceChildren(uiIcon(shown ? 'eyeOff' : 'eye', { size: 14 }));
      reveal.title = shown ? t('commonHidePassword') : t('commonShowPassword');
      reveal.setAttribute('aria-label', reveal.title);
      reveal.setAttribute('aria-pressed', String(shown));
    });
    const level = preview.bits >= 75 ? '' : preview.bits >= 50 ? 'fair' : 'weak';
    const bar = h('i', { class: level });
    bar.style.width = `${Math.max(10, Math.min(100, Math.round((preview.bits / 128) * 100)))}%`; // CSSOM: allowed under strict page CSP
    return [
      h('div', { class: 'pw' }, value, h('span', { class: 'strength' }, h('span', { class: 'meter' }, bar), tp('menuPasswordStrength', preview.length, preview.label)), reveal),
    ];
  }

  /** `pointer` gives the lighter hover look; keyboard selection is bold. */
  _setActive(i, pointer = false) {
    this.active = i;
    this._box?.classList.toggle('pointer', pointer);
    const items = this._box?.querySelectorAll('.item') || [];
    items.forEach((el, j) => { el.classList.toggle('active', j === i); el.setAttribute('aria-selected', String(j === i)); });
    items[i]?.scrollIntoView?.({ block: 'nearest' });
  }

  _onOutside(e) {
    const path = e.composedPath();
    if (this._menu && path.includes(this._menu.host)) return;
    if (this._icon && path.includes(this._icon.host)) return;
    if (this.field && path.includes(this.field)) return;
    this.close();
  }

  _track() {
    if (this._tracking) return;
    this._tracking = true;
    window.addEventListener('scroll', this._reposition, { capture: true, passive: true });
    window.addEventListener('resize', this._reposition, { passive: true });
    // Catches layout shifts that fire no scroll/resize event (animations, SPA re-renders).
    this._timer = setInterval(() => this._layout(), 400);
  }

  _untrackIfIdle() {
    if (this._icon || this._menu || !this._tracking) return;
    this._tracking = false;
    window.removeEventListener('scroll', this._reposition, { capture: true });
    window.removeEventListener('resize', this._reposition);
    clearInterval(this._timer);
  }

  _schedule() {
    if (this._raf) return;
    this._raf = requestAnimationFrame(() => {
      this._raf = 0;
      this._layout();
    });
  }

  _layout() {
    const vw = document.documentElement.clientWidth || window.innerWidth;
    const vh = document.documentElement.clientHeight || window.innerHeight;
    if (this._icon && this.iconField) {
      const f = this.iconField;
      const r = f.getBoundingClientRect();
      const gone = !f.isConnected || r.width === 0 || r.height === 0 || r.bottom < 0 || r.top > vh || this._icon.blocked;
      if (gone || r.width < 80) {
        this._icon.host.style.setProperty('display', 'none', 'important');
        if (!f.isConnected) this.hideIcon();
      } else {
        this._icon.host.style.setProperty('display', 'block', 'important');
        const size = Math.min(ICON_SIZE, Math.max(12, r.height - 8));
        const btn = this._icon.root.querySelector('.icon');
        btn.style.width = btn.style.height = `${size}px`;
        const withGen = this.iconGenerate && r.width >= MIN_WIDTH_FOR_GENERATE;
        const withMore = withGen && !!this.onGenerateOptions;
        const genWidth = size + (withMore ? MORE_WIDTH : 0);
        if (this._gen) {
          this._gen.hidden = !withGen;
          this._gen.classList.toggle('split', withMore);
          this._gen.style.width = this._gen.style.height = `${size}px`;
          this._gen.style.left = '0px';
          this._more.hidden = !withMore;
          this._more.style.height = `${size}px`;
          this._more.style.left = `${size}px`;
          btn.style.left = withGen ? `${genWidth + SLOT_GAP}px` : '0px';
        }
        const width = withGen ? genWidth + SLOT_GAP + size : size;
        this._icon.place(r.right - width - 8, r.top + (r.height - size) / 2);
      }
    }
    if (this._menu && this.field) {
      const f = this.field;
      if (!f.isConnected) { this.close(); return; }
      const r = f.getBoundingClientRect();
      if (r.bottom < 0 || r.top > vh || this._menu.blocked) { this._menu.host.style.setProperty('display', 'none', 'important'); return; }
      this._menu.host.style.setProperty('display', 'block', 'important');
      const box = this._box;
      const width = Math.min(360, Math.max(240, r.width));
      box.style.width = `${width}px`;
      // Below the field if it fits, else on the roomier side, capped to the window.
      box.style.maxHeight = '';
      let height = box.offsetHeight || 200;
      const below = vh - r.bottom - 8;
      const above = r.top - 8;
      let up = false;
      if (height > below && above > below) {
        up = true;
        if (height > above) { box.style.maxHeight = `${Math.max(0, above)}px`; height = box.offsetHeight || height; }
      } else if (height > below) {
        box.style.maxHeight = `${Math.max(0, below)}px`;
      }
      box.classList.toggle('up', up);
      const top = up ? Math.max(4, r.top - height - 2) : r.bottom + 2;
      const left = Math.max(4, Math.min(r.left, vw - width - 4));
      this._menu.place(left, top);
    }
  }
}
