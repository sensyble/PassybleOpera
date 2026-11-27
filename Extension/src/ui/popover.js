// Built with DOM APIs only (no innerHTML).
import { icon } from '../shared/svg-icon.js';
import { t } from '../shared/i18n.js';

let current = null;

export function closeMenu({ focusAnchor = false } = {}) {
  if (!current) return;
  const { el, anchor, cleanup } = current;
  current = null;
  cleanup();
  el.remove();
  anchor.setAttribute('aria-expanded', 'false');
  if (focusAnchor) anchor.focus?.();
}

/** True while a menu is open (its keys come first: Esc closes it, not the page behind it). */
export function menuIsOpen() {
  return !!current;
}

function explained(doc, item) {
  const text = doc.createElement('span');
  text.className = 'menu-text';
  const name = doc.createElement('span');
  name.className = 'menu-name';
  name.textContent = item.label;
  if (item.tag) {
    const tag = doc.createElement('span');
    tag.className = 'menu-tag';
    tag.textContent = item.tag;
    name.append(tag);
  }
  text.append(name);
  if (item.detail) {
    const detail = doc.createElement('span');
    detail.className = 'menu-detail';
    detail.textContent = item.detail;
    text.append(detail);
  }
  return text;
}

/** Opens a menu under `anchor` (toggles it when already open). Items: actions, checkboxes (`onToggle`), choices (`selected`), `pin` rows, `{ heading }` groups or 'sep'. */
export function openMenu(anchor, items, { label = t('commonMore'), compact = false } = {}) {
  const doc = anchor.ownerDocument;
  if (current?.anchor === anchor) { closeMenu({ focusAnchor: true }); return null; }
  closeMenu();
  const el = doc.createElement('div');
  el.className = `popover${compact ? ' compact' : ''}`;
  el.setAttribute('role', 'menu');
  el.setAttribute('aria-label', label);
  let into = el; // the group the next items go in (the menu itself outside a heading's group)
  for (const item of items) {
    if (!item) continue;
    if (item === 'sep') {
      const sep = doc.createElement('div');
      sep.className = 'menu-sep';
      sep.setAttribute('role', 'separator');
      el.append(sep);
      into = el;
      continue;
    }
    if (item.heading) {
      into = doc.createElement('div');
      into.className = 'menu-group';
      into.setAttribute('role', 'group');
      into.setAttribute('aria-label', item.label || item.heading);
      const heading = doc.createElement('div');
      heading.className = 'menu-heading';
      heading.setAttribute('aria-hidden', 'true');
      heading.textContent = item.heading;
      into.append(heading);
      el.append(into);
      continue;
    }
    const btn = doc.createElement('button');
    btn.type = 'button';
    const check = typeof item.onToggle === 'function';
    const choice = typeof item.selected === 'boolean';
    btn.className = `menu-item${check || choice ? ' check' : ''}${item.danger ? ' danger' : ''}${item.muted ? ' muted' : ''}`;
    btn.setAttribute('role', check ? 'menuitemcheckbox' : choice ? 'menuitemradio' : 'menuitem');
    if (item.id) btn.id = item.id;
    if (choice) btn.setAttribute('aria-checked', String(item.selected));
    if (check || choice) btn.append(icon('check', { doc }));
    else if (item.icon) btn.append(icon(item.icon, { doc }));
    btn.append(item.detail || item.tag ? explained(doc, item) : Object.assign(doc.createElement('span'), { textContent: item.label }));
    if (item.pin?.pinned && item.pin.state) {
      const note = doc.createElement('span');
      note.className = 'sr-only';
      note.textContent = item.pin.state;
      btn.append(doc.createTextNode(' '), note);
    }
    if (check) {
      btn.setAttribute('aria-checked', String(!!item.checked));
      btn.addEventListener('click', (e) => {
        e.stopPropagation();
        const on = btn.getAttribute('aria-checked') !== 'true';
        btn.setAttribute('aria-checked', String(on));
        item.onToggle(on);
      });
      into.append(btn);
      continue;
    }
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      closeMenu({ focusAnchor: true });
      item.onSelect();
    });
    into.append(item.pin ? pinRow(doc, anchor, btn, item) : btn);
  }
  doc.body.append(el);
  place(anchor, el);
  anchor.setAttribute('aria-expanded', 'true');

  const buttons = () => [...el.querySelectorAll('.menu-item')];
  const onKey = (e) => {
    const row = doc.activeElement?.closest?.('.menu-row');
    if (e.key === 'Escape') {
      e.preventDefault();
      e.stopImmediatePropagation();
      closeMenu({ focusAnchor: true });
    } else if ((e.key === 'ArrowRight' || e.key === 'ArrowLeft') && row && el.contains(row)) {
      e.preventDefault();
      e.stopImmediatePropagation();
      row.querySelector(e.key === 'ArrowRight' ? '.menu-pin' : '.menu-item')?.focus();
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      e.stopImmediatePropagation();
      const list = buttons();
      const i = list.indexOf(row ? row.querySelector('.menu-item') : doc.activeElement);
      const next = e.key === 'ArrowDown' ? (i + 1) % list.length : (i <= 0 ? list.length - 1 : i - 1);
      list[next]?.focus();
    } else if (e.key === 'Tab') {
      closeMenu();
    }
  };
  const onDown = (e) => {
    if (el.contains(e.target) || anchor.contains(e.target)) return;
    closeMenu();
  };
  doc.addEventListener('keydown', onKey, true);
  doc.addEventListener('mousedown', onDown, true);
  current = { el, anchor, cleanup: () => {
    doc.removeEventListener('keydown', onKey, true);
    doc.removeEventListener('mousedown', onDown, true);
  } };
  (el.querySelector('[role="menuitemradio"][aria-checked="true"]') || buttons()[0])?.focus();
  return el;
}

function pinRow(doc, anchor, btn, item) {
  const { pin } = item;
  const row = doc.createElement('div');
  row.className = `menu-row${pin.pinned ? ' pinned' : ''}`;
  row.setAttribute('role', 'none');
  const toggle = doc.createElement('button');
  toggle.type = 'button';
  toggle.className = 'menu-pin';
  toggle.tabIndex = -1;
  toggle.title = pin.label;
  toggle.setAttribute('aria-label', pin.label);
  toggle.setAttribute('aria-pressed', String(!!pin.pinned));
  toggle.append(icon('pin', { doc, size: 15 }));
  toggle.addEventListener('click', (e) => {
    e.stopPropagation();
    closeMenu({ focusAnchor: true });
    pin.onToggle();
  });
  if (pin.menuLabel) {
    btn.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      closeMenu();
      openMenu(anchor, [{ id: 'menu-pin-toggle', icon: pin.pinned ? 'pinOff' : 'pin', label: pin.menuLabel, onSelect: pin.onToggle }],
        { label: item.label });
    });
  }
  row.append(btn, toggle);
  return row;
}

function place(anchor, el) {
  const view = anchor.ownerDocument.defaultView;
  const r = anchor.getBoundingClientRect();
  const w = el.offsetWidth || 200;
  const h = el.offsetHeight || 0;
  const vw = view?.innerWidth || 400;
  const vh = view?.innerHeight || 600;
  let top = r.bottom + 4;
  if (h && top + h > vh - 4 && r.top - h - 4 > 0) top = r.top - h - 4;
  const left = Math.max(4, Math.min(r.right - w, vw - w - 4));
  el.style.top = `${Math.round(top)}px`;
  el.style.left = `${Math.round(left)}px`;
}
