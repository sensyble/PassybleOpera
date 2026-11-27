// An explanation tooltip on an (i) button (WCAG 1.4.13): hover or focus shows it, the pointer may
// move onto it, Esc hides it, and it stays until the user moves away. Without hover (touch), a tap
// toggles it and a tap outside closes it. Built with DOM APIs only (no innerHTML).

let seq = 0;
const GAP = 6;
const EDGE = 8;

function noHover(view) {
  try { return !!view?.matchMedia?.('(hover: none)').matches; } catch { return false; }
}

/** Places `el` below `anchor` (above when it doesn't fit), kept inside the window. */
export function placeTooltip(anchor, el) {
  const view = anchor.ownerDocument.defaultView;
  const r = anchor.getBoundingClientRect();
  const w = el.offsetWidth || 0;
  const h = el.offsetHeight || 0;
  const vw = view?.innerWidth || 400;
  const vh = view?.innerHeight || 600;
  let top = r.bottom + GAP;
  let side = 'below';
  if (top + h > vh - EDGE && r.top - GAP - h >= EDGE) { top = r.top - GAP - h; side = 'above'; }
  const left = Math.max(EDGE, Math.min(r.left + r.width / 2 - w / 2, vw - w - EDGE));
  el.style.top = `${Math.round(Math.max(EDGE, top))}px`;
  el.style.left = `${Math.round(left)}px`;
  el.dataset.side = side;
}

/** Gives `anchor` (a button with an accessible name) a tooltip with `content` (text or a node). */
export function attachTooltip(anchor, content) {
  const doc = anchor.ownerDocument;
  const view = doc.defaultView;
  const el = doc.createElement('div');
  el.className = 'tooltip';
  el.id = `tooltip-${++seq}`;
  el.setAttribute('role', 'tooltip');
  el.hidden = true;
  el.append(typeof content === 'string' ? doc.createTextNode(content) : content);
  doc.body.append(el);
  const described = (anchor.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
  anchor.setAttribute('aria-describedby', [...described, el.id].join(' '));

  let over = false;
  let kbd = false;
  let leaveTimer = 0;
  let pointer = '';
  const visible = () => !el.hidden;
  const reposition = () => { if (visible()) placeTooltip(anchor, el); };

  const onKey = (e) => {
    if (e.key !== 'Escape' || !visible()) return;
    e.preventDefault();
    e.stopImmediatePropagation();
    hide();
  };
  const onDown = (e) => {
    if (anchor.contains(e.target) || el.contains(e.target)) return;
    hide();
  };

  function show() {
    view?.clearTimeout(leaveTimer);
    if (visible()) return;
    el.hidden = false;
    placeTooltip(anchor, el);
    // On the window, so it runs before the popup's and a menu's own Esc (those listen on the document).
    view?.addEventListener('keydown', onKey, true);
    doc.addEventListener('pointerdown', onDown, true);
    view?.addEventListener('resize', reposition);
    view?.addEventListener('scroll', reposition, true);
  }
  function hide() {
    view?.clearTimeout(leaveTimer);
    if (!visible()) return;
    el.hidden = true;
    view?.removeEventListener('keydown', onKey, true);
    doc.removeEventListener('pointerdown', onDown, true);
    view?.removeEventListener('resize', reposition);
    view?.removeEventListener('scroll', reposition, true);
  }
  const enter = (e) => {
    if (e.pointerType === 'touch') return;
    over = true;
    show();
  };
  const leave = (e) => {
    if (e.pointerType === 'touch') return;
    over = false;
    view?.clearTimeout(leaveTimer);
    leaveTimer = view?.setTimeout(() => { if (!over && !kbd) hide(); }, 150);
  };

  anchor.addEventListener('pointerenter', enter);
  anchor.addEventListener('pointerleave', leave);
  el.addEventListener('pointerenter', enter);
  el.addEventListener('pointerleave', leave);
  anchor.addEventListener('pointerdown', (e) => { pointer = e.pointerType || ''; });
  anchor.addEventListener('focus', () => { if (!pointer) { kbd = true; show(); } });
  anchor.addEventListener('blur', () => { kbd = false; if (!over) hide(); });
  anchor.addEventListener('click', (e) => {
    e.preventDefault();
    const tap = pointer === 'touch' || pointer === 'pen' || noHover(view);
    pointer = '';
    if (tap) { if (visible()) hide(); else show(); } else show();
  });

  return { el, show, hide, get open() { return visible(); } };
}
