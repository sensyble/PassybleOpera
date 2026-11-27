// createElementNS, not innerHTML: works in closed shadow roots and under a page's Trusted Types CSP.
import { ICONS } from './icons.js';
import { LOGO } from './logo.js';

const SVG_NS = 'http://www.w3.org/2000/svg';

export function hasIcon(name) {
  return Object.prototype.hasOwnProperty.call(ICONS, name);
}

/** A 24x24 stroke icon in `currentColor`, `size` px (default 16). */
export function icon(name, { size = 16, strokeWidth, className = '', doc = globalThis.document } = {}) {
  if (!hasIcon(name)) throw new Error(`Unknown icon: ${name}`);
  const sw = strokeWidth ?? (size <= 18 ? 1.75 : 2);
  const svg = doc.createElementNS(SVG_NS, 'svg');
  for (const [k, v] of Object.entries({
    viewBox: '0 0 24 24', width: size, height: size, fill: 'none', stroke: 'currentColor',
    'stroke-width': sw, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true',
    focusable: 'false', class: `pass-icon${className ? ` ${className}` : ''}`,
  })) svg.setAttribute(k, String(v));
  svg.setAttribute('data-icon', name);
  for (const [tag, attrs] of ICONS[name]) {
    const child = doc.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) child.setAttribute(k, String(v));
    svg.appendChild(child);
  }
  return svg;
}

/** Fills every `[data-icon]` element under `root` with its icon (size from `data-icon-size`). Idempotent. */
export function hydrateIcons(root) {
  const doc = root.ownerDocument || root;
  for (const el of root.querySelectorAll('[data-icon]:not(svg)')) {
    const name = el.getAttribute('data-icon');
    const old = el.querySelector(':scope > svg.pass-icon');
    if (old?.getAttribute('data-icon') === name) continue;
    old?.remove();
    const size = Number(el.getAttribute('data-icon-size')) || 16;
    el.prepend(icon(name, { size, doc }));
  }
}

export function logo({ size = 24, doc = globalThis.document } = {}) {
  const svg = wordmarkNote({ doc });
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  return svg;
}

/** The mark as the toolbar icon draws it, in both themes: the lime over its dark green border. */
export function wordmarkNote({ doc = globalThis.document } = {}) {
  const svg = doc.createElementNS(SVG_NS, 'svg');
  for (const [k, v] of Object.entries({ viewBox: LOGO.view, 'aria-hidden': 'true', focusable: 'false', class: 'pass-logo pass-note' })) {
    svg.setAttribute(k, v);
  }
  for (const [fill, stroke] of [[LOGO.edge, LOGO.stroke], [LOGO.lime, 0]]) {
    const path = doc.createElementNS(SVG_NS, 'path');
    path.setAttribute('d', LOGO.mark);
    path.setAttribute('fill', fill);
    if (stroke) {
      path.setAttribute('stroke', fill);
      path.setAttribute('stroke-width', String(stroke));
      path.setAttribute('stroke-linejoin', 'round');
    }
    svg.appendChild(path);
  }
  return svg;
}

export function fillWordmark(el) {
  const doc = el.ownerDocument;
  el.replaceChildren(doc.createTextNode('Pass'), wordmarkNote({ doc }), doc.createTextNode('ble'));
  el.classList.add('wordmark');
  el.setAttribute('role', 'img');
  el.setAttribute('aria-label', 'Passyble');
  el.removeAttribute('aria-hidden');
}
