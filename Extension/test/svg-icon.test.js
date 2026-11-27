// Lucide icons (src/shared/icons.js) and the element builder (src/shared/svg-icon.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { makeDom } from './helpers/dom.js';
import { ICONS } from '../src/shared/icons.js';
import { icon, hydrateIcons, hasIcon } from '../src/shared/svg-icon.js';

const src = (rel) => readFileSync(new URL(`../src/${rel}`, import.meta.url), 'utf8');

test('icons.js is the desktop app\'s copy (only the header comment differs)', () => {
  const desktop = new URL('../../Core/desktop-app/ui/icons.js', import.meta.url);
  if (!existsSync(desktop)) return; // extension checked out on its own
  const body = (s) => s.replace(/\r\n/g, '\n').slice(s.replace(/\r\n/g, '\n').indexOf('export const ICONS'));
  assert.equal(body(src('shared/icons.js')), body(readFileSync(desktop, 'utf8')));
});

test('the license notice ships with the extension', () => {
  const notice = readFileSync(new URL('../THIRD_PARTY_NOTICES.md', import.meta.url), 'utf8');
  assert.match(notice, /Lucide/);
  assert.match(notice, /ISC License/);
  assert.match(notice, /Feather/);
});

test('icon() builds a 24x24 stroke SVG with createElementNS', () => {
  const { document } = makeDom('');
  const svg = icon('gear', { doc: document });
  assert.equal(svg.namespaceURI, 'http://www.w3.org/2000/svg');
  for (const [k, v] of Object.entries({ viewBox: '0 0 24 24', width: '16', height: '16', fill: 'none', stroke: 'currentColor',
    'stroke-width': '1.75', 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true', 'data-icon': 'gear' })) {
    assert.equal(svg.getAttribute(k), v, k);
  }
  assert.equal(svg.children.length, ICONS.gear.length);
  assert.equal(svg.children[0].namespaceURI, 'http://www.w3.org/2000/svg');
  assert.equal(icon('gear', { doc: document, size: 36 }).getAttribute('stroke-width'), '2', 'Lucide default when large');
  assert.equal(icon('gear', { doc: document, strokeWidth: 1.5 }).getAttribute('stroke-width'), '1.5');
  assert.throws(() => icon('nope', { doc: document }), /Unknown icon/);
  assert.equal(hasIcon('toString'), false, 'no prototype keys');
});

test('hydrateIcons fills [data-icon] placeholders once, before the label', () => {
  const { document } = makeDom('<button data-icon="copy" data-icon-size="18"><span>Copy</span></button><i data-icon="lock"></i>');
  hydrateIcons(document.body);
  hydrateIcons(document.body);
  const btn = document.querySelector('button');
  assert.equal(btn.querySelectorAll('svg').length, 1);
  assert.equal(btn.firstElementChild.tagName.toLowerCase(), 'svg');
  assert.equal(btn.firstElementChild.getAttribute('width'), '18');
  assert.equal(btn.textContent, 'Copy');
  const i = document.querySelector('i');
  i.setAttribute('data-icon', 'lockOpen');
  hydrateIcons(document.body);
  assert.equal(i.querySelectorAll('svg').length, 1, 'swapped, not added');
  assert.equal(i.firstElementChild.getAttribute('data-icon'), 'lockOpen');
});

test('every icon name used by the extension UI exists', () => {
  const files = ['popup/popup.html', 'popup/popup.js', 'options/options.html', 'ui/server-pair.js',
    'content/menu.js', 'content/main.js', 'content/toast.js', 'content/banner.js'];
  const used = new Set();
  for (const f of files) {
    const text = src(f);
    for (const m of text.matchAll(/data-icon="([A-Za-z]+)"/g)) used.add(m[1]);
    for (const m of text.matchAll(/\b(?:uiIcon|icon|iconButton)\('([A-Za-z]+)'/g)) used.add(m[1]);
    for (const m of text.matchAll(/\bicon: '([A-Za-z]+)'/g)) used.add(m[1]);
  }
  assert.ok(used.size >= 15, [...used].join(','));
  for (const name of used) assert.ok(hasIcon(name), name);
});

test('no hand-drawn or inline SVG markup is left in the extension UI', () => {
  for (const f of ['popup/popup.html', 'options/options.html']) {
    assert.ok(!/<svg/i.test(src(f)), f);
  }
  for (const f of ['popup/popup.js', 'content/menu.js', 'content/toast.js', 'content/banner.js', 'ui/server-pair.js']) {
    assert.ok(!/fill: 'currentColor', d:/.test(src(f)), `${f}: filled path icon`);
    assert.ok(!/innerHTML/.test(src(f)), `${f}: innerHTML`);
  }
});
