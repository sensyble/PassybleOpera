import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import { attachTooltip, placeTooltip } from '../src/ui/tooltip.js';

function setup({ hoverNone = false } = {}) {
  const { window, document } = makeDom('<p><button id="info" type="button" aria-label="About auto-lock">i</button><button id="other" type="button">x</button></p>');
  window.matchMedia = (q) => ({ matches: hoverNone && q === '(hover: none)' });
  const btn = document.getElementById('info');
  const tip = attachTooltip(btn, 'Locks the vault after a while.');
  const ev = (target, type, init = {}) => {
    const Ctor = /^pointer/.test(type) ? (window.PointerEvent || window.MouseEvent) : /^key/.test(type) ? window.KeyboardEvent : window.Event;
    const e = new Ctor(type, { bubbles: true, cancelable: true, ...init });
    if (init.pointerType && e.pointerType !== init.pointerType) Object.defineProperty(e, 'pointerType', { value: init.pointerType });
    target.dispatchEvent(e);
    return e;
  };
  return { window, document, btn, tip, ev };
}

test('tooltip: role, id and aria-describedby link it to its button, hidden at first', () => {
  const { btn, tip, document } = setup();
  assert.equal(tip.el.getAttribute('role'), 'tooltip');
  assert.equal(btn.getAttribute('aria-describedby'), tip.el.id);
  assert.equal(document.getElementById(tip.el.id).textContent, 'Locks the vault after a while.');
  assert.equal(btn.getAttribute('aria-label'), 'About auto-lock');
  assert.equal(tip.el.hidden, true);
});

test('tooltip: hover shows it, moving onto it keeps it, leaving both hides it', async () => {
  const { btn, tip, ev } = setup();
  ev(btn, 'pointerenter', { pointerType: 'mouse' });
  assert.equal(tip.el.hidden, false);
  ev(btn, 'pointerleave', { pointerType: 'mouse' });
  ev(tip.el, 'pointerenter', { pointerType: 'mouse' });
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(tip.el.hidden, false, 'the pointer is on the tooltip');
  ev(tip.el, 'pointerleave', { pointerType: 'mouse' });
  await new Promise((r) => setTimeout(r, 200));
  assert.equal(tip.el.hidden, true);
});

test('tooltip: keyboard focus shows it, blur hides it', () => {
  const { btn, tip, ev } = setup();
  ev(btn, 'focus');
  assert.equal(tip.el.hidden, false);
  ev(btn, 'blur');
  assert.equal(tip.el.hidden, true);
});

test('tooltip: Esc hides it without reaching the page', () => {
  const { btn, tip, ev, document } = setup();
  let pageSawEsc = false;
  document.addEventListener('keydown', () => { pageSawEsc = true; });
  ev(btn, 'focus');
  ev(btn, 'keydown', { key: 'Escape' });
  assert.equal(tip.el.hidden, true);
  assert.equal(pageSawEsc, false);
  ev(btn, 'keydown', { key: 'Escape' });
  assert.equal(pageSawEsc, true, 'closed: Esc goes to the page again');
});

test('tooltip: it does not vanish on its own', async () => {
  const { btn, tip, ev } = setup();
  ev(btn, 'pointerenter', { pointerType: 'mouse' });
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(tip.el.hidden, false);
});

test('tooltip: without hover a tap toggles it and a tap outside closes it', () => {
  const { btn, tip, ev, document } = setup({ hoverNone: true });
  ev(btn, 'pointerenter', { pointerType: 'touch' });
  assert.equal(tip.el.hidden, true, 'touch pointerenter alone does nothing');
  ev(btn, 'pointerdown', { pointerType: 'touch' });
  btn.click();
  assert.equal(tip.el.hidden, false);
  ev(btn, 'pointerdown', { pointerType: 'touch' });
  btn.click();
  assert.equal(tip.el.hidden, true);
  ev(btn, 'pointerdown', { pointerType: 'touch' });
  btn.click();
  ev(document.getElementById('other'), 'pointerdown', { pointerType: 'touch' });
  assert.equal(tip.el.hidden, true);
});

test('tooltip: a mouse click keeps it open (no toggle off)', () => {
  const { btn, tip, ev } = setup();
  ev(btn, 'pointerenter', { pointerType: 'mouse' });
  ev(btn, 'pointerdown', { pointerType: 'mouse' });
  btn.click();
  assert.equal(tip.el.hidden, false);
});

test('tooltip: placed below, flipped above near the bottom, kept inside the window', () => {
  const { window, document } = makeDom('<button id="b">i</button><div id="t"></div>');
  Object.defineProperty(window, 'innerWidth', { value: 360 });
  Object.defineProperty(window, 'innerHeight', { value: 500 });
  const b = document.getElementById('b');
  const t = document.getElementById('t');
  Object.defineProperty(t, 'offsetWidth', { value: 280 });
  Object.defineProperty(t, 'offsetHeight', { value: 60 });
  const at = (left, top) => { b.getBoundingClientRect = () => ({ left, top, right: left + 24, bottom: top + 24, width: 24, height: 24 }); };
  at(330, 20);
  placeTooltip(b, t);
  assert.equal(t.dataset.side, 'below');
  assert.equal(t.style.top, '50px');
  assert.equal(t.style.left, '72px', 'shifted left to stay 8px inside the right edge');
  at(4, 460);
  placeTooltip(b, t);
  assert.equal(t.dataset.side, 'above');
  assert.equal(t.style.top, '394px');
  assert.equal(t.style.left, '8px');
});
