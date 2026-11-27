// jsdom has no popovers and no modal dialogs: the stubs below model the top layer (an ordered list),
// `:modal`, `:popover-open` and the `beforetoggle` event.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM(`<!doctype html><html><body>
  <form id="page"><input id="outside" type="password"></form>
  <dialog id="dlg"><form><input id="inside" type="password"></form></dialog>
</body></html>`, { url: 'https://example.com/login', pretendToBeVisual: true });
const w = dom.window;
const doc = w.document;

const topLayer = [];                 // in paint order: the last one is on top
const modal = new Set();
const shown = new Map();             // element -> showPopover() calls
const toTop = (el) => { const i = topLayer.indexOf(el); if (i >= 0) topLayer.splice(i, 1); topLayer.push(el); };
const leave = (el) => { const i = topLayer.indexOf(el); if (i >= 0) topLayer.splice(i, 1); };
const isOpenPopover = (el) => el.isConnected && topLayer.includes(el) && el.hasAttribute('popover');

function beforeToggle(el, newState) {
  const e = new w.Event('beforetoggle');
  e.newState = newState;
  el.dispatchEvent(e);
}
function showPopover() {
  if (!this.hasAttribute('popover') || !this.isConnected || isOpenPopover(this)) throw new w.DOMException('invalid', 'InvalidStateError');
  beforeToggle(this, 'open');
  shown.set(this, (shown.get(this) || 0) + 1);
  toTop(this);
}
function hidePopover() {
  if (!isOpenPopover(this)) throw new w.DOMException('invalid', 'InvalidStateError');
  beforeToggle(this, 'closed');
  leave(this);
}
w.HTMLElement.prototype.showPopover = showPopover;
w.HTMLElement.prototype.hidePopover = hidePopover;
w.HTMLDialogElement.prototype.showModal = function () {
  this.setAttribute('open', '');
  modal.add(this);
  toTop(this);
};
w.HTMLDialogElement.prototype.close = function () {
  this.removeAttribute('open');
  modal.delete(this);
  leave(this);
};

const PSEUDO = {
  'dialog:modal': (el) => modal.has(el),
  ':modal': (el) => modal.has(el),
  ':popover-open': isOpenPopover,
  ':fullscreen': () => false,
};
const matches = w.Element.prototype.matches;
w.Element.prototype.matches = function (selector) {
  return PSEUDO[selector] ? PSEUDO[selector](this) : matches.call(this, selector);
};
const qsa = w.Document.prototype.querySelectorAll;
w.Document.prototype.querySelectorAll = function (selector) {
  if (!PSEUDO[selector]) return qsa.call(this, selector);
  return [...this.getElementsByTagName('*')].filter(PSEUDO[selector]);
};

// Boxes: fields and our UI at the top left, the dialog over most of the viewport.
const rects = new Map();
const rect = (left, top, width, height) => ({ left, top, width, height, right: left + width, bottom: top + height, x: left, y: top });
// Without the top layer, a host inside the dialog is offset by it (50, 20), as with a transform there.
w.Element.prototype.getBoundingClientRect = function () {
  if (this.localName?.startsWith('pass-') && this.parentNode?.localName === 'dialog' && !isOpenPopover(this)) {
    return rect(parseFloat(this.style.left) + 50, parseFloat(this.style.top) + 20, 0, 0);
  }
  return rects.get(this) || rect(10, 10, 200, 30);
};
rects.set(doc.getElementById('dlg'), rect(0, 0, 800, 600));

const shadowRoots = new Map();
const attachShadow = w.Element.prototype.attachShadow;
w.Element.prototype.attachShadow = function (init) {
  const root = attachShadow.call(this, init);
  shadowRoots.set(this, root);
  return root;
};

let ui;
let InlineMenu;
let showNotice;
let showSaveBanner;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, Node: w.Node, MutationObserver: w.MutationObserver,
    requestAnimationFrame: w.requestAnimationFrame.bind(w), getComputedStyle: w.getComputedStyle.bind(w),
  });
  ui = await import('../src/content/ui-common.js');
  ({ InlineMenu } = await import('../src/content/menu.js'));
  ({ showNotice } = await import('../src/content/toast.js'));
  ({ showSaveBanner } = await import('../src/content/banner.js'));
});

after(() => w.close());

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const $ = (id) => doc.getElementById(id);
const dlg = () => $('dlg');
const picked = [];
const newMenu = () => new InlineMenu({ onIconClick: () => {}, onSelect: (entry) => picked.push(entry.id), onGenerateClick: () => {} });
const MODEL = { status: 'ok', entries: [{ kind: 'login', id: 'ex', title: 'Example', subtitle: 'alice' }] };
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true, button: 0 }));
const display = (host) => host.style.getPropertyValue('display');

function reset() {
  for (const d of doc.querySelectorAll('dialog')) if (d.hasAttribute('open')) d.close();
  for (const el of [...topLayer]) leave(el);
}

test('menu and icon of a field in a modal dialog: inside the dialog, as popovers on top of it', async () => {
  reset();
  dlg().showModal();
  const menu = newMenu();
  menu.showIcon($('inside'), { generate: true });
  menu.open($('inside'), MODEL);
  const host = doc.querySelector('pass-menu');
  const icon = doc.querySelector('pass-icon');
  assert.equal(host.parentNode, dlg(), 'menu host is a child of the dialog (not inert)');
  assert.equal(icon.parentNode, dlg(), 'icon host too');
  assert.equal(host.getAttribute('popover'), 'manual');
  assert.equal(host.style.getPropertyValue('z-index'), '2147483647', 'z-index kept for browsers without popovers');
  assert.equal(host.style.getPropertyValue('inset') || host.style.getPropertyValue('right'), 'auto', 'UA popover inset undone');
  assert.equal(topLayer.at(-1), host, 'menu is the topmost element of the top layer');
  assert.ok(topLayer.indexOf(dlg()) < topLayer.indexOf(icon), 'icon above the dialog');
  assert.equal(display(host), 'block');
  assert.equal(menu.intact(), true, 'the dialog it lives in does not count as covering it');
  menu.destroy();
  assert.equal(doc.querySelector('pass-menu'), null);
});

test('a popover the page shows over the menu afterwards: not intact, then the menu is shown on top again', async () => {
  reset();
  const menu = newMenu();
  menu.open($('outside'), MODEL);
  const host = doc.querySelector('pass-menu');
  assert.equal(host.parentNode, doc.documentElement, 'no dialog: the host stays on <html>');
  assert.equal(shown.get(host), 1);
  await tick(ui.MIN_VISIBLE_MS + 50);

  const decoy = doc.createElement('div');
  decoy.setAttribute('popover', 'manual');
  doc.body.append(decoy);
  decoy.showPopover(); // over the menu (same box)
  assert.equal(topLayer.at(-1), decoy);
  assert.equal(menu.intact(), false, 'shown after the menu, over it: covering it');
  await tick(10);
  assert.equal(shown.get(host), 2, 'the menu was shown again (hide, show)');
  assert.equal(topLayer.at(-1), host, 'and is on top again');
  assert.equal(menu.intact(), true);

  // A click right after it came back on top does not count: the user may not have seen it yet.
  const item = shadowRoots.get(host).querySelector('.item');
  await click(item);
  assert.deepEqual(picked, [], 'too soon after it was shown again');
  await tick(ui.MIN_VISIBLE_MS + 50);
  await click(item);
  assert.deepEqual(picked, ['ex'], 'visible for a moment: the click picks');
  picked.length = 0;

  // Opening again with nothing new in the top layer does not hide and show it.
  menu.open($('outside'), MODEL);
  assert.equal(shown.get(host), 2, 'nothing came after it: left as it is');
  const other = doc.createElement('div');
  other.setAttribute('popover', 'manual');
  rects.set(other, rect(600, 500, 50, 50)); // elsewhere on the page
  doc.body.append(other);
  other.showPopover();
  await tick(10);
  assert.equal(shown.get(host), 2, 'a popover elsewhere: no need to move');
  menu.open($('outside'), MODEL);
  assert.equal(shown.get(host), 3, 'opening again after the page showed one: on top again');
  menu.destroy();
  decoy.remove();
  other.remove();
});

test('a modal dialog the page opens after the menu, without its field: icon and menu hide (inert field)', async () => {
  reset();
  const menu = newMenu();
  menu.showIcon($('outside'));
  menu.open($('outside'), MODEL);
  const host = doc.querySelector('pass-menu');
  const icon = doc.querySelector('pass-icon');
  assert.equal(display(host), 'block');
  dlg().showModal();
  await tick(30); // the MutationObserver, then the menu's next layout (requestAnimationFrame)
  assert.equal(display(host), 'none', 'menu hidden: its field is behind the dialog');
  assert.equal(display(icon), 'none', 'icon hidden too');
  dlg().close();
  await tick(30);
  assert.equal(display(host), 'block', 'dialog closed: shown again');
  menu.destroy();
});

test('the field moves into a modal dialog: the menu follows it there, and back out when the field does', async () => {
  reset();
  const menu = newMenu();
  const field = $('outside');
  menu.open(field, MODEL);
  const host = doc.querySelector('pass-menu');
  assert.equal(host.parentNode, doc.documentElement);
  dlg().querySelector('form').append(field);
  dlg().showModal();
  await tick(10);
  assert.equal(host.parentNode, dlg(), 'moved into the dialog');
  assert.equal(topLayer.at(-1), host, 'and shown on top of it');
  $('page').append(field);
  menu.open(field, MODEL);
  assert.equal(host.parentNode, doc.documentElement, 'back on <html> with its field');
  menu.destroy();
});

test('save banner and toast: inside the open modal dialog, back on <html> when it closes', async () => {
  reset();
  dlg().showModal();
  const banner = showSaveBanner({ mode: 'save', host: 'example.com', username: 'alice', title: null,
    onSave: async () => ({}), onDismiss: () => {} });
  const notice = showNotice('Hello');
  const bannerHost = doc.querySelector('pass-banner');
  const noticeHost = doc.querySelector('pass-notice');
  assert.equal(bannerHost.parentNode, dlg(), 'banner inside the dialog (clickable)');
  assert.equal(noticeHost.parentNode, dlg(), 'toast inside the dialog');
  assert.ok(topLayer.indexOf(bannerHost) > topLayer.indexOf(dlg()), 'banner above the dialog');
  assert.equal(bannerHost.getAttribute('popover'), 'manual');
  dlg().close();
  await tick(10);
  assert.equal(bannerHost.parentNode, doc.documentElement, 'dialog closed: banner back on <html>');
  assert.equal(noticeHost.parentNode, doc.documentElement);
  assert.ok(isOpenPopover(bannerHost), 'and still in the top layer');
  banner.close();
  notice.close();
});

test('without popovers: no popover attribute, the maximum z-index, still inside the modal dialog', async () => {
  reset();
  dlg().showModal();
  const saved = w.HTMLElement.prototype.showPopover;
  delete w.HTMLElement.prototype.showPopover;
  try {
    const notice = showNotice('Hello');
    const host = doc.querySelector('pass-notice');
    assert.equal(host.hasAttribute('popover'), false);
    assert.equal(host.style.getPropertyValue('z-index'), '2147483647');
    assert.equal(host.style.getPropertyPriority('z-index'), 'important');
    assert.equal(host.parentNode, dlg(), 'inside the modal dialog: not inert');
    assert.equal(topLayer.includes(host), false);
    notice.close();

    // The menu without the top layer, inside a dialog with an offset (a transform): the measured
    // offset is taken off so that it still lines up with its field.
    const menu = newMenu();
    rects.set($('inside'), rect(100, 100, 200, 30));
    menu.open($('inside'), MODEL);
    const menuHost = doc.querySelector('pass-menu');
    assert.equal(menuHost.parentNode, dlg());
    assert.equal(menuHost.style.getPropertyValue('left'), '50px', 'meant for 100px, measured 50px further: offset taken off');
    assert.equal(menuHost.style.getPropertyValue('top'), '112px', 'below the field (132px: 2px under it), less the 20px offset');
    assert.equal(menu.intact(), true, 'the dialog it is in does not cover it');
    menu.destroy();
    rects.delete($('inside'));
  } finally {
    w.HTMLElement.prototype.showPopover = saved;
  }
});

test('events from inside the UI do not reach the page\'s own listeners (no "click outside" for its dialog)', async () => {
  reset();
  const menu = newMenu();
  menu.open($('outside'), MODEL);
  const host = doc.querySelector('pass-menu');
  const seen = { bubble: [], capture: [] };
  const types = ['pointerdown', 'mousedown', 'click', 'focusin', 'keydown'];
  const onBubble = (e) => seen.bubble.push(e.type);
  const onCapture = (e) => seen.capture.push(e.type);
  for (const type of types) {
    doc.addEventListener(type, onBubble);
    doc.addEventListener(type, onCapture, true);
  }
  const item = shadowRoots.get(host).querySelector('.item');
  for (const type of types) item.dispatchEvent(new w.Event(type, { bubbles: true, composed: true }));
  assert.deepEqual(seen.bubble, [], 'stopped at the host');
  assert.deepEqual(seen.capture, types, 'capture listeners (ours in main.js) still see them');
  for (const type of types) {
    doc.removeEventListener(type, onBubble);
    doc.removeEventListener(type, onCapture, true);
  }
  menu.destroy();
});
