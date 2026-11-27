// jsdom can't load the edit frame: its messages are posted by the test as the extension page would.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body><p>Welcome back</p></body></html>', { url: 'https://github.com/', pretendToBeVisual: true });
const w = dom.window;
const doc = w.document;

w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};
const shadowRoots = new Map();
const attachShadow = w.Element.prototype.attachShadow;
w.Element.prototype.attachShadow = function (init) {
  const root = attachShadow.call(this, init);
  shadowRoots.set(this, root);
  return root;
};

const ORIGIN = 'chrome-extension://pass-ext';
const PASSWORD = 'github123';
const sent = [];
const responses = {
  'otp.context': () => ({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ({ items: [], pending_otp: null }),
  'save.query': () => ({ mode: 'save', host: 'github.com', username: 'octo', title: null, token: 'tok-1', editable: true,
    check: { score: 0, label: 'very_weak', vault_checked: true, issues: [
      { code: 'common', severity: 'high' }, { code: 'reused', severity: 'high', count: 3 },
      { code: 'contains_site', severity: 'medium' }, { code: 'from_the_future', severity: 'low' }] } }),
  'save.check': () => ({ score: 1, label: 'weak', vault_checked: true, issues: [{ code: 'short', severity: 'medium', min_length: 12 }] }),
};

// What the page itself sees: its own capture-phase listeners on window.
const pageSaw = [];
for (const type of ['keydown', 'keyup', 'keypress', 'beforeinput', 'input', 'compositionupdate', 'compositionend']) {
  w.addEventListener(type, (e) => pageSaw.push([type, e.key ?? e.data ?? '']), true);
}
const pageMessages = [];
w.addEventListener('message', (e) => pageMessages.push(e.data), true);

let main;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `${ORIGIN}/${p}`,
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return { ok: true, result: fn ? fn(msg) : {} };
      },
      onMessage: { addListener: () => {} },
    },
    storage: { local: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  globalThis.__passBridge = { alive: () => true, hasConditional: () => false, onConditionalChange: () => () => {}, completeConditional: async () => ({ ok: true }) };
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (fn, ms = 2000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = fn(); if (v) return v; await tick(20); }
  return fn();
};
const texts = (root) => [...root.querySelectorAll('.issues li')].map((li) => li.textContent);
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, button: 0 }));
const bannerRoot = () => shadowRoots.get(doc.querySelector('pass-banner'));

/** A message on the page's window, as the edit frame (or someone else) would post it. */
function post(data, { source, origin = ORIGIN } = {}) {
  w.dispatchEvent(new w.MessageEvent('message', { data, origin, source }));
}

test('the banner lists the problems of the captured password, short and plain, inside its closed shadow root', async () => {
  const host = await waitFor(() => doc.querySelector('pass-banner'));
  assert.ok(host, 'banner shown');
  const root = shadowRoots.get(host);
  const list = root.querySelector('.issues');
  assert.equal(list.hidden, false);
  assert.equal(list.getAttribute('aria-label'), 'Password check');
  assert.deepEqual(texts(root), [
    'This is one of the most common passwords.',
    'You use this password for 3 other logins.',
    "This password contains the site's name.",
  ], 'unknown codes are left out');
  assert.equal(root.querySelectorAll('.issues li.high').length, 2);
  assert.ok(![...root.querySelectorAll('button')].some((b) => /strong password/i.test(b.textContent)),
    'no "use a strong password" in the banner: the site already has this password');
  assert.equal(host.shadowRoot, null, 'closed shadow root');
  const page = doc.documentElement.outerHTML;
  assert.ok(!page.includes(PASSWORD) && !page.includes('common passwords'), 'not in the light DOM');
});

test('Edit: the extension\'s frame does the editing; the token goes to the extension\'s origin only; nothing typed reaches the page', async () => {
  const root = bannerRoot();
  assert.equal(root.querySelector('iframe'), null, 'no frame until Edit is opened');
  const edit = root.querySelector('button.edit');
  await click(edit);
  const frame = root.querySelector('iframe.edit-frame');
  assert.ok(frame, 'the edit frame');
  assert.equal(frame.getAttribute('src'), `${ORIGIN}/src/save/edit.html`, 'no token or value in its URL');
  assert.equal(frame.title, 'Passyble username and password');
  assert.equal(edit.getAttribute('aria-expanded'), 'true');
  assert.equal(root.querySelector('.issues').hidden, true, 'the frame shows the check of what is typed there');
  // No field for a secret in the page or in the banner: a page's key / input listeners have nothing to hear.
  for (const r of [doc, ...shadowRoots.values()]) {
    assert.equal(r.querySelectorAll('input, textarea, [contenteditable]').length, 0, 'no input of ours');
  }
  const toFrame = [];
  // jsdom gives a frame in a shadow root no window: a stand-in window for the extension page.
  const source = frame.contentWindow || new JSDOM('<!doctype html>').window;
  if (!frame.contentWindow) Object.defineProperty(frame, 'contentWindow', { configurable: true, value: source });
  source.postMessage = (data, targetOrigin) => toFrame.push([data, targetOrigin]);

  // Someone else's "ready" (the page, another origin) gets nothing.
  post({ passybleSave: 'ready', height: 90 }, { source: w, origin: ORIGIN });
  post({ passybleSave: 'ready', height: 90 }, { source, origin: 'https://github.com' });
  assert.deepEqual(toFrame, []);
  post({ passybleSave: 'ready', height: 90 }, { source });
  assert.deepEqual(toFrame, [[{ passybleSave: 'init', token: 'tok-1' }, ORIGIN]], 'the token, to the extension\'s origin only');
  assert.equal(frame.style.height, '90px');
  post({ passybleSave: 'loaded', height: 120 }, { source });
  assert.equal(frame.style.height, '120px');
  assert.deepEqual(toFrame.at(-1), [{ passybleSave: 'focus' }, ORIGIN], 'the fields take the focus');
  await tick(3100);
  assert.ok(root.querySelector('iframe.edit-frame'), 'loaded in time: stays');

  // Folded away: the banner's own list again, for what Save would save now (after the frame stored it).
  const checks = () => sent.filter((m) => m.type === 'save.check');
  await click(edit);
  assert.equal(edit.getAttribute('aria-expanded'), 'false');
  const flush = toFrame.at(-1);
  assert.equal(flush[0].passybleSave, 'flush');
  assert.equal(flush[1], ORIGIN);
  await tick(50);
  assert.equal(checks().length, 0, 'not before the frame stored its values');
  post({ passybleSave: 'flushed', seq: flush[0].seq, ok: true }, { source });
  await waitFor(() => checks().length === 1);
  assert.deepEqual(checks()[0], { type: 'save.check', token: 'tok-1' }, 'the token only, no values');
  await waitFor(() => texts(root)[0] === 'Short: use at least 12 characters.');
  assert.equal(root.querySelector('.issues').hidden, false);

  assert.deepEqual(pageSaw, [], 'the page heard no key and no input');
  assert.ok(!JSON.stringify(pageMessages).includes(PASSWORD));
  assert.ok(!JSON.stringify(sent).includes(PASSWORD), 'no password through the content script at all');
});

test('Edit on a page that blocks extension frames: the Edit section goes away, Save still works', async () => {
  doc.querySelectorAll('pass-banner').forEach((n) => n.remove());
  responses['save.query'] = () => ({ mode: 'save', host: 'github.com', username: 'octo', title: null, token: 'tok-2', editable: true, check: null });
  responses['save.commit'] = () => ({ id: 'n1', action: 'save_new' });
  history.pushState({}, '', '/next');
  const host = await waitFor(() => doc.querySelector('pass-banner'));
  const root = shadowRoots.get(host);
  const edit = root.querySelector('button.edit');
  await click(edit);
  assert.ok(root.querySelector('iframe.edit-frame'));
  await tick(3100); // no "loaded" from the frame
  assert.equal(root.querySelector('iframe'), null, 'the frame is gone');
  assert.equal(edit.hidden, true, 'no Edit');
  assert.equal(root.querySelector('.fields').hidden, true);
  assert.equal(root.querySelectorAll('input').length, 0, 'never in-page inputs instead');
  await click(root.querySelector('.btn.primary'));
  await waitFor(() => sent.some((m) => m.type === 'save.commit'));
  assert.deepEqual(sent.find((m) => m.type === 'save.commit'), { type: 'save.commit', token: 'tok-2' });
  await waitFor(() => /Saved to Passyble/.test(root.querySelector('.status').textContent));
  assert.match(root.querySelector('.status').textContent, /Saved to Passyble/);
});
