// "Update this login?" in the page (src/content/main.js, banner.js in jsdom): the card names what changed, never a
// password, and its buttons send the card's one-time token only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://github.com/login', pretendToBeVisual: true });
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

const sent = [];
const ok = (result) => ({ ok: true, result });
const fail = (code) => ({ ok: false, error: { code, message: code } });
const CARD = { token: 'card-token', host: 'github.com', title: 'GitHub', username: 'alice', new_username: 'bob@example.com',
  password_changed: false, cross: false, site: '', lookalike: '', can_update: true, can_copy: true, read_only: false };
const defaults = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ok({ items: [], pending_otp: null, locked: false }),
  'save.query': () => ok(null),
  'cross.query': () => ok(null),
};
let responses = { ...defaults };

let main;
let t;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : ok({});
      },
      onMessage: { addListener: () => {} },
    },
    storage: { local: { get: async () => ({}) }, sync: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  main = await import('../src/content/main.js');
  ({ t } = await import('../src/shared/i18n.js'));
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const VISIBLE = 520; // clicks count once the UI was visible for 500 ms (ui-common.js)
const rootOf = (tag) => {
  const host = doc.querySelector(tag);
  return host ? shadowRoots.get(host) : null;
};
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true, button: 0 }));
const ofType = (type) => sent.filter((m) => m.type === type);
let page = 0;

/** The next page of the site (an SPA navigation: the top frame asks `save.query`) answers `card`. */
async function cardAfterSubmit(card, extra = {}) {
  doc.querySelectorAll('pass-banner, pass-notice').forEach((n) => n.remove());
  sent.length = 0;
  responses = { ...defaults, 'save.query': () => ok({ changed: card }), ...extra };
  doc.body.innerHTML = `<p>Welcome ${++page}</p>`; // the scan after a change notices the navigation
  w.history.pushState({}, '', `/dashboard/${page}`);
  await tick(400);
  const root = rootOf('pass-banner');
  assert.ok(root, 'the card shows');
  return root;
}

const buttons = (root) => [...root.querySelectorAll('.cross-actions .btn')];

test('a new username: "Update this login?" names the login and the change; Update sends the token only', async () => {
  const root = await cardAfterSubmit(CARD, { 'changed.update': () => ok({ updated: true, title: 'GitHub' }) });
  assert.equal(root.querySelector('.title').textContent, t('changedTitle'));
  assert.equal(root.querySelector('.sub').textContent, 'github.com');
  assert.equal(root.querySelector('.who').textContent, 'GitHub · alice');
  assert.deepEqual([...root.querySelectorAll('.changes li')].map((li) => li.textContent), [t('changedUsername', 'bob@example.com')]);
  assert.deepEqual(buttons(root).map((b) => b.textContent), [t('changedUpdate'), t('changedSaveNew'), t('bannerNotNow')]);
  assert.ok(buttons(root)[0].classList.contains('primary'));
  assert.equal(root.querySelector('.note'), null);
  // Too soon to have been seen: nothing.
  await click(buttons(root)[0]);
  await tick(20);
  assert.equal(ofType('changed.update').length, 0);
  await tick(VISIBLE);
  await click(buttons(root)[0]);
  await tick(40);
  assert.deepEqual(ofType('changed.update'), [{ type: 'changed.update', token: 'card-token' }]);
  assert.equal(root.querySelector('.status').textContent, t('changedUpdated'));
});

test('both changed: two lines, never the password; Save as new login', async () => {
  const root = await cardAfterSubmit({ ...CARD, new_username: 'bob', password_changed: true },
    { 'changed.save': () => ok({ id: 'n1', unchanged: false }) });
  assert.deepEqual([...root.querySelectorAll('.changes li')].map((li) => li.textContent),
    [t('changedUsername', 'bob'), t('changedPassword')]);
  await tick(VISIBLE);
  await click(buttons(root)[1]);
  await tick(40);
  assert.deepEqual(ofType('changed.save'), [{ type: 'changed.save', token: 'card-token' }]);
  assert.equal(root.querySelector('.status').textContent, t('changedSavedNew'));
});

test('a read-only vault: no Update, Save as new login is the main action, and the card says why', async () => {
  const root = await cardAfterSubmit({ ...CARD, can_update: false, read_only: true });
  assert.deepEqual(buttons(root).map((b) => b.textContent), [t('changedSaveNew'), t('bannerNotNow')]);
  assert.ok(buttons(root)[0].classList.contains('primary'));
  assert.equal(root.querySelector('.note').textContent, t('changedReadOnly'));
});

test('a cross fill: where the login came from, and on a lookalike the warning with no main action; Not now', async () => {
  const root = await cardAfterSubmit({ ...CARD, host: 'paypa1.example', title: 'PayPal', username: 'p', cross: true,
    site: 'paypal.com', lookalike: 'paypal.com' });
  assert.equal(root.querySelector('.note').textContent, t('changedFromSite', 'paypal.com', 'paypa1.example'));
  assert.equal(root.querySelector('.lookalike').textContent, t('changedLookalike', 'paypa1.example', 'paypal.com'));
  assert.equal(root.querySelector('.lookalike').getAttribute('role'), 'alert');
  assert.equal(root.querySelectorAll('.cross-actions .btn.primary').length, 0);
  await tick(VISIBLE);
  await click(buttons(root).at(-1));
  await tick(20);
  assert.deepEqual(ofType('changed.dismiss'), [{ type: 'changed.dismiss', token: 'card-token' }]);
  assert.equal(doc.querySelector('pass-banner'), null);
});

test('a failed update says so on the card', async () => {
  const root = await cardAfterSubmit(CARD, { 'changed.update': () => fail('read_only') });
  await tick(VISIBLE);
  await click(buttons(root)[0]);
  await tick(40);
  assert.match(root.querySelector('.status').textContent, new RegExp(t('bannerSaveFailed', 'x').split('x')[0].slice(0, 10)));
});
