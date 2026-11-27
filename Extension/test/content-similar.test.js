// A site without logins (src/content/main.js, menu.js, banner.js in jsdom): the menu offers "Similar sites" with
// nothing preselected, and the "Use this login on <site> too?" card acts on its one-time token only.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://www.amazon.co.uk/ap/signin', pretendToBeVisual: true });
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
let runtimeListener = null;
const ok = (result) => ({ ok: true, result });
const fail = (code) => ({ ok: false, error: { code, message: code } });
const SIMILAR = {
  items: [
    { id: 'de', title: 'Amazon DE', username: 'ann', domain: 'amazon.de', has_totp: false, vault_id: null },
    { id: 'us', title: 'Amazon US', username: 'ann', domain: 'amazon.com', has_totp: true, vault_id: null },
  ],
  vaults: [], search: true, name: 'amazon', locked: false,
};
const CARD = { token: 'card-token', host: 'amazon.co.uk', site: 'amazon.com', title: 'Amazon US', username: 'ann',
  lookalike: '', can_add: true, can_copy: true };
const defaults = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ok({ items: [], pending_otp: null, locked: false }),
  'menu.similar': () => ok(SIMILAR),
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
      onMessage: { addListener: (f) => { runtimeListener = f; } },
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
const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));
const ofType = (type) => sent.filter((m) => m.type === type);

function command(msg) {
  return new Promise((resolve) => {
    const async = runtimeListener(msg, { id: 'pass-ext' }, resolve);
    if (!async) resolve(undefined);
  });
}

function reset(html) {
  doc.querySelectorAll('pass-menu, pass-banner, pass-notice').forEach((n) => n.remove());
  doc.body.innerHTML = html;
  sent.length = 0;
  responses = { ...defaults };
}

const SIGNIN = '<form><input type="email" name="user" autocomplete="username"><input type="password" name="pw" autocomplete="current-password"><button>Sign in</button></form>';

/**
 * Focus the username field as the user does, then click the Passyble icon in it (unless the
 * suggestions opened on their own: a site with logins).
 */
async function openFromIcon() {
  const field = doc.querySelector('[name=user]');
  await dispatchTrusted(field, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  field.focus();
  await tick(60);
  if (!doc.querySelector('pass-menu')) await click(rootOf('pass-icon').querySelector('.icon'));
  await tick(40);
  return field;
}

test('a site without logins: "No logins for <site>", up to 3 similar sites and "Search Passyble…", nothing preselected', async () => {
  reset(SIGNIN);
  await tick(300);
  const field = await openFromIcon();
  const menu = rootOf('pass-menu');
  assert.ok(menu, 'the menu opened');
  assert.equal(menu.querySelector('.msg').textContent, t('commonNoLoginsFor', 'amazon.co.uk'));
  assert.equal(menu.querySelector('.section').textContent, t('menuSimilarSites'));
  const rows = [...menu.querySelectorAll('.item')];
  assert.deepEqual(rows.map((r) => r.querySelector('.title').firstChild.textContent), ['Amazon DE', 'Amazon US', t('menuSearchPassyble')]);
  assert.equal(rows[1].querySelector('.sub').textContent, 'ann · amazon.com');
  assert.equal(menu.querySelectorAll('.item.active').length, 0, 'nothing preselected');
  // The background asks the agent for this frame (its URL from the browser): the message names no page.
  assert.deepEqual(ofType('menu.similar'), [{ type: 'menu.similar' }]);
  // Enter alone picks nothing: no other site's login goes in without a choice.
  await key(field, 'Enter');
  await tick(20);
  assert.equal(ofType('logins.fill_cross').length, 0);
});

test('picking a similar site is a cross fill (the desktop app asks); Cancel there leaves the form alone', async () => {
  reset(SIGNIN);
  await tick(300);
  responses['logins.fill_cross'] = () => ok({ username: 'ann', password: 'amz-pw', totp: null, cross: true });
  await openFromIcon();
  await tick(VISIBLE);
  await click(rootOf('pass-menu').querySelectorAll('.item')[1]);
  await tick(40);
  assert.deepEqual(ofType('logins.fill_cross'), [{ type: 'logins.fill_cross', id: 'us', similar: true }]);
  assert.equal(doc.querySelector('[name=user]').value, 'ann');
  assert.equal(doc.querySelector('[name=pw]').value, 'amz-pw');
  assert.equal(ofType('fill.done').length, 0, 'another site\'s login: no 2FA chain for this page');

  reset(SIGNIN);
  await tick(300);
  responses['logins.fill_cross'] = () => fail('cancelled');
  await openFromIcon();
  await tick(VISIBLE);
  await click(rootOf('pass-menu').querySelectorAll('.item')[0]);
  await tick(40);
  assert.equal(doc.querySelector('[name=pw]').value, '');
  assert.equal(doc.querySelector('pass-notice'), null, 'declined: nothing to say');
});

test('"Search Passyble…" opens the popup; where it can\'t, a notice says to use the toolbar button', async () => {
  reset(SIGNIN);
  await tick(300);
  responses['menu.search'] = () => ok({ opened: false });
  await openFromIcon();
  await tick(VISIBLE);
  const rows = rootOf('pass-menu').querySelectorAll('.item');
  await click(rows[rows.length - 1]);
  await tick(40);
  assert.deepEqual(ofType('menu.search'), [{ type: 'menu.search' }]);
  assert.equal(doc.querySelector('pass-menu'), null, 'the menu closed');
  assert.match(rootOf('pass-notice')?.textContent || '', new RegExp(t('menuSearchUseToolbar').slice(0, 20)));
});

test('a site with logins lists them as before, without similar sites', async () => {
  reset(SIGNIN);
  await tick(300);
  responses['logins.find'] = () => ok({ items: [{ id: 'own', title: 'Amazon UK', username: 'ann', has_totp: false, has_passkey: false }], pending_otp: null, locked: false });
  await openFromIcon();
  const menu = rootOf('pass-menu');
  assert.deepEqual([...menu.querySelectorAll('.item .title')].map((el) => el.firstChild.textContent), ['Amazon UK']);
  assert.equal(menu.querySelector('.section'), null);
  assert.equal(ofType('menu.similar').length, 0);
});

test('after a cross fill: the card offers Add, Copy and Not now, and sends its token only', async () => {
  reset(SIGNIN);
  responses['cross.query'] = () => ok(CARD);
  responses['cross.add'] = () => ok({ added: true, title: 'Amazon US' });
  await command({ type: 'cross.offer' });
  await tick(60);
  const card = rootOf('pass-banner');
  assert.ok(card, 'the card shows');
  assert.equal(card.querySelector('.title').textContent, t('crossTitle', 'amazon.co.uk'));
  assert.equal(card.querySelector('.who').textContent, `ann · ${t('crossSavedFor', 'amazon.com')}`);
  const buttons = [...card.querySelectorAll('.cross-actions .btn')];
  assert.deepEqual(buttons.map((b) => b.textContent), [t('crossAdd', 'amazon.co.uk'), t('crossCopy', 'amazon.co.uk'), t('bannerNotNow')]);
  assert.ok(buttons[0].classList.contains('primary'));
  assert.equal(card.querySelector('.hint').textContent, t('crossHint'));
  assert.equal(card.querySelector('.lookalike'), null);
  // A click the user can't have seen (too soon) does nothing.
  await click(buttons[0]);
  await tick(20);
  assert.equal(ofType('cross.add').length, 0);
  await tick(VISIBLE);
  await click(buttons[0]);
  await tick(40);
  assert.deepEqual(ofType('cross.add'), [{ type: 'cross.add', token: 'card-token' }]);
  assert.equal(card.querySelector('.status').textContent, t('crossAdded', 'amazon.co.uk', 'Amazon US'));
  assert.ok(!JSON.stringify(sent).includes('amz-pw'), 'no password passes through the page\'s frame');
});

test('the card on a lookalike repeats the warning, with no main action; "Not now" tells the background', async () => {
  reset(SIGNIN);
  responses['cross.query'] = () => ok({ ...CARD, host: 'paypa1.example', site: 'paypal.com', lookalike: 'paypal.com' });
  await command({ type: 'cross.offer' });
  await tick(60);
  const card = rootOf('pass-banner');
  assert.equal(card.querySelector('.lookalike').textContent, t('crossLookalike', 'paypa1.example', 'paypal.com'));
  assert.equal(card.querySelector('.lookalike').getAttribute('role'), 'alert');
  assert.equal(card.querySelectorAll('.cross-actions .btn.primary').length, 0);
  await tick(VISIBLE);
  await click([...card.querySelectorAll('.cross-actions .btn')].at(-1));
  await tick(20);
  assert.deepEqual(ofType('cross.dismiss'), [{ type: 'cross.dismiss', token: 'card-token' }]);
  assert.equal(doc.querySelector('pass-banner'), null);
});

test('the card comes instead of the save banner after the submit; an older desktop app offers the copy only', async () => {
  reset(SIGNIN);
  responses['save.query'] = () => ok({ cross: { ...CARD, can_add: false } });
  responses['cross.copy'] = () => ok({ id: 'copy-1', unchanged: false });
  await command({ type: 'save.recheck' });
  await tick(60);
  const card = rootOf('pass-banner');
  const buttons = [...card.querySelectorAll('.cross-actions .btn')];
  assert.deepEqual(buttons.map((b) => b.textContent), [t('crossCopy', 'amazon.co.uk'), t('bannerNotNow')]);
  assert.equal(card.querySelector('.hint'), null);
  await tick(VISIBLE);
  await click(buttons[0]);
  await tick(40);
  assert.deepEqual(ofType('cross.copy'), [{ type: 'cross.copy', token: 'card-token' }]);
  assert.equal(card.querySelector('.status').textContent, t('crossCopied'));
});
