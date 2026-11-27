import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
let closed = false;

const PNG = 'data:image/png;base64,iVBORw0KGgo=';
const HERE = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false }];
const RESULTS = [
  { id: 'gh', title: 'GitHub', username: 'octo', domain: 'github.com', has_totp: false },
  { id: 'gl', title: 'GitLab', username: 'me@x.test', domain: 'gitlab.com', has_totp: true },
  { id: 'gt', title: 'Gitea', username: 'admin', domain: 'gitea.example', has_totp: false },
];

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = dom.window;
  dom.window.close = () => { closed = true; };
  closed = false;
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));
const wait = (ms) => new Promise((r) => setTimeout(r, ms));

function type($, text) {
  $('search').value = text;
  $('search').dispatchEvent(new globalThis.Event('input'));
}

function state(extra = {}) {
  return { ok: true, result: { url: 'https://github.com/login', supported: true, locked: false, items: HERE, pending_otp: null,
    can_edit: true, can_icons: true, can_search: true, ...extra } };
}

const searchReply = (extra = {}) => (msg) => {
  if (msg.type === 'popup.state') return state(extra);
  if (msg.type === 'popup.search') return { ok: true, result: { items: RESULTS, truncated: false } };
  if (msg.type === 'popup.icons') return { ok: true, result: { icons: { 'gitlab.com': PNG }, items: { gl: 'gitlab.com' } } };
  if (msg.type === 'popup.copy-item') return { ok: true, result: { copied: true, field: msg.field } };
  if (msg.type === 'popup.fill-cross') return { ok: true, result: { ok: true } };
  if (msg.type === 'popup.show-item') return { ok: true, result: { shown: true } };
  return { ok: true, result: null };
};

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }] },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('typing searches the whole vault (debounced, 2+ characters); this site\'s logins are not repeated', async () => {
  reply = searchReply();
  const { $ } = await openPopup();
  assert.equal($('search').placeholder, 'Search');
  type($, 'g');
  await wait(320);
  assert.ok(!messages.some((m) => m.type === 'popup.search'), 'one character: no search');
  type($, 'gi');
  type($, 'git');
  await wait(320);
  const searches = messages.filter((m) => m.type === 'popup.search');
  // With the tab, so the background can say which results this page looks like (`lookalike`).
  assert.deepEqual(searches, [{ type: 'popup.search', query: 'git', tabId: 1 }], 'debounced to the last query');
  await flush();
  assert.equal($('results').hidden, false);
  const cards = [...$('result-list').children];
  assert.deepEqual(cards.map((c) => c.dataset.id), ['gl', 'gt'], 'GitHub is in the site list already');
  assert.match(cards[0].textContent, /gitlab\.com/);
  assert.match(cards[0].textContent, /2FA/);
  // Icons for the results, by their ids (the agent only answers for its own search results).
  assert.deepEqual(messages.find((m) => m.type === 'popup.icons' && m.ids), { type: 'popup.icons', ids: ['gl', 'gt'] });
  assert.equal(cards[0].querySelector('.avatar img').getAttribute('src'), PNG);
  assert.equal(cards[1].querySelector('.avatar').textContent, 'G');
  type($, 'g');
  await wait(10);
  assert.equal($('results').hidden, true);
});

test('a result whose site this page imitates: a red tag, and its copy and fill carry the warning', async () => {
  const lookalike = { domain: 'gitlab.com', host: 'gitlab.example', reason: 'name_in_domain' };
  const base = searchReply();
  reply = (msg) => (msg.type === 'popup.search'
    ? { ok: true, result: { items: RESULTS.map((i) => (i.id === 'gl' ? { ...i, lookalike } : i)), truncated: false } }
    : base(msg));
  const { $ } = await openPopup();
  type($, 'git');
  await wait(320);
  await flush();
  const gl = $('result-list').querySelector('[data-id="gl"]');
  const gt = $('result-list').querySelector('[data-id="gt"]');
  const tag = gl.querySelector('.tag.danger');
  assert.equal(tag?.textContent, 'Lookalike site');
  assert.equal(tag.title, 'github.com looks like gitlab.com but is a different site.');
  assert.ok(gl.classList.contains('lookalike'));
  assert.equal(gt.querySelector('.tag.danger'), null, 'other results: no tag');
  [...gl.querySelectorAll('.icon-btn')].find((b) => b.title === 'Copy password').click();
  await flush();
  assert.deepEqual(messages.filter((m) => m.type === 'popup.copy-item').at(-1),
    { type: 'popup.copy-item', tabId: 1, id: 'gl', field: 'password', lookalike: 'gitlab.com', title: 'GitLab' });
  [...gt.querySelectorAll('.icon-btn')].find((b) => b.title === 'Copy password').click();
  await flush();
  assert.equal(messages.filter((m) => m.type === 'popup.copy-item').at(-1).lookalike, undefined);
  // A cancelled warning (the background's ask) is no error.
  reply = (msg) => (msg.type === 'popup.copy-item' ? { ok: false, error: { code: 'cancelled', message: 'Cancelled' } } : base(msg));
  $('snack').textContent = '';
  [...gl.querySelectorAll('.icon-btn')].find((b) => b.title === 'Copy password').click();
  await flush();
  await flush();
  assert.equal($('snack').textContent, '');
});

test('the lookalike question: plain words in red, Cancel focused; a cross fill without one keeps its usual text', async () => {
  const ask = (extra) => (msg) => (msg.type === 'popup.state' ? state({ ask: { token: 't1', host: 'github.com', ...extra } }) : searchReply()(msg));
  reply = ask({ kind: 'lookalike', lookalike: 'gitlab.com', title: 'GitLab' });
  let { $, window } = await openPopup();
  assert.equal($('view-ask').hidden, false);
  assert.equal($('ask-title').textContent, 'This may be a fake site');
  assert.match($('ask-text').textContent, /^github\.com is not gitlab\.com, but its address looks like it\./);
  assert.match($('ask-text').textContent, /Copy your login only if/);
  assert.ok($('ask-text').classList.contains('danger'));
  assert.equal($('ask-submit-label').textContent, 'Copy anyway');
  assert.equal(window.document.activeElement, $('ask-cancel'));
  reply = ask({ kind: 'cross', lookalike: 'gitlab.com', title: 'GitLab' });
  ({ $ } = await openPopup());
  assert.match($('ask-text').textContent, /Fill your login only if/);
  assert.equal($('ask-submit-label').textContent, 'Fill anyway');
  reply = ask({ kind: 'cross', title: 'GitLab' });
  ({ $ } = await openPopup());
  assert.equal($('ask-title').textContent, 'Fill a login of another site?');
  assert.ok(!$('ask-text').classList.contains('danger'));
});

test('a calm note for an international (xn--) address, none for a plain one', async () => {
  reply = searchReply();
  let { $ } = await openPopup();
  assert.equal($('host-note').hidden, true);
  reply = (msg) => (msg.type === 'popup.state' ? state({ url: 'https://www.xn--bcher-kva.example/login' }) : searchReply()(msg));
  ({ $ } = await openPopup());
  assert.equal($('host-note').hidden, false);
  assert.equal($('host-note').textContent, 'International address: www.xn--bcher-kva.example');
});

test('another site\'s login: copies are made by the desktop app, never in the popup', async () => {
  reply = searchReply();
  const { $, window } = await openPopup();
  type($, 'gitlab');
  await wait(320);
  await flush();
  const card = $('result-list').querySelector('[data-id="gl"]');
  const button = (label) => [...card.querySelectorAll('.icon-btn')].find((b) => b.title === label);
  const menuItem = (label) => { button('More').click(); return [...document.querySelectorAll('.popover .menu-item')].find((b) => b.textContent === label); };
  assert.ok(menuItem('Copy 2FA code'), 'has 2FA: copy code offered in the ⋯ menu');
  document.querySelector('.popover .menu-item').ownerDocument.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape' }));
  assert.equal(document.querySelector('.popover'), null, 'Esc closes the menu');
  button('Copy password').click();
  await flush();
  assert.deepEqual(messages.find((m) => m.type === 'popup.copy-item'), { type: 'popup.copy-item', tabId: 1, id: 'gl', field: 'password' });
  assert.match($('snack').textContent, /copied by Passyble/);
  menuItem('Copy 2FA code').click();
  await flush();
  assert.equal(messages.filter((m) => m.type === 'popup.copy-item').at(-1).field, 'totp');
  assert.ok(!messages.some((m) => m.type === 'popup.copy' || m.type === 'clipboard.copied'), 'no secret through the popup');
  button('More').click();
  const gtMore = $('result-list').querySelector('[data-id="gt"] button[title="More"]');
  gtMore.click();
  assert.deepEqual([...document.querySelectorAll('.popover .menu-item')].map((b) => b.textContent), ['Open in Passyble'], 'no 2FA: no code item');
  gtMore.click();
});

test('"Fill on this page" asks the desktop app; "Open in Passyble" shows the login there', async () => {
  reply = searchReply();
  const { $ } = await openPopup();
  type($, 'gitea');
  await wait(320);
  await flush();
  const card = $('result-list').querySelector('[data-id="gt"]');
  card.querySelector('button[title="More"]').click();
  [...document.querySelectorAll('.popover .menu-item')].find((b) => b.textContent === 'Open in Passyble').click();
  await flush();
  assert.deepEqual(messages.find((m) => m.type === 'popup.show-item'), { type: 'popup.show-item', tabId: 1, id: 'gt' });
  const main = card.querySelector('button.item-main');
  assert.match(main.title, /Fill on this page/, 'a click on the row fills');
  main.click();
  await flush();
  assert.deepEqual(messages.find((m) => m.type === 'popup.fill-cross'), { type: 'popup.fill-cross', tabId: 1, id: 'gt' });
  await flush();
  assert.equal(closed, true);
});

test('keyboard: arrows move over this site\'s logins and the results; Enter runs the first action', async () => {
  reply = searchReply();
  const { $, window } = await openPopup();
  type($, 'git');
  await wait(320);
  await flush();
  const key = (k) => $('search').dispatchEvent(new window.KeyboardEvent('keydown', { key: k, bubbles: true, cancelable: true }));
  key('ArrowDown');
  key('ArrowDown');
  const active = [...document.querySelectorAll('.item.active')];
  assert.equal(active.length, 1);
  assert.equal(active[0].dataset.id, 'gl');
  key('ArrowUp');
  key('ArrowUp');
  assert.equal(document.querySelector('.item.active').dataset.id, 'gt', 'wraps around');
  key('Enter');
  await flush();
  assert.deepEqual(messages.find((m) => m.type === 'popup.fill-cross'), { type: 'popup.fill-cross', tabId: 1, id: 'gt' });
});

test('an older desktop app: no vault search, the site lookup stays; not_supported says to update', async () => {
  reply = searchReply({ can_search: false });
  let { $ } = await openPopup();
  type($, 'gitlab.com');
  await wait(320);
  assert.ok(!messages.some((m) => m.type === 'popup.search'));
  assert.equal($('lookup').hidden, false, 'look up by site, as before');

  reply = (msg) => (msg.type === 'popup.search'
    ? { ok: false, error: { code: 'not_supported', message: 'old' } } : searchReply()(msg));
  ({ $ } = await openPopup());
  assert.equal($('lookup').hidden, true);
  type($, 'gitlab');
  await wait(320);
  await flush();
  assert.match($('results-msg').textContent, /Update the Passyble desktop app/);
});

test('no login for this site: "No logins for <site>", its similar sites above the focused search; a pick asks the desktop app', async () => {
  const similar = { items: [{ id: 'us', title: 'Amazon US', username: 'ann', domain: 'amazon.com', has_totp: true }], vaults: [] };
  reply = (msg) => (msg.type === 'popup.state'
    ? state({ url: 'https://www.amazon.co.uk/ap/signin', items: [], similar }) : searchReply()(msg));
  const { $, window } = await openPopup();
  assert.equal($('empty').textContent, 'No logins for amazon.co.uk');
  assert.equal($('similar').hidden, false);
  const rows = [...$('similar-list').children];
  assert.deepEqual(rows.map((r) => r.dataset.id), ['us']);
  assert.match(rows[0].textContent, /ann · amazon\.com/);
  assert.equal(window.document.activeElement, $('search'), 'the search field has the focus');
  assert.deepEqual(messages.find((m) => m.type === 'popup.icons' && m.ids), { type: 'popup.icons', ids: ['us'] });
  rows[0].querySelector('.item-main').click();
  await flush();
  assert.deepEqual(messages.find((m) => m.type === 'popup.fill-cross'), { type: 'popup.fill-cross', tabId: 1, id: 'us' });
  // Typing: the vault search takes over.
  type($, 'amaz');
  await wait(10);
  assert.equal($('similar').hidden, true);
  type($, '');
});

test('"Search Passyble…" in the page\'s menu: the popup opens with that search', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? state({ url: 'https://www.amazon.co.uk/', items: [], search: 'amazon' }) : searchReply()(msg));
  const { $ } = await openPopup();
  assert.equal($('search').value, 'amazon');
  await wait(320);
  assert.deepEqual(messages.filter((m) => m.type === 'popup.search'), [{ type: 'popup.search', query: 'amazon', tabId: 1 }]);
  assert.equal($('similar').hidden, true);
});
