import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const flush = () => new Promise((r) => setTimeout(r, 0));
const sent = (type) => messages.filter((m) => m.type === type);
const ok = (result) => ({ ok: true, result });
const fail = (code, message = code) => ({ ok: false, error: { code, message } });

const ITEMS = [
  { id: 'a', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: true },
  { id: 'b', title: 'Work', username: 'me', has_totp: false, has_passkey: true },
  { id: 'c', title: 'Plain', username: 'plain', has_totp: true, has_passkey: false },
  { id: 'd', title: 'Nothing', username: 'none', has_totp: false },
];
const UNLOCKED = { url: 'https://github.com/login', supported: true, locked: false, items: ITEMS, pending_otp: null,
  can_edit: true, can_search: true, can_unlock_inline: true };

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

const tagsOf = (li) => [...li.querySelectorAll('.tags .tag')].map((t) => t.title || t.textContent);

test('Lock: sends popup.lock, then loads the state again and shows the locked view', async () => {
  let locked = false;
  reply = (msg) => {
    if (msg.type === 'popup.state') return ok(locked ? { url: UNLOCKED.url, supported: true, locked: true, can_unlock_inline: true } : UNLOCKED);
    if (msg.type === 'popup.lock') { locked = true; return ok({ locked: true }); }
    return ok(null);
  };
  const { $ } = await openPopup();
  assert.equal($('lock-btn').hidden, false, 'offered while unlocked');
  assert.equal($('lock-btn').getAttribute('aria-label'), 'Lock Passyble');
  assert.ok($('lock-btn').querySelector('svg[data-icon="lockOpen"]'), 'unlocked: an open lock from the vendored set (no status dot)');
  const loads = sent('popup.state').length;
  $('lock-btn').click();
  await flush();
  await flush();
  assert.equal(sent('popup.lock').length, 1);
  assert.deepEqual(sent('popup.lock')[0], { type: 'popup.lock' }, 'no payload');
  assert.equal(sent('popup.state').length, loads + 1, 'state refreshed');
  assert.equal($('view-locked').hidden, false);
  assert.equal($('lock-btn').hidden, true, 'nothing to lock any more');
});

test('Lock while Passyble is not running: the "Passyble isn\'t running" view', async () => {
  let down = false;
  reply = (msg) => {
    if (msg.type === 'popup.state') return down ? fail('agent_unavailable', 'The Passyble desktop app is not running') : ok(UNLOCKED);
    if (msg.type === 'popup.lock') { down = true; return fail('agent_unavailable', 'The Passyble desktop app is not running'); }
    return ok(null);
  };
  const { $ } = await openPopup();
  $('lock-btn').click();
  await flush();
  assert.equal($('view-offline').hidden, false);
  assert.equal($('offline-title').textContent, "Passyble isn't running");
  assert.equal($('start').hidden, false);
  assert.equal($('lock-btn').hidden, true);
});

test('Lock with another error: a message, the list stays and the button works again', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.state') return ok(UNLOCKED);
    if (msg.type === 'popup.lock') return fail('not_supported', 'unknown method');
    return ok(null);
  };
  const { $ } = await openPopup();
  $('lock-btn').click();
  await flush();
  assert.match($('snack').textContent, /This needs a newer Passyble app\. Update Passyble/);
  assert.equal($('view-list').hidden, false);
  assert.equal($('lock-btn').disabled, false);
});

test('soft-locked: the same lock button shows a closed lock that unlocks', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? ok({ ...UNLOCKED, locked: true, soft_locked: true }) : ok(null));
  const { $ } = await openPopup();
  assert.equal($('lock-btn').hidden, false);
  assert.equal($('lock-btn').title, 'Locked. Click to unlock');
  assert.equal($('lock-btn').getAttribute('aria-label'), 'Locked. Click to unlock');
  assert.ok($('lock-btn').querySelector('svg[data-icon="lock"]'), 'a closed lock');
  assert.equal($('status'), null, 'no separate state dot');
  $('lock-btn').click();
  await flush();
  assert.equal(sent('popup.lock').length, 0, 'a click unlocks, it does not lock again');
});

test('this site\'s rows tag "Passkey" from has_passkey, like the inline menu (2FA has its code pill there)', async () => {
  reply = (msg) => (msg.type === 'popup.state' ? ok(UNLOCKED) : ok(null));
  const { window } = await openPopup();
  const rows = [...window.document.querySelectorAll('#list > li')];
  assert.deepEqual(rows.map(tagsOf), [['Passkey'], ['Passkey'], [], []]);
  assert.equal(rows[0].querySelector('.title').firstChild.textContent, 'GitHub');
});

test('vault search results tag "2FA" and "Passkey" from the item fields', async () => {
  reply = (msg) => {
    if (msg.type === 'popup.state') return ok(UNLOCKED);
    if (msg.type === 'popup.search') {
      return ok({ items: [
        { id: 'x1', title: 'GitLab', username: 'me', domain: 'gitlab.com', has_totp: true, has_passkey: true },
        { id: 'x2', title: 'Bank', username: 'me', domain: 'bank.test', has_totp: false, has_passkey: true },
        { id: 'x3', title: 'Forum', username: 'me', domain: 'forum.test', has_totp: true, has_passkey: false },
        { id: 'x4', title: 'Blog', username: 'me', domain: 'blog.test', has_totp: false, has_passkey: false },
      ], truncated: false });
    }
    return ok(null);
  };
  const { window, $ } = await openPopup();
  $('search').value = 'zz';
  $('search').dispatchEvent(new window.Event('input', { bubbles: true }));
  await new Promise((r) => setTimeout(r, 400));
  const rows = [...window.document.querySelectorAll('#result-list > li')];
  assert.deepEqual(rows.map(tagsOf), [['2FA', 'Passkey'], ['Passkey'], ['2FA'], []]);
});
