// Pinned contact keys in the popup's "Shared with me" area, browser mode (real popup.html + popup.js in jsdom): an
// unverified signer shows its fingerprint, a changed signer is a loud warning listed first. Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const ok = (result) => ({ ok: true, result });

const HOME = { id: 'home', name: '', home: true, kind: 'personal', role: null, can_edit: true, can_reveal: true };
const STATE = { url: 'https://example.com/login', supported: true, locked: false, pending_otp: null, items: [],
  can_edit: true, can_notes: true, can_search: true, can_vaults: true, vaults: [HOME], browser: true, local_only: true };
const vault = (id, name, signer) => ({ id, name, home: false, kind: 'org', role: 'edit', can_edit: true, can_reveal: true,
  items: 0, open: true, error: null, signer });
const SIGNER = (status, fingerprint, extra = {}) => ({ status, account: 'acc-alice', fingerprint, ...extra });

function model({ vaults = [], confirm = [] } = {}) {
  return { vaults: [{ ...HOME, items: 0, open: true, error: null }, ...vaults],
    teams: { invites: 0, to_confirm: confirm.length, notices: 0 },
    browser: { status: 'ready', orgs: [], held: [], confirm, password_rule: null } };
}

function agent(teams, over = {}) {
  return (msg) => {
    if (over[msg.type]) return over[msg.type](msg);
    switch (msg.type) {
      case 'popup.state': return ok(STATE);
      case 'teams.model': return ok(teams);
      default: return ok(null);
    }
  };
}

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = { close: () => {} };
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  return (id) => dom.window.document.getElementById(id);
}

const flush = async (n = 12) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const sent = (type) => messages.filter((m) => m.type === type);

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, windowId: 7, url: 'https://example.com/login' }], create: async () => ({ id: 9 }) },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('signers: not verified yet with the fingerprint and It matches, changed first and loud, verified vaults show nothing', async () => {
  reply = agent(model({ vaults: [
    vault('v-new', 'Demo Team', SIGNER('not_pinned', 'AAAA-5555')),
    vault('v-ok', 'Demo Family', SIGNER('pinned', 'AAAA-5555')),
    vault('v-swapped', 'Demo Ops', SIGNER('changed', 'MMMM-9999', { pinned_fingerprint: 'AAAA-5555' })),
  ] }), { 'teams.verify-signer': () => ok({ vault: 'v-new', signer: { status: 'pinned' } }) });
  const $ = await openPopup();
  const rows = [...$('teams-signers').querySelectorAll('li')];
  assert.deepEqual(rows.map((r) => r.dataset.vault), ['v-swapped', 'v-new'], 'the changed one first, the verified one not at all');

  const [changed, fresh] = rows;
  assert.equal(changed.getAttribute('role'), 'alert');
  assert.ok(changed.classList.contains('warn'));
  assert.equal(changed.querySelector('.title').textContent, "Demo Ops: the manager's keys changed");
  assert.match(changed.querySelector('.sub').textContent, /not the keys you verified/);
  assert.equal(changed.querySelector('.fingerprint').textContent, 'MMMM-9999');

  assert.equal(fresh.getAttribute('role'), null);
  assert.equal(fresh.querySelector('.title').textContent, 'Demo Team is not verified yet');
  assert.equal(fresh.querySelector('.fingerprint').textContent, 'AAAA-5555');
  const go = fresh.querySelector('button');
  assert.equal(go.textContent, 'It matches');
  go.click();
  await flush();
  assert.deepEqual(sent('teams.verify-signer'), [{ type: 'teams.verify-signer', vault: 'v-new', fingerprint: 'AAAA-5555' }]);
  assert.equal($('snack').textContent, 'Demo Team is verified');
});

test('signers: the service\'s keys not matching the list is said plainly', async () => {
  reply = agent(model({ vaults: [vault('v-new', 'Demo Team', SIGNER('not_pinned', 'AAAA-5555'))] }),
    { 'teams.verify-signer': () => ({ ok: false, error: { code: 'keys_mismatch', message: 'the keys do not match the members list' } }) });
  const $ = await openPopup();
  $('teams-signers').querySelector('button').click();
  await flush();
  assert.equal($('snack').textContent, "The keys the service sent don't match this fingerprint. Nothing was changed.");
});

test('confirm: changed keys are a loud warning; left out and refused confirmations say what to do', async () => {
  const person = (extra) => ({ org: 'org-team', org_name: 'Demo Team', account_id: 'acc-bob', email: 'bob@example.com',
    fingerprint: 'BBBB-3333', vaults: 1, pin: 'changed', keys_changed: true, replaced: true, ...extra });
  let answer = ok({ added: 0, skipped: 0, left_out: [{ account: 'acc-bob', fingerprint: 'BBBB-3333', status: 'not_pinned' }] });
  reply = agent(model({ confirm: [person(), person({ account_id: 'acc-carol', email: 'carol@example.com', pin: 'not_pinned', keys_changed: false, replaced: false })] }),
    { 'teams.confirm': () => answer });
  const $ = await openPopup();
  const [bob, carol] = [...$('teams-confirm').querySelectorAll('li')];
  assert.equal(bob.getAttribute('role'), 'alert');
  assert.ok(bob.classList.contains('warn'));
  assert.equal(bob.querySelector('.warn-text').textContent,
    "bob@example.com's keys changed. Compare the new fingerprint with bob@example.com before giving access.");
  assert.equal(carol.querySelector('.warn-text'), null);
  assert.equal(carol.getAttribute('role'), null);

  carol.querySelector('input').value = 'CCCC-1111';
  carol.querySelector('button').click();
  await flush();
  assert.deepEqual(sent('teams.confirm').at(-1), { type: 'teams.confirm', org: 'org-team', account: 'acc-carol', fingerprint: 'CCCC-1111' });
  assert.equal($('snack').textContent, 'Compare the fingerprint with carol@example.com to give access.');

  answer = { ok: false, error: { code: 'fingerprint_mismatch', message: 'the fingerprint changed' } };
  bob.querySelector('button').click();
  await flush();
  assert.equal($('snack').textContent, "That fingerprint doesn't match. Compare it again with the person.");
});
