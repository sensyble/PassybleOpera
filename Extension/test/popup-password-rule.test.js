// The Team password rule in the popup's "Shared with me" area (real popup.html + popup.js in jsdom). Demo data only.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const ok = (result) => ({ ok: true, result });

const ITEMS = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false, vault_id: 'v-team' }];
const HOME = { id: 'home', name: '', home: true, kind: 'personal', role: null, can_edit: true, can_reveal: true };
const TEAM_VAULT = { id: 'v-team', name: 'Demo Team', home: false, kind: 'org', role: 'edit', can_edit: false, can_reveal: true };
const STATE = { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null, items: ITEMS,
  can_edit: true, can_notes: true, can_search: true, can_vaults: true, vaults: [HOME, TEAM_VAULT] };
const LIST = { vaults: [{ ...HOME, items: 2, open: true, error: null }, { ...TEAM_VAULT, items: 1, open: true, error: null }],
  teams: { invites: 0, to_confirm: 0, notices: 0 } };
const POLICY = { mode: 'second_password', action_needed: true, title: 'Your team requires a second password',
  message: 'Give My vault its own password, separate from your Passyble password.' };

function agent(state, teams) {
  return (msg) => {
    switch (msg.type) {
      case 'popup.state': return ok(state);
      case 'popup.vaults': case 'teams.model': return ok(teams);
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
    tabs: { query: async () => [{ id: 1, windowId: 7, url: 'https://github.com/login' }], create: async () => ({ id: 9 }) },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('app mode: the desktop app\'s password rule over the list (no "shared vaults open" line), Open in Passyble opens its Teams screen', async () => {
  reply = agent(STATE, { ...LIST, password_policy: POLICY });
  const $ = await openPopup();
  const notice = $('teams-rule');
  assert.ok(notice, 'shown');
  assert.equal($('teams-line'), null, 'nothing waits in Teams and Family: no line, no count of open shared vaults');
  assert.equal(notice.nextElementSibling, $('list'));
  assert.equal(notice.querySelector('.title').textContent, POLICY.title);
  assert.equal(notice.querySelector('.sub').textContent, POLICY.message);
  // The Team vault the agent reports with can_edit false: its login fills and copies, with no Edit.
  $('list').querySelector('[data-id="gh"] button[title="More"]').click();
  assert.deepEqual([...document.querySelectorAll('.popover .menu-item')].map((b) => b.textContent), ['Open in Passyble']);
  const open = notice.querySelector('button');
  assert.equal(open.textContent, 'Open in Passyble');
  open.click();
  await flush();
  assert.deepEqual(sent('popup.show-teams'), [{ type: 'popup.show-teams' }], 'no section: app.show_teams {}');
});

test('app mode: an older desktop app (no password_policy) or a rule that is met shows nothing new', async () => {
  reply = agent(STATE, LIST);
  let $ = await openPopup();
  assert.equal($('teams-line'), null, 'open shared vaults alone: no line');
  assert.equal($('teams-rule'), null);
  reply = agent(STATE, { ...LIST, password_policy: { ...POLICY, action_needed: false } });
  $ = await openPopup();
  assert.equal($('teams-rule'), null);
});

test('app mode: the Shared with me line only says what waits (an invite, a vault that cannot open), never how many are open', async () => {
  reply = agent(STATE, { ...LIST, teams: { invites: 1 },
    vaults: [...LIST.vaults, { id: 'broken', name: 'Broken', kind: 'org', role: 'edit', can_edit: true, can_reveal: true, open: false, error: { code: 'untrusted' } }] });
  const $ = await openPopup();
  const line = $('teams-line');
  assert.ok(line);
  assert.equal(line.querySelector('.grow').textContent, "1 can't be opened · 1 invitation");
  assert.doesNotMatch(line.textContent, /open$|vaults? open/);
});

test('browser mode: what this browser can\'t do for the rule, and where it can be done; no app button', async () => {
  const browser = { ...STATE, browser: true, local_only: true };
  const model = (rule) => ({ ...LIST, browser: { status: 'ready', orgs: [], held: [], confirm: [], password_rule: rule } });
  reply = agent(browser, model('second_password'));
  let $ = await openPopup();
  assert.equal($('teams-rule').querySelector('.title').textContent, 'Your team requires a second password');
  assert.match($('teams-rule').querySelector('.sub').textContent, /can't give its vault a second password.*not change them.*Windows or Android.*team admin/);
  assert.equal($('teams-rule').querySelector('button'), null);

  reply = agent(browser, model('one_password'));
  $ = await openPopup();
  assert.equal($('teams-rule').querySelector('.title').textContent, 'Your team uses one password');
  assert.match($('teams-rule').querySelector('.sub').textContent, /^Personal still has its own password, and this browser can't switch it/);

  reply = agent(browser, model(null));
  $ = await openPopup();
  assert.equal($('teams-line'), null, 'open shared vaults alone: no line');
  assert.equal($('teams-rule'), null);
});
