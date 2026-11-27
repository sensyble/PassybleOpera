// The Team password rule (`policy.password_mode`) in browser mode (browser-teams.js, org-api.js) and the notice of
// app mode's `vaults.list` `password_policy` (src/shared/vaults.js). Fakes for the account service, Passyble Cloud
// and the WebAssembly; demo data only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createBrowserTeams, teamRuleVaults } from '../src/background/teams/browser-teams.js';
import { createOrgApi, ORG_ROUTES, passwordMode } from '../src/background/teams/org-api.js';
import { memoryTeamsStore } from '../src/background/teams/teams-store.js';
import { passwordPolicy } from '../src/shared/vaults.js';

const ok = (result) => JSON.stringify({ result });

const TEAM = 'org-team';
const FAMILY = 'org-family';
const SHARED = [
  { org: TEAM, vault_id: 'v-team', vault_path: 'shared/team.pass', label: 'Demo Team', kind: 'org', role: 'edit' },
  { org: FAMILY, vault_id: 'v-family', vault_path: 'shared/family.pass', label: 'Demo Family', kind: 'org', role: 'edit' },
];
const ITEMS = { 'v-team': 'team-login', 'v-family': 'family-login' };

const GLUE = {
  multiForUrl: () => ok([]), multiSearch: () => ok([]), policyCheck: () => ok([]), publicKeysCheck: () => ok({}),
  sendSeal: () => ok({}), sendLink: () => ok(''),
  // The core's default would be the Team vault: the editable ones are offered instead.
  multiDefaultSaveVault: () => ok({ vault_id: 'v-team' }),
};

/** A SharedVault of the fake WebAssembly: the vault id is the file's text. */
function sharedVault(file) {
  const vaultId = new TextDecoder().decode(file);
  const writes = [];
  return {
    writes,
    info: () => ok({ vault_id: vaultId, role: 'manage', members: [], anchored: true }),
    summaries: () => ok({ vault_id: vaultId, role: 'edit', can_edit: true, can_reveal: true,
      summaries: [{ id: ITEMS[vaultId], kind: 'login', title: 'Demo login', username: 'demo' }] }),
    takeNotice: () => ok(null),
    item: (id) => JSON.stringify({ id, kind: 'login', title: 'Demo login', username: 'demo', password: 'demo-password' }),
    upsert: (json) => { writes.push(JSON.parse(json)); return ok({ id: 'new-login' }); },
    delete: (id) => { writes.push({ deleted: id }); return ok({}); },
    changeMembers: (json) => { writes.push({ members: JSON.parse(json) }); return ok({}); },
    save: () => new Uint8Array([1]),
    merge: () => ok({ dirty: false }),
  };
}

/** GET /v1/orgs: a Team whose policy has `team` (false: no Team; null: no password_mode key) and a Family. */
function orgsAnswer(team) {
  const organisations = [];
  if (team !== false) {
    organisations.push({ id: TEAM, kind: 'team', name: 'Demo Team', role: 'member', keys: 'ok', policy: team === null ? {} : { password_mode: team } });
  }
  organisations.push({ id: FAMILY, kind: 'family', name: 'Demo Family', role: 'member', keys: 'ok', policy: { password_mode: 'choice' } });
  return { organisations, sharing_keys: { fingerprint: 'fp-demo' } };
}

/**
 * Browser teams with that Team and Family, and this browser's vault linked or with its own password
 * (`linked`). `seen` and `store` can be shared with a second instance (a restarted service worker).
 */
function setup({ team = 'second_password', linked = true, seen = memorySeen(), store = memoryTeamsStore(), pending = [] } = {}) {
  const log = { reports: [], vaults: new Map() };
  const access = { kind: linked ? 'account' : 'password' };
  const agent = {
    ensureKeyset: () => ok({ fingerprint: 'fp-demo', public_keys: {} }),
    homeSummaries: () => ok({ vault_id: 'home', can_edit: true, can_reveal: true, summaries: [] }),
    openShared: (file) => { const sv = sharedVault(file); log.vaults.set(new TextDecoder().decode(file), sv); return sv; },
  };
  const teams = createBrowserTeams({
    glue: async () => GLUE,
    local: {
      info: async () => ({ locked: false, hasVault: true }),
      vaultAccess: async () => ({ ...access }),
      withAgent: async (fn) => fn(agent, { locked: false, generation: 1 }),
      request: async () => ({}),
      releaseCopy: () => {},
    },
    account: { current: async () => ({ id: 'acc-demo', email: 'demo@example.com' }), base: async () => 'https://account.example.test' },
    orgApi: {
      orgs: async () => orgsAnswer(team),
      invites: async () => ({ invites: [] }),
      cloudDevice: async () => ({ server_url: 'https://cloud.example.test', user: 'demo', token: 'demo-token', shared: SHARED }),
      confirmations: async (org) => ({ pending: pending.filter((p) => p.org === org) }),
      confirm: async () => {},
      putKeys: async () => ({}),
      orgVaults: async () => ({ vaults: [] }),
      secondPassword: async (on) => { log.reports.push(on); },
    },
    files: {
      download: async (device, path) => ({ file: new TextEncoder().encode(SHARED.find((e) => e.vault_path === path).vault_id), etag: 'e1' }),
      upload: async () => ({ etag: 'e2' }),
    },
    sends: {},
    store,
    seen,
    deviceName: () => 'Browser',
    homeName: () => 'My vault',
    log: { debug: () => {} },
  });
  return { teams, log, access };
}

function memorySeen() {
  let value = {};
  return { get: async () => structuredClone(value), set: async (v) => { value = structuredClone(v); } };
}

const home = (answer = {}) => async () => answer;
const refOf = (model, id) => model.vaults.find((v) => v.id === id);

test('passwordMode: second password wins over one password over choice; Family, missing and unknown are choice', () => {
  const team = (mode) => ({ kind: 'team', policy: mode === undefined ? {} : { password_mode: mode } });
  assert.equal(passwordMode([team('one_password'), team('second_password')]), 'second_password');
  assert.equal(passwordMode([team('choice'), team('one_password')]), 'one_password');
  assert.equal(passwordMode([team('choice')]), 'choice');
  assert.equal(passwordMode([{ kind: 'family', policy: { password_mode: 'second_password' } }]), 'choice', 'a Family is ignored');
  assert.equal(passwordMode([team(undefined), { kind: 'team' }]), 'choice', 'an older service');
  assert.equal(passwordMode([team('two_passwords')]), 'choice');
  assert.equal(passwordMode(null), 'choice');
});

test("teamRuleVaults: today the vault with the Team's keys and the counted vaults are this browser's vault", async () => {
  let access = { kind: 'account' };
  const scope = teamRuleVaults({ vaultAccess: async () => { if (!access) throw new Error('no vault'); return access; } });
  assert.equal(scope.keys.vault, 'home');
  assert.deepEqual(scope.counted.map((v) => v.vault), ['home']);
  assert.equal(scope.counted[0], scope.keys);
  assert.equal(await scope.keys.ownPassword(), false, 'linked: the Passyble password');
  access = { kind: 'password' };
  assert.equal(await scope.keys.ownPassword(), true, 'its own master password');
  access = null;
  assert.equal(await scope.keys.ownPassword(), null, 'not known');
});

test('second password required, this browser\'s vault linked: the Team\'s vaults are read-only here, the Family\'s are not', async () => {
  const { teams, log } = setup();
  const model = await teams.refresh({ force: true });
  assert.equal(refOf(model, 'v-team').can_edit, false);
  assert.equal(refOf(model, 'v-family').can_edit, true);
  assert.equal(model.browser.password_rule, 'second_password');

  const refused = { code: 'read_only' };
  await assert.rejects(teams.handle('logins.update', { id: 'team-login', fields: { title: 'Changed' } }, home()), refused);
  await assert.rejects(teams.handle('logins.delete', { id: 'team-login' }, home()), refused);
  await assert.rejects(teams.handle('logins.create', { vault: 'v-team', fields: { title: 'New' } }, home()), refused);
  await assert.rejects(teams.handle('logins.save', { vault: 'v-team', url: 'https://example.com/', username: 'demo', password: 'demo-new' }, home()), refused);
  await assert.rejects(teams.handle('logins.save', { id: 'team-login', password: 'demo-new' }, home()), refused);
  assert.deepEqual(log.vaults.get('v-team').writes, [], 'nothing changed in the Team vault');
  const edit = await teams.handle('logins.get_for_edit', { id: 'team-login' }, home());
  assert.equal(edit.read_only, true, 'it opens read-only');

  // Saving a new login offers the other vaults, never the Team's (the core's default is skipped).
  const check = await teams.handle('logins.save_check', { url: 'https://example.com/', username: 'demo', password: 'demo-new' }, home({ action: 'save_new' }));
  assert.equal(check.action, 'save_new');
  assert.deepEqual(check.vaults.map((v) => v.id), ['home', 'v-family']);
  assert.equal(check.default_vault, 'home');
  await teams.handle('logins.update', { id: 'family-login', fields: { title: 'Changed' } }, home());
  assert.equal(log.vaults.get('v-family').writes.length, 1, 'the Family vault still changes');
});

test('second password required: no key confirmation for that Team from this browser', async () => {
  const pending = [{ org: TEAM, account_id: 'acc-peer', email: 'peer@example.com', fingerprint: 'FP-PEER', keys: {}, vaults: ['v-team'] }];
  const { teams } = setup({ pending });
  const model = await teams.refresh({ force: true });
  assert.deepEqual(model.browser.confirm, []);
  assert.equal(model.teams.to_confirm, 0);
  await assert.rejects(teams.confirm(TEAM, 'acc-peer', 'FP-PEER'), { code: 'read_only' });

  const met = setup({ pending, linked: false });
  assert.equal((await met.teams.refresh({ force: true })).browser.confirm.length, 1, 'offered once the rule is met');
});

test('second password required and met (this browser\'s vault has its own password): nothing changes', async () => {
  const { teams } = setup({ linked: false });
  const model = await teams.refresh({ force: true });
  assert.equal(refOf(model, 'v-team').can_edit, true);
  assert.equal(model.browser.password_rule, null);
});

test('one password only: a notice while this browser\'s vault has its own password, nothing read-only', async () => {
  const own = await setup({ team: 'one_password', linked: false }).teams.refresh({ force: true });
  assert.equal(own.browser.password_rule, 'one_password');
  assert.equal(refOf(own, 'v-team').can_edit, true);
  const linked = await setup({ team: 'one_password', linked: true }).teams.refresh({ force: true });
  assert.equal(linked.browser.password_rule, null);
  for (const team of ['choice', null]) {
    const model = await setup({ team }).teams.refresh({ force: true });
    assert.equal(model.browser.password_rule, null, `${team}: as before`);
    assert.equal(refOf(model, 'v-team').can_edit, true);
  }
});

test('a restarted service worker opens the Team vault read-only before its first refresh', async () => {
  const seen = memorySeen();
  const store = memoryTeamsStore();
  await setup({ seen, store }).teams.refresh({ force: true });
  const { teams, log } = setup({ seen, store });
  await assert.rejects(teams.handle('logins.update', { id: 'team-login', fields: { title: 'Changed' } }, home()), { code: 'read_only' });
  assert.deepEqual(log.vaults.get('v-team').writes, []);
});

test('the second password answer is reported when it changes, for an account in a Team only', async () => {
  const { teams, log, access } = setup({ team: 'choice' });
  await teams.refresh({ force: true });
  assert.deepEqual(log.reports, [false], 'linked: no second password');
  await teams.refresh({ force: true });
  assert.deepEqual(log.reports, [false], 'the same answer is not sent again');
  access.kind = 'password';
  await teams.refresh({ force: true });
  assert.deepEqual(log.reports, [false, true]);
  await teams.signedOut();
  await teams.refresh({ force: true });
  assert.deepEqual(log.reports, [false, true, true], 'sent again after a new sign-in');

  const family = setup({ team: false });
  await family.teams.refresh({ force: true });
  assert.deepEqual(family.log.reports, [], 'a Family alone: nothing is sent');
});

test('the report goes to PUT /v1/me/second-password of the account service', async () => {
  const calls = [];
  const api = createOrgApi({
    account: { accessToken: async () => 'demo-token', base: async () => 'https://account.example.test' },
    fetch: async (url, init) => { calls.push([init.method, url, JSON.parse(init.body), init.headers.Authorization]); return { ok: true, status: 204, headers: { get: () => null } }; },
  });
  await api.secondPassword(true);
  await api.secondPassword(false);
  assert.deepEqual(calls, [
    ['PUT', 'https://account.example.test/v1/me/second-password', { second_password: true }, 'Bearer demo-token'],
    ['PUT', 'https://account.example.test/v1/me/second-password', { second_password: false }, 'Bearer demo-token'],
  ]);
  assert.deepEqual(ORG_ROUTES.secondPassword, ['PUT', '/v1/me/second-password']);
});

test('app mode: vaults.list password_policy shows while the rule is not met; older apps and met rules show nothing', () => {
  const policy = { mode: 'second_password', action_needed: true, title: ' Your team requires a second password ', message: 'Give My vault its own password.' };
  assert.deepEqual(passwordPolicy({ password_policy: policy }), { title: 'Your team requires a second password', message: 'Give My vault its own password.' });
  assert.equal(passwordPolicy({ password_policy: { ...policy, action_needed: false } }), null, 'met on this PC');
  assert.equal(passwordPolicy({ password_policy: null }), null, 'choice, or no Team');
  assert.equal(passwordPolicy({ vaults: [] }), null, 'an older desktop app');
  assert.equal(passwordPolicy({ password_policy: { ...policy, mode: 'choice' } }), null);
  assert.equal(passwordPolicy({ password_policy: { ...policy, title: 7 } }), null);
  assert.equal(passwordPolicy({ password_policy: { ...policy, message: 'x'.repeat(900) } }).message.length, 400);
});
