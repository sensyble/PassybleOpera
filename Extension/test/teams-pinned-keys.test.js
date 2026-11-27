// Pinned contact keys in browser mode (background/teams/browser-teams.js): the service's "confirmed" and "replaced"
// flags count for nothing, and a vault's signer verifies only with pinned keys from the members list. Attack
// simulations: the service marks an unpinned account confirmed, swaps a pinned member's keys, or hands out other
// keys for a vault's signer. Fakes for the account service, Passyble Cloud and the WebAssembly (the fake agent and
// SharedVault keep pins and refuse unpinned keys as the core does); demo data only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createBrowserTeams, hasPinApi, normalizeFingerprint, PIN_SCOPE } from '../src/background/teams/browser-teams.js';
import { memoryTeamsStore } from '../src/background/teams/teams-store.js';

const ok = (result) => JSON.stringify({ result });
const refused = (message) => JSON.stringify({ error: { code: 'internal', message } });

const TEAM = 'org-team';
const VAULT = 'v-team';
const SHARED = [{ org: TEAM, vault_id: VAULT, vault_path: 'shared/team.pass', label: 'Demo Team', kind: 'org', role: 'manage' }];

/** Demo public keys; the fake core's fingerprint of keys is their `enc_pub`. */
const keysOf = (account, enc) => ({ account, enc_pub: enc, sig_pub: `${enc}-sig`, created_at: 1, sig: 'demo-sig' });
const BOB = keysOf('acc-bob', 'BBBB-2222');
const BOB_NEW = keysOf('acc-bob', 'BBBB-3333');
const ALICE = keysOf('acc-alice', 'AAAA-5555');
const ME = keysOf('acc-me', 'EEEE-7777');
/** Keys the attacker made, handed out under someone else's name. */
const forged = (account) => keysOf(account, 'MMMM-9999');
const fp = (keys) => keys.enc_pub;

const GLUE = {
  multiForUrl: () => ok([]), multiSearch: () => ok([]), policyCheck: () => ok([]), sendSeal: () => ok({}), sendLink: () => ok(''),
  multiDefaultSaveVault: () => ok({ vault_id: 'home' }),
  // The keys' self-signature and fingerprint, as the core checks them.
  publicKeysCheck: (json) => { const k = JSON.parse(json); return ok({ valid: k?.sig === 'demo-sig', fingerprint: k?.enc_pub ?? '' }); },
};

/** The core's pins in the fake home vault: account -> keys, with its checks (contacts.rs). */
function fakePins({ keep = true } = {}) {
  const pins = new Map();
  const statusOf = (keys) => {
    if (keys.account === ME.account && fp(keys) === fp(ME)) return { status: 'pinned' };
    const pin = pins.get(keys.account);
    if (!pin) return { status: 'not_pinned' };
    return fp(pin) === fp(keys) ? { status: 'pinned' } : { status: 'changed', pinned_fingerprint: fp(pin) };
  };
  return { pins, statusOf, keep };
}

/**
 * The fake BrowserAgent and its one SharedVault: members, signer and pins as configured. `log.calls` keeps
 * the order of pins, member changes, uploads and confirmations.
 */
function setup({ members = [{ account: ME.account, role: 'manage', fingerprint: fp(ME) }], signer = ME, pending = [],
  people = [{ account_id: BOB.account, role: 'edit' }], directory = { [ALICE.account]: ALICE, [BOB.account]: BOB },
  pins = fakePins(), pinApi = true, lyingUnpinned = false } = {}) {
  const log = { calls: [], changes: [], confirmed: [], uploads: 0 };
  const sv = {
    info: () => ok({ vault_id: VAULT, org: TEAM, role: 'manage', members: structuredClone(members), anchored: true,
      signed_by: signer.account, signer_fingerprint: fp(signer) }),
    summaries: () => ok({ vault_id: VAULT, role: 'manage', can_edit: true, can_reveal: true, summaries: [] }),
    takeNotice: () => ok(null),
    item: () => 'null',
    // The core: every add and replace_keys must be pinned, or nothing changes.
    changeMembers: (json) => {
      const changes = JSON.parse(json);
      for (const c of changes) {
        if ((c.op === 'add' || c.op === 'replace_keys') && pins.statusOf(c.keys).status !== 'pinned') {
          return refused(`you haven't verified the keys of ${c.keys.account} yet`);
        }
      }
      for (const c of changes) {
        log.calls.push(`change:${c.op}:${c.keys?.account}`);
        log.changes.push(c);
        const at = members.findIndex((m) => m.account === c.keys.account);
        const entry = { account: c.keys.account, role: c.role || members[at]?.role, fingerprint: fp(c.keys) };
        if (at >= 0) members[at] = entry; else members.push(entry);
      }
      return ok({});
    },
    signerStatus: () => ok(pins.statusOf(signer)),
    save: () => new Uint8Array([1]),
    merge: () => ok({ dirty: false }),
  };
  const agent = {
    ensureKeyset: () => ok({ fingerprint: fp(ME), public_keys: ME }),
    homeSummaries: () => ok({ vault_id: 'home', can_edit: true, can_reveal: true, summaries: [] }),
    openShared: () => sv,
  };
  if (pinApi) {
    Object.assign(agent, {
      contactPinStatus: (json, scope) => { assert.equal(scope, PIN_SCOPE); return ok(pins.statusOf(JSON.parse(json))); },
      pinContact: (json, scope, compared) => {
        assert.equal(scope, PIN_SCOPE);
        const keys = JSON.parse(json);
        if (normalizeFingerprint(compared) !== normalizeFingerprint(fp(keys))) return refused("that fingerprint doesn't match these keys");
        log.calls.push(`pin:${keys.account}`);
        if (pins.keep) pins.pins.set(keys.account, keys);
        return ok({ account: keys.account, scope, fingerprint: fp(keys) });
      },
      unpinnedChanges: (json) => ok(lyingUnpinned ? [] : JSON.parse(json)
        .filter((c) => c.op === 'add' || c.op === 'replace_keys')
        .map((c) => ({ account: c.keys.account, fingerprint: fp(c.keys), ...pins.statusOf(c.keys) }))
        .filter((x) => x.status !== 'pinned')),
    });
  }
  const teams = createBrowserTeams({
    glue: async () => GLUE,
    local: {
      info: async () => ({ locked: false, hasVault: true }),
      vaultAccess: async () => ({ kind: 'password' }),
      withAgent: async (fn) => fn(agent, { locked: false, generation: 1 }),
      request: async () => ({}),
      releaseCopy: () => {},
    },
    account: { current: async () => ({ id: ME.account, email: 'me@example.com' }), base: async () => 'https://account.example.test' },
    orgApi: {
      orgs: async () => ({ organisations: [{ id: TEAM, kind: 'team', name: 'Demo Team', role: 'admin', keys: 'ok', policy: {} }],
        sharing_keys: { fingerprint: fp(ME) } }),
      invites: async () => ({ invites: [] }),
      cloudDevice: async () => ({ server_url: 'https://cloud.example.test', user: 'demo', token: 'demo-token', shared: SHARED }),
      confirmations: async () => ({ pending: structuredClone(pending) }),
      confirm: async (org, account, fingerprint) => { log.calls.push(`confirm:${account}`); log.confirmed.push({ org, account, fingerprint }); },
      putKeys: async () => ({}),
      orgVaults: async () => ({ vaults: [{ id: 'reg-team', vault_id: VAULT, people }] }),
      personKeys: async (org, account) => ({ keys: directory[account] ?? null, fingerprint: directory[account] ? fp(directory[account]) : '' }),
      secondPassword: async () => {},
    },
    files: {
      download: async () => ({ file: new TextEncoder().encode(VAULT), etag: 'e1' }),
      upload: async () => { log.calls.push('upload'); log.uploads++; return { etag: 'e2' }; },
    },
    sends: {},
    store: memoryTeamsStore(),
    seen: memorySeen(),
    deviceName: () => 'Browser',
    homeName: () => 'My vault',
    log: { debug: () => {} },
  });
  return { teams, log, members, pins };
}

function memorySeen() {
  let value = {};
  return { get: async () => structuredClone(value), set: async (v) => { value = structuredClone(v); } };
}

/** A person the service says waits for this admin's confirmation. */
const waiting = (keys, extra = {}) => ({ account_id: keys.account, email: `${keys.account.slice(4)}@example.com`, fingerprint: fp(keys),
  keys, replaced: false, previous_fingerprint: null, vaults: ['reg-team'], ...extra });

test('normalizeFingerprint: as the core compares, dashes, spaces, case and look-alike letters do not matter', () => {
  assert.equal(normalizeFingerprint(' 7k3qd-ol1i9 '), '7K3QD01119');
  assert.equal(normalizeFingerprint('7K3QD 01119'), normalizeFingerprint('7k3qd-ol1i9'));
  assert.notEqual(normalizeFingerprint('7K3QD-01118'), normalizeFingerprint('7K3QD-01119'));
  assert.equal(normalizeFingerprint(null), '');
});

test('hasPinApi: a BrowserAgent with pinContact, contactPinStatus and unpinnedChanges', () => {
  assert.equal(hasPinApi({ pinContact() {}, contactPinStatus() {}, unpinnedChanges() {} }), true);
  assert.equal(hasPinApi({ pinContact() {} }), false);
  assert.equal(hasPinApi(null), false);
});

test('confirm: the compared keys are pinned first, then added, uploaded and recorded with the service', async () => {
  const { teams, log, members, pins } = setup({ pending: [waiting(BOB)] });
  const model = await teams.refresh({ force: true });
  assert.equal(model.browser.confirm.length, 1);
  assert.equal(model.browser.confirm[0].pin, 'not_pinned');
  assert.equal(model.browser.confirm[0].keys_changed, false);
  assert.equal('keys' in model.browser.confirm[0], false, 'no keys go to the popup');

  // Typed the way people read it out: lower case, spaces.
  const res = await teams.confirm(TEAM, BOB.account, ' bbbb 2222 ');
  assert.deepEqual(res, { added: 1, skipped: 0, left_out: [] });
  assert.deepEqual(log.calls, ['pin:acc-bob', 'change:add:acc-bob', 'upload', 'confirm:acc-bob']);
  assert.equal(fp(pins.pins.get(BOB.account)), fp(BOB));
  assert.deepEqual(members.find((m) => m.account === BOB.account), { account: BOB.account, role: 'edit', fingerprint: fp(BOB) });
});

test('attack: the service marks an unpinned account confirmed: nobody is added without the admin comparing', async () => {
  // The service says Mallory is confirmed and belongs in the vault, with her keys: nothing happens on a refresh.
  const mallory = forged('acc-mallory');
  const { teams, log, members, pins } = setup({ pending: [waiting(mallory, { confirmed: true })],
    people: [{ account_id: 'acc-mallory', role: 'manage', confirmed: true }] });
  await teams.refresh({ force: true });
  await teams.refresh({ force: true });
  assert.deepEqual(log.calls, [], 'no pin, no member change, nothing told to the service');
  assert.equal(members.length, 1);
  assert.equal(pins.pins.size, 0);

  // Its keys under Bob's name, "confirmed": the admin compares with Bob, whose fingerprint is not these keys'.
  const swapped = setup({ pending: [waiting(forged(BOB.account), { confirmed: true })] });
  await swapped.teams.refresh({ force: true });
  await assert.rejects(swapped.teams.confirm(TEAM, BOB.account, fp(BOB)), { code: 'fingerprint_mismatch' });
  assert.deepEqual(swapped.log.calls, []);
  assert.equal(swapped.pins.pins.size, 0);

  // Keys of another account handed out for Bob: refused even with their own fingerprint typed.
  const other = setup({ pending: [{ ...waiting(mallory), account_id: BOB.account }] });
  await other.teams.refresh({ force: true });
  await assert.rejects(other.teams.confirm(TEAM, BOB.account, fp(mallory)), { code: 'keys_mismatch' });
  assert.deepEqual(other.log.calls, []);
});

test('attack: the service swaps a pinned member\'s keys: a loud warning, and the old fingerprint changes nothing', async () => {
  const pins = fakePins();
  pins.pins.set(BOB.account, BOB);
  const members = [{ account: ME.account, role: 'manage', fingerprint: fp(ME) }, { account: BOB.account, role: 'edit', fingerprint: fp(BOB) }];
  const attacker = forged(BOB.account);
  const { teams, log } = setup({ pins, members,
    pending: [waiting(attacker, { replaced: true, previous_fingerprint: fp(BOB) })] });
  const model = await teams.refresh({ force: true });
  assert.equal(model.browser.confirm[0].pin, 'changed');
  assert.equal(model.browser.confirm[0].keys_changed, true, 'shown loudly');

  // The admin compares with Bob, who still reads his old fingerprint: refused, the vault keeps Bob's keys.
  await assert.rejects(teams.confirm(TEAM, BOB.account, fp(BOB)), { code: 'fingerprint_mismatch' });
  assert.deepEqual(log.calls, []);
  assert.equal(members.find((m) => m.account === BOB.account).fingerprint, fp(BOB));
  assert.equal(fp(pins.pins.get(BOB.account)), fp(BOB), 'the pin is still the verified keys');
});

test('a member\'s real new keys: warned as changed, then compared, pinned again and replaced', async () => {
  const pins = fakePins();
  pins.pins.set(BOB.account, BOB);
  const members = [{ account: ME.account, role: 'manage', fingerprint: fp(ME) }, { account: BOB.account, role: 'edit', fingerprint: fp(BOB) }];
  const { teams, log } = setup({ pins, members, pending: [waiting(BOB_NEW, { replaced: true, previous_fingerprint: fp(BOB) })] });
  assert.equal((await teams.refresh({ force: true })).browser.confirm[0].keys_changed, true);
  const res = await teams.confirm(TEAM, BOB.account, fp(BOB_NEW));
  assert.deepEqual(res.left_out, []);
  assert.deepEqual(log.calls, ['pin:acc-bob', 'change:replace_keys:acc-bob', 'upload', 'confirm:acc-bob']);
  assert.equal(members.find((m) => m.account === BOB.account).fingerprint, fp(BOB_NEW));
});

test('a change whose keys are not pinned is left out and listed, and the confirmation is not recorded', async () => {
  // A pin that didn't hold (the home vault refused it): the change is left out, never wrapped blindly.
  const { teams, log, members } = setup({ pending: [waiting(BOB)], pins: fakePins({ keep: false }) });
  await teams.refresh({ force: true });
  const res = await teams.confirm(TEAM, BOB.account, fp(BOB));
  assert.equal(res.added, 0);
  assert.deepEqual(res.left_out, [{ account: BOB.account, fingerprint: fp(BOB), status: 'not_pinned' }]);
  assert.deepEqual(log.calls, ['pin:acc-bob'], 'no member change, no upload, nothing told to the service');
  assert.equal(members.length, 1);
  assert.equal((await teams.refresh({ force: true })).browser.confirm.length, 1, 'still waiting');
});

test('the core refuses unpinned keys even when the pin check said otherwise: nothing uploaded or recorded', async () => {
  const { teams, log } = setup({ pending: [waiting(BOB)], pins: fakePins({ keep: false }), lyingUnpinned: true });
  await teams.refresh({ force: true });
  await assert.rejects(teams.confirm(TEAM, BOB.account, fp(BOB)), { code: 'keys_not_verified' });
  assert.deepEqual(log.calls, ['pin:acc-bob']);
});

test('a build without pinned keys confirms nobody (it could only wrap blindly)', async () => {
  const { teams, log } = setup({ pending: [waiting(BOB)], pinApi: false });
  const model = await teams.refresh({ force: true });
  assert.equal(model.browser.confirm[0].pin, null);
  await assert.rejects(teams.confirm(TEAM, BOB.account, fp(BOB)), { code: 'not_supported' });
  assert.deepEqual(log.calls, []);
});

test('signer status: not verified yet with the fingerprint, verified after comparing; own lists are verified', async () => {
  const own = await setup().teams.refresh({ force: true });
  assert.equal(own.vaults[0].signer.status, 'pinned', 'this user signed it');

  const { teams, pins } = setup({ signer: ALICE });
  let model = await teams.refresh({ force: true });
  assert.deepEqual(model.vaults[0].signer, { status: 'not_pinned', account: ALICE.account, fingerprint: fp(ALICE) });

  await assert.rejects(teams.verifySigner(VAULT, 'AAAA-5556'), { code: 'fingerprint_mismatch' });
  assert.equal(pins.pins.size, 0);
  const res = await teams.verifySigner(VAULT, 'aaaa 5555');
  assert.equal(res.signer.status, 'pinned');
  assert.equal(fp(pins.pins.get(ALICE.account)), fp(ALICE));
  model = await teams.refresh({ force: true });
  assert.equal(model.vaults[0].signer.status, 'pinned');
});

test('attack: the service hands out other keys for a vault\'s signer: nothing is pinned', async () => {
  const { teams, pins } = setup({ signer: ALICE, directory: { [ALICE.account]: forged(ALICE.account) } });
  await teams.refresh({ force: true });
  // The user compared the list's fingerprint with Alice, but the service's keys are not the list's.
  await assert.rejects(teams.verifySigner(VAULT, fp(ALICE)), { code: 'keys_mismatch' });
  assert.equal(pins.pins.size, 0);
});

test('signer status: changed keys since they were verified are reported with the pinned fingerprint', async () => {
  const pins = fakePins();
  pins.pins.set(ALICE.account, keysOf(ALICE.account, 'AAAA-4444'));
  const { teams } = setup({ signer: ALICE, pins });
  const model = await teams.refresh({ force: true });
  assert.deepEqual(model.vaults[0].signer, { status: 'changed', pinned_fingerprint: 'AAAA-4444', account: ALICE.account, fingerprint: fp(ALICE) });
});
