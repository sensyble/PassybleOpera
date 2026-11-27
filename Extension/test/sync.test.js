// "Sync now" (src/shared/sync.js, src/background/sync.js, browser-teams.js syncNow): one sync at a time for every
// caller. Fakes for the account service, Passyble Cloud and the WebAssembly; demo data only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { syncNeedsUpdate, syncOutcome, syncResult } from '../src/shared/sync.js';
import { createSync, SYNC_REPEAT_MS } from '../src/background/sync.js';
import { createBrowserTeams } from '../src/background/teams/browser-teams.js';
import { memoryTeamsStore } from '../src/background/teams/teams-store.js';

const REASON = "Couldn't reach the server";

test('syncResult: counts, failures and flags checked; anything else dropped', () => {
  assert.deepEqual(syncResult({ synced: 3, failed: [], no_sync: false }), { synced: 3, failed: [], no_sync: false, browser: false });
  assert.deepEqual(syncResult({ synced: '2.7', failed: [{ vault: ' Family\n', reason: 'Offline  now' }, null, 'x'], no_sync: 'yes', browser: true }),
    { synced: 2, failed: [{ vault: 'Family', reason: 'Offline now' }], no_sync: false, browser: true });
  assert.deepEqual(syncResult(null), { synced: 0, failed: [], no_sync: false, browser: false });
  assert.deepEqual(syncResult({ synced: -1, failed: [{ vault: 7, reason: {} }] }).failed, [{ vault: '', reason: '' }]);
  assert.equal(syncResult({ failed: [{ vault: 'v'.repeat(500), reason: 'r'.repeat(900) }] }).failed[0].vault.length, 120);
});

test('syncOutcome: synced, one or several vaults that did not sync, none set up (app and browser), an older app, other errors', () => {
  assert.deepEqual(syncOutcome({ result: { synced: 2, failed: [], no_sync: false } }), { text: 'Synced just now', kind: 'done' });
  assert.deepEqual(syncOutcome({ result: { synced: 1, failed: [{ vault: 'Family', reason: REASON }] } }),
    { text: "Family didn't sync: Couldn't reach the server", kind: 'failed' });
  assert.equal(syncOutcome({ result: { failed: [{ vault: 'Family', reason: REASON }, { vault: 'Work', reason: 'Locked' }] } }).text,
    "2 vaults didn't sync. Family: Couldn't reach the server");
  assert.equal(syncOutcome({ result: { failed: [{ vault: '', reason: REASON }] } }).text, "Couldn't sync: Couldn't reach the server");
  assert.match(syncOutcome({ result: { failed: [{ vault: 'Family', reason: '' }] } }).text, /^Family didn't sync: \S/, 'a generic reason');
  assert.deepEqual(syncOutcome({ result: { synced: 0, failed: [], no_sync: true } }),
    { text: 'No vault syncs yet. Set it up in the Passyble app.', kind: 'none' });
  assert.deepEqual(syncOutcome({ result: { synced: 0, failed: [], no_sync: true, browser: true } }),
    { text: 'No vault syncs yet: this vault is only in this browser.', kind: 'none' });
  assert.deepEqual(syncOutcome({ error: { code: 'not_supported', reason: 'needs_update', message: 'unknown method' } }),
    { text: 'Update the Passyble app to sync from here', kind: 'update' });
  assert.equal(syncOutcome({ error: { code: 'not_supported', message: 'unknown method sync.now' } }).kind, 'update');
  const offline = syncOutcome({ error: { code: 'agent_unavailable', message: 'not running' } });
  assert.equal(offline.kind, 'error');
  assert.ok(offline.text && !/not running/.test(offline.text), 'the translated text, not the raw message');
  assert.equal(syncNeedsUpdate({ code: 'not_supported', message: 'Passkeys need the Passyble app' }), false);
  assert.equal(syncNeedsUpdate(null), false);
});

test('one sync at a time: callers during a sync share it; right after it, its answer again; errors are not kept', async () => {
  let clock = 0;
  let calls = 0;
  let release;
  let fail = false;
  const sync = createSync({
    browserMode: async () => false,
    appSync: () => { calls++; return fail ? Promise.reject(Object.assign(new Error('locked'), { code: 'locked' })) : new Promise((r) => { release = r; }); },
    browserSync: async () => { throw new Error('not in app mode'); },
    now: () => clock,
  });
  const a = sync.syncNow();
  const b = sync.syncNow();
  assert.equal(a, b, 'the same run');
  await new Promise((r) => setTimeout(r, 0));
  release({ synced: 1, failed: [], no_sync: false });
  assert.deepEqual(await a, { synced: 1, failed: [], no_sync: false, browser: false });
  assert.equal(calls, 1);

  clock += SYNC_REPEAT_MS - 1;
  assert.deepEqual(await sync.syncNow(), { synced: 1, failed: [], no_sync: false, browser: false }, 'a double click: no second sync');
  assert.equal(calls, 1);

  clock += 2;
  fail = true;
  await assert.rejects(sync.syncNow(), { code: 'locked' });
  await assert.rejects(sync.syncNow(), { code: 'locked' }, 'tried again');
  assert.equal(calls, 3);
});

test('browser mode: the browser sync runs and the answer says so', async () => {
  const sync = createSync({ browserMode: async () => true, appSync: async () => { throw new Error('no app'); },
    browserSync: async () => ({ synced: 0, failed: [], no_sync: true }) });
  assert.deepEqual(await sync.syncNow(), { synced: 0, failed: [], no_sync: true, browser: true });
});

const ok = (result) => JSON.stringify({ result });
const GLUE = {
  multiForUrl: () => ok([]), multiSearch: () => ok([]), multiDefaultSaveVault: () => ok(null), policyCheck: () => ok([]),
  publicKeysCheck: () => ok({}), sendSeal: () => ok({}), sendLink: () => ok(''),
};
const SHARED = [
  { vault_id: 'v-family', vault_path: 'shared/family.pass', label: 'Demo Family', role: 'edit' },
  { vault_id: 'v-work', vault_path: 'shared/work.pass', label: 'Demo Work', role: 'view' },
];

function teams({ signedIn = true, orgs = async () => ({ organisations: [{ id: 'org-demo', name: 'Demo Family', kind: 'family', role: 'member', keys: 'ok' }],
  sharing_keys: { fingerprint: 'fp-demo' } }), cloudDevice = async () => ({ server_url: 'https://cloud.example.test', user: 'demo', token: 'demo-token', shared: SHARED }),
  download = async (device, path) => {
    if (path === 'shared/work.pass') throw Object.assign(new Error('offline'), { code: 'network' });
    return { unchanged: true };
  } } = {}) {
  let clock = 1_000;
  const log = { downloads: [] };
  const t = createBrowserTeams({
    glue: async () => GLUE,
    local: {
      info: async () => ({ locked: false, hasVault: true }),
      vaultAccess: async () => ({ kind: 'password', account: null, ak_id: null, account_recovery: false }),
      withAgent: async (fn) => fn({ ensureKeyset: () => ok({ fingerprint: 'fp-demo', public_keys: {} }) }, { locked: false, generation: 1 }),
      request: async () => ({}),
      releaseCopy: () => {},
    },
    account: { current: async () => (signedIn ? { id: 'acc-demo', email: 'demo@example.com' } : null), base: async () => 'https://account.example.test' },
    orgApi: { orgs, invites: async () => ({ invites: [] }), cloudDevice, confirmations: async () => ({ pending: [] }), putKeys: async () => ({}) },
    files: { download: async (device, path, etag) => { log.downloads.push(path); clock += 5; return download(device, path, etag); }, upload: async () => ({ etag: 'e1' }) },
    sends: {},
    store: memoryTeamsStore(),
    seen: { get: async () => ({}), set: async () => {} },
    deviceName: () => 'Browser',
    homeName: () => 'My vault',
    now: () => clock,
    log: { debug: () => {} },
  });
  return { teams: t, log, tick: (ms) => { clock += ms; } };
}

test('browser teams syncNow: every shared vault downloaded now; one that could not be reached is named with its code', async () => {
  const { teams: t, log } = teams();
  assert.deepEqual(await t.syncNow(), { synced: 1, failed: [{ vault: 'Demo Work', code: 'network' }], none: false });
  assert.deepEqual(log.downloads, ['shared/family.pass', 'shared/work.pass']);
  // Within the 5 minutes a refresh would wait: Sync now downloads again.
  await t.syncNow();
  assert.equal(log.downloads.length, 4);
});

test('browser teams syncNow: nothing that syncs (signed out, no Passyble Cloud, no shared vault); the service not reached', async () => {
  assert.deepEqual(await teams({ signedIn: false }).teams.syncNow(), { synced: 0, failed: [], none: true });
  const noCloud = teams({ cloudDevice: async () => { throw Object.assign(new Error('no plan'), { code: 'no_cloud_plan' }); } });
  assert.deepEqual(await noCloud.teams.syncNow(), { synced: 0, failed: [], none: true });
  const nobody = teams({ orgs: async () => ({ organisations: [] }), cloudDevice: async () => ({ shared: [] }) });
  assert.deepEqual(await nobody.teams.syncNow(), { synced: 0, failed: [], none: true });
  const offline = teams({ orgs: async () => { throw Object.assign(new Error('offline'), { code: 'network' }); } });
  assert.deepEqual(await offline.teams.syncNow(), { synced: 0, failed: [{ vault: '', code: 'network' }], none: false });
});

test('browser teams syncNow: all reached', async () => {
  const { teams: t } = teams({ download: async () => ({ unchanged: true }) });
  assert.deepEqual(await t.syncNow(), { synced: 2, failed: [], none: false });
});
