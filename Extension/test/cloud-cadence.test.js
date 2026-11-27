// Quick Passyble Cloud checks in browser mode (background/teams/cloud-cadence.js, browser-teams.js pull): about every
// minute while the vault is unlocked and the Cloud plan is live, backing off on errors and a busy server, nothing for
// an account without a Cloud device. Fakes for the account service, Passyble Cloud and the WebAssembly; demo data only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  afterCheck, backoffMs, BACKOFF_MAX_MS, cadenceOf, cloudLive, emptyCadence, FAST_MS, nextCheckAt, retryAfterMs, shouldCheck,
} from '../src/background/teams/cloud-cadence.js';
import { createCloudFiles, fileErrorCode } from '../src/background/teams/cloud-files.js';
import { createBrowserTeams } from '../src/background/teams/browser-teams.js';
import { memoryTeamsStore } from '../src/background/teams/teams-store.js';
import { teamsErrorKey } from '../src/shared/vaults.js';

const half = () => 0.5;

test('cadence: backoff starts at 30 s, doubles and stops at 10 minutes, with a little jitter', () => {
  assert.equal(backoffMs(0, half), 0);
  assert.deepEqual([1, 2, 3, 4, 5, 6, 7, 30].map((n) => backoffMs(n, half)), [30_000, 60_000, 120_000, 240_000, 480_000, 600_000, 600_000, 600_000]);
  assert.equal(backoffMs(1, () => 0), 27_000);
  assert.equal(backoffMs(1, () => 1), 33_000);
  assert.equal(backoffMs(9, () => 1), BACKOFF_MAX_MS, 'never past the cap');
});

test('cadence: the next check is a minute after the last; popup 15 s, alarm 30 s, unlock and online at once', () => {
  const s = { ...emptyCadence(), checkedAt: 100_000 };
  assert.equal(nextCheckAt(s, 'unknown'), 100_000 + FAST_MS);
  assert.equal(shouldCheck(s, 'popup', 114_999), false);
  assert.equal(shouldCheck(s, 'popup', 115_000), true);
  assert.equal(shouldCheck(s, 'alarm', 129_999), false);
  assert.equal(shouldCheck(s, 'alarm', 130_000), true);
  assert.equal(shouldCheck(s, 'unlock', 100_001), true);
  assert.equal(shouldCheck(s, 'online', 100_001), true);
});

test('cadence: failures back off; unlock and online skip the backoff except for a busy server; success resets', () => {
  let s = emptyCadence();
  s = afterCheck(s, [{ code: 'network' }], 1_000_000, half);
  assert.deepEqual(s, { checkedAt: 1_000_000, failures: 1, retryAt: 1_030_000, code: 'network' });
  for (let i = 0; i < 4; i++) s = afterCheck(s, [{ code: 'network' }], s.checkedAt, half);
  assert.equal(s.failures, 5);
  assert.equal(s.retryAt - s.checkedAt, 480_000);
  assert.equal(shouldCheck(s, 'alarm', s.checkedAt + 300_000), false, 'the alarm waits out the backoff');
  assert.equal(shouldCheck(s, 'popup', s.checkedAt + 300_000), false);
  assert.equal(shouldCheck(s, 'online', s.checkedAt + 1), true, 'back online: at once');
  assert.deepEqual(afterCheck(s, [], s.checkedAt + 1, half), { checkedAt: s.checkedAt + 1, failures: 0, retryAt: 0, code: '' });
  assert.deepEqual(afterCheck(s, [{ code: 'not_a_member' }], 5, half).failures, 0, 'an answer is no reason to wait');

  const busy = afterCheck(emptyCadence(), [{ code: 'busy', retryAfterMs: 120_000 }], 1_000, half);
  assert.deepEqual(busy, { checkedAt: 1_000, failures: 1, retryAt: 121_000, code: 'busy' }, 'at least the Retry-After');
  assert.equal(afterCheck(emptyCadence(), [{ code: 'busy', retryAfterMs: 5_000 }], 0, half).retryAt, 30_000, 'at least the backoff');
  assert.equal(shouldCheck(busy, 'online', 60_000), false, 'a busy server is not asked early');
  assert.equal(shouldCheck(busy, 'unlock', 121_000), true);
  assert.deepEqual(cadenceOf({ checkedAt: 'x', failures: -1, retryAt: 5, code: 3 }), { checkedAt: 0, failures: 0, retryAt: 5, code: '' });
});

test('cadence: quick checks only with a Cloud device, unlocked, and a shared vault whose plan is live', () => {
  const device = { user: 'demo' };
  assert.equal(cloudLive({ device, locked: false, vaults: ['v1'] }), true);
  assert.equal(cloudLive({ device: null, locked: false, vaults: ['v1'] }), false, 'no Cloud plan: no device');
  assert.equal(cloudLive({ device, locked: true, vaults: ['v1'] }), false);
  assert.equal(cloudLive({ device, locked: false, vaults: [] }), false);
  assert.equal(cloudLive({ device, locked: false, vaults: ['v1'], blocked: ['v1'] }), false);
  assert.equal(cloudLive({ device, locked: false, vaults: ['v1', 'v2'], blocked: ['v1'] }), true);
});

test('Retry-After: seconds or an HTTP date, at most an hour', () => {
  assert.equal(retryAfterMs('120', 0), 120_000);
  assert.equal(retryAfterMs('', 0), 0);
  assert.equal(retryAfterMs(null, 0), 0);
  assert.equal(retryAfterMs('soon', 0), 0);
  assert.equal(retryAfterMs('999999', 0), 3_600_000);
  const now = Date.parse('2026-11-27T10:00:00Z');
  assert.equal(retryAfterMs('Fri, 27 Nov 2026 10:01:30 GMT', now), 90_000);
  assert.equal(retryAfterMs('Fri, 27 Nov 2026 09:00:00 GMT', now), 0);
});

test('cloud files: 429 is busy with its Retry-After; the other answers as before', async () => {
  assert.equal(fileErrorCode(429, ''), 'busy');
  assert.equal(teamsErrorKey('busy'), 'teamsErrNetwork');
  assert.equal(fileErrorCode(503, ''), 'network');
  assert.equal(fileErrorCode(403, 'subscription_inactive'), 'subscription_inactive');
  const headers = (h) => ({ get: (k) => h[k] ?? null });
  const device = { server_url: 'https://cloud.example.test', user: 'demo', token: 'demo-token' };
  const busy = createCloudFiles({ fetch: async () => ({ status: 429, ok: false, headers: headers({ 'Retry-After': '90' }) }) });
  await assert.rejects(busy.download(device, '/dav/demo/team.vault', 'e1'), (err) => err.code === 'busy' && err.retryAfterMs === 90_000);
  const same = createCloudFiles({ fetch: async (url, init) => {
    assert.equal(init.headers['If-None-Match'], 'e1');
    return { status: 304, ok: false, headers: headers({}) };
  } });
  assert.deepEqual(await same.download(device, '/dav/demo/team.vault', 'e1'), { unchanged: true, etag: 'e1' });
});

// browser-teams pull ---------------------------------------------------------------------------------------------

const ok = (result) => JSON.stringify({ result });
const GLUE = {
  multiForUrl: () => ok([]), multiSearch: () => ok([]), multiDefaultSaveVault: () => ok(null), policyCheck: () => ok([]),
  publicKeysCheck: () => ok({}), sendSeal: () => ok({}), sendLink: () => ok(''),
};
const SHARED = [{ vault_id: 'v-team', vault_path: '/dav/demo/team.vault', label: 'Demo Team', role: 'edit' }];
const DEVICE = { server_url: 'https://cloud.example.test', user: 'demo', token: 'demo-token', shared: SHARED };
const noPlan = () => Object.assign(new Error('no plan'), { status: 402, code: 'no_cloud_plan', serviceCode: 'no_cloud_plan' });

function setup({ cloudDevice = async () => structuredClone(DEVICE), download = async () => ({ unchanged: true }),
  upload = async () => ({ etag: 'e2' }), cloudState, online = () => true } = {}) {
  const env = { clock: 10_000_000, locked: false, alarm: [], downloads: 0, orgs: 0, devices: 0 };
  const sv = {
    info: () => ok({ vault_id: 'v-team', role: 'edit', members: [], anchored: true }),
    summaries: () => ok({ vault_id: 'v-team', role: 'edit', can_edit: true, can_reveal: true, summaries: [] }),
    takeNotice: () => ok(null),
    save: () => new Uint8Array([1]),
    merge: () => ok({ dirty: false }),
    upsert: () => ok({ id: 'i1' }),
  };
  const agent = {
    ensureKeyset: () => ok({ fingerprint: 'fp-demo', public_keys: {} }),
    homeSummaries: () => ok({ vault_id: 'home', can_edit: true, can_reveal: true, summaries: [] }),
    openShared: () => sv,
  };
  const teams = createBrowserTeams({
    glue: async () => GLUE,
    local: {
      info: async () => ({ locked: env.locked, hasVault: true }),
      vaultAccess: async () => ({ kind: 'password' }),
      withAgent: async (fn) => fn(agent, { locked: env.locked, generation: 1 }),
      request: async () => ({}),
      releaseCopy: () => {},
    },
    account: { current: async () => ({ id: 'acc-demo', email: 'demo@example.com' }), base: async () => 'https://account.example.test' },
    orgApi: {
      orgs: async () => { env.orgs++; return { organisations: [{ id: 'org-demo', name: 'Demo Team', kind: 'team', role: 'member', keys: 'ok' }] }; },
      invites: async () => ({ invites: [] }),
      cloudDevice: async () => { env.devices++; return cloudDevice(); },
      confirmations: async () => ({ pending: [] }),
      putKeys: async () => ({}),
      secondPassword: async () => {},
    },
    files: {
      download: async (device, path, etag) => { env.downloads++; return download(device, path, etag); },
      upload: async (...a) => upload(...a),
    },
    sends: {},
    store: memoryTeamsStore(),
    seen: { get: async () => ({}), set: async () => {} },
    deviceName: () => 'Browser',
    homeName: () => 'My vault',
    now: () => env.clock,
    log: { debug: () => {} },
    random: half,
    cloudAlarm: async (on) => { env.alarm.push(on); },
    online,
    ...(cloudState ? { cloudState } : {}),
  });
  return { teams, env, tick: (ms) => { env.clock += ms; } };
}

const firstFile = async () => ({ file: new Uint8Array([7]), etag: 'e1' });

test('pull: a paid Cloud account is checked every minute with conditional GETs; the account service every 5 minutes', async () => {
  let etags = [];
  const { teams, env, tick } = setup({ download: async (d, p, etag) => { etags.push(etag); return etag ? { unchanged: true } : firstFile(); } });
  await teams.refresh();
  assert.equal(env.orgs, 1);
  assert.equal(env.downloads, 1);
  assert.equal(env.alarm.at(-1), true, 'the minute alarm is on');

  tick(10_000);
  assert.deepEqual(await teams.pull('alarm'), { skipped: 'wait' }, 'checked 10 s ago');
  tick(50_000);
  assert.deepEqual(await teams.pull('alarm'), { checked: true, live: true });
  assert.equal(env.downloads, 2);
  assert.deepEqual(etags, [null, 'e1'], 'a conditional GET');
  for (let i = 0; i < 3; i++) { tick(FAST_MS); await teams.pull('alarm'); }
  assert.equal(env.downloads, 5);
  assert.equal(env.orgs, 1, 'no account service call within its 5 minutes');
  tick(FAST_MS);
  await teams.pull('alarm');
  assert.equal(env.orgs, 2, 'after 5 minutes the full refresh');
  assert.equal(env.devices, 2);
  assert.equal(env.downloads, 6, 'one check, not two');
});

test('pull: popup open checks when the last check is over 15 s old; unlock checks at once', async () => {
  const { teams, env, tick } = setup();
  await teams.refresh();
  tick(5_000);
  assert.deepEqual(await teams.pull('popup'), { skipped: 'wait' });
  tick(11_000);
  assert.equal((await teams.pull('popup')).checked, true);
  assert.equal((await teams.pull('unlock')).checked, true);
  assert.equal(env.downloads, 3);
});

test('pull: no Cloud device (no paid plan): no alarm and no request at all', async () => {
  const { teams, env, tick } = setup({ cloudDevice: async () => { throw noPlan(); } });
  assert.deepEqual(await teams.pull('unlock'), { skipped: 'no_cloud' }, 'nothing known yet: nothing sent');
  assert.equal(env.orgs + env.devices + env.downloads, 0);
  await teams.refresh();
  assert.equal(env.alarm.at(-1), false);
  tick(FAST_MS);
  assert.equal((await teams.pull('alarm')).skipped, 'no_cloud');
  tick(10 * FAST_MS);
  assert.equal((await teams.pull('alarm')).skipped, 'no_cloud');
  assert.equal(env.downloads, 0);
  assert.equal(env.orgs, 1);
});

test('pull: a plan that is no longer live (uploads refused) stops the quick checks of that vault', async () => {
  const { teams, env, tick } = setup({ download: firstFile,
    upload: async () => { throw Object.assign(new Error('inactive'), { status: 403, code: 'subscription_inactive' }); } });
  await teams.refresh();
  assert.equal(env.alarm.at(-1), true);
  await teams.handle('logins.create', { vault: 'v-team', fields: { title: 'Demo' } }, async () => ({}));
  tick(FAST_MS);
  assert.deepEqual(await teams.pull('alarm'), { skipped: 'not_live' });
  assert.equal(env.alarm.at(-1), false, 'the alarm is cleared');
  assert.equal(env.downloads, 1);
});

test('pull: locked: the alarm is cleared and nothing is checked', async () => {
  const { teams, env, tick } = setup();
  await teams.refresh();
  env.locked = true;
  teams.lock();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(env.alarm.at(-1), false);
  tick(FAST_MS);
  env.alarm.length = 0;
  assert.deepEqual(await teams.pull('alarm'), { skipped: 'locked' });
  assert.deepEqual(env.alarm, [false]);
  assert.equal(env.downloads, 1);
});

test('pull: offline is skipped without counting as a failure; back online checks at once', async () => {
  let on = true;
  const { teams, env, tick } = setup({ online: () => on });
  await teams.refresh();
  on = false;
  for (let i = 0; i < 5; i++) { tick(FAST_MS); assert.deepEqual(await teams.pull('alarm'), { skipped: 'offline' }); }
  assert.equal(env.downloads, 1);
  on = true;
  tick(1_000);
  assert.equal((await teams.pull('online')).checked, true);
  assert.equal(env.downloads, 2);
});

test('pull: errors back off 30 s doubling to 10 minutes; a busy server waits its Retry-After; success resets', async () => {
  let answer = async () => ({ unchanged: true });
  const { teams, env, tick } = setup({ download: (...a) => answer(...a) });
  await teams.refresh();
  answer = async () => { throw Object.assign(new Error('offline'), { status: 0, code: 'network' }); };
  const checks = [];
  for (let i = 0; i < 15 * 60; i++) {
    const before = env.downloads;
    tick(FAST_MS / 2);
    await teams.pull('alarm');
    if (env.downloads > before) checks.push(env.clock);
    if (env.clock - checks[0] > 40 * FAST_MS) break;
  }
  const gaps = checks.slice(1).map((t, i) => t - checks[i]);
  // Alarms every 30 s here: the 30 s and 60 s waits round up to the next alarm.
  assert.deepEqual(gaps.slice(0, 6), [30_000, 60_000, 120_000, 240_000, 480_000, 600_000]);
  assert.ok(gaps.slice(6).every((g) => g === 600_000), 'capped at 10 minutes');

  answer = async () => ({ unchanged: true });
  tick(600_000);
  assert.equal((await teams.pull('alarm')).checked, true);
  tick(FAST_MS);
  const before = env.downloads;
  await teams.pull('alarm');
  assert.equal(env.downloads, before + 1, 'back to every minute');

  answer = async () => { throw Object.assign(new Error('busy'), { status: 429, code: 'busy', retryAfterMs: 300_000 }); };
  tick(FAST_MS);
  await teams.pull('alarm');
  const busyAt = env.downloads;
  tick(FAST_MS);
  assert.deepEqual(await teams.pull('online'), { skipped: 'wait' }, 'a busy server is not asked early, even back online');
  tick(4 * FAST_MS);
  await teams.pull('alarm');
  assert.equal(env.downloads, busyAt + 1, 'asked again after its Retry-After');
});

test('pull: a restarted service worker checks with the saved device, without asking the account service', async () => {
  const saved = (() => {
    let v = null;
    return { get: async () => v, set: async (x) => { v = structuredClone(x); }, remove: async () => { v = null; } };
  })();
  const first = setup({ cloudState: saved });
  await first.teams.refresh();
  const again = setup({ cloudState: saved });
  again.env.clock = first.env.clock + FAST_MS;
  assert.deepEqual(await again.teams.pull('alarm'), { checked: true, live: true });
  assert.equal(again.env.orgs + again.env.devices, 0, 'no account service call');
  assert.equal(again.env.downloads, 1);
  await again.teams.signedOut();
  assert.equal(await saved.get(), null, 'signing out forgets the device');
  assert.equal(again.env.alarm.at(-1), false);
});

test('pull: a revoked device (401) stops the quick checks until the next refresh', async () => {
  let answer = async () => ({ unchanged: true });
  const { teams, env, tick } = setup({ download: (...a) => answer(...a) });
  await teams.refresh();
  answer = async () => { throw Object.assign(new Error('revoked'), { status: 401, code: 'signed_out' }); };
  tick(FAST_MS);
  assert.deepEqual(await teams.pull('alarm'), { checked: true, live: false });
  assert.equal(env.alarm.at(-1), false);
});
