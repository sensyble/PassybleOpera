// The mode decision of "the Passyble app always wins" as pure functions (shared/vault-mode.js), and where the setup
// guide starts (welcome/setup-steps.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MISSING_CHECKS, MISS_SPACING_MS, MoveState, browserModeOffered, hostOutcome, moveAfterImport, moveOfferDue,
  nextHostState, sanitizeMove,
} from '../src/shared/vault-mode.js';
import { isHostMissing } from '../src/shared/messages.js';
import { vaultStart } from '../src/welcome/setup-steps.js';

const missing = { message: 'Specified native messaging host not found.' };
const notRunning = { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' };

test('hostOutcome: an answer is connected, "not running" or a timeout is installed, only "host not found" is missing', () => {
  assert.equal(hostOutcome(null, isHostMissing), 'connected');
  assert.equal(hostOutcome(notRunning, isHostMissing), 'installed');
  assert.equal(hostOutcome({ code: 'timeout', message: 'slow' }, isHostMissing), 'installed');
  assert.equal(hostOutcome(missing, isHostMissing), 'missing');
});

test('installed and running, or installed and not running: app mode, from nothing chosen and from browser mode', () => {
  for (const outcome of ['connected', 'installed']) {
    const fresh = nextHostState({}, outcome);
    assert.deepEqual([fresh.mode, fresh.host, fresh.switched, fresh.appGone], ['app', 'present', false, false], outcome);
    const browser = nextHostState({ mode: 'browser', host: 'missing' }, outcome);
    assert.deepEqual([browser.mode, browser.host, browser.switched], ['app', 'present', true], `${outcome}: switched, the move offer follows`);
    const app = nextHostState({ mode: 'app', host: 'present', misses: 2, missAt: 5, appGone: true }, outcome);
    assert.deepEqual([app.mode, app.misses, app.missAt, app.appGone, app.switched], ['app', 0, 0, false, false], 'an answer clears what waited');
  }
  // A browser that can't keep a vault: always app mode, nothing to switch.
  const unsupported = nextHostState({ mode: null }, 'connected', { supported: false });
  assert.deepEqual([unsupported.mode, unsupported.switched], [null, false]);
});

test('missing and never seen: host missing at once (browser mode allowed as before), nothing counted', () => {
  const next = nextHostState({}, 'missing');
  assert.deepEqual([next.mode, next.host, next.misses, next.appGone, next.gone], [null, 'missing', 0, false, false]);
  assert.equal(browserModeOffered({ supported: true, host: next.host }), true);
  assert.equal(browserModeOffered({ supported: true, host: null }), true);
  assert.equal(browserModeOffered({ supported: true, host: 'present' }), false, 'not while the app is installed');
  assert.equal(browserModeOffered({ supported: false, host: 'missing' }), false);
});

test('a flaky single failure after the app was seen: counted once, still installed, wiped by the next answer', () => {
  const now = 1_000_000;
  let s = nextHostState({ mode: 'app', host: 'present' }, 'missing', { now });
  assert.deepEqual([s.host, s.misses, s.missAt, s.appGone], ['present', 1, now, false]);
  // More failures right after: the same check.
  s = nextHostState(s, 'missing', { now: now + 1000 });
  s = nextHostState(s, 'missing', { now: now + MISS_SPACING_MS - 1 });
  assert.equal(s.misses, 1);
  s = nextHostState(s, 'installed', { now: now + 2000 });
  assert.deepEqual([s.host, s.misses, s.mode], ['present', 0, 'app']);
});

test('the app gone: only after MISSING_CHECKS spaced checks; mode unchanged, browser mode offered again', () => {
  let now = 5_000_000;
  let s = { mode: 'app', host: 'present' };
  for (let i = 1; i < MISSING_CHECKS; i++) {
    s = nextHostState(s, 'missing', { now });
    assert.deepEqual([s.host, s.misses, s.gone], ['present', i, false], `check ${i}`);
    now += MISS_SPACING_MS;
  }
  s = nextHostState(s, 'missing', { now });
  assert.deepEqual([s.mode, s.host, s.misses, s.appGone, s.gone], ['app', 'missing', 0, true, true]);
  assert.equal(browserModeOffered({ supported: true, host: s.host }), true);
  // Gone stays gone, said once; the app back clears it.
  const again = nextHostState(s, 'missing', { now: now + MISS_SPACING_MS });
  assert.deepEqual([again.appGone, again.gone], [true, false]);
  assert.equal(nextHostState(again, 'connected').appGone, false);
  // In browser mode an app that went away needs no notice.
  let b = { mode: 'browser', host: 'present' };
  for (let i = 0; i < MISSING_CHECKS; i++) { b = nextHostState(b, 'missing', { now: now + i * MISS_SPACING_MS }); }
  assert.deepEqual([b.mode, b.host, b.appGone], ['browser', 'missing', false]);
});

test('a clock that went back still counts the next failure (never stuck)', () => {
  const s = nextHostState({ mode: 'app', host: 'present', misses: 1, missAt: 9_000_000 }, 'missing', { now: 1000 });
  assert.equal(s.misses, 2);
});

test('the move record: moved when nothing failed (duplicates skipped are fine), partial with the titles that failed', () => {
  const done = moveAfterImport('v1', { total: 23, added: 20, skipped: 3, failed_count: 0, failed: [] }, 42);
  assert.deepEqual(done, { state: 'moved', vault_id: 'v1', count: 23, total: 23, added: 20, skipped: 3, failed_count: 0, failed: [], at: 42 });
  const partial = moveAfterImport('v1', { total: 23, added: 18, skipped: 3, failed_count: 2,
    failed: [{ title: 'Bank', kind: 'login', message: 'bad' }, { title: 'x'.repeat(300), kind: 'note' }] });
  assert.equal(partial.state, MoveState.PARTIAL);
  assert.deepEqual([partial.added, partial.skipped, partial.failed_count, partial.failed[0], partial.failed[1].length], [18, 3, 2, 'Bank', 256]);
  // More failed than named (the app names at most 50): the count wins.
  assert.equal(moveAfterImport('v1', { failed_count: 70, failed: [] }).state, 'partial');
  // Odd answers: numbers only.
  assert.deepEqual(moveAfterImport('v1', { total: -1, added: 'x' }).added, 0);
});

test('sanitizeMove: only known states, for this vault; the popup offers only an unanswered offer in app mode', () => {
  assert.equal(sanitizeMove(null), null);
  assert.equal(sanitizeMove({ state: 'weird' }), null);
  const offer = sanitizeMove({ state: 'offer', vault_id: 'v1', count: 23, failed: ['a', 3] });
  assert.deepEqual([offer.state, offer.count, offer.failed], ['offer', 23, ['a']]);
  assert.equal(sanitizeMove({ state: 'offer', vault_id: 'v1' }, 'v2'), null, 'another vault');
  assert.equal(sanitizeMove({ state: 'offer', vault_id: 'v1' }).count, null, 'count unknown (the vault was locked)');
  assert.equal(moveOfferDue(offer, { mode: 'app', hasVault: true }), true);
  assert.equal(moveOfferDue(offer, { mode: 'browser', hasVault: true }), false);
  assert.equal(moveOfferDue(offer, { mode: 'app', hasVault: false }), false);
  assert.equal(moveOfferDue({ ...offer, state: 'later' }, { mode: 'app', hasVault: true }), false, '"Not now": Options only');
  assert.equal(moveOfferDue({ ...offer, count: 0 }, { mode: 'app', hasVault: true }), false, 'nothing to move');
});

test('setup flow: the app installed skips the choice whatever the hash; without it the choice as before', () => {
  const base = { supported: true, mode: null, host: null, has_vault: false, app_installed: false, app_gone: false };
  // Fresh install, the app installed (running or not): straight to the app checklist.
  for (const hash of ['', 'browser', 'create', 'open', 'sync']) {
    assert.equal(vaultStart({ ...base, mode: 'app', host: 'present', app_installed: true }, hash), 'app', hash);
  }
  // No app found at the first run: the choice (or the form the hash names).
  const noApp = { ...base, host: 'missing' };
  assert.equal(vaultStart(noApp, ''), 'choice');
  assert.equal(vaultStart(noApp, 'create'), 'create');
  assert.equal(vaultStart(noApp, 'open'), 'open');
  assert.equal(vaultStart(noApp, 'sync'), 'drive');
  // Still checking (host unknown): the app checklist, which finds out.
  assert.equal(vaultStart(base, ''), 'app');
  // Browser mode with a vault: ready; app mode after the app went away: the choice again.
  assert.equal(vaultStart({ ...base, mode: 'browser', host: 'missing', has_vault: true }, ''), 'ready');
  assert.equal(vaultStart({ ...base, mode: 'app', host: 'missing', app_gone: true }, ''), 'choice');
  assert.equal(vaultStart({ ...base, mode: 'app', host: 'missing' }, ''), 'app');
  // No browser vault here (an older background, or a browser without it).
  assert.equal(vaultStart(null, 'create'), 'app');
  assert.equal(vaultStart({ ...base, supported: false }, 'create'), 'app');
});
