import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  LOCAL_REMINDER_SNOOZE_MS, dismissLocalReminder, isDriveRecord, isLocalOnlyVault, localReminderDue,
} from '../src/shared/vault-mode.js';

const DAY = 24 * 3600 * 1000;
const NOW = Date.parse('2026-11-19T12:00:00Z');

test('local only: a vault of this browser with no sync; not without a vault, and not a record that says Google Drive', () => {
  assert.equal(isLocalOnlyVault({ hasVault: true, vaultId: 'v1', source: null }), true);
  assert.equal(isLocalOnlyVault({ hasVault: true, vaultId: 'v1' }), true, 'no source at all: kept only here');
  assert.equal(isLocalOnlyVault({ hasVault: true, vaultId: 'v1', source: '' }), true);
  assert.equal(isLocalOnlyVault({ hasVault: false, vaultId: null, source: null }), false, 'no vault');
  assert.equal(isLocalOnlyVault({ hasVault: true, vaultId: null, source: null }), false, 'a file that did not open has no id');
  assert.equal(isLocalOnlyVault({ hasVault: true, vaultId: 'v1', source: 'drive' }), false, 'it has a copy in Google Drive');
  assert.equal(isLocalOnlyVault(null), false);
  assert.equal(isLocalOnlyVault(undefined), false);
  assert.equal(isDriveRecord({ hasVault: true, vaultId: 'v1', source: 'drive' }), true);
  assert.equal(isDriveRecord({ hasVault: true, vaultId: 'v1', source: null }), false);
  assert.equal(isDriveRecord({ hasVault: false, source: 'drive' }), false);
});

test('the reminder is due until "Not now", then hidden for 30 days for that vault only', () => {
  assert.equal(LOCAL_REMINDER_SNOOZE_MS, 30 * DAY);
  assert.equal(localReminderDue({}, 'v1', NOW), true, 'never dismissed');
  assert.equal(localReminderDue(null, 'v1', NOW), true);
  assert.equal(localReminderDue(undefined, 'v1', NOW), true);
  const dismissed = dismissLocalReminder({}, 'v1', NOW);
  assert.deepEqual(dismissed, { v1: NOW });
  assert.equal(localReminderDue(dismissed, 'v1', NOW), false, 'just dismissed');
  assert.equal(localReminderDue(dismissed, 'v1', NOW + 29 * DAY), false, '29 days later: still hidden');
  assert.equal(localReminderDue(dismissed, 'v1', NOW + 30 * DAY - 1), false);
  assert.equal(localReminderDue(dismissed, 'v1', NOW + 30 * DAY), true, '30 days later: shows again');
  assert.equal(localReminderDue(dismissed, 'v1', NOW + 90 * DAY), true);
  assert.equal(localReminderDue(dismissed, 'v2', NOW), true, 'another vault: its own time');
});

test('dismiss times: odd stored values count as never dismissed; a time in the future counts as just now', () => {
  assert.equal(localReminderDue({ v1: 'yesterday' }, 'v1', NOW), true);
  assert.equal(localReminderDue({ v1: 0 }, 'v1', NOW), true);
  assert.equal(localReminderDue({ v1: -5 }, 'v1', NOW), true);
  assert.equal(localReminderDue('not an object', 'v1', NOW), true);
  // Another clock (or a clock set back): the reminder stays hidden for 30 days from now, not longer.
  assert.equal(localReminderDue({ v1: NOW + 365 * DAY }, 'v1', NOW), false);
});

test('"Not now" again: the newest time wins; entries of other vaults older than 30 days are tidied away', () => {
  const first = dismissLocalReminder({}, 'v1', NOW);
  const later = dismissLocalReminder(first, 'v1', NOW + 40 * DAY);
  assert.deepEqual(later, { v1: NOW + 40 * DAY });
  const mixed = { old: NOW - 31 * DAY, recent: NOW - 2 * DAY, junk: 'x' };
  assert.deepEqual(dismissLocalReminder(mixed, 'v1', NOW), { recent: NOW - 2 * DAY, v1: NOW });
  assert.deepEqual(dismissLocalReminder(null, 'v1', NOW), { v1: NOW });
  assert.deepEqual(dismissLocalReminder({}, 42, NOW), { 42: NOW }, 'the id as text');
});
