// The master password tip of the vault in this browser (src/shared/vault-mode.js). Only the two booleans (weak,
// dismissed) are ever stored.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  MASTER_TIP_KEY, clearMasterTip, dismissMasterTip, masterTipAfterUnlock, masterTipVisible, sanitizeMasterTips,
} from '../src/shared/vault-mode.js';

test('the storage key is a plain device-local setting name', () => {
  assert.equal(MASTER_TIP_KEY, 'vaultMasterPasswordTip');
});

test('a master password unlock sets the weak flag to the rule\'s answer; a later strong one clears it', () => {
  let tips = masterTipAfterUnlock({}, 'v1', true);
  assert.deepEqual(tips, { v1: { weak: true } });
  assert.equal(masterTipVisible(tips, 'v1'), true);
  // Changed on another device: the next unlock here passes the rule.
  tips = masterTipAfterUnlock(tips, 'v1', false);
  assert.deepEqual(tips, {}, 'nothing left to keep');
  assert.equal(masterTipVisible(tips, 'v1'), false);
  assert.deepEqual(masterTipAfterUnlock({}, 'v1', false), {}, 'a strong one from the start stores nothing');
  assert.deepEqual(masterTipAfterUnlock({}, 'v1', 'yes'), {}, 'only true counts as weak');
});

test('other vaults keep their flags; no vault id changes nothing', () => {
  const tips = { v1: { weak: true }, v2: { weak: true, dismissed: true } };
  assert.deepEqual(masterTipAfterUnlock(tips, 'v1', false), { v2: { weak: true, dismissed: true } });
  assert.deepEqual(masterTipAfterUnlock(tips, null, true), tips);
  assert.deepEqual(dismissMasterTip(tips, ''), tips);
  assert.deepEqual(tips, { v1: { weak: true }, v2: { weak: true, dismissed: true } }, 'the input is not changed');
});

test('Dismiss hides it and the dismissal survives later unlocks with the same weak password', () => {
  let tips = dismissMasterTip(masterTipAfterUnlock({}, 'v1', true), 'v1');
  assert.deepEqual(tips, { v1: { weak: true, dismissed: true } });
  assert.equal(masterTipVisible(tips, 'v1'), false);
  tips = masterTipAfterUnlock(tips, 'v1', true);
  assert.equal(masterTipVisible(tips, 'v1'), false, 'still dismissed');
  tips = masterTipAfterUnlock(tips, 'v1', false);
  assert.deepEqual(tips, { v1: { dismissed: true } }, 'an unlock sets only the weak flag');
  assert.equal(masterTipVisible(tips, 'v1'), false);
});

test('changing the master password (or the vault leaving this browser) clears both flags', () => {
  const tips = { v1: { weak: true, dismissed: true }, v2: { weak: true } };
  const cleared = clearMasterTip(tips, 'v1');
  assert.deepEqual(cleared, { v2: { weak: true } });
  assert.equal(masterTipVisible(cleared, 'v1'), false);
  // A weak one again later shows the tip again (the earlier dismissal is gone).
  assert.equal(masterTipVisible(masterTipAfterUnlock(cleared, 'v1', true), 'v1'), true);
});

test('visible only while weak and not dismissed', () => {
  assert.equal(masterTipVisible({ v1: { weak: true } }, 'v1'), true);
  assert.equal(masterTipVisible({ v1: { weak: true, dismissed: true } }, 'v1'), false);
  assert.equal(masterTipVisible({ v1: { dismissed: true } }, 'v1'), false);
  assert.equal(masterTipVisible({}, 'v1'), false);
  assert.equal(masterTipVisible({ v2: { weak: true } }, 'v1'), false, 'per vault');
  assert.equal(masterTipVisible(null, 'v1'), false);
  assert.equal(masterTipVisible(undefined, undefined), false);
});

test('stored values are checked: only the two flags, only true, nothing else kept', () => {
  assert.deepEqual(sanitizeMasterTips(null), {});
  assert.deepEqual(sanitizeMasterTips('weak'), {});
  assert.deepEqual(sanitizeMasterTips([{ weak: true }]), {});
  assert.deepEqual(sanitizeMasterTips({
    v1: { weak: true, score: 1, password: 'x', issues: ['common'] },
    v2: { weak: 'true', dismissed: 1 },
    v3: null,
    v4: { dismissed: true },
  }), { v1: { weak: true }, v4: { dismissed: true } });
  assert.equal(masterTipVisible({ v1: { weak: 1 } }, 'v1'), false);
});
