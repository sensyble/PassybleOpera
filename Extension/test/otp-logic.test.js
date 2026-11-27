import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  looksLike2faPage, shouldOfferPendingOtp, decideOtpAction, decideShortcutAction, pickTotpItem,
  secondsLeft, formatCode, PENDING_OTP_WINDOW_MS, TOAST_DELAY_MS, SKIP_DETECT_MS, OTP_ON_DEMAND_MS,
  latePendingOtp, looksLikeLoginPath, looksSignedIn,
} from '../src/shared/otp-logic.js';

test('2FA page text detection (several languages) and non-2FA pages', () => {
  for (const t of [
    'Enter the 6-digit code from your authenticator app',
    'Two-factor authentication',
    '2-Step Verification: Verify it’s you',
    'Please enter your verification code',
    'Geben Sie den Bestätigungscode ein',
    'Saisissez le code de vérification',
    'Introduce el código de verificación',
    '認証コードを入力してください',
  ]) assert.ok(looksLike2faPage(t), t);
  for (const t of ['Welcome back! Your inbox', 'Sign in to GitHub', 'Shopping cart (2 items)', '']) {
    assert.ok(!looksLike2faPage(t), t);
  }
});

const pending = { id: 'gh', title: 'GitHub' };

test('pending OTP is offered unless it was already filled inline or consumed', () => {
  const now = 1_000_000;
  assert.equal(shouldOfferPendingOtp({ pending: null, record: null, now }), false);
  assert.equal(shouldOfferPendingOtp({ pending, record: null, now }), true, 'agent knows about it: offer');
  assert.equal(shouldOfferPendingOtp({ pending, record: { itemId: 'gh', at: now - 1000 }, now }), true);
  assert.equal(shouldOfferPendingOtp({ pending, record: { itemId: 'gh', at: now - 1000, otpFilledInline: true }, now }), false);
  assert.equal(shouldOfferPendingOtp({ pending, record: { itemId: 'gh', at: now - 1000, consumed: true }, now }), false);
  assert.equal(shouldOfferPendingOtp({ pending, record: { itemId: 'gh', at: now - PENDING_OTP_WINDOW_MS - 1 }, now }), false);
  assert.equal(shouldOfferPendingOtp({ pending, record: { itemId: 'other', at: now, consumed: true }, now }), true);
});

const base = { offer: true, hasOtpField: false, autoFillOtp: false, canAutoFill: true, elapsedMs: 0,
  pageLooks2fa: false, isTopFrame: true, otpFieldElsewhere: false, toastShown: false };

test('OTP field present: offer first, or auto-fill when enabled and allowed', () => {
  assert.equal(decideOtpAction({ ...base, hasOtpField: true }), 'offer');
  assert.equal(decideOtpAction({ ...base, hasOtpField: true, autoFillOtp: true }), 'autofill');
  assert.equal(decideOtpAction({ ...base, hasOtpField: true, autoFillOtp: true, canAutoFill: false }), 'offer');
  assert.equal(decideOtpAction({ ...base, hasOtpField: true, isTopFrame: false }), 'offer');
});

test('no OTP field: wait a moment, then toast only if the page reads like a 2FA step', () => {
  assert.equal(decideOtpAction({ ...base, elapsedMs: 1000, pageLooks2fa: true }), 'wait');
  assert.equal(decideOtpAction({ ...base, elapsedMs: TOAST_DELAY_MS, pageLooks2fa: true }), 'toast');
  assert.equal(decideOtpAction({ ...base, elapsedMs: TOAST_DELAY_MS + 1, pageLooks2fa: false }), 'wait');
  assert.equal(decideOtpAction({ ...base, elapsedMs: PENDING_OTP_WINDOW_MS + 1, pageLooks2fa: true }), 'none');
});

test('toast is top-frame only, once, and not when another frame has the field', () => {
  const late = { ...base, elapsedMs: TOAST_DELAY_MS + 100, pageLooks2fa: true };
  assert.equal(decideOtpAction({ ...late, isTopFrame: false }), 'wait');
  assert.equal(decideOtpAction({ ...late, toastShown: true }), 'wait');
  assert.equal(decideOtpAction({ ...late, otpFieldElsewhere: true }), 'wait');
});

test('nothing happens without an offer', () => {
  assert.equal(decideOtpAction({ ...base, offer: false, hasOtpField: true }), 'none');
  assert.equal(decideOtpAction({ ...base, offer: false, elapsedMs: 9000, pageLooks2fa: true }), 'none');
});

test('shortcut: fill when a field exists, toast otherwise; pending item wins', () => {
  const items = [{ id: 'a', title: 'A', has_totp: false }, { id: 'b', title: 'B', has_totp: true }, { id: 'c', title: 'C', has_totp: true }];
  assert.deepEqual(decideShortcutAction({ hasOtpField: true, pending: null, items }), { action: 'fill', id: 'b', title: 'B' });
  assert.deepEqual(decideShortcutAction({ hasOtpField: false, pending: null, items }), { action: 'toast', id: 'b', title: 'B' });
  assert.deepEqual(decideShortcutAction({ hasOtpField: false, pending, items }), { action: 'toast', id: 'gh', title: 'GitHub' });
  assert.equal(decideShortcutAction({ hasOtpField: true, pending: null, items: [items[0]] }), null);
  assert.equal(pickTotpItem({ pending: null, items: undefined }), null);
});

test('countdown and code formatting', () => {
  const reading = { remaining_secs: 20, period: 30 };
  assert.equal(secondsLeft(reading, 0, 0), 20);
  assert.equal(secondsLeft(reading, 0, 5_400), 15);
  assert.equal(secondsLeft(reading, 0, 25_000), 0);
  assert.equal(secondsLeft({ remaining_secs: 99, period: 30 }, 0, 0), 30);
  assert.equal(formatCode('123456'), '123 456');
  assert.equal(formatCode('12345678'), '1234 5678');
  assert.equal(formatCode('12345'), '12345');
  assert.equal(formatCode('ABCDE'), 'ABCDE');
});

test('signed in without a 2FA step: "skipped" once the page settled, never before', () => {
  const signedIn = { ...base, signedIn: true };
  assert.equal(decideOtpAction({ ...signedIn, elapsedMs: 2000, settledMs: 2000 }), 'wait');
  assert.equal(decideOtpAction({ ...signedIn, elapsedMs: SKIP_DETECT_MS + 5000, settledMs: SKIP_DETECT_MS - 1 }), 'wait', 'a submission restarts the check');
  assert.equal(decideOtpAction({ ...signedIn, elapsedMs: SKIP_DETECT_MS, settledMs: SKIP_DETECT_MS }), 'skipped');
  assert.equal(decideOtpAction({ ...signedIn, elapsedMs: SKIP_DETECT_MS }), 'skipped', 'settledMs defaults to elapsedMs');
  assert.equal(decideOtpAction({ ...signedIn, elapsedMs: SKIP_DETECT_MS, isTopFrame: false }), 'wait', 'top frame decides');
  assert.equal(decideOtpAction({ ...signedIn, elapsedMs: SKIP_DETECT_MS, otpFieldElsewhere: true }), 'wait');
  assert.equal(decideOtpAction({ ...base, elapsedMs: SKIP_DETECT_MS + 1 }), 'wait', 'not signed in (yet)');
});

test('after a skip only a code field gets the code; no toast', () => {
  const skipped = { ...base, skipped: true, elapsedMs: SKIP_DETECT_MS + 1, pageLooks2fa: true };
  assert.equal(decideOtpAction(skipped), 'none');
  assert.equal(decideOtpAction({ ...skipped, hasOtpField: true, autoFillOtp: true }), 'autofill');
  assert.equal(decideOtpAction({ ...skipped, hasOtpField: true }), 'offer');
});

test('quiet (the site usually skips 2FA): code field still filled, wording alone shows nothing', () => {
  const quiet = { ...base, quiet: true, elapsedMs: TOAST_DELAY_MS + 100 };
  assert.equal(decideOtpAction({ ...quiet, pageLooks2fa: true }), 'wait', 'no toast');
  assert.equal(decideOtpAction({ ...quiet, hasOtpField: true, autoFillOtp: true }), 'autofill');
  assert.equal(decideOtpAction({ ...quiet, signedIn: true, elapsedMs: SKIP_DETECT_MS }), 'skipped', 'still learns');
});

test('late offer (agent window over): offered in the menu, never auto-filled or toasted', () => {
  const late = { ...base, late: true, autoFillOtp: true, elapsedMs: TOAST_DELAY_MS + 100 };
  assert.equal(decideOtpAction({ ...late, hasOtpField: true }), 'offer');
  assert.equal(decideOtpAction({ ...late, pageLooks2fa: true }), 'wait');
});

test('latePendingOtp: the tab\'s fill, for this site, within 5 minutes, code not used', () => {
  const now = 10_000_000;
  const items = [{ id: 'gh', title: 'GitHub', has_totp: true }, { id: 'np', title: 'No 2FA', has_totp: false }];
  const rec = (patch = {}) => ({ itemId: 'gh', at: now - PENDING_OTP_WINDOW_MS - 1000, ...patch });
  assert.deepEqual(latePendingOtp({ record: rec(), items, now }), { id: 'gh', title: 'GitHub' });
  assert.equal(latePendingOtp({ record: null, items, now }), null);
  assert.equal(latePendingOtp({ record: rec({ at: now - OTP_ON_DEMAND_MS - 1 }), items, now }), null, 'too old');
  assert.equal(latePendingOtp({ record: rec({ at: now + 1 }), items, now }), null, 'clock moved back');
  assert.equal(latePendingOtp({ record: rec({ consumed: true }), items, now }), null);
  assert.equal(latePendingOtp({ record: rec({ otpFilledInline: true }), items, now }), null);
  assert.equal(latePendingOtp({ record: rec({ itemId: 'np' }), items, now }), null, 'login without 2FA');
  assert.equal(latePendingOtp({ record: rec({ itemId: 'elsewhere' }), items, now }), null, 'not a login of this site');
});

test('sign-in URLs and signed-in pages', () => {
  for (const u of ['https://github.com/login', 'https://github.com/sessions/two-factor', 'https://accounts.google.com/v3/signin/challenge/totp',
    'https://login.example.com/oauth2/authorize', 'https://x.com/i/flow/login', 'https://app.example.com/#/auth/mfa', 'https://example.com/account/verify']) {
    assert.ok(looksLikeLoginPath(u), u);
  }
  for (const u of ['https://github.com/', 'https://mail.example.com/inbox', 'https://example.com/dashboard?tab=home', 'not a url']) {
    assert.ok(!looksLikeLoginPath(u), u);
  }
  const quietPage = { hasOtpField: false, wording: false, passwordShown: false, loginPath: false };
  assert.equal(looksSignedIn(quietPage), true);
  for (const k of Object.keys(quietPage)) assert.equal(looksSignedIn({ ...quietPage, [k]: true }), false, k);
});
