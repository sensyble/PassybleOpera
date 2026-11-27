// Pure decision logic for the TOTP fallback chain, shared by the background and the content script.

/** The agent keeps a pending OTP for 3 minutes after `logins.fill`. */
export const PENDING_OTP_WINDOW_MS = 3 * 60_000;
/** No fillable code field yet on a page that reads like a 2FA step: wait this long (fields render late) before the toast. */
export const TOAST_DELAY_MS = 3_000;
// Sites that skip 2FA (remembered device): this long after load or submit with no code field, 2FA wording,
// password field or sign-in URL, the user counts as signed in and nothing is shown.
export const SKIP_DETECT_MS = 10_000;
/** After the agent's pending window the filled login's code is still offered on demand, never shown on its own. */
export const OTP_ON_DEMAND_MS = 5 * 60_000;

const TWO_FA_PAGE_RE = new RegExp([
  'authenticator', 'verification code', 'verify (it.?s|that it.?s) you', 'two[- ]?factor', '2[- ]?step',
  'two[- ]?step', '\\b2fa\\b', '\\bmfa\\b', 'multi[- ]?factor', 'one[- ]?time (pass)?code', 'security code',
  'enter (the|your)? ?(\\d[- ]digit )?code', '\\d[- ]digit code', 'login code', 'sign[- ]in code',
  'authentication code', 'otp\\b',
  'bestätigungscode', 'zwei[- ]faktor', 'sicherheitscode', 'code de vérification', 'double authentification',
  'código de verificación', 'verificación en dos pasos', 'código de verificação', 'codice di verifica',
  'verificatiecode', 'tweestapsverificatie', 'kod weryfikacyjny', 'код подтверждения',
  'двухфакторн', '認証コード', '2段階認証', '验证码', '驗證碼', '인증 코드',
].join('|'), 'i');

export function looksLike2faPage(text) {
  if (!text) return false;
  return TWO_FA_PAGE_RE.test(String(text).slice(0, 20_000).replace(/\s+/g, ' '));
}

/** Background side: offer the agent's `pending_otp` on this page? `record` may be null (a fill from the desktop app). */
export function shouldOfferPendingOtp({ pending, record, now }) {
  if (!pending || !pending.id) return false;
  if (record && record.itemId === pending.id) {
    if (record.otpFilledInline || record.consumed) return false;
    if (now - record.at > PENDING_OTP_WINDOW_MS) return false;
  }
  return true;
}

/** Background side: the code of the login filled in this tab, offered on demand after the agent's window ran out. */
export function latePendingOtp({ record, items, now }) {
  if (!record || record.otpFilledInline || record.consumed) return null;
  if (now < record.at || now - record.at > OTP_ON_DEMAND_MS) return null;
  const item = (items || []).find((it) => it.id === record.itemId && it.has_totp);
  return item ? { id: item.id, title: item.title || '' } : null;
}

const LOGIN_PATH_RE = /log-?[io]n|sign-?[io]n|signon|auth|2fa|mfa|otp|two-?factor|2-?step|verif|challenge|checkpoint|\bsso\b|session|passw|recover/i;

export function looksLikeLoginPath(url) {
  let u;
  try { u = new URL(url); } catch { return false; }
  let path = `${u.pathname}${u.hash}`;
  try { path = decodeURIComponent(path); } catch { /* keep it encoded */ }
  return LOGIN_PATH_RE.test(path);
}

export function looksSignedIn({ hasOtpField, wording, passwordShown, loginPath }) {
  return !hasOtpField && !wording && !passwordShown && !loginPath;
}

// Content side: what to do about a pending OTP on the current scan. Nothing is shown unless the 2FA step is
// detected: a code field, or 2FA wording on a sign-in step (then the toast). `quiet`: the site usually skips 2FA,
// so only a code field that shows up gets the code. `late`: past the agent's pending window, offer only.
export function decideOtpAction(s) {
  if (!s.offer) return 'none';
  if (s.hasOtpField) return s.autoFillOtp && s.canAutoFill && !s.late ? 'autofill' : 'offer';
  // A code field that still shows up is handled above (re-checked on DOM changes).
  if (s.skipped) return 'none';
  if (s.elapsedMs > PENDING_OTP_WINDOW_MS) return 'none';
  // Only the top frame shows the toast or decides that 2FA was skipped.
  if (!s.isTopFrame || s.otpFieldElsewhere) return 'wait';
  if (s.pageLooks2fa) {
    if (s.quiet || s.late || s.toastShown) return 'wait';
    return s.elapsedMs >= TOAST_DELAY_MS ? 'toast' : 'wait';
  }
  if (s.signedIn && (s.settledMs ?? s.elapsedMs) >= SKIP_DETECT_MS) return 'skipped';
  return 'wait';
}

/** The OTP shortcut / "Fill 2FA code": fill when there is a field, else the toast; null when no item has a code. */
export function decideShortcutAction({ hasOtpField, pending, items }) {
  const target = pickTotpItem({ pending, items });
  if (!target) return null;
  return { action: hasOtpField ? 'fill' : 'toast', ...target };
}

/** Which item supplies the code: the pending one first, then the best match that has TOTP. */
export function pickTotpItem({ pending, items }) {
  if (pending?.id) return { id: pending.id, title: pending.title || '' };
  const withTotp = (items || []).filter((it) => it.has_totp);
  if (!withTotp.length) return null;
  return { id: withTotp[0].id, title: withTotp[0].title || '' };
}

export function secondsLeft({ remaining_secs: remaining, period }, fetchedAt, now) {
  const elapsed = Math.floor((now - fetchedAt) / 1000);
  const left = remaining - elapsed;
  if (!Number.isFinite(left)) return 0;
  return Math.max(0, Math.min(period || 30, left));
}

export function formatCode(code) {
  const c = String(code || '');
  if (!/^\d+$/.test(c)) return c;
  if (c.length === 6) return `${c.slice(0, 3)} ${c.slice(3)}`;
  if (c.length === 8) return `${c.slice(0, 4)} ${c.slice(4)}`;
  return c;
}
