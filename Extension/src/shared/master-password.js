// The master password rule is pass-core's (`check_master_password`); the background's WebAssembly answers it and
// this module only turns the answer (no secrets) into texts. Never re-implement the rule here.
import { t } from './i18n.js';

export const MASTER_CHECK_DEBOUNCE_MS = 150;

/** Only a cheap first filter before asking the WebAssembly: the core decides. */
export const MASTER_MIN_LENGTH = 12;

// In the core's order (MasterPasswordIssue): the one to fix first comes first.
const KEYS = Object.freeze({
  too_short: 'vaultMasterTooShort',
  common: 'vaultMasterCommon',
  contains_name: 'vaultMasterContainsName',
  pattern: 'vaultMasterPattern',
  guessable: 'vaultMasterGuessable',
});

function minLength(check) {
  const n = check?.min_length;
  return Number.isInteger(n) && n > 0 ? n : MASTER_MIN_LENGTH;
}

/** Why the master password is refused, in the core's order. Unknown codes fall back to "Too easy to guess". */
export function masterIssueTexts(check) {
  if (!check || check.ok === true) return [];
  const issues = Array.isArray(check.issues) ? check.issues : [];
  const out = [];
  for (const code of issues) {
    if (typeof code !== 'string' || !KEYS[code] || out.some((i) => i.code === code)) continue;
    out.push({ code, text: code === 'too_short' ? t(KEYS.too_short, minLength(check)) : t(KEYS[code]) });
  }
  if (!out.length && issues.length) out.push({ code: 'guessable', text: t(KEYS.guessable) });
  return out;
}

export function masterOkText(check) {
  if (check?.ok !== true) return '';
  return t('vaultMasterStrongEnough', t(check.label === 'strong' ? 'vaultStrengthStrong' : 'vaultStrengthOk'));
}

export function masterRefusal(check) {
  if (check?.ok === true) return '';
  return masterIssueTexts(check)[0]?.text || t(KEYS.too_short, minLength(check));
}
