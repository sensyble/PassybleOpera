// Texts for the desktop app's `password.check` answer, which carries no secrets.
import { t, tp } from './i18n.js';

export const CHECK_DEBOUNCE_MS = 350;

const KEYS = Object.freeze({
  common: 'issueCommon',
  weak: 'issueWeak',
  used_before: 'issueUsedBefore',
  contains_username: 'issueContainsUsername',
  contains_site: 'issueContainsSite',
});

const SEVERITIES = Object.freeze(['high', 'medium', 'low']);

/** The issues of a `password.check` answer as `{ code, severity, text }`, most important first. */
export function issueTexts(check) {
  const issues = Array.isArray(check?.issues) ? check.issues : [];
  const out = [];
  for (const issue of issues) {
    if (!issue || typeof issue.code !== 'string') continue;
    const severity = SEVERITIES.includes(issue.severity) ? issue.severity : 'medium';
    let text = '';
    if (issue.code === 'reused') {
      const count = Number.isInteger(issue.count) && issue.count > 0 ? issue.count : 1;
      text = tp('issueReused', count);
    } else if (issue.code === 'short') {
      text = t('issueShort', Number.isInteger(issue.min_length) && issue.min_length > 0 ? issue.min_length : 12);
    } else if (KEYS[issue.code]) {
      text = t(KEYS[issue.code]);
    } else {
      continue; // a newer desktop app's check this extension doesn't know yet
    }
    out.push({ code: issue.code, severity, text });
  }
  return out;
}

export function wantsStrongPassword(check) {
  return issueTexts(check).some((i) => i.severity !== 'low');
}

export function looksStrong(check) {
  return !!check && issueTexts(check).length === 0 && Number(check.score) >= 3;
}
