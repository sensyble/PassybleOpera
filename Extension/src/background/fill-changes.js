// "Update this login?" after the user typed over a filled login and submitted. The record of the last fill
// keeps the password only as a SHA-256 with the frame's origin, so nothing here can give it back; memory
// only, one per tab, and content scripts never see it.
import { createGeneratedPasswords } from './generated.js';

export const FILLED_TTL_MS = 10 * 60_000;

export async function filledLogin({ itemId, origin, frameId = 0, result, cross = false, now = () => Date.now() }) {
  const password = typeof result?.password === 'string' ? result.password : '';
  const passwords = createGeneratedPasswords({ now });
  await passwords.remember(origin, password);
  const vault = result?.vault && typeof result.vault === 'object' ? result.vault : null;
  return {
    itemId: String(itemId), origin, frameId,
    username: typeof result?.username === 'string' ? result.username : '',
    hasPassword: !!password, passwords,
    canEdit: vault?.can_edit !== false,
    // A fill-only member's password is for the page only, never a new login of the user's.
    noReveal: vault?.can_reveal === false,
    cross: !!cross,
    title: typeof result?.title === 'string' ? result.title.slice(0, 256) : '',
    at: now(),
  };
}

export function liveFilled(filled, origin, now = Date.now()) {
  if (!filled || now - filled.at > FILLED_TTL_MS) return null;
  return filled.origin === origin ? filled : null;
}

function sameName(a, b) {
  const x = String(a ?? '').trim().toLowerCase();
  return x !== '' && x === String(b ?? '').trim().toLowerCase();
}

/** What the submit changed of the fill, or null when nothing did (including values changed back). */
export async function changesOf(filled, save) {
  const typed = String(save.username ?? '').trim();
  const username = typed && !sameName(typed, filled.username) ? typed : '';
  const password = !!save.password && !(filled.hasPassword && (await filled.passwords.matches(filled.origin, save.password)));
  return username || password ? { username, password } : null;
}

/**
 * Whether the submit gets "Update this login?" (`card`) or the usual banner. The agent knows the logins, so
 * its answer wins where it names another one. A cross fill's login is never the page's, so only `save_new`
 * gives the card there.
 */
export function changedPlan({ decided, filledId, changes }) {
  if (!changes || !decided) return 'usual';
  const mine = decided.id != null && String(decided.id) === String(filledId);
  switch (decided.action) {
    case 'none':
      return mine ? 'card' : 'usual';
    case 'update_password':
      return mine && changes.username ? 'card' : 'usual';
    case 'update_username':
      return mine ? 'card' : 'usual';
    case 'save_new':
      return 'card';
    default:
      return 'usual';
  }
}
