// Tracks generated passwords per tab so a submit can auto-save them. Memory only, expires after
// GENERATED_TTL_MS, and keeps just a SHA-256 of origin and password.

export const GENERATED_TTL_MS = 30 * 60_000;
const MAX_GENERATED = 8;

/** Hex SHA-256 of origin and password, separated by a NUL (no origin ends in one). */
async function digest(origin, password) {
  const bytes = new TextEncoder().encode(`${origin}\u0000${password}`);
  const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** One tab's generated passwords: `matches` is true for exactly this password and origin within the TTL. */
export function createGeneratedPasswords({ now = () => Date.now() } = {}) {
  let entries = [];

  const prune = () => {
    const t = now();
    entries = entries.filter((e) => t - e.at < GENERATED_TTL_MS);
  };

  return {
    async remember(origin, password) {
      if (typeof password !== 'string' || !password || !origin || origin === 'null') return;
      const hash = await digest(origin, password);
      prune();
      entries = entries.filter((e) => e.hash !== hash);
      entries.push({ hash, at: now() });
      if (entries.length > MAX_GENERATED) entries = entries.slice(-MAX_GENERATED);
    },
    async matches(origin, password) {
      prune();
      if (!entries.length || typeof password !== 'string' || !password || !origin || origin === 'null') return false;
      const hash = await digest(origin, password);
      return entries.some((e) => e.hash === hash);
    },
    get size() {
      prune();
      return entries.length;
    },
  };
}

/**
 * What the submit of a generated password does: `update` an existing login of this username, `create` a new
 * one, or `prompt` with the save banner when the agent's decision (null while locked) can't tell.
 */
export function autoSavePlan(decided, { username = '', siteLogins = null } = {}) {
  if (!decided) return 'prompt';
  if (decided.action === 'update_password') return decided.id ? 'update' : 'prompt';
  if (decided.action !== 'save_new') return 'prompt';
  if (String(username).trim()) return 'create';
  return siteLogins === 0 ? 'create' : 'prompt';
}
