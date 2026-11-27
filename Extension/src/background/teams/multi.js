// Turns the WebAssembly's cross-vault lists into the protocol answers the desktop agent gives with linked
// vaults (`vault_id` per item, a `vaults` table, home first). Pure functions, tested without WebAssembly.

export function homeRef(summaries, name) {
  return { id: String(summaries?.vault_id || ''), name: String(name || ''), home: true, kind: 'personal', role: null, can_edit: true, can_reveal: true };
}

/** The VaultRef of a shared vault: never wider than the server lets this account write (`writable`). */
export function sharedRef(summaries, entry, { writable = true } = {}) {
  const kind = summaries?.shared === 'direct' || entry?.kind === 'direct' ? 'direct' : 'org';
  const role = ['manage', 'edit', 'view', 'fill'].includes(summaries?.role) ? summaries.role : null;
  return {
    id: String(summaries?.vault_id || entry?.vault_id || ''),
    name: String(entry?.label || '').slice(0, 120),
    home: false,
    kind,
    role,
    can_edit: summaries?.can_edit === true && writable !== false,
    can_reveal: summaries?.can_reveal !== false,
  };
}

export function groupsJson(groups) {
  return JSON.stringify(groups.filter(Boolean));
}

/** Rights follow `ref`: the server's word wins over the members list. */
export function withRights(summaries, ref) {
  return { ...summaries, can_edit: !!ref?.can_edit, can_reveal: ref?.can_reveal !== false };
}

function itemOfSummary(summary, vaultId, { domain = false } = {}) {
  const item = {
    id: String(summary.id), title: String(summary.title || ''), username: String(summary.username || ''),
    has_totp: !!summary.has_totp, has_passkey: Array.isArray(summary.passkeys) && summary.passkeys.length > 0,
    vault_id: vaultId,
  };
  if (domain) item.domain = String(summary.domain || '');
  return item;
}

function tableFor(items, refs) {
  const used = new Set(items.map((i) => i.vault_id));
  return refs.filter((r) => used.has(r.id));
}

/**
 * `logins.find` across vaults in multiForUrl's order. Home items come from the home agent's answer (it knows
 * more), shared ones from their summaries. Logins only: cards and identities stay in the home vault's lists.
 */
export function mergeFind(hits, home, refs) {
  const homeId = refs.find((r) => r.home)?.id;
  const homeItems = new Map((home?.items || []).map((i) => [i.id, i]));
  const items = [];
  const seen = new Set();
  for (const hit of Array.isArray(hits) ? hits : []) {
    const s = hit?.summary;
    if (!s || typeof s.id !== 'string' || seen.has(s.id)) continue;
    if (s.kind && s.kind !== 'login') continue;
    if (hit.vault_id === homeId) {
      const own = homeItems.get(s.id);
      if (!own) continue; // the home agent left it out (it knows better): so do we
      items.push({ ...own, vault_id: homeId });
    } else if (refs.some((r) => r.id === hit.vault_id)) {
      items.push(itemOfSummary(s, hit.vault_id));
    } else {
      continue;
    }
    seen.add(s.id);
  }
  for (const own of homeItems.values()) if (!seen.has(own.id)) items.push({ ...own, vault_id: homeId });
  return { ...home, items, vaults: tableFor(items, refs) };
}

export function mergeSearch(hits, home, refs, limit) {
  const homeId = refs.find((r) => r.home)?.id;
  const homeItems = new Map((home?.items || []).map((i) => [i.id, i]));
  const items = [];
  let more = !!home?.truncated;
  for (const hit of Array.isArray(hits) ? hits : []) {
    const s = hit?.summary;
    if (!s || typeof s.id !== 'string') continue;
    if (s.kind && s.kind !== 'login') continue;
    let item = null;
    if (hit.vault_id === homeId) item = homeItems.has(s.id) ? { ...homeItems.get(s.id), vault_id: homeId } : null;
    else if (refs.some((r) => r.id === hit.vault_id)) item = itemOfSummary(s, hit.vault_id, { domain: true });
    if (!item) continue;
    if (items.length >= limit) { more = true; break; }
    items.push(item);
  }
  return { items, truncated: more, locked: !!home?.locked, vaults: tableFor(items, refs) };
}

export function vaultIdOf(groups, id) {
  for (const g of groups) if ((g?.summaries || []).some((s) => s.id === id)) return g.vault_id;
  return null;
}

/** `logins.save_check` across vaults: an update is offered only in a vault the user can edit. */
export function mergeSaveCheck(home, shared, { refs, username, defaultVault }) {
  if (home?.action === 'none') return home;
  if (shared.some((s) => s.same && (!username || sameName(s.username, username)))) {
    const hit = shared.find((s) => s.same);
    return { action: 'none', id: hit.id, title: hit.title, vault: hit.ref };
  }
  const homeRefOf = refs.find((r) => r.home);
  if (home?.action === 'update_password' || home?.action === 'update_username') return { ...home, vault: homeRefOf };
  const named = shared.find((s) => s.ref.can_edit && username && sameName(s.username, username) && !s.same);
  if (named) return { action: 'update_password', id: named.id, title: named.title, vault: named.ref };
  const vaults = refs.filter((r) => r.can_edit);
  return { ...(home || {}), action: 'save_new', vaults, default_vault: vaults.some((v) => v.id === defaultVault) ? defaultVault : (vaults[0]?.id ?? null) };
}

export function urlRulesOf(item) {
  const urls = new Set(Array.isArray(item?.urls) ? item.urls : []);
  return (Array.isArray(item?.url_rules) ? item.url_rules : [])
    .filter((r) => r && urls.has(r.url) && (r.rule === 'host' || r.rule === 'never'))
    .map(({ url, rule }) => ({ url, rule }));
}

/** Summaries matched as if they had no website rules: a login picked by hand is checked against these. */
export function withoutRules(summaries) {
  if (!summaries) return summaries;
  return { ...summaries, summaries: (summaries.summaries || []).map(({ url_rules: _rules, ...s }) => s) };
}

function sameName(a, b) {
  return String(a || '').trim().toLowerCase() === String(b || '').trim().toLowerCase();
}

export function newLoginItem({ url, username, password, title = '', notes = '', urls = null, totp = null }) {
  let origin = '';
  let host = '';
  try {
    const u = new URL(url);
    origin = u.origin;
    host = u.hostname.replace(/^www\./, '');
  } catch { /* no website */ }
  const item = { kind: 'login', title: String(title || host), username: String(username || ''), password: String(password || ''),
    urls: Array.isArray(urls) ? urls.map(String) : origin ? [origin] : [], notes: String(notes || '') };
  if (typeof totp === 'string' && totp) item.totp = totp;
  return item;
}

export function applyFields(item, fields) {
  const next = { ...item };
  for (const k of ['title', 'username', 'password', 'notes']) if (typeof fields?.[k] === 'string') next[k] = fields[k];
  if (Array.isArray(fields?.urls)) next.urls = fields.urls.map(String);
  if (Array.isArray(fields?.url_rules)) next.url_rules = urlRulesOf({ urls: next.urls, url_rules: fields.url_rules });
  if (fields && 'totp' in fields) {
    if (fields.totp === null) delete next.totp;
    else if (typeof fields.totp === 'string') next.totp = fields.totp;
  }
  return next;
}
