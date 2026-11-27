// Linked vaults: pure display helpers shared by app mode and the browser vault's shared vaults.
// An answer without a `vaults` table is one vault: no vault names are shown and every item may be revealed and edited.

const ROLES = Object.freeze(['manage', 'edit', 'view', 'fill']);
const KINDS = new Set(['personal', 'org', 'direct', 'emergency']);
const MAX_NAME = 120;

export function vaultRef(v) {
  if (!v || typeof v !== 'object' || typeof v.id !== 'string' || !v.id) return null;
  const role = ROLES.includes(v.role) ? v.role : null;
  return {
    id: v.id,
    name: typeof v.name === 'string' ? v.name.slice(0, MAX_NAME) : '',
    home: v.home === true,
    kind: KINDS.has(v.kind) ? v.kind : (v.home === true ? 'personal' : 'org'),
    role,
    // Missing flags allow everything; the agent enforces the roles anyway.
    can_edit: v.can_edit !== false,
    can_reveal: v.can_reveal !== false,
  };
}

/** One Map id -> VaultRef from any number of `vaults` lists; the first list's order wins. */
export function vaultTable(...lists) {
  const table = new Map();
  for (const list of lists) {
    if (!Array.isArray(list)) continue;
    for (const v of list) {
      const ref = vaultRef(v);
      if (ref && !table.has(ref.id)) table.set(ref.id, ref);
    }
  }
  const home = [...table.values()].find((v) => v.home);
  if (home && table.keys().next().value !== home.id) {
    const rest = [...table.values()].filter((v) => v !== home);
    return new Map([[home.id, home], ...rest.map((v) => [v.id, v])]);
  }
  return table;
}

/** More than one vault open: only then are vault names shown. */
export function isMultiVault(table) {
  return !!table && table.size > 1;
}

function vaultOf(item, table) {
  if (!item || !table || typeof item.vault_id !== 'string') return null;
  return table.get(item.vault_id) || null;
}

export function vaultLabel(item, table) {
  if (!isMultiVault(table)) return '';
  return vaultOf(item, table)?.name || '';
}

export function canReveal(item, table) {
  if (item && item.can_reveal === false) return false;
  return vaultOf(item, table)?.can_reveal !== false;
}

export function canEdit(item, table) {
  if (item && item.can_edit === false) return false;
  return vaultOf(item, table)?.can_edit !== false;
}

/** `reveal`, `edit`, `view` (read-only editor) and `open` (any editor; not for fill members, whose `logins.get_for_edit` answers `fill_only`). */
export function itemRights(item, table) {
  const reveal = canReveal(item, table);
  const edit = canEdit(item, table);
  return { reveal, edit, view: !edit && reveal, open: reveal };
}

/** `can_edit: true` said outright (a missing flag doesn't count), and not opened through emergency access. */
function isEditableVault(v) {
  return !!v && v.can_edit === true && v.role !== 'view' && v.role !== 'fill' && v.kind !== 'emergency';
}

function editableVaults(list) {
  return [...vaultTable(list.filter(isEditableVault)).values()];
}

/** `{ vaults, selected }` when there are two or more vaults to pick from, else null. */
export function newLoginVaultChoice(answer) {
  const vaults = editableVaults(Array.isArray(answer?.vaults) ? answer.vaults : []);
  if (vaults.length < 2) return null;
  const preferred = typeof answer?.default_vault === 'string' ? answer.default_vault : '';
  const selected = vaults.some((v) => v.id === preferred) ? preferred : vaults[0].id;
  return { vaults: vaults.map(({ id, name }) => ({ id, name })), selected };
}

/** `vault` as a request may carry it: an id of `choice`, else undefined (the agent's default). */
export function chosenVault(choice, vault) {
  if (!choice || typeof vault !== 'string' || !vault) return undefined;
  return choice.vaults.some((v) => v.id === vault) ? vault : undefined;
}

const MAX_PINS = 5;

function usable(lists) {
  return lists.map((list) => (Array.isArray(list) ? list.filter((v) => v && typeof v === 'object' && !v.error) : []));
}

export function filterVaults(...lists) {
  return vaultTable(...usable(lists));
}

/** Entries of `vaults.list` with `open: false` are left out; VaultRefs (which have no `open`) count as open. */
export function moveTargets(...lists) {
  return editableVaults(usable(lists).flat().filter((v) => v.open !== false));
}

export function pinsOf(answer) {
  const pins = Array.isArray(answer?.pins) ? answer.pins.filter((id) => typeof id === 'string' && id) : [];
  const max = Number.isInteger(answer?.max) && answer.max > 0 ? answer.max : MAX_PINS;
  return { pins, max };
}

/** Active vault first, then pinned entries in pin order, then the rest in their own order. */
export function pinnedFirst(list, pins, key = 'id', isActive = () => false) {
  const at = new Map();
  for (const [i, id] of (pins || []).entries()) if (!at.has(id)) at.set(id, i);
  const active = list.filter((v) => isActive(v));
  const rest = list.filter((v) => !isActive(v));
  const pinned = rest.filter((v) => at.has(v?.[key])).sort((a, b) => at.get(a[key]) - at.get(b[key]));
  return [...active, ...pinned, ...rest.filter((v) => !at.has(v?.[key]))];
}

/** Every id of `pins` stays, also vaults this browser doesn't show; null when a new pin would pass `max`. */
export function togglePin({ pins, max }, id, on) {
  if (!on) return pins.filter((p) => p !== id);
  if (pins.includes(id)) return pins;
  return pins.length >= max ? null : [...pins, id];
}

const ROLE_KEYS = Object.freeze({
  manage: 'teamsRoleManage',
  edit: 'teamsRoleEdit',
  view: 'teamsRoleView',
  fill: 'teamsRoleFill',
});

function roleKey(role) {
  return ROLE_KEYS[role] || '';
}

// The shared vault status codes of `vaults.list` (`teams_errors`), and the browser vault's own.
const TEAMS_ERROR_KEYS = Object.freeze({
  no_keyset: 'teamsErrNoKeyset',
  not_a_member: 'teamsErrNotMember',
  keys_mismatch: 'teamsErrKeysMismatch',
  untrusted: 'teamsErrUntrusted',
  rollback: 'teamsErrRollback',
  read_only_member: 'teamsErrReadOnlyMember',
  subscription_inactive: 'teamsErrSubscriptionInactive',
  account_suspended: 'teamsErrAccountSuspended',
  vault_limit: 'teamsErrVaultLimit',
  network: 'teamsErrNetwork',
  busy: 'teamsErrNetwork',
  internal: 'teamsErrInternal',
});

export function teamsErrorKey(code) {
  return TEAMS_ERROR_KEYS[code] || 'teamsErrInternal';
}

/** Codes the user can't fix in the browser: say "open Passyble" for them (keys, trust, membership). */
const FIX_IN_APP = new Set(['no_keyset', 'keys_mismatch', 'untrusted', 'rollback']);

function count(n) {
  const v = Number(n);
  return Number.isFinite(v) && v > 0 ? Math.floor(v) : 0;
}

/** The popup's "Shared with me" section from `vaults.list` or the browser vault's teams model (same shape). */
export function sharedWithMe(list) {
  const vaults = [];
  for (const raw of Array.isArray(list?.vaults) ? list.vaults : []) {
    const ref = vaultRef(raw);
    // Someone's vault opened through emergency access (until the next lock) isn't shared with the user.
    if (!ref || ref.home || ref.kind === 'emergency') continue;
    const code = raw.error && typeof raw.error === 'object' && typeof raw.error.code === 'string' ? raw.error.code : '';
    vaults.push({
      id: ref.id, name: ref.name, kind: ref.kind, role: ref.role, roleKey: roleKey(ref.role),
      items: count(raw.items), open: raw.open === true,
      errorCode: code, errorKey: code ? teamsErrorKey(code) : '', fixInApp: FIX_IN_APP.has(code),
    });
  }
  const teams = list?.teams && typeof list.teams === 'object' ? list.teams : null;
  const invites = count(teams?.invites);
  const toConfirm = count(teams?.to_confirm);
  const notices = count(teams?.notices);
  return {
    show: vaults.length > 0 || invites > 0 || toConfirm > 0 || notices > 0,
    vaults,
    open: vaults.filter((v) => v.open).length,
    errors: vaults.filter((v) => v.errorCode).length,
    invites,
    toConfirm,
    notices,
  };
}

const MAX_POLICY_TEXT = 400;

/** The Team password rule (`password_policy`, texts in the desktop app's language) while it isn't met, else null. */
export function passwordPolicy(list) {
  const p = list?.password_policy;
  if (!p || typeof p !== 'object' || !['second_password', 'one_password'].includes(p.mode) || p.action_needed !== true) return null;
  const text = (v) => (typeof v === 'string' ? v.trim().slice(0, MAX_POLICY_TEXT) : '');
  const title = text(p.title);
  return title ? { title, message: text(p.message) } : null;
}

export function teamsSection(model) {
  if (!model) return 'shared';
  if (model.toConfirm) return 'confirm';
  if (model.invites) return 'invites';
  if (model.notices) return 'notices';
  return 'shared';
}
