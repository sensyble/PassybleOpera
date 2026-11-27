// Stand-in for the browser vault's WebAssembly glue (src/wasm/pass_wasm.js): the same exports and JSON
// envelopes as pass-wasm's BrowserAgent, with a plain JSON vault (no crypto). Used when a test sets
// `globalThis.__passFakeWasm` before importing the background, and whenever src/wasm/ isn't built.
const enc = new TextEncoder();
const dec = new TextDecoder();
let kdfCalls = 0;

export const fakeStats = { get kdfCalls() { return kdfCalls; }, instances: 0, masterChecks: 0, masterNames: null, keysFreed: 0, approvedFreed: 0 };

export default async function init() { return {}; }
export function initSync() { return {}; }
export function setKdf() {}

// One Passyble password, test-only: a Secret Key is `P1-` and 30 of [0-9A-Z] in groups of five; a password wrap's `ct`
// is `pw:<hash of password, Secret Key and salt>:<AK hex>`, sealed keys' `sealed:<enc_pub>:<AK hex>:<Secret Key>`;
// an `ak_id` is `ak-<account>-<first 12 hex of AK>`. Errors throw `"<code>: <message>"` as the real bindings do.
const fnv = (text) => {
  let h = 0x811c9dc5;
  for (const c of String(text)) { h ^= c.codePointAt(0); h = Math.imul(h, 0x01000193) >>> 0; }
  return h.toString(16).padStart(8, '0');
};
const thrown = (code, message = code) => new Error(`${code}: ${message}`);
const unhex = (h) => new Uint8Array(String(h).match(/../g).map((x) => parseInt(x, 16)));

export function fakeAkId(account, akHex) { return `ak-${account}-${String(akHex).slice(0, 12)}`; }

function readSk(text) {
  const body = String(text ?? '').toUpperCase().replace(/[\s-]/g, '').replace(/^P1/, '');
  if (!/^[0-9A-Z]{30}$/.test(body)) return null;
  return `P1-${body.match(/.{5}/g).join('-')}`;
}

export function secretKeyText(text) {
  const sk = readSk(text);
  return sk ? ok({ text: sk }) : err('invalid_params', 'This is not a Secret Key');
}

const accessOf = (v) => (v?.account
  ? { kind: 'account', account: v.account.account, ak_id: v.account.ak_id, account_recovery: false }
  : { kind: 'password', account: null, ak_id: null, account_recovery: false });

export function vaultFileAccess(file) {
  try {
    const v = JSON.parse(dec.decode(file));
    if (!v?.id) throw new Error('no');
    return ok(accessOf(v));
  } catch {
    return err('invalid_params', 'This is not a Passyble vault file');
  }
}

export function qrSvgPath(text) {
  return text ? ok({ size: 29, path: `M4 4h1v1h-1z` }) : err('invalid_params');
}

/** A linked vault file (the fake's JSON) for `account` and the AK `akHex`. */
export function fakeLinkedVaultFile(account, akHex, logins = []) {
  return enc.encode(JSON.stringify({
    id: `vault-linked-${fnv(account + akHex)}`, keyHex: hex(keyOf(`vk:${akHex}`)),
    account: { account, ak_id: fakeAkId(account, akHex) }, logins, cards: [],
  }));
}

export class AccountPassword {
  constructor(password, secretKey, salt, kdfJson) {
    let kdf;
    try { kdf = JSON.parse(kdfJson); } catch { throw thrown('invalid_params', 'kdf'); }
    if (kdf?.alg !== 'argon2id' || !(kdf.m_kib >= 65536) || !(kdf.t >= 3)) throw thrown('invalid_params', 'unsafe parameters');
    const sk = readSk(secretKey);
    if (!sk) throw thrown('invalid_params', 'This is not a Secret Key');
    kdfCalls++;
    this._h = fnv(`${password}|${sk}|${salt}`);
  }
  signIn(email, nonce, device, platform) { return `sig:${this._h}:${email}:${nonce}:${device}:${platform}`; }
  openAccountKey(account, akId, wrapJson) {
    const w = JSON.parse(wrapJson);
    const m = /^pw:([0-9a-f]{8}):([0-9a-f]{64})$/.exec(String(w?.ct || ''));
    if (!m || m[1] !== this._h) throw thrown('wrong_password', 'Check your Passyble password and Secret Key');
    return AccountKey.fromBytes(account, unhex(m[2]), akId);
  }
  free() {}
}

export class AccountKey {
  static fromBytes(account, bytes, akId) {
    const akHex = hex(bytes);
    if (fakeAkId(account, akHex) !== akId) throw thrown('invalid_params', 'not this account key');
    const k = new AccountKey();
    k._account = account;
    k._hex = akHex;
    return k;
  }
  account() { return this._account; }
  akId() { return fakeAkId(this._account, this._hex); }
  passwordWrap(password) { return JSON.stringify({ nonce: 'n', ct: `pw:${password._h}:${this._hex}` }); }
  free() { fakeStats.keysFreed++; }
}

let approvalSeq = 0;

export class DeviceApprovalKeys {
  constructor(id = `${Date.now().toString(16)}${++approvalSeq}`) { this._id = id; }
  static restore(secret) {
    const m = /^dak-(.+)$/.exec(String(secret));
    if (!m) throw thrown('invalid_params', 'damaged');
    return new DeviceApprovalKeys(m[1]);
  }
  secret() { return `dak-${this._id}`; }
  encPub() { return `enc-${this._id}`; }
  commitment() { return `com-${this._id}`; }
  reveal() { return `rn-${this._id}`; }
  approvalQr(requestId) { return `passyble:approve/v1?id=${encodeURIComponent(requestId)}&k=${this.encPub()}&r=${this.reveal()}`; }
  code(requestId, account, rA) { return fakeApprovalCode(requestId, account, this.encPub(), rA); }
  open(requestId, account, akId, rA, sealedJson) {
    const m = /^sealed:([^:]+):([0-9a-f]{64}):(.+)$/.exec(String(JSON.parse(sealedJson)?.ct || ''));
    if (!m || m[1] !== this.encPub() || !rA) throw thrown('invalid_params', "The keys don't match");
    return new ApprovedKeys(AccountKey.fromBytes(account, unhex(m[2]), akId), m[3]);
  }
  free() {}
}

export class ApprovedKeys {
  constructor(ak, sk) { this._ak = ak; this._sk = sk; }
  /** The arrived account key's fingerprint, as Settings shows it on the approving device (the fake's). */
  fingerprint() { return fakeAkFingerprint(this._ak._hex); }
  accountKey() { return this._ak; }
  secretKey() { return this._sk; }
  free() { fakeStats.approvedFreed++; }
}

/** The fake's account key fingerprint of `akHex` (`ABCD-EF01-...`). */
export function fakeAkFingerprint(akHex) {
  return String(akHex).slice(0, 16).toUpperCase().match(/.{4}/g).join('-');
}

/** The 6 digits both screens show (the fake's). */
export function fakeApprovalCode(requestId, account, encPub, rA) {
  return String(parseInt(fnv(`${requestId}|${account}|${encPub}|${rA}`), 16) % 1_000_000).padStart(6, '0');
}

/** What an approving device seals for `encPub` (the fake's `{ enc, ct }`). */
export function fakeSealFor(encPub, akHex, secretKey) {
  return { enc: 'e', ct: `sealed:${encPub}:${akHex}:${secretKey}` };
}

const COMMON = ['password', 'qwerty', 'iloveyou', 'dragon', 'monkey', 'letmein', 'sunshine', 'football'];

export function checkMasterPassword(password, namesJson) {
  fakeStats.masterChecks++;
  const pw = String(password ?? '');
  let names = [];
  try { names = JSON.parse(namesJson); } catch { names = []; }
  names = Array.isArray(names) ? names.filter((n) => typeof n === 'string') : [];
  fakeStats.masterNames = names;
  const answer = (o) => JSON.stringify({ ok: false, score: 0, label: '', entropy_bits: 0, issues: [], name: '', min_length: 12, ...o });
  if (!pw) return answer({});
  const lower = pw.toLowerCase();
  const issues = [];
  let name = '';
  if ([...pw].length < 12) issues.push('too_short');
  if (COMMON.includes(lower.replace(/[^a-z]+$/, ''))) {
    issues.push('common');
  } else {
    const parts = names.flatMap((n) => n.toLowerCase().split(/[^a-z0-9]+/)).filter((p) => p.length >= 4);
    name = parts.find((p) => lower.includes(p)) || '';
    if (name) issues.push('contains_name');
    if (/(.)\1\1/.test(pw) || /abcd|1234|qwer|asdf/.test(lower)) issues.push('pattern');
    if (name || issues.includes('pattern') || new Set(pw).size < 8) issues.push('guessable');
  }
  const bits = Math.round(new Set(pw).size * 4.5 + pw.length);
  if (issues.length) return answer({ score: Math.min(2, Math.floor(bits / 30)), label: ['very_weak', 'weak', 'fair'][Math.min(2, Math.floor(bits / 30))], entropy_bits: bits, issues, name });
  const strong = pw.length >= 20;
  return answer({ ok: true, score: strong ? 4 : 3, label: strong ? 'strong' : 'good', entropy_bits: Math.max(60, bits) });
}

const keyOf = (password) => {
  kdfCalls++;
  const k = new Uint8Array(32);
  const b = enc.encode(`k:${password}`);
  for (let i = 0; i < b.length; i++) k[i % 32] = (k[i % 32] * 31 + b[i]) & 0xff;
  return k;
};
const hex = (u8) => [...u8].map((b) => b.toString(16).padStart(2, '0')).join('');
const ok = (result) => JSON.stringify({ result });
const err = (code, message = code) => JSON.stringify({ error: { code, message } });
let grantSeq = 0;

export class BrowserAgent {
  constructor(config) {
    const cfg = JSON.parse(config);
    if (!cfg.device_id) throw new Error('device_id');
    this.cfg = { auto_lock_secs: 900, verify_each_fill: false, keep_list: true, ...cfg };
    this.vault = null;     // { id, keyHex, logins: [...], cards: [...] } while loaded
    this.unlocked = false;
    this.soft = null;      // the list kept by a soft lock
    this.effects = [];
    this.saved = null;
    this.lastUse = Date.now();
    this.saveDueAt = 0;
    this.grants = new Set();
    this.freed = false;
    fakeStats.instances++;
  }

  free() { this.freed = true; }
  hasVault() { return !!this.vault; }
  idleMs() { return Math.max(0, Date.now() - this.lastUse); }
  takeEffects() { const out = JSON.stringify(this.effects); this.effects = []; return out; }
  takeSave() { const s = this.saved; this.saved = null; return s ?? undefined; }
  vaultKey() { return this.unlocked ? new Uint8Array(this.vault.keyHex.match(/../g).map((h) => parseInt(h, 16))) : undefined; }

  nextTickMs() {
    if (this.saveDueAt) return Math.max(0, this.saveDueAt - Date.now());
    if (!this.unlocked) return undefined;
    return Math.max(0, this.cfg.auto_lock_secs * 1000 - this.idleMs());
  }

  tick() {
    if (this.saveDueAt && Date.now() >= this.saveDueAt) { this.saveDueAt = 0; this._write(); }
    if (this.unlocked && this.idleMs() >= this.cfg.auto_lock_secs * 1000) this._lock(false);
  }

  _write() { this.saved = enc.encode(JSON.stringify(this.vault)); }
  _changed() { this._write(); this.effects.push({ type: 'vault_changed' }); }
  _grant() { const g = `grant-${++grantSeq}-${'x'.repeat(30)}`; this.grants.add(g); return g; }
  _open() {
    this.unlocked = true;
    this.soft = null;
    this.lastUse = Date.now();
    this.effects.push({ type: 'lock_state', locked: false });
  }

  _lock(completely) {
    if (!this.vault) return;
    const was = this.unlocked;
    if (this.saveDueAt) { this.saveDueAt = 0; this._write(); }
    if (completely || !this.cfg.keep_list) this.soft = null;
    else if (was) this.soft = this.vault.logins.map(({ password, totp, ...rest }) => rest);
    this.unlocked = false;
    this.grants.clear();
    if (was) this.effects.push({ type: 'lock_state', locked: true });
  }

  create(password) {
    if (this.vault) return err('invalid_state');
    if (!password) return err('invalid_params');
    this.vault = { id: `vault-${Math.random().toString(16).slice(2)}`, keyHex: hex(keyOf(password)), logins: [], cards: [{ id: 'card1', title: 'Visa', last4: '4242', number: '4242424242424242', security_code: '123' }] };
    this._write();
    this._open();
    return ok({ vault_id: this.vault.id, grant: this._grant() });
  }

  load(file) {
    if (this.unlocked) return err('invalid_state');
    try {
      const v = JSON.parse(dec.decode(file));
      if (!v?.id || !v.keyHex) throw new Error('no');
      this.vault = v;
      this.soft = null;
      return ok({ vault_id: v.id });
    } catch {
      return err('invalid_params', 'This is not a Passyble vault file');
    }
  }

  unlock(password) {
    if (!this.vault) return err('no_vault');
    if (this.vault.account) return err('invalid_params', 'This vault opens with your Passyble password');
    if (hex(keyOf(password)) !== this.vault.keyHex) return err('wrong_password', 'Wrong master password. Check Caps Lock and try again.');
    this._open();
    return ok({ locked: false, grant: this._grant() });
  }

  // A linked vault carries `account: { account, ak_id }`.
  vaultAccess() {
    if (!this.vault) return err('no_vault');
    return ok(accessOf(this.vault));
  }

  unlockWithAccountKey(ak) {
    if (!this.vault) return err('no_vault');
    const link = this.vault.account;
    if (!link) return err('invalid_params', 'This vault is not linked to a Passyble account');
    if (link.account !== ak.account() || link.ak_id !== ak.akId()) return err('invalid_params', 'Linked to another account key');
    this._open();
    return ok({ locked: false, grant: this._grant() });
  }

  verifyAccountKey(ak) {
    if (!this.unlocked) return err('locked');
    const link = this.vault.account;
    if (!link || link.account !== ak.account() || link.ak_id !== ak.akId()) return err('wrong_password');
    return ok({ grant: this._grant() });
  }

  unlockWithKey(key, idle) {
    if (!this.vault) return err('no_vault');
    if (hex(key) !== this.vault.keyHex) return err('wrong_password');
    key.fill(0);
    this._open();
    this.lastUse = Date.now() - idle;
    return ok({ locked: false });
  }

  verifyPassword(password) {
    if (!this.unlocked) return err('locked');
    if (hex(keyOf(password)) !== this.vault.keyHex) return err('wrong_password');
    return ok({ grant: this._grant() });
  }

  lock(completely) { this._lock(!!completely); return ok({ locked: true }); }

  setOptions(json) {
    const o = JSON.parse(json);
    for (const k of Object.keys(o)) if (!['auto_lock_secs', 'keep_list', 'verify_each_fill'].includes(k)) return err('invalid_params');
    Object.assign(this.cfg, o);
    return ok({});
  }

  exportVault() {
    if (!this.vault) return undefined;
    if (this.saveDueAt) { this.saveDueAt = 0; this._write(); this.saved = null; }
    return enc.encode(JSON.stringify(this.vault));
  }

  handle(line) {
    const req = JSON.parse(line);
    const out = (body) => JSON.stringify({ id: req.id, ...JSON.parse(body) });
    const grant = typeof req.grant === 'string' && this.grants.delete(req.grant);
    const p = req.params || {};
    const m = req.method;
    if (m === 'status') {
      return out(ok({ features: ['edit', 'notes.create', 'notes.list', 'logins.search', 'locked.list', 'unlock.inline', 'lock', 'cards', 'identities', 'generate.username', 'generate.email', 'password.check', 'vault.browser'],
        locked: !this.unlocked, soft_locked: !this.unlocked && !!this.soft, vault: !!this.vault, version: '0.1.0' }));
    }
    if (!this.vault) return out(err('no_vault', 'There is no vault in this browser yet'));
    if (m === 'unlock') return out(err('cancelled'));
    if (['totp.popup', 'app.show_item', 'server.pair'].includes(m)) return out(err('not_supported'));
    if (m === 'unlock.options') return out(ok({ hello: false, locked: !this.unlocked, password: true }));
    if (m === 'unlock.password') {
      const r = JSON.parse(this.unlock(p.password));
      if (r.result) delete r.result.grant;
      return out(JSON.stringify(r));
    }
    if (m === 'lock') { this._lock(false); return out(ok({ locked: true })); }
    const host = (u) => { try { return new URL(u).hostname; } catch { return ''; } };
    if (m === 'logins.find') {
      if (!this.unlocked) return this.soft ? out(ok({ items: this.soft.filter((l) => host(l.url) === host(p.url)), locked: true, pending_otp: null })) : out(err('locked', 'Vault is locked'));
      return out(ok({ items: this.vault.logins.filter((l) => host(l.url) === host(p.url)).map(({ password, totp, ...rest }) => rest), locked: false, pending_otp: null }));
    }
    if (!this.unlocked) return out(err('locked', 'Vault is locked'));
    this.lastUse = Date.now();
    const login = (id) => this.vault.logins.find((l) => l.id === id);
    const needsCheck = () => this.cfg.verify_each_fill && !grant;
    switch (m) {
      case 'logins.save': {
        const id = `login-${this.vault.logins.length + 1}-${this.cfg.device_id.slice(0, 8)}`;
        this.vault.logins.push({ id, title: host(p.url), username: p.username || '', password: p.password, url: p.url, has_totp: false, has_passkey: false });
        this._changed();
        return out(ok({ id }));
      }
      case 'logins.create': {
        const id = `login-${this.vault.logins.length + 1}-${this.cfg.device_id.slice(0, 8)}`;
        const f = p.fields || {};
        this.vault.logins.push({ id, title: f.title || host(p.url), username: f.username || '', password: f.password || '', url: p.url, has_totp: false, has_passkey: false });
        this._changed();
        return out(ok({ id, title: f.title || host(p.url) }));
      }
      case 'logins.update': {
        const l = login(p.id);
        if (!l) return out(err('not_found'));
        Object.assign(l, p.fields || {});
        this._changed();
        return out(ok({ id: l.id, title: l.title }));
      }
      case 'logins.delete': {
        const i = this.vault.logins.findIndex((l) => l.id === p.id);
        if (i < 0) return out(err('not_found'));
        this.vault.logins.splice(i, 1);
        this._changed();
        return out(ok({ deleted: true }));
      }
      case 'logins.save_check': return out(ok({ action: this.vault.logins.some((l) => l.password === p.password && host(l.url) === host(p.url)) ? 'none' : 'save_new' }));
      case 'logins.fill': {
        const l = login(p.id);
        if (!l) return out(err('not_found'));
        if (host(l.url) !== host(p.url)) return out(err('url_mismatch'));
        if (needsCheck()) return out(err('verification_required', "Confirm it's you, then try again"));
        return out(ok({ username: l.username, password: l.password, totp: null, skips_2fa: false }));
      }
      case 'logins.fill_cross': {
        const l = login(p.id);
        if (!l) return out(err('not_found'));
        if (req.confirmed !== true) return out(err('cancelled'));
        return out(ok({ username: l.username, password: l.password, totp: null, cross: false }));
      }
      case 'logins.copy': {
        const l = login(p.id);
        if (!l) return out(err('not_found'));
        if (needsCheck()) return out(err('verification_required'));
        this.effects.push({ type: 'copy', text: p.field === 'username' ? l.username : l.password });
        return out(ok({ copied: true, field: p.field }));
      }
      case 'generate.copy': this.effects.push({ type: 'copy', text: p.password }); return out(ok({ copied: true }));
      case 'cards.list': return out(ok({ items: this.vault.cards.map(({ number, security_code, ...rest }) => rest), locked: false }));
      case 'cards.fill': {
        if (req.confirmed !== true) return out(err('cancelled'));
        const c = this.vault.cards.find((x) => x.id === p.id);
        if (p.purpose === 'copy' && p.field) { this.effects.push({ type: 'copy', text: c[p.field] }); return out(ok({ copied: true, field: p.field })); }
        return out(ok({ number: c.number, security_code: c.security_code, cardholder_name: 'A', expiry_month: 1, expiry_year: 2030 }));
      }
      case 'logins.search': return out(ok({ items: this.vault.logins.filter((l) => l.title.includes(p.query)).map(({ password, totp, ...rest }) => ({ ...rest, domain: host(rest.url) })), locked: false, truncated: false }));
      case 'generate': return out(ok({ password: 'Generated-Pw-123!' }));
      case 'totp.set': {
        const value = String(p.totp || '');
        if (!/^otpauth:\/\/totp\/.+secret=[A-Z2-7]{16,}/i.test(value) && !/^[A-Z2-7]{16,}$/i.test(value)) return out(err('invalid_params', '2FA secret is not valid'));
        if (!p.id) return out(ok({ code: '123456', remaining_secs: 20 }));
        const l = login(p.id);
        if (!l) return out(err('not_found'));
        if (host(l.url) !== host(p.url)) return out(err('url_mismatch'));
        l.totp = value;
        l.has_totp = true;
        this._changed();
        return out(ok({ id: l.id, title: l.title, username: l.username, has_totp: true, has_passkey: false }));
      }
      case 'notes.create': {
        const f = p.fields || {};
        if (!String(f.title || '').trim()) return out(err('invalid_params', 'a note needs a title'));
        this.vault.notes ??= [];
        const id = `note-${this.vault.notes.length + 1}`;
        this.vault.notes.push({ id, title: String(f.title).trim(), notes: String(f.notes || '') });
        this._changed();
        return out(ok({ id, title: String(f.title).trim(), kind: 'note' }));
      }
      case 'notes.list': {
        const words = String(p.query || '').toLowerCase().split(/\s+/).filter(Boolean);
        const items = (this.vault.notes || []).filter((n) => words.every((w) => n.title.toLowerCase().includes(w)))
          .map(({ id, title }) => ({ id, title, favorite: false, updated: 0, vault_id: this.vault.id }));
        return out(ok({ items, truncated: false, locked: false, vaults: [] }));
      }
      case 'notes.get': {
        const n = (this.vault.notes || []).find((x) => x.id === p.id);
        if (!n) return out(err('not_found', 'no such note'));
        if (needsCheck()) return out(err('verification_required', "Confirm it's you, then try again"));
        if (p.copy === true) {
          if (!n.notes) return out(ok({ copied: false }));
          this.effects.push({ type: 'copy', text: n.notes });
          return out(ok({ copied: true }));
        }
        return out(ok({ id: n.id, title: n.title, notes: n.notes, favorite: false, updated: 0 }));
      }
      // The home vault only (the move offer counts its items).
      case 'vaults.list': {
        const items = this.vault.logins.length + this.vault.cards.length + (this.vault.notes?.length || 0);
        return out(ok({ vaults: [{ id: this.vault.id, name: '', home: true, kind: 'personal', role: null, can_edit: true,
          can_reveal: true, items, open: true, error: null, last_sync: null }], teams: null }));
      }
      // Pins: `known` comes back too, so a test sees what the background sent.
      case 'vaults.set_pins':
        this.vault.pins = p.ids;
        return out(ok({ pins: p.ids, max: 5, known: p.known ?? null }));
      default: return out(err('invalid_params', `unknown method ${m}`));
    }
  }
}
