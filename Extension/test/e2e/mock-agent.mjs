// Stand-in for the desktop agent in the end-to-end tests: the methods the extension uses, with the
// same shapes and the same 2FA rules. Codes are real RFC 6238 TOTP codes (SHA-1, 6 digits, 30 s).
import { createHash, createHmac, generateKeyPairSync, randomBytes, sign } from 'node:crypto';

const PENDING_OTP_TTL_MS = 3 * 60_000;

export function base32Decode(input) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let value = 0;
  const out = [];
  for (const c of input.replace(/[\s=]+/g, '').toUpperCase()) {
    const i = alphabet.indexOf(c);
    if (i < 0) throw new Error(`bad base32 character ${c}`);
    value = (value << 5) | i;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
      value &= (1 << bits) - 1;
    }
  }
  return Buffer.from(out);
}

/** RFC 6238 code for `secret` (base32) at `atMs`. */
export function totpCode(secret, atMs = Date.now(), period = 30) {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(atMs / 1000 / period)));
  const mac = createHmac('sha1', base32Decode(secret)).update(counter).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const n = (mac.readUInt32BE(offset) & 0x7fffffff) % 1_000_000;
  return String(n).padStart(6, '0');
}

/** Codes valid around now (previous, current, next period): a fill may straddle a period change. */
export function validCodes(secret, now = Date.now()) {
  return [-30_000, 0, 30_000].map((d) => totpCode(secret, now + d));
}

function hostOf(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch { return ''; }
}

/**
 * Registrable domain, simplified for the test hosts (`*.example.localhost`): the last two labels.
 * The agent uses the Public Suffix List (pass-core `registrable_domain`), which gives the same
 * answer for these hosts.
 */
export function registrableDomain(host) {
  if (!host) return '';
  if (/^[\d.]+$/.test(host) || !host.includes('.')) return host;
  return host.split('.').slice(-2).join('.');
}

function matches(stored, pageUrl) {
  const s = hostOf(stored.includes('://') ? stored : `https://${stored}`);
  const p = hostOf(pageUrl);
  if (!s || !p) return false;
  if (s === p) return true;
  return s.includes('.') && registrableDomain(s) === registrableDomain(p);
}

export class MockAgent {
  constructor(items) {
    this.items = items;
    this.pending = new Map(); // registrable domain -> { id, expires }
    this.calls = [];
    this.locked = false;
    this.outcomes = new Map(); // registrable domain -> ['asked' | 'skipped' | 'used', …] (otp.outcome)
    // Opt-in (menu.e2e.mjs): a soft lock keeps the list, and the extension's own unlock form
    // (`unlock.inline`) unlocks with `masterPassword`, or with Windows Hello when `hello`.
    this.softLocked = false;
    this.inlineUnlock = false;
    this.masterPassword = 'master';
    this.hello = false;
  }

  reset() {
    this.pending.clear();
    this.calls = [];
    this.outcomes.clear();
  }

  /** As the agent: the last two sign-ins on the site skipped 2FA. */
  skips2fa(url) {
    const list = this.outcomes.get(registrableDomain(hostOf(url))) || [];
    return list.length >= 2 && list.slice(-2).every((o) => o === 'skipped');
  }

  find(url) {
    return this.items.filter((it) => it.urls.some((u) => matches(u, url)));
  }

  pendingFor(url) {
    const key = registrableDomain(hostOf(url));
    const p = this.pending.get(key);
    if (!p || p.expires < Date.now()) { this.pending.delete(key); return null; }
    const item = this.items.find((it) => it.id === p.id);
    return item ? { id: item.id, title: item.title, skips_2fa: this.skips2fa(url) } : null;
  }

  itemFor(url, id) {
    const item = this.find(url).find((it) => it.id === id);
    if (item) return item;
    throw this.items.some((it) => it.id === id)
      ? { code: 'url_mismatch', message: 'item does not belong to this site' }
      : { code: 'not_found', message: 'no such item' };
  }

  totp(item) {
    if (!item.totp) return null;
    const now = Date.now();
    return { code: totpCode(item.totp, now), period: 30, remaining_secs: 30 - (Math.floor(now / 1000) % 30) };
  }

  /** One JSON-RPC style request `{ id, method, params }` -> `{ id, result }` / `{ id, error }`. */
  handle({ id, method, params = {} }) {
    this.calls.push({ method, params });
    try {
      return { id, result: this.call(method, params) };
    } catch (err) {
      return { id, error: err && err.code ? err : { code: 'internal', message: String(err?.message || err) } };
    }
  }

  call(method, p) {
    const needUnlocked = () => { if (this.locked) throw { code: 'locked', message: 'Vault is locked' }; };
    switch (method) {
      case 'status':
        return { locked: this.locked, soft_locked: this.locked && this.softLocked,
          features: ['edit', 'save_check', ...(this.inlineUnlock ? ['locked.list', 'unlock.inline'] : [])] };
      case 'unlock.options':
        if (!this.inlineUnlock) throw { code: 'invalid_params', message: `unknown method ${method}` };
        return { locked: this.locked, password: true, hello: this.locked && this.hello };
      case 'unlock.password':
        if (!this.inlineUnlock) throw { code: 'invalid_params', message: `unknown method ${method}` };
        if (p.password !== this.masterPassword) throw { code: 'wrong_password', message: 'Wrong master password. Check Caps Lock and try again.' };
        this.locked = false;
        return { locked: false };
      case 'unlock.hello':
        if (!this.inlineUnlock) throw { code: 'invalid_params', message: `unknown method ${method}` };
        if (!this.hello) throw { code: 'not_supported', message: 'Windows Hello is off for this vault. Use your master password.' };
        this.locked = false;
        return { locked: false };
      case 'logins.find': {
        if (!(this.locked && this.softLocked)) needUnlocked();
        const items = this.find(p.url).map((it) => ({
          id: it.id, title: it.title, username: it.username, has_totp: !!it.totp, has_passkey: !!it.passkeys?.some((pk) => hostOf(p.url) === pk.rpId || hostOf(p.url).endsWith(`.${pk.rpId}`)),
        }));
        if (this.locked) return { items, pending_otp: null, locked: true };
        return { items, pending_otp: this.pendingFor(p.url) };
      }
      case 'logins.fill': {
        needUnlocked();
        const item = this.itemFor(p.url, p.id);
        const totp = this.totp(item);
        if (totp) {
          this.pending.set(registrableDomain(hostOf(p.url)), { id: item.id, expires: Date.now() + PENDING_OTP_TTL_MS });
        }
        return { username: item.username, password: item.password, totp, skips_2fa: !!totp && this.skips2fa(p.url) };
      }
      case 'totp.get': {
        needUnlocked();
        let item;
        if (p.id) item = this.itemFor(p.url, p.id);
        else {
          const pending = this.pendingFor(p.url);
          if (!pending) throw { code: 'not_found', message: 'no pending code for this site' };
          item = this.itemFor(p.url, pending.id);
        }
        const code = this.totp(item);
        if (!code) throw { code: 'not_found', message: 'this login has no 2FA secret' };
        return { id: item.id, title: item.title, ...code };
      }
      case 'totp.popup':
        needUnlocked();
        this.itemFor(p.url, p.id);
        return {};
      case 'otp.outcome': {
        if (!['asked', 'skipped', 'used'].includes(p.outcome)) throw { code: 'invalid_params', message: 'bad outcome' };
        const key = registrableDomain(hostOf(p.url));
        this.outcomes.set(key, [...(this.outcomes.get(key) || []), p.outcome].slice(-5));
        return { skips_2fa: this.skips2fa(p.url) };
      }
      case 'generate':
        return { password: 'Generated-Password-1234' };
      case 'generate.copy':
        if (this.olderApp) throw { code: 'invalid_params', message: `unknown method ${method}` };
        return { copied: true };
      case 'unlock':
        this.locked = false;
        return { locked: false };
      case 'logins.save_check':
        return { action: 'none' };
      // Editing (drafts of generated passwords): the login belongs to the page's origin.
      case 'logins.create': {
        needUnlocked();
        const origin = new URL(p.url).origin;
        const item = { id: `new-${this.items.length + 1}`, title: p.fields.title || hostOf(p.url), username: p.fields.username || '',
          password: p.fields.password || '', urls: [origin] };
        this.items.push(item);
        return { id: item.id, title: item.title, username: item.username, has_totp: false, has_passkey: false };
      }
      case 'logins.update': {
        needUnlocked();
        const item = this.itemFor(p.url, p.id);
        for (const k of ['title', 'username', 'password']) if (typeof p.fields?.[k] === 'string') item[k] = p.fields[k];
        return { id: item.id, title: item.title, username: item.username, has_totp: !!item.totp, has_passkey: false };
      }
      case 'logins.delete': {
        needUnlocked();
        const item = this.itemFor(p.url, p.id);
        this.items.splice(this.items.indexOf(item), 1);
        return { undo_secs: 60 };
      }
      case 'passkey.create':
        needUnlocked();
        return this.passkeyCreate(p);
      case 'passkey.get':
        needUnlocked();
        return this.passkeyGet(p);
      case 'passkey.find': {
        // Names only, from the kept list too.
        if (!(this.locked && this.softLocked)) needUnlocked();
        const rpId = this.passkeyRp(p.origin, p.rpId);
        const items = this.passkeyMatches(rpId, p.allowCredentials).map(({ item, pk }) => ({
          id: item.id, title: item.title, user_name: pk.userName ?? item.username, user_display_name: '', credential_id: pk.credentialId,
        }));
        return { rp_id: rpId, items, locked: !!this.locked };
      }
      case 'passkey.create_options': {
        // What the "Save a passkey?" card offers: titles and names only.
        if (!(this.locked && this.softLocked)) needUnlocked();
        const rpId = this.passkeyRp(p.origin, p.rpId);
        const site = (u) => { try { const h = new URL(u).hostname; return h === rpId || h.endsWith(`.${rpId}`); } catch { return false; } };
        const logins = this.items.filter((it) => (it.urls || []).some(site));
        const name = String(p.userName || '').toLowerCase();
        return {
          rp_id: rpId,
          locked: !!this.locked,
          excluded: !!p.excludeCredentials?.length && this.passkeyMatches(rpId, p.excludeCredentials).length > 0,
          candidates: logins.map((it) => ({ id: it.id, title: it.title, username: it.username })),
          suggested: (name && logins.find((it) => String(it.username || '').toLowerCase() === name)?.id) || null,
          vault: null,
        };
      }
      default:
        throw { code: 'not_supported', message: `mock agent: ${method}` };
    }
  }

  // Passkeys: a software authenticator like pass-core's (ES256, "none" attestation, BE/BS set; never UV, since this
  // mock never verifies the user).

  passkeyRp(origin, rpId) {
    const u = new URL(origin);
    const host = u.hostname;
    const rp = (rpId || host).toLowerCase();
    const secure = u.protocol === 'https:' || (u.protocol === 'http:' && (host === 'localhost' || host.endsWith('.localhost')));
    if (!secure || u.origin !== origin || !(host === rp || host.endsWith(`.${rp}`)) || !rp.includes('.') && rp !== 'localhost') {
      throw { code: 'url_mismatch', message: `${rp} is not valid for ${origin}` };
    }
    return rp;
  }

  passkeyMatches(rpId, allow = [], id) {
    const ids = allow.map((c) => c.id);
    const out = [];
    for (const item of this.items) {
      if (id && item.id !== id) continue;
      for (const pk of item.passkeys || []) {
        if (pk.rpId === rpId && (!ids.length || ids.includes(pk.credentialId))) out.push({ item, pk });
      }
    }
    return out;
  }

  passkeyCreate(p) {
    const rpId = this.passkeyRp(p.origin, p.rp?.id);
    const algs = (p.pubKeyCredParams || []).map((a) => a.alg);
    if (algs.length && !algs.includes(-7)) throw { code: 'not_supported', message: 'only ES256 passkeys are supported' };
    if (p.excludeCredentials?.length && this.passkeyMatches(rpId, p.excludeCredentials).length) {
      throw { code: 'invalid_state', message: 'a passkey for this account is already in Passyble' };
    }
    if (p.authenticatorSelection?.userVerification === 'required') {
      throw { code: 'not_supported', message: 'user verification is required and Passyble could not verify the user' };
    }
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: p.challenge, origin: p.origin, crossOrigin: !!p.crossOrigin }));
    const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credentialId = randomBytes(16);
    const cose = Buffer.concat([Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]), Buffer.from(jwk.x, 'base64url'),
      Buffer.from([0x22, 0x58, 0x20]), Buffer.from(jwk.y, 'base64url')]);
    const len = Buffer.alloc(2);
    len.writeUInt16BE(credentialId.length);
    const authData = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([0x01 | 0x08 | 0x10 | 0x40]), Buffer.alloc(4),
      Buffer.alloc(16, 0x5a), len, credentialId, cose]);
    const text = (t) => Buffer.concat([Buffer.from([0x60 + t.length]), Buffer.from(t)]);
    const attestation = Buffer.concat([Buffer.from([0xa3]), text('fmt'), text('none'), text('attStmt'), Buffer.from([0xa0]), text('authData'),
      Buffer.from([0x59, authData.length >> 8, authData.length & 0xff]), authData]);
    // The login chosen in the extension's card (`consent`), else as "Create a new login" in the
    // desktop app's consent window.
    let item = p.consent?.itemId ? this.items.find((it) => it.id === p.consent.itemId) : null;
    if (p.consent?.itemId && !item) throw { code: 'url_mismatch', message: 'item does not belong to this site' };
    if (!item) {
      item = { id: `pk-${this.items.length + 1}`, title: rpId, username: p.user.name, password: '', urls: [p.origin] };
      this.items.push(item);
    }
    (item.passkeys ||= []).push({ credentialId: credentialId.toString('base64url'), rpId, userHandle: p.user.id, userName: p.user.name, key: privateKey, signCount: 0 });
    const b = (buf) => Buffer.from(buf).toString('base64url');
    return { credentialId: b(credentialId), clientDataJSON: b(clientData), attestationObject: b(attestation), authenticatorData: b(authData),
      publicKey: b(publicKey.export({ format: 'der', type: 'spki' })), publicKeyAlgorithm: -7, transports: ['internal', 'hybrid'] };
  }

  passkeyGet(p) {
    const rpId = this.passkeyRp(p.origin, p.rpId);
    const matches = this.passkeyMatches(rpId, p.allowCredentials, p.id).filter(({ pk }) => !p.id || !p.credentialId || pk.credentialId === p.credentialId);
    if (!matches.length) throw { code: 'not_found', message: 'no passkey for this site in Passyble' };
    if (p.userVerification === 'required') {
      throw { code: 'not_supported', message: 'user verification is required and Passyble could not verify the user' };
    }
    const { pk } = matches[0];
    pk.signCount += 1;
    const count = Buffer.alloc(4);
    count.writeUInt32BE(pk.signCount);
    const authData = Buffer.concat([createHash('sha256').update(rpId).digest(), Buffer.from([0x01 | 0x08 | 0x10]), count]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: p.challenge, origin: p.origin, crossOrigin: !!p.crossOrigin }));
    const signature = sign('sha256', Buffer.concat([authData, createHash('sha256').update(clientData).digest()]), pk.key);
    const b = (buf) => Buffer.from(buf).toString('base64url');
    return { credentialId: pk.credentialId, clientDataJSON: b(clientData), authenticatorData: b(authData), signature: b(signature), userHandle: pk.userHandle };
  }

}
