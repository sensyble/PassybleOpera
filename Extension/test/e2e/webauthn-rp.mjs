// A minimal WebAuthn relying party for passkey.e2e.mjs: makes options in the JSON shape servers send and verifies
// the client's JSON as a real server would (clientDataJSON, rpIdHash, flags, "none" attestation, COSE key, ES256).
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';

export const b64u = (buf) => Buffer.from(buf).toString('base64url');
export const fromB64u = (s) => Buffer.from(String(s), 'base64url');
const sha256 = (data) => createHash('sha256').update(data).digest();

/** Decodes one CBOR item (the subset WebAuthn uses: ints, bytes, text, arrays, maps). */
export function cborDecode(buf) {
  let pos = 0;
  function length(info) {
    if (info < 24) return info;
    if (info === 24) return buf[pos++];
    if (info === 25) { const v = buf.readUInt16BE(pos); pos += 2; return v; }
    if (info === 26) { const v = buf.readUInt32BE(pos); pos += 4; return v; }
    throw new Error(`unsupported CBOR length ${info}`);
  }
  function item() {
    const first = buf[pos++];
    const major = first >> 5;
    const n = length(first & 0x1f);
    switch (major) {
      case 0: return n;
      case 1: return -1 - n;
      case 2: { const v = buf.subarray(pos, pos + n); pos += n; return Buffer.from(v); }
      case 3: { const v = buf.subarray(pos, pos + n).toString('utf8'); pos += n; return v; }
      case 4: return Array.from({ length: n }, item);
      case 5: { const m = new Map(); for (let i = 0; i < n; i++) { const k = item(); m.set(k, item()); } return m; }
      default: throw new Error(`unsupported CBOR major type ${major}`);
    }
  }
  const value = item();
  return { value, rest: buf.subarray(pos) };
}

/** Splits authenticator data (WebAuthn §6.1). */
export function parseAuthData(data) {
  const out = { rpIdHash: data.subarray(0, 32), flags: data[32], signCount: data.readUInt32BE(33) };
  out.up = !!(out.flags & 0x01);
  out.uv = !!(out.flags & 0x04);
  out.be = !!(out.flags & 0x08);
  out.bs = !!(out.flags & 0x10);
  if (out.flags & 0x40) {
    out.aaguid = data.subarray(37, 53);
    const len = data.readUInt16BE(53);
    out.credentialId = data.subarray(55, 55 + len);
    const { value, rest } = cborDecode(data.subarray(55 + len));
    out.coseKey = value;
    if (rest.length && !(out.flags & 0x80)) throw new Error('trailing bytes after the credential public key');
  }
  return out;
}

/** COSE EC2 P-256 key -> node KeyObject. */
export function coseToKey(cose) {
  if (cose.get(1) !== 2 || cose.get(3) !== -7 || cose.get(-1) !== 1) throw new Error('not an ES256 COSE key');
  return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256', x: b64u(cose.get(-2)), y: b64u(cose.get(-3)) } });
}

function checkClientData(json, type, challenge, origin) {
  const cd = JSON.parse(fromB64u(json).toString('utf8'));
  if (cd.type !== type) throw new Error(`clientData.type ${cd.type}`);
  if (cd.challenge !== challenge) throw new Error('clientData.challenge mismatch');
  if (cd.origin !== origin) throw new Error(`clientData.origin ${cd.origin} != ${origin}`);
  return cd;
}

export class RelyingParty {
  constructor({ rpId, origin, name = 'Test RP' }) {
    Object.assign(this, { rpId, origin, name });
    this.credentials = new Map(); // credential id (b64url) -> { key, userHandle, signCount, transports }
  }

  /** PublicKeyCredentialCreationOptionsJSON, webauthn.io's defaults unless overridden. */
  registrationOptions({ user = 'alice', userId = b64u(randomBytes(16)), exclude = [], ...extra } = {}) {
    this.challenge = b64u(randomBytes(32));
    return {
      rp: { id: this.rpId, name: this.name },
      user: { id: userId, name: user, displayName: user },
      challenge: this.challenge,
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
      timeout: 60000,
      excludeCredentials: exclude.map((id) => ({ type: 'public-key', id, transports: ['internal'] })),
      authenticatorSelection: { residentKey: 'required', requireResidentKey: true, userVerification: 'preferred' },
      attestation: 'none',
      hints: [],
      extensions: { credProps: true },
      ...extra,
    };
  }

  /** Verifies a RegistrationResponseJSON; stores and returns the credential. */
  verifyRegistration(json, { requireUV = false } = {}) {
    if (json.type !== 'public-key') throw new Error(`type ${json.type}`);
    if (json.id !== json.rawId) throw new Error('id != rawId');
    checkClientData(json.response.clientDataJSON, 'webauthn.create', this.challenge, this.origin);
    const { value: att } = cborDecode(fromB64u(json.response.attestationObject));
    if (att.get('fmt') !== 'none') throw new Error(`attestation fmt ${att.get('fmt')}`);
    if (att.get('attStmt').size !== 0) throw new Error('none attestation with a statement');
    const authData = att.get('authData');
    const ad = parseAuthData(authData);
    if (!ad.rpIdHash.equals(sha256(this.rpId))) throw new Error('rpIdHash mismatch');
    if (!ad.up) throw new Error('user not present');
    if (requireUV && !ad.uv) throw new Error('user not verified');
    if (b64u(ad.credentialId) !== json.id) throw new Error('credential id in authData != id');
    const key = coseToKey(ad.coseKey);
    // The JSON's own copies (toJSON / getPublicKey / getAuthenticatorData) must agree.
    if (json.response.authenticatorData && !fromB64u(json.response.authenticatorData).equals(authData)) {
      throw new Error('response.authenticatorData != attestationObject.authData');
    }
    if (json.response.publicKey) {
      const spki = createPublicKey({ key: fromB64u(json.response.publicKey), format: 'der', type: 'spki' });
      if (!spki.export({ format: 'der', type: 'spki' }).equals(key.export({ format: 'der', type: 'spki' }))) {
        throw new Error('response.publicKey != COSE key');
      }
    }
    if (json.response.publicKeyAlgorithm !== undefined && json.response.publicKeyAlgorithm !== -7) {
      throw new Error(`publicKeyAlgorithm ${json.response.publicKeyAlgorithm}`);
    }
    const cred = { id: json.id, key, signCount: ad.signCount, transports: json.response.transports || [], flags: ad, aaguid: b64u(ad.aaguid) };
    this.credentials.set(json.id, cred);
    return cred;
  }

  /** PublicKeyCredentialRequestOptionsJSON; `allow` lists credential ids (GitHub style). */
  authenticationOptions({ allow = [], userVerification = 'preferred' } = {}) {
    this.challenge = b64u(randomBytes(32));
    return {
      challenge: this.challenge,
      timeout: 60000,
      rpId: this.rpId,
      allowCredentials: allow.map((id) => ({ type: 'public-key', id, transports: ['internal', 'hybrid'] })),
      userVerification,
    };
  }

  /** Verifies an AuthenticationResponseJSON against a stored credential. */
  verifyAuthentication(json, { userHandle, requireUV = false } = {}) {
    const cred = this.credentials.get(json.id);
    if (!cred) throw new Error(`unknown credential ${json.id}`);
    if (json.id !== json.rawId) throw new Error('id != rawId');
    const clientDataJSON = fromB64u(json.response.clientDataJSON);
    checkClientData(json.response.clientDataJSON, 'webauthn.get', this.challenge, this.origin);
    const authData = fromB64u(json.response.authenticatorData);
    const ad = parseAuthData(authData);
    if (!ad.rpIdHash.equals(sha256(this.rpId))) throw new Error('rpIdHash mismatch');
    if (!ad.up) throw new Error('user not present');
    if (requireUV && !ad.uv) throw new Error('user not verified');
    const ok = verify('sha256', Buffer.concat([authData, sha256(clientDataJSON)]), { key: cred.key, dsaEncoding: 'der' },
      fromB64u(json.response.signature));
    if (!ok) throw new Error('bad signature');
    if (userHandle !== undefined && json.response.userHandle !== userHandle) throw new Error('userHandle mismatch');
    if (ad.signCount !== 0 || cred.signCount !== 0) {
      if (ad.signCount <= cred.signCount) throw new Error('sign count did not increase');
    }
    cred.signCount = ad.signCount;
    return { credential: cred, flags: ad };
  }
}
