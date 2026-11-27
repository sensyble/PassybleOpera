import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../', import.meta.url));
export const MAIN_SRC = readFileSync(`${root}src/content/webauthn-main.js`, 'utf8');
export const BRIDGE_SRC = readFileSync(`${root}src/content/bridge.js`, 'utf8');

// Fake browser WebAuthn surface, evaluated inside the page realm.
const FAKES = `
  window.__native = [];
  class CredentialsContainer {
    create(o) { window.__native.push(['create', o]); return Promise.resolve({ native: 'create' }); }
    get(o) {
      window.__native.push(['get', o]);
      if (o && o.mediation === 'conditional') {
        return new Promise((resolve, reject) => {
          window.__resolveNativeConditional = resolve;
          o.signal && o.signal.addEventListener('abort', () => reject(new DOMException('aborted', 'AbortError')));
        });
      }
      return Promise.resolve({ native: 'get' });
    }
  }
  window.CredentialsContainer = CredentialsContainer;
  Object.defineProperty(navigator, 'credentials', { value: new CredentialsContainer(), configurable: true });
  class PublicKeyCredential {
    get id() { throw new TypeError('Illegal invocation'); }
    static isConditionalMediationAvailable() { return Promise.resolve(false); }
    static isUserVerifyingPlatformAuthenticatorAvailable() { return Promise.resolve(false); }
    static getClientCapabilities() { return Promise.resolve({ hybridTransport: true }); }
  }
  class AuthenticatorResponse {}
  class AuthenticatorAttestationResponse extends AuthenticatorResponse {}
  class AuthenticatorAssertionResponse extends AuthenticatorResponse {}
  Object.assign(window, { PublicKeyCredential, AuthenticatorResponse, AuthenticatorAttestationResponse, AuthenticatorAssertionResponse });
`;

/**
 * Builds a page with the fake WebAuthn API and (optionally) a fake isolated-world bridge that answers
 * each request with `handler(msg)`, then runs webauthn-main.js.
 */
export function makePage({ handler = null, bridge = true, url = 'https://example.com/' } = {}) {
  const dom = new JSDOM('<!doctype html><html><body></body></html>', { runScripts: 'outside-only', url });
  const w = dom.window;
  w.eval(FAKES);
  const requests = [];
  const state = { channel: null };
  if (bridge) {
    w.addEventListener('pass-webauthn-hello-v1', (e) => {
      if (state.channel) return;
      state.channel = e.detail;
      w.addEventListener(`${state.channel}:req`, async (ev) => {
        const msg = JSON.parse(ev.detail);
        // As bridge.js: a synchronous receipt, unless the test plays a dead bridge.
        if (!state.dead) w.dispatchEvent(new w.CustomEvent(`${state.channel}:got`, { detail: msg.rid }));
        requests.push(msg);
        const reply = await handler?.(msg);
        if (reply !== undefined) state.respond(msg.rid, reply);
      });
      w.dispatchEvent(new w.CustomEvent(`${state.channel}:ack`));
    });
    state.respond = (rid, reply) => {
      w.dispatchEvent(new w.CustomEvent(`${state.channel}:res`, { detail: JSON.stringify({ rid, ...reply }) }));
    };
  }
  w.eval(MAIN_SRC);
  return { dom, window: w, requests, state, run: (code) => w.eval(code) };
}

export const CREATE_OPTIONS = `({ publicKey: {
  rp: { id: 'example.com', name: 'Example' },
  user: { id: new Uint8Array([1, 2, 3, 4]), name: 'alice', displayName: 'Alice' },
  challenge: new Uint8Array([9, 8, 7]).buffer,
  pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }],
  excludeCredentials: [{ type: 'public-key', id: new Uint8Array([0xfb, 0xff]) }],
  authenticatorSelection: { residentKey: 'required', userVerification: 'preferred' },
  extensions: { credProps: true },
} })`;

export const GET_OPTIONS = `({ publicKey: {
  rpId: 'example.com',
  challenge: new Uint8Array([5, 6, 7]),
  allowCredentials: [{ type: 'public-key', id: new Uint8Array([1, 1]), transports: ['internal'] }],
  userVerification: 'required',
} })`;

export const CREATE_RESULT = {
  credentialId: 'AQID', clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0', attestationObject: 'o2NmbXRkbm9uZQ',
  authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFAAAAAA', publicKey: 'MFkwEwYHKoZIzj0CAQ',
  publicKeyAlgorithm: -7, transports: ['internal', 'hybrid'],
};

export const GET_RESULT = {
  credentialId: 'AQID', clientDataJSON: 'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0', authenticatorData: 'SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2MFAAAAAA',
  signature: 'MEUCIQ', userHandle: 'AQIDBA',
};

export const bytes = (buf) => [...new Uint8Array(buf)];
