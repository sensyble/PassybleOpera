// Page-side WebAuthn client for passkey.e2e.mjs, served inline in the test pages. It does what
// SimpleWebAuthn browser and the native JSON helpers do. Each call returns { json, checks } or
// { error: { name, message } }.
(() => {
  const toBuf = (s) => {
    const clean = String(s).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(clean + '==='.slice((clean.length + 3) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const b64u = (buf) => {
    const u = new Uint8Array(buf);
    let s = '';
    for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const credList = (list) => list?.map((c) => ({ ...c, id: toBuf(c.id) }));

  // SimpleWebAuthn's WebAuthnAbortService: one ceremony at a time.
  let controller = null;
  function signal() {
    if (controller) {
      const err = new Error('Cancelling existing WebAuthn API call for new one');
      err.name = 'AbortError';
      controller.abort(err);
    }
    controller = new AbortController();
    return controller.signal;
  }

  function describeError(err) {
    return { error: { name: err?.name, message: String(err?.message || err), isDOMException: err instanceof DOMException } };
  }

  /** What libraries and sites read from a credential; every access must work. */
  function checks(cred) {
    const r = cred.response;
    const c = {
      instancePKC: cred instanceof PublicKeyCredential,
      instanceCredential: typeof Credential === 'function' ? cred instanceof Credential : null,
      toStringTag: Object.prototype.toString.call(cred),
      type: cred.type,
      idIsString: typeof cred.id === 'string',
      rawIdMatches: b64u(cred.rawId) === cred.id,
      authenticatorAttachment: cred.authenticatorAttachment,
      extensions: cred.getClientExtensionResults(),
      hasToJSON: typeof cred.toJSON === 'function',
      stringify: null,
    };
    try { c.stringify = JSON.parse(JSON.stringify(cred)).id === cred.id; } catch (e) { c.stringify = String(e); }
    if (typeof AuthenticatorAttestationResponse === 'function' && r instanceof AuthenticatorAttestationResponse) {
      c.responseType = 'attestation';
      c.transports = r.getTransports();
      c.publicKeyAlgorithm = r.getPublicKeyAlgorithm();
      c.publicKeyBytes = r.getPublicKey()?.byteLength ?? null;
      c.authenticatorDataBytes = r.getAuthenticatorData().byteLength;
    } else if (typeof AuthenticatorAssertionResponse === 'function' && r instanceof AuthenticatorAssertionResponse) {
      c.responseType = 'assertion';
      c.userHandle = r.userHandle ? b64u(r.userHandle) : null;
    }
    c.instanceAuthenticatorResponse = typeof AuthenticatorResponse === 'function' ? r instanceof AuthenticatorResponse : null;
    return c;
  }

  /** SimpleWebAuthn browser's registration flow. `native`: parse with the browser's JSON helper. */
  async function register(json, { native = false, useToJSON = true, mediation } = {}) {
    try {
      const publicKey = native ? PublicKeyCredential.parseCreationOptionsFromJSON(json) : {
        ...json,
        challenge: toBuf(json.challenge),
        user: { ...json.user, id: toBuf(json.user.id) },
        excludeCredentials: credList(json.excludeCredentials),
      };
      const options = { publicKey, signal: signal() };
      if (mediation) options.mediation = mediation;
      const cred = await navigator.credentials.create(options);
      if (!cred) return { json: null };
      const r = cred.response;
      let out;
      if (useToJSON && typeof cred.toJSON === 'function') out = cred.toJSON();
      else {
        out = {
          id: cred.id,
          rawId: b64u(cred.rawId),
          response: {
            attestationObject: b64u(r.attestationObject),
            clientDataJSON: b64u(r.clientDataJSON),
            transports: typeof r.getTransports === 'function' ? r.getTransports() : undefined,
            publicKeyAlgorithm: typeof r.getPublicKeyAlgorithm === 'function' ? r.getPublicKeyAlgorithm() : undefined,
            publicKey: typeof r.getPublicKey === 'function' && r.getPublicKey() ? b64u(r.getPublicKey()) : undefined,
            authenticatorData: typeof r.getAuthenticatorData === 'function' ? b64u(r.getAuthenticatorData()) : undefined,
          },
          type: cred.type,
          clientExtensionResults: cred.getClientExtensionResults(),
          authenticatorAttachment: cred.authenticatorAttachment,
        };
      }
      return { json: JSON.parse(JSON.stringify(out)), checks: checks(cred) };
    } catch (err) {
      return describeError(err);
    }
  }

  /** SimpleWebAuthn browser's authentication flow (`mediation: 'conditional'` = browser autofill). */
  async function authenticate(json, { native = false, useToJSON = true, mediation } = {}) {
    try {
      const publicKey = native ? PublicKeyCredential.parseRequestOptionsFromJSON(json) : {
        ...json,
        challenge: toBuf(json.challenge),
        allowCredentials: credList(json.allowCredentials),
      };
      const options = { publicKey, signal: signal() };
      if (mediation) options.mediation = mediation;
      const cred = await navigator.credentials.get(options);
      if (!cred) return { json: null };
      const r = cred.response;
      const out = useToJSON && typeof cred.toJSON === 'function' ? cred.toJSON() : {
        id: cred.id,
        rawId: b64u(cred.rawId),
        response: {
          authenticatorData: b64u(r.authenticatorData),
          clientDataJSON: b64u(r.clientDataJSON),
          signature: b64u(r.signature),
          userHandle: r.userHandle ? b64u(r.userHandle) : undefined,
        },
        type: cred.type,
        clientExtensionResults: cred.getClientExtensionResults(),
        authenticatorAttachment: cred.authenticatorAttachment,
      };
      return { json: JSON.parse(JSON.stringify(out)), checks: checks(cred) };
    } catch (err) {
      return describeError(err);
    }
  }

  async function capabilities() {
    const P = window.PublicKeyCredential;
    const out = {
      hasPKC: typeof P === 'function',
      uvpaa: await P.isUserVerifyingPlatformAuthenticatorAvailable(),
      cma: typeof P.isConditionalMediationAvailable === 'function' ? await P.isConditionalMediationAvailable() : null,
      caps: typeof P.getClientCapabilities === 'function' ? await P.getClientCapabilities() : null,
      parseCreation: typeof P.parseCreationOptionsFromJSON === 'function',
      parseRequest: typeof P.parseRequestOptionsFromJSON === 'function',
      createName: navigator.credentials.create.name,
      createLength: navigator.credentials.create.length,
    };
    return out;
  }

  window.pkClient = { register, authenticate, capabilities, abort: () => controller?.abort() };
})();
