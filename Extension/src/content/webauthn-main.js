// Passyble passkey interception in the page's MAIN world at document_start (classic script). Wraps
// navigator.credentials create/get for `publicKey` requests and hands them to the isolated-world bridge
// (bridge.js); anything Passyble can't or shouldn't handle falls through to the browser.
// Channel: synchronous CustomEvents on `window` under a random name announced before page scripts run,
// through private copies of dispatchEvent/addEventListener/CustomEvent/JSON taken at that point.
// The page can still call the wrappers, which grants nothing beyond navigator.credentials itself: the
// background takes the origin from the browser's sender info, never from this script. If the bridge loads
// later, early page scripts can see the fallback handshake; at worst a page talks about its own origin.
(function passWebauthnMain() {
  'use strict';

  const w = window;
  const nav = w.navigator;
  const CC = w.CredentialsContainer;
  if (!CC || !nav || !nav.credentials || typeof CC.prototype.get !== 'function') return; // insecure context

  const ET = w.EventTarget.prototype;
  const addEL = ET.addEventListener;
  const removeEL = ET.removeEventListener;
  const dispatch = ET.dispatchEvent;
  const CustomEventCtor = w.CustomEvent;
  const detailOf = Object.getOwnPropertyDescriptor(w.CustomEvent.prototype, 'detail').get;
  const jsonStringify = JSON.stringify;
  const jsonParse = JSON.parse;
  const PromiseCtor = w.Promise;
  const DOMExceptionCtor = w.DOMException;
  const AbortControllerCtor = w.AbortController;
  const U8 = w.Uint8Array;
  const AB = w.ArrayBuffer;
  const isView = AB.isView;
  const btoaFn = w.btoa.bind(w);
  const atobFn = w.atob.bind(w);
  const fromCharCode = String.fromCharCode;
  const getRandomValues = w.crypto.getRandomValues.bind(w.crypto);
  const defineProperty = Object.defineProperty;
  const objectCreate = Object.create;
  const setTimeoutFn = w.setTimeout.bind(w);

  const PKC = w.PublicKeyCredential;

  // After an extension update background.js injects this script again on top of the old copy, whose
  // bridge is gone. Each wrapper records the browser's own method under NATIVE: a copy with a live bridge
  // falls back to it, a copy without one defers to the older copy's wrappers. The page can replace these;
  // that only changes what its own requests fall back to.
  const NATIVE = Symbol.for('passyble.webauthn.native');
  function nativeOf(fn) {
    const d = typeof fn === 'function' ? Object.getOwnPropertyDescriptor(fn, NATIVE) : undefined;
    return d && typeof d.value === 'function' ? d.value : fn;
  }
  const previous = {
    create: CC.prototype.create,
    get: CC.prototype.get,
    isConditionalMediationAvailable: PKC && PKC.isConditionalMediationAvailable,
    isUserVerifyingPlatformAuthenticatorAvailable: PKC && PKC.isUserVerifyingPlatformAuthenticatorAvailable,
    getClientCapabilities: PKC && PKC.getClientCapabilities,
  };
  const natives = {};
  for (const key of Object.keys(previous)) natives[key] = nativeOf(previous[key]);
  function orig(name) {
    return bridgeReady ? natives[name] : previous[name];
  }
  const origCreate = { call: (that, options) => orig('create').call(that, options), apply: (that, args) => orig('create').apply(that, args) };
  const origGet = { call: (that, options) => orig('get').call(that, options), apply: (that, args) => orig('get').apply(that, args) };

  const HELLO = 'pass-webauthn-hello-v1';
  const READY = 'pass-webauthn-ready-v1';
  const BRIDGE_WAIT_MS = 300;

  // Errors after which the browser's own WebAuthn takes over. An answer the in-page card decided is
  // marked `final` and always reaches the page as a DOMException instead.
  const FALLBACK_CODES = { not_found: 1, agent_unavailable: 1, timeout: 1, extension_reloaded: 1, locked: 1, invalid_params: 1, not_supported: 1, internal: 1, disabled: 1, update_required: 1 };
  // "silent", "immediate" and conditional create must not open unlock or consent windows, so the
  // browser handles those.
  const PASS_MEDIATION = { optional: 1, required: 1 };

  function randomHex(bytes) {
    const a = new U8(bytes);
    getRandomValues(a);
    let s = '';
    for (let i = 0; i < a.length; i++) s += (a[i] + 0x100).toString(16).slice(1);
    return s;
  }

  function toBytes(data) {
    if (data instanceof AB) return new U8(data);
    if (isView(data)) return new U8(data.buffer, data.byteOffset, data.byteLength);
    // Buffers from another realm (iframes) fail instanceof.
    if (data && Object.prototype.toString.call(data) === '[object ArrayBuffer]') return new U8(data);
    throw new TypeError('Expected BufferSource');
  }

  function b64u(data) {
    const bytes = toBytes(data);
    let bin = '';
    for (let i = 0; i < bytes.length; i += 0x8000) bin += fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    return btoaFn(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  function fromB64u(str) {
    const clean = String(str).replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
    const bin = atobFn(clean + '==='.slice((clean.length + 3) % 4));
    const out = new U8(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }

  function abortReason(signal) {
    return signal && signal.reason !== undefined
      ? signal.reason
      : new DOMExceptionCtor('The operation was aborted.', 'AbortError');
  }

  function domError(code, message) {
    const msg = message || 'The operation either timed out or was not allowed.';
    if (code === 'invalid_state' || (code === 'cancelled' && /invalid.?state|exclude/i.test(message || ''))) {
      return new DOMExceptionCtor('The authenticator already contains one of the excluded credentials.', 'InvalidStateError');
    }
    if (code === 'url_mismatch') return new DOMExceptionCtor('The relying party ID is not valid for this origin.', 'SecurityError');
    if (code === 'aborted') return new DOMExceptionCtor('The operation was aborted.', 'AbortError');
    return new DOMExceptionCtor(code === 'cancelled' ? 'The operation either timed out or was not allowed.' : msg, 'NotAllowedError');
  }

  const channel = 'pass-' + randomHex(16);
  const pending = new Map(); // rid -> resolve
  let bridgeReady = false;
  // The bridge confirms each request synchronously inside our dispatchEvent. No receipt means the
  // extension was reloaded, so the browser takes over from then on.
  let lastReceipt = null;
  let bridgeGone = false;
  const readyWaiters = [];

  function onAck() {
    if (bridgeReady) return;
    bridgeReady = true;
    removeEL.call(w, READY, onBridgeReady, true);
    while (readyWaiters.length) readyWaiters.shift()(true);
  }

  function onResponse(event) {
    let msg;
    try { msg = jsonParse(detailOf.call(event)); } catch { return; }
    if (!msg || typeof msg.rid !== 'string') return;
    const resolve = pending.get(msg.rid);
    if (!resolve) return;
    pending.delete(msg.rid);
    resolve(msg);
  }

  function sayHello() {
    dispatch.call(w, new CustomEventCtor(HELLO, { detail: channel }));
  }

  function onBridgeReady() {
    if (!bridgeReady) sayHello();
  }

  addEL.call(w, channel + ':ack', onAck, true);
  addEL.call(w, channel + ':res', onResponse, true);
  addEL.call(w, channel + ':got', (event) => { lastReceipt = detailOf.call(event); }, true);
  sayHello(); // the bridge answers synchronously with `${channel}:ack` when it is already listening
  if (!bridgeReady) addEL.call(w, READY, onBridgeReady, true);

  function waitForBridge() {
    if (bridgeReady) return PromiseCtor.resolve(true);
    return new PromiseCtor((resolve) => {
      readyWaiters.push(resolve);
      setTimeoutFn(() => resolve(bridgeReady), BRIDGE_WAIT_MS);
    });
  }

  /** Sends one request to the bridge. Resolves with { ok, result } | { ok:false, error } | { fallback }. */
  function call(op, payload) {
    const rid = randomHex(16);
    const promise = waitForBridge().then((ready) => {
      if (!ready || bridgeGone) return { fallback: true };
      return new PromiseCtor((resolve) => {
        pending.set(rid, resolve);
        lastReceipt = null;
        dispatch.call(w, new CustomEventCtor(channel + ':req', { detail: jsonStringify({ rid, op, payload }) }));
        if (lastReceipt !== rid) {
          bridgeGone = true;
          pending.delete(rid);
          resolve({ fallback: true });
        }
      });
    });
    return { rid, promise };
  }

  function cancel(rid) {
    pending.delete(rid);
    if (bridgeReady) {
      dispatch.call(w, new CustomEventCtor(channel + ':req', { detail: jsonStringify({ rid: randomHex(16), op: 'cancel', payload: { target: rid } }) }));
    }
  }

  function withAbort(req, signal) {
    if (!signal) return req.promise;
    return new PromiseCtor((resolve, reject) => {
      const onAbort = () => { cancel(req.rid); reject(abortReason(signal)); };
      addEL.call(signal, 'abort', onAbort, { once: true });
      req.promise.then((v) => { removeEL.call(signal, 'abort', onAbort); resolve(v); },
        (e) => { removeEL.call(signal, 'abort', onAbort); reject(e); });
    });
  }

  let configPromise = null;
  function getConfig() {
    if (!configPromise) {
      configPromise = call('config', {}).promise.then((r) => (r && r.ok && r.result ? r.result : { enabled: false }),
        () => ({ enabled: false }));
    }
    return configPromise;
  }

  function serializeCreation(pk) {
    const sel = pk.authenticatorSelection || {};
    return {
      rp: { id: pk.rp && pk.rp.id != null ? String(pk.rp.id) : null, name: pk.rp && pk.rp.name != null ? String(pk.rp.name) : '' },
      user: {
        id: b64u(pk.user.id),
        name: String(pk.user.name ?? ''),
        displayName: String(pk.user.displayName ?? ''),
      },
      challenge: b64u(pk.challenge),
      pubKeyCredParams: Array.from(pk.pubKeyCredParams || [], (p) => ({ type: String(p.type), alg: Number(p.alg) })),
      excludeCredentials: Array.from(pk.excludeCredentials || [], (c) => ({
        type: String(c.type || 'public-key'), id: b64u(c.id),
        transports: c.transports ? Array.from(c.transports, String) : undefined,
      })),
      authenticatorSelection: {
        authenticatorAttachment: sel.authenticatorAttachment,
        residentKey: sel.residentKey,
        requireResidentKey: !!sel.requireResidentKey,
        userVerification: sel.userVerification,
      },
      attestation: pk.attestation,
      timeout: pk.timeout,
      extensions: { credProps: !!(pk.extensions && pk.extensions.credProps), prf: prfInputs(pk.extensions) },
    };
  }

  /** `extensions.prf` as WebAuthn JSON (binary values base64url), or undefined without one. */
  function prfInputs(extensions) {
    const prf = extensions ? extensions.prf : undefined;
    if (prf === undefined || prf === null) return undefined;
    if (typeof prf !== 'object') throw new TypeError('prf must be a dictionary');
    const values = (v) => {
      if (!v || typeof v !== 'object') throw new TypeError('prf values must be a dictionary');
      const out = { first: b64u(v.first) };
      if (v.second !== undefined && v.second !== null) out.second = b64u(v.second);
      return out;
    };
    const out = {};
    if (prf.eval !== undefined && prf.eval !== null) out.eval = values(prf.eval);
    if (prf.evalByCredential !== undefined && prf.evalByCredential !== null) {
      if (typeof prf.evalByCredential !== 'object') throw new TypeError('evalByCredential must be a record');
      out.evalByCredential = {};
      for (const key of Object.keys(prf.evalByCredential)) {
        out.evalByCredential[String(key)] = values(prf.evalByCredential[key]);
      }
    }
    return out;
  }

  /**
   * The agent's PRF results checked and copied. Without them (an older desktop app): `{ enabled: false }`
   * for a registration, `{}` for a sign-in.
   */
  function prfOutputJSON(results, registration) {
    const prf = results && typeof results === 'object' ? results.prf : null;
    const out = {};
    if (registration) out.enabled = !!(prf && prf.enabled === true);
    const r = prf && prf.results;
    if (r && typeof r.first === 'string') {
      out.results = { first: r.first };
      if (typeof r.second === 'string') out.results.second = r.second;
    }
    return out;
  }

  /** `getClientExtensionResults()` from the JSON form: PRF results as ArrayBuffers. */
  function liveExtensionResults(json) {
    const out = jsonParse(jsonStringify(json));
    if (json.prf && json.prf.results) {
      out.prf.results = { first: fromB64u(json.prf.results.first) };
      if (json.prf.results.second !== undefined) out.prf.results.second = fromB64u(json.prf.results.second);
    }
    return out;
  }

  function serializeRequest(pk) {
    return {
      rpId: pk.rpId != null ? String(pk.rpId) : null,
      challenge: b64u(pk.challenge),
      allowCredentials: Array.from(pk.allowCredentials || [], (c) => ({
        type: String(c.type || 'public-key'), id: b64u(c.id),
        transports: c.transports ? Array.from(c.transports, String) : undefined,
      })),
      userVerification: pk.userVerification || 'preferred',
      timeout: pk.timeout,
      extensions: { prf: prfInputs(pk.extensions) },
    };
  }

  /** Passyble makes ES256 platform credentials only. */
  function passCanCreate(pk) {
    const sel = pk.authenticatorSelection || {};
    if (sel.authenticatorAttachment === 'cross-platform') return false;
    const params = pk.pubKeyCredParams || [];
    if (params.length === 0) return true; // spec default includes ES256
    return Array.from(params).some((p) => p && p.type === 'public-key' && Number(p.alg) === -7);
  }

  function ro(obj, props) {
    for (const key of Object.keys(props)) {
      defineProperty(obj, key, { value: props[key], enumerable: typeof props[key] !== 'function', configurable: true, writable: false });
    }
    return obj;
  }

  function copy(buf) {
    return buf ? buf.slice(0) : null;
  }

  function protoOf(name) {
    const C = w[name];
    return C && C.prototype ? C.prototype : Object.prototype;
  }

  function makeAttestation(r, clientExtensionResults) {
    const rawId = fromB64u(r.credentialId);
    const clientDataJSON = fromB64u(r.clientDataJSON);
    const attestationObject = fromB64u(r.attestationObject);
    const authenticatorData = fromB64u(r.authenticatorData);
    const publicKey = r.publicKey ? fromB64u(r.publicKey) : null;
    const alg = typeof r.publicKeyAlgorithm === 'number' ? r.publicKeyAlgorithm : -7;
    const transports = Array.isArray(r.transports) && r.transports.length ? r.transports.map(String) : ['internal', 'hybrid'];

    const response = ro(objectCreate(protoOf('AuthenticatorAttestationResponse')), {
      clientDataJSON,
      attestationObject,
      getTransports: function getTransports() { return transports.slice(); },
      getAuthenticatorData: function getAuthenticatorData() { return copy(authenticatorData); },
      getPublicKey: function getPublicKey() { return copy(publicKey); },
      getPublicKeyAlgorithm: function getPublicKeyAlgorithm() { return alg; },
    });
    const json = {
      id: r.credentialId,
      rawId: r.credentialId,
      response: {
        clientDataJSON: r.clientDataJSON,
        authenticatorData: r.authenticatorData,
        transports: transports.slice(),
        publicKey: r.publicKey || undefined,
        publicKeyAlgorithm: alg,
        attestationObject: r.attestationObject,
      },
      authenticatorAttachment: 'platform',
      clientExtensionResults,
      type: 'public-key',
    };
    return makeCredential(rawId, r.credentialId, response, clientExtensionResults, json);
  }

  function makeAssertion(r, clientExtensionResults) {
    const ext = clientExtensionResults || {};
    const rawId = fromB64u(r.credentialId);
    const response = ro(objectCreate(protoOf('AuthenticatorAssertionResponse')), {
      clientDataJSON: fromB64u(r.clientDataJSON),
      authenticatorData: fromB64u(r.authenticatorData),
      signature: fromB64u(r.signature),
      userHandle: r.userHandle ? fromB64u(r.userHandle) : null,
    });
    const json = {
      id: r.credentialId,
      rawId: r.credentialId,
      response: {
        clientDataJSON: r.clientDataJSON,
        authenticatorData: r.authenticatorData,
        signature: r.signature,
        userHandle: r.userHandle || undefined,
      },
      authenticatorAttachment: 'platform',
      clientExtensionResults: ext,
      type: 'public-key',
    };
    return makeCredential(rawId, r.credentialId, response, ext, json);
  }

  function assertionExtensions(payload, result) {
    const ext = {};
    if (payload.extensions && payload.extensions.prf !== undefined) ext.prf = prfOutputJSON(result.clientExtensionResults, false);
    return ext;
  }

  function makeCredential(rawId, id, response, clientExtensionResults, json) {
    // Uses PublicKeyCredential.prototype so instanceof holds. Its native getters would throw on
    // this object, so every member is an own property.
    return ro(objectCreate(protoOf('PublicKeyCredential')), {
      id,
      rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response,
      getClientExtensionResults: function getClientExtensionResults() { return liveExtensionResults(clientExtensionResults); },
      toJSON: function toJSON() { return jsonParse(jsonStringify(json)); },
    });
  }

  function isPublicKeyOnly(options) {
    return options && typeof options === 'object' && options.publicKey && typeof options.publicKey === 'object' &&
      !options.password && !options.federated && !options.identity && !options.otp;
  }

  async function passCreate(container, options) {
    const pk = options.publicKey;
    const signal = options.signal;
    if (signal && signal.aborted) throw abortReason(signal);
    if (options.mediation !== undefined && PASS_MEDIATION[options.mediation] !== 1) return origCreate.call(container, options);
    let payload;
    try {
      if (!passCanCreate(pk)) return origCreate.call(container, options);
      payload = serializeCreation(pk);
    } catch {
      return origCreate.call(container, options); // malformed options: let the browser throw the right TypeError
    }
    const resp = await withAbort(call('create', { publicKey: payload }), signal);
    if (resp && resp.ok && resp.result) {
      const ext = {};
      if (payload.extensions.credProps) ext.credProps = { rk: true };
      if (payload.extensions.prf !== undefined) ext.prf = prfOutputJSON(resp.result.clientExtensionResults, true);
      return makeAttestation(resp.result, ext);
    }
    const code = resp && resp.error ? resp.error.code : null;
    if (!code || (FALLBACK_CODES[code] === 1 && resp.final !== true)) return origCreate.call(container, options);
    throw domError(code, resp.error.message);
  }

  async function passGet(container, options) {
    const pk = options.publicKey;
    const signal = options.signal;
    if (signal && signal.aborted) throw abortReason(signal);
    let payload;
    try { payload = serializeRequest(pk); } catch { return origGet.call(container, options); }
    if (options.mediation === 'conditional') return conditionalGet(container, options, payload);
    if (options.mediation !== undefined && PASS_MEDIATION[options.mediation] !== 1) return origGet.call(container, options);
    const resp = await withAbort(call('get', { publicKey: payload, mediation: options.mediation || 'optional' }), signal);
    if (resp && resp.ok && resp.result) return makeAssertion(resp.result, assertionExtensions(payload, resp.result));
    const code = resp && resp.error ? resp.error.code : null;
    if (!code || (FALLBACK_CODES[code] === 1 && resp.final !== true)) return origGet.call(container, options);
    throw domError(code, resp.error.message);
  }

  // Passkey autofill. The browser's own conditional request runs in parallel so its passkeys still
  // show; whichever the user picks wins and the other is cancelled.
  function conditionalGet(container, options, payload) {
    const signal = options.signal;
    return new PromiseCtor((resolve, reject) => {
      let settled = false;
      let nativeError = null;
      let passGone = false;
      const internal = new AbortControllerCtor();
      const req = call('get', { publicKey: payload, mediation: 'conditional' });
      const finish = (fn, value) => {
        if (settled) return;
        settled = true;
        if (signal) removeEL.call(signal, 'abort', onAbort);
        fn(value);
      };
      const onAbort = () => {
        cancel(req.rid);
        internal.abort(abortReason(signal));
        finish(reject, abortReason(signal));
      };
      if (signal) addEL.call(signal, 'abort', onAbort, { once: true });

      const nativeOptions = Object.assign({}, options, { signal: internal.signal });
      PromiseCtor.resolve()
        .then(() => origGet.call(container, nativeOptions))
        .then((cred) => { cancel(req.rid); finish(resolve, cred); },
          (err) => {
            if (internal.signal.aborted) return;
            nativeError = err;
            if (passGone) finish(reject, err);
          });

      req.promise.then((resp) => {
        if (resp && resp.ok && resp.result) {
          internal.abort(new DOMExceptionCtor('Handled by Passyble', 'AbortError'));
          finish(resolve, makeAssertion(resp.result, assertionExtensions(payload, resp.result)));
          return;
        }
        // Disabled, no bridge or no passkey: only the native request remains.
        passGone = true;
        if (nativeError) finish(reject, nativeError);
      });
    });
  }

  // `function` + `arguments` keeps .length === 0 and .name like the native methods.
  const wrappedCreate = function create() {
    const options = arguments[0];
    if (!isPublicKeyOnly(options)) return origCreate.apply(this, arguments);
    return passCreate(this, options);
  };
  const wrappedGet = function get() {
    const options = arguments[0];
    if (!isPublicKeyOnly(options)) return origGet.apply(this, arguments);
    return passGet(this, options);
  };

  function replaceMethod(target, name, fn, nativeFn) {
    if (typeof nativeFn === 'function') defineProperty(fn, NATIVE, { value: nativeFn });
    const desc = Object.getOwnPropertyDescriptor(target, name);
    defineProperty(target, name, {
      value: fn,
      writable: desc ? desc.writable : true,
      enumerable: desc ? desc.enumerable : false,
      configurable: true,
    });
  }

  replaceMethod(CC.prototype, 'create', wrappedCreate, natives.create);
  replaceMethod(CC.prototype, 'get', wrappedGet, natives.get);

  if (PKC) {
    const native = (name) => {
      const fn = orig(name);
      return typeof fn === 'function' ? fn.call(PKC) : false;
    };
    replaceMethod(PKC, 'isConditionalMediationAvailable', function isConditionalMediationAvailable() {
      return getConfig().then((c) => (c.enabled ? true : native('isConditionalMediationAvailable')));
    }, natives.isConditionalMediationAvailable);
    replaceMethod(PKC, 'isUserVerifyingPlatformAuthenticatorAvailable', function isUserVerifyingPlatformAuthenticatorAvailable() {
      return getConfig().then((c) => (c.enabled ? true : native('isUserVerifyingPlatformAuthenticatorAvailable')));
    }, natives.isUserVerifyingPlatformAuthenticatorAvailable);
    if (typeof previous.getClientCapabilities === 'function') {
      replaceMethod(PKC, 'getClientCapabilities', function getClientCapabilities() {
        // Config first: it settles bridgeReady, which decides which copy's method answers.
        return getConfig().then((c) => PromiseCtor.all([native('getClientCapabilities'), c])).then(([caps, c]) => {
          if (!c.enabled) return caps;
          return Object.assign({}, caps, {
            conditionalGet: true,
            passkeyPlatformAuthenticator: true,
            userVerifyingPlatformAuthenticator: true,
          });
        });
      }, natives.getClientCapabilities);
    }
  }
})();
