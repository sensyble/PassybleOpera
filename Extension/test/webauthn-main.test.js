import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makePage, MAIN_SRC, CREATE_OPTIONS, GET_OPTIONS, CREATE_RESULT, GET_RESULT, bytes } from './helpers/webauthn-env.js';

// Values from the page realm have other prototypes; compare their JSON shape.
const same = (actual, expected, msg) => assert.deepEqual(JSON.parse(JSON.stringify(actual)), expected, msg);
const ok = (result) => ({ ok: true, result });
const fail = (code, message) => ({ ok: false, error: { code, message } });

test('wrappers keep native-looking names and lengths', () => {
  const { run } = makePage();
  assert.equal(run('navigator.credentials.get.name'), 'get');
  assert.equal(run('navigator.credentials.create.name'), 'create');
  assert.equal(run('navigator.credentials.get.length'), 0);
});

test('create: serialises options to base64url and builds a PublicKeyCredential', async () => {
  const page = makePage({ handler: (m) => (m.op === 'create' ? ok(CREATE_RESULT) : undefined) });
  const cred = await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  const req = page.requests.find((r) => r.op === 'create');
  const pk = req.payload.publicKey;
  assert.equal(pk.challenge, 'CQgH');
  assert.equal(pk.user.id, 'AQIDBA');
  assert.equal(pk.user.name, 'alice');
  same(pk.rp, { id: 'example.com', name: 'Example' });
  same(pk.excludeCredentials, [{ type: 'public-key', id: '-_8' }]);
  same(pk.pubKeyCredParams, [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -257 }]);

  const w = page.window;
  assert.ok(cred instanceof w.PublicKeyCredential);
  assert.ok(cred.response instanceof w.AuthenticatorAttestationResponse);
  assert.equal(cred.id, 'AQID');
  assert.equal(cred.type, 'public-key');
  assert.equal(cred.authenticatorAttachment, 'platform');
  same(bytes(cred.rawId), [1, 2, 3]);
  assert.equal(new TextDecoder().decode(cred.response.clientDataJSON), '{"type":"webauthn.create"}');
  same(cred.response.getTransports(), ['internal', 'hybrid']);
  assert.equal(cred.response.getPublicKeyAlgorithm(), -7);
  assert.ok(cred.response.getPublicKey().byteLength > 0);
  assert.ok(cred.response.getAuthenticatorData().byteLength >= 37);
  assert.ok(cred.response.attestationObject.byteLength > 0);
  same(cred.getClientExtensionResults(), { credProps: { rk: true } });
  const json = cred.toJSON();
  assert.equal(json.id, 'AQID');
  assert.equal(json.rawId, 'AQID');
  assert.equal(json.type, 'public-key');
  assert.equal(json.authenticatorAttachment, 'platform');
  assert.equal(json.response.attestationObject, CREATE_RESULT.attestationObject);
  assert.equal(json.response.publicKeyAlgorithm, -7);
  same(json.response.transports, ['internal', 'hybrid']);
  assert.equal(JSON.parse(w.JSON.stringify(cred)).id, 'AQID', 'JSON.stringify uses toJSON');
  assert.equal(w.__native.length, 0, 'native create was not called');
});

test('get: serialises the request and builds an assertion', async () => {
  const page = makePage({ handler: (m) => (m.op === 'get' ? ok(GET_RESULT) : undefined) });
  const cred = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  const pk = page.requests[0].payload.publicKey;
  assert.equal(pk.challenge, 'BQYH');
  assert.equal(pk.rpId, 'example.com');
  assert.equal(pk.userVerification, 'required');
  same(pk.allowCredentials, [{ type: 'public-key', id: 'AQE', transports: ['internal'] }]);
  assert.ok(cred.response instanceof page.window.AuthenticatorAssertionResponse);
  same(bytes(cred.response.userHandle), [1, 2, 3, 4]);
  assert.ok(cred.response.signature.byteLength > 0);
  same(cred.getClientExtensionResults(), {});
  assert.equal(cred.toJSON().response.signature, 'MEUCIQ');
});

for (const code of ['not_found', 'agent_unavailable', 'timeout', 'extension_reloaded', 'locked', 'internal', 'invalid_params']) {
  test(`falls back to native WebAuthn on ${code}`, async () => {
    const page = makePage({ handler: () => fail(code) });
    const res = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
    same(res, { native: 'get' });
    assert.equal(page.window.__native.length, 1);
    assert.equal(page.window.__native[0][1].publicKey.rpId, 'example.com', 'original options passed through');
  });
}

test('falls back when the bridge says passkeys are disabled', async () => {
  const page = makePage({ handler: () => ({ fallback: true }) });
  same(await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`), { native: 'create' });
});

test('maps errors to DOMExceptions', async () => {
  const cases = [
    [fail('cancelled', 'User declined'), 'NotAllowedError'],
    [fail('invalid_state', 'excluded'), 'InvalidStateError'],
    [fail('cancelled', 'invalid_state'), 'InvalidStateError'],
    [fail('url_mismatch', 'rp'), 'SecurityError'],
  ];
  for (const [reply, name] of cases) {
    const page = makePage({ handler: () => reply });
    await assert.rejects(page.run(`navigator.credentials.create(${CREATE_OPTIONS})`), (e) => e.name === name && e instanceof page.window.DOMException, name);
  }
});

test('password / federated requests and non-ES256 creations go straight to native', async () => {
  const page = makePage({ handler: () => ok(GET_RESULT) });
  same(await page.run('navigator.credentials.get({ password: true })'), { native: 'get' });
  same(await page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { password: true }))`), { native: 'get' });
  same(await page.run('navigator.credentials.create({ password: { id: "a", password: "b" } })'), { native: 'create' });
  const rsaOnly = CREATE_OPTIONS.replace("{ type: 'public-key', alg: -7 }, ", '');
  same(await page.run(`navigator.credentials.create(${rsaOnly})`), { native: 'create' });
  const crossPlatform = CREATE_OPTIONS.replace("residentKey: 'required'", "authenticatorAttachment: 'cross-platform'");
  same(await page.run(`navigator.credentials.create(${crossPlatform})`), { native: 'create' });
  assert.equal(page.requests.filter((r) => r.op === 'get' || r.op === 'create').length, 0);
});

test('AbortSignal: an aborted request rejects with the reason and tells the bridge to cancel', async () => {
  const page = makePage({ handler: () => undefined }); // never answers
  page.run('window.__ac = new AbortController()');
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { signal: window.__ac.signal }))`);
  await new Promise((r) => setTimeout(r, 5));
  page.run('window.__ac.abort()');
  await assert.rejects(p, (e) => e.name === 'AbortError');
  const cancel = page.requests.find((r) => r.op === 'cancel');
  assert.ok(cancel, 'cancel sent');
  assert.equal(cancel.payload.target, page.requests.find((r) => r.op === 'get').rid);
});

test('AbortSignal: already aborted rejects without contacting Passyble', async () => {
  const page = makePage({ handler: () => ok(GET_RESULT) });
  await assert.rejects(page.run(`(() => { const c = new AbortController(); c.abort(); return navigator.credentials.get(Object.assign(${GET_OPTIONS}, { signal: c.signal })); })()`),
    (e) => e.name === 'AbortError');
  assert.equal(page.requests.length, 0);
});

test('no bridge: falls back to native after a short wait', async () => {
  const page = makePage({ bridge: false });
  const t0 = Date.now();
  same(await page.run(`navigator.credentials.get(${GET_OPTIONS})`), { native: 'get' });
  assert.ok(Date.now() - t0 >= 250);
});

test('responses with unknown request ids are ignored (spoofing)', async () => {
  let pass;
  const page = makePage({ handler: (m) => { if (m.op === 'get') pass = m; return undefined; } });
  const p = page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  await new Promise((r) => setTimeout(r, 5));
  page.state.respond('f'.repeat(32), ok(GET_RESULT));
  page.window.dispatchEvent(new page.window.CustomEvent(`${page.state.channel}:res`, { detail: 'not json' }));
  let settled = false;
  p.then(() => { settled = true; }, () => { settled = true; });
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(settled, false);
  page.state.respond(pass.rid, fail('not_found'));
  same(await p, { native: 'get' });
});

test('conditional mediation: Passyble result wins and the native conditional request is aborted', async () => {
  let conditionalReq;
  const page = makePage({ handler: (m) => { if (m.op === 'get') conditionalReq = m; return undefined; } });
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional' }))`);
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(conditionalReq.payload.mediation, 'conditional');
  const nativeCall = page.window.__native.find((c) => c[0] === 'get');
  assert.ok(nativeCall, 'native conditional request runs in parallel');
  assert.equal(nativeCall[1].mediation, 'conditional');
  page.state.respond(conditionalReq.rid, ok(GET_RESULT)); // user picked the passkey in the Passyble menu
  const cred = await p;
  assert.equal(cred.id, 'AQID');
  assert.equal(nativeCall[1].signal.aborted, true);
});

test('conditional mediation: native result wins and Passyble is told to cancel', async () => {
  const page = makePage({ handler: () => undefined });
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional' }))`);
  await new Promise((r) => setTimeout(r, 5));
  page.window.__resolveNativeConditional({ native: 'conditional' });
  same(await p, { native: 'conditional' });
  assert.ok(page.requests.some((r) => r.op === 'cancel'));
});

test('conditional mediation: page abort rejects and cancels both', async () => {
  const page = makePage({ handler: () => undefined });
  page.run('window.__ac = new AbortController()');
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional', signal: window.__ac.signal }))`);
  await new Promise((r) => setTimeout(r, 5));
  page.run('window.__ac.abort()');
  await assert.rejects(p, (e) => e.name === 'AbortError');
  assert.ok(page.requests.some((r) => r.op === 'cancel'));
});

test('isConditionalMediationAvailable / UVPA / capabilities follow the setting', async () => {
  let enabled = true;
  const page = makePage({ handler: (m) => (m.op === 'config' ? ok({ enabled }) : undefined) });
  assert.equal(await page.run('PublicKeyCredential.isConditionalMediationAvailable()'), true);
  assert.equal(await page.run('PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()'), true);
  const caps = await page.run('PublicKeyCredential.getClientCapabilities()');
  assert.equal(caps.conditionalGet, true);
  assert.equal(caps.hybridTransport, true);

  enabled = false;
  const off = makePage({ handler: (m) => (m.op === 'config' ? ok({ enabled }) : undefined) });
  assert.equal(await off.run('PublicKeyCredential.isConditionalMediationAvailable()'), false);
});

test('not_supported from Passyble (e.g. no ES256 acceptable) falls back to the browser', async () => {
  const page = makePage({ handler: (msg) => (msg.op === 'config' ? { ok: true, result: { enabled: true } } : { ok: false, error: { code: 'not_supported', message: 'only ES256' } }) });
  same(await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`), { native: 'create' });
  same(await page.run(`navigator.credentials.get(${GET_OPTIONS})`), { native: 'get' });
});

test('mediation Passyble cannot honour (silent / immediate get, conditional create) goes straight to the browser', async () => {
  const page = makePage({ handler: () => ({ ok: true, result: GET_RESULT }) });
  for (const [call, mediation] of [['get', 'silent'], ['get', 'immediate'], ['create', 'conditional']]) {
    const opts = call === 'get' ? GET_OPTIONS : CREATE_OPTIONS;
    const res = await page.run(`navigator.credentials.${call}(Object.assign(${opts}, { mediation: '${mediation}' }))`);
    same(res, { native: call }, `${call} ${mediation}`);
  }
  assert.equal(page.requests.filter((r) => r.op === 'get' || r.op === 'create').length, 0, 'no Passyble window for these');
  const required = await page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'required' }))`);
  assert.equal(required.id, 'AQID', 'required mediation is still served by Passyble');
});

test('a dead bridge (extension reloaded) lets the browser take over instead of hanging', async () => {
  const page = makePage({ handler: (m) => (m.op === 'create' ? ok(CREATE_RESULT) : undefined) });
  page.state.dead = true; // the bridge stops confirming requests (its runtime is gone)
  const res = await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  same(res, { native: 'create' });
  assert.equal(page.window.__native.length, 1);
});

test('re-injected after a reload: falls back to the browser, not to the dead previous copy', async () => {
  const page = makePage({ handler: () => undefined });
  const w = page.window;
  page.state.dead = true;
  // The new bridge, injected before the new copy of webauthn-main.js (background.js injectContentScripts).
  const fresh = { requests: [] };
  w.addEventListener('pass-webauthn-hello-v1', (e) => {
    if (fresh.channel) return;
    fresh.channel = e.detail;
    w.addEventListener(`${fresh.channel}:req`, (ev) => {
      const msg = JSON.parse(ev.detail);
      w.dispatchEvent(new w.CustomEvent(`${fresh.channel}:got`, { detail: msg.rid }));
      fresh.requests.push(msg);
      const reply = msg.op === 'config' ? ok({ enabled: true }) : msg.op === 'create' ? ok(CREATE_RESULT) : msg.op === 'get' ? fail('not_found', 'none') : null;
      if (reply) w.dispatchEvent(new w.CustomEvent(`${fresh.channel}:res`, { detail: JSON.stringify({ rid: msg.rid, ...reply }) }));
    });
    w.dispatchEvent(new w.CustomEvent(`${fresh.channel}:ack`));
  });
  w.eval(MAIN_SRC);
  // The new copy wraps the browser's own methods, recorded by the previous copy.
  const cred = await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  assert.equal(cred.id, 'AQID');
  same(await page.run(`navigator.credentials.get(${GET_OPTIONS})`), { native: 'get' }, 'not_found falls back to the browser');
  const caps = await page.run('PublicKeyCredential.getClientCapabilities()');
  assert.equal(caps.passkeyPlatformAuthenticator, true);
  assert.equal(caps.hybridTransport, true);
  assert.equal(page.requests.length, 0, 'nothing went to the dead copy');
  assert.ok(fresh.requests.some((r) => r.op === 'create'));
});

// WebAuthn PRF extension.
const PRF_OUT = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'; // bytes 0..31
const PRF_OUT2 = 'ICEiIyQlJicoKSorLC0uLzAxMjM0NTY3ODk6Ozw9Pj8'; // bytes 32..63
const range = (from) => Array.from({ length: 32 }, (_, i) => from + i);

test('prf at create: inputs go as base64url, enabled and results come back as ArrayBuffers', async () => {
  const result = { ...CREATE_RESULT, clientExtensionResults: { prf: { enabled: true, results: { first: PRF_OUT } } } };
  const page = makePage({ handler: (m) => (m.op === 'create' ? ok(result) : undefined) });
  const opts = CREATE_OPTIONS.replace('extensions: { credProps: true }',
    'extensions: { credProps: true, prf: { eval: { first: new Uint8Array([1, 2, 3]) } } }');
  const cred = await page.run(`navigator.credentials.create(${opts})`);
  const pk = page.requests.find((r) => r.op === 'create').payload.publicKey;
  same(pk.extensions, { credProps: true, prf: { eval: { first: 'AQID' } } });
  const ext = cred.getClientExtensionResults();
  assert.equal(ext.prf.enabled, true);
  assert.ok(ext.prf.results.first instanceof page.window.ArrayBuffer);
  same(bytes(ext.prf.results.first), range(0));
  assert.equal(ext.prf.results.second, undefined);
  same(ext.credProps, { rk: true });
  // toJSON: base64url, as browsers serialise it.
  same(cred.toJSON().clientExtensionResults, { credProps: { rk: true }, prf: { enabled: true, results: { first: PRF_OUT } } });
  // Each call returns a fresh copy.
  assert.notEqual(cred.getClientExtensionResults().prf.results.first, ext.prf.results.first);
});

test('prf at create with an older desktop app (no prf in the answer): enabled false', async () => {
  const page = makePage({ handler: (m) => (m.op === 'create' ? ok(CREATE_RESULT) : undefined) });
  const opts = CREATE_OPTIONS.replace('extensions: { credProps: true }', 'extensions: { prf: {} }');
  const cred = await page.run(`navigator.credentials.create(${opts})`);
  same(cred.getClientExtensionResults(), { prf: { enabled: false } });
});

test('prf at get: eval and evalByCredential serialised; results as ArrayBuffers; none asked, none given', async () => {
  const result = { ...GET_RESULT, clientExtensionResults: { prf: { results: { first: PRF_OUT, second: PRF_OUT2 } } } };
  const page = makePage({ handler: (m) => (m.op === 'get' ? ok(result) : undefined) });
  const opts = GET_OPTIONS.replace("userVerification: 'required',",
    "userVerification: 'required', extensions: { prf: { eval: { first: new Uint8Array([1]), second: new Uint8Array([2]).buffer }, evalByCredential: { AQE: { first: new Uint8Array([3]) } } } },");
  const cred = await page.run(`navigator.credentials.get(${opts})`);
  same(page.requests[0].payload.publicKey.extensions, { prf: { eval: { first: 'AQ', second: 'Ag' }, evalByCredential: { AQE: { first: 'Aw' } } } });
  const ext = cred.getClientExtensionResults();
  assert.equal(ext.prf.enabled, undefined, 'enabled is for registrations only');
  same(bytes(ext.prf.results.first), range(0));
  same(bytes(ext.prf.results.second), range(32));
  same(cred.toJSON().clientExtensionResults, { prf: { results: { first: PRF_OUT, second: PRF_OUT2 } } });

  // A passkey without a PRF: prf: {}.
  const page2 = makePage({ handler: (m) => (m.op === 'get' ? ok({ ...GET_RESULT, clientExtensionResults: { prf: {} } }) : undefined) });
  same((await page2.run(`navigator.credentials.get(${opts})`)).getClientExtensionResults(), { prf: {} });
  // Without prf in the request: no prf output even if one came back.
  const page3 = makePage({ handler: (m) => (m.op === 'get' ? ok(result) : undefined) });
  same((await page3.run(`navigator.credentials.get(${GET_OPTIONS})`)).getClientExtensionResults(), {});
});

test('a malformed prf input goes to the browser, which reports it', async () => {
  const page = makePage({ handler: () => ok(GET_RESULT) });
  const opts = GET_OPTIONS.replace("userVerification: 'required',", "userVerification: 'required', extensions: { prf: { eval: { first: 'not a buffer' } } },");
  same(await page.run(`navigator.credentials.get(${opts})`), { native: 'get' });
  assert.equal(page.requests.filter((r) => r.op === 'get').length, 0);
});
