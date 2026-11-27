// Integration: real bridge.js (isolated world) and webauthn-main.js (MAIN world) in one jsdom page.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { MAIN_SRC, BRIDGE_SRC, GET_OPTIONS, CREATE_OPTIONS, GET_RESULT, CREATE_RESULT } from './helpers/webauthn-env.js';

function makeIntegratedPage({ order = 'bridge-first', passkeys = true, reply, setup } = {}) {
  const dom = new JSDOM('<!doctype html><html><body></body></html>', { runScripts: 'outside-only', url: 'https://example.com/' });
  const w = dom.window;
  // Minimal fake WebAuthn surface (see helpers/webauthn-env.js for the fuller one).
  w.eval(`
    window.__native = [];
    class CredentialsContainer {
      create(o) { window.__native.push(['create', o]); return Promise.resolve({ native: 'create' }); }
      get(o) {
        window.__native.push(['get', o]);
        if (o && o.mediation === 'conditional') return new Promise((res, rej) => o.signal && o.signal.addEventListener('abort', () => rej(new DOMException('aborted', 'AbortError'))));
        return Promise.resolve({ native: 'get' });
      }
    }
    window.CredentialsContainer = CredentialsContainer;
    Object.defineProperty(navigator, 'credentials', { value: new CredentialsContainer(), configurable: true });
    window.PublicKeyCredential = class PublicKeyCredential {};
    window.AuthenticatorAttestationResponse = class AuthenticatorAttestationResponse {};
    window.AuthenticatorAssertionResponse = class AuthenticatorAssertionResponse {};
  `);
  const sent = [];
  w.chrome = {
    runtime: {
      id: 'pass-test',
      sendMessage: async (msg) => { sent.push(msg); return reply(msg); },
    },
    storage: { local: { get: async (defaults) => ({ ...defaults, passkeys }) } },
  };
  setup?.(w);
  if (order === 'bridge-first') { w.eval(BRIDGE_SRC); w.eval(MAIN_SRC); } else { w.eval(MAIN_SRC); w.eval(BRIDGE_SRC); }
  return { window: w, sent, run: (code) => w.eval(code) };
}

for (const order of ['bridge-first', 'main-first']) {
  test(`get round-trips through the bridge to the background (${order})`, async () => {
    const page = makeIntegratedPage({ order, reply: () => ({ ok: true, result: GET_RESULT }) });
    const cred = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
    assert.equal(cred.id, 'AQID');
    assert.equal(page.sent.length, 1);
    assert.equal(page.sent[0].type, 'passkey.get');
    assert.equal(page.sent[0].options.challenge, 'BQYH');
    assert.equal(page.sent[0].options.rpId, 'example.com');
    assert.equal('origin' in page.sent[0], false, 'the page never supplies the origin; the background derives it');
  });
}

test('create round-trips and background errors reach the page as DOMExceptions', async () => {
  let n = 0;
  const page = makeIntegratedPage({ reply: () => (n++ === 0 ? { ok: true, result: CREATE_RESULT } : { ok: false, error: { code: 'cancelled', message: 'Denied' } }) });
  const cred = await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  assert.equal(cred.response.getPublicKeyAlgorithm(), -7);
  assert.equal(page.sent[0].type, 'passkey.create');
  await assert.rejects(page.run(`navigator.credentials.create(${CREATE_OPTIONS})`), (e) => e.name === 'NotAllowedError');
});

test('runtime failure (e.g. extension reloaded) falls back to native', async () => {
  const page = makeIntegratedPage({ reply: () => { throw new Error('Extension context invalidated.'); } });
  const res = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(res.native, 'get');
});

test('a message that did not reach the background (service worker starting) is sent once more', async () => {
  let n = 0;
  const page = makeIntegratedPage({ reply: () => {
    if (n++ === 0) throw new Error('Could not establish connection. Receiving end does not exist.');
    return { ok: true, result: GET_RESULT };
  } });
  const cred = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(cred.id, 'AQID');
  assert.equal(page.sent.length, 2, 'retried once');
  assert.equal(page.window.__native.length, 0, 'Passyble answered, not the browser');
});

test('a service worker slow to wake (Brave) gets growing pauses, about 2 s in all, before the browser takes over', async () => {
  let n = 0;
  const slow = makeIntegratedPage({ reply: () => {
    if (n++ < 3) throw new Error('Could not establish connection. Receiving end does not exist.');
    return { ok: true, result: GET_RESULT };
  } });
  const started = Date.now();
  const cred = await slow.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(cred.id, 'AQID');
  assert.equal(slow.sent.length, 4, 'three retries');
  assert.ok(Date.now() - started >= 1650, '250 + 500 + 1000 ms');

  const gone = makeIntegratedPage({ reply: () => { throw new Error('Could not establish connection. Receiving end does not exist.'); } });
  const res = await gone.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(res.native, 'get');
  assert.equal(gone.sent.length, 4, 'gives up after three retries');
});

test('other send failures are not repeated (the message may have arrived); the browser takes over', async () => {
  const page = makeIntegratedPage({ reply: () => { throw new Error('The message port closed before a response was received.'); } });
  const res = await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  assert.equal(res.native, 'create');
  assert.equal(page.sent.length, 1);
});

test('extension updated while a request is on its way: extension_reloaded, and the browser takes over', async () => {
  const page = makeIntegratedPage({ reply: () => {
    page.window.chrome.runtime.id = undefined; // the context is gone
    throw new Error('Extension context invalidated.');
  } });
  const res = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(res.native, 'get');
  assert.equal(page.sent.length, 1, 'no retry into a dead context');
});

test('passkeys disabled in options: native WebAuthn, background never asked', async () => {
  const page = makeIntegratedPage({ passkeys: false, reply: () => ({ ok: true, result: GET_RESULT }) });
  const res = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(res.native, 'get');
  assert.equal(page.sent.length, 0);
  assert.equal(await page.run('PublicKeyCredential.isConditionalMediationAvailable ? PublicKeyCredential.isConditionalMediationAvailable() : false'), false);
});

test('conditional mediation is completed from the inline menu via __passBridge', async () => {
  const page = makeIntegratedPage({ reply: (msg) => (msg.id === 'item-1' ? { ok: true, result: GET_RESULT } : { ok: false, error: { code: 'not_found' } }) });
  const changes = [];
  page.window.__passBridge.onConditionalChange((v) => changes.push(v));
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional' }))`);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(page.window.__passBridge.hasConditional(), true);
  assert.equal(page.sent.length, 0, 'nothing sent until the user picks');

  const miss = await page.window.__passBridge.completeConditional('other');
  assert.equal(miss.ok, false);
  assert.equal(page.window.__passBridge.hasConditional(), true, 'a failed pick keeps the request pending');

  const hit = await page.window.__passBridge.completeConditional('item-1');
  assert.equal(hit.ok, true);
  const cred = await p;
  assert.equal(cred.id, 'AQID');
  assert.equal(page.sent.at(-1).mediation, 'conditional');
  assert.equal(page.sent.at(-1).id, 'item-1');
  assert.equal(page.window.__passBridge.hasConditional(), false);
  assert.deepEqual(changes, [true, false]);
});

test('the pending conditional request: rpId and allowCredentials for passkey.find, never the challenge', async () => {
  const page = makeIntegratedPage({ reply: () => ({ ok: true, result: GET_RESULT }) });
  assert.equal(page.window.__passBridge.conditionalRequest(), null);
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional' }))`);
  await new Promise((r) => setTimeout(r, 10));
  const req = page.window.__passBridge.conditionalRequest();
  assert.equal(typeof req.rid, 'string');
  assert.equal(req.rpId, 'example.com');
  assert.equal(JSON.stringify(req.allowCredentials), '[{"id":"AQE"}]'); // another realm: compared as JSON
  assert.equal('challenge' in req, false);
  assert.ok(Object.isFrozen(req));
  assert.equal(page.sent.length, 0, 'looking at it sends nothing');

  // The passkey card names which passkey of the login: passed on to the background.
  const hit = await page.window.__passBridge.completeConditional('item-1', 'AQE');
  assert.equal(hit.ok, true);
  await p;
  assert.equal(page.sent.at(-1).id, 'item-1');
  assert.equal(page.sent.at(-1).credentialId, 'AQE');
  assert.equal(page.sent.at(-1).userActivated, true);
  assert.equal(page.window.__passBridge.conditionalRequest(), null);
});

test('no passkey in Passyble: endConditional steps out at once; the browser\'s own conditional request alone answers the page', async () => {
  // The browser's own conditional request settles when the test says (its passkey autofill picked).
  const setup = (w) => w.eval(`
    const nativeGet = CredentialsContainer.prototype.get;
    CredentialsContainer.prototype.get = function get(o) {
      if (!o || o.mediation !== 'conditional') return nativeGet.call(this, o);
      window.__native.push(['get', o]);
      return new Promise((res, rej) => { window.__settleNative = { res, rej, signal: o.signal }; });
    };
  `);
  const page = makeIntegratedPage({ setup, reply: () => ({ ok: true, result: GET_RESULT }) });
  const changes = [];
  page.window.__passBridge.onConditionalChange((v) => changes.push(v));
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional' }))`);
  await new Promise((r) => setTimeout(r, 10));
  const { rid } = page.window.__passBridge.conditionalRequest();
  assert.equal(page.window.__passBridge.endConditional('not-this-one'), false);
  assert.equal(page.window.__passBridge.endConditional(rid), true);
  assert.equal(page.window.__passBridge.hasConditional(), false);
  assert.deepEqual(changes, [true, false]);
  assert.equal(page.window.__passBridge.endConditional(rid), false, 'once');
  assert.equal(page.sent.length, 0, 'the background was never asked');
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(page.window.__native.length, 1, "the browser's own conditional request, from the start");
  assert.equal(page.window.__settleNative.signal.aborted, false, 'and it keeps running');
  page.window.__settleNative.res({ native: 'conditional' });
  assert.equal((await p).native, 'conditional', "the page gets the browser's answer");
  // Its error, too, once Passyble is out (no hang).
  const page2 = makeIntegratedPage({ setup, reply: () => ({ ok: true, result: GET_RESULT }) });
  const p2 = page2.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional' }))`);
  await new Promise((r) => setTimeout(r, 10));
  page2.window.__passBridge.endConditional(page2.window.__passBridge.conditionalRequest().rid);
  await new Promise((r) => setTimeout(r, 10));
  page2.window.__settleNative.rej(new page2.window.DOMException('nope', 'NotAllowedError'));
  await assert.rejects(p2, (e) => e.name === 'NotAllowedError');
});

test('aborting a conditional request clears it from the bridge', async () => {
  const page = makeIntegratedPage({ reply: () => ({ ok: true, result: GET_RESULT }) });
  page.run('window.__ac = new AbortController()');
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional', signal: window.__ac.signal }))`);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(page.window.__passBridge.hasConditional(), true);
  page.run('window.__ac.abort()');
  await assert.rejects(p, (e) => e.name === 'AbortError');
  assert.equal(page.window.__passBridge.hasConditional(), false);
});

test('a page cannot hijack the channel after the handshake', async () => {
  const page = makeIntegratedPage({ reply: () => ({ ok: true, result: GET_RESULT }) });
  // A late fake hello is ignored by the bridge (it binds to the first one only).
  page.run(`window.dispatchEvent(new CustomEvent('pass-webauthn-hello-v1', { detail: 'pass-' + '0'.repeat(32) }))`);
  page.run(`window.dispatchEvent(new CustomEvent('pass-${'0'.repeat(32)}:req', { detail: JSON.stringify({ rid: 'x', op: 'get', payload: { publicKey: {} } }) }))`);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(page.sent.length, 0);
  const cred = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(cred.id, 'AQID');
});

test('opaque-origin document (sandboxed frame / CSP sandbox): native WebAuthn, background never asked', async () => {
  // Browsers report document.domain === "" exactly for opaque origins; jsdom has no sandboxing.
  const page = makeIntegratedPage({ reply: () => ({ ok: true, result: GET_RESULT }),
    setup: (w) => Object.defineProperty(w.document, 'domain', { value: '', configurable: true }) });
  const cred = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(cred.native, 'get');
  assert.equal(page.sent.length, 0);
  assert.equal(await page.run('PublicKeyCredential.isConditionalMediationAvailable()'), false, 'Passyble not offered there');
});

test('requests tell the background whether a parent frame has another origin', async () => {
  const page = makeIntegratedPage({ reply: () => ({ ok: true, result: GET_RESULT }) });
  await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  assert.equal(page.sent[0].crossOriginAncestor, false, 'top-level document');
});

// User activation: only a ceremony the user started may ask a locked Passyble to unlock.

const activation = (state) => (w) => Object.defineProperty(w.navigator, 'userActivation', { value: state, configurable: true });

test('a passkey request on page load (a tab restored at browser start) says nobody started it', async () => {
  const locked = () => ({ ok: false, error: { code: 'locked', message: 'Vault is locked' } });
  for (const setup of [activation({ isActive: false, hasBeenActive: false }), undefined]) {
    const page = makeIntegratedPage({ reply: locked, setup });
    const res = await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
    assert.equal(page.sent[0].userActivated, false);
    // Locked: the browser's own WebAuthn, no Passyble prompt (the background never asks to unlock).
    assert.equal(res.native, 'get');
    const created = await page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
    assert.equal(page.sent[1].type, 'passkey.create');
    assert.equal(page.sent[1].userActivated, false);
    assert.equal(created.native, 'create');
  }
});

test('a passkey request right after the user clicked says so', async () => {
  for (const state of [{ isActive: true, hasBeenActive: true }, { isActive: false, hasBeenActive: true }]) {
    const page = makeIntegratedPage({ reply: () => ({ ok: true, result: GET_RESULT }), setup: activation(state) });
    await page.run(`navigator.credentials.get(${GET_OPTIONS})`);
    assert.equal(page.sent[0].userActivated, true);
  }
});

test('conditional mediation on page load sends nothing; the pick in the menu is the user starting it', async () => {
  const page = makeIntegratedPage({ reply: () => ({ ok: true, result: GET_RESULT }), setup: activation({ isActive: false, hasBeenActive: false }) });
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { mediation: 'conditional' }))`);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(page.sent.length, 0, 'parked until the user picks a passkey in the Passyble menu');
  await page.window.__passBridge.completeConditional('item-1');
  await p;
  assert.equal(page.sent.length, 1);
  assert.equal(page.sent[0].userActivated, true);
});

// A page's own get() / create(), answered in Passyble's card (src/content/passkey-flow.js).

/** A page whose content script takes the page's own requests (`onModalRequest`): what it was told. */
function modalPage(reply, { take = true } = {}) {
  const page = makeIntegratedPage({ reply });
  page.asked = [];
  page.changes = [];
  page.window.__passBridge.onModalRequest((info) => { page.asked.push(info); return take; });
  page.window.__passBridge.onModalChange((rid) => page.changes.push(rid));
  return page;
}
const settle = () => new Promise((r) => setTimeout(r, 10));

test("a page's own get() waits for the card: nothing goes out until the pick, which names the passkey", async () => {
  const page = modalPage((msg) => (msg.id === 'item-1' ? { ok: true, result: GET_RESULT } : { ok: false, error: { code: 'cancelled', message: 'no' } }));
  const p = page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  await settle();
  assert.equal(page.sent.length, 0, 'parked for the card');
  const [info] = page.asked;
  assert.equal(info.kind, 'get');
  assert.equal(info.rpId, 'example.com');
  assert.equal(JSON.stringify(info.allowCredentials), '[{"id":"AQE"}]');
  assert.equal('challenge' in info, false, 'never the challenge');
  assert.ok(Object.isFrozen(info));
  assert.ok(page.window.__passBridge.hasModal(info.rid));

  // A failed attempt (Windows Hello declined) keeps the request for another try.
  const miss = await page.window.__passBridge.completeModal(info.rid, { id: 'item-2', credentialId: 'AQE' });
  assert.equal(miss.ok, false);
  assert.ok(page.window.__passBridge.hasModal(info.rid));

  const hit = await page.window.__passBridge.completeModal(info.rid, { id: 'item-1', credentialId: 'AQE' });
  assert.equal(hit.ok, true);
  const cred = await p;
  assert.equal(cred.id, 'AQID');
  const sent = page.sent.at(-1);
  assert.equal(sent.type, 'passkey.get');
  assert.equal(sent.id, 'item-1');
  assert.equal(sent.credentialId, 'AQE');
  assert.equal(sent.userActivated, true, 'the click in the card');
  assert.equal(sent.inPage, true, 'locked meanwhile: `locked` back, no desktop unlock window');
  assert.equal(sent.options.challenge, 'BQYH');
  assert.equal(page.window.__passBridge.hasModal(info.rid), false);
  assert.deepEqual(page.changes, [null]);
  assert.equal(page.window.__native.length, 0);
});

test("a page's own create() saved from the card carries the login chosen there", async () => {
  const page = modalPage(() => ({ ok: true, result: CREATE_RESULT }));
  const p = page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  await settle();
  const [info] = page.asked;
  assert.equal(info.kind, 'create');
  assert.equal(info.rpId, 'example.com');
  assert.equal(info.rpName, 'Example');
  assert.equal(JSON.stringify(info.user), '{"name":"alice","displayName":"Alice"}', 'no user handle');
  assert.equal(JSON.stringify(info.excludeCredentials), '[{"id":"-_8"}]');
  assert.equal(page.sent.length, 0);
  await page.window.__passBridge.completeModal(info.rid, { itemId: 'login-7' });
  const cred = await p;
  assert.equal(cred.response.getPublicKeyAlgorithm(), -7);
  assert.equal(page.sent[0].type, 'passkey.create');
  assert.equal(JSON.stringify(page.sent[0].consent), '{"itemId":"login-7"}');
  assert.equal(page.sent[0].inPage, true);

  const again = page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  await settle();
  await page.window.__passBridge.completeModal(page.asked[1].rid, { itemId: null });
  await again;
  assert.equal(JSON.stringify(page.sent[1].consent), '{"itemId":null}');
});

test('"Use another device" hands the request to the browser; Cancel fails it; an answer goes as it is', async () => {
  const page = modalPage(() => ({ ok: true, result: GET_RESULT }));
  const p1 = page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  await settle();
  assert.equal(page.window.__passBridge.endModal(page.asked[0].rid, 'fallback'), true);
  assert.equal((await p1).native, 'get', "the browser's own WebAuthn");

  const p2 = page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  await settle();
  page.window.__passBridge.endModal(page.asked[1].rid, 'cancel');
  await assert.rejects(p2, (e) => e.name === 'NotAllowedError');

  const p3 = page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  await settle();
  page.window.__passBridge.endModal(page.asked[2].rid, { ok: false, error: { code: 'invalid_state', message: 'there already' } });
  await assert.rejects(p3, (e) => e.name === 'InvalidStateError');
  assert.equal(page.sent.length, 0, 'the background was never asked');
  // A request that is gone can't be answered again.
  assert.equal(page.window.__passBridge.endModal(page.asked[2].rid, 'fallback'), false);
});

test('the page aborting its request takes it from the bridge (and the card with it)', async () => {
  const page = modalPage(() => ({ ok: true, result: GET_RESULT }));
  page.run('window.__ac = new AbortController()');
  const p = page.run(`navigator.credentials.get(Object.assign(${GET_OPTIONS}, { signal: window.__ac.signal }))`);
  await settle();
  const { rid } = page.asked[0];
  page.run('window.__ac.abort()');
  await assert.rejects(p, (e) => e.name === 'AbortError');
  assert.equal(page.window.__passBridge.hasModal(rid), false);
  assert.deepEqual(page.changes, [null]);
  const late = await page.window.__passBridge.completeModal(rid, { id: 'item-1' });
  assert.equal(late.ok, false);
  assert.equal(page.sent.length, 0);
});

test('an older desktop app, or a content script that declines: the request goes out as before', async () => {
  const page = modalPage(() => ({ ok: true, result: GET_RESULT }));
  const p = page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  await settle();
  assert.equal(page.window.__passBridge.passModal(page.asked[0].rid), true);
  assert.equal((await p).id, 'AQID');
  assert.equal(page.sent[0].type, 'passkey.get');
  assert.equal('id' in page.sent[0], false, 'nothing picked: the desktop app asks');
  assert.equal('inPage' in page.sent[0], false);

  const declining = modalPage(() => ({ ok: true, result: CREATE_RESULT }), { take: false });
  const cred = await declining.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  assert.equal(cred.id, 'AQID');
  assert.equal(declining.sent.length, 1);
  assert.equal('consent' in declining.sent[0], false);
});

test('a newer request replaces one still waiting for the card', async () => {
  const page = modalPage(() => ({ ok: true, result: GET_RESULT }));
  const first = page.run(`navigator.credentials.get(${GET_OPTIONS})`).catch((e) => e);
  await settle();
  const second = page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  await settle();
  assert.equal((await first).name, 'NotAllowedError');
  assert.equal(page.window.__passBridge.hasModal(page.asked[0].rid), false);
  assert.equal(page.window.__passBridge.hasModal(page.asked[1].rid), true);
  page.window.__passBridge.endModal(page.asked[1].rid, 'fallback');
  assert.equal((await second).native, 'get');
});

test("an answer the card decided is final: the page gets its DOMException, never the browser's own WebAuthn", async () => {
  const page = modalPage(() => ({ ok: true, result: GET_RESULT }));
  // Codes that, sent by the background as the request came, mean "the browser takes over".
  for (const code of ['not_found', 'not_supported', 'locked', 'internal', 'agent_unavailable', 'timeout', 'invalid_params']) {
    const p = page.run(`navigator.credentials.get(${GET_OPTIONS})`);
    await settle();
    page.window.__passBridge.endModal(page.asked.at(-1).rid, { ok: false, error: { code, message: 'x' } });
    await assert.rejects(p, (e) => e.name === 'NotAllowedError', code);
  }
  const p = page.run(`navigator.credentials.create(${CREATE_OPTIONS})`);
  await settle();
  page.window.__passBridge.endModal(page.asked.at(-1).rid, { ok: false, error: { code: 'url_mismatch', message: 'x' } });
  await assert.rejects(p, (e) => e.name === 'SecurityError');
  assert.equal(page.window.__native.length, 0, "the browser's own WebAuthn never ran");
  assert.equal(page.sent.length, 0);
});

test('a request once the page has loaded, before loader.js came: the bridge starts the content script, and its card takes the request', async () => {
  const urls = [];
  let page = null;
  page = makeIntegratedPage({
    reply: () => ({ ok: true, result: GET_RESULT }),
    setup: (w) => {
      w.chrome.runtime.getURL = (p) => {
        urls.push(p);
        // main.js start(), which takes the page's requests at once.
        page.asked = [];
        w.__passBridge.onModalRequest((info) => { page.asked.push(info); return true; });
        return `chrome-extension://pass-test/${p}`;
      };
    },
  });
  const p = page.run(`navigator.credentials.get(${GET_OPTIONS})`);
  await new Promise((r) => setTimeout(r, 400)); // the page loaded, loader.js gets a moment first
  assert.deepEqual(urls, ['src/content/main.js'], 'the bridge imports the content script itself (jsdom cannot load it: the stand-in above takes the requests)');
  assert.equal(page.sent.length, 0, 'parked for the card, not sent as it came');
  assert.equal(page.asked.length, 1);
  page.window.__passBridge.endModal(page.asked[0].rid, 'cancel');
  await assert.rejects(p, (e) => e.name === 'NotAllowedError');
  assert.equal(page.window.__native.length, 0);
});
