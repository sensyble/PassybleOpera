import { test } from 'node:test';
import assert from 'node:assert/strict';
import { browserVaultSupported, lockOnComputerLockSupported } from '../src/shared/vault-mode.js';
import { cameBackTo, webAuthRedirect } from '../src/background/web-auth.js';
import { ACCOUNT_DATA, SYNC_DATA, askDataConsent, hasDataConsent, optionalDataCategories } from '../src/shared/data-consent.js';
import { isSafariExtension, safariPort } from '../src/background/native-safari.js';
import { NativeClient } from '../src/background/native-client.js';
import { isHostMissing } from '../src/shared/messages.js';

const FF_HASH = 'a616c7e5d8c971387d4568e8f94bdd4e9fe1b085';
const FF = `https://${FF_HASH}.extensions.allizom.org/`;
const CR = `https://${'abcdefghijklmnop'.repeat(2)}.chromiumapp.org/`;

test('the vault in this browser: wherever WebAssembly and storage.session are, by feature, not by name', () => {
  const session = { get: async () => ({}) };
  assert.equal(browserVaultSupported({ storage: { session } }, { WebAssembly }), true);
  assert.equal(browserVaultSupported({ storage: {} }, { WebAssembly }), false, 'no storage.session (Firefox before 115)');
  assert.equal(browserVaultSupported({ storage: { session } }, {}), false, 'no WebAssembly');
  assert.equal(browserVaultSupported(undefined, { WebAssembly }), false);
});

test('"Lock when the computer locks" only where the idle API is (Safari has none; Firefox is checked by name)', () => {
  assert.equal(lockOnComputerLockSupported({ idle: { onStateChanged: { addListener() {} } } }), true);
  assert.equal(lockOnComputerLockSupported({}), false);
});

test('launchWebAuthFlow redirect (the Passyble account): chromiumapp.org or Firefox allizom.org, else none', () => {
  const api = (uri) => ({ identity: { getRedirectURL: () => uri, launchWebAuthFlow: async () => '' } });
  assert.equal(webAuthRedirect(api(CR)), CR);
  assert.equal(webAuthRedirect(api(FF)), FF);
  for (const other of ['https://0123.extensions.allizom.org/', 'https://example.com/', '', undefined]) {
    assert.equal(webAuthRedirect(api(other)), null, String(other));
  }
  assert.equal(webAuthRedirect({}), null, 'no identity API (Safari)');
  assert.equal(webAuthRedirect({ identity: { getRedirectURL: () => CR } }), null, 'no launchWebAuthFlow');
  assert.equal(webAuthRedirect({ identity: { getRedirectURL: () => { throw new Error('x'); }, launchWebAuthFlow() {} } }), null);
});

test('launchWebAuthFlow redirect without getRedirectURL (Opera documents only launchWebAuthFlow): from the Chromium ID', () => {
  const id = 'abcdefghijklmnop'.repeat(2);
  assert.equal(webAuthRedirect({ runtime: { id }, identity: { launchWebAuthFlow() {} } }), CR);
  assert.equal(webAuthRedirect({ runtime: { id: 'pass@sensyble.com' }, identity: { launchWebAuthFlow() {} } }), null, 'not a Chromium ID');
  assert.equal(webAuthRedirect({ runtime: { id }, identity: {} }), null, 'no launchWebAuthFlow either');
  assert.equal(webAuthRedirect({ runtime: { id } }), null, 'no identity API');
  // A getRedirectURL that answers something unknown is not second-guessed.
  assert.equal(webAuthRedirect({ runtime: { id }, identity: { getRedirectURL: () => 'https://example.com/', launchWebAuthFlow() {} } }), null);
});

test('cameBackTo: the answer is at exactly the redirect (origin, or origin and path for a redirect with one)', () => {
  assert.equal(cameBackTo(`${FF}?code=1`, FF), true);
  assert.equal(cameBackTo(`https://${'0'.repeat(40)}.extensions.allizom.org/?code=1`, FF), false);
  const withPath = `http://127.0.0.1/back/${FF_HASH}`;
  assert.equal(cameBackTo(`${withPath}?code=1`, withPath), true);
  assert.equal(cameBackTo('http://127.0.0.1/back/other?code=1', withPath), false);
  assert.equal(cameBackTo('not a url', FF), false);
});

/** A Firefox-like API with the optional data consent categories. */
function firefoxApi({ grant = true, optional = SYNC_DATA } = {}) {
  const calls = [];
  return {
    calls,
    runtime: { getManifest: () => ({ browser_specific_settings: { gecko: { data_collection_permissions: { required: ['none'], optional } } } }) },
    permissions: {
      request: (q) => { calls.push(['request', q]); return Promise.resolve(grant); },
      contains: async (q) => { calls.push(['contains', q]); return grant; },
    },
  };
}

test('data consent: Chromium and Safari have none, so nothing is asked', async () => {
  const chrome = { runtime: { getManifest: () => ({ manifest_version: 3 }) }, permissions: { request: () => { throw new Error('asked'); } } };
  assert.deepEqual(optionalDataCategories(chrome), []);
  assert.equal(await askDataConsent(ACCOUNT_DATA, chrome), true);
  assert.equal(await hasDataConsent(ACCOUNT_DATA, chrome), true);
});

test('data consent in Firefox: asks for the declared categories only, synchronously on the click', async () => {
  const api = firefoxApi({ optional: ['authenticationInfo'] });
  const pending = askDataConsent(ACCOUNT_DATA, api);
  // permissions.request ran before askDataConsent returned (Firefox needs it inside the click).
  assert.deepEqual(api.calls, [['request', { data_collection: ['authenticationInfo'] }]]);
  assert.equal(await pending, true);
  assert.equal(await askDataConsent(ACCOUNT_DATA, firefoxApi({ grant: false })), false, 'the user said no');
  assert.equal(await hasDataConsent(SYNC_DATA, firefoxApi({ grant: false })), false);
  const throwing = firefoxApi();
  throwing.permissions.request = () => { throw new Error('not from a user action'); };
  assert.equal(await askDataConsent(ACCOUNT_DATA, throwing), false);
});

test('Safari detection: browser.* with sendNativeMessage, a Safari user agent, no getBrowserInfo', () => {
  const safariUa = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.2 Safari/605.1.15';
  const chromeUa = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36';
  const runtime = { sendNativeMessage() {} };
  assert.equal(isSafariExtension({ browser: { runtime }, navigator: { userAgent: safariUa } }), true);
  assert.equal(isSafariExtension({ browser: { runtime }, navigator: { userAgent: chromeUa } }), false);
  assert.equal(isSafariExtension({ browser: { runtime: { ...runtime, getBrowserInfo() {} } }, navigator: { userAgent: safariUa } }), false, 'Firefox');
  assert.equal(isSafariExtension({ chrome: { runtime }, navigator: { userAgent: chromeUa } }), false);
});

test('Safari: NativeClient over sendNativeMessage, one request per message; a failed send is agent_unavailable', async () => {
  const sent = [];
  let fail = null;
  const client = new NativeClient({
    connect: (name) => safariPort(async (host, msg) => {
      sent.push([host, msg]);
      if (fail) throw new Error(fail);
      return msg.method === 'status' ? { id: msg.id, result: { locked: true } } : { id: msg.id, error: { code: 'locked', message: 'Vault is locked' } };
    }, name),
  });
  assert.deepEqual(await client.request('status'), { locked: true });
  await assert.rejects(client.request('logins.list'), (err) => err.code === 'locked');
  assert.deepEqual(sent.map(([host, m]) => [host, m.method]), [['com.sensyble.pass', 'status'], ['com.sensyble.pass', 'logins.list']]);
  fail = 'Specified native messaging host not found.';
  const err = await client.request('status').catch((e) => e);
  assert.equal(err.code, 'agent_unavailable');
  assert.equal(isHostMissing(err), true, 'no Passyble app: the setup guide offers the vault in the browser');
});

test('Safari port: an answer without an id, or one after disconnect, never settles another request', async () => {
  const port = safariPort(async () => 'nonsense', 'com.sensyble.pass');
  const got = [];
  port.onMessage.addListener((m) => got.push(m));
  port.postMessage({ id: 7, method: 'status', params: {} });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(got.length, 1);
  assert.equal(got[0].id, 7);
  assert.equal(got[0].error.code, 'internal');
  port.disconnect();
  assert.throws(() => port.postMessage({ id: 8 }));
});
