import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ACCESS_KEY, ACCOUNT_BASE, CLIENT_ID, DEV_BASE_KEY, createAccount, deviceName, memoryAccountStore, pkceChallenge } from '../src/background/account.js';

const EXT_ID = 'abcdefghijklmnopabcdefghijklmnop';
const REDIRECT = `https://${EXT_ID}.chromiumapp.org/`;

/** A fake account service and browser. `answer(url)`: what the sign-in window returns to the redirect. */
function setup({ app = false, appApi = null, redirect = REDIRECT, answer, token = null, installType = 'normal', local = {}, revokeFails = false } = {}) {
  const calls = { flows: [], fetches: [], tabs: [] };
  const session = {};
  let clock = 1_000_000;
  const ext = {
    identity: {
      getRedirectURL: () => redirect,
      launchWebAuthFlow: async (opts) => {
        calls.flows.push(opts);
        const url = new URL(opts.url);
        const q = url.searchParams;
        return answer ? answer(q) : `${REDIRECT}?code=pac_code1&state=${encodeURIComponent(q.get('state'))}&iss=${encodeURIComponent(ACCOUNT_BASE)}`;
      },
    },
    tabs: { create: async (o) => { calls.tabs.push(o.url); } },
    management: { getSelf: async () => ({ installType }) },
    storage: {
      local: { get: async (k) => (k in local ? { [k]: local[k] } : {}) },
      session: {
        level: null,
        setAccessLevel: async (o) => { ext.storage.session.level = o.accessLevel; },
        get: async (k) => (k in session ? { [k]: session[k] } : {}),
        set: async (o) => { Object.assign(session, o); },
        remove: async (k) => { delete session[k]; },
      },
    },
  };
  let refreshes = 0;
  const fetch = async (url, init) => {
    const body = Object.fromEntries(new URLSearchParams(init.body));
    calls.fetches.push({ url, init, body });
    const json = (status, value) => ({ status, ok: status < 400, json: async () => value });
    if (url.endsWith('/oauth/revoke')) {
      if (revokeFails) throw new TypeError('Failed to fetch');
      return json(200, {});
    }
    if (token) return token(body);
    if (body.grant_type === 'refresh_token') {
      refreshes += 1;
      return json(200, { access_token: `pat_${refreshes + 1}`, token_type: 'Bearer', expires_in: 900, refresh_token: `prt_${refreshes + 1}`, account: { id: 'u1', email: 'ada@example.com' } });
    }
    return json(200, { access_token: 'pat_1', token_type: 'Bearer', expires_in: 900, refresh_token: 'prt_1', session_id: 's1', account: { id: 'u1', email: 'ada@example.com' } });
  };
  const store = memoryAccountStore();
  const account = createAccount({ ext, fetch, store, now: () => clock, appMode: async () => app, app: appApi });
  return { account, calls, session, store, ext, tick: (ms) => { clock += ms; } };
}

test('PKCE S256 as in RFC 7636 appendix B', async () => {
  assert.equal(await pkceChallenge('dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'), 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
});

test('sign in: the website in launchWebAuthFlow, then the code exchanged with its verifier; tokens stay in the background', async () => {
  const { account, calls, session, store, ext } = setup();
  assert.equal(ext.storage.session.level, 'TRUSTED_CONTEXTS');
  assert.deepEqual(await account.status(), { signed_in: false, email: null, app_mode: false });
  const res = await account.signIn();
  assert.deepEqual(res, { signed_in: true, email: 'ada@example.com', app_mode: false }, 'no token in the answer to the page');

  assert.equal(calls.flows.length, 1);
  assert.equal(calls.flows[0].interactive, true);
  const auth = new URL(calls.flows[0].url);
  assert.equal(`${auth.origin}${auth.pathname}`, 'https://account.passyble.com/oauth/authorize');
  const q = auth.searchParams;
  assert.equal(q.get('client_id'), CLIENT_ID);
  assert.equal(q.get('client_id'), 'passyble-extension');
  assert.equal(q.get('redirect_uri'), REDIRECT);
  assert.equal(q.get('response_type'), 'code');
  assert.equal(q.get('code_challenge_method'), 'S256');
  assert.match(q.get('code_challenge'), /^[A-Za-z0-9_-]{43}$/);
  assert.match(q.get('state'), /^[A-Za-z0-9_-]{22}$/);
  assert.ok(q.get('device_name'));

  assert.equal(calls.fetches.length, 1);
  const { url, init, body } = calls.fetches[0];
  assert.equal(url, 'https://account.passyble.com/oauth/token');
  assert.equal(init.method, 'POST');
  assert.equal(init.credentials, 'omit');
  assert.equal(init.headers['Content-Type'], 'application/x-www-form-urlencoded');
  assert.deepEqual(Object.keys(body).sort(), ['client_id', 'code', 'code_verifier', 'grant_type', 'redirect_uri']);
  assert.equal(body.grant_type, 'authorization_code');
  assert.equal(body.code, 'pac_code1');
  assert.equal(body.client_id, 'passyble-extension');
  assert.equal(body.redirect_uri, REDIRECT);
  assert.match(body.code_verifier, /^[A-Za-z0-9_-]{43}$/);
  assert.equal(await pkceChallenge(body.code_verifier), q.get('code_challenge'), 'the verifier of that challenge');

  assert.deepEqual(session[ACCESS_KEY], { token: 'pat_1', expires_at: 1_000_000 + 900_000 }, 'access token: storage.session');
  const rec = await store.get();
  assert.equal(rec.refresh_token, 'prt_1', 'refresh token: the background\'s IndexedDB');
  assert.deepEqual(rec.account, { id: 'u1', email: 'ada@example.com' });
  assert.deepEqual(await account.status(), { signed_in: true, email: 'ada@example.com', app_mode: false });
});

test('sign in: an answer with another state, another issuer or no code is refused before any token request', async () => {
  for (const answer of [
    () => `${REDIRECT}?code=pac_x&state=not-ours`,
    (q) => `${REDIRECT}?code=pac_x&state=${q.get('state')}&iss=https%3A%2F%2Fevil.example`,
    (q) => `https://${'p'.repeat(32)}.chromiumapp.org/?code=pac_x&state=${q.get('state')}`,
    (q) => `${REDIRECT}?state=${q.get('state')}`,
    (q) => `${REDIRECT}?error=server_error&state=${q.get('state')}`,
  ]) {
    const { account, calls, store } = setup({ answer });
    await assert.rejects(account.signIn(), (err) => err.code === 'internal');
    assert.equal(calls.fetches.length, 0);
    assert.equal(await store.get(), null);
  }
});

test('sign in: closing the window or "Cancel" on the website is a cancel, nothing stored', async () => {
  const closed = setup();
  closed.ext.identity.launchWebAuthFlow = async () => { throw new Error('The user did not approve access.'); };
  await assert.rejects(closed.account.signIn(), (err) => err.code === 'cancelled');
  assert.equal(closed.calls.fetches.length, 0);
  const denied = setup({ answer: (q) => `${REDIRECT}?error=access_denied&state=${q.get('state')}` });
  await assert.rejects(denied.account.signIn(), (err) => err.code === 'cancelled');
  assert.equal(await denied.store.get(), null);
});

test('sign in: a refused token request stores nothing', async () => {
  const { account, store, session } = setup({ token: () => ({ status: 400, ok: false, json: async () => ({ error: 'invalid_grant' }) }) });
  await assert.rejects(account.signIn(), (err) => err.code === 'internal');
  assert.equal(await store.get(), null);
  assert.equal(session[ACCESS_KEY], undefined);
});

/** The desktop app's account through the native host (`account.status`, `app.show_account`), or one that can't be reached. */
function desktopApp({ signedIn = false, email = 'ada@app.example', reachable = true } = {}) {
  const api = { shown: [], signedIn };
  api.status = async () => {
    if (!api.reachable) throw Object.assign(new Error('Passyble desktop app is not running'), { code: 'agent_unavailable' });
    return { signed_in: api.signedIn, email: api.signedIn ? email : null };
  };
  api.show = async (params) => {
    if (!api.reachable) throw Object.assign(new Error('Passyble desktop app is not running'), { code: 'agent_unavailable' });
    api.shown.push(params);
    return { shown: true };
  };
  api.reachable = reachable;
  return api;
}

test('app mode: the status is the desktop app\'s account, and the extension keeps no token', async () => {
  const appApi = desktopApp({ signedIn: true });
  const { account, calls, store } = setup({ app: true, appApi });
  assert.deepEqual(await account.status(), { signed_in: true, email: 'ada@app.example', app_mode: true, app_reachable: true });
  appApi.signedIn = false;
  assert.deepEqual(await account.status(), { signed_in: false, email: null, app_mode: true, app_reachable: true });
  assert.equal(calls.fetches.length, 0);
  assert.equal(await store.get(), null);
});

test('app mode: Sign in asks the desktop app to sign in (no tab, no window here, no token); Sign out opens its account screen', async () => {
  const appApi = desktopApp();
  const { account, calls, store, session } = setup({ app: true, appApi });
  const res = await account.signIn();
  assert.deepEqual(appApi.shown, [{ sign_in: true }]);
  assert.deepEqual(res, { signed_in: false, email: null, app_mode: true, app_reachable: true, in_app: true });
  assert.deepEqual(calls.tabs, []);
  assert.equal(calls.flows.length, 0);
  assert.equal(calls.fetches.length, 0);
  assert.equal(await store.get(), null);
  assert.deepEqual(session, {});
  // Signed in in the app meanwhile: the page's next status says so.
  appApi.signedIn = true;
  assert.equal((await account.status()).email, 'ada@app.example');
  const out = await account.signOut();
  assert.deepEqual(appApi.shown, [{ sign_in: true }, {}], 'Sign out happens in the app, after its own confirmation');
  assert.equal(out.in_app, true);
  assert.equal(out.signed_in, true, 'nothing signed out here');
  assert.equal(calls.fetches.length, 0, 'no revoke from here');
});

test('app mode without the app (no host, not running, an older app, an odd answer): the extension signs in itself', async () => {
  const unreachable = [
    desktopApp({ reachable: false }),
    { status: async () => { throw Object.assign(new Error('unknown method account.status'), { code: 'invalid_params' }); },
      show: async () => { throw Object.assign(new Error('unknown method app.show_account'), { code: 'invalid_params' }); } },
    { status: async () => ({ locked: true }), show: async () => { throw new Error('no'); } },
    null,
  ];
  for (const appApi of unreachable) {
    const { account, calls, store } = setup({ app: true, appApi });
    assert.deepEqual(await account.status(), { signed_in: false, email: null, app_mode: true, app_reachable: false });
    const res = await account.signIn();
    assert.equal(calls.flows.length, 1, 'launchWebAuthFlow, client passyble-extension');
    assert.equal(new URL(calls.flows[0].url).searchParams.get('client_id'), CLIENT_ID);
    assert.deepEqual(calls.tabs, []);
    assert.deepEqual(res, { signed_in: true, email: 'ada@example.com', app_mode: true, app_reachable: false });
    assert.equal((await store.get()).refresh_token, 'prt_1');
    const out = await account.signOut();
    assert.equal(out.signed_in, false);
    assert.ok(calls.fetches.some((f) => f.url.endsWith('/oauth/revoke')));
  }
});

test('app mode: the app back later shows its own account; one gone later falls back', async () => {
  const appApi = desktopApp({ reachable: false });
  const { account } = setup({ app: true, appApi });
  await account.signIn();
  assert.equal((await account.status()).email, 'ada@example.com');
  appApi.reachable = true;
  assert.deepEqual(await account.status(), { signed_in: false, email: null, app_mode: true, app_reachable: true });
  appApi.reachable = false;
  assert.deepEqual(await account.status(), { signed_in: true, email: 'ada@example.com', app_mode: true, app_reachable: false });
});

test('app mode without the app in Firefox: no data consent, nothing goes out', async () => {
  const s = setup({ app: true, appApi: desktopApp({ reachable: false }), redirect: 'https://a616c7e5d8c971387d4568e8f94bdd4e9fe1b085.extensions.allizom.org/' });
  s.ext.runtime = { getManifest: () => ({ browser_specific_settings: { gecko: { data_collection_permissions: {
    required: ['none'], optional: ['authenticationInfo', 'personallyIdentifyingInfo'] } } } }) };
  s.ext.permissions = { contains: async () => false };
  await assert.rejects(s.account.signIn(), (err) => err.code === 'cancelled');
  assert.equal(s.calls.flows.length, 0);
  assert.equal(s.calls.fetches.length, 0);
});

test('browser mode never asks the desktop app', async () => {
  const appApi = desktopApp({ signedIn: true });
  const { account } = setup({ app: false, appApi });
  assert.deepEqual(await account.status(), { signed_in: false, email: null, app_mode: false });
  await account.signIn();
  await account.signOut();
  assert.deepEqual(appApi.shown, []);
});

test('a redirect of no form we know (or no identity API, Safari): the website in a tab instead', async () => {
  for (const redirect of ['https://0123456789abcdef.extensions.allizom.org/', 'https://example.com/', null]) {
    const { account, calls } = setup({ redirect });
    await account.signIn();
    assert.deepEqual(calls.tabs, ['https://account.passyble.com/sign-in']);
    assert.equal(calls.flows.length, 0);
  }
});

// Firefox: getRedirectURL() is https://<sha1 of the add-on id>.extensions.allizom.org/
const FF_REDIRECT = 'https://a616c7e5d8c971387d4568e8f94bdd4e9fe1b085.extensions.allizom.org/';
const ffAnswer = (q) => `${FF_REDIRECT}?code=pac_code1&state=${encodeURIComponent(q.get('state'))}&iss=${encodeURIComponent(ACCOUNT_BASE)}`;

test('Firefox: the same sign-in with the allizom.org redirect', async () => {
  const { account, calls } = setup({ redirect: FF_REDIRECT, answer: ffAnswer });
  const res = await account.signIn();
  assert.equal(res.signed_in, true);
  assert.equal(new URL(calls.flows[0].url).searchParams.get('redirect_uri'), FF_REDIRECT);
  assert.equal(calls.fetches[0].body.redirect_uri, FF_REDIRECT);
  // An answer at another add-on's address is refused.
  const other = setup({ redirect: FF_REDIRECT, answer: (q) => `https://${'0'.repeat(40)}.extensions.allizom.org/?code=x&state=${q.get('state')}` });
  await assert.rejects(other.account.signIn(), (err) => err.code === 'internal');
  assert.equal(other.calls.fetches.length, 0);
});

test('Firefox: without the data consent for the account, nothing goes out', async () => {
  const consent = (granted) => {
    const s = setup({ redirect: FF_REDIRECT, answer: ffAnswer });
    s.ext.runtime = { getManifest: () => ({ browser_specific_settings: { gecko: { data_collection_permissions: {
      required: ['none'], optional: ['authenticationInfo', 'personallyIdentifyingInfo'] } } } }) };
    s.ext.permissions = { contains: async (q) => { s.asked = q; return granted; } };
    return s;
  };
  const no = consent(false);
  await assert.rejects(no.account.signIn(), (err) => err.code === 'cancelled');
  assert.deepEqual(no.asked, { data_collection: ['authenticationInfo', 'personallyIdentifyingInfo'] });
  assert.equal(no.calls.flows.length, 0);
  assert.equal(no.calls.fetches.length, 0);
  const yes = consent(true);
  assert.equal((await yes.account.signIn()).signed_in, true);
});

test('sign out: revokes the refresh token and forgets both tokens, also when offline', async () => {
  for (const revokeFails of [false, true]) {
    const { account, calls, store, session } = setup({ revokeFails });
    await account.signIn();
    const res = await account.signOut();
    assert.deepEqual(res, { signed_in: false, email: null, app_mode: false });
    const revoke = calls.fetches.find((f) => f.url.endsWith('/oauth/revoke'));
    assert.equal(revoke.url, 'https://account.passyble.com/oauth/revoke');
    assert.deepEqual(revoke.body, { token: 'prt_1', client_id: 'passyble-extension' });
    assert.equal(await store.get(), null);
    assert.equal(session[ACCESS_KEY], undefined);
  }
});

test('access token: refreshed shortly before it expires, the refresh token rotated; a refused refresh signs out', async () => {
  const { account, calls, store, tick } = setup();
  await account.signIn();
  assert.equal(await account.accessToken(), 'pat_1');
  assert.equal(calls.fetches.length, 1, 'still valid: no request');
  tick(850_000);
  assert.equal(await account.accessToken(), 'pat_2');
  const refresh = calls.fetches.at(-1).body;
  assert.deepEqual(refresh, { grant_type: 'refresh_token', refresh_token: 'prt_1', client_id: 'passyble-extension' });
  assert.equal((await store.get()).refresh_token, 'prt_2', 'rotated');

  const refused = setup({ token: (b) => (b.grant_type === 'refresh_token'
    ? { status: 400, ok: false, json: async () => ({ error: 'invalid_grant' }) }
    : { status: 200, ok: true, json: async () => ({ access_token: 'pat_1', expires_in: 900, refresh_token: 'prt_1', account: { id: 'u1', email: 'ada@example.com' } }) }) });
  await refused.account.signIn();
  refused.tick(900_000);
  assert.equal(await refused.account.accessToken(), null);
  assert.equal((await refused.account.status()).signed_in, false);
});

test('the account service is account.passyble.com; a dev override only in an unpacked extension', async () => {
  const dev = setup({ installType: 'development', local: { [DEV_BASE_KEY]: 'http://127.0.0.1:8787' } });
  assert.equal(await dev.account.base(), 'http://127.0.0.1:8787');
  await dev.account.signIn().catch(() => {});
  assert.ok(dev.calls.flows[0].url.startsWith('http://127.0.0.1:8787/oauth/authorize?'));
  const store = setup({ installType: 'normal', local: { [DEV_BASE_KEY]: 'http://127.0.0.1:8787' } });
  assert.equal(await store.account.base(), ACCOUNT_BASE);
  const bad = setup({ installType: 'development', local: { [DEV_BASE_KEY]: 'http://127.0.0.1:8787/path?x' } });
  assert.equal(await bad.account.base(), ACCOUNT_BASE);
});

test('one sign-in at a time', async () => {
  const { account, ext } = setup();
  let release;
  ext.identity.launchWebAuthFlow = () => new Promise((r) => { release = r; });
  const first = account.signIn();
  await assert.rejects(account.signIn(), (err) => err.code === 'invalid_state');
  while (!release) await new Promise((r) => setTimeout(r, 1));
  release('about:blank');
  await assert.rejects(first);
});

test('device name: browser and OS only', () => {
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0', platform: 'Win32' }), 'Chrome on Windows');
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (Macintosh) Chrome/140.0 Edg/140.0', platform: 'MacIntel' }), 'Edge on macOS');
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (X11; CrOS x86_64) Chrome/140.0', platform: 'Linux x86_64' }), 'Chrome on ChromeOS');
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:140.0) Gecko/20100101 Firefox/140.0', platform: 'Win32' }), 'Firefox on Windows');
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.4 Safari/605.1.15', platform: 'MacIntel' }), 'Safari on macOS');
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36', platform: 'Win32' }), 'Chrome on Windows');
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/140.0 Safari/537.36 OPR/125.0', platform: 'Win32' }), 'Opera on Windows');
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (Windows NT 10.0) Chrome/140.0 Safari/537.36 OPR/125.0', platform: 'Win32', userAgentData: { brands: [{ brand: 'Opera GX', version: '125' }], platform: 'Windows' } }), 'Opera GX on Windows');
  assert.equal(deviceName({ userAgent: 'Mozilla/5.0 (X11; Linux x86_64) Chrome/140.0 Safari/537.36 OPR/125.0', platform: 'Linux x86_64' }), 'Opera on Linux');
});
