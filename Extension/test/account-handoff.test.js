// The same-computer sign-in handoff (account.js syncWithApp, browser mode): the extension and the Passyble app sign
// each other in through the native host. The app, the account service and the browser are fakes.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { ACCESS_KEY, ACCOUNT_BASE, APP_CLIENT_ID, CLIENT_ID, HANDOFF_REDIRECT, PEER_EVERY_MS, createAccount, memoryAccountStore, pkceChallenge } from '../src/background/account.js';

const EXT_ID = 'abcdefghijklmnopabcdefghijklmnop';
const REDIRECT = `https://${EXT_ID}.chromiumapp.org/`;
const APP_CHALLENGE = 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM';

/**
 * The Passyble app's handoff methods through the native host. `calls`: every method and its params, as the app
 * received them. `version: 'old'`: an app without the handoff ("unknown method" for each).
 */
function desktopApp({ signedIn = false, email = 'ada@example.com', acceptsHandoff = true, signOutExtension = false, version = 'new', reachable = true } = {}) {
  const app = { signedIn, email, acceptsHandoff, signOutExtension, reachable, calls: [], ends: 0, codes: 0 };
  app.call = async (method, params) => {
    app.calls.push({ method, params: structuredClone(params) });
    if (!app.reachable) throw Object.assign(new Error('Passyble desktop app is not running'), { code: 'agent_unavailable' });
    if (version === 'old') throw Object.assign(new Error(`unknown method ${method}`), { code: 'invalid_params' });
    switch (method) {
      case 'account.peer':
        return { signed_in: app.signedIn, email: app.signedIn || app.signOutExtension ? app.email : null,
          accepts_handoff: app.acceptsHandoff, sign_out_extension: app.signOutExtension };
      case 'account.handoff_to_extension':
        if (!app.signedIn) throw Object.assign(new Error('not signed in'), { code: 'invalid_state' });
        app.codes += 1;
        app.challenge = params.code_challenge;
        return { code: `pac_fromapp${app.codes}`, email: app.email };
      case 'account.handoff_begin':
        if (app.signedIn || !app.acceptsHandoff) throw Object.assign(new Error('no'), { code: 'invalid_state' });
        return { code_challenge: APP_CHALLENGE, device_name: 'Passyble on DESKTOP-1' };
      case 'account.handoff_finish':
        app.signedIn = true;
        return { signed_in: true, email: app.email };
      case 'account.sign_out':
        app.signedIn = false;
        return { signed_out: true };
      case 'account.peer_signed_out':
        app.signOutExtension = false;
        return {};
      default:
        throw Object.assign(new Error(`unknown method ${method}`), { code: 'invalid_params' });
    }
  };
  app.end = () => { app.ends += 1; };
  app.methods = () => app.calls.map((c) => c.method);
  return app;
}

/** A fake account service (with POST /v1/session/handoff) and browser; the account is ada@example.com. */
function setup({ appApi = desktopApp(), appMode = false, peerStore = memoryAccountStore(), handoffStatus = 200, tokenStatus = 200, consent = true } = {}) {
  const calls = { fetches: [], flows: [] };
  const session = {};
  let clock = 1_000_000;
  let sessions = 0;
  const ext = {
    identity: {
      getRedirectURL: () => REDIRECT,
      launchWebAuthFlow: async (opts) => {
        calls.flows.push(opts);
        const q = new URL(opts.url).searchParams;
        return `${REDIRECT}?code=pac_web&state=${encodeURIComponent(q.get('state'))}&iss=${encodeURIComponent(ACCOUNT_BASE)}`;
      },
    },
    tabs: { create: async () => {} },
    management: { getSelf: async () => ({ installType: 'normal' }) },
    storage: {
      local: { get: async () => ({}) },
      session: {
        get: async (k) => (k in session ? { [k]: session[k] } : {}),
        set: async (o) => { Object.assign(session, o); },
        remove: async (k) => { delete session[k]; },
      },
    },
  };
  if (!consent) {
    ext.runtime = { getManifest: () => ({ browser_specific_settings: { gecko: { data_collection_permissions: {
      required: ['none'], optional: ['authenticationInfo', 'personallyIdentifyingInfo'] } } } }) };
    ext.permissions = { contains: async () => false };
  }
  const json = (status, value) => ({ status, ok: status < 400, json: async () => value });
  const fetch = async (url, init) => {
    const isJson = init.headers['Content-Type'] === 'application/json';
    const body = isJson ? JSON.parse(init.body) : Object.fromEntries(new URLSearchParams(init.body));
    calls.fetches.push({ url, init, body });
    if (url.endsWith('/oauth/revoke')) return json(200, {});
    if (url.endsWith('/v1/session/handoff')) {
      if (handoffStatus !== 200) return json(handoffStatus, { error: 'too_many_requests' });
      return json(200, { code: 'pac_forapp', redirect_uri: HANDOFF_REDIRECT, expires_in: 60 });
    }
    if (tokenStatus !== 200) return json(tokenStatus, { error: 'invalid_grant' });
    sessions += 1;
    return json(200, { access_token: `pat_${sessions}`, token_type: 'Bearer', expires_in: 900, refresh_token: `prt_${sessions}`,
      account: { id: 'acc_1', email: 'ada@example.com' } });
  };
  const store = memoryAccountStore();
  const signedOut = [];
  // App mode: the app's own account (`account.status`, `app.show_account`), from the same fake.
  const unreachable = () => Object.assign(new Error('Passyble desktop app is not running'), { code: 'agent_unavailable' });
  const app = {
    status: async () => {
      if (!appApi.reachable) throw unreachable();
      return { signed_in: appApi.signedIn, email: appApi.signedIn ? appApi.email : null };
    },
    show: async () => {
      if (!appApi.reachable) throw unreachable();
      return {};
    },
  };
  const account = createAccount({ ext, fetch, store, now: () => clock, appMode: async () => appMode, app, peer: appApi, peerStore,
    onSignedOut: () => { signedOut.push(true); } });
  return { account, appApi, calls, session, store, peerStore, signedOut, tick: (ms) => { clock += ms; } };
}

/** The extension signed in on the website first (no handoff involved), then the app's calls cleared. */
async function signedInHere(s) {
  await s.account.signIn();
  await s.account.syncWithApp();
  s.appApi.calls.length = 0;
  s.calls.fetches.length = 0;
  s.tick(PEER_EVERY_MS);
}

test('the app signed in, the extension not: the extension signs in through the app with its own session', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }) });
  const st = await s.account.statusWithApp();
  assert.deepEqual(st, { signed_in: true, email: 'ada@example.com', app_mode: false, via_app: true,
    app_peer: { signed_in: true, same_account: true } });
  assert.deepEqual(s.appApi.methods(), ['account.peer', 'account.handoff_to_extension']);
  const ask = s.appApi.calls[1].params;
  assert.deepEqual(Object.keys(ask).sort(), ['code_challenge', 'device_name']);
  assert.match(ask.code_challenge, /^[A-Za-z0-9_-]{43}$/);
  assert.ok(ask.device_name);

  assert.equal(s.calls.fetches.length, 1);
  const { url, body } = s.calls.fetches[0];
  assert.equal(url, 'https://account.passyble.com/oauth/token');
  assert.deepEqual(body, { grant_type: 'authorization_code', code: 'pac_fromapp1', code_verifier: body.code_verifier,
    client_id: CLIENT_ID, redirect_uri: 'urn:passyble:handoff' });
  assert.equal(await pkceChallenge(body.code_verifier), ask.code_challenge, 'the verifier stayed here; only its challenge went to the app');
  assert.equal((await s.store.get()).refresh_token, 'prt_1');
  assert.equal((await s.store.get()).via, 'app');
  assert.equal(s.session[ACCESS_KEY].token, 'pat_1');
  assert.equal(s.appApi.ends, 1, 'the port closes after the check');
});

test('signed in through the app survives a token refresh; a sign-in on the website is no longer "through the app"', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }) });
  await s.account.syncWithApp();
  s.tick(900_000);
  assert.equal(await s.account.accessToken(), 'pat_2');
  assert.equal((await s.account.status()).via_app, true);
  await s.account.signOut();
  await s.account.signIn();
  assert.equal((await s.account.status()).via_app, undefined);
});

test('the extension signed in, the app not: the app signs in through a code from the extension\'s session', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: false }) });
  await s.account.signIn();
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer', 'account.handoff_begin', 'account.handoff_finish']);
  assert.deepEqual(s.appApi.calls[1].params, {});
  assert.deepEqual(s.appApi.calls[2].params, { code: 'pac_forapp' });
  const handoff = s.calls.fetches.find((f) => f.url.endsWith('/v1/session/handoff'));
  assert.equal(handoff.url, 'https://account.passyble.com/v1/session/handoff');
  assert.equal(handoff.init.method, 'POST');
  assert.equal(handoff.init.credentials, 'omit');
  assert.equal(handoff.init.headers.Authorization, 'Bearer pat_1', 'the extension\'s own access token, to the service only');
  assert.deepEqual(handoff.body, { client_id: APP_CLIENT_ID, code_challenge: APP_CHALLENGE, device_name: 'Passyble on DESKTOP-1' });
  assert.equal(s.appApi.signedIn, true);
  const st = await s.account.status();
  assert.deepEqual(st.app_peer, { signed_in: true, same_account: true });
  assert.equal(st.via_app, undefined);
});

test('the app takes no handoff after the user signed out of it and kept the extension signed in', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: false, acceptsHandoff: false }) });
  await signedInHere(s);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer']);
  assert.equal(s.calls.fetches.length, 0);
});

test('the user signed out of the app with "also the browser extension": the extension signs out too', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }) });
  await signedInHere(s);
  s.appApi.signedIn = false;
  s.appApi.signOutExtension = true;
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer', 'account.peer_signed_out']);
  assert.equal(await s.store.get(), null);
  assert.equal(s.session[ACCESS_KEY], undefined);
  const revoke = s.calls.fetches.find((f) => f.url.endsWith('/oauth/revoke'));
  assert.deepEqual(revoke.body, { token: 'prt_1', client_id: CLIENT_ID });
  assert.deepEqual(s.signedOut, [true], 'the shared vaults close as on Sign out');
  assert.equal(s.appApi.signOutExtension, false);
  // The app signed out on purpose: no handoff back to it, and none from it.
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods().slice(2), ['account.peer']);
});

test('"also sign out the browser extension" for another address: nothing here, and no handoff to the app either', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: false, signOutExtension: true, email: 'bob@example.com' }) });
  await signedInHere(s);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer']);
  assert.equal((await s.store.get()).account.email, 'ada@example.com');
  assert.deepEqual(s.signedOut, []);
});

test('both signed in to different addresses: nothing', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true, email: 'bob@example.com' }) });
  await signedInHere(s);
  const st = await s.account.statusWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer']);
  assert.equal(st.email, 'ada@example.com');
  assert.deepEqual(st.app_peer, { signed_in: true, same_account: false }, 'no box in the sign-out confirmation');
  assert.equal(JSON.stringify(st).includes('bob@'), false, 'the app\'s address isn\'t shown to the page');
});

test('sign out with "also the Passyble app": the app signs out, nothing paused', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }) });
  await signedInHere(s);
  const out = await s.account.signOut({ alsoApp: true });
  assert.deepEqual(s.appApi.methods(), ['account.peer', 'account.sign_out']);
  assert.deepEqual(s.appApi.calls[1].params, {});
  assert.equal(s.appApi.signedIn, false);
  assert.equal(out.signed_in, false);
  assert.equal(await s.peerStore.get(), null);
  // Both signed out: nothing more happens.
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods().slice(2), ['account.peer']);
  assert.equal(await s.store.get(), null);
});

test('sign out without the box: paused, so the app doesn\'t sign the extension in again until the user does', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }) });
  await signedInHere(s);
  await s.account.signOut({ alsoApp: false });
  assert.deepEqual(s.appApi.methods(), [], 'the app is not touched');
  assert.equal((await s.peerStore.get()).paused, true);
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer'], 'no automatic sign-in while paused');
  assert.equal(await s.store.get(), null);
  // The user's own sign-in here ends the pause.
  await s.account.signIn();
  assert.equal(await s.peerStore.get(), null);
});

test('paused ends when the app is seen signed out; its next sign-in signs the extension in again', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }) });
  await signedInHere(s);
  await s.account.signOut();
  s.appApi.signedIn = false;
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.equal(await s.peerStore.get(), null);
  s.appApi.signedIn = true;
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.equal((await s.store.get())?.via, 'app');
});

test('"also the Passyble app" when the app can\'t be reached or another account is signed in there: paused instead', async () => {
  for (const change of [(app) => { app.reachable = false; }, (app) => { app.email = 'bob@example.com'; }]) {
    const s = setup({ appApi: desktopApp({ signedIn: true }) });
    await signedInHere(s);
    change(s.appApi);
    await s.account.signOut({ alsoApp: true });
    assert.equal(s.appApi.methods().includes('account.sign_out'), false);
    assert.equal((await s.peerStore.get()).paused, true);
  }
});

test('an older Passyble app ("unknown method"), or none running: nothing happens, silently', async () => {
  for (const appApi of [desktopApp({ signedIn: true, version: 'old' }), desktopApp({ signedIn: true, reachable: false })]) {
    const s = setup({ appApi });
    assert.deepEqual(await s.account.statusWithApp(), { signed_in: false, email: null, app_mode: false });
    assert.deepEqual(appApi.methods(), ['account.peer']);
    assert.equal(s.calls.fetches.length, 0);
    await s.account.signIn();
    await s.account.syncWithApp();
    assert.equal((await s.account.signOut({ alsoApp: true })).signed_in, false);
    assert.equal(appApi.methods().includes('account.sign_out'), false);
  }
});

test('app mode without a session of the extension\'s own: the app isn\'t asked, and never signs the extension in', async () => {
  for (const signedIn of [true, false]) {
    const appApi = desktopApp({ signedIn });
    const s = setup({ appApi, appMode: true });
    await s.account.statusWithApp();
    await s.account.syncWithApp({ force: true });
    assert.deepEqual(appApi.calls, []);
    assert.equal(s.calls.fetches.length, 0);
    assert.equal(await s.store.get(), null);
  }
});

/**
 * App mode: the extension signed in with its own account while the app couldn't be reached (account.js status:
 * `app_reachable: false`); then the app is back, its calls cleared.
 */
async function ownSessionInAppMode(s) {
  s.appApi.reachable = false;
  await s.account.signIn();
  await s.account.syncWithApp();
  assert.equal((await s.store.get()).refresh_token, 'prt_1');
  s.appApi.reachable = true;
  s.appApi.calls.length = 0;
  s.calls.fetches.length = 0;
  s.tick(PEER_EVERY_MS);
}

test('app mode, the app signed out: the extension\'s own session goes to the app, then is revoked and forgotten here', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: false }), appMode: true });
  await ownSessionInAppMode(s);
  await s.account.statusWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer', 'account.handoff_begin', 'account.handoff_finish']);
  assert.deepEqual(s.appApi.calls[2].params, { code: 'pac_forapp' });
  const handoff = s.calls.fetches.find((f) => f.url.endsWith('/v1/session/handoff'));
  assert.equal(handoff.init.headers.Authorization, 'Bearer pat_1');
  assert.deepEqual(handoff.body, { client_id: APP_CLIENT_ID, code_challenge: APP_CHALLENGE, device_name: 'Passyble on DESKTOP-1' });
  assert.equal(s.appApi.signedIn, true);
  const revoke = s.calls.fetches.find((f) => f.url.endsWith('/oauth/revoke'));
  assert.deepEqual(revoke.body, { token: 'prt_1', client_id: CLIENT_ID }, 'revoked after the app said it is signed in');
  assert.ok(s.calls.fetches.indexOf(revoke) > s.calls.fetches.indexOf(handoff));
  assert.equal(await s.store.get(), null);
  assert.equal(s.session[ACCESS_KEY], undefined);
  assert.deepEqual(s.signedOut, [true]);
});

test('app mode: a handoff that fails keeps the extension\'s own session and waits 10 minutes', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: false }), appMode: true, handoffStatus: 429 });
  await ownSessionInAppMode(s);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer', 'account.handoff_begin']);
  assert.equal((await s.store.get()).refresh_token, 'prt_1');
  assert.equal(s.calls.fetches.some((f) => f.url.endsWith('/oauth/revoke')), false);
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods().slice(2), ['account.peer']);
  s.tick(10 * 60_000);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods().slice(3), ['account.peer', 'account.handoff_begin']);

  // The app refuses to finish (invalid_state): the same.
  const refused = setup({ appApi: desktopApp({ signedIn: false }), appMode: true });
  refused.appApi.call = ((call) => async (method, params) => {
    if (method === 'account.handoff_finish') throw Object.assign(new Error('no pending handoff'), { code: 'invalid_state' });
    return call(method, params);
  })(refused.appApi.call);
  await ownSessionInAppMode(refused);
  await refused.account.syncWithApp();
  assert.equal((await refused.store.get()).refresh_token, 'prt_1');
});

test('app mode, the app takes no handoff (or is an older app, or isn\'t running): the own session stays', async () => {
  for (const change of [(app) => { app.acceptsHandoff = false; }, (app) => { app.call = async () => {
    throw Object.assign(new Error('unknown method account.peer'), { code: 'invalid_params' }); }; }]) {
    const s = setup({ appApi: desktopApp({ signedIn: false }), appMode: true });
    await ownSessionInAppMode(s);
    change(s.appApi);
    await s.account.syncWithApp();
    assert.equal((await s.store.get()).refresh_token, 'prt_1');
    assert.equal(s.calls.fetches.length, 0);
  }
});

test('app mode, the app signed in to the same address: the extension\'s own session is revoked and forgotten quietly', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }), appMode: true });
  await ownSessionInAppMode(s);
  const st = await s.account.statusWithApp();
  assert.deepEqual(st, { signed_in: true, email: 'ada@example.com', app_mode: true, app_reachable: true });
  assert.deepEqual(s.appApi.methods(), ['account.peer'], 'nothing else asked of the app');
  assert.equal(await s.store.get(), null);
  assert.equal(s.session[ACCESS_KEY], undefined);
  assert.deepEqual(s.calls.fetches.map((f) => f.url), ['https://account.passyble.com/oauth/revoke']);
  assert.deepEqual(s.calls.fetches[0].body, { token: 'prt_1', client_id: CLIENT_ID });
  assert.deepEqual(s.signedOut, [true]);
});

test('app mode, the app signed in to another address: nothing automatic; status names both, and "Use the app\'s account" drops this browser\'s', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true, email: 'grace@example.com' }), appMode: true });
  await ownSessionInAppMode(s);
  const st = await s.account.statusWithApp();
  assert.deepEqual(st, { signed_in: true, email: 'grace@example.com', app_mode: true, app_reachable: true, browser_email: 'ada@example.com' });
  assert.deepEqual(s.appApi.methods(), ['account.peer'], 'no handoff, no sign-out asked of the app');
  assert.equal((await s.store.get()).refresh_token, 'prt_1', 'kept');
  assert.equal(s.calls.fetches.length, 0, 'nothing revoked');
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.equal((await s.store.get()).refresh_token, 'prt_1', 'still kept on the next check');

  const after = await s.account.useAppAccount();
  assert.deepEqual(after, { signed_in: true, email: 'grace@example.com', app_mode: true, app_reachable: true });
  assert.equal(await s.store.get(), null);
  assert.equal(s.session[ACCESS_KEY], undefined);
  assert.deepEqual(s.calls.fetches.map((f) => [f.url, f.body.token]), [['https://account.passyble.com/oauth/revoke', 'prt_1']]);
  assert.deepEqual(s.signedOut, [true]);
  assert.deepEqual(s.appApi.methods().filter((m) => m !== 'account.peer'), [], 'the app is only read, never changed');
});

test('"Use the app\'s account" only in app mode with the app signed in', async () => {
  const browser = setup({ appApi: desktopApp({ signedIn: true, email: 'grace@example.com' }) });
  await signedInHere(browser);
  await assert.rejects(browser.account.useAppAccount(), { code: 'not_supported' });
  assert.equal((await browser.store.get()).refresh_token, 'prt_1');

  const appOut = setup({ appApi: desktopApp({ signedIn: false, acceptsHandoff: false }), appMode: true });
  await ownSessionInAppMode(appOut);
  await assert.rejects(appOut.account.useAppAccount(), { code: 'invalid_state' });
  appOut.appApi.reachable = false;
  await assert.rejects(appOut.account.useAppAccount(), { code: 'invalid_state' });
  assert.equal((await appOut.store.get()).refresh_token, 'prt_1');
});

test('app mode, the app signed out with "also the browser extension": the own session of that address goes', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: false, signOutExtension: true }), appMode: true });
  await ownSessionInAppMode(s);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer', 'account.peer_signed_out']);
  assert.equal(await s.store.get(), null);
  assert.equal(s.calls.fetches.find((f) => f.url.endsWith('/oauth/revoke')).body.token, 'prt_1');

  const other = setup({ appApi: desktopApp({ signedIn: false, signOutExtension: true, email: 'bob@example.com' }), appMode: true });
  await ownSessionInAppMode(other);
  await other.account.syncWithApp();
  assert.deepEqual(other.appApi.methods(), ['account.peer']);
  assert.equal((await other.store.get()).refresh_token, 'prt_1');
});

test('at most every 30 s, and one check at a time', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: false }) });
  await s.account.statusWithApp();
  await s.account.statusWithApp();
  s.tick(PEER_EVERY_MS - 1);
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer']);
  s.tick(1);
  const [a, b] = [s.account.syncWithApp(), s.account.syncWithApp()];
  assert.equal(a, b, 'the running check is the answer');
  await a;
  assert.deepEqual(s.appApi.methods(), ['account.peer', 'account.peer']);
});

test('sign in and sign out wait for a running check; no check starts during them', async () => {
  const appApi = desktopApp({ signedIn: false });
  let release;
  const call = appApi.call;
  appApi.call = async (method, params) => {
    if (method === 'account.peer' && !release) await new Promise((r) => { release = r; });
    return call(method, params);
  };
  const s = setup({ appApi });
  const check = s.account.syncWithApp();
  while (!release) await new Promise((r) => setTimeout(r, 1));
  const signIn = s.account.signIn();
  await new Promise((r) => setTimeout(r, 5));
  assert.equal(s.calls.flows.length, 0, 'the sign-in waits for the check');
  release();
  await check;
  await signIn;
  assert.equal(s.calls.flows.length, 1);
});

test('a handoff that fails is not tried again for a while (the service allows 20 codes an hour)', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }), tokenStatus: 400 });
  await s.account.syncWithApp();
  assert.equal(s.appApi.codes, 1);
  assert.equal(await s.store.get(), null);
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.equal(s.appApi.codes, 1);
  s.tick(10 * 60_000);
  await s.account.syncWithApp();
  assert.equal(s.appApi.codes, 2);

  const refused = setup({ appApi: desktopApp({ signedIn: false }), handoffStatus: 429 });
  await refused.account.signIn();
  await refused.account.syncWithApp();
  assert.deepEqual(refused.appApi.methods(), ['account.peer', 'account.handoff_begin']);
  assert.equal(refused.appApi.signedIn, false);
});

test('Firefox without the data consent for the account: no automatic sign-in, nothing goes out', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: true }), consent: false });
  await s.account.syncWithApp();
  assert.deepEqual(s.appApi.methods(), ['account.peer']);
  assert.equal(s.calls.fetches.length, 0);
});

test('after the extension\'s own sign-in the check runs at once', async () => {
  const s = setup({ appApi: desktopApp({ signedIn: false }) });
  await s.account.statusWithApp(); // a check just ran
  await s.account.signIn();
  await s.account.syncWithApp();
  assert.equal(s.appApi.signedIn, true, 'the app took this sign-in');
});

test('status waits briefly for a slow app, then says the check is still running', async () => {
  const appApi = desktopApp({ signedIn: true });
  let release;
  const call = appApi.call;
  appApi.call = async (method, params) => {
    if (method === 'account.peer') await new Promise((r) => { release = r; });
    return call(method, params);
  };
  const s = setup({ appApi });
  const st = await s.account.statusWithApp({ waitMs: 5 });
  assert.deepEqual(st, { signed_in: false, email: null, app_mode: false, app_syncing: true });
  release();
  await s.account.syncWithApp();
  assert.equal((await s.account.status()).signed_in, true);
});

test('the app only ever gets a challenge or a code from the extension, never a token or a verifier', async () => {
  const appApi = desktopApp({ signedIn: true });
  const s = setup({ appApi });
  await s.account.syncWithApp(); // signed in through the app
  appApi.signedIn = false;
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp(); // the app back in through the extension
  await s.account.signOut({ alsoApp: true });
  appApi.signedIn = true;
  s.tick(PEER_EVERY_MS);
  await s.account.syncWithApp();
  assert.ok(appApi.methods().includes('account.handoff_finish'));
  const allowed = { code_challenge: /^[A-Za-z0-9_-]{43}$/, device_name: /^[\w .-]+$/, code: /^pac_forapp$/ };
  const verifiers = s.calls.fetches.map((f) => f.body.code_verifier).filter(Boolean);
  const tokens = s.calls.fetches.map((f) => f.body.refresh_token).filter(Boolean);
  for (const { method, params } of appApi.calls) {
    for (const [k, v] of Object.entries(params)) {
      assert.ok(allowed[k], `${method}: no ${k}`);
      assert.match(v, allowed[k]);
    }
    const sent = JSON.stringify(params);
    assert.equal(/pat_|prt_/.test(sent), false, `${method}: no token`);
    for (const secret of [...verifiers, ...tokens]) assert.equal(sent.includes(secret), false, `${method}: no verifier`);
  }
});
