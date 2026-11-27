// Background router with a fake WebExtension API and a fake native host.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';

const evt = () => {
  const fns = [];
  return { addListener: (f) => fns.push(f), removeListener: () => {}, fns };
};

const calls = []; // [method, params] sent to the agent
let agent = () => ({}); // (method, params) => result | { __error: {code, message} }
const tabsById = new Map([[1, { id: 1, url: 'https://github.com/login', active: true }]]);
const tabMessages = [];
let onMessage;
const alarmsCreated = [];
const alarmListeners = [];
const offscreenLog = [];
const sessionStore = {};
const storageWrites = []; // every storage.*.set payload, to check that no secret is persisted
const ports = []; // every native port the background opened
let connectBehaviour = null; // (port) => void, e.g. simulate "native messaging host not found"
const captures = []; // tabs.captureVisibleTab calls
let capture = async () => 'data:image/png;base64,iVBORw0+/A==';

function fakePort() {
  const port = { onMessage: evt(), onDisconnect: evt() };
  port.postMessage = (msg) => {
    calls.push([msg.method, msg.params]);
    queueMicrotask(async () => {
      const out = await agent(msg.method, msg.params);
      const reply = out && out.__error ? { id: msg.id, error: out.__error } : { id: msg.id, result: out };
      port.onMessage.fns.forEach((f) => f(reply));
    });
  };
  port.disconnect = () => { port.closed = true; };
  return port;
}

before(async () => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext', lastError: undefined,
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
      connectNative: () => {
        const port = fakePort();
        ports.push(port);
        connectBehaviour?.(port);
        return port;
      },
      onMessage: { addListener: (f) => { onMessage = f; } },
      onInstalled: evt(), onStartup: evt(),
      sendMessage: async (msg) => {
        if (msg?.target !== 'offscreen') return undefined;
        offscreenLog.push(['msg', msg]);
        return { result: 'cleared' };
      },
    },
    alarms: { create: async (name, info) => { alarmsCreated.push([name, info]); }, onAlarm: { addListener: (f) => alarmListeners.push(f) } },
    offscreen: {
      createDocument: async (opts) => { offscreenLog.push(['create', opts.reasons]); },
      closeDocument: async () => { offscreenLog.push(['close']); },
    },
    tabs: {
      onRemoved: evt(), onActivated: evt(), onUpdated: evt(),
      query: async () => [...tabsById.values()],
      get: async (id) => tabsById.get(id),
      sendMessage: async (tabId, msg, opts) => { tabMessages.push([tabId, msg, opts]); return { ok: true }; },
      captureVisibleTab: async (windowId, opts) => { captures.push([windowId, opts]); return capture(windowId, opts); },
    },
    contextMenus: { removeAll: (cb) => cb?.(), create: () => {}, onClicked: evt() },
    commands: { onCommand: evt() },
    action: { setBadgeText: async () => {}, setTitle: async () => {}, setBadgeBackgroundColor: async () => {} },
    scripting: { executeScript: async () => [] },
    storage: {
      local: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
      sync: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
      onChanged: evt(),
      session: {
        set: async (o) => { storageWrites.push(o); Object.assign(sessionStore, o); },
        get: async (k) => (k in sessionStore ? { [k]: sessionStore[k] } : {}),
        remove: async (k) => { delete sessionStore[k]; },
      },
    },
  };
  await import('../src/background.js');
});

/** Sends `msg` to the router as if from `sender`; resolves with the response. */
function send(msg, sender) {
  return new Promise((resolve) => {
    const async = onMessage(msg, { id: 'pass-ext', ...sender }, resolve);
    if (!async) resolve(undefined);
  });
}

const contentSender = (url, extra = {}) => ({ tab: tabsById.get(1), frameId: 0, url, ...extra });
const lastCall = (method) => [...calls].reverse().find((c) => c[0] === method)?.[1];

test('logins.find uses the URL the browser reports for the sender, not the message', async () => {
  agent = () => ({ items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }], pending_otp: null });
  const res = await send({ type: 'logins.find', url: 'https://evil.test/' }, contentSender('https://github.com/login'));
  assert.equal(res.ok, true);
  assert.equal(lastCall('logins.find').url, 'https://github.com/login');
});

test('a sub-frame fill is bound to the frame URL', async () => {
  agent = (m) => (m === 'logins.fill' ? { username: 'u', password: 'p', totp: null } : {});
  const res = await send({ type: 'logins.fill', id: 'item' }, contentSender('https://accounts.example.com/frame', { frameId: 7 }));
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('logins.fill'), { url: 'https://accounts.example.com/frame', id: 'item' });
});

test('non-web pages are refused before reaching the agent', async () => {
  const before = calls.length;
  const res = await send({ type: 'logins.find' }, contentSender('file:///C:/secret.html'));
  assert.equal(res.ok, false);
  assert.equal(calls.length, before);
});

test('agent errors are forwarded with their protocol code', async () => {
  agent = () => ({ __error: { code: 'url_mismatch', message: 'nope' } });
  const res = await send({ type: 'totp.get', id: 'x' }, contentSender('https://github.com/'));
  assert.deepEqual(res, { ok: false, error: { code: 'url_mismatch', message: 'nope' } });
});

test('popup-only handlers are not reachable from content scripts', async () => {
  const res = await send({ type: 'popup.copy', tabId: 1, id: 'gh', field: 'password' }, contentSender('https://github.com/'));
  assert.equal(res, undefined, 'no handler: listener returns false');
});

test('popup.copy uses the tab URL from tabs.get and returns only the requested field', async () => {
  agent = (m) => (m === 'logins.fill' ? { username: 'octo', password: 'hunter2', totp: null } : {});
  const res = await send({ type: 'popup.copy', tabId: 1, id: 'gh', field: 'username' }, { url: 'chrome-extension://pass-ext/src/popup/popup.html' });
  assert.deepEqual(res, { ok: true, result: { value: 'octo' } });
  assert.equal(lastCall('logins.fill').url, 'https://github.com/login');
});

test('passkey.get: origin from sender.origin, rpId default, unknown option fields dropped', async () => {
  agent = (m) => (m === 'passkey.get' ? { credentialId: 'AQ' } : {});
  const res = await send({ type: 'passkey.get', options: { challenge: 'AQID', allowCredentials: [{ type: 'public-key', id: 'AQE', transports: ['usb'] }], userVerification: 'required', origin: 'https://evil.test' } },
    contentSender('https://www.example.com/signin', { origin: 'https://www.example.com' }));
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('passkey.get'), {
    origin: 'https://www.example.com', rpId: 'www.example.com', challenge: 'AQID',
    allowCredentials: [{ id: 'AQE' }], userVerification: 'required', crossOrigin: false,
  });
});

test('passkey.create / passkey.get: the WebAuthn PRF input goes to the agent as it is', async () => {
  agent = () => ({ credentialId: 'AQ' });
  const prf = { eval: { first: 'AQID', second: 'BAUG' }, evalByCredential: { AQE: { first: 'BwgJ' } } };
  await send({ type: 'passkey.get', options: { rpId: 'example.com', challenge: 'AQID', allowCredentials: [{ id: 'AQE' }], extensions: { prf, credProps: true } } },
    contentSender('https://example.com/'));
  assert.deepEqual(lastCall('passkey.get').extensions, { prf });
  await send({ type: 'passkey.create', options: { rp: { id: 'example.com' }, user: { id: 'AQ', name: 'a' }, challenge: 'AQID', extensions: { prf: {} } } },
    contentSender('https://example.com/'));
  assert.deepEqual(lastCall('passkey.create').extensions, { prf: {} });
  // No prf (or not a dictionary): no extensions at all.
  await send({ type: 'passkey.get', options: { rpId: 'example.com', challenge: 'AQID', extensions: { prf: 'x' } } }, contentSender('https://example.com/'));
  assert.equal(lastCall('passkey.get').extensions, undefined);
  await send({ type: 'passkey.get', options: { rpId: 'example.com', challenge: 'AQID' } }, contentSender('https://example.com/'));
  assert.equal(lastCall('passkey.get').extensions, undefined);
});

test('passkey.get from the inline menu carries the picked item id', async () => {
  agent = () => ({ credentialId: 'AQ' });
  await send({ type: 'passkey.get', mediation: 'conditional', id: 'item-9', options: { rpId: 'example.com', challenge: 'AQID' } },
    contentSender('https://example.com/'));
  assert.equal(lastCall('passkey.get').id, 'item-9');
});

test('passkey.find: the origin from the browser, the rpId and allowCredentials of the request, never an unlock', async () => {
  agent = (m) => (m === 'passkey.find' ? { rp_id: 'example.com', items: [], locked: false } : {});
  let res = await send({ type: 'passkey.find', options: { rpId: 'example.com', allowCredentials: [{ id: 'AQE' }], challenge: 'AQID' }, origin: 'https://evil.test' },
    contentSender('https://login.example.com/signin', { origin: 'https://login.example.com' }));
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('passkey.find'), { origin: 'https://login.example.com', rpId: 'example.com', allowCredentials: [{ id: 'AQE' }] });
  // No rpId: the page's host, like passkey.get.
  await send({ type: 'passkey.find', options: {} }, contentSender('https://www.example.com/', { origin: 'https://www.example.com' }));
  assert.deepEqual(lastCall('passkey.find'), { origin: 'https://www.example.com', rpId: 'www.example.com', allowCredentials: [] });
  // Locked: `locked` back, no unlock prompt (the card simply doesn't show).
  agent = (m) => (m === 'unlock' ? { locked: false } : { __error: { code: 'locked', message: 'Vault is locked' } });
  const before = calls.length;
  res = await send({ type: 'passkey.find', options: { rpId: 'example.com' } }, contentSender('https://example.com/'));
  assert.equal(res.error.code, 'locked');
  assert.deepEqual(calls.slice(before).map((c) => c[0]), ['passkey.find']);
  // An older desktop app: not_supported.
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method passkey.find' } });
  res = await send({ type: 'passkey.find', options: { rpId: 'example.com' } }, contentSender('https://example.com/'));
  assert.equal(res.error.code, 'not_supported');
});

test('passkey.find: insecure pages, cross-origin frames and bad credential ids never reach the agent', async () => {
  const before = calls.filter((c) => c[0] === 'passkey.find').length;
  let res = await send({ type: 'passkey.find', options: {} }, contentSender('http://example.com/'));
  assert.equal(res.error.code, 'not_found');
  res = await send({ type: 'passkey.find', options: {} }, contentSender('https://widget.other.test/', { frameId: 3 }));
  assert.equal(res.error.code, 'not_found');
  res = await send({ type: 'passkey.find', options: { allowCredentials: [{ id: 'not base64!' }] } }, contentSender('https://example.com/'));
  assert.equal(res.error.code, 'invalid_params');
  assert.equal(calls.filter((c) => c[0] === 'passkey.find').length, before);
});

test('passkey.get from the passkey card: the picked passkey, and a locked vault unlocks for that login', async () => {
  let locked = true;
  agent = (m) => {
    if (m === 'unlock') { locked = false; return { locked: false }; }
    return locked ? { __error: { code: 'locked', message: 'Vault is locked' } } : { credentialId: 'AQ' };
  };
  const res = await send({ type: 'passkey.get', mediation: 'conditional', id: 'item-9', credentialId: 'AQE', userActivated: true,
    options: { rpId: 'example.com', challenge: 'AQID' } }, contentSender('https://example.com/'));
  assert.equal(res.ok, true);
  assert.equal(lastCall('passkey.get').id, 'item-9');
  assert.equal(lastCall('passkey.get').credentialId, 'AQE');
  assert.deepEqual(lastCall('unlock'), { for: 'item-9' });
  // A credential id that isn't base64url never reaches the agent.
  const before = calls.length;
  const bad = await send({ type: 'passkey.get', mediation: 'conditional', id: 'item-9', credentialId: 'no!', options: { challenge: 'AQID' } },
    contentSender('https://example.com/'));
  assert.equal(bad.error.code, 'invalid_params');
  assert.equal(calls.length, before);
});

test('passkey.create builds the agent request params', async () => {
  agent = () => ({ credentialId: 'AQ' });
  await send({ type: 'passkey.create', options: {
    rp: { name: 'Example' }, user: { id: 'AQIDBA', name: 'alice', displayName: 'Alice' }, challenge: 'CQgH',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [{ type: 'public-key', id: '-_8' }],
  } }, contentSender('https://example.com/register'));
  assert.deepEqual(lastCall('passkey.create'), {
    origin: 'https://example.com', rp: { id: 'example.com', name: 'Example' },
    user: { id: 'AQIDBA', name: 'alice', displayName: 'Alice' }, challenge: 'CQgH',
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }], excludeCredentials: [{ id: '-_8' }],
    authenticatorSelection: { userVerification: 'preferred' }, crossOrigin: false,
  });
});

test('passkey.create forwards a required userVerification to the agent', async () => {
  agent = () => ({ credentialId: 'AQ' });
  await send({ type: 'passkey.create', options: {
    rp: { name: 'Example' }, user: { id: 'AQIDBA', name: 'alice' }, challenge: 'CQgH',
    authenticatorSelection: { userVerification: 'required', residentKey: 'required' },
  } }, contentSender('https://example.com/register'));
  assert.deepEqual(lastCall('passkey.create').authenticatorSelection, { userVerification: 'required' });
  await send({ type: 'passkey.create', options: {
    rp: { name: 'Example' }, user: { id: 'AQIDBA', name: 'alice' }, challenge: 'CQgH',
    authenticatorSelection: { userVerification: 'bogus' },
  } }, contentSender('https://example.com/register'));
  assert.deepEqual(lastCall('passkey.create').authenticatorSelection, { userVerification: 'preferred' });
});

test('passkeys: insecure origins, cross-origin frames and bad base64url never reach the agent', async () => {
  const before = calls.filter((c) => c[0].startsWith('passkey')).length;
  let res = await send({ type: 'passkey.get', options: { challenge: 'AQID' } }, contentSender('http://example.com/'));
  assert.equal(res.error.code, 'not_found');
  res = await send({ type: 'passkey.get', options: { challenge: 'AQID' } }, contentSender('https://widget.other.test/', { frameId: 3 }));
  assert.equal(res.error.code, 'not_found');
  res = await send({ type: 'passkey.get', options: { challenge: 'not base64!' } }, contentSender('https://example.com/'));
  assert.equal(res.error.code, 'invalid_params');
  assert.equal(calls.filter((c) => c[0].startsWith('passkey')).length, before);
  // http://localhost is allowed
  agent = () => ({ credentialId: 'AQ' });
  res = await send({ type: 'passkey.get', options: { challenge: 'AQID' } }, contentSender('http://localhost:8080/'));
  assert.equal(res.ok, true);
});

test('locked vault: a passkey request the user started triggers unlock and retries once', async () => {
  let locked = true;
  agent = (m) => {
    if (m === 'unlock') { locked = false; return { locked: false }; }
    return locked ? { __error: { code: 'locked', message: 'Vault is locked' } } : { credentialId: 'AQ' };
  };
  const res = await send({ type: 'passkey.get', options: { challenge: 'AQID' }, userActivated: true }, contentSender('https://example.com/'));
  assert.equal(res.ok, true);
  assert.deepEqual(calls.slice(-3).map((c) => c[0]), ['passkey.get', 'unlock', 'passkey.get']);
});

test('locked vault: a passkey request nobody started (a page asking as it loads) never asks to unlock', async () => {
  agent = (m) => (m === 'unlock' ? { locked: false } : { __error: { code: 'locked', message: 'Vault is locked' } });
  for (const msg of [
    { type: 'passkey.get', options: { challenge: 'AQID' } },
    { type: 'passkey.get', options: { challenge: 'AQID' }, userActivated: false },
    { type: 'passkey.create', options: { rp: { name: 'Example' }, user: { id: 'AQ', name: 'a' }, challenge: 'AQID' } },
  ]) {
    const before = calls.length;
    const res = await send(msg, contentSender('https://example.com/'));
    assert.equal(res.ok, false);
    // `locked` goes back to the page script, which hands the request to the browser's own WebAuthn.
    assert.equal(res.error.code, 'locked');
    assert.deepEqual(calls.slice(before).map((c) => c[0]), [msg.type], 'no unlock prompt');
  }
});

test("totp.get: the toast's next code and a late code never ask to unlock", async () => {
  let locked = true;
  agent = (m) => {
    if (m === 'unlock') { locked = false; return { locked: false }; }
    return locked ? { __error: { code: 'locked', message: 'Vault is locked' } } : { id: 'gh', code: '123456', period: 30, remaining_secs: 20 };
  };
  const before = calls.length;
  const res = await send({ type: 'totp.get', id: 'gh', automatic: true }, contentSender('https://github.com/sessions/two-factor'));
  assert.equal(res.ok, false);
  assert.equal(res.error.code, 'locked');
  assert.deepEqual(calls.slice(before).map((c) => c[0]), ['totp.get']);
  // Picked by the user: unlock first.
  const picked = await send({ type: 'totp.get', id: 'gh' }, contentSender('https://github.com/sessions/two-factor'));
  assert.equal(picked.ok, true);
  assert.deepEqual(calls.slice(before + 1).map((c) => c[0]), ['totp.get', 'unlock', 'totp.get']);
});

test('save flow: capture, query (never the password to the content script), commit with token', async () => {
  agent = (m, p) => {
    if (m === 'logins.save_check') return { action: 'update_password', id: 'gh', title: 'GitHub' };
    if (m === 'logins.save') return { id: 'gh' };
    return {};
  };
  await send({ type: 'save.capture', username: 'octo', password: 'n3w-secret', kind: 'login' }, contentSender('https://github.com/session'));
  const q = await send({ type: 'save.query' }, contentSender('https://github.com/'));
  assert.equal(q.ok, true);
  assert.equal(q.result.mode, 'update');
  assert.equal(q.result.title, 'GitHub');
  assert.equal(q.result.editable, true);
  assert.equal(q.result.password, undefined, 'the banner never has it: its edit frame asks for it (save.edit-get)');
  assert.ok(!JSON.stringify(q).includes('n3w-secret'));
  const again = await send({ type: 'save.query' }, contentSender('https://github.com/'));
  assert.equal(again.result, null, 'offered once');
  const bad = await send({ type: 'save.commit', token: 'wrong' }, contentSender('https://github.com/'));
  assert.equal(bad.ok, false);
  const done = await send({ type: 'save.commit', token: q.result.token }, contentSender('https://github.com/'));
  assert.equal(done.ok, true);
  assert.deepEqual(lastCall('logins.save'), { url: 'https://github.com/session', username: 'octo', password: 'n3w-secret', id: 'gh' });
  const replay = await send({ type: 'save.commit', token: q.result.token }, contentSender('https://github.com/'));
  assert.equal(replay.ok, false, 'password dropped after commit');
});

test('save.query is ignored from sub-frames', async () => {
  await send({ type: 'save.capture', username: 'a', password: 'b' }, contentSender('https://github.com/'));
  const q = await send({ type: 'save.query' }, contentSender('https://github.com/', { frameId: 2 }));
  assert.equal(q.result, null);
});

test('otp.context: offers the agent pending OTP until it is consumed', async () => {
  agent = () => ({ items: [], pending_otp: { id: 'gh', title: 'GitHub' } });
  let ctx = await send({ type: 'otp.context', navigation: true }, contentSender('https://github.com/sessions/two-factor'));
  assert.equal(ctx.result.offer, true);
  assert.deepEqual(ctx.result.pending, { id: 'gh', title: 'GitHub' });
  await send({ type: 'otp.consumed', id: 'gh' }, contentSender('https://github.com/sessions/two-factor'));
  ctx = await send({ type: 'otp.context', navigation: true }, contentSender('https://github.com/sessions/two-factor'));
  assert.equal(ctx.result.offer, false);
});

test('otp.context: no proactive offer when the OTP was filled with the password', async () => {
  agent = (m) => (m === 'logins.fill' ? { username: 'u', password: 'p', totp: { code: '1', period: 30, remaining_secs: 9 } } : { items: [], pending_otp: { id: 'gl', title: 'GitLab' } });
  await send({ type: 'logins.fill', id: 'gl' }, contentSender('https://gitlab.com/users/sign_in'));
  await send({ type: 'fill.done', id: 'gl', otp: true }, contentSender('https://gitlab.com/users/sign_in'));
  const ctx = await send({ type: 'otp.context', navigation: true }, contentSender('https://gitlab.com/'));
  assert.equal(ctx.result.offer, false);
});

test('popup.fill targets the frame that last reported focus', async () => {
  await send({ type: 'focus', kind: 'username' }, contentSender('https://github.com/', { frameId: 5 }));
  tabMessages.length = 0;
  const res = await send({ type: 'popup.fill', tabId: 1, id: 'gh' }, { url: 'chrome-extension://pass-ext/src/popup/popup.html' });
  assert.equal(res.ok, true);
  assert.deepEqual(tabMessages[0], [1, { type: 'cmd.fill-item', id: 'gh' }, { frameId: 5 }]);
});

test('clipboard.copied (popup or OTP toast) arms the 45 s alarm; the alarm clears through the offscreen document', async () => {
  const before = Date.now();
  let res = await send({ type: 'clipboard.copied', value: 'hunter2' }, { url: 'chrome-extension://pass-ext/src/popup/popup.html' });
  assert.deepEqual(res, { ok: true, result: { scheduled: true } });
  res = await send({ type: 'clipboard.copied', value: '123456' }, contentSender('https://github.com/sessions/two-factor'));
  assert.deepEqual(res, { ok: true, result: { scheduled: true } });
  assert.equal(alarmsCreated.length, 2);
  const [name, { when }] = alarmsCreated[1];
  assert.equal(name, 'pass-clipboard-clear');
  assert.ok(when >= before + 45_000 && when <= Date.now() + 45_000);
  assert.ok(!JSON.stringify(sessionStore).includes('123456'), 'only an HMAC is kept');
  assert.deepEqual(Object.keys(sessionStore.passClipboardClear).sort(), ['mac', 'when'], 'never the HMAC key');

  assert.equal(alarmListeners.length, 1, 'onAlarm registered at startup');
  await alarmListeners[0]({ name: 'pass-clipboard-clear' });
  await new Promise((r) => setTimeout(r, 20));
  assert.deepEqual(offscreenLog.map((e) => e[0]), ['create', 'msg', 'close']);
  assert.deepEqual(offscreenLog[0][1], ['CLIPBOARD']);
  assert.equal(offscreenLog[1][1].mac.length, 64);
  assert.match(offscreenLog[1][1].key, /^[0-9a-f]{64}$/, 'the in-memory key goes to the offscreen document only');
});

test('save.query on a page with a visible sign-in form: skips a plain login, still offers a sign-up', async () => {
  agent = (m) => (m === 'logins.save_check' ? { action: 'save_new' } : {});
  await send({ type: 'save.capture', username: 'octo', password: 'wrong-pw', kind: 'login' }, contentSender('https://github.com/session'));
  const failed = await send({ type: 'save.query', sameDocument: false, loginFormVisible: true }, contentSender('https://github.com/session'));
  assert.equal(failed.result, null, 'a sign-in form still on screen means the password was wrong');

  await send({ type: 'save.capture', username: 'new@user.test', password: 'Gen-Pw-1!', kind: 'signup' }, contentSender('https://github.com/signup'));
  const q = await send({ type: 'save.query', sameDocument: false, loginFormVisible: true }, contentSender('https://github.com/login'));
  assert.equal(q.result.mode, 'save', 'redirected to the login page after signing up');
  assert.equal(q.result.username, 'new@user.test');
  await send({ type: 'save.dismiss' }, contentSender('https://github.com/login'));
});

test('save flow while the vault is locked: banner in save mode, commit unlocks then saves', async () => {
  let locked = true;
  agent = (m) => {
    if (m === 'unlock') { locked = false; return {}; }
    if (locked && (m === 'logins.save_check' || m === 'logins.save')) return { __error: { code: 'locked', message: 'Vault is locked' } };
    if (m === 'logins.save_check') return { action: 'save_new' };
    if (m === 'logins.save') return { id: 'new' };
    return { items: [], pending_otp: null };
  };
  await send({ type: 'save.capture', username: 'new@user.test', password: 'Gen-Pw-2!', kind: 'signup' }, contentSender('https://github.com/signup'));
  const q = await send({ type: 'save.query', sameDocument: true }, contentSender('https://github.com/signup'));
  assert.equal(q.result.mode, 'save');
  const done = await send({ type: 'save.commit', token: q.result.token }, contentSender('https://github.com/welcome'));
  assert.equal(done.ok, true);
  assert.deepEqual(lastCall('logins.save'), { url: 'https://github.com/signup', username: 'new@user.test', password: 'Gen-Pw-2!' });
});

test('generate: automatic requests (inline menu opened on its own) pass length through', async () => {
  agent = (m) => (m === 'generate' ? { password: 'x'.repeat(20) } : {});
  const res = await send({ type: 'generate', length: 20, automatic: true }, contentSender('https://github.com/signup'));
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('generate'), { length: 20 });
});

const PAIR_TOKEN = 'pst_kr3RuvCRcaQ29nq0oGvtM8RWx1_YAaPvx1qy-J047Hw';
const PAIR_LINK = `pass+server://pass.example.com:8443/dav/alice/personal.vault?v=1&user=alice&token=${PAIR_TOKEN}&name=Pixel%209&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g`;
const popupSender = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const optionsSender = { url: 'chrome-extension://pass-ext/src/options/options.html' };

test('popup.server-pair: hands the trimmed link to server.pair and returns host/user', async () => {
  agent = (m, p) => (m === 'server.pair' ? { shown: true, host: 'pass.example.com:8443', user: 'alice' } : {});
  const res = await send({ type: 'popup.server-pair', link: `  ${PAIR_LINK}
` }, popupSender);
  assert.deepEqual(res, { ok: true, result: { shown: true, host: 'pass.example.com:8443', user: 'alice', sign_in: false } });
  assert.deepEqual(lastCall('server.pair'), { link: PAIR_LINK });
  const fromOptions = await send({ type: 'popup.server-pair', link: PAIR_LINK }, optionsSender);
  assert.equal(fromOptions.ok, true, 'the options page may call it too');
});

test('popup.server-pair: an invite link (no token) is forwarded unchanged', async () => {
  agent = (m, p) => (m === 'server.pair' ? { shown: true, host: 'pass.example.com', user: 'alice' } : {});
  const invite = 'pass+server://pass.example.com/dav/alice/personal.vault?v=1&user=alice';
  const res = await send({ type: 'popup.server-pair', link: invite }, popupSender);
  assert.deepEqual(res, { ok: true, result: { shown: true, host: 'pass.example.com', user: 'alice', sign_in: true } });
  assert.deepEqual(lastCall('server.pair'), { link: invite });
});

test('popup.server-pair is not reachable from content scripts', async () => {
  const before = calls.length;
  const res = await send({ type: 'popup.server-pair', link: PAIR_LINK }, contentSender('https://evil.test/'));
  assert.equal(res, undefined, 'no handler: listener returns false');
  const forged = await send({ type: 'popup.server-pair', link: PAIR_LINK }, { url: 'https://evil.test/', tab: tabsById.get(1), frameId: 0 });
  assert.equal(forged, undefined);
  assert.equal(calls.length, before);
});

test('popup.server-pair: invalid links are refused before reaching the agent', async () => {
  const before = calls.length;
  for (const link of [undefined, '', 'https://x/y?v=1&user=a&token=b', 'pass+server://x/y?v=2&user=a&token=b',
    'pass+server://x/y?v=1&token=b', `pass+server://x/y?v=1&user=a&token=${'t'.repeat(5000)}`]) {
    const res = await send({ type: 'popup.server-pair', link }, popupSender);
    assert.equal(res.ok, false, String(link).slice(0, 40));
    assert.equal(res.error.code, 'invalid_params');
  }
  assert.equal(calls.length, before);
});

test('popup.server-pair: agent errors keep their code; an old agent reports not_supported', async () => {
  agent = () => ({ __error: { code: 'not_supported', message: "this Passyble app can't connect to Passyble Server" } });
  let res = await send({ type: 'popup.server-pair', link: PAIR_LINK }, popupSender);
  assert.equal(res.error.code, 'not_supported');
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method server.pair' } });
  res = await send({ type: 'popup.server-pair', link: PAIR_LINK }, popupSender);
  assert.equal(res.error.code, 'not_supported', 'desktop apps from before server.pair');
  agent = () => ({ __error: { code: 'invalid_params', message: 'link has no vault path' } });
  res = await send({ type: 'popup.server-pair', link: PAIR_LINK }, popupSender);
  assert.deepEqual(res.error, { code: 'invalid_params', message: 'link has no vault path' });
});

test('popup.server-pair: the token is never stored or logged', async () => {
  const logged = [];
  const saved = {};
  for (const k of ['log', 'info', 'warn', 'error', 'debug']) {
    saved[k] = console[k];
    console[k] = (...args) => logged.push(args.map(String).join(' '));
  }
  try {
    agent = () => ({ shown: true, host: 'pass.example.com:8443', user: 'alice' });
    await send({ type: 'popup.server-pair', link: PAIR_LINK }, popupSender);
    agent = () => ({ __error: { code: 'agent_unavailable', message: 'Passyble desktop app is not running' } });
    const res = await send({ type: 'popup.server-pair', link: PAIR_LINK }, popupSender);
    assert.equal(res.error.code, 'agent_unavailable');
    const bad = await send({ type: 'popup.server-pair', link: `${PAIR_LINK.replace('v=1', 'v=9')}` }, popupSender);
    assert.ok(!JSON.stringify(bad).includes(PAIR_TOKEN), 'error messages do not echo the token');
  } finally {
    Object.assign(console, saved);
  }
  assert.ok(!logged.some((l) => l.includes(PAIR_TOKEN)), 'not logged');
  assert.ok(!JSON.stringify(storageWrites).includes(PAIR_TOKEN), 'not written to storage');
  assert.ok(!JSON.stringify(sessionStore).includes(PAIR_TOKEN), 'not in storage.session');
});

test('popup.server-pair: a plain server address is normalized and handed to server.pair as the link', async () => {
  agent = (m) => (m === 'server.pair' ? { shown: true, host: 'pass.example.com:8443', user: null, sign_in: true } : {});
  for (const [typed, link] of [
    ['pass.example.com:8443', 'https://pass.example.com:8443'],
    ['  https://Pass.Example.com:8443/  ', 'https://pass.example.com:8443'],
    ['http://10.0.0.5:8080/pass/', 'http://10.0.0.5:8080/pass'],
  ]) {
    const res = await send({ type: 'popup.server-pair', link: typed }, popupSender);
    assert.deepEqual(res, { ok: true, result: { shown: true, host: 'pass.example.com:8443', user: null, sign_in: true, address: true } }, typed);
    assert.deepEqual(lastCall('server.pair'), { link }, typed);
  }
});

test('popup.server-pair: bad addresses never reach the agent; an old agent keeps its invalid_params', async () => {
  const before = calls.length;
  for (const link of ['alice@example.com', 'https://u:p@pass.example.com', 'pass.example.com/?x', 'ftp://pass.example.com', 'a b']) {
    const res = await send({ type: 'popup.server-pair', link }, popupSender);
    assert.equal(res.error.code, 'invalid_params', link);
  }
  assert.equal(calls.length, before);
  agent = () => ({ __error: { code: 'invalid_params', message: 'not a pass+server:// link' } });
  const old = await send({ type: 'popup.server-pair', link: 'pass.example.com' }, popupSender);
  assert.deepEqual(old.error, { code: 'invalid_params', message: 'not a pass+server:// link' }, 'the page explains "update Passyble"');
});

test('popup.start drops the native port and asks again, so a fresh host starts the desktop app', async () => {
  // A host that gave up (Passyble wasn't running when it started) answers agent_unavailable to everything.
  agent = () => ({ __error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });
  let res = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(res.error.code, 'agent_unavailable');
  const stale = ports.at(-1);
  const opened = ports.length;
  // The user clicks Start Passyble; the fresh host launches Passyble and connects.
  agent = (m) => (m === 'status' ? { version: '1.2.0', locked: true } : {});
  res = await send({ type: 'popup.start' }, popupSender);
  assert.deepEqual(res, { ok: true, result: { version: '1.2.0', locked: true } });
  assert.equal(stale.closed, true, 'old port closed');
  assert.equal(ports.length, opened + 1, 'a new native host was spawned');
  assert.equal(lastCall('status') !== undefined, true);
});

test('popup.start: still not running after the host tried, and a missing host registration', async () => {
  agent = () => ({ __error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });
  let res = await send({ type: 'popup.start' }, popupSender);
  assert.deepEqual(res.error, { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' });

  // Chrome: the port disconnects at once with lastError "Specified native messaging host not found."
  connectBehaviour = (port) => {
    port.postMessage = () => {};
    queueMicrotask(() => {
      chrome.runtime.lastError = { message: 'Specified native messaging host not found.' };
      port.onDisconnect.fns.forEach((fn) => fn(port));
      chrome.runtime.lastError = undefined;
    });
  };
  try {
    res = await send({ type: 'popup.start' }, popupSender);
  } finally {
    connectBehaviour = null;
  }
  assert.deepEqual(res.error, { code: 'agent_unavailable', message: 'Specified native messaging host not found.' });
});

test('passkey.start_app ("Open Passyble" in the passkey card): a fresh host starts the desktop app, at most once in a while; only the lock state back', async () => {
  agent = () => ({ __error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });
  const page = contentSender('https://login.example.com/');
  let res = await send({ type: 'passkey.find', options: { rpId: 'example.com' } }, page);
  assert.equal(res.error.code, 'agent_unavailable');
  agent = (m) => (m === 'status' ? { version: '1.2.0', locked: true, features: ['unlock.inline'] } : {});
  // Running already (a port that still works): nothing restarted.
  res = await send({ type: 'passkey.start_app' }, page);
  assert.deepEqual(res, { ok: true, result: { locked: true } }, 'the lock state only, no version or features');
  // Not running: the port goes, a new host starts Passyble.
  const stale = ports.at(-1);
  const opened = ports.length;
  agent = (m) => (m === 'status' && ports.length > opened ? { version: '1.2.0', locked: true } : { __error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });
  res = await send({ type: 'passkey.start_app' }, page);
  assert.deepEqual(res, { ok: true, result: { locked: true } });
  assert.equal(stale.closed, true, 'old port closed');
  assert.equal(ports.length, opened + 1, 'a new native host was spawned');
  // Again right away (a page's renderer could send it in a loop): no second restart.
  agent = () => ({ __error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });
  const spawned = ports.length;
  res = await send({ type: 'passkey.start_app' }, page);
  assert.equal(res.error.code, 'agent_unavailable');
  assert.ok(ports.length <= spawned + 1, 'no restart of the host');
  // passkey.find for the page's own request (the user waits) asks even within the backoff.
  agent = (m) => (m === 'passkey.find' ? { rp_id: 'example.com', items: [], locked: false } : {});
  res = await send({ type: 'passkey.find', options: { rpId: 'example.com' }, automatic: false }, page);
  assert.equal(res.ok, true, JSON.stringify(res));
});

test('popup.start is not reachable from content scripts', async () => {
  const opened = ports.length;
  const res = await send({ type: 'popup.start' }, contentSender('https://evil.test/'));
  assert.equal(res, undefined);
  assert.equal(ports.length, opened, 'no host spawned by a web page');
});

test('a timeout is not "not running": no backoff for automatic calls, and the badge does not say so', async () => {
  const titles = [];
  const savedSetTitle = chrome.action.setTitle;
  chrome.action.setTitle = async ({ title }) => { titles.push(title); };
  const badge = async () => {
    titles.length = 0;
    chrome.tabs.onUpdated.fns.forEach((f) => f(1, { status: 'complete' }, tabsById.get(1)));
    for (let i = 0; i < 20 && !titles.length; i++) await new Promise((r) => setTimeout(r, 0));
    return titles.at(-1);
  };
  try {
    // A Windows Hello prompt left open: the fill times out (NativeClient rejects with `timeout`).
    agent = (m) => (m === 'logins.fill' ? { __error: { code: 'timeout', message: 'Passyble did not answer "logins.fill" in time' } } : { version: '1.0.0', locked: false });
    await send({ type: 'popup.status' }, popupSender); // a success clears any earlier backoff
    const res = await send({ type: 'logins.fill', id: 'gh' }, contentSender('https://github.com/login'));
    assert.equal(res.error.code, 'timeout');
    // The badge's automatic logins.find still reaches the agent.
    agent = (m) => (m === 'logins.find' ? { items: [{ id: 'gh', title: 'GitHub' }], pending_otp: null } : {});
    const before = calls.length;
    assert.equal(await badge(), 'Passyble: 1 login for this site');
    assert.equal(calls.slice(before).some((c) => c[0] === 'logins.find'), true, 'not skipped by the unavailable backoff');
    // A badge check that times out itself shows the plain title, not "not running".
    agent = () => ({ __error: { code: 'timeout', message: 'Passyble did not answer "logins.find" in time' } });
    const title = await badge();
    assert.equal(title, 'Passyble');
    assert.notEqual(title, 'Passyble desktop app is not running');
  } finally {
    chrome.action.setTitle = savedSetTitle;
  }
});

test('a read lost with a native port that just closed is sent once more on a fresh port; a fill never is', async () => {
  const page = contentSender('https://github.com/login');
  agent = (m) => (m === 'logins.find' ? { items: [{ id: 'gh', title: 'GitHub', username: 'octo' }], pending_otp: null } : { username: 'octo', password: 'hunter2', totp: null });
  // The host exits (Passyble restarted, or the browser ended it) with the next request unanswered.
  const dieOnNextMessage = () => {
    const port = ports.at(-1);
    port.postMessage = (msg) => {
      calls.push([msg.method, msg.params]);
      queueMicrotask(() => port.onDisconnect.fns.forEach((f) => f({ error: { message: 'Native host has exited.' } })));
    };
  };
  assert.equal((await send({ type: 'logins.find' }, page)).ok, true); // the current port is ports.at(-1)
  dieOnNextMessage();
  let opened = ports.length;
  let before = calls.length;
  const found = await send({ type: 'logins.find' }, page);
  assert.equal(found.ok, true, JSON.stringify(found));
  assert.equal(found.result.items[0].id, 'gh');
  assert.equal(ports.length, opened + 1, 'on a fresh port (a new native host)');
  assert.deepEqual(calls.slice(before).map((c) => c[0]), ['logins.find', 'logins.find']);

  // A fill may have reached the agent (and its Windows Hello prompt): never sent twice.
  dieOnNextMessage();
  opened = ports.length;
  before = calls.length;
  const filled = await send({ type: 'logins.fill', id: 'gh' }, page);
  assert.equal(filled.error.code, 'agent_unavailable');
  assert.deepEqual(calls.slice(before).map((c) => c[0]), ['logins.fill']);
  assert.equal(ports.length, opened, 'no new host for it');

  // The host's own answer ("not running") is final, and so is a missing host registration.
  agent = () => ({ __error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } });
  before = calls.length;
  assert.equal((await send({ type: 'logins.find' }, page)).error.code, 'agent_unavailable');
  assert.equal(calls.length, before + 1);
  connectBehaviour = (port) => {
    port.postMessage = () => {};
    queueMicrotask(() => {
      chrome.runtime.lastError = { message: 'Specified native messaging host not found.' };
      port.onDisconnect.fns.forEach((fn) => fn(port));
      chrome.runtime.lastError = undefined;
    });
  };
  try {
    opened = ports.length;
    const res = await send({ type: 'popup.start' }, popupSender);
    assert.equal(res.error.message, 'Specified native messaging host not found.');
    assert.equal(ports.length, opened + 1, 'asked once');
  } finally {
    connectBehaviour = null;
  }
  agent = (m) => (m === 'status' ? { version: '1.0.0', locked: false } : {});
  await send({ type: 'popup.start' }, popupSender); // a working port again (and no back-off) for the next tests
});

test('opaque origin (sandboxed frame / CSP sandbox): never treated as the site its URL names', async () => {
  // e.g. user-uploaded HTML served from https://github.com/... with `Content-Security-Policy: sandbox`
  agent = (m) => (m === 'passkey.get' ? { credentialId: 'AQID' } : { items: [], pending_otp: null, username: 'u', password: 'p' });
  const opaque = contentSender('https://github.com/user-content/page.html', { origin: 'null' });
  const before = calls.length;
  for (const type of ['logins.find', 'logins.fill', 'totp.get', 'totp.popup']) {
    const res = await send({ type, id: 'gh' }, opaque);
    assert.equal(res.ok, false, type);
  }
  const pk = await send({ type: 'passkey.get', options: { rpId: 'github.com', challenge: 'AQID' } }, opaque);
  assert.deepEqual([pk.ok, pk.error.code], [false, 'not_found'], 'passkeys fall back to the browser, which refuses an opaque origin');
  const ctx = await send({ type: 'otp.context', navigation: true }, opaque);
  assert.equal(ctx.result.pending, null);
  await send({ type: 'save.capture', username: 'u', password: 'typed' }, opaque);
  assert.equal(await send({ type: 'save.query' }, opaque).then((r) => r.result), null, 'nothing captured');
  assert.equal(calls.length, before, 'the agent was never asked');
});

test('a sender origin that differs from its URL is refused; a matching one is fine', async () => {
  agent = () => ({ items: [], pending_otp: null });
  const before = calls.length;
  const bad = await send({ type: 'logins.find' }, contentSender('https://github.com/login', { origin: 'https://evil.test' }));
  assert.equal(bad.ok, false);
  assert.equal(calls.length, before);
  const good = await send({ type: 'logins.find' }, contentSender('https://github.com/login', { origin: 'https://github.com' }));
  assert.equal(good.ok, true);
  assert.equal(lastCall('logins.find').url, 'https://github.com/login');
});

test('a sub-frame without its own URL never borrows the tab (top frame) URL', async () => {
  const before = calls.length;
  const res = await send({ type: 'logins.fill', id: 'gh' }, { tab: tabsById.get(1), frameId: 5 });
  assert.equal(res.ok, false);
  assert.equal(calls.length, before);
});

test('passkeys: a same-origin frame under a cross-origin parent (A > B > A) goes to the browser', async () => {
  agent = () => ({ credentialId: 'AQID' });
  const nested = { tab: tabsById.get(1), frameId: 9, url: 'https://github.com/frame', origin: 'https://github.com' };
  const before = calls.length;
  const res = await send({ type: 'passkey.get', options: { challenge: 'AQID' }, crossOriginAncestor: true }, nested);
  assert.deepEqual([res.ok, res.error.code], [false, 'not_found']);
  assert.equal(calls.length, before);
  const direct = await send({ type: 'passkey.get', options: { challenge: 'AQID' }, crossOriginAncestor: false }, nested);
  assert.equal(direct.ok, true);
  assert.equal(lastCall('passkey.get').crossOrigin, false);
  assert.equal(lastCall('passkey.get').origin, 'https://github.com');
});

test('editor handlers are popup-only: content scripts cannot read or change logins', async () => {
  const before = calls.length;
  for (const type of ['popup.edit-get', 'popup.edit-save', 'popup.edit-delete', 'popup.edit-restore',
    'popup.totp-check', 'popup.totp-scan', 'popup.show-item']) {
    const res = await send({ type, tabId: 1, id: 'gh', fields: { password: 'x' } }, contentSender('https://github.com/'));
    assert.equal(res, undefined, type);
  }
  assert.equal(calls.length, before);
  assert.equal(captures.length, 0);
});

test('popup.state advertises editing from the agent features', async () => {
  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['edit', 'totp.from_image'] } : { items: [], pending_otp: null });
  const res = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(res.result.can_edit, true);
  assert.equal(res.result.can_scan, true);
  agent = (m) => (m === 'status' ? { locked: false, version: '0.1' } : { items: [], pending_otp: null });
  const old = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(old.result.can_edit, false);
});

test('popup.icons: icons.get for the tab URL (or a looked-up site); popup only; advertised by features', async () => {
  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['edit', 'icons.get'] }
    : m === 'icons.get' ? { icons: {}, items: {} } : { items: [], pending_otp: null });
  assert.equal((await send({ type: 'popup.state', tabId: 1 }, popupSender)).result.can_icons, true);
  const res = await send({ type: 'popup.icons', tabId: 1 }, popupSender);
  assert.deepEqual(res, { ok: true, result: { icons: {}, items: {} } });
  assert.deepEqual(lastCall('icons.get'), { url: 'https://github.com/login' });
  await send({ type: 'popup.icons', url: 'https://example.com/' }, popupSender);
  assert.deepEqual(lastCall('icons.get'), { url: 'https://example.com/' });
  const before = calls.length;
  assert.equal(await send({ type: 'popup.icons', tabId: 1 }, contentSender('https://github.com/')), undefined);
  assert.equal(calls.length, before);
});

test('popup.edit-get is bound to the tab URL from tabs.get, never one from the message', async () => {
  agent = (m) => (m === 'logins.get_for_edit' ? { id: 'gh', password: 'pw' } : {});
  const res = await send({ type: 'popup.edit-get', tabId: 1, id: 'gh', url: 'https://evil.test/' }, popupSender);
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('logins.get_for_edit'), { url: 'https://github.com/login', id: 'gh' });
});

test('popup.edit-save: update with an id, create without; only known fields, checked', async () => {
  agent = (m) => ({ id: m === 'logins.create' ? 'new' : 'gh', title: 'GitHub' });
  const fields = { title: 'GitHub', username: 'octo', password: 'pw', notes: '', urls: ['github.com'], totp: null, favorite: true };
  const updated = await send({ type: 'popup.edit-save', tabId: 1, id: 'gh', fields }, popupSender);
  assert.equal(updated.ok, true);
  assert.deepEqual(lastCall('logins.update'), { url: 'https://github.com/login', id: 'gh',
    fields: { title: 'GitHub', username: 'octo', password: 'pw', notes: '', urls: ['github.com'], totp: null } });
  const created = await send({ type: 'popup.edit-save', tabId: 1, fields: { username: 'octo', password: 'pw' } }, popupSender);
  assert.equal(created.result.id, 'new');
  assert.deepEqual(lastCall('logins.create'), { url: 'https://github.com/login', fields: { username: 'octo', password: 'pw' } });

  const before = calls.length;
  for (const bad of [{ password: 42 }, { urls: 'github.com' }, { urls: Array(33).fill('a.com') }, { title: 'x'.repeat(300) }, { totp: 5 }]) {
    const res = await send({ type: 'popup.edit-save', tabId: 1, id: 'gh', fields: bad }, popupSender);
    assert.equal(res.error.code, 'invalid_params', JSON.stringify(bad).slice(0, 40));
  }
  const noId = await send({ type: 'popup.edit-delete', tabId: 1, id: 7 }, popupSender);
  assert.equal(noId.error.code, 'invalid_params');
  assert.equal(calls.length, before, 'refused before reaching the agent');
});

test('editor calls on a locked vault unlock first, then retry', async () => {
  let locked = true;
  agent = (m) => {
    if (m === 'unlock') { locked = false; return { locked: false }; }
    if (locked) return { __error: { code: 'locked', message: 'Vault is locked' } };
    return { undo_secs: 60 };
  };
  const res = await send({ type: 'popup.edit-delete', tabId: 1, id: 'gh' }, popupSender);
  assert.deepEqual(res, { ok: true, result: { undo_secs: 60 } });
  const methods = calls.filter((c) => c[0] !== 'logins.find').slice(-3).map((c) => c[0]);
  assert.deepEqual(methods, ['logins.delete', 'unlock', 'logins.delete']);
});

test('an older desktop app (unknown method) answers not_supported for every editor call', async () => {
  agent = (m) => ({ __error: { code: 'invalid_params', message: 'unknown method ' + m } });
  const cases = [['popup.edit-get', { id: 'gh' }], ['popup.edit-save', { fields: {} }], ['popup.edit-restore', { id: 'gh' }],
    ['popup.totp-check', { totp: 'JBSWY3DPEHPK3PXP' }], ['popup.show-item', { id: 'gh' }]];
  for (const [type, extra] of cases) {
    const res = await send({ type, tabId: 1, ...extra }, popupSender);
    assert.equal(res.error.code, 'not_supported', type);
  }
  // Other invalid_params stay as they are.
  agent = () => ({ __error: { code: 'invalid_params', message: '2FA secret is too short' } });
  const res = await send({ type: 'popup.totp-check', tabId: 1, totp: 'JBSW' }, popupSender);
  assert.deepEqual(res.error, { code: 'invalid_params', message: '2FA secret is too short' });
});

test('popup.totp-check previews a pasted secret through totp.set without an id', async () => {
  agent = () => ({ code: '123456', remaining_secs: 20 });
  await send({ type: 'popup.totp-check', tabId: 1, totp: 'JBSWY3DPEHPK3PXP' }, popupSender);
  assert.deepEqual(lastCall('totp.set'), { url: 'https://github.com/login', totp: 'JBSWY3DPEHPK3PXP' });
});

test('popup.totp-scan captures the visible tab and sends the image to totp.from_image', async () => {
  tabsById.set(3, { id: 3, windowId: 42, url: 'https://example.com/2fa', active: false });
  agent = (m) => (m === 'totp.from_image' ? { totp: 'otpauth://totp/x?secret=JBSWY3DPEHPK3PXP', issuer: 'Example' } : { items: [] });
  capture = async () => 'data:image/png;base64,iVBORw0+/A==';
  captures.length = 0;
  // Not the visible tab: nothing is captured.
  const notVisible = await send({ type: 'popup.totp-scan', tabId: 3 }, popupSender);
  assert.equal(notVisible.ok, false);
  assert.equal(notVisible.error.code, 'open_qr_page_first', 'a code of its own, not not_found (that means "no QR code")');
  assert.equal(captures.length, 0);

  tabsById.get(3).active = true;
  const res = await send({ type: 'popup.totp-scan', tabId: 3 }, popupSender);
  assert.equal(res.ok, true);
  assert.deepEqual(captures, [[42, { format: 'png' }]]);
  assert.deepEqual(lastCall('totp.from_image'), { url: 'https://example.com/2fa', image: 'iVBORw0-_A' }, 'base64url, no padding');

  // A huge screen: JPEG instead; still too big: refused before the native host.
  captures.length = 0;
  const huge = 'A'.repeat(8 * 1024 * 1024);
  capture = async (w, opts) => (opts.format === 'png' ? 'data:image/png;base64,' + huge : 'data:image/jpeg;base64,/9j/');
  await send({ type: 'popup.totp-scan', tabId: 3 }, popupSender);
  assert.deepEqual(captures.map((c) => c[1].format), ['png', 'jpeg']);
  assert.equal(lastCall('totp.from_image').image, '_9j_');
  const before = calls.filter((c) => c[0] === 'totp.from_image').length;
  capture = async () => 'data:image/jpeg;base64,' + huge;
  const big = await send({ type: 'popup.totp-scan', tabId: 3 }, popupSender);
  assert.equal(big.ok, false);
  assert.equal(big.error.code, 'page_too_large');
  capture = async () => { throw new Error('Missing activeTab permission'); };
  const refused = await send({ type: 'popup.totp-scan', tabId: 3 }, popupSender);
  assert.equal(refused.error.message, "Can't read this page");
  assert.equal(refused.error.code, 'cant_read_page', 'a code of its own, so the popup can translate it');
  assert.equal(calls.filter((c) => c[0] === 'totp.from_image').length, before, 'the agent saw neither');
  capture = async () => 'data:image/png;base64,iVBORw0+/A==';
  tabsById.delete(3);
});

test('secure notes in app mode: titles from notes.list, a note through notes.get (copied by the desktop app); an older app has neither', async () => {
  agent = (m, p) => ({
    'notes.list': { items: [{ id: 'n1', title: 'Recovery codes', favorite: true, updated: 1, vault_id: 'home' }], truncated: false, locked: false, vaults: [] },
    'notes.get': p?.copy ? { copied: true } : { id: 'n1', title: 'Recovery codes', notes: '1111-2222', favorite: true, updated: 1 },
  }[m] ?? { items: [] });
  const list = await send({ type: 'popup.notes', query: 'ignored' }, popupSender);
  assert.equal(list.result.items[0].title, 'Recovery codes');
  assert.deepEqual(lastCall('notes.list'), { limit: 200 }, 'the whole list; the popup narrows it by title itself');
  const opened = await send({ type: 'popup.note-get', id: 'n1', copy: 'yes', extra: 1 }, popupSender);
  assert.equal(opened.result.notes, '1111-2222');
  assert.deepEqual(lastCall('notes.get'), { id: 'n1' }, 'copy only when it is true');
  const copied = await send({ type: 'popup.note-get', id: 'n1', copy: true }, popupSender);
  assert.deepEqual(copied, { ok: true, result: { copied: true } });
  assert.deepEqual(lastCall('notes.get'), { id: 'n1', copy: true });
  const before = calls.length;
  assert.equal((await send({ type: 'popup.note-get', id: 7 }, popupSender)).error?.code, 'invalid_params', 'checked before the desktop app sees it');
  assert.equal(calls.length, before);

  agent = (m) => ({ __error: { code: 'invalid_params', message: `unknown method ${m}` } });
  assert.equal((await send({ type: 'popup.notes' }, popupSender)).error.code, 'not_supported');
  assert.equal((await send({ type: 'popup.note-get', id: 'n1' }, popupSender)).error.code, 'not_supported');
});

const NL = String.fromCharCode(10);
test('quick actions in app mode: a scanned 2FA link goes to totp.set for the tab page, a note to notes.create, Generate copies through the desktop app', async () => {
  const link = 'otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
  agent = (m) => ({
    'totp.set': { id: 'gh', title: 'GitHub', has_totp: true },
    'notes.create': { id: 'n1', title: 'Recovery codes for github.com', kind: 'note', vault: { id: 'home' } },
    'generate.copy': { copied: true },
  }[m] ?? { items: [] });
  captures.length = 0;
  const attached = await send({ type: 'popup.totp-attach', tabId: 1, id: 'gh', totp: link, inline: true }, popupSender);
  assert.equal(attached.ok, true);
  assert.deepEqual(lastCall('totp.set'), { url: 'https://github.com/login', id: 'gh', totp: link }, 'the page from tabs.get; the image never went anywhere');
  assert.equal(captures.length, 0, 'the background captures nothing: the popup reads the QR code itself');
  const note = await send({ type: 'popup.note-create', fields: { title: '  Recovery codes for github.com ', notes: '1111' + NL + '2222', extra: 'dropped' } }, popupSender);
  assert.deepEqual(note, { ok: true, result: { id: 'n1', title: 'Recovery codes for github.com' } });
  assert.deepEqual(lastCall('notes.create'), { fields: { title: 'Recovery codes for github.com', notes: '1111' + NL + '2222' } }, 'no page: a note belongs to no site');
  const copied = await send({ type: 'popup.generate-copy', password: 'Generated-Pw-123!' }, popupSender);
  assert.equal(copied.ok, true);
  assert.deepEqual(lastCall('generate.copy'), { password: 'Generated-Pw-123!' });

  // Checked before the desktop app sees it.
  const before = calls.length;
  for (const [msg, why] of [
    [{ type: 'popup.totp-attach', tabId: 1, id: 'gh', totp: '' }, 'an empty value'],
    [{ type: 'popup.totp-attach', tabId: 1, totp: link }, 'no login'],
    [{ type: 'popup.note-create', fields: { title: ' ', notes: 'x' } }, 'no title'],
    [{ type: 'popup.note-create', fields: { title: 'x'.repeat(257), notes: 'x' } }, 'a long title'],
    [{ type: 'popup.note-create', fields: { title: 'x', notes: 'x'.repeat(20_001) } }, 'long notes'],
    [{ type: 'popup.note-create', fields: { title: 'x', notes: 5 } }, 'notes that are no text'],
  ]) {
    const res = await send(msg, popupSender);
    assert.equal(res.error?.code, 'invalid_params', why);
  }
  assert.equal(calls.length, before);
  // A page that is not a website: no attach.
  tabsById.set(5, { id: 5, windowId: 42, active: true, url: 'chrome://settings/' });
  assert.equal((await send({ type: 'popup.totp-attach', tabId: 5, id: 'gh', totp: link }, popupSender)).ok, false);
  tabsById.delete(5);
  // An older desktop app without notes.create: "Update Passyble".
  agent = (m) => (m === 'notes.create' ? { __error: { code: 'invalid_params', message: 'unknown method notes.create' } } : {});
  assert.equal((await send({ type: 'popup.note-create', fields: { title: 'x', notes: 'y' } }, popupSender)).error.code, 'not_supported');
  // Content scripts can't reach them.
  for (const type of ['popup.totp-attach', 'popup.note-create', 'popup.generate-copy']) {
    assert.equal(await send({ type, tabId: 1, id: 'gh', totp: link, fields: { title: 'x' }, password: 'p' }, contentSender('https://github.com/')), undefined, type);
  }
});

test('popup.totp-scan refuses a page that is not a website', async () => {
  tabsById.set(5, { id: 5, windowId: 42, active: true, url: ['file:', '', '', 'qr.html'].join('/') });
  captures.length = 0;
  const res = await send({ type: 'popup.totp-scan', tabId: 5 }, popupSender);
  assert.equal(res.ok, false);
  assert.equal(captures.length, 0);
  tabsById.delete(5);
});

test('popup.show-item and popup.edit-restore name the tab page', async () => {
  agent = () => ({ shown: true });
  await send({ type: 'popup.show-item', tabId: 1, id: 'gh' }, popupSender);
  assert.deepEqual(lastCall('app.show_item'), { url: 'https://github.com/login', id: 'gh' });
  await send({ type: 'popup.edit-restore', tabId: 1, id: 'gh' }, popupSender);
  assert.deepEqual(lastCall('logins.restore'), { url: 'https://github.com/login', id: 'gh' });
});

test('popup.show-teams: the Teams screen on a known section, else app.show_teams {}', async () => {
  agent = () => ({ shown: true });
  await send({ type: 'popup.show-teams', section: 'confirm' }, popupSender);
  assert.deepEqual(lastCall('app.show_teams'), { section: 'confirm' });
  await send({ type: 'popup.show-teams' }, popupSender);
  assert.deepEqual(lastCall('app.show_teams'), {});
  await send({ type: 'popup.show-teams', section: 'billing' }, popupSender);
  assert.deepEqual(lastCall('app.show_teams'), {});
});

test('linked vaults: popup.state says what the agent can do; pins, the switcher and a move go to the agent', async () => {
  const unknown = (m) => ({ __error: { code: 'invalid_params', message: `unknown method ${m}` } });
  agent = (m, p) => {
    if (m === 'status') return { locked: false, version: '1', features: ['edit', 'vaults', 'vaults.pins', 'items.move'] };
    if (m === 'logins.find') return { items: [], pending_otp: null };
    if (m === 'vaults.pins') return { pins: ['eng'], max: 5 };
    if (m === 'vaults.set_pins') return { pins: p.ids, max: 5 };
    if (m === 'vaults.switch') return { switching: true };
    if (m === 'items.move') return { id: 'gh-2', title: 'GitHub', kind: 'login', moved_from: p.id, vault: { id: p.vault, name: 'Engineering' } };
    return unknown(m);
  };
  const state = (await send({ type: 'popup.state', tabId: 1 }, popupSender)).result;
  assert.deepEqual([state.can_pins, state.can_move], [true, true]);
  assert.deepEqual((await send({ type: 'popup.pins' }, popupSender)).result, { pins: ['eng'], max: 5 });
  const saved = await send({ type: 'popup.set-pins', ids: ['eng', 'not-here'], known: ['eng'] }, popupSender);
  assert.deepEqual([lastCall('vaults.set_pins'), saved.result], [{ ids: ['eng', 'not-here'] }, { pins: ['eng', 'not-here'], max: 5 }],
    'app mode: no known ids, the desktop app knows every vault');
  const before = calls.length;
  for (const ids of ['eng', [''], [7], Array.from({ length: 40 }, (_, i) => `v${i}`)]) {
    assert.equal((await send({ type: 'popup.set-pins', ids }, popupSender)).error.code, 'invalid_params');
  }
  assert.equal(calls.length, before, 'nothing malformed reaches the agent');
  assert.deepEqual((await send({ type: 'popup.switch-vault', id: 'f-work' }, popupSender)).result, { switching: true });
  assert.deepEqual(lastCall('vaults.switch'), { id: 'f-work' });
  assert.equal((await send({ type: 'popup.own-vaults' }, popupSender)).error.code, 'not_supported', 'an older desktop app');
  const moved = await send({ type: 'popup.edit-move', tabId: 1, id: 'gh', vault: 'eng' }, popupSender);
  assert.equal(moved.result.id, 'gh-2');
  assert.deepEqual(lastCall('items.move'), { id: 'gh', vault: 'eng' });
  assert.equal((await send({ type: 'popup.edit-move', tabId: 1, id: 'gh', vault: '' }, popupSender)).error.code, 'invalid_params');

  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['edit', 'vaults'] } : m === 'logins.find' ? { items: [], pending_otp: null } : unknown(m));
  const old = (await send({ type: 'popup.state', tabId: 1 }, popupSender)).result;
  assert.deepEqual([old.can_pins, old.can_move], [false, false]);
  assert.equal((await send({ type: 'popup.pins' }, popupSender)).error.code, 'not_supported');
});

test('nothing the editor handles is written to extension storage', async () => {
  assert.ok(!JSON.stringify(storageWrites).includes('JBSWY3DPEHPK3PXP'));
  assert.ok(!JSON.stringify(storageWrites).includes('octo'));
});

/** Captures a submit on github.com and asks for the banner; `decision` is the agent's answer. */
async function saveBanner(decision, capture = { username: 'octo', password: 'typed-pw', kind: 'login' }) {
  agent = (m) => {
    if (m === 'logins.save_check') return decision;
    if (m === 'logins.save') return { id: decision.id || 'new' };
    return { items: [], pending_otp: null };
  };
  await send({ type: 'save.capture', ...capture }, contentSender('https://github.com/session'));
  return (await send({ type: 'save.query' }, contentSender('https://github.com/'))).result;
}

test('save banner: the agent decides, and gets the typed login (never returns a stored one)', async () => {
  await saveBanner({ action: 'save_new' });
  // (`filled_id`: whatever this tab filled last; the agent only uses it if it is a login of this site.)
  const { filled_id: _filled, ...params } = lastCall('logins.save_check');
  assert.deepEqual(params, { url: 'https://github.com/session', username: 'octo', password: 'typed-pw', kind: 'login' });
});

test('save banner case 1: username and password already saved → no banner, nothing kept', async () => {
  const q = await saveBanner({ action: 'none', id: 'gh', title: 'GitHub' });
  assert.equal(q, null);
  const commit = await send({ type: 'save.commit', token: 'any' }, contentSender('https://github.com/'));
  assert.equal(commit.ok, false, 'the typed password was dropped');
});

test('save banner case 2: same username, new password → "Update password"', async () => {
  const q = await saveBanner({ action: 'update_password', id: 'gh', title: 'GitHub' });
  assert.equal(q.mode, 'update');
  assert.equal(q.title, 'GitHub');
  await send({ type: 'save.commit', token: q.token }, contentSender('https://github.com/'));
  assert.deepEqual(lastCall('logins.save'), { url: 'https://github.com/session', username: 'octo', password: 'typed-pw', id: 'gh' });
});

test('save banner case 3: new username with a saved password → "Update username"', async () => {
  const q = await saveBanner({ action: 'update_username', id: 'gh', title: 'GitHub' },
    { username: 'octo@example.com', password: 'typed-pw', kind: 'login' });
  assert.equal(q.mode, 'username');
  assert.equal(q.username, 'octo@example.com');
  await send({ type: 'save.commit', token: q.token }, contentSender('https://github.com/'));
  assert.deepEqual(lastCall('logins.save'),
    { url: 'https://github.com/session', username: 'octo@example.com', password: 'typed-pw', id: 'gh', update: 'username' });
});

test('save banner case 4: anything else → "Save login"', async () => {
  const q = await saveBanner({ action: 'save_new' }, { username: 'someone', password: 'other', kind: 'signup' });
  assert.equal(q.mode, 'save');
  assert.equal(q.title, null);
  await send({ type: 'save.commit', token: q.token }, contentSender('https://github.com/'));
  assert.deepEqual(lastCall('logins.save'), { url: 'https://github.com/session', username: 'someone', password: 'other' });
});

test('save banner: the login Passyble just filled is named, so its own password shows no banner', async () => {
  agent = (m) => (m === 'logins.fill' ? { username: 'octo', password: 'pw', totp: null } : { action: 'none', id: 'gh' });
  await send({ type: 'logins.fill', id: 'gh' }, contentSender('https://github.com/login'));
  await send({ type: 'save.capture', username: 'Octo', password: 'pw', kind: 'login' }, contentSender('https://github.com/session'));
  const q = await send({ type: 'save.query' }, contentSender('https://github.com/'));
  assert.equal(q.result, null);
  assert.equal(lastCall('logins.save_check').filled_id, 'gh');
});

test('save banner shown while locked: Save unlocks, then skips a login that is already saved', async () => {
  let locked = true;
  agent = (m) => {
    if (m === 'unlock') { locked = false; return {}; }
    if (locked) return { __error: { code: 'locked', message: 'Vault is locked' } };
    if (m === 'logins.save_check') return { action: 'none', id: 'gh' };
    return { id: 'gh' };
  };
  await send({ type: 'save.capture', username: 'octo', password: 'pw', kind: 'login' }, contentSender('https://github.com/session'));
  const q = await send({ type: 'save.query' }, contentSender('https://github.com/'));
  assert.equal(q.result.mode, 'save');
  const before = calls.filter((c) => c[0] === 'logins.save').length;
  const done = await send({ type: 'save.commit', token: q.result.token }, contentSender('https://github.com/'));
  assert.deepEqual(done.result, { id: 'gh', unchanged: true, action: 'none' });
  assert.equal(calls.filter((c) => c[0] === 'logins.save').length, before, 'nothing written');
});

test('save banner with an older desktop app (no logins.save_check): same-username rule from logins.find', async () => {
  agent = (m) => {
    if (m === 'logins.save_check') return { __error: { code: 'invalid_params', message: 'unknown method logins.save_check' } };
    if (m === 'logins.find') return { items: [{ id: 'gh', title: 'GitHub', username: 'Octo', has_totp: false, has_passkey: false }], pending_otp: null };
    return { id: 'gh' };
  };
  await send({ type: 'save.capture', username: 'octo', password: 'n3w', kind: 'login' }, contentSender('https://github.com/session'));
  const q = await send({ type: 'save.query' }, contentSender('https://github.com/'));
  assert.equal(q.result.mode, 'update');
  assert.equal(q.result.title, 'GitHub');
  await send({ type: 'save.dismiss' }, contentSender('https://github.com/'));
});

const tab9 = (url, extra = {}) => ({ tab: { id: 9, url }, frameId: 0, url, ...extra });
const outcomeCalls = () => calls.filter((c) => c[0] === 'otp.outcome').map((c) => c[1]);

test('otp.outcome: forwarded to the agent with the sender frame URL; anything else is refused', async () => {
  agent = () => ({ skips_2fa: false });
  const before = outcomeCalls().length;
  const res = await send({ type: 'otp.outcome', outcome: 'asked', url: 'https://evil.test/' }, tab9('https://example.com/2fa'));
  assert.equal(res.ok, true);
  assert.deepEqual(outcomeCalls().at(-1), { url: 'https://example.com/2fa', outcome: 'asked' });
  for (const outcome of ['used', 'whatever', undefined]) {
    assert.equal((await send({ type: 'otp.outcome', outcome }, tab9('https://example.com/2fa'))).ok, false, String(outcome));
  }
  assert.equal(outcomeCalls().length, before + 1);
  // An older agent without the method: still fine for the page.
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method otp.outcome' } });
  assert.equal((await send({ type: 'otp.outcome', outcome: 'skipped' }, tab9('https://example.com/'))).ok, true);
});

test('otp.context: a skipped 2FA step on this sign-in makes the offer quiet (field only)', async () => {
  agent = (m) => (m === 'logins.fill' ? { username: 'u', password: 'p', totp: { code: '1', period: 30, remaining_secs: 9 } }
    : m === 'logins.find' ? { items: [], pending_otp: { id: 'ex', title: 'Example' } } : {});
  await send({ type: 'logins.fill', id: 'ex' }, tab9('https://example.com/login'));
  let ctx = await send({ type: 'otp.context', navigation: true }, tab9('https://example.com/'));
  assert.equal(ctx.result.offer, true);
  assert.equal(ctx.result.quiet, false);
  // Only the top frame decides that the step was skipped.
  await send({ type: 'otp.outcome', outcome: 'skipped' }, tab9('https://example.com/', { frameId: 3 }));
  ctx = await send({ type: 'otp.context', navigation: true }, tab9('https://example.com/'));
  assert.equal(ctx.result.quiet, false);
  await send({ type: 'otp.outcome', outcome: 'skipped' }, tab9('https://example.com/'));
  ctx = await send({ type: 'otp.context', navigation: true }, tab9('https://example.com/'));
  assert.equal(ctx.result.offer, true, 'a code field that shows up later still gets the code');
  assert.equal(ctx.result.quiet, true);
  // A new fill starts over.
  await send({ type: 'logins.fill', id: 'ex' }, tab9('https://example.com/login'));
  ctx = await send({ type: 'otp.context', navigation: true }, tab9('https://example.com/'));
  assert.equal(ctx.result.quiet, false);
});

test('otp.context: the agent\'s learned skips_2fa makes the offer quiet', async () => {
  agent = () => ({ items: [], pending_otp: { id: 'ex', title: 'Example', skips_2fa: true } });
  const ctx = await send({ type: 'otp.context', navigation: true }, tab9('https://example.com/'));
  assert.equal(ctx.result.offer, true);
  assert.equal(ctx.result.quiet, true);
});

test('otp.context: after the agent\'s window, the tab\'s fill is offered late (quiet), for its own site only', async () => {
  agent = (m) => (m === 'logins.fill' ? { username: 'u', password: 'p', totp: { code: '1', period: 30, remaining_secs: 9 } }
    : m === 'logins.find' ? { items: [{ id: 'ex', title: 'Example', username: 'u', has_totp: true, has_passkey: false }], pending_otp: null } : {});
  await send({ type: 'logins.fill', id: 'ex' }, tab9('https://example.com/login'));
  let ctx = await send({ type: 'otp.context', navigation: true }, tab9('https://example.com/2fa'));
  assert.deepEqual([ctx.result.offer, ctx.result.late, ctx.result.quiet], [true, true, true]);
  assert.deepEqual(ctx.result.pending, { id: 'ex', title: 'Example' });
  agent = (m) => (m === 'logins.find' ? { items: [], pending_otp: null } : {});
  ctx = await send({ type: 'otp.context', navigation: true }, tab9('https://other.test/2fa'));
  assert.equal(ctx.result.offer, false, 'not a login of that site');
});

test('a used code (consumed, or filled with the password) is reported as "used"', async () => {
  agent = () => ({});
  await send({ type: 'otp.consumed', id: 'ex' }, tab9('https://example.com/2fa'));
  assert.deepEqual(outcomeCalls().at(-1), { url: 'https://example.com/2fa', outcome: 'used' });
  await send({ type: 'fill.done', id: 'ex', otp: true }, tab9('https://example.com/login'));
  assert.deepEqual(outcomeCalls().at(-1), { url: 'https://example.com/login', outcome: 'used' });
  const before = outcomeCalls().length;
  await send({ type: 'fill.done', id: 'ex', otp: false }, tab9('https://example.com/login'));
  assert.equal(outcomeCalls().length, before, 'no code filled: nothing to report');
});

const tab21 = (url, extra = {}) => ({ tab: { id: 21, url }, frameId: 0, url, ...extra });
const tab22 = (url, extra = {}) => ({ tab: { id: 22, url }, frameId: 0, url, ...extra });
const POPUP = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
const callsOf = (method) => calls.filter((c) => c[0] === method).map((c) => c[1]);

test('context menu: "Generate password" and its letters-and-numbers twin next to "Fill with Passyble"; a click goes to the right-clicked frame', async () => {
  const created = [];
  const realCreate = chrome.contextMenus.create;
  chrome.contextMenus.create = (props, cb) => { created.push(props); cb?.(); };
  try {
    for (const f of chrome.runtime.onInstalled.fns) await f({ reason: 'update' });
    await new Promise((r) => setTimeout(r, 0));
  } finally {
    chrome.contextMenus.create = realCreate;
  }
  const gen = created.find((c) => c.id === 'pass-generate');
  assert.ok(created.some((c) => c.id === 'pass-fill'));
  assert.equal(gen.title, 'Generate password');
  assert.deepEqual(gen.contexts, ['editable']);
  assert.deepEqual(gen.documentUrlPatterns, ['http://*/*', 'https://*/*']);
  assert.equal(gen.visible, false, 'hidden until a password field is right-clicked');
  const plain = created.find((c) => c.id === 'pass-generate-plain');
  assert.equal(plain.title, 'Generate password (letters and numbers only)');
  assert.deepEqual(plain.contexts, ['editable']);
  assert.deepEqual(plain.documentUrlPatterns, ['http://*/*', 'https://*/*']);
  assert.equal(plain.visible, false);
  assert.equal(created.indexOf(plain), created.indexOf(gen) + 1, 'right under "Generate password"');

  // The right-clicked frame says whether its target is a password field: the item follows.
  const updates = [];
  chrome.contextMenus.update = (id, props, cb) => { updates.push([id, props]); cb?.(); };
  try {
    await send({ type: 'menu.target', password: true }, contentSender('https://github.com/signup'));
    await send({ type: 'menu.target', password: true }, contentSender('https://github.com/signup'));
    await send({ type: 'menu.target', password: false }, contentSender('https://github.com/signup'));
    await send({ type: 'menu.target', password: 'yes' }, contentSender('https://github.com/signup'));
  } finally {
    delete chrome.contextMenus.update;
  }
  assert.deepEqual(updates, [['pass-generate', { visible: true }], ['pass-generate-plain', { visible: true }],
    ['pass-generate', { visible: false }], ['pass-generate-plain', { visible: false }]], 'only on a change; anything but true hides them');

  const before = tabMessages.length;
  for (const f of chrome.contextMenus.onClicked.fns) f({ menuItemId: 'pass-generate', frameId: 3, editable: true }, { id: 1 });
  await new Promise((r) => setTimeout(r, 0));
  const sentMsg = tabMessages.slice(before).find(([, m]) => m.type === 'cmd.generate-here');
  assert.deepEqual(sentMsg, [1, { type: 'cmd.generate-here', symbols: true }, { frameId: 3 }]);

  const next = tabMessages.length;
  for (const f of chrome.contextMenus.onClicked.fns) f({ menuItemId: 'pass-generate-plain', frameId: 3, editable: true }, { id: 1 });
  await new Promise((r) => setTimeout(r, 0));
  const plainMsg = tabMessages.slice(next).find(([, m]) => m.type === 'cmd.generate-here');
  assert.deepEqual(plainMsg, [1, { type: 'cmd.generate-here', symbols: false }, { frameId: 3 }]);
});

test('draft.save: creates a login of the frame site, then updates that same login', async () => {
  agent = (m, p) => {
    if (m === 'logins.create') return { id: 'd1', title: 'shop.example', username: p.fields.username };
    if (m === 'logins.update') return { id: p.id, title: 'shop.example' };
    return { items: [], pending_otp: null };
  };
  const first = await send({ type: 'draft.save', username: ' me@x.test ', password: 'Gen-1', kind: 'signup', url: 'https://evil.test/' },
    tab21('https://shop.example/signup'));
  assert.deepEqual(first.result, { id: 'd1', created: true, title: 'shop.example' });
  assert.deepEqual(lastCall('logins.create'), { url: 'https://shop.example/signup', fields: { password: 'Gen-1', username: 'me@x.test' } });
  const again = await send({ type: 'draft.save', username: '', password: 'Gen-2', kind: 'signup' }, tab21('https://shop.example/signup'));
  assert.equal(again.result.created, false);
  assert.deepEqual(lastCall('logins.update'), { url: 'https://shop.example/signup', id: 'd1', fields: { password: 'Gen-2' } });
  // Another site in the same tab gets its own draft.
  await send({ type: 'draft.save', username: '', password: 'Gen-3', kind: 'signup' }, tab21('https://other.example/join'));
  assert.equal(lastCall('logins.create').url, 'https://other.example/join');
});

test('draft.save: a password change form keeps the draft as a separate "(new password)" login', async () => {
  agent = (m) => (m === 'logins.create' ? { id: 'd-change' } : {});
  await send({ type: 'draft.save', username: 'octo', password: 'Gen-c', kind: 'change' }, tab22('https://www.github.com/settings'));
  assert.equal(lastCall('logins.create').fields.title, 'github.com (new password)');
});

test('submit after a draft (sign-up): the draft is updated, no banner, no second login', async () => {
  agent = (m, p) => (m === 'logins.create' ? { id: 'd5' } : m === 'logins.update' ? { id: p.id } : { items: [], pending_otp: null });
  const sender = (url) => ({ tab: { id: 23, url }, frameId: 0, url });
  await send({ type: 'draft.save', username: '', password: 'Gen-5', kind: 'signup' }, sender('https://shop.example/signup'));
  const saves = callsOf('logins.save').length;
  await send({ type: 'save.capture', username: 'new@x.test', password: 'Gen-5', kind: 'signup' }, sender('https://shop.example/signup'));
  const q = await send({ type: 'save.query' }, sender('https://shop.example/welcome'));
  assert.equal(q.result, null, 'nothing to ask');
  assert.deepEqual(lastCall('logins.update'), { url: 'https://shop.example/signup', id: 'd5', fields: { password: 'Gen-5', username: 'new@x.test' } });
  assert.equal(callsOf('logins.save').length, saves);
  assert.ok(!callsOf('logins.create').some((p) => p.fields?.username === 'new@x.test'), 'no duplicate');
});

test('submit after a draft while locked: the banner offers it instead (no unlock prompt on submit)', async () => {
  const sender = (url) => ({ tab: { id: 24, url }, frameId: 0, url });
  agent = (m) => (m === 'logins.create' ? { id: 'd6' } : { items: [], pending_otp: null });
  await send({ type: 'draft.save', username: '', password: 'Gen-6', kind: 'signup' }, sender('https://shop.example/signup'));
  const unlocks = callsOf('unlock').length;
  agent = (m) => (m === 'logins.save_check' ? { action: 'save_new' } : { __error: { code: 'locked', message: 'Vault is locked' } });
  await send({ type: 'save.capture', username: 'me', password: 'Gen-6', kind: 'signup' }, sender('https://shop.example/signup'));
  const q = await send({ type: 'save.query' }, sender('https://shop.example/next'));
  assert.equal(q.result.mode, 'save');
  assert.equal(callsOf('unlock').length, unlocks);
});

test('submit of a password change after a draft: the generated password updates the real login without asking (draft ignored, then removed); Undo puts both back', async () => {
  const sender = (url) => ({ tab: { id: 25, url }, frameId: 0, url });
  agent = (m) => {
    if (m === 'logins.create') return { id: 'd7' };
    if (m === 'logins.save_check') return { action: 'update_password', id: 'gh', title: 'GitHub' };
    if (m === 'logins.save') return { id: 'gh' };
    if (m === 'logins.restore') return { id: 'restored' };
    return {};
  };
  await send({ type: 'draft.save', username: 'octo', password: 'Gen-7', kind: 'change' }, sender('https://github.com/settings/password'));
  await send({ type: 'save.capture', username: 'octo', password: 'Gen-7', kind: 'change' }, sender('https://github.com/settings/password'));
  const q = await send({ type: 'save.query' }, sender('https://github.com/settings'));
  assert.equal(q.result.autosaved, 'updated', 'no banner: "Password updated in Passyble"');
  assert.equal(q.result.mode, undefined);
  assert.equal(lastCall('logins.save_check').ignore_id, 'd7');
  assert.deepEqual(lastCall('logins.save'), { url: 'https://github.com/settings/password', username: 'octo', password: 'Gen-7', id: 'gh' });
  await new Promise((r) => setTimeout(r, 0));
  assert.deepEqual(lastCall('logins.delete'), { url: 'https://github.com/settings/password', id: 'd7' });
  // The capture is gone: no banner can save it a second time.
  const commit = await send({ type: 'save.commit', token: q.result.token }, sender('https://github.com/settings'));
  assert.equal(commit.ok, false);
  const undo = await send({ type: 'save.undo', token: q.result.token }, sender('https://github.com/settings'));
  assert.deepEqual(undo.result, { undone: 'updated' });
  assert.deepEqual(callsOf('logins.restore').slice(-2), [
    { url: 'https://github.com/settings/password', id: 'gh' },
    { url: 'https://github.com/settings/password', id: 'd7' },
  ]);
});

test('password change after a draft on a subdomain with no login of its own: the draft is kept as the new login', async () => {
  const sender = (url) => ({ tab: { id: 27, url }, frameId: 0, url });
  agent = (m) => {
    if (m === 'logins.create') return { id: 'd9' };
    // Only example.com has a login: never updated from app.example.com, so a new login is offered ...
    if (m === 'logins.save_check') return { action: 'save_new' };
    // ... and the agent finds that the draft has that password already.
    if (m === 'logins.save') return { id: 'd9', unchanged: true };
    return {};
  };
  const deletes = callsOf('logins.delete').length;
  await send({ type: 'draft.save', username: '', password: 'Gen-9', kind: 'change' }, sender('https://app.example.com/password'));
  await send({ type: 'save.capture', username: '', password: 'Gen-9', kind: 'change' }, sender('https://app.example.com/password'));
  const q = await send({ type: 'save.query' }, sender('https://app.example.com/account'));
  assert.equal(q.result.mode, 'save');
  assert.equal(lastCall('logins.save_check').ignore_id, 'd9');
  await send({ type: 'save.commit', token: q.result.token }, sender('https://app.example.com/account'));
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(callsOf('logins.delete').length, deletes, 'the draft is not deleted');
  assert.deepEqual(lastCall('logins.update'), { url: 'https://app.example.com/password', id: 'd9', fields: { title: 'app.example.com' } });
});

test('the page canonical address goes to the agent as canonical_url: top frame, https, another host only', async () => {
  const at = (url, frameId = 0) => ({ tab: { id: 28, url: 'https://app.example.com/' }, frameId, url });
  agent = (m) => {
    if (m === 'logins.save_check') return { action: 'update_password', id: 'ex', title: 'Example' };
    if (m === 'logins.save') return { id: 'ex' };
    return { items: [], pending_otp: null };
  };
  const decide = async (url, canonical, frameId) => {
    await send({ type: 'save.capture', username: 'me', password: 'pw', kind: 'login', canonical }, at(url, frameId));
    return send({ type: 'save.query' }, at('https://app.example.com/home'));
  };
  // Accepted host of the page's site (the agent checks the site itself): passed on, as an origin.
  const q = await decide('https://app.example.com/login', 'https://example.com/welcome?x=1');
  assert.equal(lastCall('logins.save_check').canonical_url, 'https://example.com');
  await send({ type: 'save.commit', token: q.result.token }, at('https://app.example.com/home'));
  assert.equal(lastCall('logins.save').canonical_url, 'https://example.com');
  // Missing, a plain-http page, an http link, the page's own host, junk, a frame: nothing passed.
  for (const [url, canonical, frameId] of [
    ['https://app.example.com/login', undefined, 0],
    ['http://app.example.com/login', 'https://example.com/', 0],
    ['https://app.example.com/login', 'http://example.com/', 0],
    ['https://app.example.com/login', 'https://app.example.com/other', 0],
    ['https://app.example.com/login', 'not a url', 0],
    ['https://app.example.com/login', 'https://example.com/', 3],
  ]) {
    await decide(url, canonical, frameId);
    assert.equal('canonical_url' in lastCall('logins.save_check'), false, `${url} ${canonical} ${frameId}`);
  }
});

test('draft.undo deletes the draft (restorable), only from its site; locked unlocks first', async () => {
  const sender = (url) => ({ tab: { id: 26, url }, frameId: 0, url });
  let locked = true;
  agent = (m) => {
    if (m === 'unlock') { locked = false; return {}; }
    if (locked) return { __error: { code: 'locked', message: 'Vault is locked' } };
    if (m === 'logins.create') return { id: 'd8' };
    if (m === 'logins.delete') return { undo_secs: 60 };
    return {};
  };
  const saved = await send({ type: 'draft.save', username: '', password: 'Gen-8', kind: 'signup' }, sender('https://shop.example/signup'));
  assert.equal(saved.result.id, 'd8', 'unlocked, then saved');
  const elsewhere = await send({ type: 'draft.undo', id: 'd8' }, sender('https://evil.test/'));
  assert.equal(elsewhere.ok, false);
  const undone = await send({ type: 'draft.undo', id: 'd8' }, sender('https://shop.example/signup'));
  assert.deepEqual(undone.result, { deleted: true });
  assert.deepEqual(lastCall('logins.delete'), { url: 'https://shop.example/signup', id: 'd8' });
  const twice = await send({ type: 'draft.undo', id: 'd8' }, sender('https://shop.example/signup'));
  assert.equal(twice.ok, false);
  assert.deepEqual([twice.error.code, twice.error.reason], ['not_found', 'nothing_to_undo'], 'shown as "nothing to undo"');
  const page = await send({ type: 'draft.undo', id: 'd8' }, sender('file:///C:/page.html'));
  assert.deepEqual([page.error.code, page.error.reason], ['not_found', 'web_pages_only']);
});

test('draft.save with an older desktop app (no editing): not_supported; bad input refused', async () => {
  agent = (m) => (m === 'logins.create' ? { __error: { code: 'invalid_params', message: 'unknown method logins.create' } } : {});
  const res = await send({ type: 'draft.save', username: '', password: 'Gen-9', kind: 'signup' }, tab21('https://old.example/signup'));
  assert.equal(res.error.code, 'not_supported');
  const bad = await send({ type: 'draft.save', username: '', password: '' }, tab21('https://old.example/signup'));
  assert.equal(bad.error.code, 'invalid_params');
});

test('banner edits: changed values are decided again by the agent and saved as edited', async () => {
  const sender = (url) => ({ tab: { id: 27, url }, frameId: 0, url });
  agent = (m, p) => {
    if (m === 'logins.save_check') return p.username === 'right@x.test' ? { action: 'update_password', id: 'r', title: 'Right' } : { action: 'save_new' };
    if (m === 'logins.save') return { id: p.id || 'new' };
    return {};
  };
  await send({ type: 'save.capture', username: 'typo@x.test', password: 'pw1', kind: 'login' }, sender('https://site.example/login'));
  const q = await send({ type: 'save.query' }, sender('https://site.example/home'));
  assert.equal(q.result.mode, 'save');
  const bad = await send({ type: 'save.commit', token: q.result.token, username: 'x'.repeat(600) }, sender('https://site.example/home'));
  assert.equal(bad.error.code, 'invalid_params');
  await send({ type: 'save.capture', username: 'typo@x.test', password: 'pw1', kind: 'login' }, sender('https://site.example/login'));
  const q2 = await send({ type: 'save.query' }, sender('https://site.example/home'));
  const done = await send({ type: 'save.commit', token: q2.result.token, username: ' right@x.test ', password: 'pw2' }, sender('https://site.example/home'));
  assert.equal(done.result.action, 'update_password');
  assert.deepEqual(lastCall('logins.save_check'), { url: 'https://site.example/login', username: 'right@x.test', password: 'pw2', kind: 'login' });
  assert.deepEqual(lastCall('logins.save'), { url: 'https://site.example/login', username: 'right@x.test', password: 'pw2', id: 'r' });
});

test('banner on another origin than the form: no password sent to it', async () => {
  const sender = (url) => ({ tab: { id: 28, url }, frameId: 0, url });
  agent = (m) => (m === 'logins.save_check' ? { action: 'save_new' } : {});
  await send({ type: 'save.capture', username: 'me', password: 'secret-pw', kind: 'signup' }, sender('https://accounts.example.com/signup'));
  const q = await send({ type: 'save.query' }, sender('https://www.example.com/welcome'));
  assert.equal(q.result.mode, 'save');
  assert.ok(!JSON.stringify(q).includes('secret-pw'));
});

// The save banner's edit frame (src/save/edit.html): an extension page inside the banner.

const EDIT_URL = 'chrome-extension://pass-ext/src/save/edit.html';
const editFrame = (tabId, tabUrl, extra = {}) => ({ url: EDIT_URL, tab: { id: tabId, url: tabUrl }, frameId: 4, ...extra });

async function bannerOn(tabId, formUrl, pageUrl, { username = 'me', password = 'secret-pw' } = {}) {
  const page = (url) => ({ tab: { id: tabId, url }, frameId: 0, url });
  await send({ type: 'save.capture', username, password, kind: 'login' }, page(formUrl));
  return (await send({ type: 'save.query' }, page(pageUrl))).result;
}

test('save.edit-get: only the edit page in a frame of that tab, with the banner\'s token; the password only on the form\'s origin', async () => {
  agent = (m) => {
    if (m === 'logins.save_check') return { action: 'save_new' };
    if (m === 'password.check') return CHECK;
    return {};
  };
  const q = await bannerOn(40, 'https://site.example/login', 'https://site.example/home');
  const ask = (sender, token = q.token) => send({ type: 'save.edit-get', token }, sender);
  const refused = [
    ['a content script', { tab: { id: 40, url: 'https://site.example/home' }, frameId: 0, url: 'https://site.example/home' }, 'no handler'],
    ['the popup', { url: 'chrome-extension://pass-ext/src/popup/popup.html', tab: { id: 40, url: 'https://site.example/home' }, frameId: 4 }],
    ['the unlock frame', { url: 'chrome-extension://pass-ext/src/unlock/frame.html', tab: { id: 40, url: 'https://site.example/home' }, frameId: 4 }],
    ['a look-alike path', { url: `${EDIT_URL}x`, tab: { id: 40, url: 'https://site.example/home' }, frameId: 4 }],
    ['the edit page opened as a tab of its own', editFrame(40, EDIT_URL, { frameId: 0 })],
    ['no tab', { url: EDIT_URL, frameId: 4 }],
    ['another tab', editFrame(41, 'https://site.example/home')],
  ];
  for (const [what, sender, expected = 'not_found'] of refused) {
    const res = await ask(sender);
    if (expected === 'no handler') assert.equal(res, undefined, `${what}: no such handler`);
    else assert.equal(res.error?.code, expected, what);
  }
  assert.equal((await ask(editFrame(40, 'https://site.example/home'), 'wrong')).error.code, 'not_found', 'another token');
  const same = await ask(editFrame(40, 'https://site.example/home'));
  assert.equal(same.result.username, 'me');
  assert.equal(same.result.password, 'secret-pw', 'the page it was typed into: the frame may show it');
  assert.equal(same.result.check.issues[0].code, 'common');
  await send({ type: 'save.dismiss' }, { tab: { id: 40, url: 'https://site.example/home' }, frameId: 0, url: 'https://site.example/home' });
  assert.equal((await ask(editFrame(40, 'https://site.example/home'))).error.code, 'not_found', 'gone after dismiss');

  // The banner on another origin than the form: no password, not even to the extension's frame.
  const other = await bannerOn(42, 'https://accounts.example.com/signup', 'https://www.example.com/welcome');
  const cross = await send({ type: 'save.edit-get', token: other.token }, editFrame(42, 'https://www.example.com/welcome'));
  assert.equal(cross.ok, true);
  assert.equal(cross.result.password, undefined);
  assert.ok(!JSON.stringify(cross).includes('secret-pw'));
  // Nothing comes back once the captured password's time is over (5 minutes).
  const realNow = Date.now;
  Date.now = () => realNow() + 6 * 60_000;
  try {
    assert.equal((await send({ type: 'save.edit-get', token: other.token }, editFrame(42, 'https://www.example.com/welcome'))).error.code, 'not_found');
  } finally {
    Date.now = realNow;
  }
});

test('save.edit-set stores the frame\'s edits for Save (token only), checks them; save.check without values follows them', async () => {
  agent = (m, p) => {
    if (m === 'logins.save_check') return p.username === 'right@x.test' ? { action: 'update_password', id: 'r', title: 'Right' } : { action: 'save_new' };
    if (m === 'logins.save') return { id: p.id || 'new' };
    if (m === 'password.check') return { score: 4, label: 'strong', vault_checked: true, issues: [] };
    return {};
  };
  const page = { tab: { id: 43, url: 'https://site.example/home' }, frameId: 0, url: 'https://site.example/home' };
  const q = await bannerOn(43, 'https://site.example/login', 'https://site.example/home', { username: 'typo@x.test', password: 'pw1' });
  const frame = editFrame(43, 'https://site.example/home');
  assert.equal((await send({ type: 'save.edit-set', token: 'wrong', username: 'a', password: 'b' }, frame)).error.code, 'not_found');
  assert.equal((await send({ type: 'save.edit-set', token: q.token, username: 'a' }, page)), undefined, 'not from the content script');
  assert.equal((await send({ type: 'save.edit-set', token: q.token, username: 'x'.repeat(600), password: '' }, frame)).error.code, 'invalid_params');
  const set = await send({ type: 'save.edit-set', token: q.token, username: ' right@x.test ', password: 'Pw-fixed-2' }, frame);
  assert.deepEqual(set.result, { check: { score: 4, label: 'strong', issues: [], vault_checked: true } });
  assert.deepEqual(lastCall('password.check'), { password: 'Pw-fixed-2', username: 'right@x.test', url: 'https://site.example/login' });
  // The banner's own check, folded away again: what Save would save now.
  await send({ type: 'save.check', token: q.token }, page);
  assert.equal(lastCall('password.check').password, 'Pw-fixed-2');
  const done = await send({ type: 'save.commit', token: q.token }, page);
  assert.equal(done.result.action, 'update_password');
  assert.deepEqual(lastCall('logins.save_check'), { url: 'https://site.example/login', username: 'right@x.test', password: 'Pw-fixed-2', kind: 'login' });
  assert.deepEqual(lastCall('logins.save'), { url: 'https://site.example/login', username: 'right@x.test', password: 'Pw-fixed-2', id: 'r' });

  // An empty password field keeps the captured one; save.edit-get starts over (the frame shows the capture).
  const q2 = await bannerOn(43, 'https://site.example/login', 'https://site.example/home', { username: 'typo@x.test', password: 'pw1' });
  await send({ type: 'save.edit-set', token: q2.token, username: 'right@x.test', password: '' }, frame);
  await send({ type: 'save.commit', token: q2.token }, page);
  assert.deepEqual(lastCall('logins.save'), { url: 'https://site.example/login', username: 'right@x.test', password: 'pw1', id: 'r' });
  const q3 = await bannerOn(43, 'https://site.example/login', 'https://site.example/home', { username: 'typo@x.test', password: 'pw1' });
  await send({ type: 'save.edit-set', token: q3.token, username: 'right@x.test', password: 'pw9' }, frame);
  await send({ type: 'save.edit-get', token: q3.token }, frame);
  await send({ type: 'save.commit', token: q3.token }, page);
  assert.deepEqual(lastCall('logins.save'), { url: 'https://site.example/login', username: 'typo@x.test', password: 'pw1' }, 'as captured');
});

test('popup.search: whole-vault search with 2+ characters; nothing reaches the agent otherwise', async () => {
  agent = (m) => (m === 'logins.search' ? { items: [{ id: 'gl', title: 'GitLab', username: 'me', domain: 'gitlab.com', has_totp: true }], truncated: false } : {});
  const before = callsOf('logins.search').length;
  const short = await send({ type: 'popup.search', query: ' g ' }, POPUP);
  assert.equal(short.error.code, 'invalid_params');
  assert.equal(callsOf('logins.search').length, before);
  const res = await send({ type: 'popup.search', query: ' git ' }, POPUP);
  assert.equal(res.result.items[0].id, 'gl');
  assert.deepEqual(lastCall('logins.search'), { query: 'git', limit: 20 });
  // With the popup's tab: its address goes along, so results whose site it imitates are marked.
  await send({ type: 'popup.search', query: 'git', tabId: 1 }, POPUP);
  assert.deepEqual(lastCall('logins.search'), { query: 'git', limit: 20, url: 'https://github.com/login' });
  tabsById.set(45, { id: 45, url: 'chrome://settings', active: false });
  await send({ type: 'popup.search', query: 'git', tabId: 45 }, POPUP);
  assert.deepEqual(lastCall('logins.search'), { query: 'git', limit: 20 }, 'not a web page: no address');
  tabsById.delete(45);
  const fromPage = await send({ type: 'popup.search', query: 'git' }, contentSender('https://github.com/'));
  assert.equal(fromPage, undefined, 'popup only');
});

test('popup.copy-item on a page that looks like the login\'s site: the password or code only after a yes', async () => {
  agent = (m, p) => (m === 'logins.copy' ? { copied: true, field: p.field } : {});
  // The question opens the popup (the browser's action popup) and waits for its answer.
  chrome.action.openPopup = async () => {};
  const copies = () => callsOf('logins.copy').length;
  const before = copies();
  const copying = send({ type: 'popup.copy-item', tabId: 1, id: 'gl', field: 'password', lookalike: 'gitlab.com', title: 'GitLab' }, POPUP);
  await new Promise((r) => setTimeout(r, 10));
  assert.equal(copies(), before, 'nothing copied before the answer');
  const ask = (await send({ type: 'popup.ask-get' }, POPUP)).result;
  assert.equal(ask.kind, 'lookalike');
  assert.equal(ask.lookalike, 'gitlab.com');
  assert.equal(ask.host, 'github.com');
  await send({ type: 'popup.ask-answer', token: ask.token, yes: true }, POPUP);
  assert.deepEqual((await copying).result, { copied: true, field: 'password' });
  assert.equal(copies(), before + 1);

  const cancelled = send({ type: 'popup.copy-item', tabId: 1, id: 'gl', field: 'totp', lookalike: { domain: 'gitlab.com' } }, POPUP);
  await new Promise((r) => setTimeout(r, 10));
  const ask2 = (await send({ type: 'popup.ask-get' }, POPUP)).result;
  await send({ type: 'popup.ask-answer', token: ask2.token, cancel: true }, POPUP);
  assert.equal((await cancelled).error.code, 'cancelled');
  assert.equal(copies(), before + 1);

  // A username isn't a secret: no question.
  const user = await send({ type: 'popup.copy-item', tabId: 1, id: 'gl', field: 'username', lookalike: 'gitlab.com' }, POPUP);
  assert.deepEqual(user.result, { copied: true, field: 'username' });
  assert.equal((await send({ type: 'popup.ask-get' }, POPUP)).result, null);
  delete chrome.action.openPopup;
});

test('save banner: a new login on a page that looks like one of the user\'s sites carries the warning', async () => {
  agent = (m) => (m === 'logins.save_check'
    ? { action: 'save_new', lookalike: { domain: 'paypal.com', host: 'paypa1.example', reason: 'homograph' } }
    : {});
  const info = await bannerOn(46, 'https://paypa1.example/login', 'https://paypa1.example/home');
  assert.equal(info.mode, 'save');
  assert.equal(info.lookalike, 'paypal.com');
  await send({ type: 'save.dismiss' }, { tab: { id: 46, url: 'https://paypa1.example/home' }, frameId: 0, url: 'https://paypa1.example/home' });
  agent = (m) => (m === 'logins.save_check' ? { action: 'save_new' } : {});
  const plain = await bannerOn(47, 'https://news.example/login', 'https://news.example/home');
  assert.equal(plain.lookalike, undefined);
});

test('popup.search with an older desktop app: not_supported', async () => {
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method logins.search' } });
  const res = await send({ type: 'popup.search', query: 'git' }, POPUP);
  assert.equal(res.error.code, 'not_supported');
});

test('popup.copy-item: the agent copies; the value never comes back to the extension', async () => {
  agent = (m) => (m === 'logins.copy' ? { copied: true, field: 'password' } : {});
  const res = await send({ type: 'popup.copy-item', tabId: 1, id: 'gl', field: 'password' }, POPUP);
  assert.deepEqual(res.result, { copied: true, field: 'password' });
  assert.deepEqual(lastCall('logins.copy'), { id: 'gl', field: 'password', url: 'https://github.com/login' });
  const bad = await send({ type: 'popup.copy-item', tabId: 1, id: 'gl', field: 'notes' }, POPUP);
  assert.equal(bad.error.code, 'invalid_params');
});

test('popup.copy-item for the tab\'s own login (own): the agent copies; a copied password counts as a fill of it', async () => {
  tabsById.set(44, { id: 44, url: 'https://own.example/login', active: false });
  agent = (m, p) => {
    if (m === 'logins.copy') return { copied: true, field: p.field };
    if (m === 'logins.save_check') return { action: 'save_new' };
    return {};
  };
  const res = await send({ type: 'popup.copy-item', tabId: 44, id: 'own1', field: 'password', own: true }, POPUP);
  assert.deepEqual(res.result, { copied: true, field: 'password' });
  assert.deepEqual(lastCall('logins.copy'), { id: 'own1', field: 'password', url: 'https://own.example/login' });
  // Like popup.copy: the next save of this tab names the login that was just used.
  const page = { tab: tabsById.get(44), frameId: 0, url: 'https://own.example/login' };
  await send({ type: 'save.capture', username: 'me', password: 'pw', kind: 'login' }, page);
  await send({ type: 'save.query' }, page);
  assert.equal(lastCall('logins.save_check').filled_id, 'own1');
  await send({ type: 'save.dismiss' }, page);
  const code = await send({ type: 'popup.copy-item', tabId: 44, id: 'own1', field: 'totp', own: true }, POPUP);
  assert.deepEqual(code.result, { copied: true, field: 'totp' });
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method logins.copy' } });
  const old = await send({ type: 'popup.copy-item', tabId: 44, id: 'own1', field: 'password', own: true }, POPUP);
  assert.equal(old.error.code, 'not_supported', 'an older desktop app: the popup copies the old way');
  tabsById.delete(44);
});

test('totp.copy (the OTP toast\'s Copy): the agent copies the code for the asking frame\'s own URL; never the value back', async () => {
  agent = (m, p) => (m === 'logins.copy' ? { copied: true, field: p.field } : {});
  const res = await send({ type: 'totp.copy', id: 'gh', url: 'https://evil.example/' },
    contentSender('https://accounts.example.com/2fa', { frameId: 6 }));
  assert.deepEqual(res.result, { copied: true, field: 'totp' });
  assert.deepEqual(lastCall('logins.copy'), { id: 'gh', field: 'totp', url: 'https://accounts.example.com/2fa' });
  const before = callsOf('logins.copy').length;
  assert.equal((await send({ type: 'totp.copy', id: '' }, contentSender('https://github.com/'))).error.code, 'invalid_params');
  assert.equal((await send({ type: 'totp.copy', id: 'gh' }, contentSender('file:///C:/x.html'))).ok, false);
  assert.equal(callsOf('logins.copy').length, before, 'nothing reached the agent');
  assert.equal(await send({ type: 'totp.copy', id: 'gh' }, POPUP), undefined, 'content scripts only');
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method logins.copy' } });
  assert.equal((await send({ type: 'totp.copy', id: 'gh' }, contentSender('https://github.com/'))).error.code, 'not_supported');
});

test('popup.fill-cross: the frame asks the agent itself, once, for exactly that login', async () => {
  tabsById.set(30, { id: 30, url: 'https://new-site.example/login', active: false });
  agent = (m) => (m === 'logins.fill_cross' ? { username: 'me', password: 'pw', totp: null, cross: true } : {});
  const frame = (url, frameId = 0) => ({ tab: { id: 30 }, frameId, url });
  // Without the popup's request, a page can't ask.
  const unasked = await send({ type: 'logins.fill_cross', id: 'gl' }, frame('https://new-site.example/login'));
  assert.equal(unasked.error.code, 'not_found');
  assert.equal(unasked.error.reason, 'pick_in_popup', 'shown as "pick the login in the popup first"');
  const before = tabMessages.length;
  const res = await send({ type: 'popup.fill-cross', tabId: 30, id: 'gl' }, POPUP);
  assert.equal(res.ok, true);
  assert.deepEqual(tabMessages.slice(before).map(([t, m]) => [t, m]), [[30, { type: 'cmd.fill-cross', id: 'gl' }]]);
  const other = await send({ type: 'logins.fill_cross', id: 'other' }, frame('https://new-site.example/login'));
  assert.equal(other.ok, false, 'another id: refused (and the request is used up)');
  await send({ type: 'popup.fill-cross', tabId: 30, id: 'gl' }, POPUP);
  const filled = await send({ type: 'logins.fill_cross', id: 'gl', url: 'https://evil.test/' }, frame('https://login.new-site.example/frame', 2));
  assert.equal(filled.result.cross, true);
  assert.deepEqual(lastCall('logins.fill_cross'), { url: 'https://login.new-site.example/frame', id: 'gl' });
  const replay = await send({ type: 'logins.fill_cross', id: 'gl' }, frame('https://new-site.example/login'));
  assert.equal(replay.ok, false, 'one fill per request');
});

test('popup.icons for search results: by ids, never a URL', async () => {
  agent = (m) => (m === 'icons.get' ? { icons: {}, items: {} } : {});
  await send({ type: 'popup.icons', ids: ['a', 'b'] }, POPUP);
  assert.deepEqual(lastCall('icons.get'), { ids: ['a', 'b'] });
});

// Soft lock: the list stays, secrets unlock first.

/** A soft-locked agent: lists from the kept list, `locked` for secrets until `unlock`. */
function softLockedAgent(extra = {}) {
  const state = { locked: true, unlocks: 0 };
  agent = (m, p) => {
    if (m === 'status') return { locked: state.locked, soft_locked: state.locked, version: '1', features: ['edit', 'locked.list'] };
    if (m === 'logins.find') return { items: [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }], pending_otp: null, locked: state.locked };
    if (m === 'unlock') { state.unlocks += 1; state.locked = false; return { locked: false }; }
    if (state.locked) return { __error: { code: 'locked', message: 'Vault is locked' } };
    if (m in extra) return extra[m](p);
    return {};
  };
  return state;
}

test('popup.state lists the logins of a soft-locked vault', async () => {
  softLockedAgent();
  const res = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(res.result.locked, true);
  assert.equal(res.result.soft_locked, true);
  assert.deepEqual(res.result.items.map((i) => i.id), ['gh']);
  assert.equal(res.result.can_edit, true);
  // Fully locked (or an older desktop app): nothing to list; the quick actions say what the app can do.
  agent = (m) => (m === 'status' ? { locked: true, version: '1' } : { __error: { code: 'locked', message: 'Vault is locked' } });
  const full = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.deepEqual(full.result, { url: 'https://github.com/login', supported: true, locked: true, can_edit: false, can_notes: false,
    can_unlock_inline: false, unlock_hello: false, unlock_hello_auto: false, unlock_hello_pending: false, ask_unlock: false });
  agent = (m) => (m === 'status' ? { locked: true, version: '1', features: ['edit', 'notes.create', 'unlock.inline'] }
    : m === 'unlock.options' ? { hello: false } : { __error: { code: 'locked', message: 'Vault is locked' } });
  const withNotes = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(withNotes.result.can_edit, true);
  assert.equal(withNotes.result.can_notes, true);
});

test('a soft-locked fill, copy or 2FA code unlocks first and then completes in one go', async () => {
  const state = softLockedAgent({
    'logins.fill': () => ({ username: 'octo', password: 'pw', totp: null }),
    'totp.get': () => ({ id: 'gh', title: 'GitHub', code: '123456', period: 30, remaining_secs: 20 }),
  });
  const fill = await send({ type: 'logins.fill', id: 'gh' }, contentSender('https://github.com/login'));
  assert.equal(fill.result.password, 'pw');
  assert.equal(state.unlocks, 1);

  state.locked = true;
  const code = await send({ type: 'popup.totp', tabId: 1, id: 'gh' }, popupSender);
  assert.equal(code.result.code, '123456');
  assert.equal(state.unlocks, 2);

  state.locked = true;
  const inline = await send({ type: 'totp.get', id: 'gh' }, contentSender('https://github.com/login'));
  assert.equal(inline.result.code, '123456');
  assert.equal(state.unlocks, 3);

  state.locked = true;
  const copy = await send({ type: 'popup.copy', tabId: 1, id: 'gh', field: 'password' }, popupSender);
  assert.equal(copy.result.value, 'pw');
  assert.equal(state.unlocks, 4);

  // The pending code after a fill (no id) never pops up an unlock window on its own.
  state.locked = true;
  const pending = await send({ type: 'totp.get' }, contentSender('https://github.com/login'));
  assert.equal(pending.error.code, 'locked');
  assert.equal(state.unlocks, 4);
});

const CARD = { cardholder_name: 'Ada Lovelace', number: '4242424242424242', expiry_month: 4, expiry_year: 2029, security_code: '737', brand: 'visa' };
const formsAgent = (extra = {}) => (m, p) => {
  if (m === 'status') return { locked: false, version: '1', features: ['edit', 'cards', 'identities'] };
  if (m === 'cards.list') return { items: [{ id: 'visa', title: 'Visa •••• 4242', brand: 'visa', last4: '4242', expiry_month: 4, expiry_year: 2029, cardholder_name: 'Ada' }], locked: false };
  if (m === 'identities.list') return { items: [{ id: 'home', title: 'Home', full_name: 'Ada Lovelace', email: 'ada@example.org', company: '' }], locked: false };
  if (m === 'cards.fill') return CARD;
  if (m === 'identities.fill') return { full_name: 'Ada Lovelace', email: 'ada@example.org', phone: '+44', address1: '12 Square', address2: '', address3: '', postal_code: 'SW1', city: 'London', region: '', country: 'GB' };
  return extra[m] ? extra[m](p) : {};
};

test('forms.features: what the desktop app has (status.features), for content scripts', async () => {
  agent = formsAgent();
  const res = await send({ type: 'forms.features' }, contentSender('https://shop.example/checkout'));
  assert.deepEqual(res.result, { cards: true, identities: true });
});

test('cards.fill from a cross-origin payment frame: that frame\'s own URL, the tab page only as top_url; the answer goes to that frame alone', async () => {
  agent = formsAgent();
  tabMessages.length = 0;
  const sender = contentSender('https://js.stripe.com/v3/elements-inner-card.html', { frameId: 9, origin: 'https://js.stripe.com' });
  sender.tab = { ...tabsById.get(1), url: 'https://shop.example/checkout' };
  const res = await send({ type: 'cards.fill', id: 'visa', url: 'https://evil.example/' }, sender);
  assert.deepEqual(res, { ok: true, result: CARD });
  assert.deepEqual(lastCall('cards.fill'), { url: 'https://js.stripe.com/v3/elements-inner-card.html', id: 'visa', top_url: 'https://shop.example/checkout' });
  assert.equal(tabMessages.length, 0, 'no other frame hears of it');
  // The top frame itself: no top_url.
  await send({ type: 'cards.fill', id: 'visa' }, contentSender('https://shop.example/checkout'));
  assert.deepEqual(lastCall('cards.fill'), { url: 'https://shop.example/checkout', id: 'visa' });
});

test('cards and identities: insecure pages, opaque frames and bad ids never reach the agent', async () => {
  agent = formsAgent();
  const before = calls.length;
  for (const [type, url, extra] of [
    ['cards.fill', 'http://shop.example/checkout', {}],
    ['cards.list', 'http://shop.example/checkout', {}],
    ['identities.fill', 'file:///C:/form.html', {}],
    ['cards.fill', 'https://shop.example/', { origin: 'null' }],
  ]) {
    const res = await send({ type, id: 'visa' }, contentSender(url, extra));
    assert.equal(res.ok, false, `${type} ${url}`);
  }
  assert.equal((await send({ type: 'cards.fill', id: 42 }, contentSender('https://shop.example/'))).error.code, 'invalid_params');
  assert.equal(calls.length, before);
  // http on this device is fine.
  const local = await send({ type: 'identities.list' }, contentSender('http://localhost:8080/checkout'));
  assert.equal(local.ok, true);
});

test('cards and identities: content-script and popup handlers stay apart', async () => {
  agent = formsAgent();
  assert.equal(await send({ type: 'popup.card-copy', tabId: 1, id: 'visa', field: 'number' }, contentSender('https://shop.example/')), undefined);
  assert.equal(await send({ type: 'popup.forms', tabId: 1 }, contentSender('https://shop.example/')), undefined);
  assert.equal(await send({ type: 'cards.fill', id: 'visa' }, popupSender), undefined, 'the popup copies through popup.card-copy only');
});

test('"Offer cards and addresses" off: no features, and card requests are refused', async () => {
  agent = formsAgent();
  const get = chrome.storage.local.get;
  chrome.storage.local.get = async () => ({ formFill: false });
  try {
    assert.deepEqual((await send({ type: 'forms.features' }, contentSender('https://shop.example/'))).result, { cards: false, identities: false });
    const before = calls.length;
    const off = (await send({ type: 'cards.list' }, contentSender('https://shop.example/'))).error;
    // not_supported (the menu closes quietly); the reason says why when it is shown.
    assert.deepEqual([off.code, off.reason], ['not_supported', 'forms_off']);
    assert.equal(calls.length, before);
  } finally {
    chrome.storage.local.get = get;
  }
});

test('cards with an older desktop app (unknown method): not_supported', async () => {
  agent = (m) => (m === 'cards.list' ? { __error: { code: 'invalid_params', message: 'unknown method cards.list' } } : {});
  const res = await send({ type: 'cards.list' }, contentSender('https://shop.example/'));
  assert.equal(res.error.code, 'not_supported');
});

test('a locked vault: picking a card unlocks first, then fills', async () => {
  let locked = true;
  let unlocks = 0;
  agent = (m) => {
    if (m === 'unlock') { unlocks++; locked = false; return { locked: false }; }
    if (m === 'cards.fill') return locked ? { __error: { code: 'locked', message: 'Vault is locked' } } : CARD;
    return {};
  };
  const res = await send({ type: 'cards.fill', id: 'visa' }, contentSender('https://shop.example/'));
  assert.equal(res.result.number, CARD.number);
  assert.equal(unlocks, 1);
});

test('popup.state advertises cards and addresses on secure pages only', async () => {
  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['cards', 'identities'] } : { items: [], pending_otp: null });
  const res = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(res.result.can_cards, true);
  assert.equal(res.result.can_identities, true);
  tabsById.set(2, { id: 2, url: 'http://intranet.example/', active: false });
  const insecure = await send({ type: 'popup.state', tabId: 2 }, popupSender);
  assert.equal(insecure.result.can_cards, false);
  tabsById.delete(2);
});

test('popup.forms lists cards and identities for the tab page; popup.card-copy returns only the asked value', async () => {
  tabsById.set(3, { id: 3, url: 'https://shop.example/checkout', active: true });
  agent = formsAgent();
  const lists = await send({ type: 'popup.forms', tabId: 3 }, popupSender);
  assert.deepEqual(lists.result.cards.map((c) => c.id), ['visa']);
  assert.deepEqual(lists.result.identities.map((i) => i.id), ['home']);
  assert.equal(lastCall('cards.list').url, 'https://shop.example/checkout');

  // An older desktop app ignores `field` and answers the card: only the asked value goes to the popup.
  const number = await send({ type: 'popup.card-copy', tabId: 3, id: 'visa', field: 'number', url: 'https://evil.example/' }, popupSender);
  assert.deepEqual(number.result, { value: '4242424242424242' });
  assert.deepEqual(lastCall('cards.fill'), { url: 'https://shop.example/checkout', id: 'visa', purpose: 'copy', field: 'number' });
  const cvv = await send({ type: 'popup.card-copy', tabId: 3, id: 'visa', field: 'security_code' }, popupSender);
  assert.deepEqual(cvv.result, { value: '737' });
  assert.equal((await send({ type: 'popup.card-copy', tabId: 3, id: 'visa', field: 'pin' }, popupSender)).error.code, 'invalid_params');
  const address = await send({ type: 'popup.identity-copy', tabId: 3, id: 'home', field: 'address' }, popupSender);
  assert.deepEqual(address.result, { value: '12 Square, SW1 London, GB' });

  // Not a secure page: nothing listed, nothing copied.
  tabsById.set(3, { id: 3, url: 'http://shop.example/checkout', active: true });
  assert.deepEqual((await send({ type: 'popup.forms', tabId: 3 }, popupSender)).result, { cards: [], identities: [], locked: false });
  assert.equal((await send({ type: 'popup.card-copy', tabId: 3, id: 'visa', field: 'number' }, popupSender)).ok, false);
  tabsById.delete(3);
});

test('popup.card-copy: a desktop app that copies the card value itself answers copied; no card value reaches the popup', async () => {
  tabsById.set(3, { id: 3, url: 'https://shop.example/checkout', active: true });
  agent = formsAgent();
  const plain = agent;
  agent = (m, p) => (m === 'cards.fill' ? { copied: true, field: p.field, number: 'leak?' } : plain(m, p));
  for (const field of ['number', 'security_code']) {
    const res = await send({ type: 'popup.card-copy', tabId: 3, id: 'visa', field }, popupSender);
    assert.deepEqual(res.result, { copied: true }, 'only that it was copied');
    assert.deepEqual(lastCall('cards.fill'), { url: 'https://shop.example/checkout', id: 'visa', purpose: 'copy', field });
  }
  tabsById.delete(3);
});

test('nothing card-related is written to extension storage', async () => {
  const before = storageWrites.length;
  agent = formsAgent();
  await send({ type: 'cards.fill', id: 'visa' }, contentSender('https://shop.example/'));
  await send({ type: 'identities.fill', id: 'home' }, contentSender('https://shop.example/'));
  assert.ok(!JSON.stringify(storageWrites.slice(before)).includes('4242'));
});

// Password check (password.check): codes only, through the background.

const CHECK = { score: 0, label: 'very_weak', entropy_bits: 9.2, vault_checked: true,
  issues: [{ code: 'common', severity: 'high' }, { code: 'reused', severity: 'high', count: 2 }, { code: 'contains_site', severity: 'medium', name: 'github' }] };

test('save.query carries the password check of the captured password (codes only); save.check rechecks edits by token', async () => {
  agent = (m) => {
    if (m === 'logins.save_check') return { action: 'update_password', id: 'gh', title: 'GitHub' };
    if (m === 'password.check') return { ...CHECK, password: 'leaked?' };
    return {};
  };
  await send({ type: 'save.capture', username: 'octo', password: 'github123', kind: 'login' }, contentSender('https://github.com/session'));
  const q = await send({ type: 'save.query' }, contentSender('https://github.com/'));
  assert.deepEqual(lastCall('password.check'), { password: 'github123', username: 'octo', url: 'https://github.com/session', id: 'gh' },
    'the login being updated is named, so its own password is not "reused"');
  assert.deepEqual(q.result.check, { score: 0, label: 'very_weak', vault_checked: true,
    issues: [{ code: 'common', severity: 'high' }, { code: 'reused', severity: 'high', count: 2 }, { code: 'contains_site', severity: 'medium' }] });
  assert.ok(!JSON.stringify(q.result.check).includes('leaked'), 'only the known fields');

  const wrong = await send({ type: 'save.check', token: 'nope', password: 'other' }, contentSender('https://github.com/'));
  assert.equal(wrong.result, null, 'another token: nothing checked');
  const frame = await send({ type: 'save.check', token: q.result.token, password: 'other' }, contentSender('https://github.com/', { frameId: 3 }));
  assert.equal(frame.result, null, 'sub-frames: nothing checked');
  const edited = await send({ type: 'save.check', token: q.result.token, username: 'octo2', password: 'Edited-Pass-9!' }, contentSender('https://github.com/'));
  assert.equal(edited.ok, true);
  assert.deepEqual(lastCall('password.check'), { password: 'Edited-Pass-9!', username: 'octo2', url: 'https://github.com/session', id: 'gh' });
  const kept = await send({ type: 'save.check', token: q.result.token, username: 'octo' }, contentSender('https://github.com/'));
  assert.equal(kept.ok, true);
  assert.equal(lastCall('password.check').password, 'github123', 'no password typed: the captured one');
  await send({ type: 'save.dismiss' }, contentSender('https://github.com/'));
  assert.equal((await send({ type: 'save.check', token: q.result.token }, contentSender('https://github.com/'))).result, null, 'gone after dismiss');
});

test('save.query: an older desktop app without password.check still offers the banner, with no check', async () => {
  agent = (m) => {
    if (m === 'logins.save_check') return { action: 'save_new' };
    if (m === 'password.check') return { __error: { code: 'invalid_params', message: 'unknown method password.check' } };
    return {};
  };
  await send({ type: 'save.capture', username: 'octo', password: 'pw-123', kind: 'login' }, contentSender('https://github.com/session'));
  const q = await send({ type: 'save.query' }, contentSender('https://github.com/'));
  assert.equal(q.result.mode, 'save');
  assert.equal(q.result.check, null);
  await send({ type: 'save.dismiss' }, contentSender('https://github.com/'));
});

test('popup.password-check: the tab URL from tabs.get, the edited login id; not reachable from content scripts', async () => {
  agent = (m) => (m === 'password.check' ? CHECK : {});
  const popup = { url: 'chrome-extension://pass-ext/src/popup/popup.html' };
  const res = await send({ type: 'popup.password-check', tabId: 1, password: 'hunter2', username: 'octo', title: 'GitHub', id: 'gh', url: 'https://evil.test/' }, popup);
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('password.check'), { password: 'hunter2', username: 'octo', url: 'https://github.com/login', id: 'gh', title: 'GitHub' });
  assert.equal(res.result.issues.length, 3);
  const before = calls.length;
  assert.equal(await send({ type: 'popup.password-check', tabId: 1, password: 'x' }, contentSender('https://github.com/')), undefined);
  assert.equal(await send({ type: 'password.check', password: 'x' }, contentSender('https://github.com/')), undefined);
  assert.equal(await send({ type: 'password.check', password: 'x' }, popup), undefined, 'no raw agent method for pages either');
  assert.equal(calls.length, before, 'nothing reached the agent');
  const empty = await send({ type: 'popup.password-check', tabId: 1, password: '' }, popup);
  assert.equal(empty.result, null);
  assert.equal(calls.length, before, 'an empty password is not sent');
});

test("passkey.create_options: the origin from the browser and the request's names; never an unlock", async () => {
  agent = (m) => (m === 'passkey.create_options' ? { rp_id: 'example.com', locked: false, excluded: false, candidates: [], suggested: null, vault: null } : {});
  let res = await send({ type: 'passkey.create_options', options: { rpId: 'example.com', userName: 'alice', excludeCredentials: [{ id: 'AQE' }], challenge: 'AQID' }, origin: 'https://evil.test' },
    contentSender('https://login.example.com/signup', { origin: 'https://login.example.com' }));
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('passkey.create_options'), { origin: 'https://login.example.com', rpId: 'example.com', userName: 'alice', excludeCredentials: [{ id: 'AQE' }] });
  agent = (m) => (m === 'unlock' ? { locked: false } : { __error: { code: 'locked', message: 'Vault is locked' } });
  const before = calls.length;
  res = await send({ type: 'passkey.create_options', options: { rpId: 'example.com' } }, contentSender('https://example.com/'));
  assert.equal(res.error.code, 'locked');
  assert.deepEqual(calls.slice(before).map((c) => c[0]), ['passkey.create_options']);
  agent = () => ({ __error: { code: 'invalid_params', message: 'unknown method passkey.create_options' } });
  res = await send({ type: 'passkey.create_options', options: {} }, contentSender('https://example.com/'));
  assert.equal(res.error.code, 'not_supported', 'an older desktop app');
});

test('passkey.create saved in the card carries the consent; a choice made in the page never opens the unlock window', async () => {
  const CREATE = { rp: { id: 'example.com', name: 'Example' }, user: { id: 'AQID', name: 'alice' }, challenge: 'AQID', pubKeyCredParams: [{ type: 'public-key', alg: -7 }] };
  agent = (m) => (m === 'passkey.create' ? { credentialId: 'AQ' } : {});
  let res = await send({ type: 'passkey.create', inPage: true, userActivated: true, consent: { itemId: 'login-1' }, options: CREATE }, contentSender('https://example.com/'));
  assert.equal(res.ok, true);
  assert.deepEqual(lastCall('passkey.create').consent, { itemId: 'login-1' });
  await send({ type: 'passkey.create', inPage: true, userActivated: true, consent: { itemId: 7 }, options: CREATE }, contentSender('https://example.com/'));
  assert.deepEqual(lastCall('passkey.create').consent, { itemId: null }, 'not an item id: a new login');
  // Only from the card (`inPage`): a page's message can't carry consent through bridge.js anyway.
  await send({ type: 'passkey.create', userActivated: true, consent: { itemId: 'login-1' }, options: CREATE }, contentSender('https://example.com/'));
  assert.equal('consent' in lastCall('passkey.create'), false);

  // Locked meanwhile: `locked` back to the card (it unlocks in the page), with a desktop app that can.
  agent = (m) => {
    if (m === 'status') return { locked: true, features: ['unlock.inline'] };
    if (m === 'unlock') return { locked: false };
    return { __error: { code: 'locked', message: 'Vault is locked' } };
  };
  let before = calls.length;
  res = await send({ type: 'passkey.get', inPage: true, userActivated: true, id: 'item-1', options: { rpId: 'example.com', challenge: 'AQID' } }, contentSender('https://example.com/'));
  assert.equal(res.error.code, 'locked');
  assert.ok(!calls.slice(before).some((c) => c[0] === 'unlock'), 'no desktop unlock window');
  // An older desktop app without the in-page unlock: its own unlock window.
  agent = (m) => {
    if (m === 'status') return { locked: true, features: [] };
    if (m === 'unlock') return { locked: false };
    return { __error: { code: 'locked', message: 'Vault is locked' } };
  };
  before = calls.length;
  await send({ type: 'passkey.get', inPage: true, userActivated: true, id: 'item-1', options: { rpId: 'example.com', challenge: 'AQID' } }, contentSender('https://example.com/'));
  assert.ok(calls.slice(before).some((c) => c[0] === 'unlock'));
});

test('shortcuts: Scan QR without openPopup says to click the toolbar, and that popup starts the scan once', async () => {
  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['edit', 'notes.create'] } : { items: [], pending_otp: null });
  const onCommand = globalThis.chrome.commands.onCommand.fns[0];
  const before = tabMessages.length;
  onCommand('scan-qr', tabsById.get(1));
  await new Promise((r) => setTimeout(r, 20));
  const notices = tabMessages.slice(before).filter(([, msg]) => msg.type === 'cmd.notice');
  assert.deepEqual(notices, [[1, { type: 'cmd.notice', text: 'To go on, click Passyble in the browser toolbar.' }, { frameId: 0 }]]);
  assert.equal(captures.length, 0, 'the background takes no screenshot');
  const res = await send({ type: 'popup.state', tabId: 1 }, popupSender);
  assert.equal(res.result.quick_action, 'scan');
  assert.equal((await send({ type: 'popup.state', tabId: 1 }, popupSender)).result.quick_action, undefined, 'once');
});

test('shortcuts: Generate goes to the focused field (the site\'s choice); Lock asks the desktop app to lock', async () => {
  agent = (m) => (m === 'lock' ? { locked: true } : m === 'status' ? { locked: false, version: '1', features: [] } : {});
  const onCommand = globalThis.chrome.commands.onCommand.fns[0];
  const before = tabMessages.length;
  onCommand('generate-password', tabsById.get(1));
  await new Promise((r) => setTimeout(r, 20));
  const sent = tabMessages.slice(before).map(([tabId, msg]) => [tabId, msg]);
  assert.deepEqual(sent, [[1, { type: 'cmd.generate-here', focused: true }]], 'the page filled it: nothing copied, no notice');
  const locks = calls.filter((c) => c[0] === 'lock').length;
  onCommand('lock', tabsById.get(1));
  await new Promise((r) => setTimeout(r, 20));
  assert.equal(calls.filter((c) => c[0] === 'lock').length, locks + 1);
  assert.ok(tabMessages.some(([, msg]) => msg.type === 'cmd.notice' && msg.text === 'Passyble is locked.'));
});

test('website rules: popup.state says url_rules; edit-save passes url_rules checked; popup.rule-hint asks sites.rule_hint (popup only)', async () => {
  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['edit', 'url_rules'] }
    : m === 'sites.rule_hint' ? { suggested: 'host' } : m === 'logins.update' ? { id: 'gh' } : { items: [], pending_otp: null });
  assert.equal((await send({ type: 'popup.state', tabId: 1 }, popupSender)).result.can_url_rules, true);
  const url_rules = [{ url: 'alice.github.io', rule: 'host', extra: 1 }, { url: 'https://github.com', rule: 'never' }];
  await send({ type: 'popup.edit-save', tabId: 1, id: 'gh', fields: { urls: ['alice.github.io', 'https://github.com'], url_rules } }, popupSender);
  assert.deepEqual(lastCall('logins.update').fields.url_rules, [{ url: 'alice.github.io', rule: 'host' }, { url: 'https://github.com', rule: 'never' }]);
  const before = calls.length;
  for (const bad of [{ url_rules: 'host' }, { url_rules: [{ url: 'a.com', rule: 'always' }] }, { url_rules: [{ rule: 'host' }] },
    { url_rules: Array(33).fill({ url: 'a.com', rule: 'host' }) }]) {
    const res = await send({ type: 'popup.edit-save', tabId: 1, id: 'gh', fields: bad }, popupSender);
    assert.equal(res.error.code, 'invalid_params', JSON.stringify(bad).slice(0, 40));
  }
  assert.equal(calls.length, before, 'refused before reaching the agent');

  const hint = await send({ type: 'popup.rule-hint', url: ' alice.github.io ' }, popupSender);
  assert.deepEqual(hint, { ok: true, result: { suggested: 'host' } });
  assert.deepEqual(lastCall('sites.rule_hint'), { url: 'alice.github.io' });
  assert.equal((await send({ type: 'popup.rule-hint', url: '' }, popupSender)).error.code, 'invalid_params');
  assert.equal(await send({ type: 'popup.rule-hint', url: 'a.com' }, contentSender('https://github.com/')), undefined);
  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['edit'] } : { items: [], pending_otp: null });
  assert.equal((await send({ type: 'popup.state', tabId: 1 }, popupSender)).result.can_url_rules, false);
});

test('popular sites: popup.state says sites.suggest; popup.site-suggest and popup.site-name ask the agent (popup only, checked)', async () => {
  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['edit', 'sites.suggest'] }
    : m === 'sites.suggest' ? { sites: [{ name: 'GitHub', domain: 'github.com' }] } : m === 'sites.name_for' ? { name: 'GitHub' }
      : { items: [], pending_otp: null });
  assert.equal((await send({ type: 'popup.state', tabId: 1 }, popupSender)).result.can_sites, true);
  assert.deepEqual((await send({ type: 'popup.site-suggest', query: ' git ' }, popupSender)).result, { sites: [{ name: 'GitHub', domain: 'github.com' }] });
  assert.deepEqual(lastCall('sites.suggest'), { query: 'git', limit: 6 });
  assert.deepEqual((await send({ type: 'popup.site-name', url: 'https://github.com' }, popupSender)).result, { name: 'GitHub' });
  assert.deepEqual(lastCall('sites.name_for'), { url: 'https://github.com' });
  const before = calls.length;
  assert.equal((await send({ type: 'popup.site-suggest', query: 'x'.repeat(257) }, popupSender)).error.code, 'invalid_params');
  assert.equal((await send({ type: 'popup.site-name', url: 42 }, popupSender)).error.code, 'invalid_params');
  assert.equal(await send({ type: 'popup.site-suggest', query: 'git' }, contentSender('https://github.com/')), undefined);
  assert.equal(calls.length, before);
  agent = (m) => (m === 'status' ? { locked: false, version: '1', features: ['edit'] } : { items: [], pending_otp: null });
  assert.equal((await send({ type: 'popup.state', tabId: 1 }, popupSender)).result.can_sites, false);
});
