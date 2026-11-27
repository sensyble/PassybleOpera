// End-to-end test of passkeys: real Chromium, the real extension and local pages that register and sign in like real
// sites through a SimpleWebAuthn-style client (passkey-client.js); webauthn-rp.mjs verifies every response.
// The authenticator is the real desktop agent's test harness when built (`cargo build -p pass-agent --example e2e_agent`
// in ../Core, or PASS_E2E_AGENT=<binary>), else the mock agent. The browser's own WebAuthn never reaches the platform:
// every page gets a stand-in for it, behind it a CDP virtual authenticator, and the browser runs with
// --disable-features=WebAuthenticationUseNativeWinApi, so no Windows Security passkey dialog can open.
// Opt-in: npm run test:e2e (HEADED=1 to watch, BROWSER=<path> for e.g. Brave, PASSKEY_SHOTS=<dir> for screenshots).
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { spawn } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { MockAgent } from './mock-agent.mjs';
import { RelyingParty, b64u } from './webauthn-rp.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const extRoot = path.resolve(here, '..', '..');
const repoRoot = path.resolve(extRoot, '..');
const CLIENT_JS = readFileSync(path.join(here, 'passkey-client.js'), 'utf8');

async function loadPlaywright() {
  if (process.env.PLAYWRIGHT_DIR) return createRequire(path.join(process.env.PLAYWRIGHT_DIR, 'x.js'))('./index.js');
  try { return await import('playwright'); } catch { return null; }
}

const pw = await loadPlaywright();
const skip = pw ? false : 'playwright is not installed (see the header of test/e2e/otp.e2e.mjs)';

/** The real agent's test harness, if built. */
function agentBinary() {
  const exe = process.platform === 'win32' ? 'e2e_agent.exe' : 'e2e_agent';
  const candidates = [
    process.env.PASS_E2E_AGENT,
    process.env.CARGO_TARGET_DIR && path.join(process.env.CARGO_TARGET_DIR, 'debug', 'examples', exe),
    path.join(repoRoot, 'Core', 'target', 'debug', 'examples', exe),
  ].filter(Boolean);
  return candidates.find((p) => existsSync(p)) || null;
}

/** Line-based JSON-RPC to the real agent harness: `{ handle(req) -> Promise<reply>, calls, close }`. */
function realAgent(bin) {
  const child = spawn(bin, [], { stdio: ['pipe', 'pipe', 'inherit'] });
  const waiting = new Map();
  const calls = [];
  createInterface({ input: child.stdout }).on('line', (line) => {
    const reply = JSON.parse(line);
    const resolve = waiting.get(reply.id);
    waiting.delete(reply.id);
    resolve?.(reply);
  });
  let next = 1;
  return {
    kind: 'real',
    calls,
    handle(req) {
      calls.push({ method: req.method, params: req.params });
      const id = next++;
      return new Promise((resolve) => {
        waiting.set(id, (reply) => resolve({ ...reply, id: req.id }));
        child.stdin.write(`${JSON.stringify({ ...req, id })}\n`);
      });
    },
    reset() { calls.length = 0; },
    close() { child.stdin.end(); child.kill(); },
  };
}

function mockAgent() {
  const agent = new MockAgent([]);
  const mock = {
    kind: 'mock',
    get calls() { return agent.calls; },
    // `down`: the desktop app isn't running (the native host answers every request so).
    down: false,
    handle: async (req) => (mock.down
      ? { id: req.id, error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } }
      : agent.handle(req)),
    reset: () => { agent.calls.length = 0; },
    close() {},
    agent,
  };
  return mock;
}

// The first page script records whether navigator.credentials was already wrapped (document_start).
const EARLY = `<script>window.__early = /\\[native code\\]/.test(String(navigator.credentials.create)) ? 'native' : 'wrapped';</script>`;
const PAGE = (title, body = '') => `<!doctype html><html><head><meta charset="utf-8"><title>${title}</title>${EARLY}</head>
<body><h1>${title}</h1>${body}<script>${CLIENT_JS}</script></body></html>`;

const SIGNIN_FORM = `<form id="f" onsubmit="return false"><label for="u">Username</label>
<input id="u" name="username" autocomplete="username webauthn"><button>Continue</button></form>`;

// Every page (and frame), `?fakenative` or not: the browser's own WebAuthn must never run for real.
const FAKE_NATIVE = `(() => {
  if (window.__nativeCalls) return; // webauthn-main.js injected again: the stand-in is in place
  const calls = [];
  window.__nativeCalls = calls;
  const fake = (kind) => function fakeNative(options) {
    calls.push({ kind, mediation: (options && options.mediation) || null });
    return Promise.reject(new DOMException('The browser was asked (e2e stand-in)', 'NotAllowedError'));
  };
  CredentialsContainer.prototype.create = fake('create');
  CredentialsContainer.prototype.get = fake('get');
})();`;

let agent; let server; let context; let dir; let port; let sw;
const origin = (sub) => `http://${sub}.example.localhost:${port}`;

function startServer() {
  const srv = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    const send = (body, type = 'text/html; charset=utf-8') => {
      res.writeHead(200, { 'content-type': type, 'cache-control': 'no-store' });
      res.end(body);
    };
    if (url.pathname === '/__agent') {
      let body = '';
      req.on('data', (c) => { body += c; });
      req.on('end', async () => send(JSON.stringify(await agent.handle(JSON.parse(body))), 'application/json'));
      return;
    }
    if (url.pathname === '/signin') { send(PAGE('Sign in', SIGNIN_FORM)); return; }
    if (url.pathname === '/embed') {
      // A cross-origin iframe allowed to use WebAuthn (permissions policy).
      const src = url.searchParams.get('src');
      send(PAGE('Embed', `<iframe id="frame" src="${src}" allow="publickey-credentials-create *; publickey-credentials-get *" style="width:600px;height:300px"></iframe>`));
      return;
    }
    send(PAGE('Passkeys'));
  });
  return new Promise((resolve) => srv.listen(0, '127.0.0.1', () => resolve(srv)));
}

async function serviceWorker() {
  const live = context.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://'));
  return live || context.waitForEvent('serviceworker', { timeout: 10_000 });
}

before(async () => {
  if (skip) return;
  const bin = agentBinary();
  agent = bin ? realAgent(bin) : mockAgent();
  console.log(`# passkey e2e: ${agent.kind} agent${bin ? ` (${bin})` : ''}`);
  server = await startServer();
  port = server.address().port;
  dir = mkdtempSync(path.join(tmpdir(), 'pass-e2e-pk-'));
  const extDir = path.join(dir, 'ext');
  for (const p of ['manifest.json', '_locales', 'src', 'icons']) cpSync(path.join(extRoot, p), path.join(extDir, p), { recursive: true });
  writeFileSync(path.join(extDir, 'src', 'e2e-native-stub.js'),
    readFileSync(path.join(here, 'native-stub.js'), 'utf8').replaceAll('__AGENT_URL__', `http://127.0.0.1:${port}/__agent`));
  writeFileSync(path.join(extDir, 'src', 'e2e-sw.js'), "import './e2e-native-stub.js';\nimport './background.js';\n");
  // webauthn-main.js takes the page's stand-in WebAuthn as its fallback, which records the call and says no:
  // the "Use another device" tests check that the request was handed over without running anywhere.
  const mainPath = path.join(extDir, 'src', 'content', 'webauthn-main.js');
  writeFileSync(mainPath, `${FAKE_NATIVE}
${readFileSync(mainPath, 'utf8')}`);
  const manifest = JSON.parse(readFileSync(path.join(extDir, 'manifest.json'), 'utf8'));
  manifest.background.service_worker = 'src/e2e-sw.js';
  writeFileSync(path.join(extDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  context = await pw.chromium.launchPersistentContext(path.join(dir, 'profile'), {
    ...(process.env.BROWSER ? { executablePath: process.env.BROWSER } : { channel: 'chromium' }),
    headless: !process.env.HEADED,
    // Chromium's own WebAuthn stack instead of the platform's (webauthn.dll): a fallback that slipped
    // past the virtual authenticator must never open Windows Security's passkey dialog.
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`, '--disable-features=WebAuthenticationUseNativeWinApi'],
  });
  sw = await serviceWorker();
});

after(async () => {
  await context?.close();
  server?.close();
  agent?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

/** A new tab with a CDP virtual authenticator standing in for the browser's own WebAuthn. */
async function openPage(url) {
  const page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'internal', hasResidentKey: true, hasUserVerification: true,
      isUserVerified: true, automaticPresenceSimulation: true },
  });
  page.native = async () => (await cdp.send('WebAuthn.getCredentials', { authenticatorId })).credentials;
  // The one CDP session of the page: looking into Passyble's UI goes through it too (uiButton). A
  // second session that detaches can switch the virtual authenticator off, and the browser's own
  // WebAuthn would then reach the real platform (Windows Security's passkey dialog). Never let it.
  page.cdp = cdp;
  await page.goto(url);
  return page;
}

const run = (page, fn, ...args) => page.evaluate(([f, a]) => window.pkClient[f](...a), [fn, args]);
const nativeCalls = (target) => target.evaluate(() => window.__nativeCalls);

/** PASSKEY_SHOTS=<dir>: a screenshot of the top right corner (the card) as <name>.png. */
async function screenshot(page, name) {
  const dirOut = process.env.PASSKEY_SHOTS;
  if (!dirOut) return;
  await new Promise((r) => setTimeout(r, 300)); // the card's entry animation
  const { width } = page.viewportSize() || { width: 1280 };
  await page.screenshot({ path: path.join(dirOut, `${name}.png`), clip: { x: Math.max(0, width - 420), y: 0, width: Math.min(420, width), height: 300 } });
}

/**
 * Runs pkClient[fn](...args) (a page's own create() or get()) and answers Passyble's card in the page
 * with a click on `text` ("Save passkey", "Sign in", "Use another device"), as the user would.
 */
async function withCard(page, fn, args, text, { shot = null } = {}) {
  await page.evaluate(([f, a]) => {
    window.__pkDone = false;
    window.__pk = window.pkClient[f](...a).finally(() => { window.__pkDone = true; });
  }, [fn, args]);
  let at = null;
  for (const end = Date.now() + 8000; !at && Date.now() < end;) {
    at = await uiButton(page, 'pass-passkey', text);
    if (!at) await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(at, `Passyble's card with "${text}"; agent calls: ${agent.calls.map((c) => c.method)}`);
  if (shot) await screenshot(page, shot);
  // The card must be on screen for a moment first, and the browser must have seen it unobstructed
  // (IntersectionObserver v2, which reports that late in a browser just started): the click guard
  // ignores a click before that, as it should, so the user's click comes again.
  for (let tries = 0; tries < 4; tries++) {
    await new Promise((r) => setTimeout(r, 900));
    if (await page.evaluate(() => window.__pkDone)) break;
    const now = await uiButton(page, 'pass-passkey', text);
    if (!now) break;
    await page.mouse.click(now.x, now.y);
  }
  return page.evaluate(() => Promise.race([window.__pk, new Promise((r) => setTimeout(() => r({ error: { name: 'timeout' } }), 8000))]));
}

test('capabilities: Passyble reports a platform authenticator', { skip }, async () => {
  const page = await openPage(`${origin('caps')}/`);
  const caps = await run(page, 'capabilities');
  console.log('# capabilities', JSON.stringify(caps));
  assert.equal(caps.uvpaa, true);
  assert.equal(caps.cma, true);
  if (caps.caps) {
    assert.equal(caps.caps.passkeyPlatformAuthenticator, true);
    assert.equal(caps.caps.conditionalGet, true);
  }
  assert.equal(caps.createName, 'create');
  await page.close();
});

for (const [label, opts] of [
  ['SimpleWebAuthn style (hand-converted options, toJSON)', {}],
  ['SimpleWebAuthn style (getters, no toJSON)', { useToJSON: false }],
  ['native JSON helpers (parse*FromJSON + toJSON)', { native: true }],
]) {
  test(`register then sign in: ${label}`, { skip }, async (t) => {
    const site = `rp${Math.random().toString(16).slice(2, 8)}`;
    const page = await openPage(`${origin(site)}/`);
    if (opts.native && !(await run(page, 'capabilities')).parseCreation) {
      t.skip('this browser has no PublicKeyCredential.parseCreationOptionsFromJSON');
      await page.close();
      return;
    }
    const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
    const userId = b64u(Buffer.from(`user-${site}`));
    agent.reset();
    const reg = await withCard(page, 'register', [rp.registrationOptions({ userId }), opts], 'Save passkey');
    assert.ok(!reg.error, `register failed: ${JSON.stringify(reg.error)}; agent calls: ${agent.calls.map((c) => c.method)}`);
    const created = agent.calls.find((c) => c.method === 'passkey.create');
    assert.ok(created?.params.consent, 'saved from the card in the page, no consent window');
    console.log('# register checks', JSON.stringify(reg.checks));
    assert.ok(agent.calls.some((c) => c.method === 'passkey.create'), 'Passyble handled the registration');
    assert.equal((await page.native()).length, 0, 'not the browser authenticator');
    const cred = rp.verifyRegistration(reg.json);
    assert.equal(reg.checks.instancePKC, true);
    assert.equal(reg.checks.responseType, 'attestation');
    assert.equal(reg.checks.authenticatorAttachment, 'platform');
    assert.equal(reg.json.authenticatorAttachment, 'platform');
    assert.deepEqual(reg.checks.extensions, { credProps: { rk: true } });
    assert.equal(reg.checks.publicKeyAlgorithm, -7);
    assert.ok(reg.checks.publicKeyBytes > 60);
    assert.ok(reg.checks.transports.includes('internal'));
    assert.equal(reg.checks.stringify, true);
    assert.ok(cred.flags.be && cred.flags.bs, 'backup eligible + backed up (synced)');

    // Discoverable sign-in (webauthn.io "Authenticate" with no username): the card in the page.
    const auth = await withCard(page, 'authenticate', [rp.authenticationOptions(), opts], 'Sign in');
    assert.ok(!auth.error, `sign-in failed: ${JSON.stringify(auth.error)}`);
    rp.verifyAuthentication(auth.json, { userHandle: userId });
    assert.equal(auth.checks.instancePKC, true);
    assert.equal(auth.checks.responseType, 'assertion');
    assert.equal(auth.checks.userHandle, userId);

    const signed = agent.calls.find((c) => c.method === 'passkey.get');
    assert.ok(signed?.params.id && signed.params.credentialId, 'the passkey picked in the card: no chooser window');
    // GitHub style: allowCredentials names the credential.
    const auth2 = await withCard(page, 'authenticate', [rp.authenticationOptions({ allow: [cred.id] }), opts], 'Sign in');
    assert.ok(!auth2.error, `sign-in failed: ${JSON.stringify(auth2.error)}`);
    rp.verifyAuthentication(auth2.json, { userHandle: userId });

    // Registering the same account again: excludeCredentials -> InvalidStateError.
    const again = await run(page, 'register', rp.registrationOptions({ userId, exclude: [cred.id] }), opts);
    assert.equal(again.error?.name, 'InvalidStateError', JSON.stringify(again));
    assert.equal(again.error.isDOMException, true);
    await page.close();
  });
}

test('a credential Passyble does not have: no card, the browser\'s own get() at once, "No passkey for <site> in Passyble"', { skip }, async () => {
  const site = 'miss';
  const page = await openPage(`${origin(site)}/`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  const opts = rp.authenticationOptions({ allow: [b64u(Buffer.from('not-in-passyble'))] });
  agent.reset();
  const started = Date.now();
  const res = await run(page, 'authenticate', opts);
  assert.equal(res.error?.name, 'NotAllowedError', JSON.stringify(res));
  assert.ok(Date.now() - started < 5000, 'no wait for a click or a timeout');
  assert.deepEqual(await nativeCalls(page), [{ kind: 'get', mediation: null }], "the browser's own get(), without a click");
  assert.ok(!agent.calls.some((c) => c.method === 'passkey.get'), 'Passyble signed nothing');
  assert.equal(await uiButton(page, 'pass-passkey', 'Use another device'), null, 'no card');
  assert.match(await uiText(page, 'pass-passkey-none') || '', /^No passkey for \S+ in Passyble$/);
  await screenshot(page, 'no-passkey-get');
  await page.close();
});

test('RSA-only sites go to the browser (Passyble makes ES256 passkeys only)', { skip }, async () => {
  const site = 'rsa';
  const page = await openPage(`${origin(site)}/`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  const options = rp.registrationOptions({ pubKeyCredParams: [{ type: 'public-key', alg: -257 }] });
  const res = await run(page, 'register', options);
  assert.equal(res.error?.name, 'NotAllowedError', JSON.stringify(res));
  assert.deepEqual((await nativeCalls(page)).map((c) => c.kind), ['create'], "the browser's own create() (the stand-in)");
  await page.close();
});

test('cross-origin iframe: the card says Passyble can\'t answer there; the browser with "Use another device"', { skip }, async () => {
  const site = 'framed';
  const page = await openPage(`${origin('top')}/embed?src=${encodeURIComponent(`${origin(site)}/`)}`);
  const frame = await (await page.$('#frame')).contentFrame();
  await frame.waitForFunction(() => !!window.pkClient);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  agent.reset();
  await frame.evaluate((o) => { window.__reg = window.pkClient.register(o); }, rp.registrationOptions());
  // The card is in the frame: CDP's pierced DOM reaches it, its box is in the page's coordinates.
  let at = null;
  for (const end = Date.now() + 8000; !at && Date.now() < end;) {
    at = await uiButton(page, 'pass-passkey', 'Use another device');
    if (!at) await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(at, 'the card in the frame');
  for (let tries = 0; tries < 4 && !(await nativeCalls(frame)).length; tries++) {
    await new Promise((r) => setTimeout(r, 900));
    const now = await uiButton(page, 'pass-passkey', 'Use another device');
    if (now) await page.mouse.click(now.x, now.y);
  }
  const reg = await frame.evaluate(() => Promise.race([window.__reg, new Promise((r) => setTimeout(() => r({ error: { name: 'timeout' } }), 8000))]));
  assert.equal(reg.error?.name, 'NotAllowedError', JSON.stringify(reg));
  assert.deepEqual((await nativeCalls(frame)).map((c) => c.kind), ['create']);
  assert.ok(!agent.calls.some((c) => c.method === 'passkey.create'));
  await page.close();
});

test('an aborted signal rejects with its reason', { skip }, async () => {
  const page = await openPage(`${origin('abort')}/`);
  const res = await page.evaluate(async () => {
    const ac = new AbortController();
    ac.abort();
    try {
      await navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32) }, signal: ac.signal });
      return 'resolved';
    } catch (e) { return e.name; }
  });
  assert.equal(res, 'AbortError');
  await page.close();
});

test('the wrapper is in place before the page\'s first script', { skip }, async () => {
  const page = await openPage(`${origin('early')}/`);
  assert.equal(await page.evaluate(() => window.__early), 'wrapped');
  await page.close();
});

test('webauthn.io flow: conditional request on load, then Register aborts it and registers', { skip }, async () => {
  const site = 'wio';
  const page = await openPage(`${origin(site)}/signin`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  await page.evaluate((o) => { window.__cond = window.pkClient.authenticate(o, { mediation: 'conditional' }); }, rp.authenticationOptions());
  await page.click('#u');
  await page.keyboard.type('dave');
  agent.reset();
  const reg = await withCard(page, 'register', [rp.registrationOptions({ user: 'dave' })], 'Save passkey');
  assert.ok(!reg.error, JSON.stringify(reg.error));
  rp.verifyRegistration(reg.json);
  assert.equal((await page.evaluate(() => window.__cond)).error?.name, 'AbortError');
  assert.ok(agent.calls.some((c) => c.method === 'passkey.create'));
  await page.close();
});

// background.js injectContentScripts runs on every onInstalled, also after a browser update, when
// the tab's content scripts are still alive: the second copy must leave the live one in charge.
// (After an extension reload the old bridge is dead instead; Playwright can't reload a
// command-line extension, so that case is covered in test/webauthn-main.test.js.)
test('content scripts injected twice: every call still settles, and Passyble still answers', { skip }, async () => {
  const site = 'twice';
  const page = await openPage(`${origin(site)}/`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  await page.evaluate(() => { window.__before = navigator.credentials.create; });
  sw = await serviceWorker();
  await sw.evaluate(async (url) => {
    const [tab] = await chrome.tabs.query({ url: `${url}*` });
    const target = { tabId: tab.id, allFrames: true };
    await chrome.scripting.executeScript({ target, files: ['src/content/bridge.js'] });
    await chrome.scripting.executeScript({ target, files: ['src/content/webauthn-main.js'], world: 'MAIN' });
  }, `${origin(site)}/`);
  assert.notEqual(await page.evaluate(() => navigator.credentials.create !== window.__before), false, 'second copy installed');
  const settle = (code) => page.evaluate((c) => Promise.race([(0, eval)(c), new Promise((r) => setTimeout(() => r('hung'), 4000))]), code);
  assert.equal(await settle('PublicKeyCredential.getClientCapabilities().then((c) => String(c.passkeyPlatformAuthenticator))'), 'true');
  assert.equal(await settle('PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(String)'), 'true');
  agent.reset();
  const reg = await withCard(page, 'register', [rp.registrationOptions()], 'Save passkey');
  assert.ok(!reg.error, JSON.stringify(reg.error));
  rp.verifyRegistration(reg.json);
  assert.ok(agent.calls.some((c) => c.method === 'passkey.create'), 'Passyble answered');
  await page.close();
});

test('conditional mediation: picking the passkey in the Passyble menu signs in', { skip }, async () => {
  const site = 'cond';
  const page = await openPage(`${origin(site)}/signin`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  const userId = b64u(Buffer.from('cond-user'));
  const reg = await withCard(page, 'register', [rp.registrationOptions({ userId, user: 'carol' })], 'Save passkey');
  assert.ok(!reg.error, JSON.stringify(reg.error));
  rp.verifyRegistration(reg.json);
  await page.reload();
  await page.waitForFunction(() => !!window.pkClient);
  // As SimpleWebAuthn's startAuthentication({ useBrowserAutofill: true }) on page load.
  await page.evaluate((o) => { window.__cond = window.pkClient.authenticate(o, { mediation: 'conditional' }); }, rp.authenticationOptions());
  agent.reset();
  await page.click('#u');
  // The menu opens for the passkey request (it lists the logins of the site, with their passkeys).
  const end = Date.now() + 8000;
  while (!agent.calls.some((c) => c.method === 'logins.find') && Date.now() < end) await new Promise((r) => setTimeout(r, 100));
  await new Promise((r) => setTimeout(r, 400));
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
  const auth = await page.evaluate(() => Promise.race([window.__cond, new Promise((r) => setTimeout(() => r({ error: { name: 'timeout' } }), 8000))]));
  assert.ok(!auth.error, `${JSON.stringify(auth.error)}; agent calls: ${agent.calls.map((c) => c.method)}`);
  rp.verifyAuthentication(auth.json, { userHandle: userId });
  const get = agent.calls.find((c) => c.method === 'passkey.get');
  assert.ok(get?.params.id, 'Passyble signed in with the passkey picked in the menu');
  await page.close();
});


/**
 * The middle of a button in Passyble's in-page UI (closed shadow roots, which page scripts and
 * Playwright's selectors can't reach; CDP's pierced DOM can), or null. `host`: the UI's element name.
 */
async function uiButton(page, host, text) {
  const cdp = page.cdp;
  try {
    const { root } = await cdp.send('DOM.getDocument', { depth: -1, pierce: true });
    const kids = (n) => [...(n.children || []), ...(n.shadowRoots || []), ...(n.contentDocument ? [n.contentDocument] : [])];
    const textOf = (n) => (n.nodeType === 3 ? n.nodeValue : kids(n).map(textOf).join(''));
    const find = (n, test) => (test(n) ? n : kids(n).reduce((hit, c) => hit || find(c, test), null));
    const ui = find(root, (n) => n.nodeName === host.toUpperCase());
    const button = ui && find(ui, (n) => n.nodeName === 'BUTTON' && textOf(n).trim() === text);
    if (!button) return null;
    const { model } = await cdp.send('DOM.getBoxModel', { nodeId: button.nodeId });
    const [x1, y1, , , x3, y3] = model.border;
    return { x: (x1 + x3) / 2, y: (y1 + y3) / 2 };
  } catch {
    return null;
  }
}

/** The text of Passyble's UI `host` (its closed shadow root, through CDP's pierced DOM), or null. */
async function uiText(page, host) {
  try {
    const { root } = await page.cdp.send('DOM.getDocument', { depth: -1, pierce: true });
    const kids = (n) => [...(n.children || []), ...(n.shadowRoots || []), ...(n.contentDocument ? [n.contentDocument] : [])];
    const textOf = (n) => (n.nodeType === 3 ? n.nodeValue : n.nodeName === 'STYLE' ? '' : kids(n).map(textOf).join(''));
    const find = (n) => (n.nodeName === host.toUpperCase() ? n : kids(n).reduce((hit, c) => hit || find(c), null));
    const ui = find(root);
    return ui ? textOf(ui).trim() : null;
  } catch {
    return null;
  }
}

test('passkey sign-in offered on its own: the card signs in with one click', { skip }, async () => {
  const site = 'card';
  const page = await openPage(`${origin(site)}/signin`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  const userId = b64u(Buffer.from('card-user'));
  const reg = await withCard(page, 'register', [rp.registrationOptions({ userId, user: 'erin' })], 'Save passkey');
  assert.ok(!reg.error, JSON.stringify(reg.error));
  rp.verifyRegistration(reg.json);
  await page.reload();
  await page.waitForFunction(() => !!window.pkClient);
  agent.reset();
  // As SimpleWebAuthn's startAuthentication({ useBrowserAutofill: true }) on page load: no click.
  await page.evaluate((o) => { window.__cond = window.pkClient.authenticate(o, { mediation: 'conditional' }); }, rp.authenticationOptions());
  let at = null;
  for (const end = Date.now() + 8000; !at && Date.now() < end;) {
    at = await uiButton(page, 'pass-passkey', 'Sign in');
    if (!at) await new Promise((r) => setTimeout(r, 100));
  }
  assert.ok(at, `the card shows; agent calls: ${agent.calls.map((c) => c.method)}`);
  const find = agent.calls.find((c) => c.method === 'passkey.find');
  assert.equal(find?.params.rpId, `${site}.example.localhost`);
  assert.ok(!agent.calls.some((c) => c.method === 'passkey.get'), 'nothing signed before the click');
  await new Promise((r) => setTimeout(r, 600)); // the card must be on screen for a moment first
  await page.mouse.click(at.x, at.y);
  const auth = await page.evaluate(() => Promise.race([window.__cond, new Promise((r) => setTimeout(() => r({ error: { name: 'timeout' } }), 8000))]));
  assert.ok(!auth.error, `${JSON.stringify(auth.error)}; agent calls: ${agent.calls.map((c) => c.method)}`);
  rp.verifyAuthentication(auth.json, { userHandle: userId });
  const get = agent.calls.find((c) => c.method === 'passkey.get');
  assert.ok(get?.params.id && get.params.credentialId, 'the passkey shown in the card');
  assert.equal(await uiButton(page, 'pass-passkey', 'Sign in'), null, 'the card is gone');
  await page.close();
});

test("\"Use another device\" in the save card hands create() to the browser; nothing is saved in Passyble", { skip }, async () => {
  const site = 'elsewhere';
  const page = await openPage(`${origin(site)}/`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  agent.reset();
  const reg = await withCard(page, 'register', [rp.registrationOptions({ user: 'frank' })], 'Use another device');
  assert.equal(reg.error?.name, 'NotAllowedError', JSON.stringify(reg));
  assert.deepEqual(await page.evaluate(() => window.__nativeCalls), [{ kind: 'create', mediation: null }], "the browser's own create()");
  assert.ok(!agent.calls.some((c) => c.method === 'passkey.create'), 'nothing saved in Passyble');
  // Nothing of Passyble's for the site: the card says so; the browser only with "Use another device".
  const auth = await withCard(page, 'authenticate', [rp.authenticationOptions()], 'Use another device');
  assert.equal(auth.error?.name, 'NotAllowedError', JSON.stringify(auth));
  assert.deepEqual((await page.evaluate(() => window.__nativeCalls)).map((c) => c.kind), ['create', 'get']);
  assert.ok(!agent.calls.some((c) => c.method === 'passkey.get'));
  await page.close();
});

test("a page's own sign-in: \"Use another device\" in the card hands it to the browser; Cancel fails it", { skip }, async () => {
  const site = 'modal';
  const page = await openPage(`${origin(site)}/`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  const reg = await withCard(page, 'register', [rp.registrationOptions({ user: 'gina' })], 'Save passkey');
  assert.ok(!reg.error, JSON.stringify(reg.error));
  rp.verifyRegistration(reg.json);
  agent.reset();
  const elsewhere = await withCard(page, 'authenticate', [rp.authenticationOptions()], 'Use another device');
  assert.equal(elsewhere.error?.name, 'NotAllowedError', JSON.stringify(elsewhere));
  assert.deepEqual(await page.evaluate(() => window.__nativeCalls), [{ kind: 'get', mediation: null }], "the browser's own get()");
  assert.ok(!agent.calls.some((c) => c.method === 'passkey.get'), 'Passyble signed nothing');
  const cancelled = await withCard(page, 'authenticate', [rp.authenticationOptions()], 'Cancel');
  assert.equal(cancelled.error?.name, 'NotAllowedError', JSON.stringify(cancelled));
  assert.equal((await page.evaluate(() => window.__nativeCalls)).length, 1, 'Cancel: not the browser either');
  assert.ok(!agent.calls.some((c) => c.method === 'passkey.get'));
  await page.close();
});

// The card first, also locked, without a passkey, or with Passyble away (mock agent).

const mockOnly = skip;

test('fully locked (after boot), a page asking as it loads: "Sign in with a Passyble passkey?", Unlock signs in; nothing reaches the browser', { skip: mockOnly }, async (t) => {
  if (agent.kind !== 'mock') { t.skip('needs the mock agent (its lock)'); return; }
  const site = 'boot';
  const page = await openPage(`${origin(site)}/`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  const userId = b64u(Buffer.from('boot-user'));
  const reg = await withCard(page, 'register', [rp.registrationOptions({ userId, user: 'hana' })], 'Save passkey');
  assert.ok(!reg.error, JSON.stringify(reg.error));
  rp.verifyRegistration(reg.json);
  const mock = agent.agent;
  Object.assign(mock, { locked: true, softLocked: false, inlineUnlock: true, hello: true });
  try {
    await page.reload();
    await page.waitForFunction(() => !!window.pkClient);
    agent.reset();
    // No click in this document: the request comes as the page loads.
    const auth = await withCard(page, 'authenticate', [rp.authenticationOptions()], 'Unlock', { shot: 'locked-get' });
    assert.ok(!auth.error, `${JSON.stringify(auth.error)}; agent calls: ${agent.calls.map((c) => c.method)}`);
    rp.verifyAuthentication(auth.json, { userHandle: userId });
    assert.ok(agent.calls.some((c) => c.method === 'unlock.hello'), 'unlocked in the card (Windows Hello, the mock)');
    assert.ok(!agent.calls.some((c) => c.method === 'unlock'), "never the desktop app's unlock window");
    assert.deepEqual(await nativeCalls(page), [], "the browser's own WebAuthn never ran");

    // Locked again, create(): the save card asks to unlock too.
    mock.locked = true;
    await page.reload();
    await page.waitForFunction(() => !!window.pkClient);
    const again = await withCard(page, 'register', [rp.registrationOptions({ user: 'ivan' })], 'Use another device', { shot: 'locked-create' });
    assert.equal(again.error?.name, 'NotAllowedError');
    assert.deepEqual((await nativeCalls(page)).map((c) => c.kind), ['create'], 'the browser only with the click');
  } finally {
    Object.assign(mock, { locked: false, inlineUnlock: false, hello: false });
  }
  await page.close();
});

test('Passyble not running: "Passyble isn\'t running", Open Passyble goes on in the card; Cancel is not the browser', { skip: mockOnly }, async (t) => {
  if (agent.kind !== 'mock') { t.skip('needs the mock agent (switched off)'); return; }
  const site = 'down';
  const page = await openPage(`${origin(site)}/`);
  const rp = new RelyingParty({ rpId: `${site}.example.localhost`, origin: origin(site) });
  agent.down = true;
  try {
    await page.evaluate((o) => {
      window.__pkDone = false;
      window.__pk = window.pkClient.authenticate(o).finally(() => { window.__pkDone = true; });
    }, rp.authenticationOptions());
    let at = null;
    for (const end = Date.now() + 8000; !at && Date.now() < end;) {
      at = await uiButton(page, 'pass-passkey', 'Open Passyble');
      if (!at) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(at, 'the "Passyble isn\'t running" card');
    await screenshot(page, 'not-running');
    agent.down = false; // the native host starts Passyble
    agent.reset();
    const asked = () => agent.calls.some((c) => c.method === 'passkey.find');
    // The click guard ignores clicks before the card was seen for a moment: click again until taken.
    for (let tries = 0; tries < 4 && !asked(); tries++) {
      await new Promise((r) => setTimeout(r, 900));
      const now = await uiButton(page, 'pass-passkey', 'Open Passyble');
      if (!now) break;
      await page.mouse.click(now.x, now.y);
    }
    // Started: nothing in Passyble for this site, the card says so.
    let none = null;
    for (const end = Date.now() + 8000; !none && Date.now() < end;) {
      none = await uiButton(page, 'pass-passkey', 'Cancel');
      if (none && !asked()) none = null;
      if (!none) await new Promise((r) => setTimeout(r, 100));
    }
    assert.ok(none, `asked Passyble again; agent calls: ${agent.calls.map((c) => c.method)}`);
    await screenshot(page, 'no-passkey-after-start');
    await new Promise((r) => setTimeout(r, 900));
    const cancel = await uiButton(page, 'pass-passkey', 'Cancel');
    await page.mouse.click(cancel.x, cancel.y);
    const res = await page.evaluate(() => Promise.race([window.__pk, new Promise((r) => setTimeout(() => r({ error: { name: 'timeout' } }), 8000))]));
    assert.equal(res.error?.name, 'NotAllowedError', JSON.stringify(res));
    assert.deepEqual(await nativeCalls(page), [], 'Cancel: not the browser either');
  } finally {
    agent.down = false;
  }
  await page.close();
});
