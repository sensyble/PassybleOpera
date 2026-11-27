// End-to-end test of the 2FA chain: real Chromium, the real extension, a mock agent behind a stubbed connectNative
// (test/e2e/native-stub.js) and local sign-in pages with the 2FA step in common shapes. Opt-in, not part of `npm test`:
//   npm run test:e2e   (headless; HEADED=1 to watch)
// Needs `npm i --no-save playwright` and `npx playwright install chromium`, or PLAYWRIGHT_DIR=<path to node_modules/playwright>.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MockAgent, validCodes } from './mock-agent.mjs';
import { SCENARIOS, startServer } from './pages.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const extRoot = path.resolve(here, '..', '..');
const SECRET = 'JBSWY3DPEHPK3PXP';

async function loadPlaywright() {
  if (process.env.PLAYWRIGHT_DIR) return createRequire(path.join(process.env.PLAYWRIGHT_DIR, 'x.js'))('./index.js');
  try { return await import('playwright'); } catch { return null; }
}

const pw = await loadPlaywright();
const skip = pw ? false : 'playwright is not installed (see the header of this file)';

const agent = new MockAgent([
  { id: 'ex', title: 'Example', username: 'alice@example.com', password: 'correct horse', urls: ['http://example.localhost'], totp: SECRET },
  { id: 'other', title: 'Other site', username: 'bob', password: 'x', urls: ['http://other.localhost'], totp: 'GEZDGNBVGY3TQOJQ' },
]);

let server; let context; let dir; let base; let sw;

async function serviceWorker() {
  const live = context.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://'));
  return live || context.waitForEvent('serviceworker', { timeout: 10_000 });
}

/** Back to the defaults (nothing stored), as on a fresh install. */
async function defaultSettings() {
  sw = await serviceWorker();
  await sw.evaluate(() => chrome.storage.local.clear());
}

async function setSettings(values) {
  sw = await serviceWorker();
  await sw.evaluate((v) => chrome.storage.local.set(v), values);
}

/**
 * Sends a command to the active tab's top frame, as the background does for a keyboard shortcut, again until the
 * content script listens (right after a navigation it may still be starting).
 */
async function command(type) {
  sw = await serviceWorker();
  for (let attempt = 0; ; attempt++) {
    try {
      return await sw.evaluate(async (t) => {
        const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
        return chrome.tabs.sendMessage(tab.id, { type: t }, { frameId: 0 });
      }, type);
    } catch (err) {
      if (attempt >= 20 || !/receiving end does not exist/i.test(String(err?.message))) throw err;
      await sleep(100);
    }
  }
}

before(async () => {
  if (skip) return;
  server = await startServer(agent);
  const port = server.address().port;
  base = (sub) => `http://${sub}.example.localhost:${port}`;
  // A copy of the extension whose service worker first loads the connectNative stub.
  dir = mkdtempSync(path.join(tmpdir(), 'pass-e2e-'));
  const extDir = path.join(dir, 'ext');
  for (const p of ['manifest.json', '_locales', 'src', 'icons']) cpSync(path.join(extRoot, p), path.join(extDir, p), { recursive: true });
  writeFileSync(path.join(extDir, 'src', 'e2e-native-stub.js'),
    readFileSync(path.join(here, 'native-stub.js'), 'utf8').replaceAll('__AGENT_URL__', `http://127.0.0.1:${port}/__agent`));
  writeFileSync(path.join(extDir, 'src', 'e2e-sw.js'), "import './e2e-native-stub.js';\nimport './background.js';\n");
  const manifest = JSON.parse(readFileSync(path.join(extDir, 'manifest.json'), 'utf8'));
  manifest.background.service_worker = 'src/e2e-sw.js';
  writeFileSync(path.join(extDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  context = await pw.chromium.launchPersistentContext(path.join(dir, 'profile'), {
    channel: 'chromium',
    headless: !process.env.HEADED,
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
  });
  sw = await serviceWorker();
});

after(async () => {
  await context?.close();
  server?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, { timeout = 8000, what = 'condition' } = {}) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    last = await fn();
    if (last) return last;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what} (last: ${JSON.stringify(last)})`);
}

/** Opens the scenario's sign-in page and fills it through the inline menu (↓ then Enter). */
async function signIn(page, id, { host = 'login' } = {}) {
  await page.goto(`${base(host)}/s/${id}/login`);
  await page.click('#email');
  await waitFor(() => page.evaluate(() => !!document.querySelector('pass-icon')), { what: 'Passyble icon' });
  await page.keyboard.press('ArrowDown');
  await waitFor(() => agent.calls.some((c) => c.method === 'logins.find'), { what: 'logins.find' });
  await sleep(400);
  await page.keyboard.press('Enter');
  await waitFor(() => page.inputValue('#password'), { what: 'password filled' });
  assert.equal(await page.inputValue('#email'), 'alice@example.com');
}

async function codeTarget(page, sc) {
  const frame = sc.frame ? page.frameLocator(sc.frame) : page;
  return sc.state ? frame.locator(sc.state) : frame.locator(sc.field);
}

async function currentValue(page, sc) {
  const loc = await codeTarget(page, sc);
  if (!(await loc.count())) return '';
  return sc.state ? (await loc.textContent()).trim() : loc.inputValue();
}

async function expectCode(page, sc, timeout = 10_000) {
  const value = await waitFor(async () => {
    const v = await currentValue(page, sc);
    return validCodes(SECRET).includes(v) ? v : '';
  }, { timeout, what: `2FA code in ${sc.state || sc.field}` }).catch(async (err) => {
    err.message += `; value now "${await currentValue(page, sc)}"; agent calls: ${agent.calls.map((c) => c.method).join(', ')}`;
    throw err;
  });
  return value;
}

async function freshPage() {
  agent.reset();
  const page = await context.newPage();
  page.on('console', (m) => { if (process.env.DEBUG) console.log(`[page] ${m.text()}`); });
  return page;
}

// Auto-fill on the next step (default settings).

const AUTO = Object.entries(SCENARIOS).filter(([, sc]) => !sc.unrecognised && !sc.signsIn);

for (const [id, sc] of AUTO) {
  test(`auto-fills the 2FA code after a Passyble fill: ${id}`, { skip }, async () => {
    await defaultSettings();
    const page = await freshPage();
    try {
      await signIn(page, id);
      await page.click('#login button[type=submit]');
      await expectCode(page, sc);
      const totp = agent.calls.filter((c) => c.method === 'totp.get');
      assert.ok(totp.length, 'code came from totp.get');
      assert.ok(totp.every((c) => /example\.localhost/.test(c.params.url)), 'asked for the page URL');
      assert.equal(page.url().includes('/done'), false, 'did not submit the 2FA form');
    } finally {
      await page.close();
    }
  });
}

test('auto-fill works after the service worker was stopped between the steps', { skip }, async () => {
  await setSettings({ autoFillOtp: true });
  const page = await freshPage();
  try {
    await signIn(page, 'a');
    await (await serviceWorker()).evaluate(() => { globalThis.__e2eMarker = true; });
    const cdp = await context.newCDPSession(page);
    await cdp.send('ServiceWorker.enable');
    await cdp.send('ServiceWorker.stopAllWorkers');
    await page.click('#login button[type=submit]');
    await expectCode(page, SCENARIOS.a);
    sw = await serviceWorker();
    assert.equal(await sw.evaluate(() => globalThis.__e2eMarker === true), false, 'a new service worker instance');
  } finally {
    await page.close();
  }
});

test('no code field on the 2FA step: the toast shows the code', { skip }, async () => {
  await defaultSettings();
  const page = await freshPage();
  try {
    await signIn(page, 'push');
    await page.click('#login button[type=submit]');
    await waitFor(() => page.evaluate(() => !!document.querySelector('pass-toast')), { timeout: 14_000, what: 'toast' });
    assert.ok(agent.calls.some((c) => c.method === 'totp.get' && !c.params.id), 'pending code fetched');
  } finally {
    await page.close();
  }
});

test('no fill moments ago: clicking a code field opens the menu with the site login\'s code', { skip }, async () => {
  await defaultSettings();
  const page = await freshPage();
  try {
    await page.goto(`${base('login')}/s/github/2fa`);
    await sleep(500);
    assert.equal(await page.evaluate(() => !!document.querySelector('pass-menu')), false, 'not on its own');
    await page.click('#app_totp');
    await waitFor(() => page.evaluate(() => !!document.querySelector('pass-menu')), { what: 'menu on click' });
    await sleep(300);
    await page.keyboard.press('Enter');
    await expectCode(page, SCENARIOS.github);
    assert.ok(agent.calls.some((c) => c.method === 'totp.get' && c.params.id === 'ex'));
  } finally {
    await page.close();
  }
});

test('with auto-fill off, the menu opens on the code field and Enter fills the code', { skip }, async () => {
  await setSettings({ autoFillOtp: false });
  const page = await freshPage();
  try {
    await signIn(page, 'github');
    await page.click('#login button[type=submit]');
    await page.waitForSelector('#app_totp');
    await waitFor(() => page.evaluate(() => !!document.querySelector('pass-menu')), { what: 'menu opened on its own' });
    assert.equal(await page.inputValue('#app_totp'), '', 'nothing filled without a click');
    await page.click('#app_totp');
    await sleep(300);
    await page.keyboard.press('Enter');
    await expectCode(page, SCENARIOS.github);
  } finally {
    await page.close();
    await setSettings({ autoFillOtp: true });
  }
});

test('unrecognised code field: focusing it offers the pending code in the menu', { skip }, async () => {
  await setSettings({ autoFillOtp: true });
  const page = await freshPage();
  try {
    await signIn(page, 'unknown');
    await page.click('#login button[type=submit]');
    await page.waitForSelector('#c');
    await sleep(600);
    assert.equal(await page.inputValue('#c'), '', 'not filled on its own');
    await page.click('#c');
    await waitFor(() => page.evaluate(() => !!document.querySelector('pass-menu')), { what: 'menu on focus' });
    await sleep(300);
    await page.keyboard.press('Enter');
    await expectCode(page, SCENARIOS.unknown);
  } finally {
    await page.close();
  }
});

test('Alt+Shift+K (cmd.fill-otp) fills the focused field', { skip }, async () => {
  await setSettings({ autoFillOtp: true });
  const page = await freshPage();
  try {
    await signIn(page, 'unknown');
    await page.click('#login button[type=submit]');
    await page.waitForSelector('#c');
    await page.focus('#c');
    await page.keyboard.press('Escape');
    await command('cmd.fill-otp');
    await expectCode(page, SCENARIOS.unknown);
  } finally {
    await page.close();
  }
});

test('Alt+Shift+K without a pending fill uses the site login with 2FA', { skip }, async () => {
  const page = await freshPage();
  try {
    await page.goto(`${base('login')}/s/github/2fa`);
    await page.focus('#app_totp');
    await command('cmd.fill-otp');
    await expectCode(page, SCENARIOS.github);
  } finally {
    await page.close();
  }
});

test('no code for another site: other.localhost gets nothing from the example.localhost login', { skip }, async () => {
  const page = await freshPage();
  try {
    await signIn(page, 'a');
    const port = server.address().port;
    await page.goto(`http://other.localhost:${port}/s/a/2fa`);
    await sleep(1500);
    assert.equal(await page.inputValue('#c'), '');
    assert.ok(!agent.calls.some((c) => c.method === 'totp.get' && /other\.localhost/.test(c.params.url) && !c.params.id));
  } finally {
    await page.close();
  }
});

// Sites that don't always ask for 2FA.

const outcomes = () => agent.calls.filter((c) => c.method === 'otp.outcome').map((c) => c.params.outcome);

test('site skipped 2FA: nothing shows, "skipped" is reported to the agent', { skip }, async () => {
  await defaultSettings();
  const page = await freshPage();
  try {
    await signIn(page, 'skip');
    await page.click('#login button[type=submit]');
    await page.waitForURL(/\/s\/skip\/home$/);
    await waitFor(() => outcomes().includes('skipped'), { timeout: 16_000, what: 'otp.outcome skipped' });
    assert.equal(await page.evaluate(() => !!document.querySelector('pass-toast')), false, 'no toast');
    assert.equal(await page.evaluate(() => !!document.querySelector('pass-menu')), false, 'no menu');
    assert.ok(!agent.calls.some((c) => c.method === 'totp.get'), 'the code was never fetched');
    assert.ok(agent.calls.some((c) => c.method === 'otp.outcome' && /example\.localhost/.test(c.params.url)));
  } finally {
    await page.close();
  }
});

test('learned skip (skips_2fa): a 2FA page without a code field shows no toast; a code field is still filled', { skip }, async () => {
  await defaultSettings();
  const page = await freshPage();
  try {
    agent.outcomes.set('example.localhost', ['skipped', 'skipped']);
    await signIn(page, 'push');
    await page.click('#login button[type=submit]');
    await page.waitForURL(/\/s\/push\/2fa$/);
    await sleep(6000);
    assert.equal(await page.evaluate(() => !!document.querySelector('pass-toast')), false, 'no toast');
    // The site asks after all, with a code field: it still gets the code.
    await page.evaluate(() => {
      document.getElementById('widget').innerHTML = '<input id="c" name="otp" autocomplete="one-time-code" inputmode="numeric">';
    });
    await expectCode(page, { field: '#c' });
  } finally {
    await page.close();
  }
});
