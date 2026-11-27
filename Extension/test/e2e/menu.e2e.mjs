// End-to-end test of the in-page menu with the mouse, also on a page a dark-mode extension filters (`filter` on <html>,
// where IntersectionObserver v2 reports nothing as visible). Opt-in like otp.e2e.mjs. The copy of the extension under
// test opens its shadow roots (closed in the real one) so that Playwright can click the entries by their text.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { MockAgent } from './mock-agent.mjs';
import { startServer } from './pages.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const extRoot = path.resolve(here, '..', '..');

async function loadPlaywright() {
  if (process.env.PLAYWRIGHT_DIR) return createRequire(path.join(process.env.PLAYWRIGHT_DIR, 'x.js'))('./index.js');
  try { return await import('playwright'); } catch { return null; }
}

const pw = await loadPlaywright();
const skip = pw ? false : 'playwright is not installed (see the header of otp.e2e.mjs)';
const PASSWORD = 'correct horse';

const agent = new MockAgent([
  { id: 'ex', title: 'Example', username: 'alice@example.com', password: PASSWORD, urls: ['http://example.localhost'] },
  { id: 'bob', title: 'Example (Bob)', username: 'bob@example.com', password: 'bobs secret', urls: ['http://example.localhost'] },
]);
let server; let context; let dir; let base;

async function serviceWorker() {
  const live = context.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://'));
  return live || context.waitForEvent('serviceworker', { timeout: 10_000 });
}

before(async () => {
  if (skip) return;
  server = await startServer(agent);
  base = `http://login.example.localhost:${server.address().port}`;
  dir = mkdtempSync(path.join(tmpdir(), 'pass-e2e-menu-'));
  const extDir = path.join(dir, 'ext');
  for (const p of ['manifest.json', '_locales', 'src', 'icons']) cpSync(path.join(extRoot, p), path.join(extDir, p), { recursive: true });
  writeFileSync(path.join(extDir, 'src', 'e2e-native-stub.js'),
    readFileSync(path.join(here, 'native-stub.js'), 'utf8').replaceAll('__AGENT_URL__', `http://127.0.0.1:${server.address().port}/__agent`));
  // Headless Chromium "opens" the toolbar popup without showing it: take the small unlock window instead.
  writeFileSync(path.join(extDir, 'src', 'e2e-no-popup.js'),
    "try { Object.defineProperty(chrome.action, 'openPopup', { value: undefined, configurable: true }); } catch { chrome.action.openPopup = undefined; }\n");
  writeFileSync(path.join(extDir, 'src', 'e2e-sw.js'), "import './e2e-native-stub.js';\nimport './e2e-no-popup.js';\nimport './background.js';\n");
  const uiCommon = path.join(extDir, 'src', 'content', 'ui-common.js');
  const src = readFileSync(uiCommon, 'utf8');
  assert.ok(src.includes("attachShadow({ mode: 'closed' })"));
  writeFileSync(uiCommon, src.replace("attachShadow({ mode: 'closed' })", "attachShadow({ mode: 'open' })"));
  const manifest = JSON.parse(readFileSync(path.join(extDir, 'manifest.json'), 'utf8'));
  manifest.background.service_worker = 'src/e2e-sw.js';
  writeFileSync(path.join(extDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  context = await pw.chromium.launchPersistentContext(path.join(dir, 'profile'), {
    channel: 'chromium',
    headless: !process.env.HEADED,
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
  });
  await serviceWorker();
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
  throw new Error(`timed out waiting for ${what} (last: ${JSON.stringify(last)}); agent calls: ${agent.calls.map((c) => c.method).join(', ')}`);
}

function setAgent({ locked = false, hello = false } = {}) {
  agent.reset();
  agent.locked = locked;
  agent.softLocked = locked;
  agent.inlineUnlock = true;
  agent.hello = hello;
}

/** The sign-in page, the e-mail field clicked: the suggestions open on their own. */
async function openSignIn({ css = '' } = {}) {
  const page = await context.newPage();
  await page.goto(`${base}/s/a/login`);
  if (css) await page.addStyleTag({ content: css });
  await waitFor(() => page.evaluate(() => !!document.querySelector('pass-icon') || document.readyState === 'complete'), { what: 'page' });
  await page.click('#email');
  await waitFor(() => page.locator('pass-menu .item').count(), { what: 'suggestions' });
  return page;
}

const entry = (page, text) => page.locator('pass-menu .item', { hasText: text }).first();
const titles = (page) => page.locator('pass-menu .item .title').allTextContents();

/** A real mouse click, after the moment new entries must be on screen before a click counts. */
async function clickEntry(page, text) {
  await sleep(650);
  await entry(page, text).click();
}

test('a mouse click on an entry fills the login (as Enter does)', { skip }, async () => {
  setAgent();
  const page = await openSignIn();
  try {
    await clickEntry(page, 'alice@example.com');
    await waitFor(() => page.inputValue('#password'), { what: 'password filled' });
    assert.equal(await page.inputValue('#email'), 'alice@example.com');
    assert.equal(await page.inputValue('#password'), PASSWORD);
    assert.equal(await page.locator('pass-menu').count(), 0, 'the menu closed');
  } finally {
    await page.close();
  }
});

test('a mouse click fills on a page a dark-mode extension filters', { skip }, async () => {
  setAgent();
  const page = await openSignIn({ css: 'html { filter: invert(1) hue-rotate(180deg) !important; }' });
  try {
    await clickEntry(page, 'bob@example.com');
    await waitFor(() => page.inputValue('#password'), { what: 'password filled' });
    assert.equal(await page.inputValue('#email'), 'bob@example.com');
    assert.equal(await page.inputValue('#password'), 'bobs secret');
  } finally {
    await page.close();
  }
});

test('typing into the e-mail field filters the logins; the menu stays; a click fills the match', { skip }, async () => {
  setAgent();
  const page = await openSignIn();
  try {
    assert.deepEqual(await titles(page), ['Example', 'Example (Bob)']);
    await page.keyboard.type('bo');
    await waitFor(async () => (await titles(page)).length === 1, { what: 'filtered' });
    assert.deepEqual(await titles(page), ['Example (Bob)']);
    assert.equal(await page.inputValue('#email'), 'bo', 'typing fills nothing');
    assert.ok(!agent.calls.some((c) => c.method === 'logins.fill'));
    await page.keyboard.type('x');
    await waitFor(() => page.locator('pass-menu', { hasText: 'No logins match' }).count(), { what: '"No logins match"' });
    await page.keyboard.press('Backspace');
    await waitFor(async () => (await titles(page)).length === 1, { what: 'filtered again' });
    await clickEntry(page, 'Example (Bob)');
    await waitFor(() => page.inputValue('#password'), { what: 'password filled' });
    assert.equal(await page.inputValue('#email'), 'bob@example.com');
  } finally {
    await page.close();
  }
});

test('locked: "Unlock with Windows Hello" in the menu unlocks, then the picked login fills', { skip }, async () => {
  setAgent({ locked: true, hello: true });
  const page = await openSignIn();
  try {
    await clickEntry(page, 'alice@example.com');
    await waitFor(() => entry(page, 'Unlock with Windows Hello').count(), { what: 'unlock choices' });
    assert.deepEqual(await titles(page), ['Unlock with Windows Hello', 'Enter master password', 'Open Passyble']);
    assert.equal(await page.inputValue('#password'), '');
    await clickEntry(page, 'Unlock with Windows Hello');
    await waitFor(() => page.inputValue('#password'), { what: 'password filled after the unlock' });
    assert.equal(await page.inputValue('#email'), 'alice@example.com');
    assert.equal(await page.inputValue('#password'), PASSWORD);
    assert.ok(agent.calls.some((c) => c.method === 'unlock.hello'));
    assert.ok(!agent.calls.some((c) => c.method === 'unlock'), "not the desktop app's prompt");
  } finally {
    await page.close();
  }
});

test('locked: "Enter master password" opens the extension\'s form; once unlocked there, the login fills', { skip }, async () => {
  setAgent({ locked: true, hello: false });
  const page = await openSignIn();
  try {
    await clickEntry(page, 'bob@example.com');
    await waitFor(() => entry(page, 'Enter master password').count(), { what: 'unlock choices' });
    assert.equal(await entry(page, 'Windows Hello').count(), 0, 'no Windows Hello when the desktop app does not offer it');
    const opened = context.waitForEvent('page', { timeout: 10_000 });
    await clickEntry(page, 'Enter master password');
    const form = await opened;
    await form.waitForLoadState();
    assert.match(form.url(), /src\/popup\/popup\.html\?unlock=1$/);
    await form.waitForSelector('#master', { state: 'visible' });
    assert.equal(await form.getAttribute('#master', 'autocomplete'), 'off');
    await form.fill('#master', 'wrong');
    await form.click('#unlock-submit');
    await waitFor(() => form.locator('#unlock-msg', { hasText: 'Wrong master password' }).count(), { what: 'wrong password text' });
    assert.equal(await page.inputValue('#password'), '', 'still nothing filled');
    const closed = form.waitForEvent('close', { timeout: 10_000 });
    await form.fill('#master', 'master');
    await form.click('#unlock-submit');
    await closed;
    await waitFor(() => page.inputValue('#password'), { what: 'password filled after the unlock' });
    assert.equal(await page.inputValue('#email'), 'bob@example.com');
    assert.equal(await page.inputValue('#password'), 'bobs secret');
    const unlocks = agent.calls.filter((c) => c.method === 'unlock.password');
    assert.equal(unlocks.length, 2);
  } finally {
    await page.close();
  }
});
