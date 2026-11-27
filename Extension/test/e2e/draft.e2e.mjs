// End-to-end test of generated passwords saved right away (drafts): real Chromium, the real
// extension, the mock agent and a local sign-up page. Opt-in like otp.e2e.mjs.
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
const GENERATED = 'Generated-Password-1234';

const agent = new MockAgent([]);
let server; let context; let dir; let base;

async function serviceWorker() {
  const live = context.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://'));
  return live || context.waitForEvent('serviceworker', { timeout: 10_000 });
}

before(async () => {
  if (skip) return;
  server = await startServer(agent);
  base = `http://login.example.localhost:${server.address().port}`;
  dir = mkdtempSync(path.join(tmpdir(), 'pass-e2e-draft-'));
  const extDir = path.join(dir, 'ext');
  for (const p of ['manifest.json', '_locales', 'src', 'icons']) cpSync(path.join(extRoot, p), path.join(extDir, p), { recursive: true });
  writeFileSync(path.join(extDir, 'src', 'e2e-native-stub.js'),
    readFileSync(path.join(here, 'native-stub.js'), 'utf8').replaceAll('__AGENT_URL__', `http://127.0.0.1:${server.address().port}/__agent`));
  writeFileSync(path.join(extDir, 'src', 'e2e-sw.js'), "import './e2e-native-stub.js';\nimport './background.js';\n");
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

const callsOf = (method) => agent.calls.filter((c) => c.method === method).map((c) => c.params);

async function freshPage() {
  agent.reset();
  agent.items.length = 0;
  const page = await context.newPage();
  await page.goto(`${base}/signup`);
  return page;
}

test('generate button: fills password + confirmation, saves at once, submit updates that login', { skip }, async () => {
  const page = await freshPage();
  try {
    await page.click('#password');
    await waitFor(() => page.evaluate(() => !!document.querySelector('pass-icon')), { what: 'Passyble icon' });
    await page.keyboard.press('Escape'); // the generator menu opened on its own; use the button instead
    await sleep(700); // a click counts once the button was visible for a moment
    const box = await page.locator('#password').boundingBox();
    const size = Math.min(18, Math.max(12, box.height - 8));
    // [generate][gap 4][Passyble icon] at the field's right end, 8 px in.
    await page.mouse.click(box.x + box.width - 8 - (size * 2 + 4) + size / 2, box.y + box.height / 2);
    await waitFor(() => callsOf('logins.create').length, { what: 'logins.create' });
    assert.equal(await page.inputValue('#password'), GENERATED);
    assert.equal(await page.inputValue('#confirm'), GENERATED);
    const [created] = callsOf('logins.create');
    assert.equal(created.url, `${base}/signup`);
    assert.deepEqual(created.fields, { password: GENERATED, username: '' });
    assert.ok(await page.evaluate(() => !!document.querySelector('pass-action-toast')), '"Saved · Undo" toast');

    await page.fill('#email', 'alice@example.com');
    await page.click('#signup button[type=submit]');
    await waitFor(() => callsOf('logins.update').length, { what: 'logins.update on submit' });
    assert.deepEqual(callsOf('logins.update').at(-1).fields, { password: GENERATED, username: 'alice@example.com' });
    assert.equal(callsOf('logins.create').length, 1, 'no second login');
    assert.equal(agent.items.length, 1);
    assert.equal(agent.items[0].username, 'alice@example.com');
  } finally {
    await page.close();
  }
});

/**
 * The middle of the callout's Copy button, found from the page's side: the callout lets every click
 * through but the button's, so the button is the only place in its caption row where the page's
 * elementFromPoint says the host.
 */
async function copyButtonCenter(page) {
  return page.evaluate(() => {
    const host = document.querySelector('pass-reveal');
    if (!host) return null;
    const { left, top } = host.getBoundingClientRect();
    const hits = [];
    for (let x = left; x < left + 500; x += 2) {
      if (document.elementFromPoint(x, top + 14) === host) hits.push(x);
    }
    return hits.length ? { x: (hits[0] + hits.at(-1)) / 2, y: top + 14, hits: hits.length } : null;
  });
}

test('a generated password shows once with Copy: the desktop app copies, an older one falls back, window.find finds nothing', { skip }, async () => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write'], { origin: base });
  const page = await freshPage();
  try {
    await page.click('#password');
    await waitFor(() => page.evaluate(() => !!document.querySelector('pass-menu')), { what: 'the generator menu' });
    await sleep(700);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await waitFor(async () => (await page.inputValue('#confirm')) === GENERATED, { what: 'the fill' });
    await waitFor(() => page.evaluate(() => !!document.querySelector('pass-reveal')), { what: 'the callout' });
    assert.equal(await page.evaluate(() => document.activeElement.id), 'confirm');
    assert.equal(await page.evaluate((text) => window.find(text) || window.find(text.slice(-8)) || document.body.innerText.includes(text), GENERATED), false, 'not findable');

    await sleep(700);
    const button = await copyButtonCenter(page);
    assert.ok(button?.hits > 2, 'Copy takes clicks');
    await page.mouse.click(button.x, button.y);
    await waitFor(() => callsOf('generate.copy').length, { what: 'generate.copy' });
    assert.deepEqual(callsOf('generate.copy'), [{ password: GENERATED }]);
    assert.ok(await page.evaluate(() => !!document.querySelector('pass-reveal')), 'the callout stays');
    assert.equal(await page.evaluate(() => document.activeElement.id), 'confirm', 'the field keeps the focus');
    assert.notEqual(new URL(page.url()).pathname, '/done', 'the form is not submitted');

    // A click on the callout beside the button goes to the page: a click elsewhere.
    const { left, top } = await page.evaluate(() => document.querySelector('pass-reveal').getBoundingClientRect().toJSON());
    await page.mouse.click(left + 4, top + 34);
    await waitFor(() => page.evaluate(() => !document.querySelector('pass-reveal')), { what: 'the callout to go' });
    await page.focus('#confirm');
    await sleep(300);
    assert.equal(await page.evaluate(() => !!document.querySelector('pass-reveal')), false, 'not shown again on refocus');
  } finally {
    await page.close();
  }

  const older = await freshPage();
  agent.olderApp = true;
  try {
    await older.click('#password');
    await waitFor(() => older.evaluate(() => !!document.querySelector('pass-menu')), { what: 'the generator menu' });
    await sleep(700);
    await older.keyboard.press('ArrowDown');
    await older.keyboard.press('Enter');
    await waitFor(() => older.evaluate(() => !!document.querySelector('pass-reveal')), { what: 'the callout' });
    await sleep(700);
    const button = await copyButtonCenter(older);
    await older.mouse.click(button.x, button.y);
    await waitFor(() => callsOf('generate.copy').length, { what: 'generate.copy' });
    await waitFor(async () => (await older.evaluate(() => navigator.clipboard.readText())) === GENERATED, { what: 'the clipboard' });
    assert.ok(await older.evaluate(() => !!document.querySelector('pass-reveal')), 'the callout stays');
    assert.equal(await older.evaluate(() => document.activeElement.id), 'confirm');
  } finally {
    agent.olderApp = false;
    await context.clearPermissions();
    await older.close();
  }
});

test('context menu "Generate password": shown and used for password fields only', { skip }, async () => {
  const page = await freshPage();
  const sw = await serviceWorker();
  const generateHere = () => sw.evaluate(async () => {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    return chrome.tabs.sendMessage(tab.id, { type: 'cmd.generate-here' }, { frameId: 0 });
  });
  try {
    // A plain text field: the item is hidden, and a stale click on it does nothing.
    await page.click('#bio', { button: 'right' });
    await page.keyboard.press('Escape');
    assert.deepEqual(await generateHere(), { ok: false });
    assert.equal(await page.inputValue('#bio'), '');
    assert.equal(callsOf('logins.create').length, 0);

    await page.click('#confirm', { button: 'right' });
    await page.keyboard.press('Escape');
    assert.deepEqual(await generateHere(), { ok: true });
    await waitFor(() => callsOf('logins.create').length, { what: 'logins.create' });
    assert.equal(await page.inputValue('#confirm'), GENERATED);
  } finally {
    await page.close();
  }
});
