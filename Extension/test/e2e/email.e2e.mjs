// End-to-end test of e-mail sign-in fields (EMAIL_PAGES in pages.mjs). The autofocused e-mail field
// has focus before Passyble is there, so the suggestions must open without a click. Opt-in like
// otp.e2e.mjs.
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
const USER = 'alice@example.com';
const PASSWORD = 'correct horse';

const agent = new MockAgent([
  { id: 'ex', title: 'Example', username: USER, password: PASSWORD, urls: ['http://example.localhost'] },
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
  dir = mkdtempSync(path.join(tmpdir(), 'pass-e2e-email-'));
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

const has = (page, tag) => page.evaluate((t) => !!document.querySelector(t), tag);

async function open(variant, step = '') {
  agent.reset();
  const page = await context.newPage();
  await page.goto(`${base}/email/${variant}${step}`);
  return page;
}

/** The suggestions opened on their own for the autofocused field: ArrowDown + Enter picks the login. */
async function pickFromAutoMenu(page, selector) {
  await waitFor(() => has(page, 'pass-icon'), { what: 'Passyble icon' });
  await waitFor(() => has(page, 'pass-menu'), { what: 'suggestions opened for the autofocused field' });
  assert.equal(await page.evaluate(() => document.activeElement?.id), selector.slice(1), 'focus left where the page put it');
  assert.equal(await page.inputValue(selector), '', 'nothing filled before a pick');
  await sleep(400);
  await page.keyboard.press('ArrowDown');
  await page.keyboard.press('Enter');
}

const SINGLE_PAGE = {
  exact: '#inputEmail', bootstrap: '#inputEmail', floating: '#floatingInput', noname: '#inputEmail',
  'ac-email': '#inputEmail', 'ac-username': '#inputEmail',
};
const PASSWORD_FIELD = { floating: '#floatingPassword' };

for (const [variant, emailSel] of Object.entries(SINGLE_PAGE)) {
  test(`e-mail sign-in (${variant}): suggestions on the autofocused field; username and password filled`, { skip }, async () => {
    const page = await open(variant);
    const pwSel = PASSWORD_FIELD[variant] || '#inputPassword';
    try {
      await pickFromAutoMenu(page, emailSel);
      await waitFor(() => page.inputValue(pwSel), { what: 'password filled' });
      assert.equal(await page.inputValue(emailSel), USER);
      assert.equal(await page.inputValue(pwSel), PASSWORD);
      assert.ok(agent.calls.some((c) => c.method === 'logins.fill' && c.params.id === 'ex'));
    } finally {
      await page.close();
    }
  });
}

test('e-mail sign-in (exact): a click into the field after Esc, then ArrowDown, still fills', { skip }, async () => {
  const page = await open('exact');
  try {
    await waitFor(() => has(page, 'pass-menu'), { what: 'suggestions' });
    await page.keyboard.press('Escape');
    assert.equal(await has(page, 'pass-menu'), false, 'Esc closes them');
    await page.click('#inputPassword');
    await page.click('#inputEmail');
    await page.keyboard.press('ArrowDown');
    await waitFor(() => has(page, 'pass-menu'), { what: 'menu on ArrowDown' });
    await sleep(300);
    await page.keyboard.press('ArrowDown');
    await page.keyboard.press('Enter');
    await waitFor(() => page.inputValue('#inputPassword'), { what: 'password filled' });
    assert.equal(await page.inputValue('#inputEmail'), USER);
  } finally {
    await page.close();
  }
});

for (const variant of ['idfirst', 'idfirst-plain']) {
  test(`identifier-first (${variant}): the e-mail step gets the username only, the next step the password`, { skip }, async () => {
    const page = await open(variant);
    try {
      await pickFromAutoMenu(page, '#inputEmail');
      await waitFor(() => page.inputValue('#inputEmail'), { what: 'username filled' });
      assert.equal(await page.inputValue('#inputEmail'), USER);
      await page.click('button[type=submit]');
      await page.waitForURL(/\/password$/);
      await pickFromAutoMenu(page, '#inputPassword');
      await waitFor(() => page.inputValue('#inputPassword'), { what: 'password filled' });
      assert.equal(await page.inputValue('#inputPassword'), PASSWORD);
    } finally {
      await page.close();
    }
  });
}
