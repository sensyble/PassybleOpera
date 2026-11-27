// End-to-end test of the in-browser vault: real Chromium, the real extension with the built WebAssembly (`npm run wasm`)
// and a throwaway profile without the Passyble app (connectNative answers "host not found", test/e2e/no-native-host.js),
// so nothing on this computer is started. Opt-in like otp.e2e.mjs. SHOTS=<dir> also saves screenshots.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
const built = existsSync(path.join(extRoot, 'src', 'wasm', 'pass_wasm_bg.wasm'));
const skip = !pw ? 'playwright is not installed (see the header of otp.e2e.mjs)' : !built ? 'src/wasm/ is not built (npm run wasm)' : false;
// A passphrase the master password rule accepts (pass-core's own tests use it).
const MASTER = 'correct-horse-battery-staple-orbit';
const SHOTS = process.env.SHOTS || '';

let server; let context; let dir; let base; let extId;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, { timeout = 10_000, what = 'condition' } = {}) {
  const end = Date.now() + timeout;
  let last;
  while (Date.now() < end) {
    try { last = await fn(); } catch (err) { last = String(err?.message || err); }
    if (last && !(typeof last === 'string' && /Error|closed/.test(last))) return last;
    await sleep(100);
  }
  throw new Error(`timed out waiting for ${what} (last: ${JSON.stringify(last)})`);
}

async function shot(page, name) {
  if (!SHOTS) return;
  mkdirSync(SHOTS, { recursive: true });
  await page.screenshot({ path: path.join(SHOTS, `${name}.png`), fullPage: true });
}

const extUrl = (p) => `chrome-extension://${extId}/${p}`;

/** An extension page to send background messages from (like the popup or Options do). */
let messenger;
async function bg(type, payload = {}) {
  const res = await messenger.evaluate(([t, p]) => chrome.runtime.sendMessage({ type: t, ...p }), [type, payload]);
  if (!res?.ok) throw Object.assign(new Error(res?.error?.message || 'no answer'), { code: res?.error?.code });
  return res.result;
}

before(async () => {
  if (skip) return;
  server = await startServer(new MockAgent([]));
  base = `http://login.example.localhost:${server.address().port}`;
  dir = mkdtempSync(path.join(tmpdir(), 'pass-e2e-vault-'));
  const extDir = path.join(dir, 'ext');
  for (const p of ['manifest.json', '_locales', 'src', 'icons']) cpSync(path.join(extRoot, p), path.join(extDir, p), { recursive: true });
  writeFileSync(path.join(extDir, 'src', 'e2e-no-native-host.js'), readFileSync(path.join(here, 'no-native-host.js'), 'utf8'));
  // Headless Chromium "opens" the toolbar popup without showing it: the small window instead.
  writeFileSync(path.join(extDir, 'src', 'e2e-no-popup.js'),
    "try { Object.defineProperty(chrome.action, 'openPopup', { value: undefined, configurable: true }); } catch { chrome.action.openPopup = undefined; }\n");
  writeFileSync(path.join(extDir, 'src', 'e2e-sw.js'), "import './e2e-no-native-host.js';\nimport './e2e-no-popup.js';\nimport './background.js';\n");
  const uiCommon = path.join(extDir, 'src', 'content', 'ui-common.js');
  const src = readFileSync(uiCommon, 'utf8');
  writeFileSync(uiCommon, src.replace("attachShadow({ mode: 'closed' })", "attachShadow({ mode: 'open' })"));
  const manifest = JSON.parse(readFileSync(path.join(extDir, 'manifest.json'), 'utf8'));
  manifest.background.service_worker = 'src/e2e-sw.js';
  writeFileSync(path.join(extDir, 'manifest.json'), JSON.stringify(manifest, null, 2));
  context = await pw.chromium.launchPersistentContext(path.join(dir, 'profile'), {
    channel: 'chromium',
    headless: !process.env.HEADED,
    acceptDownloads: true,
    viewport: { width: 1000, height: 820 },
    args: [`--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`],
  });
  const sw = context.serviceWorkers().find((w) => w.url().startsWith('chrome-extension://')) || await context.waitForEvent('serviceworker', { timeout: 10_000 });
  extId = new URL(sw.url()).host;
});

after(async () => {
  await context?.close();
  server?.close();
  if (dir) rmSync(dir, { recursive: true, force: true });
});

test('first run without the Passyble app: the setup guide asks, and a vault is created in this browser', { skip }, async () => {
  const welcome = await waitFor(() => context.pages().find((p) => p.url().includes('/src/welcome/welcome.html')), { what: 'the setup guide' });
  await welcome.bringToFront();
  await welcome.locator('#vault-choice').waitFor({ state: 'visible' });
  assert.equal(await welcome.locator('#setup').isHidden(), true, 'no app checklist without the app');
  await shot(welcome, 'welcome-choice');
  await welcome.click('#choose-create');
  await welcome.fill('#create-pw', MASTER);
  await welcome.fill('#create-pw2', MASTER);
  assert.equal(await welcome.textContent('#create-strength'), 'Strong');
  assert.match(await welcome.textContent('#create-local'), /Only on this device./);
  await shot(welcome, 'create-vault');
  await welcome.click('#create-submit');
  await welcome.locator('#vault-ready').waitFor({ state: 'visible', timeout: 15_000 });
  assert.equal(await welcome.inputValue('#create-pw'), '', 'the field is cleared');
  assert.equal(await welcome.textContent('#ready-notice-title'), 'This vault is only on this device');
  messenger = welcome;
  const state = await bg('vault.state');
  assert.equal(state.mode, 'browser');
  assert.equal(state.has_vault, true);
  assert.equal(state.locked, false);
  assert.deepEqual([state.local_only, state.reminder, state.drive_needs_app], [true, true, false]);
  const status = await bg('popup.status');
  assert.ok(status.features.includes('vault.browser'));
});

test('a login saved from the save prompt fills from the in-page menu', { skip }, async () => {
  const page = await context.newPage();
  await page.goto(`${base}/email/bootstrap`);
  // The content scripts start at document_idle: the Passyble icon in the field says they watch the form.
  await page.click('#inputEmail');
  await page.locator('pass-icon').first().waitFor({ state: 'attached', timeout: 10_000 }).catch(() => {});
  await sleep(500);
  await page.fill('#inputEmail', 'alice@example.com');
  await page.fill('#inputPassword', 'correct horse battery');
  await Promise.all([page.waitForURL(/\/done$/), page.click('button[type=submit]')]);
  const save = page.locator('pass-banner .btn.primary');
  await save.waitFor({ state: 'visible', timeout: 10_000 });
  await sleep(650);
  await save.click();
  await waitFor(async () => (await bg('popup.find', { url: `${base}/email/bootstrap` })).items.length === 1, { what: 'saved' });
  await page.goto(`${base}/email/bootstrap`);
  await page.click('#inputEmail');
  const entry = page.locator('pass-menu .item', { hasText: 'alice@example.com' }).first();
  await entry.waitFor({ state: 'visible', timeout: 10_000 });
  await sleep(650);
  await entry.click();
  await waitFor(() => page.inputValue('#inputPassword'), { what: 'password filled' });
  assert.equal(await page.inputValue('#inputPassword'), 'correct horse battery');
  // Two more logins of the site for the popup's list.
  const [tab] = await messenger.evaluate((u) => chrome.tabs.query({ url: u }), `${base.replace(/:\d+$/, '')}/*`);
  for (const [title, username] of [['Example (work)', 'alice@work.example'], ['Example (Bob)', 'bob@example.com']]) {
    await bg('popup.edit-save', { tabId: tab.id, fields: { title, username, password: `${username}-Pw-2026`, urls: [base] } });
  }
  const found = await bg('popup.find', { url: `${base}/email/bootstrap` });
  assert.equal(found.items.length, 3);
  await page.bringToFront();
  await shotPopup(tab.id, 'popup-unlocked');
  await page.close();
});

/** The popup page as the toolbar shows it, for the tab `tabId` (its tabs.query answers that tab). */
async function shotPopup(tabId, name, { theme = 'light', view = '#view-list' } = {}) {
  if (!SHOTS) return;
  const popup = await context.newPage();
  await popup.setViewportSize({ width: 360, height: 520 });
  await popup.emulateMedia({ colorScheme: theme });
  await popup.addInitScript((id) => {
    const query = chrome.tabs.query.bind(chrome.tabs);
    chrome.tabs.query = async (q) => (q?.active && q?.currentWindow ? [await chrome.tabs.get(id)] : query(q));
  }, tabId);
  await popup.goto(extUrl('src/popup/popup.html'));
  await popup.locator(view).waitFor({ state: 'visible', timeout: 10_000 });
  // The first popup's notice (the browser's own autofill turned off) goes away by itself.
  await waitFor(() => popup.evaluate(() => !document.getElementById('snack').classList.contains('show')), { timeout: 12_000, what: 'no notice' });
  await sleep(400);
  await popup.screenshot({ path: path.join(SHOTS, `${name}.png`) });
  await popup.close();
}

test('Options: where the vault is, "only on this device", and Download a copy', { skip }, async () => {
  const options = await context.newPage();
  await options.goto(extUrl('src/options/options.html#vault'));
  await options.locator('#vault').waitFor({ state: 'visible' });
  assert.equal(await options.textContent('#mode-name'), 'In this browser');
  assert.equal(await options.locator('#server').isHidden(), true, 'no Passyble Server card in browser mode');
  assert.equal(await options.textContent('#local-only-title'), 'This vault is only on this device');
  await shot(options, 'options-vault-light');
  await options.emulateMedia({ colorScheme: 'dark' });
  await sleep(400); // the buttons' colour transition
  await shot(options, 'options-vault-dark');
  await options.emulateMedia({ colorScheme: 'light' });
  const [download] = await Promise.all([options.waitForEvent('download'), options.click('#backup-download')]);
  const file = path.join(dir, 'backup.vault');
  await download.saveAs(file);
  assert.match(download.suggestedFilename(), /^Passyble-\d{4}-\d{2}-\d{2}\.vault$/);
  assert.ok(readFileSync(file).length > 200);
  await waitFor(async () => (await bg('vault.state')).backed_up_at > 0, { what: 'backed up' });
  await options.close();
});

test('lock, unlock, and a stopped service worker comes back unlocked (the key in storage.session)', { skip }, async () => {
  await bg('popup.lock');
  assert.equal((await bg('popup.status')).locked, true);
  const soft = await bg('popup.find', { url: `${base}/email/bootstrap` });
  assert.equal(soft.locked, true);
  assert.equal(soft.items.length, 3, 'a soft lock keeps the list (no secrets) for the menus');
  await assert.rejects(bg('popup.unlock-password', { password: 'wrong one' }), (err) => err.code === 'wrong_password');
  await bg('popup.unlock-password', { password: MASTER });
  assert.equal((await bg('popup.status')).locked, false);
  const cdp = await context.newCDPSession(messenger);
  await cdp.send('ServiceWorker.enable').catch(() => {});
  const stopWorker = async () => {
    await cdp.send('ServiceWorker.stopAllWorkers');
    await sleep(500);
    return waitFor(() => bg('popup.status'), { what: 'the service worker again' });
  };
  const status = await stopWorker();
  assert.equal(status.locked, false, 'unlocked again from the key in storage.session');
  const found = await bg('popup.find', { url: `${base}/email/bootstrap` });
  assert.equal(found.items.length, 3);
  assert.equal(found.locked, false);

  // Locked when the worker stops: the list kept by a soft lock is in its memory only, so fully locked after.
  await bg('popup.lock');
  assert.equal((await stopWorker()).locked, true);
  await assert.rejects(bg('popup.find', { url: `${base}/email/bootstrap` }), (err) => err.code === 'locked');
  if (SHOTS) {
    const page = await context.newPage();
    await page.goto(`${base}/email/bootstrap`);
    const [tab] = await messenger.evaluate((u) => chrome.tabs.query({ url: u }), 'http://login.example.localhost/*');
    await shotPopup(tab.id, 'popup-locked', { view: '#view-locked' });
    await shotPopup(tab.id, 'popup-locked-dark', { view: '#view-locked', theme: 'dark' });
    await page.close();
  }
  await bg('popup.unlock-password', { password: MASTER });
  assert.equal((await bg('popup.find', { url: `${base}/email/bootstrap` })).items.length, 3);
});

test('delete the vault (after the backup) and open it again from the backup file', { skip }, async () => {
  await assert.rejects(bg('vault.delete', { password: 'wrong one' }), (err) => err.code === 'wrong_password');
  const state = await bg('vault.delete', { password: MASTER });
  assert.equal(state.has_vault, false);
  assert.equal((await bg('popup.status')).vault, false);
  const welcome = await context.newPage();
  await welcome.goto(extUrl('src/welcome/welcome.html#open'));
  await welcome.locator('#vault-open').waitFor({ state: 'visible' });
  await welcome.setInputFiles('#open-file', path.join(dir, 'backup.vault'));
  await welcome.fill('#open-pw', 'not it');
  await welcome.click('#open-submit');
  await waitFor(async () => /Wrong master password/.test(await welcome.textContent('#open-msg')), { what: 'wrong password' });
  await welcome.fill('#open-pw', MASTER);
  await welcome.click('#open-submit');
  await welcome.locator('#vault-ready').waitFor({ state: 'visible', timeout: 15_000 });
  const found = await bg('popup.find', { url: `${base}/email/bootstrap` });
  assert.deepEqual(found.items.map((i) => i.username).sort(), ['alice@example.com', 'alice@work.example', 'bob@example.com']);
  await welcome.close();
});
