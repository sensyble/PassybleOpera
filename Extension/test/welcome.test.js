import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { setupSteps } from '../src/welcome/setup-steps.js';

const NOT_RUNNING = { error: { code: 'agent_unavailable', message: 'The Passyble desktop app is not running' } };
const HOST_MISSING = { error: { code: 'agent_unavailable', message: 'Specified native messaging host not found.' } };

const byId = (r) => Object.fromEntries(r.steps.map((s) => [s.id, s]));
const current = (r) => r.steps.find((s) => s.current)?.id;

test('steps: nothing known yet is "checking", with install as the current step', () => {
  const r = setupSteps({ agent: null });
  assert.equal(r.checking, true);
  assert.deepEqual(r.steps.map((s) => s.id), ['install', 'start', 'vault', 'pin']);
  assert.ok(r.steps.every((s) => !s.done));
  assert.equal(current(r), 'install');
  assert.equal(r.allDone, false);
});

test('steps: the browser has no native host for Passyble: install is to do (Firefox wording too)', () => {
  for (const agent of [HOST_MISSING, { error: { code: 'agent_unavailable', message: 'No such native application com.sensyble.pass' } }]) {
    const r = setupSteps({ agent });
    assert.equal(r.checking, false);
    assert.deepEqual(byId(r).install, { id: 'install', done: false, current: true, detail: 'missing' });
    assert.equal(byId(r).start.done, false);
    assert.equal(byId(r).vault.done, false);
  }
});

test('steps: host there, no agent (not running, or no vault yet): start is current', () => {
  const r = setupSteps({ agent: NOT_RUNNING });
  assert.equal(byId(r).install.done, true);
  assert.equal(byId(r).start.done, false);
  assert.equal(byId(r).start.detail, 'stopped');
  assert.equal(current(r), 'start');
});

test('steps: a status answer means running with a vault, locked or unlocked', () => {
  const locked = setupSteps({ agent: { status: { locked: true, version: '1.0.0' } } });
  assert.deepEqual(locked.steps.slice(0, 3).map((s) => [s.id, s.done, s.detail]), [['install', true, ''], ['start', true, ''], ['vault', true, 'locked']]);
  assert.equal(current(locked), 'pin');
  const unlocked = setupSteps({ agent: { status: { locked: false } } });
  assert.equal(byId(unlocked).vault.detail, 'unlocked');
});

test('steps: another error (a timeout while a Passyble dialog is open) means running, vault unknown', () => {
  const r = setupSteps({ agent: { error: { code: 'timeout', message: 'timed out' } } });
  assert.equal(byId(r).install.done, true);
  assert.equal(byId(r).start.done, true);
  assert.equal(byId(r).vault.done, false);
  assert.equal(current(r), 'vault');
});

test('steps: the website access step appears once access was missing, before pinning; all done', () => {
  const status = { status: { locked: false } };
  assert.ok(!setupSteps({ agent: status }).steps.some((s) => s.id === 'access'), 'not shown where access is granted');
  const r = setupSteps({ agent: status, accessNeeded: true, access: false, pinned: true });
  assert.deepEqual(r.steps.map((s) => s.id), ['install', 'start', 'vault', 'access', 'pin']);
  assert.equal(current(r), 'access');
  assert.equal(r.allDone, false);
  const granted = setupSteps({ agent: status, accessNeeded: true, access: true, pinned: true });
  assert.equal(byId(granted).access.done, true, 'stays listed, ticked off');
  assert.equal(granted.allDone, true);
  assert.equal(current(granted), undefined);
  assert.equal(setupSteps({ agent: status, pinned: false }).allDone, false, 'pinning is a step too');
});

const messages = [];
const created = [];
const stored = {};
const scheduled = []; // poll delays the page asked for
let reply = () => ({ ok: true, result: null });
let permissions = null; // { contains, request } or null (no permissions API)
let userSettings = null; // action.getUserSettings result, or null (no API)
let instance = 0;

const flush = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => { for (let i = 0; i < 6; i++) await flush(); };

async function openWelcome() {
  const html = readFileSync(new URL('../src/welcome/welcome.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/src/welcome/welcome.html', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  messages.length = 0;
  scheduled.length = 0;
  globalThis.chrome.permissions = permissions ?? undefined;
  globalThis.chrome.action = userSettings ? { getUserSettings: async () => userSettings } : {};
  await import(`../src/welcome/welcome.js?instance=${++instance}`);
  await settle();
  const document = dom.window.document;
  const $ = (id) => document.getElementById(id);
  /** The visible parts of a step: its state and which data-show parts are on screen. */
  const step = (id) => {
    const li = $(`step-${id}`);
    return { hidden: li.hidden, state: li.dataset.state, shown: [...li.querySelectorAll('[data-show]')].filter((p) => !p.hidden).map((p) => p.dataset.show) };
  };
  return { window: dom.window, document, $, step };
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      getManifest: () => ({ version: '1.2.3', host_permissions: ['<all_urls>'] }),
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
    },
    tabs: { create: async (o) => { created.push(o); } },
    storage: { local: { get: async (k) => (k in stored ? { [k]: stored[k] } : {}), set: async (o) => { Object.assign(stored, o); } } },
    commands: { getAll: async () => [
      { name: '_execute_action', shortcut: 'Alt+Shift+P' },
      { name: 'fill-login', shortcut: 'Ctrl+Shift+L' },
      { name: 'fill-otp', shortcut: '' },
    ] },
  };
  // The page polls every few seconds: record those timers instead of running them (each test pokes
  // the page itself), so old page instances stay quiet and the process can exit.
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (fn, ms, ...args) => {
    if (ms >= 1000) { scheduled.push(ms); return { unref() {} }; }
    return realSetTimeout(fn, ms, ...args);
  };
});

const answer = (status) => (msg) => {
  if (msg.type === 'popup.status') return status;
  return { ok: true, result: null };
};
const asReply = (agent) => ('status' in agent ? { ok: true, result: agent.status } : { ok: false, error: agent.error });

test('page: Passyble not installed: download link and Try again; nothing else asks for a click', async () => {
  reply = answer(asReply(HOST_MISSING));
  const { $, step, document } = await openWelcome();
  assert.equal(document.title, 'Welcome to Passyble');
  assert.deepEqual(step('install'), { hidden: false, state: 'current', shown: ['active', 'active'] });
  const download = $('download');
  assert.equal(download.href, 'https://github.com/sensyble/pass-releases/releases/latest');
  assert.equal(download.target, '_blank');
  assert.match(download.rel, /noopener/);
  assert.equal(download.textContent.trim(), 'Download');
  assert.match($('step-install').textContent, /Installed\? Open it, then try again\./);
  assert.deepEqual(step('start'), { hidden: false, state: 'todo', shown: [] }, 'no Start button before Passyble is installed');
  assert.deepEqual(step('vault'), { hidden: false, state: 'todo', shown: [] });
  assert.equal(step('access').hidden, true, 'Chrome: access is granted at install');
  assert.equal($('all-set').hidden, true);
  assert.deepEqual(scheduled, [3000], 'asks again in a few seconds');

  // Installed meanwhile: Try again asks at once and ticks it off.
  reply = answer(asReply(NOT_RUNNING));
  const before = messages.filter((m) => m.type === 'popup.status').length;
  $('retry').click();
  await settle();
  assert.equal(messages.filter((m) => m.type === 'popup.status').length, before + 1);
  assert.equal(step('install').state, 'done');
  assert.deepEqual(step('install').shown, []);
  assert.equal($('step-install').querySelector('[data-step-state]').textContent, 'Done', 'for screen readers');
  assert.equal(step('start').state, 'current');
});

test('page: Passyble not running (or no vault yet): Start Passyble, the no-vault hint, then it ticks off', async () => {
  let started = false;
  reply = (msg) => {
    if (msg.type === 'popup.start') { started = true; return { ok: true, result: { locked: true } }; }
    if (msg.type === 'popup.status') return started ? { ok: true, result: { locked: true } } : asReply(NOT_RUNNING);
    return { ok: true, result: null };
  };
  const { $, step } = await openWelcome();
  assert.equal(step('install').state, 'done');
  assert.deepEqual(step('start'), { hidden: false, state: 'current', shown: ['active', 'active'] });
  assert.match($('step-start').textContent, /It connects once it has a vault/);
  assert.equal($('start').textContent.trim(), 'Start Passyble');
  assert.equal($('check-status').textContent, '', 'not running is the step itself, not an error line');

  $('start').click();
  assert.equal($('start').disabled, true);
  assert.equal($('start').textContent.trim(), 'Starting Passyble…');
  assert.equal($('start-msg').textContent, 'This can take a few seconds.');
  await settle();
  assert.ok(messages.some((m) => m.type === 'popup.start'));
  assert.equal($('start').disabled, false);
  assert.equal(step('start').state, 'done');
  assert.equal(step('vault').state, 'done');
  assert.deepEqual(step('vault').shown, []);
  assert.equal(step('pin').state, 'current');
});

test('page: Start Passyble that does not get it up says what to do', async () => {
  reply = (msg) => (msg.type === 'popup.start' || msg.type === 'popup.status' ? asReply(NOT_RUNNING) : { ok: true, result: null });
  const { $, step } = await openWelcome();
  $('start').click();
  await settle();
  assert.match($('start-msg').textContent, /Open Passyble from the Start menu/);
  assert.equal(step('start').state, 'current');
});

test('page: first answer pending: "Checking…", no buttons for the app steps; pinning can be done already', async () => {
  let release;
  reply = (msg) => (msg.type === 'popup.status' ? new Promise((r) => { release = r; }) : { ok: true, result: null });
  const { $, step } = await openWelcome();
  assert.equal($('check-status').textContent, 'Checking…');
  assert.deepEqual(step('install').shown, [], 'no download button while checking');
  assert.ok(step('pin').shown.includes('active'), 'the pin checkbox is there');
  release({ ok: true, result: { locked: false } });
  await settle();
  assert.equal($('check-status').textContent, '');
  assert.deepEqual(step('vault').shown, []);
});

test('page: other errors show a friendly line and keep the steps', async () => {
  reply = answer({ ok: false, error: { code: 'timeout', message: 'Request timed out' } });
  const { $, step } = await openWelcome();
  assert.match($('check-status').textContent, /didn't answer/);
  assert.equal(step('start').state, 'done');
  assert.equal(step('vault').state, 'current');
});

test('page: pinning: ticked by hand (stored), or detected by action.getUserSettings; then all set', async () => {
  reply = answer({ ok: true, result: { locked: false } });
  delete stored.guidePinned;
  let page = await openWelcome();
  assert.equal(page.step('pin').state, 'current');
  assert.match(page.$('pin-how').textContent, /puzzle piece in the toolbar, then the pin next to Passyble/, 'Chrome wording');
  assert.equal(page.$('all-set').hidden, true);
  page.$('pin-done').checked = true;
  page.$('pin-done').dispatchEvent(new page.window.Event('change'));
  await settle();
  assert.equal(stored.guidePinned, true, 'only the tick is stored');
  assert.equal(page.step('pin').state, 'done');
  assert.equal(page.$('all-set').hidden, false);
  assert.equal(page.$('all-set').querySelector('h3').textContent, "You're all set");
  assert.equal(scheduled.at(-1), 15000, 'all done: asks less often');

  delete stored.guidePinned;
  userSettings = { isOnToolbar: true };
  page = await openWelcome();
  assert.equal(page.step('pin').state, 'done', 'Chrome tells whether it is on the toolbar');
  assert.equal(page.$('all-set').hidden, false);
  userSettings = { isOnToolbar: false };
  page = await openWelcome();
  assert.equal(page.step('pin').state, 'current');
  userSettings = null;
});

test('page: Edge gets its own pinning words', async () => {
  reply = answer(asReply(NOT_RUNNING));
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'navigator', { value: { userAgent: 'Mozilla/5.0 Chrome/130.0 Safari/537.36 Edg/130.0' }, configurable: true });
  try {
    const { $ } = await openWelcome();
    assert.match($('pin-how').textContent, /eye next to Passyble/);
  } finally {
    if (saved) Object.defineProperty(globalThis, 'navigator', saved);
    else delete globalThis.navigator;
  }
});

test('page: Opera gets its own pinning words (the cube, not the puzzle piece)', async () => {
  reply = answer(asReply(NOT_RUNNING));
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
  Object.defineProperty(globalThis, 'navigator', { value: { userAgent: 'Mozilla/5.0 Chrome/130.0 Safari/537.36 OPR/115.0' }, configurable: true });
  try {
    const { $ } = await openWelcome();
    assert.match($('pin-how').textContent, /cube in the toolbar/);
  } finally {
    if (saved) Object.defineProperty(globalThis, 'navigator', saved);
    else delete globalThis.navigator;
  }
});

test('page: website access limited: an Allow step that asks with the manifest host permissions', async () => {
  reply = answer({ ok: true, result: { locked: false } });
  stored.guidePinned = true;
  let granted = false;
  const requests = [];
  permissions = {
    contains: async () => granted,
    request: (p) => { requests.push(p); granted = true; return Promise.resolve(true); },
    onAdded: { addListener: () => {} },
  };
  const { $, step } = await openWelcome();
  assert.deepEqual(step('access'), { hidden: false, state: 'current', shown: ['active'] });
  assert.equal($('all-set').hidden, true);
  $('allow-access').click();
  assert.deepEqual(requests, [{ origins: ['<all_urls>'] }], 'asked right in the click (user gesture)');
  await settle();
  assert.equal(step('access').hidden, false, 'stays listed');
  assert.equal(step('access').state, 'done');
  assert.equal($('all-set').hidden, false);

  // Declined: says where else to turn it on, in this browser's words (Chrome here; Firefox in
  // welcome-firefox.test.js).
  granted = false;
  permissions.request = () => Promise.resolve(false);
  const page = await openWelcome();
  page.$('allow-access').click();
  await settle();
  assert.equal(page.$('access-msg').textContent, 'Not allowed. Turn it on in chrome://extensions → Passyble → Site access.');
  assert.doesNotMatch(page.$('access-msg').textContent, /about:addons/);
  permissions = null;
  delete stored.guidePinned;
});

for (const [browser, nav, page] of [
  ['Edge', { userAgent: 'Mozilla/5.0 Chrome/130.0 Safari/537.36 Edg/130.0' }, 'edge://extensions'],
  ['Brave', { userAgent: 'Mozilla/5.0 Chrome/130.0 Safari/537.36', brave: { isBrave: async () => true } }, 'brave://extensions'],
  ['Brave (brands)', { userAgent: 'Mozilla/5.0 Chrome/130.0 Safari/537.36', userAgentData: { brands: [{ brand: 'Brave', version: '130' }] } }, 'brave://extensions'],
  ['Opera', { userAgent: 'Mozilla/5.0 Chrome/130.0 Safari/537.36 OPR/115.0' }, 'opera://extensions'],
  ['Opera GX (brands)', { userAgent: 'Mozilla/5.0 Chrome/130.0 Safari/537.36', userAgentData: { brands: [{ brand: 'Opera GX', version: '115' }] } }, 'opera://extensions'],
]) {
  test(`page: website access declined in ${browser}: its own extensions page`, async () => {
    reply = answer({ ok: true, result: { locked: false } });
    permissions = { contains: async () => false, request: () => Promise.resolve(false), onAdded: { addListener: () => {} } };
    const saved = Object.getOwnPropertyDescriptor(globalThis, 'navigator');
    Object.defineProperty(globalThis, 'navigator', { value: nav, configurable: true });
    try {
      const { $ } = await openWelcome();
      $('allow-access').click();
      await settle();
      assert.equal($('access-msg').textContent, `Not allowed. Turn it on in ${page} → Passyble → Site access.`);
    } finally {
      if (saved) Object.defineProperty(globalThis, 'navigator', saved);
      else delete globalThis.navigator;
      permissions = null;
    }
  });
}

test('page: no how-to cards, one link to the help center, and settings', async () => {
  reply = answer(asReply(NOT_RUNNING));
  const { $, document } = await openWelcome();
  assert.equal(document.querySelector('.tip, #tips, #shortcuts'), null, 'how-tos and shortcuts are on the site and in Options');
  assert.equal($('guides').href, 'https://help.passyble.com/');
  assert.equal($('guides').textContent.trim(), 'How to use Passyble');
  assert.equal($('guides').target, '_blank');
  assert.match($('guides').rel, /noopener/);
  assert.ok($('open-settings').href.endsWith('/src/options/options.html'));
  assert.ok(document.querySelector('.page-head svg.pass-logo'));
  assert.equal(document.querySelector('footer.credit a').href, 'https://www.sensyble.net/');
});
