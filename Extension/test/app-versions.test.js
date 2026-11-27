import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  Platform, STORE_URLS, UPDATE_GATE_KEY, allowedWhileReadOnly, chromiumPlatform, cleanMessage, compareVersions,
  detectPlatform, evaluateVersions, extensionBlocked, gateBlocks, parseOwnVersion, parseVersion,
} from '../src/shared/app-versions.js';
import {
  CACHE_KEY, CHECK_PERIOD_MIN, DISMISSED_KEY, TRIED_KEY, VERSIONS_ALARM, VERSIONS_URL, applyUpdate, createVersionCheck, storeUrl,
} from '../src/background/app-versions.js';

const CHROME_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36';
const brands = (...names) => ({ brands: names.map((brand) => ({ brand, version: '131' })) });

test('detect: Chrome, and Brave and other Chromium browsers count as Chrome', async () => {
  const chromium = { runtime: {} };
  assert.equal(await detectPlatform({ api: chromium, nav: { userAgent: CHROME_UA, userAgentData: brands('Google Chrome', 'Chromium', 'Not_A Brand') } }), Platform.CHROME);
  assert.equal(await detectPlatform({ api: chromium, nav: { userAgent: CHROME_UA, brave: {}, userAgentData: brands('Brave', 'Chromium', 'Not_A Brand') } }), Platform.CHROME);
  assert.equal(await detectPlatform({ api: chromium, nav: { userAgent: CHROME_UA, userAgentData: brands('Vivaldi', 'Chromium') } }), Platform.CHROME);
  assert.equal(await detectPlatform({ api: chromium, nav: { userAgent: CHROME_UA } }), Platform.CHROME, 'no userAgentData');
  assert.equal(await detectPlatform({ api: chromium, nav: undefined }), Platform.CHROME, 'nothing known');
});

test('detect: Edge by its brand, else the Edg/ token', async () => {
  const api = { runtime: {} };
  assert.equal(await detectPlatform({ api, nav: { userAgent: CHROME_UA, userAgentData: brands('Microsoft Edge', 'Chromium', 'Not_A Brand') } }), Platform.EDGE);
  assert.equal(await detectPlatform({ api, nav: { userAgent: `${CHROME_UA} Edg/131.0.0.0` } }), Platform.EDGE, 'UA fallback');
  assert.equal(chromiumPlatform({ userAgent: `${CHROME_UA} Edg/131.0.0.0`, userAgentData: { brands: [] } }), Platform.EDGE, 'empty brands: the UA');
});

test('detect: Opera (and Opera GX) by its brand, else the OPR/ token', async () => {
  const api = { runtime: {} };
  assert.equal(await detectPlatform({ api, nav: { userAgent: CHROME_UA, userAgentData: brands('Opera', 'Chromium', 'Not_A Brand') } }), Platform.OPERA);
  assert.equal(await detectPlatform({ api, nav: { userAgent: CHROME_UA, userAgentData: brands('Opera GX', 'Chromium') } }), Platform.OPERA);
  assert.equal(await detectPlatform({ api, nav: { userAgent: `${CHROME_UA} OPR/115.0.0.0` } }), Platform.OPERA, 'UA fallback');
});

test('detect: Firefox by runtime.getBrowserInfo, whatever the user agent says', async () => {
  let asked = 0;
  const firefox = { runtime: { getBrowserInfo: async () => { asked++; return { name: 'Firefox', vendor: 'Mozilla', version: '140.0' }; } } };
  assert.equal(await detectPlatform({ api: firefox, nav: { userAgent: 'Mozilla/5.0 (Windows NT 10.0; rv:140.0) Gecko/20100101 Firefox/140.0' } }), Platform.FIREFOX);
  assert.equal(asked, 1);
  const failing = { runtime: { getBrowserInfo: async () => { throw new Error('nope'); } } };
  assert.equal(await detectPlatform({ api: failing, nav: { userAgent: CHROME_UA } }), Platform.FIREFOX, 'only Gecko has the method');
});

test('store pages: one per browser, Chrome for anything unknown', () => {
  assert.equal(storeUrl(Platform.CHROME), 'https://chromewebstore.google.com/search/Passyble');
  assert.equal(storeUrl(Platform.EDGE), 'https://microsoftedge.microsoft.com/addons/search/Passyble');
  assert.equal(storeUrl(Platform.FIREFOX), 'https://addons.mozilla.org/firefox/addon/passyble/');
  assert.equal(storeUrl(Platform.OPERA), 'https://addons.opera.com/en/search/?query=Passyble');
  assert.equal(storeUrl('extension-safari'), STORE_URLS[Platform.CHROME]);
  for (const url of Object.values(STORE_URLS)) assert.match(url, /^https:\/\//);
});

test('versions: MAJOR.MINOR.PATCH compared numerically, -prerelease and +build ignored', () => {
  assert.deepEqual(parseVersion('1.2.3'), [1, 2, 3]);
  assert.deepEqual(parseVersion('1.2.3-beta.1'), [1, 2, 3]);
  assert.deepEqual(parseVersion('1.2.3+build.7'), [1, 2, 3]);
  assert.deepEqual(parseVersion('1.2.3-rc.1+exp.sha.5114f85'), [1, 2, 3]);
  assert.equal(compareVersions([0, 10, 0], [0, 9, 9]), 1, '10 > 9, not "1" < "9"');
  assert.equal(compareVersions([1, 2, 3], [1, 2, 3]), 0);
  assert.equal(compareVersions([1, 2, 3], [1, 3, 0]), -1);
  for (const bad of ['1.2', '1.2.3.4', 'v1.2.3', ' 1.2.3', '1.2.x', '', '1..3', '-1.2.3', '1.2.3-', null, 3, {}, ['1.2.3'], '1.2.3 <b>']) {
    assert.equal(parseVersion(bad), null, String(bad));
  }
  // The extension's own manifest version: 1 to 4 numbers.
  assert.deepEqual(parseOwnVersion('0.1.0'), [0, 1, 0]);
  assert.deepEqual(parseOwnVersion('2.5'), [2, 5, 0]);
  assert.deepEqual(parseOwnVersion('1.2.3.4'), [1, 2, 3]);
  assert.deepEqual(parseOwnVersion('1.2.3-beta'), [1, 2, 3]);
  assert.equal(parseOwnVersion(''), null);
  assert.equal(parseOwnVersion(undefined), null);
});

const answer = (entry, platform = Platform.CHROME) => ({ v: 1, platforms: { windows: { minimum: '9.9.9' }, [platform]: entry } });

test('evaluate: below the minimum is required, between minimum and recommended is the banner', () => {
  assert.deepEqual(evaluateVersions(answer({ minimum: '0.2.0', recommended: '0.3.0', message: 'Security fix' }), Platform.CHROME, '0.1.0'),
    { required: true, recommended: false, minimum: '0.2.0', recommendedVersion: '0.3.0', message: 'Security fix' });
  assert.deepEqual(evaluateVersions(answer({ minimum: '0.1.0', recommended: '0.3.0' }), Platform.CHROME, '0.1.0'),
    { required: false, recommended: true, minimum: '0.1.0', recommendedVersion: '0.3.0', message: '' });
  assert.equal(evaluateVersions(answer({ minimum: '0.1.0', recommended: '0.1.0' }), Platform.CHROME, '0.1.0').recommended, false, 'at the recommended version');
  assert.equal(evaluateVersions(answer({ minimum: '0.2.0' }, Platform.EDGE), Platform.CHROME, '0.1.0').required, false, 'another browser\'s minimum');
  assert.equal(evaluateVersions(answer({ minimum: '0.2.0' }, Platform.EDGE), Platform.EDGE, '0.1.0').required, true);
});

test('evaluate: prerelease and build suffixes on either side are ignored', () => {
  assert.equal(evaluateVersions(answer({ minimum: '0.2.0-beta.1' }), Platform.CHROME, '0.2.0').required, false, '0.2.0 is not below 0.2.0-beta');
  assert.equal(evaluateVersions(answer({ minimum: '0.2.0+build.9' }), Platform.CHROME, '0.1.9').required, true);
  assert.equal(evaluateVersions(answer({ minimum: '0.2.0' }), Platform.CHROME, '0.2.0-rc.1').required, false, 'own prerelease counts as the release');
  assert.equal(evaluateVersions(answer({ minimum: '0.2.0' }), Platform.CHROME, '0.1.9-rc.1').required, true);
});

test('evaluate: missing, null and malformed values are no requirement, never a block', () => {
  const none = { required: false, recommended: false, minimum: null, recommendedVersion: null, message: '' };
  for (const entry of [undefined, null, {}, { minimum: null, recommended: null }, { minimum: 'soon' }, { minimum: '1.2' },
    { minimum: 99 }, { minimum: ['9.9.9'] }, { minimum: { major: 9 } }, { minimum: '<script>9.9.9' }, [], 'x']) {
    assert.deepEqual(evaluateVersions(answer(entry), Platform.CHROME, '0.1.0'), none, JSON.stringify(entry));
  }
  for (const data of [null, undefined, 'x', [], {}, { v: 2, platforms: { [Platform.CHROME]: { minimum: '9.9.9' } } },
    { v: '1', platforms: { [Platform.CHROME]: { minimum: '9.9.9' } } }, { v: 1 }, { v: 1, platforms: [] }, { v: 1, platforms: null }]) {
    assert.deepEqual(evaluateVersions(data, Platform.CHROME, '0.1.0'), none, JSON.stringify(data));
  }
  assert.deepEqual(evaluateVersions(answer({ minimum: '9.9.9' }), Platform.CHROME, ''), none, 'own version unknown');
  assert.deepEqual(evaluateVersions(answer({ minimum: '9.9.9' }), null, '0.1.0'), none, 'no platform (Safari)');
  // A malformed minimum doesn't take the recommended version along with it.
  assert.equal(evaluateVersions(answer({ minimum: 'x', recommended: '0.3.0' }), Platform.CHROME, '0.1.0').recommended, true);
  // Inherited properties are not platforms.
  assert.deepEqual(evaluateVersions({ v: 1, platforms: {} }, 'toString', '0.1.0'), none);
});

test('message: plain text, control characters dropped, trimmed to 280 characters', () => {
  assert.equal(cleanMessage('  Please update.  '), 'Please update.');
  assert.equal(cleanMessage('<b>bold</b> & <img src=x onerror=alert(1)>'), '<b>bold</b> & <img src=x onerror=alert(1)>', 'kept as text (shown with textContent)');
  assert.equal(cleanMessage('a\u0000b\u0007c\r\nd'), 'a b c\nd');
  assert.equal(Array.from(cleanMessage('é'.repeat(400))).length, 280);
  assert.equal(Array.from(cleanMessage('😀'.repeat(300))).length, 280, 'no surrogate pair cut in half');
  assert.equal(cleanMessage(42), '');
  assert.equal(cleanMessage(null), '');
});

test('gate: blocks only the exact version it was decided for (an update clears it at once)', () => {
  const gate = { required: true, version: '0.1.0' };
  assert.equal(gateBlocks(gate, '0.1.0'), true);
  assert.equal(gateBlocks(gate, '0.2.0'), false, 'updated since');
  assert.equal(gateBlocks({ ...gate, required: false }, '0.1.0'), false);
  assert.equal(gateBlocks({ required: 'true', version: '0.1.0' }, '0.1.0'), false);
  assert.equal(gateBlocks(null, '0.1.0'), false);
  assert.equal(gateBlocks(gate, ''), false);
});

test('extensionBlocked reads the stored gate with the manifest version; no manifest or storage: never', async () => {
  const api = (gate, version = '0.1.0') => ({
    runtime: { getManifest: () => ({ version }) },
    storage: { local: { get: async (key) => ({ [key]: gate }) } },
  });
  assert.equal(await extensionBlocked(api({ required: true, version: '0.1.0' })), true);
  assert.equal(await extensionBlocked(api({ required: true, version: '0.1.0' }, '0.2.0')), false);
  assert.equal(await extensionBlocked(api(undefined)), false);
  assert.equal(await extensionBlocked({ storage: { local: { get: async () => ({ [UPDATE_GATE_KEY]: { required: true, version: '0.1.0' } }) } } }), false);
  assert.equal(await extensionBlocked({ runtime: { getManifest: () => ({ version: '0.1.0' }) }, storage: { local: { get: async () => { throw new Error('gone'); } } } }), false);
});

test('read-only methods: the desktop contract\'s list, cards.fill only as a copy', () => {
  for (const m of ['status', 'unlock', 'unlock.options', 'unlock.password', 'unlock.hello', 'unlock.cancel', 'lock', 'logins.search',
    'logins.copy', 'cards.list', 'identities.list', 'notes.list', 'notes.get', 'app.show_item', 'icons.get', 'password.check', 'generate', 'generate.options',
    'generate.username', 'generate.copy', 'account.status', 'app.show_account']) assert.equal(allowedWhileReadOnly(m, {}), true, m);
  for (const m of ['logins.find', 'logins.fill', 'logins.fill_cross', 'logins.save', 'logins.save_check', 'logins.get_for_edit', 'logins.update',
    'logins.create', 'logins.delete', 'logins.restore', 'totp.get', 'totp.popup', 'totp.set', 'totp.from_image', 'otp.outcome', 'cards.fill',
    'identities.fill', 'passkey.find', 'passkey.create_options', 'passkey.create', 'passkey.get', 'server.pair', 'generate.email', 'some.future']) {
    assert.equal(allowedWhileReadOnly(m, { url: 'https://x.test/' }), false, m);
  }
  assert.equal(allowedWhileReadOnly('cards.fill', { purpose: 'copy', field: 'number' }), true);
  assert.equal(allowedWhileReadOnly('cards.fill', { purpose: 'copy' }), false, 'a copy names its field');
  assert.equal(allowedWhileReadOnly('cards.fill', { purpose: 'fill', field: 'number' }), false);
});

function fakeExt({ store = {} } = {}) {
  const created = [];
  const writes = [];
  return {
    store, created, writes,
    storage: {
      local: {
        get: async (key) => (Object.hasOwn(store, key) ? { [key]: structuredClone(store[key]) } : {}),
        set: async (obj) => { writes.push(obj); Object.assign(store, structuredClone(obj)); },
      },
    },
    alarms: { get: async (name) => created.find((a) => a[0] === name), create: async (name, info) => { created.push([name, info]); } },
  };
}

const ok = (data) => async () => ({ ok: true, status: 200, text: async () => JSON.stringify(data) });
const MIN_020 = { v: 1, platforms: { [Platform.CHROME]: { minimum: '0.2.0', recommended: '0.3.0', message: 'Please update.' } } };

function makeCheck({ ext = fakeExt(), fetch, version = '0.1.0', platform = Platform.CHROME, now = () => 1_000_000, timeoutMs } = {}) {
  const calls = [];
  const check = createVersionCheck({
    ext,
    version: () => version,
    platform: async () => platform,
    fetch: async (url, init) => { calls.push([url, init]); return fetch(url, init); },
    now,
    ...(timeoutMs ? { timeoutMs } : {}),
  });
  return { check, calls, ext };
}

test('check: a good answer is cached with its time and decides the gate', async () => {
  const { check, calls, ext } = makeCheck({ fetch: ok(MIN_020) });
  const gate = await check.check();
  assert.equal(gate.required, true);
  assert.equal(gate.message, 'Please update.');
  assert.equal(await check.blocked(), true);
  assert.deepEqual(ext.store[CACHE_KEY], { at: 1_000_000, data: MIN_020 });
  assert.deepEqual(ext.store[TRIED_KEY], { at: 1_000_000, ok: true });
  assert.deepEqual(ext.store[UPDATE_GATE_KEY], { required: true, recommended: false, minimum: '0.2.0', recommendedVersion: '0.3.0',
    message: 'Please update.', version: '0.1.0', platform: Platform.CHROME, fetchedAt: 1_000_000 });
  // The request: the fixed address, nothing about the user, no cookies, no referrer.
  assert.equal(calls.length, 1);
  const [url, init] = calls[0];
  assert.equal(url, VERSIONS_URL);
  assert.equal(url, 'https://account.passyble.com/api/app-versions');
  assert.equal(init.method, 'GET');
  assert.equal(init.credentials, 'omit');
  assert.equal(init.referrerPolicy, 'no-referrer');
  assert.equal(init.headers, undefined, 'no headers of its own');
  assert.equal(init.body, undefined);
  assert.ok(init.signal instanceof AbortSignal);
});

test('check: a failed fetch keeps the cached answer', async () => {
  const ext = fakeExt({ store: { [CACHE_KEY]: { at: 5, data: MIN_020 } } });
  for (const fetch of [async () => { throw new TypeError('Failed to fetch'); }, async () => ({ ok: false, status: 503, text: async () => '' }),
    async () => ({ ok: true, status: 200, text: async () => 'not json' }), ok({ v: 2, platforms: {} })]) {
    const { check } = makeCheck({ ext, fetch });
    const gate = await check.check();
    assert.equal(gate.required, true, 'the cached minimum still applies');
    assert.equal(gate.fetchedAt, 5);
    assert.deepEqual(ext.store[CACHE_KEY], { at: 5, data: MIN_020 }, 'the bad answer is not cached');
    assert.equal(ext.store[TRIED_KEY].ok, false);
  }
});

test('check: with nothing ever fetched, a failure never blocks', async () => {
  const { check, ext } = makeCheck({ fetch: async () => { throw new TypeError('offline'); } });
  const gate = await check.check();
  assert.equal(gate.required, false);
  assert.equal(gate.recommended, false);
  assert.equal(await check.blocked(), false);
  assert.equal(ext.store[CACHE_KEY], undefined);
});

test('check: malformed server values are ignored (no block), the rest of the answer still counts', async () => {
  const data = { v: 1, platforms: { [Platform.CHROME]: { minimum: 'latest', recommended: '0.3.0', message: 7 } } };
  const { check } = makeCheck({ fetch: ok(data) });
  const gate = await check.check();
  assert.equal(gate.required, false);
  assert.equal(gate.recommended, true);
  assert.equal(gate.message, '');
});

test('check: prerelease versions on the server and in the manifest', async () => {
  const data = { v: 1, platforms: { [Platform.CHROME]: { minimum: '0.2.0-beta.2', recommended: '0.2.1+build.5' } } };
  assert.equal((await makeCheck({ fetch: ok(data), version: '0.2.0' }).check.check()).required, false);
  assert.equal((await makeCheck({ fetch: ok(data), version: '0.2.0' }).check.check()).recommended, true);
  assert.equal((await makeCheck({ fetch: ok(data), version: '0.1.5-beta' }).check.check()).required, true);
});

test('check: no answer within the timeout aborts the request (then the cache, or nothing)', async () => {
  let aborted = false;
  const hang = (url, init) => new Promise((resolve, reject) => {
    init.signal.addEventListener('abort', () => { aborted = true; reject(new DOMException('aborted', 'AbortError')); });
  });
  const { check } = makeCheck({ fetch: hang, timeoutMs: 20 });
  const gate = await check.check();
  assert.equal(aborted, true);
  assert.equal(gate.required, false);
});

test('check: 10 s is the default timeout', async () => {
  const { FETCH_TIMEOUT_MS } = await import('../src/background/app-versions.js');
  assert.equal(FETCH_TIMEOUT_MS, 10_000);
});

test('check: one fetch at a time; no version (tests, odd builds) means no check at all', async () => {
  let release;
  const { check, calls } = makeCheck({ fetch: () => new Promise((r) => { release = () => r({ ok: true, status: 200, text: async () => JSON.stringify(MIN_020) }); }) });
  const a = check.check();
  const b = check.check();
  await new Promise((r) => setTimeout(r, 0));
  release();
  await Promise.all([a, b]);
  assert.equal(calls.length, 1);
  const none = makeCheck({ fetch: ok(MIN_020), version: '' });
  await none.check.start();
  assert.equal((await none.check.check()).required, false);
  assert.equal(none.calls.length, 0);
  assert.equal(none.ext.created.length, 0);
  assert.deepEqual(none.ext.writes, []);
});

test('start: the cached decision at once, the 6-hour alarm once, a fetch only when one is due', async () => {
  let t = 10 * 3600_000;
  const ext = fakeExt({ store: { [CACHE_KEY]: { at: 1, data: MIN_020 } } });
  const { check, calls } = makeCheck({ ext, fetch: ok(MIN_020), now: () => t });
  await check.start();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(await check.blocked(), true, 'decided from the cache');
  assert.deepEqual(ext.created, [[VERSIONS_ALARM, { delayInMinutes: CHECK_PERIOD_MIN, periodInMinutes: CHECK_PERIOD_MIN }]]);
  assert.equal(CHECK_PERIOD_MIN, 360);
  assert.equal(calls.length, 1, 'never tried: fetched');
  // The background starts again an hour later: no new alarm, no fetch yet.
  t += 3600_000;
  const again = makeCheck({ ext, fetch: ok(MIN_020), now: () => t });
  await again.check.start();
  assert.equal(ext.created.length, 1);
  assert.equal(again.calls.length, 0);
  // Six hours after the last try: due.
  t += 5 * 3600_000;
  const later = makeCheck({ ext, fetch: ok(MIN_020), now: () => t });
  await later.check.start();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(later.calls.length, 1);
  later.check.onAlarm({ name: 'something-else' });
  later.check.onAlarm({ name: VERSIONS_ALARM });
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(later.calls.length, 2);
});

test('start: a failed try is retried at the next start after 15 minutes', async () => {
  let t = 1_000_000;
  const ext = fakeExt({ store: { [TRIED_KEY]: { at: t, ok: false } } });
  const first = makeCheck({ ext, fetch: ok(MIN_020), now: () => t + 5 * 60_000 });
  await first.check.start();
  assert.equal(first.calls.length, 0);
  const second = makeCheck({ ext, fetch: ok(MIN_020), now: () => t + 16 * 60_000 });
  await second.check.start();
  await new Promise((r) => setTimeout(r, 0));
  assert.equal(second.calls.length, 1);
});

test('the banner\'s dismissal is kept per recommended version', async () => {
  const { check, ext } = makeCheck({ fetch: ok(MIN_020) });
  assert.equal(await check.dismissed(), '');
  await check.dismiss('0.3.0');
  assert.equal(await check.dismissed(), '0.3.0');
  assert.equal(ext.store[DISMISSED_KEY], '0.3.0');
  await check.dismiss('');
  assert.equal(await check.dismissed(), '0.3.0');
});

test('an update clears the block at once: the gate names the version it was decided for', async () => {
  const ext = fakeExt({ store: { [CACHE_KEY]: { at: 1, data: MIN_020 } } });
  const old = makeCheck({ ext, fetch: async () => { throw new Error('offline'); }, version: '0.1.0' });
  await old.check.check();
  assert.equal(await old.check.blocked(), true);
  // The new version's content scripts read the old gate before the background decided again: not blocked.
  assert.equal(gateBlocks(ext.store[UPDATE_GATE_KEY], '0.2.0'), false);
  const updated = makeCheck({ ext, fetch: ok(MIN_020), version: '0.2.0' });
  assert.equal(await updated.check.blocked(), false);
  assert.equal(ext.store[UPDATE_GATE_KEY].version, '0.2.0');
  assert.equal(ext.store[UPDATE_GATE_KEY].required, false);
});

function updateExt({ check, reload = () => {} } = {}) {
  const tabs = [];
  return {
    tabs,
    ext: {
      runtime: { ...(check ? { requestUpdateCheck: check } : {}), reload },
      tabs: { create: async (o) => { tabs.push(o.url); return {}; } },
    },
  };
}

test('Update: the browser has the new version: it is applied (reload), no store page', async () => {
  let reloaded = 0;
  let scheduled = null;
  const { ext, tabs } = updateExt({ check: async () => ({ status: 'update_available', version: '0.2.0' }), reload: () => { reloaded++; } });
  const res = await applyUpdate({ ext, platform: Platform.CHROME, schedule: (fn) => { scheduled = fn; } });
  assert.deepEqual(res, { reloading: true });
  assert.equal(reloaded, 0, 'answered first');
  await scheduled();
  assert.equal(reloaded, 1);
  assert.deepEqual(tabs, []);
});

test('Update: no update yet, throttled, or an error: the store page for this browser', async () => {
  for (const status of ['no_update', 'throttled']) {
    const { ext, tabs } = updateExt({ check: async () => ({ status }) });
    assert.deepEqual(await applyUpdate({ ext, platform: Platform.EDGE }), { store: STORE_URLS[Platform.EDGE] });
    assert.deepEqual(tabs, [STORE_URLS[Platform.EDGE]], status);
  }
  const { ext, tabs } = updateExt({ check: async () => { throw new Error('not allowed'); } });
  await applyUpdate({ ext, platform: Platform.OPERA });
  assert.deepEqual(tabs, [STORE_URLS[Platform.OPERA]]);
  // An older Chromium's callback style answer: [status, details].
  const old = updateExt({ check: async () => ['no_update', {}] });
  await applyUpdate({ ext: old.ext, platform: Platform.CHROME });
  assert.deepEqual(old.tabs, [STORE_URLS[Platform.CHROME]]);
});

test('Update: Firefox without requestUpdateCheck goes to addons.mozilla.org', async () => {
  const { ext, tabs } = updateExt();
  assert.deepEqual(await applyUpdate({ ext, platform: Platform.FIREFOX }), { store: 'https://addons.mozilla.org/firefox/addon/passyble/' });
  assert.deepEqual(tabs, ['https://addons.mozilla.org/firefox/addon/passyble/']);
});
