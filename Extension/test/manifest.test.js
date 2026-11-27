import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { toFirefoxManifest, GECKO_ID } from '../scripts/make-firefox-manifest.mjs';
import { extensionIdFromKey, nativeHostIds, NATIVE_MESSAGING_RS } from '../scripts/extension-id.mjs';
import { COMMAND_ORDER } from '../src/shared/shortcuts.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const manifest = JSON.parse(readFileSync(path.join(root, 'manifest.json'), 'utf8'));

test('localized: default_locale en; name, description, action title and command descriptions from messages.json', () => {
  assert.equal(manifest.default_locale, 'en');
  const messages = JSON.parse(readFileSync(path.join(root, '_locales', 'en', 'messages.json'), 'utf8'));
  const msg = (v) => { const m = /^__MSG_(\w+)__$/.exec(v); assert.ok(m, `${v} is a __MSG_ reference`); return messages[m[1]].message; };
  assert.equal(msg(manifest.name), 'Passyble');
  assert.equal(manifest.short_name, 'Passyble', 'brand name, not translated');
  assert.equal(msg(manifest.description), 'Passwords, 2FA codes and passkeys from the Passyble desktop app, filled in the browser.');
  assert.equal(msg(manifest.action.default_title), 'Passyble');
  for (const cmd of Object.values(manifest.commands)) assert.ok(msg(cmd.description));
  assert.equal(toFirefoxManifest(manifest).default_locale, 'en');
});

test('MV3 with the minimal permission set', () => {
  assert.equal(manifest.manifest_version, 3);
  assert.deepEqual([...manifest.permissions].sort(),
    ['activeTab', 'alarms', 'clipboardWrite', 'contextMenus', 'identity', 'idle', 'nativeMessaging', 'offscreen', 'privacy', 'scripting', 'storage', 'unlimitedStorage']);
  assert.deepEqual(manifest.host_permissions, ['<all_urls>']);
  assert.equal(manifest.background.service_worker, 'src/background.js');
  assert.equal(manifest.background.type, 'module');
});

test('every file the manifest references exists', () => {
  const files = [
    manifest.background.service_worker, manifest.action.default_popup, manifest.options_ui.page,
    ...Object.values(manifest.icons), ...Object.values(manifest.action.default_icon),
    ...manifest.content_scripts.flatMap((c) => c.js),
    'src/offscreen/offscreen.html', 'src/offscreen/offscreen.js',
    `_locales/${manifest.default_locale}/messages.json`,
  ];
  for (const f of files) assert.ok(existsSync(path.join(root, f)), f);
});

test('content scripts: bridge before the MAIN-world interceptor, both at document_start in all frames', () => {
  const [bridge, main, loader] = manifest.content_scripts;
  assert.deepEqual(bridge.js, ['src/content/bridge.js']);
  assert.equal(bridge.run_at, 'document_start');
  assert.deepEqual(main.js, ['src/content/webauthn-main.js']);
  assert.equal(main.world, 'MAIN');
  assert.equal(main.run_at, 'document_start');
  assert.ok(bridge.all_frames && main.all_frames && loader.all_frames);
  assert.equal(bridge.world, undefined, 'bridge stays in the isolated world');
});

test('every module the content loader imports is web-accessible', () => {
  const patterns = manifest.web_accessible_resources.flatMap((w) => w.resources);
  const covered = (f) => patterns.some((p) => new RegExp('^' + p.replace(/[.]/g, '\\.').replace(/\*/g, '[^/]*') + '$').test(f));
  const seen = new Set();
  const visit = (rel) => {
    if (seen.has(rel)) return;
    seen.add(rel);
    assert.ok(covered(rel), `${rel} must be in web_accessible_resources`);
    const src = readFileSync(path.join(root, rel), 'utf8');
    for (const m of src.matchAll(/^import .* from '(\.[^']+)';$/gm)) visit(path.posix.normalize(path.posix.join(path.posix.dirname(rel), m[1])));
  };
  visit('src/content/main.js');
  assert.ok(seen.size > 5);
});

test('commands: fill login (Ctrl+Shift+L) and OTP (Alt+Shift+K)', () => {
  assert.equal(manifest.commands['fill-login'].suggested_key.default, 'Ctrl+Shift+L');
  assert.equal(manifest.commands['fill-otp'].suggested_key.default, 'Alt+Shift+K');
});

test('commands: Scan QR (Alt+Shift+Q), and Generate, New note, Lock and Sync now without a key; at most 4 suggested keys', () => {
  assert.deepEqual(Object.keys(manifest.commands), ['_execute_action', 'fill-login', 'fill-otp', 'scan-qr', 'generate-password', 'new-note', 'lock', 'sync-now']);
  assert.deepEqual(manifest.commands['scan-qr'].suggested_key, { default: 'Alt+Shift+Q', mac: 'MacCtrl+Shift+Q' });
  for (const name of ['generate-password', 'new-note', 'lock', 'sync-now']) {
    assert.equal(manifest.commands[name].suggested_key, undefined, `${name}: the user binds it`);
    assert.match(manifest.commands[name].description, /^__MSG_\w+__$/);
  }
  // Chrome takes at most four suggested keys (_execute_action included) and ignores the others.
  assert.ok(Object.values(manifest.commands).filter((c) => c.suggested_key).length <= 4);
  // Every command has a name in Options (src/shared/shortcuts.js).
  for (const name of Object.keys(manifest.commands)) assert.ok(COMMAND_ORDER.includes(name), name);
});

test('suggested shortcuts avoid built-in Firefox, Chrome and Edge shortcuts', () => {
  // Ctrl+Shift+K: Firefox web console, Edge duplicate tab. The others: devtools, private/incognito
  // window, library, bookmarks, reopen tab, Edge collections / read aloud, Firefox RTL text, ...
  const reserved = new Set(['A', 'B', 'C', 'D', 'E', 'H', 'I', 'J', 'K', 'M', 'N', 'O', 'P', 'Q',
    'R', 'S', 'T', 'U', 'W', 'X', 'Y', 'Delete'].map((k) => `Ctrl+Shift+${k}`));
  for (const m of [manifest, toFirefoxManifest(manifest)]) {
    for (const [name, cmd] of Object.entries(m.commands)) {
      if (!cmd.suggested_key) continue; // no key of its own: the user picks one
      assert.ok(!reserved.has(cmd.suggested_key.default), `${name}: ${cmd.suggested_key.default}`);
      assert.ok(!['Command+Option+K', 'Command+Option+I', 'Command+Option+J'].includes(cmd.suggested_key.mac), name);
    }
  }
});

test('Firefox variant: background.scripts, gecko id, Chrome-only keys removed', () => {
  assert.ok(manifest.key, 'source manifest pins the Chromium ID');
  const ff = toFirefoxManifest(manifest);
  assert.deepEqual(ff.background, { scripts: ['src/background.js'], type: 'module' });
  assert.equal(ff.browser_specific_settings.gecko.id, GECKO_ID);
  // addons.mozilla.org refuses new add-ons without Firefox's data consent declaration: nothing by
  // default, optional categories asked for when the user turns on sign-in or sync.
  assert.deepEqual(ff.browser_specific_settings.gecko.data_collection_permissions.required, ['none']);
  assert.equal(ff.browser_specific_settings.gecko.strict_min_version, '140.0');
  assert.deepEqual(ff.content_security_policy, manifest.content_security_policy, "'wasm-unsafe-eval' for the browser vault");
  assert.equal(GECKO_ID, 'pass@sensyble.com');
  assert.equal(ff.minimum_chrome_version, undefined);
  assert.equal(ff.key, undefined);
  assert.ok(!ff.permissions.includes('offscreen'), 'offscreen is Chrome-only');
  assert.deepEqual(ff.permissions, manifest.permissions.filter((p) => p !== 'offscreen'));
  assert.ok(manifest.permissions.includes('offscreen'), 'source manifest untouched');
  assert.deepEqual(ff.content_scripts, manifest.content_scripts);
  assert.equal(manifest.background.service_worker, 'src/background.js', 'source manifest untouched');
});

test('icons exist as real PNGs', () => {
  for (const f of readdirSync(path.join(root, 'icons')).filter((n) => n.endsWith('.png'))) {
    const buf = readFileSync(path.join(root, 'icons', f));
    assert.deepEqual([...buf.subarray(1, 4)], [0x50, 0x4e, 0x47], f);
  }
});

test('extension ID from a manifest key: 32 chars a-p, deterministic', () => {
  const key = Buffer.from('not a real key, but any DER bytes hash the same way').toString('base64');
  const id = extensionIdFromKey(key);
  assert.match(id, /^[a-p]{32}$/);
  assert.equal(extensionIdFromKey(key), id);
  // sha256('') = e3b0c44298fc1c149afbf4c8996fb924... -> e=o 3=d b=l 0=a c=m 4=e ...
  assert.equal(extensionIdFromKey(''), 'odlameecjipmbmbejkplpemijjgpljce');
});

test('manifest key pins the ID that the desktop app registers in allowed_origins', () => {
  const id = extensionIdFromKey(manifest.key);
  assert.match(id, /^[a-p]{32}$/);
  const der = Buffer.from(manifest.key, 'base64');
  assert.equal(der[0], 0x30, 'DER SEQUENCE');
  assert.ok(der.length > 290 && der.length < 300, 'RSA-2048 SubjectPublicKeyInfo');
  const ids = nativeHostIds(readFileSync(NATIVE_MESSAGING_RS, 'utf8'));
  assert.ok(ids.chromium, 'CHROMIUM_EXTENSION_IDS found in native_messaging.rs');
  assert.ok(ids.chromium.includes(id), `CHROMIUM_EXTENSION_IDS ${JSON.stringify(ids.chromium)} must include ${id}`);
  for (const other of ids.chromium) assert.match(other, /^[a-p]{32}$/, 'no placeholders in allowed_origins');
  // Store IDs (empty until a store assigns one), never placeholder strings.
  for (const [name, list] of [['CHROME_STORE_EXTENSION_IDS', ids.chromeStore], ['EDGE_STORE_EXTENSION_IDS', ids.edgeStore], ['OPERA_STORE_EXTENSION_IDS', ids.opera]]) {
    assert.ok(list, `${name} found in native_messaging.rs`);
    for (const other of list) assert.match(other, /^[a-p]{32}$/, `${name}: well-formed IDs only`);
  }
  assert.ok(ids.opera.includes('elckicaofoomkdcfbkkbnjdljhbbmkch'), 'the Opera Add-ons ID is allowed');
  assert.equal(ids.firefox, GECKO_ID, 'FIREFOX_EXTENSION_ID matches the gecko id');
});

test('nativeHostIds parses the Rust constants', () => {
  const src = ['pub const FIREFOX_EXTENSION_ID: &str = "a@b";', 'pub const CHROMIUM_EXTENSION_IDS: &[&str] = &[',
    '    "abc",', '    "def",', '];', 'pub const OPERA_STORE_EXTENSION_IDS: &[&str] = &[];'].join('\n');
  assert.deepEqual(nativeHostIds(src), { chromium: ['abc', 'def'], chromeStore: null, edgeStore: null, opera: [], firefox: 'a@b' });
  assert.equal(nativeHostIds('pub const CHROMIUM_EXTENSION_IDS: &[&str] = &["abc"];').opera, null);
  assert.deepEqual(nativeHostIds('pub const OPERA_STORE_EXTENSION_IDS: &[&str] = &[\n    "ghi",\n];').opera, ['ghi']);
});

test('commands: _execute_action opens the popup (Alt+Shift+P), also in the Firefox manifest', () => {
  const cmd = manifest.commands._execute_action;
  assert.ok(cmd, '_execute_action present');
  assert.equal(cmd.suggested_key.default, 'Alt+Shift+P');
  assert.match(cmd.suggested_key.mac, /^(MacCtrl|Command)\+/);
  assert.ok(cmd.description);
  // It is not handled by onCommand (the browser opens the action's popup itself), so no other command shares the key.
  const keys = Object.values(manifest.commands).filter((c) => c.suggested_key).map((c) => c.suggested_key.default);
  const macKeys = Object.values(manifest.commands).filter((c) => c.suggested_key?.mac).map((c) => c.suggested_key.mac);
  assert.equal(new Set(macKeys).size, macKeys.length, 'no two commands share a macOS key');
  assert.equal(new Set(keys).size, keys.length, 'no two commands share a key');
  assert.ok(manifest.action.default_popup, 'there is a popup to open');
  const ff = toFirefoxManifest(manifest);
  assert.deepEqual(ff.commands._execute_action, cmd, 'Firefox MV3 uses the same command name');
  assert.equal(ff.commands._execute_browser_action, undefined);
  // The MV2 name is rewritten.
  const legacy = structuredClone(manifest);
  legacy.commands._execute_browser_action = legacy.commands._execute_action;
  delete legacy.commands._execute_action;
  const fixed = toFirefoxManifest(legacy);
  assert.ok(fixed.commands._execute_action);
  assert.equal(fixed.commands._execute_browser_action, undefined);
});
