import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inflateRawSync } from 'node:zlib';
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildPackages, crc32, listPackageFiles, missingWasm, WASM_FILES } from '../scripts/package.mjs';
import { cliVersion, pinnedWasmBindgen, remapRustflags, resolveCoreDir } from '../scripts/build-wasm.mjs';
import { checkManifestMessages, manifestMessageNames } from '../scripts/make-firefox-manifest.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const locales = readdirSync(new URL('../_locales/', import.meta.url));

/** Reads a zip via its central directory: Map name -> Buffer (verifies sizes and CRCs). */
function unzip(buf) {
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  assert.ok(eocd >= 0, 'end of central directory');
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const out = new Map();
  for (let i = 0; i < count; i++) {
    assert.equal(buf.readUInt32LE(p), 0x02014b50);
    const method = buf.readUInt16LE(p + 10), crc = buf.readUInt32LE(p + 16);
    const csize = buf.readUInt32LE(p + 20), size = buf.readUInt32LE(p + 24);
    const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const lho = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nlen);
    const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
    const raw = buf.subarray(start, start + csize);
    const data = method === 8 ? inflateRawSync(raw) : raw;
    assert.equal(data.length, size, name);
    assert.equal(crc32(data), crc, name);
    out.set(name, data);
    p += 46 + nlen + xlen + clen;
  }
  return out;
}

test('store packages: chromium manifest has no key, firefox is the gecko variant', async () => {
  const pkg = await buildPackages();
  const chromium = unzip(pkg.chromium);
  const firefox = unzip(pkg.firefox);

  for (const zip of [chromium, firefox]) {
    assert.ok(zip.has('manifest.json'));
    assert.ok(zip.has('src/background.js'));
    assert.ok(zip.has('icons/icon-128.png'));
    // The setup guide opened on install (and everything its page loads).
    for (const f of ['src/welcome/welcome.html', 'src/welcome/welcome.js', 'src/welcome/welcome.css', 'src/welcome/setup-steps.js',
      'src/shared/welcome-link.js', 'src/options/options.css']) assert.ok(zip.has(f), f);
    // Translations: the default locale (manifest __MSG_ strings, UI text) and every other locale present.
    for (const locale of locales) assert.ok(zip.has(`_locales/${locale}/messages.json`), `_locales/${locale}`);
    for (const name of zip.keys()) {
      assert.ok(!/^(test|scripts|node_modules|dist)\//.test(name), name);
      assert.ok(!name.split('/').some((s) => s.startsWith('.')), name);
      assert.ok(!['package.json', 'package-lock.json', 'README.md', 'manifest.firefox.json'].includes(name), name);
    }
  }

  const cm = JSON.parse(chromium.get('manifest.json').toString());
  assert.equal('key' in cm, false);
  assert.equal(cm.background.service_worker, 'src/background.js');
  assert.ok(cm.permissions.includes('offscreen'));
  assert.equal(cm.name, '__MSG_extName__');
  assert.equal(cm.default_locale, 'en');

  const fm = JSON.parse(firefox.get('manifest.json').toString());
  assert.equal('key' in fm, false);
  assert.deepEqual(fm.background.scripts, ['src/background.js']);
  assert.equal(fm.browser_specific_settings.gecko.id, 'pass@sensyble.com');
  assert.ok(!fm.permissions.includes('offscreen'));
  // Firefox resolves __MSG_ from _locales like Chrome; the localized keys stay as they are.
  assert.equal(fm.default_locale, 'en');
  assert.equal(fm.name, '__MSG_extName__');
  assert.equal(fm.commands['fill-login'].description, '__MSG_cmdFillLogin__');
});

test('the unpacked package keeps the key, so the extension gets the ID the native host allows', async () => {
  const pkg = await buildPackages();
  const unpacked = unzip(pkg.unpacked);
  const repo = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
  const um = JSON.parse(unpacked.get('manifest.json').toString());
  assert.equal(um.key, repo.key);
  assert.ok(um.key, 'manifest.json has a key');
  assert.deepEqual([...unpacked.keys()].sort(), [...unzip(pkg.chromium).keys()].sort());
});

test('packaging refuses a manifest whose __MSG_ names are not in the default locale', async () => {
  const manifest = { name: '__MSG_extName__', default_locale: 'en', commands: { a: { description: '__MSG_noSuchMessage__' } } };
  assert.deepEqual(manifestMessageNames(manifest), ['extName', 'noSuchMessage']);
  await assert.rejects(checkManifestMessages(manifest, root), /noSuchMessage/);
  await assert.rejects(checkManifestMessages({ name: '__MSG_extName__' }, root), /default_locale/);
  await assert.rejects(checkManifestMessages({ name: 'x', default_locale: 'xx' }, root), /_locales/);
  await checkManifestMessages({ name: '__MSG_EXTNAME__', default_locale: 'en' }, root); // names are case-insensitive
});

test('store packages are reproducible', async () => {
  const [a, b] = [await buildPackages(), await buildPackages()];
  assert.ok(a.chromium.equals(b.chromium));
  assert.ok(a.firefox.equals(b.firefox));
});

test("the browser vault's WebAssembly ships when built (npm run package needs it), its Rust sources never", async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pass-package-'));
  try {
    const write = (rel, data = 'x') => {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), data);
    };
    write('src/background.js');
    write('wasm/Cargo.toml');
    write('wasm/src/lib.rs');
    assert.deepEqual(await listPackageFiles(dir), ['src/background.js']);
    assert.deepEqual(missingWasm(await listPackageFiles(dir)), WASM_FILES, 'npm run package stops: not built');
    for (const f of ['pass_wasm.js', 'pass_wasm_bg.wasm', 'pass_wasm_kdf.wasm', 'kdf.js', 'build.json']) write(`src/wasm/${f}`);
    assert.deepEqual(await listPackageFiles(dir), [
      'src/background.js', 'src/wasm/kdf.js', 'src/wasm/pass_wasm.js', 'src/wasm/pass_wasm_bg.wasm', 'src/wasm/pass_wasm_kdf.wasm',
    ]);
    assert.deepEqual(missingWasm(await listPackageFiles(dir)), []);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the licence ships; notes, tool settings and repository docs never do', async () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'pass-package-'));
  try {
    const write = (rel, data = 'x') => {
      mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
      writeFileSync(path.join(dir, rel), data);
    };
    for (const f of ['LICENSE', 'SECURITY.md', 'README.md', 'CONTRIBUTING.md', 'NOTES.md', 'NOTES.local.md', 'TODO.md',
      '.tooling/settings.json', 'src/background.js', 'src/NOTES.md', 'src/popup/TODO.md']) write(f);
    assert.deepEqual(await listPackageFiles(dir), ['LICENSE', 'SECURITY.md', 'src/background.js']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('the WebAssembly build uses ../Core unless --core or PASSYBLE_CORE_DIR names another checkout', () => {
  const ext = path.resolve('/work/Extension-sec');
  const parent = path.dirname(ext);
  assert.equal(resolveCoreDir([], {}, ext), path.join(parent, 'Core'));
  assert.equal(resolveCoreDir(['--no-opt'], { PASSYBLE_CORE_DIR: '  ' }, ext), path.join(parent, 'Core'));
  assert.equal(resolveCoreDir([], { PASSYBLE_CORE_DIR: '../Core-sec' }, ext), path.join(parent, 'Core-sec'));
  assert.equal(resolveCoreDir(['--core', '../Core-x'], { PASSYBLE_CORE_DIR: '../Core-sec' }, ext), path.join(parent, 'Core-x'));
  const absolute = path.resolve('/elsewhere/Core');
  assert.equal(resolveCoreDir(['--core', absolute], {}, ext), absolute);
  assert.throws(() => resolveCoreDir(['--core'], {}, ext), /needs a folder/);
  assert.throws(() => resolveCoreDir(['--core', '--no-opt'], {}, ext), /needs a folder/);
});

test("the WebAssembly build pins the wasm-bindgen CLI to the crate's version", () => {
  const toml = readFileSync(new URL('../../Core/wasm/Cargo.toml', import.meta.url), 'utf8');
  const version = pinnedWasmBindgen(toml);
  assert.match(version, /^0\.2\.\d+$/);
  assert.throws(() => pinnedWasmBindgen('wasm-bindgen = "0.2"'), /pin/);
  assert.equal(cliVersion('wasm-bindgen 0.2.129\n'), '0.2.129');
  assert.equal(cliVersion(''), null);
  assert.equal(cliVersion(null), null);
});

test('no Google sign-in of its own: no Google client file, no google-oauth.env, no Drive code in the packages', async () => {
  const pkg = await buildPackages();
  for (const f of ['src/google-client.json', 'google-oauth.env', 'src/background/local/google.js', 'src/background/local/drive.js']) {
    assert.ok(!pkg.files.includes(f), f);
  }
  assert.equal('googleClient' in pkg, false);
  // A Google client file left on a developer's PC never ships.
  const dir = mkdtempSync(path.join(tmpdir(), 'pass-google-'));
  try {
    mkdirSync(path.join(dir, 'src'), { recursive: true });
    writeFileSync(path.join(dir, 'src', 'google-client.json'), '{"client_id":"1-x.apps.googleusercontent.com"}\n');
    writeFileSync(path.join(dir, 'google-oauth.env'), 'PASS_GOOGLE_WEB_CLIENT_ID=1-x.apps.googleusercontent.com\n');
    writeFileSync(path.join(dir, 'src', 'background.js'), '');
    assert.deepEqual(await listPackageFiles(dir), ['src/background.js']);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('remapRustflags: the Cargo home and the Core folder become fixed names, after flags already set', () => {
  const core = path.join('x', 'Core');
  const split = (s) => s.split('\x1f');
  assert.deepEqual(split(remapRustflags({}, core, 'home')), [
    `--remap-path-prefix=${path.join('home', '.cargo')}=/cargo`, `--remap-path-prefix=${core}=/src`,
  ]);
  assert.deepEqual(split(remapRustflags({ CARGO_HOME: 'ch', RUSTFLAGS: ' -C  opt-level=z ' }, core, 'home')).slice(0, 3),
    ['-C', 'opt-level=z', '--remap-path-prefix=ch=/cargo']);
  assert.deepEqual(split(remapRustflags({ CARGO_ENCODED_RUSTFLAGS: 'a\x1fb c', RUSTFLAGS: 'ignored' }, core, 'home')).slice(0, 2),
    ['a', 'b c']);
});
