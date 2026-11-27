// npm run package:opera (scripts/package-opera.mjs): the Opera Add-ons zip and the source zip for its reviewers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { inflateRawSync } from 'node:zlib';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { buildPackages } from '../scripts/package.mjs';
import { buildOpera, checkOperaListing, operaBuildingNotes, operaSourceFiles, toOperaManifest } from '../scripts/package-opera.mjs';

/** Names in a zip (central directory). */
function names(buf) {
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  const out = [];
  for (let i = 0; i < count; i++) {
    const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    out.push(buf.toString('utf8', p + 46, p + 46 + nlen));
    p += 46 + nlen + xlen + clen;
  }
  return out;
}

/** One entry of a zip, inflated. */
function entry(buf, name) {
  const eocd = buf.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
  const count = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16);
  for (let i = 0; i < count; i++) {
    const method = buf.readUInt16LE(p + 10), csize = buf.readUInt32LE(p + 20);
    const nlen = buf.readUInt16LE(p + 28), xlen = buf.readUInt16LE(p + 30), clen = buf.readUInt16LE(p + 32);
    const lho = buf.readUInt32LE(p + 42);
    if (buf.toString('utf8', p + 46, p + 46 + nlen) === name) {
      const start = lho + 30 + buf.readUInt16LE(lho + 26) + buf.readUInt16LE(lho + 28);
      const raw = buf.subarray(start, start + csize);
      return method === 8 ? inflateRawSync(raw) : raw;
    }
    p += 46 + nlen + xlen + clen;
  }
  return null;
}

test('Opera package: the Chrome Web Store zip (no key; Opera Add-ons assigns its own ID)', async () => {
  const [opera, chromium] = [await buildOpera({ withSource: false }), await buildPackages()];
  assert.ok(opera.extension.equals(chromium.chromium), 'byte for byte the store zip');
  assert.equal('key' in opera.manifest, false);
  assert.ok(opera.manifest.permissions.includes('nativeMessaging'));
  assert.ok(opera.manifest.permissions.includes('offscreen'), 'Opera is Chromium: offscreen stays');
  const repoManifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
  assert.deepEqual(toOperaManifest(repoManifest), opera.manifest);
  assert.ok(repoManifest.key, 'the repo manifest itself is untouched');
  assert.equal(opera.source, null);
});

test("Opera's acceptance criteria: no \"Opera\" in the title of any locale", async () => {
  const repoManifest = JSON.parse(readFileSync(new URL('../manifest.json', import.meta.url), 'utf8'));
  await checkOperaListing(repoManifest);
  const dir = mkdtempSync(path.join(tmpdir(), 'pass-opera-'));
  try {
    mkdirSync(path.join(dir, '_locales', 'en'), { recursive: true });
    writeFileSync(path.join(dir, '_locales', 'en', 'messages.json'), JSON.stringify({ extName: { message: 'Passyble for Opera' } }));
    await assert.rejects(checkOperaListing({ short_name: 'Passyble' }, dir), /Opera Add-ons rejects titles/);
    writeFileSync(path.join(dir, '_locales', 'en', 'messages.json'), JSON.stringify({ extName: { message: 'Passyble' } }));
    await checkOperaListing({ short_name: 'Passyble' }, dir);
    await assert.rejects(checkOperaListing({ short_name: 'Opera Pass' }, dir), /Opera Pass/);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('Opera source zip: the WebAssembly crates and this extension, not the desktop app or secrets', () => {
  const files = operaSourceFiles([
    'Core/Cargo.lock', 'Core/Cargo.toml', 'Core/core/src/lib.rs', 'Core/agent/src/lib.rs', 'Core/wasm/src/lib.rs',
    'Core/wasm/kdf/kdf.js', 'Core/desktop-app/src-tauri/src/main.rs', 'Core/native-host/src/main.rs', 'Core/NOTES.md',
    'Extension/src/background.js', 'Extension/manifest.json', 'Extension/NOTES.md', 'Extension/google-oauth.env',
    'Extension/.github/workflows/x.yml', 'Extension/node_modules/jsdom/index.js', 'Extension/key.pem', 'Firefox/manifest.json',
    'Extension/LICENSE', 'Extension/TODO.md', 'Extension/src/NOTES.md', 'Core/core/TODO.md', 'Core/wasm/NOTES.local.md',
    'Extension/.tooling/settings.json',
  ]);
  assert.deepEqual(files, [
    'Core/Cargo.lock', 'Core/agent/src/lib.rs', 'Core/core/src/lib.rs', 'Core/wasm/kdf/kdf.js', 'Core/wasm/src/lib.rs',
    'Extension/LICENSE', 'Extension/manifest.json', 'Extension/src/background.js',
  ]);
});

test('Opera source zip BUILDING.md: the tool versions and the steps, no em dash', () => {
  const notes = operaBuildingNotes({ rustc: 'rustc 1.99.0', cargo: 'cargo 1.99.0', node: 'v26.2.0', wasmBindgen: '0.2.100', version: '1.2.3' });
  assert.match(notes, /^# Building Passyble for Opera 1\.2\.3 from source/);
  assert.match(notes, /wasm-bindgen-cli 0\.2\.100/);
  assert.match(notes, /node scripts\/package-opera\.mjs --out out/);
  assert.ok(!notes.includes(String.fromCharCode(0x2014)), 'no em dash');
});

test('Opera source zip from the sibling repositories: Core crates, a cut-down workspace, BUILDING.md', async () => {
  const { source } = await buildOpera();
  const list = names(source);
  assert.ok(list.includes('BUILDING.md'));
  assert.ok(list.includes('Core/Cargo.toml'));
  assert.ok(list.includes('Extension/manifest.json'));
  assert.ok(list.some((n) => n.startsWith('Core/wasm/')), 'the pass-wasm crate');
  assert.ok(!list.some((n) => n.startsWith('Core/desktop-app/') || n.startsWith('Core/native-host/')), 'no desktop app');
  assert.ok(!list.some((n) => /(^|\/)node_modules\//.test(n) || n.endsWith('.pem') || /^[^/]+\/(?!README\.md$|THIRD_PARTY_NOTICES\.md$)[^/]+\.md$/.test(n)));
  const toml = entry(source, 'Core/Cargo.toml').toString();
  assert.match(toml, /members = \["core", "agent", "wasm", "wasm\/kdf"\]/);
  assert.doesNotMatch(toml, /^default-members/m);
});
