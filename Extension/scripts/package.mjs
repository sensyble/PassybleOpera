#!/usr/bin/env node
// Builds the store packages: node scripts/package.mjs [--out dist]
//   pass-chromium.zip           Chrome Web Store and Edge Add-ons. No "key": the stores assign their own ID.
//   pass-firefox.zip            addons.mozilla.org.
//   pass-chromium-unpacked.zip  for "Load unpacked". Keeps "key" so the ID matches what the native host allows.
// The zips are reproducible (sorted entries, fixed timestamp). Run `npm run wasm` first: the background
// imports the WebAssembly glue, so a package without it would not start.
import { readFile, writeFile, readdir, mkdir } from 'node:fs/promises';
import { deflateRawSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { checkManifestMessages } from './make-firefox-manifest.mjs';
import { toFirefoxManifest } from '../../Firefox/scripts/firefox-manifest.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

/** Top-level names that never ship (dot-files and dot-folders are skipped at every level). */
const EXCLUDED_TOP = new Set([
  'test', 'scripts', 'node_modules', 'dist', 'wasm', 'google-oauth.env',
  'package.json', 'package-lock.json', 'manifest.firefox.json', 'manifest.json', // manifest.json is written separately
]);
// Markdown is repository documentation: only these top-level files ship, and no Markdown file below the top level.
const SHIPPED_TOP_DOCS = new Set(['SECURITY.md', 'THIRD_PARTY_NOTICES.md']);
const EXCLUDED_EXT = ['.pem', '.map'];
/**
 * Build notes next to the WebAssembly, not needed at run time, and a Google client file that must never
 * ship should one be left on a developer's PC.
 */
const EXCLUDED_FILES = new Set(['src/wasm/build.json', 'src/google-client.json']);

/** Files to ship (POSIX paths relative to the extension directory), sorted, without manifest.json. */
export async function listPackageFiles(dir = root) {
  const out = [];
  async function walk(abs, rel) {
    for (const e of await readdir(abs, { withFileTypes: true })) {
      if (e.name.startsWith('.')) continue;
      const r = rel ? `${rel}/${e.name}` : e.name;
      if (!rel && EXCLUDED_TOP.has(e.name)) continue;
      if (e.isFile() && /\.md$/i.test(e.name) && (rel || !SHIPPED_TOP_DOCS.has(e.name))) continue;
      if (e.isDirectory()) await walk(path.join(abs, e.name), r);
      else if (e.isFile() && !EXCLUDED_EXT.some((x) => e.name.endsWith(x)) && !EXCLUDED_FILES.has(r)) out.push(r);
    }
  }
  await walk(dir, '');
  return out.sort();
}

/** The Chrome Web Store / Edge manifest: the repo manifest minus `key`. */
export function toStoreChromiumManifest(chrome) {
  const m = structuredClone(chrome);
  delete m.key;
  return m;
}

const json = (m) => Buffer.from(JSON.stringify(m, null, 2) + '\n');

let crcTable;
export function crc32(buf) {
  if (!crcTable) {
    crcTable = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      crcTable[n] = c >>> 0;
    }
  }
  let c = 0xffffffff;
  for (const b of buf) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}

/** Minimal zip writer: entries = [{ name, data: Buffer }], deflate, UTF-8 names, 2000-01-01 timestamp. */
export function makeZip(entries) {
  const DOS_TIME = 0, DOS_DATE = ((2000 - 1980) << 9) | (1 << 5) | 1;
  const locals = [], central = [];
  let offset = 0;
  for (const { name, data } of entries) {
    const nameBuf = Buffer.from(name, 'utf8');
    const deflated = deflateRawSync(data, { level: 9 });
    const store = deflated.length >= data.length;
    const body = store ? data : deflated;
    const method = store ? 0 : 8;
    const crc = crc32(data);
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0);
    lh.writeUInt16LE(20, 4); // version needed
    lh.writeUInt16LE(0x0800, 6); // UTF-8 names
    lh.writeUInt16LE(method, 8);
    lh.writeUInt16LE(DOS_TIME, 10);
    lh.writeUInt16LE(DOS_DATE, 12);
    lh.writeUInt32LE(crc, 14);
    lh.writeUInt32LE(body.length, 18);
    lh.writeUInt32LE(data.length, 22);
    lh.writeUInt16LE(nameBuf.length, 26);
    locals.push(lh, nameBuf, body);
    const ch = Buffer.alloc(46);
    ch.writeUInt32LE(0x02014b50, 0);
    ch.writeUInt16LE(20, 4); // version made by
    ch.writeUInt16LE(20, 6); // version needed
    ch.writeUInt16LE(0x0800, 8);
    ch.writeUInt16LE(method, 10);
    ch.writeUInt16LE(DOS_TIME, 12);
    ch.writeUInt16LE(DOS_DATE, 14);
    ch.writeUInt32LE(crc, 16);
    ch.writeUInt32LE(body.length, 20);
    ch.writeUInt32LE(data.length, 24);
    ch.writeUInt16LE(nameBuf.length, 28);
    ch.writeUInt32LE(offset, 42);
    central.push(ch, nameBuf);
    offset += lh.length + nameBuf.length + body.length;
  }
  const centralBuf = Buffer.concat(central);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(entries.length, 8);
  end.writeUInt16LE(entries.length, 10);
  end.writeUInt32LE(centralBuf.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBuf, end]);
}

/** The browser vault's built files (src/wasm/) a package must have. */
export const WASM_FILES = Object.freeze(['src/wasm/kdf.js', 'src/wasm/pass_wasm.js', 'src/wasm/pass_wasm_bg.wasm', 'src/wasm/pass_wasm_kdf.wasm']);

/** Which of WASM_FILES are not among `files` (empty: all there). */
export function missingWasm(files) {
  return WASM_FILES.filter((f) => !files.includes(f));
}

/** Builds the packages in memory: { chromium, firefox, unpacked, files, chromiumManifest, firefoxManifest }. */
export async function buildPackages(dir = root) {
  const chrome = JSON.parse(await readFile(path.join(dir, 'manifest.json'), 'utf8'));
  await checkManifestMessages(chrome, dir);
  const chromiumManifest = toStoreChromiumManifest(chrome);
  const firefoxManifest = toFirefoxManifest(chrome);
  const files = await listPackageFiles(dir);
  if (chrome.default_locale && !files.includes(`_locales/${chrome.default_locale}/messages.json`)) {
    throw new Error(`_locales/${chrome.default_locale}/messages.json is not in the package`);
  }
  const entries = await Promise.all(files.map(async (f) => ({ name: f, data: await readFile(path.join(dir, f)) })));
  const zip = (manifest) => makeZip([{ name: 'manifest.json', data: json(manifest) }, ...entries]);
  return {
    chromium: zip(chromiumManifest),
    firefox: zip(firefoxManifest),
    unpacked: zip(chrome),
    files,
    chromiumManifest,
    firefoxManifest,
  };
}

async function main(argv) {
  const outIdx = argv.indexOf('--out');
  const outDir = path.resolve(outIdx >= 0 ? argv[outIdx + 1] : path.join(root, 'dist'));
  const pkg = await buildPackages();
  const missing = missingWasm(pkg.files);
  if (missing.length) {
    throw new Error(`The browser vault's WebAssembly is not built (missing: ${missing.join(', ')}). Run "npm run wasm" first, or "npm run release".`);
  }
  await mkdir(outDir, { recursive: true });
  for (const [name, buf] of [
    ['pass-chromium.zip', pkg.chromium],
    ['pass-firefox.zip', pkg.firefox],
    ['pass-chromium-unpacked.zip', pkg.unpacked],
  ]) {
    await writeFile(path.join(outDir, name), buf);
    console.log(`wrote ${path.relative(process.cwd(), path.join(outDir, name)) || name} (${buf.length} bytes, ${pkg.files.length + 1} files)`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => { console.error(err); process.exit(1); });
}
