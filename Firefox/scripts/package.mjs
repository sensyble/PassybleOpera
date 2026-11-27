#!/usr/bin/env node
// Builds Passyble for Firefox: node Firefox/scripts/package.mjs [--out Firefox/dist]
//   pass-firefox.zip         the add-on, same files as the Chromium store zip with the Firefox manifest.
//   pass-firefox-source.zip  source for AMO review, since src/wasm/ is compiled from Rust.
//   unpacked/                the add-on as a folder, for about:debugging and web-ext.
// Run `npm run wasm` in Extension/ first.
import { readFile, writeFile, mkdir, rm, cp } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { buildPackages, listPackageFiles, makeZip, missingWasm } from '../../Extension/scripts/package.mjs';
import { checkManifestMessages } from '../../Extension/scripts/make-firefox-manifest.mjs';
import { toFirefoxManifest, FIREFOX_DIR, GECKO_ID } from './firefox-manifest.mjs';

// Parent folder of the Core, Extension and Firefox repositories.
const repo = path.resolve(FIREFOX_DIR, '..');
const extension = path.join(repo, 'Extension');

export const SOURCE_REPOS = Object.freeze(['Core', 'Extension', 'Firefox']);
/** Paths prefixed with the repository folder. A trailing slash matches everything under it. */
export const SOURCE_PATHS = Object.freeze([
  'Core/.cargo/config.toml', 'Core/Cargo.lock', 'Core/core/', 'Core/agent/', 'Core/wasm/', 'Core/scripts/cargo-low.cmd', 'Extension/', 'Firefox/',
]);
/** Never in the source zip, even when tracked. */
const SOURCE_EXCLUDED = [/(^|\/)node_modules\//, /(^|\/)\.env/, /\.pem$/];
/** A folder whose name starts with a dot, at any level (CI workflows, editor and tool settings). */
const DOT_FOLDER = /(^|\/)\.[^/]*\//;
/** Top-level Markdown of a repository that ships: the README and licence notices. */
const SOURCE_TOP_DOCS = new Set(['README.md', 'THIRD_PARTY_NOTICES.md']);
/** Markdown below the top level ships only under one of these names. */
const SOURCE_DOCS = new Set([...SOURCE_TOP_DOCS, 'SECURITY.md', 'CONTRIBUTING.md', 'CLA.md', 'TRADEMARKS.md']);
/** The add-on's AMO listing texts, privacy policy and reviewer notes. */
const AMO_DOC = /^Firefox\/amo\/(listing\.[A-Za-z_]+|privacy-policy|reviewer-notes)\.md$/;

/** Whether a Markdown file (a path with the repository folder in front) is one of the public docs that ship. */
function shippedDoc(f) {
  const parts = f.split('/');
  return (parts.length === 2 ? SOURCE_TOP_DOCS : SOURCE_DOCS).has(parts[parts.length - 1]) || AMO_DOC.test(f);
}

/**
 * Whether `f` stays out of the source zip. A path named on its own in SOURCE_PATHS is taken even inside a
 * dot-folder (Core/.cargo/config.toml).
 */
function sourceExcluded(f) {
  if (SOURCE_EXCLUDED.some((re) => re.test(f))) return true;
  if (DOT_FOLDER.test(f) && !SOURCE_PATHS.includes(f)) return true;
  return /\.md$/i.test(f) && !shippedDoc(f);
}
/** The workspace members the WebAssembly needs (paths in Core/Cargo.toml). */
export const SOURCE_MEMBERS = Object.freeze(['core', 'agent', 'wasm', 'wasm/kdf']);

/** Core's Cargo.toml with `members` cut down to SOURCE_MEMBERS and no default-members. */
export function sourceWorkspaceToml(cargoToml) {
  const members = `members = [${SOURCE_MEMBERS.map((m) => `"${m}"`).join(', ')}]`;
  const out = cargoToml
    .replace(/^members\s*=\s*\[[^\]]*\]/m, members)
    .replace(/^default-members\s*=\s*\[[^\]]*\]\n?/m, '');
  if (!out.includes(members)) throw new Error('Cargo.toml has no [workspace] members line');
  return out;
}

/** Tracked files for the source zip, sorted. */
export function sourceFiles(list) {
  return list
    .filter((f) => SOURCE_PATHS.some((p) => (p.endsWith('/') ? f.startsWith(p) : f === p)))
    .filter((f) => !sourceExcluded(f))
    .sort();
}

function tool(command, args) {
  try { return execFileSync(command, args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return ''; }
}

/** BUILDING.md for the source zip: the tool versions this package was built with, and the steps. */
export function buildingNotes({ rustc, cargo, node, wasmBindgen, version }) {
  return `# Building Passyble for Firefox ${version} from source

The add-on is plain JavaScript (no bundler, no minifier): every .js file in the add-on is the file in
Extension/src/ as is. The only generated files are the browser vault's WebAssembly in src/wasm/:

| file | made from |
|---|---|
| src/wasm/pass_wasm_bg.wasm, src/wasm/pass_wasm.js | the Rust crate Core/wasm (pass-wasm), with wasm-bindgen |
| src/wasm/pass_wasm_kdf.wasm | the Rust crate Core/wasm/kdf (pass-wasm-kdf) |
| src/wasm/kdf.js | copied from Core/wasm/kdf/kdf.js |

Tools used for this package:

* ${rustc || 'rustc (version not recorded)'}
* ${cargo || 'cargo (version not recorded)'}
* rustup target wasm32-unknown-unknown
* wasm-bindgen-cli ${wasmBindgen} (\`cargo install wasm-bindgen-cli --version ${wasmBindgen} --locked\`)
* Node.js ${node}
* no wasm-opt

Steps (Linux, macOS or Windows):

\`\`\`sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version ${wasmBindgen} --locked
cd Extension
node scripts/build-wasm.mjs --no-install --no-opt
cd ..
node Firefox/scripts/package.mjs --out out
\`\`\`

\`out/pass-firefox.zip\` is then the add-on. To compare with the uploaded file, unzip both and compare
src/wasm/. Rust embeds the build folder's path in panic messages, so build from a folder with the same
path length, or compare everything except those strings; every other file is byte for byte the same
(the zip has fixed timestamps and sorted entries).

The add-on ID is ${GECKO_ID}. It talks to the Passyble desktop app over native messaging
(com.sensyble.pass), or keeps its own encrypted vault in the browser (the WebAssembly above).
`;
}

/** Builds the Firefox outputs in memory: { addon, source, files, manifest }. */
export async function buildFirefox({ withSource = true } = {}) {
  const pkg = await buildPackages(extension);
  const chrome = JSON.parse(await readFile(path.join(extension, 'manifest.json'), 'utf8'));
  await checkManifestMessages(chrome, extension);
  const manifest = toFirefoxManifest(chrome);
  if (JSON.stringify(manifest) !== JSON.stringify(pkg.firefoxManifest)) throw new Error('the two Firefox manifests differ');
  let source = null;
  if (withSource) {
    const tracked = SOURCE_REPOS.flatMap((name) => execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: path.join(repo, name), encoding: 'utf8' })
      .split('\0').filter(Boolean).map((f) => `${name}/${f}`));
    const files = sourceFiles(tracked);
    const wasmBindgen = /^wasm-bindgen\s*=\s*"=([^"]+)"/m.exec(await readFile(path.join(repo, 'Core', 'wasm', 'Cargo.toml'), 'utf8'))?.[1] || '?';
    const entries = await Promise.all(files.map(async (f) => ({ name: f, data: await readFile(path.join(repo, f)) })));
    entries.push({ name: 'Core/Cargo.toml', data: Buffer.from(sourceWorkspaceToml(await readFile(path.join(repo, 'Core', 'Cargo.toml'), 'utf8'))) });
    entries.push({ name: 'BUILDING.md', data: Buffer.from(buildingNotes({
      rustc: tool('rustc', ['--version']), cargo: tool('cargo', ['--version']), node: process.version, wasmBindgen, version: chrome.version,
    })) });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    source = makeZip(entries);
  }
  return { addon: pkg.firefox, source, files: pkg.files, manifest };
}

async function main(argv) {
  const outIdx = argv.indexOf('--out');
  const outDir = path.resolve(outIdx >= 0 ? argv[outIdx + 1] : path.join(FIREFOX_DIR, 'dist'));
  const files = await listPackageFiles(extension);
  const missing = missingWasm(files);
  if (missing.length) {
    throw new Error(`The browser vault's WebAssembly is not built (missing: ${missing.join(', ')}). Run "npm run wasm" in Extension/ first.`);
  }
  const { addon, source, manifest } = await buildFirefox();
  await mkdir(outDir, { recursive: true });
  for (const [name, buf] of [['pass-firefox.zip', addon], ['pass-firefox-source.zip', source]]) {
    await writeFile(path.join(outDir, name), buf);
    console.log(`wrote ${path.relative(process.cwd(), path.join(outDir, name))} (${buf.length} bytes)`);
  }
  const unpacked = path.join(outDir, 'unpacked');
  await rm(unpacked, { recursive: true, force: true });
  await mkdir(unpacked, { recursive: true });
  for (const f of files) await cp(path.join(extension, f), path.join(unpacked, f));
  await writeFile(path.join(unpacked, 'manifest.json'), JSON.stringify(manifest, null, 2) + '\n');
  console.log(`wrote ${path.relative(process.cwd(), unpacked)} (${files.length + 1} files)`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => { console.error(err); process.exit(1); });
}
