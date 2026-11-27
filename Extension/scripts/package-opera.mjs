#!/usr/bin/env node
// Builds the Opera Add-ons packages:
//   node scripts/package-opera.mjs [--out dist]
//   -> dist/pass-opera.zip         the files of pass-chromium.zip with the Chrome Web Store manifest (no "key")
//   -> dist/pass-opera-source.zip  the readable source Opera's reviewers ask for, since the extension ships WebAssembly built from Rust
// The WebAssembly (src/wasm/) must be built first: `npm run wasm`.
import { readFile, readdir, writeFile, mkdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { buildPackages, makeZip, missingWasm, toStoreChromiumManifest } from './package.mjs';
import { sourceWorkspaceToml } from '../../Firefox/scripts/package.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const repo = path.resolve(root, '..');

/** The sibling repositories the source zip takes files from (each one's folder name). */
export const OPERA_SOURCE_REPOS = Object.freeze(['Core', 'Extension', 'Firefox']);
/** What the source zip takes from them (git ls-files paths with the folder name in front, prefix match). */
export const OPERA_SOURCE_PATHS = Object.freeze([
  'Core/.cargo/config.toml', 'Core/Cargo.lock', 'Core/core/', 'Core/agent/', 'Core/wasm/', 'Core/scripts/cargo-low.cmd', 'Extension/',
  // The packaging scripts import these.
  'Firefox/manifest.overrides.json', 'Firefox/scripts/firefox-manifest.mjs', 'Firefox/scripts/package.mjs',
]);
/** Never in the source zip, even when tracked. */
const SOURCE_EXCLUDED = [/(^|\/)node_modules\//, /(^|\/)\.env/, /\.pem$/, /(^|\/)google-oauth\.env$/];
/** A folder whose name starts with a dot, at any level (CI workflows, editor and tool settings). */
const DOT_FOLDER = /(^|\/)\.[^/]*\//;
/** Top-level Markdown of a repository that ships: the README and licence notices. */
const SOURCE_TOP_DOCS = new Set(['README.md', 'THIRD_PARTY_NOTICES.md']);
/** Markdown below the top level ships only under one of these names. */
const SOURCE_DOCS = new Set([...SOURCE_TOP_DOCS, 'SECURITY.md', 'CONTRIBUTING.md', 'CLA.md', 'TRADEMARKS.md']);

/** Whether a Markdown file (a path with the repository folder in front) is one of the public docs that ship. */
function shippedDoc(f) {
  const parts = f.split('/');
  return (parts.length === 2 ? SOURCE_TOP_DOCS : SOURCE_DOCS).has(parts[parts.length - 1]);
}

/**
 * Whether `f` stays out of the source zip. A path named on its own in OPERA_SOURCE_PATHS is taken even
 * inside a dot-folder (Core/.cargo/config.toml).
 */
function sourceExcluded(f) {
  if (SOURCE_EXCLUDED.some((re) => re.test(f))) return true;
  if (DOT_FOLDER.test(f) && !OPERA_SOURCE_PATHS.includes(f)) return true;
  return /\.md$/i.test(f) && !shippedDoc(f);
}

/** The Opera Add-ons manifest: the Chrome Web Store one (no `key`). */
export function toOperaManifest(chrome) {
  return toStoreChromiumManifest(chrome);
}

/** Tracked files for the source zip, sorted. */
export function operaSourceFiles(list) {
  return list
    .filter((f) => OPERA_SOURCE_PATHS.some((p) => (p.endsWith('/') ? f.startsWith(p) : f === p)))
    .filter((f) => !sourceExcluded(f))
    .sort();
}

/**
 * Opera's acceptance criteria: the title must not use Opera's name. Throws when `extName` or `short_name`
 * of any locale says "Opera".
 */
export async function checkOperaListing(chrome, dir = root) {
  const names = [chrome.short_name || ''];
  for (const locale of await readdir(path.join(dir, '_locales'))) {
    const messages = JSON.parse(await readFile(path.join(dir, '_locales', locale, 'messages.json'), 'utf8'));
    names.push(messages.extName?.message || '');
  }
  const bad = names.filter((n) => /opera/i.test(n));
  if (bad.length) throw new Error(`Opera Add-ons rejects titles with "Opera" in them: ${JSON.stringify(bad)}`);
}

function tool(command, args) {
  try { return execFileSync(command, args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim(); } catch { return ''; }
}

/** BUILDING.md for the source zip: the tool versions this package was built with, and the steps. */
export function operaBuildingNotes({ rustc, cargo, node, wasmBindgen, version }) {
  return `# Building Passyble for Opera ${version} from source

The extension is plain JavaScript (no bundler, no minifier): every .js file in pass-opera.zip is the
file in Extension/src/ as is. The only generated files are the browser vault's WebAssembly in src/wasm/:

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
node scripts/package-opera.mjs --out out
\`\`\`

\`Extension/out/pass-opera.zip\` is then the extension. To compare with the uploaded file, unzip both and
compare them. build-wasm.mjs maps local paths (the Cargo home and the Core folder) to fixed names, so
the WebAssembly comes out the same wherever it is built, and the zip has fixed timestamps and sorted
entries. Every file should match byte for byte.

The extension talks to the Passyble desktop app over native messaging (com.sensyble.pass), or keeps its
own encrypted vault in the browser (the WebAssembly above).
`;
}

function gitFiles(name) {
  return execFileSync('git', ['ls-files', '-z', '--cached', '--others', '--exclude-standard'], { cwd: path.join(repo, name), encoding: 'utf8' })
    .split('\0').filter(Boolean).map((f) => `${name}/${f}`);
}

/** Builds the Opera outputs in memory: { extension, source, files, manifest }. */
export async function buildOpera({ dir = root, withSource = true } = {}) {
  const pkg = await buildPackages(dir);
  const chrome = JSON.parse(await readFile(path.join(dir, 'manifest.json'), 'utf8'));
  await checkOperaListing(chrome, dir);
  const manifest = toOperaManifest(chrome);
  if (JSON.stringify(manifest) !== JSON.stringify(pkg.chromiumManifest)) throw new Error('the Opera and Chrome Web Store manifests differ');
  let source = null;
  if (withSource) {
    const files = operaSourceFiles(OPERA_SOURCE_REPOS.flatMap(gitFiles));
    const wasmBindgen = /^wasm-bindgen\s*=\s*"=([^"]+)"/m.exec(await readFile(path.join(repo, 'Core', 'wasm', 'Cargo.toml'), 'utf8'))?.[1] || '?';
    const entries = await Promise.all(files.map(async (f) => ({ name: f, data: await readFile(path.join(repo, f)) })));
    entries.push({ name: 'Core/Cargo.toml', data: Buffer.from(sourceWorkspaceToml(await readFile(path.join(repo, 'Core', 'Cargo.toml'), 'utf8'))) });
    entries.push({ name: 'BUILDING.md', data: Buffer.from(operaBuildingNotes({
      rustc: tool('rustc', ['--version']), cargo: tool('cargo', ['--version']), node: process.version, wasmBindgen, version: chrome.version,
    })) });
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    source = makeZip(entries);
  }
  return { extension: pkg.chromium, source, files: pkg.files, manifest };
}

async function main(argv) {
  const outIdx = argv.indexOf('--out');
  const outDir = path.resolve(outIdx >= 0 ? argv[outIdx + 1] : path.join(root, 'dist'));
  const { extension, source, files } = await buildOpera();
  const missing = missingWasm(files);
  if (missing.length) {
    throw new Error(`The browser vault's WebAssembly is not built (missing: ${missing.join(', ')}). Run "npm run wasm" first.`);
  }
  await mkdir(outDir, { recursive: true });
  for (const [name, buf] of [['pass-opera.zip', extension], ['pass-opera-source.zip', source]]) {
    await writeFile(path.join(outDir, name), buf);
    console.log(`wrote ${path.relative(process.cwd(), path.join(outDir, name)) || name} (${buf.length} bytes)`);
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => { console.error(err); process.exit(1); });
}
