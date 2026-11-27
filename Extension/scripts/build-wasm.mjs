#!/usr/bin/env node
// Builds the browser vault's WebAssembly into src/wasm/:
//   node scripts/build-wasm.mjs [--no-install] [--no-opt] [--out <dir>]
// Needs the Core repository next to this one and `rustup target add wasm32-unknown-unknown`.
// wasm-opt runs when it is on the PATH.
import { spawnSync } from 'node:child_process';
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const extension = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
/** The Core workspace: `--core <dir>`, else PASSYBLE_CORE_DIR, else ../Core, relative to the extension folder. */
export function resolveCoreDir(argv, env, extensionDir) {
  const i = argv.indexOf('--core');
  if (i >= 0 && (!argv[i + 1] || argv[i + 1].startsWith('--'))) throw new Error('--core needs a folder');
  const given = i >= 0 ? argv[i + 1] : (env.PASSYBLE_CORE_DIR || '').trim();
  return path.resolve(extensionDir, given || path.join('..', 'Core'));
}

const core = resolveCoreDir(process.argv.slice(2), process.env, extension);
const windows = process.platform === 'win32';

/** The main module may not grow past this, gzipped. */
export const BUDGET_GZIP_BYTES = 1.5 * 1024 * 1024;

/** The wasm-bindgen version Core/wasm/Cargo.toml pins (`wasm-bindgen = "=<version>"`). */
export function pinnedWasmBindgen(cargoToml) {
  const m = /^wasm-bindgen\s*=\s*"=([0-9][^"]*)"/m.exec(cargoToml);
  if (!m) throw new Error('Core/wasm/Cargo.toml must pin wasm-bindgen with "=<version>"');
  return m[1];
}

/** The version a `wasm-bindgen --version` line names (`wasm-bindgen 0.2.129`), or null. */
export function cliVersion(output) {
  const m = /wasm-bindgen\s+([0-9][^\s]*)/.exec(output || '');
  return m ? m[1] : null;
}

function run(command, args, options = {}) {
  console.log(`> ${command} ${args.join(' ')}`);
  const result = spawnSync(command, args, { stdio: 'inherit', cwd: core, ...options });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`${command} exited with ${result.status}`);
}

/**
 * rustc flags that map the Cargo home and the Core folder to fixed names (/cargo, /src). Panic messages
 * carry source paths, so without this the WebAssembly holds local paths and differs from machine to machine.
 * Flags already set in CARGO_ENCODED_RUSTFLAGS or RUSTFLAGS come first.
 */
export function remapRustflags(env, coreDir, home = homedir()) {
  const cargoHome = (env.CARGO_HOME || '').trim() || path.join(home, '.cargo');
  const own = env.CARGO_ENCODED_RUSTFLAGS ? env.CARGO_ENCODED_RUSTFLAGS.split('\x1f')
    : (env.RUSTFLAGS || '').split(/\s+/).filter(Boolean);
  return [...own, `--remap-path-prefix=${cargoHome}=/cargo`, `--remap-path-prefix=${coreDir}=/src`].join('\x1f');
}

// Idle CPU priority on Windows so the build does not slow the PC down.
function cargo(args, env = process.env) {
  const options = { env };
  if (windows) run('cmd', ['/c', path.join(core, 'scripts', 'cargo-low.cmd'), ...args], options);
  else run('cargo', args, options);
}

function capture(command, args) {
  const result = spawnSync(command, args, { cwd: core, encoding: 'utf8', shell: false });
  return result.error || result.status !== 0 ? null : result.stdout;
}

function targetDir() {
  if (process.env.CARGO_TARGET_DIR) return path.resolve(core, process.env.CARGO_TARGET_DIR);
  const metadata = capture('cargo', ['metadata', '--format-version', '1', '--no-deps']);
  return metadata ? JSON.parse(metadata).target_directory : path.join(core, 'target');
}

function ensureWasmBindgen(version, install) {
  const found = cliVersion(capture('wasm-bindgen', ['--version']));
  if (found === version) return;
  const command = ['install', 'wasm-bindgen-cli', '--version', version, '--locked'];
  const why = found ? `wasm-bindgen ${found} is installed, the crate uses ${version}` : 'wasm-bindgen is not installed';
  if (!install) {
    throw new Error(`${why}. Install it with: cargo ${command.join(' ')}`);
  }
  console.log(`${why}: installing it.`);
  cargo(command);
  const now = cliVersion(capture('wasm-bindgen', ['--version']));
  if (now !== version) throw new Error(`wasm-bindgen ${version} still not on the PATH (found ${now})`);
}

/** Features rustc's wasm32 target emits by default; wasm-opt must accept them. */
const WASM_OPT_FEATURES = [
  '--enable-bulk-memory', '--enable-mutable-globals', '--enable-nontrapping-float-to-int',
  '--enable-sign-ext', '--enable-reference-types', '--enable-multivalue',
];

function optimize(file, level) {
  if (!capture('wasm-opt', ['--version'])) return false;
  run('wasm-opt', [level, ...WASM_OPT_FEATURES, file, '-o', file]);
  return true;
}

const kib = (n) => `${(n / 1024).toFixed(0)} KiB`;

async function main(argv) {
  const outIdx = argv.indexOf('--out');
  const out = path.resolve(outIdx >= 0 ? argv[outIdx + 1] : path.join(extension, 'src', 'wasm'));
  const install = !argv.includes('--no-install');
  const opt = !argv.includes('--no-opt');
  console.log(`Passyble-Core: ${core}`);
  const version = pinnedWasmBindgen(readFileSync(path.join(core, 'wasm', 'Cargo.toml'), 'utf8'));

  const buildEnv = { ...process.env, CARGO_ENCODED_RUSTFLAGS: remapRustflags(process.env, core) };
  delete buildEnv.RUSTFLAGS;
  cargo(['build', '--profile', 'wasm-release', '--target', 'wasm32-unknown-unknown', '-p', 'pass-wasm'], buildEnv);
  cargo(['build', '--release', '--target', 'wasm32-unknown-unknown', '-p', 'pass-wasm-kdf'], buildEnv);
  ensureWasmBindgen(version, install);

  const target = path.join(targetDir(), 'wasm32-unknown-unknown');
  const staging = mkdtempSync(path.join(tmpdir(), 'pass-wasm-'));
  try {
    run('wasm-bindgen', [
      '--target', 'web', '--no-typescript', '--out-name', 'pass_wasm', '--out-dir', staging,
      path.join(target, 'wasm-release', 'pass_wasm.wasm'),
    ]);
    copyFileSync(path.join(target, 'release', 'pass_wasm_kdf.wasm'), path.join(staging, 'pass_wasm_kdf.wasm'));
    let optimized = false;
    if (opt) {
      optimized = optimize(path.join(staging, 'pass_wasm_bg.wasm'), '-Oz');
      optimize(path.join(staging, 'pass_wasm_kdf.wasm'), '-O3');
    }
    if (!optimized) console.log('wasm-opt not found (or --no-opt): the modules are not post-optimized.');
    mkdirSync(out, { recursive: true });
    for (const name of ['pass_wasm.js', 'pass_wasm_bg.wasm', 'pass_wasm_kdf.wasm']) {
      copyFileSync(path.join(staging, name), path.join(out, name));
    }
    copyFileSync(path.join(core, 'wasm', 'kdf', 'kdf.js'), path.join(out, 'kdf.js'));
  } finally {
    rmSync(staging, { recursive: true, force: true });
  }

  const sizes = {};
  for (const name of ['pass_wasm_bg.wasm', 'pass_wasm_kdf.wasm', 'pass_wasm.js']) {
    const data = readFileSync(path.join(out, name));
    sizes[name] = { bytes: statSync(path.join(out, name)).size, gzip: gzipSync(data, { level: 9 }).length };
    console.log(`${name}: ${kib(sizes[name].bytes)} (${kib(sizes[name].gzip)} gzipped)`);
  }
  writeFileSync(path.join(out, 'build.json'), JSON.stringify({ wasm_bindgen: version, sizes }, null, 2) + '\n');
  if (sizes['pass_wasm_bg.wasm'].gzip > BUDGET_GZIP_BYTES) {
    throw new Error(`pass_wasm_bg.wasm is ${kib(sizes['pass_wasm_bg.wasm'].gzip)} gzipped, over the budget of ${kib(BUDGET_GZIP_BYTES)}`);
  }
  console.log(`wrote ${path.relative(process.cwd(), out) || out}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => { console.error(err.message || err); process.exit(1); });
}
