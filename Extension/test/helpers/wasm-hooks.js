// Loaded for every test file with --import (package.json). The background imports the WebAssembly glue
// (src/wasm/, git-ignored) statically, as an MV3 service worker must. Where it isn't built, or a test
// sets `globalThis.__passFakeWasm = true`, the glue and kdf.js resolve to fake-wasm.js and fake-kdf.js.
import { existsSync } from 'node:fs';
import module from 'node:module';
import { fileURLToPath } from 'node:url';

const wasmDir = new URL('../../src/wasm/', import.meta.url).href;
const fakes = {
  'pass_wasm.js': new URL('./fake-wasm.js', import.meta.url).href,
  'kdf.js': new URL('./fake-kdf.js', import.meta.url).href,
};
const RELATIVE = /^\.{1,2}\//;

/** The fake for `url` (a module of src/wasm/), or null for the real one. */
function redirect(url) {
  if (!url.startsWith(wasmDir)) return null;
  const real = url.split(/[?#]/)[0];
  const name = real.slice(wasmDir.length);
  if (!fakes[name]) return null;
  if (globalThis.__passFakeWasm === true || !existsSync(fileURLToPath(real))) return fakes[name];
  return null;
}

if (typeof module.registerHooks === 'function') {
  module.registerHooks({
    resolve(specifier, context, nextResolve) {
      // Before Node's own resolution, which fails on a file that isn't there.
      if (RELATIVE.test(specifier) && context.parentURL) {
        const fake = redirect(new URL(specifier, context.parentURL).href);
        if (fake) return { url: fake, format: 'module', shortCircuit: true };
      }
      return nextResolve(specifier, context);
    },
  });
} else {
  // Older Node: hooks off the main thread, so only "not built" can be seen there.
  const code = [
    "import { existsSync } from 'node:fs';",
    "import { fileURLToPath } from 'node:url';",
    `const wasmDir = ${JSON.stringify(wasmDir)};`,
    `const fakes = ${JSON.stringify(fakes)};`,
    `const RELATIVE = new RegExp(${JSON.stringify(RELATIVE.source)});`,
    'export async function resolve(specifier, context, next) {',
    '  if (RELATIVE.test(specifier) && context.parentURL) {',
    '    const real = new URL(specifier, context.parentURL).href.split(/[?#]/)[0];',
    '    const name = real.startsWith(wasmDir) ? real.slice(wasmDir.length) : "";',
    '    if (fakes[name] && !existsSync(fileURLToPath(real))) return { url: fakes[name], format: "module", shortCircuit: true };',
    '  }',
    '  return next(specifier, context);',
    '}',
  ].join('\n');
  module.register(`data:text/javascript,${encodeURIComponent(code)}`);
}
