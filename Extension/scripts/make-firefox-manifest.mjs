#!/usr/bin/env node
// Writes the Firefox variant of manifest.json (the Firefox-specific overrides and AMO packaging live in Firefox/):
//   node scripts/make-firefox-manifest.mjs [--dist dist/firefox
//  --out <file>
//  --in-place]
// Firefox refuses a manifest with default_locale but no _locales folder, so --dist copies _locales too.
import { readFile, writeFile, cp, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { toFirefoxManifest } from '../../Firefox/scripts/firefox-manifest.mjs';

export { GECKO_ID, GECKO_MIN_VERSION, CHROME_ONLY_PERMISSIONS, DATA_COLLECTION, toFirefoxManifest, firefoxRedirectUrls }
  from '../../Firefox/scripts/firefox-manifest.mjs';

/** Folders (besides manifest.json) that make up the loadable extension. */
export const RUNTIME_DIRS = Object.freeze(['src', 'icons', '_locales']);

/** The `__MSG_name__` names a manifest uses (any string value, at any depth). */
export function manifestMessageNames(manifest) {
  const names = new Set();
  const walk = (v) => {
    if (typeof v === 'string') for (const m of v.matchAll(/__MSG_([A-Za-z0-9_@]+)__/g)) names.add(m[1]);
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === 'object') Object.values(v).forEach(walk);
  };
  walk(manifest);
  return [...names].sort();
}

/** Throws unless the default locale has every __MSG_ name. Case-insensitive, like the browsers. */
export async function checkManifestMessages(manifest, dir) {
  const names = manifestMessageNames(manifest);
  if (!manifest.default_locale) {
    if (names.length) throw new Error(`manifest uses __MSG_${names[0]}__ but has no default_locale`);
    return;
  }
  const file = path.join(dir, '_locales', manifest.default_locale, 'messages.json');
  if (!existsSync(file)) throw new Error(`default_locale "${manifest.default_locale}" has no ${path.relative(dir, file)}`);
  const known = new Set(Object.keys(JSON.parse(await readFile(file, 'utf8'))).map((k) => k.toLowerCase()));
  const missing = names.filter((n) => !known.has(n.toLowerCase()));
  if (missing.length) throw new Error(`messages missing from ${path.relative(dir, file)}: ${missing.join(', ')}`);
}

async function main(argv) {
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
  const src = path.join(root, 'manifest.json');
  const distIdx = argv.indexOf('--dist');
  if (distIdx >= 0) {
    const dist = path.resolve(argv[distIdx + 1] || path.join(root, 'dist', 'firefox'));
    await rm(dist, { recursive: true, force: true });
    await mkdir(dist, { recursive: true });
    const chrome = JSON.parse(await readFile(src, 'utf8'));
    await checkManifestMessages(chrome, root);
    for (const dir of RUNTIME_DIRS) await cp(path.join(root, dir), path.join(dist, dir), { recursive: true });
    await writeFile(path.join(dist, 'manifest.json'), JSON.stringify(toFirefoxManifest(chrome), null, 2) + '\n');
    console.log(`wrote ${path.relative(process.cwd(), dist) || dist}`);
    return;
  }
  const inPlace = argv.includes('--in-place');
  const outIdx = argv.indexOf('--out');
  const out = inPlace ? src : path.resolve(outIdx >= 0 ? argv[outIdx + 1] : path.join(root, 'manifest.firefox.json'));
  const chrome = JSON.parse(await readFile(src, 'utf8'));
  if (chrome.browser_specific_settings && !chrome.background?.service_worker) {
    console.log('manifest.json already looks like a Firefox manifest; nothing to do');
    return;
  }
  await writeFile(out, JSON.stringify(toFirefoxManifest(chrome), null, 2) + '\n');
  console.log(`wrote ${path.relative(process.cwd(), out) || out}`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main(process.argv.slice(2)).catch((err) => { console.error(err); process.exit(1); });
}
