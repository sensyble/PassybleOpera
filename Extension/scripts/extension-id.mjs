#!/usr/bin/env node
// Prints the Chrome/Edge extension ID for a manifest "key" (base64 DER SubjectPublicKeyInfo).
//   node scripts/extension-id.mjs [<base64-key>]   defaults to the "key" in manifest.json
//   node scripts/extension-id.mjs --check          exit 1 unless the native host allows the ID
// The ID is the first 128 bits of SHA-256(DER key), hex digits mapped 0-f to a-p.
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const NATIVE_MESSAGING_RS = path.resolve(root, '..', 'Core', 'desktop-app', 'src-tauri', 'src', 'native_messaging.rs');

export function extensionIdFromKey(base64Key) {
  const der = Buffer.from(base64Key.replace(/\s+/g, ''), 'base64');
  const hex = createHash('sha256').update(der).digest('hex').slice(0, 32);
  return [...hex].map((c) => String.fromCharCode('a'.charCodeAt(0) + parseInt(c, 16))).join('');
}

/** Extension IDs declared in native_messaging.rs. A list that is missing comes back as null. */
export function nativeHostIds(rustSource) {
  const strings = (name) => {
    const list = rustSource.match(new RegExp(`${name}\\s*:\\s*&\\[&str\\]\\s*=\\s*&\\[([^\\]]*)\\]`));
    return list ? [...list[1].matchAll(/"([^"]*)"/g)].map((m) => m[1]) : null;
  };
  const firefox = rustSource.match(/FIREFOX_EXTENSION_ID\s*:\s*&str\s*=\s*"([^"]*)"/);
  return {
    chromium: strings('CHROMIUM_EXTENSION_IDS'),
    chromeStore: strings('CHROME_STORE_EXTENSION_IDS'),
    edgeStore: strings('EDGE_STORE_EXTENSION_IDS'),
    opera: strings('OPERA_STORE_EXTENSION_IDS'),
    firefox: firefox ? firefox[1] : null,
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const check = args.includes('--check');
  let key = args.find((a) => !a.startsWith('--'));
  if (!key) key = JSON.parse(readFileSync(path.join(root, 'manifest.json'), 'utf8')).key;
  if (!key) {
    console.error('No key given and manifest.json has no "key" field (see README: "Stable extension ID").');
    process.exit(1);
  }
  const id = extensionIdFromKey(key);
  console.log(id);
  if (check) {
    const { chromium } = nativeHostIds(readFileSync(NATIVE_MESSAGING_RS, 'utf8'));
    if (!chromium?.includes(id)) {
      console.error(`${id} is not in CHROMIUM_EXTENSION_IDS (${NATIVE_MESSAGING_RS}): ${JSON.stringify(chromium)}`);
      process.exit(1);
    }
  }
}
