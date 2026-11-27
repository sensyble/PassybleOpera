// Memory of the content script, which runs in every frame of every tab: the save banner and the generated
// password's callout load on first use, and the browser vault's lock drops the shared vaults' keys at once.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

const read = (path) => readFileSync(new URL(path, import.meta.url), 'utf8');
const main = read('../src/content/main.js');

test('main.js does not import banner.js or reveal.js statically', () => {
  const statics = [...main.matchAll(/^import[^;]*from '([^']+)';/gms)].map((m) => m[1]);
  assert.ok(statics.length > 5, 'found the static imports');
  for (const lazy of ['./banner.js', './reveal.js']) {
    assert.ok(!statics.includes(lazy), `${lazy} is imported statically`);
    assert.ok(main.includes(`import('${lazy}')`), `${lazy} is loaded on demand`);
  }
});

test('a banner or callout closed while loading never shows', () => {
  for (const name of ['saveBanner', 'generatedReveal']) {
    assert.match(main, new RegExp(`if \\(pending\\.closed \\|\\| ${name} !== pending\\) return;`), name);
  }
});

test('the browser vault locking frees the shared vaults', () => {
  const bg = read('../src/background.js');
  const handler = bg.slice(bg.indexOf("local.on('lock_state'"), bg.indexOf("local.on('vault_changed'"));
  assert.match(handler, /data\?\.locked === true\) \{ try \{ teamsInstance\?\.lock\(\); \}/);
});
