// How fast the browser vault's WebAssembly answers what the popup and content scripts ask per keystroke and per
// page, in Node's V8. Skipped when src/wasm/ isn't built. Every run checks search and page matching over 2 000
// made-up summaries with generous limits; PASS_PERF_VAULT=<Core's 5 000-item demo vault> also times unlocking and
// the lists across a home vault and three shared ones.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';

const dir = new URL('../src/wasm/', import.meta.url);
const built = existsSync(new URL('pass_wasm_bg.wasm', dir)) && existsSync(new URL('pass_wasm_kdf.wasm', dir));
const skip = built ? false : 'src/wasm/ is not built (npm run wasm)';
const fixture = process.env.PASS_PERF_VAULT || '';
const skipFixture = skip || (fixture && existsSync(fixture) ? false : 'PASS_PERF_VAULT is not set');

const KEYSTROKES = ['g', 'gi', 'git', 'gith', 'githu', 'github', 'github 1'];
const WORDS = ['github', 'gitlab', 'google', 'mail', 'bank', 'shop', 'cloud', 'music', 'video', 'news', 'travel', 'hotel'];

async function load() {
  const glue = await import(new URL('pass_wasm.js', dir));
  await glue.default({ module_or_path: readFileSync(new URL('pass_wasm_bg.wasm', dir)) });
  const { loadKdf } = await import(new URL('kdf.js', dir));
  glue.setKdf(await loadKdf(readFileSync(new URL('pass_wasm_kdf.wasm', dir))));
  return glue;
}

const json = (text) => JSON.parse(text);

/** The median time of `runs` calls of `f`, in milliseconds (after one warm-up call). */
function median(runs, f) {
  f();
  const times = [];
  for (let i = 0; i < runs; i++) {
    const t = process.hrtime.bigint();
    f();
    times.push(Number(process.hrtime.bigint() - t) / 1e6);
  }
  times.sort((a, b) => a - b);
  return times[Math.floor(times.length / 2)];
}

const perKeystroke = (f) => median(5, () => KEYSTROKES.forEach(f)) / KEYSTROKES.length;
const show = (name, ms) => console.log(`${name.padEnd(46)} ${ms.toFixed(3).padStart(9)} ms`);

function summaries(n, offset) {
  return Array.from({ length: n }, (_, i) => {
    const site = `${WORDS[(i * 7) % WORDS.length]}${(i + offset) % 1500}.com`;
    return {
      id: `item-${offset + i}`, kind: 'login', title: `${WORDS[i % WORDS.length]} ${offset + i}`,
      username: `kim.demo${i % 7}@example.com`, urls: [`https://${site}/login`], domain: site, rank: i % 13,
    };
  });
}

const group = (id, list) => ({ vault_id: id, shared: id === 'home' ? null : 'org', can_edit: true, can_reveal: true, summaries: list });

test('search and page matching across vaults stay fast', { skip }, async () => {
  const glue = await load();
  const groups = JSON.stringify([group('home', summaries(1400, 0)), group('team', summaries(600, 10000))]);
  const search = perKeystroke((q) => assert.ok(json(glue.multiSearch(groups, q)).result));
  const page = median(9, () => json(glue.multiForUrl(groups, 'https://github7.com/login')));
  show('multiSearch per keystroke, 2 000 summaries', search);
  show('multiForUrl, 2 000 summaries', page);
  // Far above what they take (a few milliseconds here): only for work that grows out of proportion.
  assert.ok(search < 400, `multiSearch took ${search} ms per keystroke`);
  assert.ok(page < 200, `multiForUrl took ${page} ms`);
  if (typeof glue.SearchIndex !== 'function') return;
  // The lists read once (what the Teams code keeps while they don't change): the same answers.
  const index = new glue.SearchIndex(groups);
  try {
    for (const q of [...KEYSTROKES, '', 'kim', 'zzz']) assert.equal(index.search(q), glue.multiSearch(groups, q), q);
    assert.equal(index.forUrl('https://github7.com/login'), glue.multiForUrl(groups, 'https://github7.com/login'));
    const flat = JSON.parse(groups).flatMap((g) => g.summaries.map((summary) => ({ vault_id: g.vault_id, summary })));
    for (const q of KEYSTROKES) {
      const byPlace = Array.from(index.searchPositions(q), (i) => flat[i].summary.id);
      assert.deepEqual(byPlace, json(glue.multiSearch(groups, q)).result.map((h) => h.summary.id), q);
    }
    const kept = perKeystroke((q) => index.searchPositions(q));
    show('SearchIndex.searchPositions per keystroke, 2 000', kept);
    assert.ok(kept < 100, `SearchIndex.search took ${kept} ms per keystroke`);
  } finally {
    index.free();
  }
});

test('the 5 000-item demo vault: unlock, search per keystroke, page matching', { skip: skipFixture }, async () => {
  const glue = await load();
  const file = new Uint8Array(readFileSync(fixture));
  const agent = new glue.BrowserAgent(JSON.stringify({ device_id: 'node-perf' }));
  agent.load(file);
  let t = process.hrtime.bigint();
  assert.equal(json(agent.unlock('demo master password')).result.locked, false);
  show('unlock (Argon2id 64 MiB t=3, 5 000 items)', Number(process.hrtime.bigint() - t) / 1e6);
  const request = (method, params) => json(agent.handle(JSON.stringify({ id: 1, method, params })));
  const search = perKeystroke((q) => {
    if (q.length < 2) return; // the popup asks from two characters on
    assert.ok(request('logins.search', { query: q, url: 'https://paypa1.com/' }).result);
  });
  show('logins.search per keystroke (from 2 letters)', search * KEYSTROKES.length / (KEYSTROKES.length - 1));
  show('logins.find (a page with a login form)', median(9, () => request('logins.find', { url: 'https://accounts.github7.com/login' })));
  t = process.hrtime.bigint();
  const home = json(agent.homeSummaries()).result;
  show('homeSummaries', Number(process.hrtime.bigint() - t) / 1e6);
  const shared = [0, 1, 2].map((v) => group(`team-${v}`, home.summaries.slice(v * 500, v * 500 + 500).map((s) => ({ ...s, id: `${v}-${s.id}` }))));
  const groups = JSON.stringify([home, ...shared]);
  show('multiSearch per keystroke (5 000 + 3 x 500)', perKeystroke((q) => glue.multiSearch(groups, q)));
  show('multiForUrl (5 000 + 3 x 500)', median(9, () => glue.multiForUrl(groups, 'https://accounts.github7.com/login')));
  if (typeof glue.SearchIndex !== 'function') return;
  assert.equal(agent.homeStamp(), agent.homeStamp(), 'the stamp holds while nothing changes');
  show('homeStamp', median(9, () => agent.homeStamp()));
  t = process.hrtime.bigint();
  const index = new glue.SearchIndex(groups);
  show('new SearchIndex (5 000 + 3 x 500, once per change)', Number(process.hrtime.bigint() - t) / 1e6);
  show('SearchIndex.search per keystroke (JSON out)', perKeystroke((q) => index.search(q)));
  show('SearchIndex.searchPositions per keystroke', perKeystroke((q) => index.searchPositions(q)));
  show('SearchIndex.forUrl', median(9, () => index.forUrl('https://accounts.github7.com/login')));
  index.free();
});
