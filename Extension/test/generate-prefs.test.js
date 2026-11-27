// "Letters and numbers only" remembered per site (src/shared/generate-prefs.js): the site key without a
// public-suffix list, remember / forget, the most recent last, the cap, and storage that fails.
import { test, beforeEach } from 'node:test';
import assert from 'node:assert/strict';

let store = {};
let failing = false;
globalThis.chrome = {
  runtime: { id: 'pass-ext' },
  storage: {
    local: {
      get: async (keys) => {
        if (failing) throw new Error('storage unavailable');
        return Object.fromEntries(keys.filter((k) => k in store).map((k) => [k, structuredClone(store[k])]));
      },
      set: async (o) => {
        if (failing) throw new Error('storage unavailable');
        Object.assign(store, structuredClone(o));
      },
    },
  },
};
const { siteKeyOf, prefersNoSymbols, rememberSymbols, NO_SYMBOLS_KEY, MAX_SITES } = await import('../src/shared/generate-prefs.js');

beforeEach(() => { store = {}; failing = false; });

test('siteKeyOf: registrable domain as far as it can be told, nothing for other schemes', () => {
  const cases = {
    'https://shop.example/signup': 'shop.example',
    'https://www.shop.example/a?b': 'shop.example',
    'https://accounts.login.example.com/': 'example.com',
    'https://my.bank.example.co.uk/join': 'example.co.uk',
    'https://shop.example.com.au/': 'example.com.au',
    'https://a.b.example.de/': 'example.de',
    'https://www.example.co/': 'example.co',
    'http://localhost:8080/': 'localhost',
    'http://192.168.1.10/login': '192.168.1.10',
    'http://[::1]:3000/': '[::1]',
    'HTTPS://Shop.Example./x': 'shop.example',
    'chrome-extension://abc/popup.html': '',
    'file:///C:/x.html': '',
    'not a url': '',
    '': '',
  };
  for (const [url, key] of Object.entries(cases)) assert.equal(siteKeyOf(url), key, url);
});

test('remember without symbols, then with symbols again: forgotten', async () => {
  assert.equal(await prefersNoSymbols('https://shop.example/'), false);
  await rememberSymbols('https://login.shop.example/signup', false);
  assert.deepEqual(store[NO_SYMBOLS_KEY], ['shop.example']);
  assert.equal(await prefersNoSymbols('https://www.shop.example/account'), true, 'the whole site');
  assert.equal(await prefersNoSymbols('https://other.example/'), false);
  await rememberSymbols('https://shop.example/', true);
  assert.deepEqual(store[NO_SYMBOLS_KEY], []);
  assert.equal(await prefersNoSymbols('https://shop.example/'), false);
});

test('the most recent last; writes only on a change; nothing for non-web pages or a missing choice', async () => {
  await rememberSymbols('https://a.example/', false);
  await rememberSymbols('https://b.example/', false);
  await rememberSymbols('https://a.example/', false);
  assert.deepEqual(store[NO_SYMBOLS_KEY], ['b.example', 'a.example']);
  let writes = 0;
  const set = chrome.storage.local.set;
  chrome.storage.local.set = async (o) => { writes++; return set(o); };
  try {
    await rememberSymbols('https://a.example/', false);
    await rememberSymbols('https://c.example/', true);
    await rememberSymbols('chrome://settings', false);
    await rememberSymbols('https://d.example/', undefined);
  } finally {
    chrome.storage.local.set = set;
  }
  assert.equal(writes, 0);
  assert.deepEqual(store[NO_SYMBOLS_KEY], ['b.example', 'a.example']);
});

test(`at most ${MAX_SITES} sites: the oldest go first; junk in storage is dropped`, async () => {
  store[NO_SYMBOLS_KEY] = [...Array.from({ length: MAX_SITES }, (_, i) => `s${i}.example`), 42, '', null, 's1.example'];
  assert.equal(await prefersNoSymbols('https://s0.example/'), true);
  await rememberSymbols('https://new.example/', false);
  const list = store[NO_SYMBOLS_KEY];
  assert.equal(list.length, MAX_SITES);
  assert.equal(list.at(-1), 'new.example');
  assert.ok(!list.includes('s0.example'), 'the oldest dropped');
  assert.ok(list.every((v) => typeof v === 'string' && v));
});

test('storage unavailable: symbols by default, nothing thrown', async () => {
  failing = true;
  assert.equal(await prefersNoSymbols('https://shop.example/'), false);
  await rememberSymbols('https://shop.example/', false);
});

test('generator options: defaults, cleaning, remembered only on a change, storage that fails', async () => {
  const { generatorOptions, rememberOptions, cleanOptions, DEFAULT_OPTIONS, OPTIONS_KEY } = await import('../src/shared/generate-prefs.js');
  assert.deepEqual(await generatorOptions(), { ...DEFAULT_OPTIONS });
  assert.deepEqual(DEFAULT_OPTIONS, { mode: 'password', length: 20, lowercase: true, uppercase: true, digits: true, words: 6 });
  assert.deepEqual(cleanOptions({ mode: 'words', length: 3, words: 99, digits: 'no', uppercase: false, extra: 1 }),
    { mode: 'password', length: 20, lowercase: true, uppercase: false, digits: true, words: 6 });
  assert.deepEqual(cleanOptions({ mode: 'passphrase', length: 128, words: 4 }).length, 128);
  await rememberOptions({ mode: 'passphrase', words: 8 });
  assert.deepEqual(store[OPTIONS_KEY], { ...DEFAULT_OPTIONS, mode: 'passphrase', words: 8 });
  assert.deepEqual(await generatorOptions(), store[OPTIONS_KEY]);
  let writes = 0;
  const set = chrome.storage.local.set;
  chrome.storage.local.set = async (o) => { writes++; return set(o); };
  await rememberOptions({ mode: 'passphrase', words: 8 });
  assert.equal(writes, 0, 'the same options: nothing written');
  chrome.storage.local.set = set;
  await rememberOptions(null);
  await rememberOptions('x');
  assert.equal(store[OPTIONS_KEY].words, 8);
  failing = true;
  assert.deepEqual(await generatorOptions(), { ...DEFAULT_OPTIONS });
  await rememberOptions({ length: 30 });
});
