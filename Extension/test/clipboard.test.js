import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import { CLEAR_AFTER_MS, hmacHex, randomKeyHex, clearClipboard, writeEmptyClipboard } from '../src/shared/clipboard.js';
import { createClipboardClearer, clearViaOffscreen, CLEAR_ALARM, OFFSCREEN_URL } from '../src/background/clipboard-clear.js';

function fakeExt({ session = true } = {}) {
  const store = {};
  const alarms = [];
  const ext = {
    alarms: { create: async (name, info) => { alarms.push([name, info]); } },
    storage: session ? { session: {
      set: async (o) => Object.assign(store, o),
      get: async (k) => (k in store ? { [k]: store[k] } : {}),
      remove: async (k) => { delete store[k]; },
    } } : {},
  };
  return { ext, store, alarms };
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

test('hmacHex: RFC 4231 test case 2; randomKeyHex: 32 random bytes', async () => {
  const key = [...new TextEncoder().encode('Jefe')].map((b) => b.toString(16).padStart(2, '0')).join('');
  assert.equal(await hmacHex(key, 'what do ya want for nothing?'), '5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843');
  assert.match(randomKeyHex(), /^[0-9a-f]{64}$/);
  assert.notEqual(randomKeyHex(), randomKeyHex());
});

test('schedule: 45 s alarm, only a keyed HMAC is stored (never the key), later copies replace earlier ones', async () => {
  const { ext, store, alarms } = fakeExt();
  const cleared = [];
  const c = createClipboardClearer({ ext, clearNow: async (what) => { cleared.push(what); return 'cleared'; }, now: () => 1000 });
  assert.equal(CLEAR_AFTER_MS, 45_000);
  assert.equal(await c.schedule('hunter2'), true);
  assert.deepEqual(alarms[0], [CLEAR_ALARM, { when: 46_000 }]);
  assert.ok(!JSON.stringify(store).includes('hunter2'), 'value never stored');
  await c.schedule('123456');
  assert.equal(alarms.length, 2);
  assert.equal(alarms[1][0], CLEAR_ALARM, 'same alarm name: replaces the pending one');
  const stored = store.passClipboardClear;
  assert.deepEqual(Object.keys(stored).sort(), ['mac', 'when'], 'no key next to the HMAC');
  assert.notEqual(stored.mac, await sha256Hex('123456'), 'not a plain hash, which a 6-digit code is looked up from');

  assert.equal(await c.onAlarm({ name: 'something-else' }), null);
  assert.equal(await c.onAlarm({ name: CLEAR_ALARM }), 'cleared');
  assert.equal(cleared.length, 1, 'only the latest copy');
  assert.equal(cleared[0].mac, stored.mac);
  assert.equal(await hmacHex(cleared[0].key, '123456'), stored.mac, 'the in-memory key goes with it');
  assert.deepEqual(store, {}, 'state dropped');
  assert.equal(await c.onAlarm({ name: CLEAR_ALARM }), null, 'nothing pending: no clear');
  assert.equal(cleared.length, 1);
});

test('a service worker started again within the 45 s still clears, without the old key', async () => {
  const { ext, store } = fakeExt();
  const first = createClipboardClearer({ ext, clearNow: async () => 'cleared' });
  await first.schedule('654321');
  const { mac } = store.passClipboardClear;
  const cleared = [];
  // The same storage.session, a new service worker (module state gone).
  const again = createClipboardClearer({ ext, clearNow: async (what) => { cleared.push(what); return 'cleared'; } });
  assert.equal(await again.onAlarm({ name: CLEAR_ALARM }), 'cleared');
  assert.deepEqual(cleared, [{ mac, key: null }], 'cleared as when the clipboard is not readable');
});

test('schedule ignores empty, non-string and oversized values; works without storage.session', async () => {
  const { ext, alarms } = fakeExt({ session: false });
  let cleared = 0;
  const c = createClipboardClearer({ ext, clearNow: async () => { cleared++; } });
  assert.equal(await c.schedule(''), false);
  assert.equal(await c.schedule(42), false);
  assert.equal(await c.schedule('x'.repeat(5000)), false);
  assert.equal(alarms.length, 0);
  assert.equal(await c.schedule('p@ss'), true);
  await c.onAlarm({ name: CLEAR_ALARM });
  assert.equal(cleared, 1);
});

function clipboardDom(clipboard) {
  const { window, document } = makeDom('');
  Object.defineProperty(window.navigator, 'clipboard', { value: clipboard, configurable: true });
  return { window, document };
}

const KEY = randomKeyHex();

test('clearClipboard: readable and still ours -> cleared', async () => {
  const writes = [];
  const { document } = clipboardDom({ readText: async () => 'hunter2', writeText: async (t) => { writes.push(t); } });
  assert.equal(await clearClipboard(document, { mac: await hmacHex(KEY, 'hunter2'), key: KEY }), 'cleared');
  assert.deepEqual(writes, ['']);
});

test('clearClipboard: readable and something else was copied -> left alone', async () => {
  const writes = [];
  const { document } = clipboardDom({ readText: async () => 'my notes', writeText: async (t) => { writes.push(t); } });
  assert.equal(await clearClipboard(document, { mac: await hmacHex(KEY, 'hunter2'), key: KEY }), 'changed');
  assert.deepEqual(writes, []);
});

test('clearClipboard: not readable, or no key to compare with -> cleared (Passyble copied last)', async () => {
  const writes = [];
  const { document } = clipboardDom({ readText: async () => { throw new Error('NotAllowedError'); }, writeText: async (t) => { writes.push(t); } });
  document.execCommand = () => false; // paste not allowed either
  assert.equal(await clearClipboard(document, { mac: await hmacHex(KEY, 'hunter2'), key: KEY }), 'cleared');
  assert.deepEqual(writes, ['']);
  const other = clipboardDom({ readText: async () => 'my notes', writeText: async (t) => { writes.push(t); } });
  assert.equal(await clearClipboard(other.document, { mac: await hmacHex(KEY, 'hunter2'), key: null }), 'cleared');
  assert.deepEqual(writes, ['', '']);
});


test('writeEmptyClipboard falls back to execCommand(copy) with an empty payload (offscreen document)', async () => {
  const { window, document } = clipboardDom({ writeText: async () => { throw new Error('Document is not focused'); } });
  let data = null;
  document.execCommand = (cmd) => {
    assert.equal(cmd, 'copy');
    const e = new window.Event('copy', { cancelable: true });
    e.clipboardData = { setData: (type, v) => { data = [type, v]; } };
    document.dispatchEvent(e);
    return e.defaultPrevented;
  };
  assert.equal(await writeEmptyClipboard(document), true);
  assert.deepEqual(data, ['text/plain', '']);
  assert.equal(document.querySelector('textarea'), null, 'helper element removed');
});

test('clearViaOffscreen: CLIPBOARD offscreen document, HMAC and key sent, document closed', async () => {
  const log = [];
  const ext = {
    offscreen: {
      createDocument: async (opts) => { log.push(['create', opts.url, opts.reasons]); },
      closeDocument: async () => { log.push(['close']); },
    },
    runtime: { sendMessage: async (msg) => { log.push(['msg', msg]); return { result: 'cleared' }; } },
  };
  assert.equal(await clearViaOffscreen(ext, { mac: 'abc', key: 'k1' }), 'cleared');
  assert.deepEqual(log, [
    ['create', OFFSCREEN_URL, ['CLIPBOARD']],
    ['msg', { target: 'offscreen', type: 'clipboard.clear', mac: 'abc', key: 'k1' }],
    ['close'],
  ]);
  // An already open document is reused.
  ext.offscreen.createDocument = async () => { throw new Error('Only a single offscreen document may be created.'); };
  assert.equal(await clearViaOffscreen(ext, { mac: 'abc', key: 'k1' }), 'cleared');
});

test('offscreen.js answers only clipboard.clear messages from the extension itself', async () => {
  const { window, document } = clipboardDom({ readText: async () => { throw new Error('no'); }, writeText: async () => {} });
  document.execCommand = () => false;
  let listener;
  globalThis.document = document;
  globalThis.chrome = { runtime: { id: 'pass-ext', onMessage: { addListener: (f) => { listener = f; } } } };
  try {
    await import('../src/offscreen/offscreen.js');
    assert.equal(listener({ target: 'offscreen', type: 'clipboard.clear', mac: 'x', key: null }, { id: 'other' }, () => {}), false);
    assert.equal(listener({ type: 'lock_state' }, { id: 'pass-ext' }, () => {}), false);
    const res = await new Promise((resolve) => {
      assert.equal(listener({ target: 'offscreen', type: 'clipboard.clear', mac: 'x', key: null }, { id: 'pass-ext' }, resolve), true);
    });
    assert.deepEqual(res, { result: 'cleared' });
  } finally {
    delete globalThis.document;
    delete globalThis.chrome;
    window.close();
  }
});
