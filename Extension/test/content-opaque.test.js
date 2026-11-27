// Browsers report document.domain === "" exactly for opaque origins (sandboxed frames, CSP sandbox).
// jsdom has no sandboxing, so the tests set it.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM(`<!doctype html><html><body>
  <form id="f"><h1>Sign in</h1><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>
</body></html>`, { url: 'https://github.com/user-content/upload.html', pretendToBeVisual: true });
const w = dom.window;
Object.defineProperty(w.document, 'domain', { value: '', configurable: true });
w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};

const sent = [];
let main;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: w.document, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { sent.push(msg); return { ok: true, result: { items: [{ id: 'gh', title: 'GitHub', username: 'octo' }] } }; },
      onMessage: { addListener: () => { sent.push({ type: '(listening)' }); } },
    },
    storage: { local: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

test('opaque origin: the content script does not start (no menu, no messages, no save capture)', async () => {
  assert.equal(main.opaqueOrigin(), true);
  const email = w.document.querySelector('[name=email]');
  await dispatchTrusted(email, new w.MouseEvent('mousedown', { bubbles: true, composed: true, button: 0 }));
  email.focus();
  email.value = 'octo';
  w.document.querySelector('[name=password]').value = 'typed-secret';
  await dispatchTrusted(w.document.getElementById('f'), new w.Event('submit', { bubbles: true, cancelable: true }));
  await new Promise((r) => setTimeout(r, 300));
  assert.equal(w.document.querySelector('pass-icon'), null);
  assert.deepEqual(sent, []);
});
