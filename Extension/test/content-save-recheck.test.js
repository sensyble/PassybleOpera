import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';

const dom = new JSDOM('<!doctype html><html><body><p>Welcome back</p></body></html>', { url: 'https://github.com/', pretendToBeVisual: true });
const w = dom.window;
const doc = w.document;

w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};

const sent = [];
const banner = (mode) => ({ mode, host: 'github.com', username: 'octo', title: mode === 'save' ? null : 'GitHub', token: `tok-${mode}`, editable: true, check: null });
let answer = () => banner('save'); // save.query
const responses = {
  'otp.context': () => ({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': () => ({ items: [], pending_otp: null }),
  'save.query': (msg) => answer(msg),
};

let main;
let runtimeListener;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return { ok: true, result: fn ? fn(msg) : {} };
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: { local: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  globalThis.__passBridge = { alive: () => true, hasConditional: () => false, onConditionalChange: () => () => {}, completeConditional: async () => ({ ok: true }) };
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  main.stop();
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const waitFor = async (fn, ms = 2000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) { const v = fn(); if (v) return v; await tick(20); }
  return fn();
};
const recheck = () => new Promise((resolve) => {
  const async = runtimeListener({ type: 'save.recheck' }, { id: 'pass-ext' }, resolve);
  if (!async) resolve(undefined);
});

test('a banner shown while locked goes away when the unlock shows the login is saved already', async () => {
  assert.ok(await waitFor(() => doc.querySelector('pass-banner')), 'shown on load (vault locked: "Save login?")');
  answer = () => ({ close: true });
  const res = await recheck();
  assert.equal(res.ok, true);
  assert.deepEqual(sent.filter((m) => m.type === 'save.query').at(-1), { type: 'save.query', recheck: true });
  assert.equal(doc.querySelector('pass-banner'), null, 'closed');
  assert.equal(sent.filter((m) => m.type === 'save.dismiss').length, 0, 'not a "Not now" of the user');
});

test('a banner held back while locked shows after the unlock; nothing when there is nothing to ask', async () => {
  answer = () => null;
  await recheck();
  assert.equal(doc.querySelector('pass-banner'), null);
  answer = () => banner('update');
  await recheck();
  assert.ok(await waitFor(() => doc.querySelector('pass-banner')), '"Update password?" now');
  // A second answer replaces it: never two banners.
  await recheck();
  await tick(20);
  assert.equal(doc.querySelectorAll('pass-banner').length, 1);
});
