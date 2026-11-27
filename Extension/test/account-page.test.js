// The Passyble password page (real src/account/account.html + account.js in jsdom): password sign-in, approval from
// another device, and app mode, which offers nothing (the Passyble app holds the account key).
import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;
let timers = [];
let timerSeq = 0;

async function openPage(hash = '') {
  const html = readFileSync(new URL('../src/account/account.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: `https://extension.test/src/account/account.html${hash}`, pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event']) globalThis[k] = dom.window[k];
  globalThis.window = dom.window;
  globalThis.location = dom.window.location;
  messages.length = 0;
  timers = [];
  globalThis.setTimeout = (fn, ms) => { if (ms === 2000) { timers.push({ id: ++timerSeq, fn }); return timerSeq; } return realSetTimeout(fn, ms); };
  globalThis.clearTimeout = (id) => { timers = timers.filter((x) => x.id !== id); realClearTimeout(id); };
  await import(`../src/account/account.js?instance=${++instance}`);
  await settle();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

const realSetTimeout = globalThis.setTimeout;
const realClearTimeout = globalThis.clearTimeout;
const settle = async () => { for (let i = 0; i < 6; i++) await new Promise((r) => realSetTimeout(r, 0)); };
const sent = (type) => messages.filter((m) => m.type === type);
/** Runs the poll the page scheduled (2 s), once. */
async function tick() {
  const due = timers.splice(0);
  for (const { fn } of due) fn();
  await settle();
}

before(() => {
  globalThis.chrome = { runtime: { id: 'pass-ext', sendMessage: async (msg) => { messages.push(msg); return reply(msg); } } };
});

afterEach(() => {
  globalThis.setTimeout = realSetTimeout;
  globalThis.clearTimeout = realClearTimeout;
  delete globalThis.window;
  delete globalThis.location;
});

function background({ keysState = { available: true, linked: null }, signIn, approval = [], confirm = null, cancel = null } = {}) {
  const polls = [...approval];
  reply = (msg) => {
    switch (msg.type) {
      case 'account.keys-state': return { ok: true, result: keysState };
      case 'account.status': return { ok: true, result: { signed_in: false, email: null, app_mode: false } };
      case 'account.password-sign-in': return signIn(msg);
      case 'account.approval-start': return { ok: true, result: { id: 'akq_1', expires_at: Date.now() + 600_000, qr: { size: 29, path: 'M4 4h1v1h-1z' } } };
      case 'account.approval-poll': return { ok: true, result: polls.length ? polls.shift() : { state: 'none' } };
      case 'account.approval-cancel': return { ok: true, result: cancel || { state: 'none' } };
      case 'account.approval-confirm': return confirm(msg);
      default: return { ok: true, result: null };
    }
  };
}

const submit = (win, form) => form.dispatchEvent(new win.Event('submit', { cancelable: true, bubbles: true }));

test('sign in with the Passyble password: the Secret Key once the background asks, then "Signed in as"', async () => {
  background({
    signIn: (msg) => (msg.secret_key
      ? { ok: true, result: { signed_in: true, email: 'demo@example.com', unlocked: true } }
      : { ok: false, error: { code: 'invalid_state', message: 'secret key needed', reason: 'secret_key_needed' } }),
  });
  const { window: win, $ } = await openPage();
  assert.equal($('in-app').hidden, true);
  assert.equal($('pw-form').hidden, false);
  assert.equal($('approve').hidden, false);
  assert.equal($('pw-sk-part').hidden, true);

  $('pw-email').value = 'demo@example.com';
  $('pw-password').value = 'passyble pw';
  submit(win, $('pw-form'));
  await settle();
  assert.deepEqual(sent('account.password-sign-in').at(-1), { type: 'account.password-sign-in', email: 'demo@example.com', password: 'passyble pw' });
  assert.equal($('pw-sk-part').hidden, false);
  assert.equal($('pw-password').value, '');
  assert.equal($('pw-msg').textContent, "Enter your Secret Key once in this browser. It's in your Emergency Kit.");

  $('pw-password').value = 'passyble pw';
  $('pw-secret-key').value = 'P1-AAAAA';
  submit(win, $('pw-form'));
  await settle();
  assert.deepEqual(sent('account.password-sign-in').at(-1),
    { type: 'account.password-sign-in', email: 'demo@example.com', password: 'passyble pw', secret_key: 'P1-AAAAA', shared: false });
  assert.equal($('pw-secret-key').value, '');
  assert.equal($('pw-password').value, '');
  assert.equal($('signed-in-note').hidden, false);
  assert.equal($('signed-in-note').textContent, 'Signed in as demo@example.com. Your vault in this browser is unlocked.');
});

const FINGERPRINT = 'ABAB-ABAB-ABAB-ABAB';

test('approve from another device: the QR, the code to type there, the fingerprint check, then done', async () => {
  background({ approval: [{ state: 'none' }, { state: 'waiting' }, { state: 'code', code: '123456' }, { state: 'check', fingerprint: FINGERPRINT },
    { state: 'check', fingerprint: FINGERPRINT }],
  confirm: () => ({ ok: true, result: { state: 'done', email: 'demo@example.com', unlocked: false } }) });
  const { window: win, $ } = await openPage('#approve');
  $('ap-email').value = 'demo@example.com';
  submit(win, $('approve'));
  await settle();
  assert.deepEqual(sent('account.approval-start').at(-1), { type: 'account.approval-start', email: 'demo@example.com', shared: false });
  assert.equal($('ap-wait').hidden, false);
  const path = $('ap-qr').querySelector('svg path');
  assert.equal(path.getAttribute('d'), 'M4 4h1v1h-1z');
  assert.equal($('ap-qr').querySelector('svg').getAttribute('viewBox'), '0 0 29 29');
  assert.equal($('ap-cancel').hidden, false);
  await tick();
  assert.equal($('ap-wait').hidden, false, 'still waiting');
  await tick();
  assert.equal($('ap-code-part').hidden, false);
  assert.equal($('ap-code').textContent, '123 456');
  assert.equal($('ap-code-part').querySelector('p').textContent, 'Type this code on your other device.');
  await tick();
  // The keys arrived: nothing kept until the user compared the fingerprint with the other device.
  assert.equal($('ap-check-part').hidden, false);
  assert.equal($('ap-code-part').hidden, true);
  assert.equal($('ap-cancel').hidden, true);
  assert.equal($('ap-fingerprint').textContent, FINGERPRINT);
  assert.equal($('ap-check-part').querySelector('p').textContent,
    'Check that your other device shows this fingerprint in Settings, Passyble password.');
  assert.equal($('ap-match').textContent, 'It matches');
  assert.equal($('ap-mismatch').textContent, "It doesn't match");
  assert.equal(sent('account.approval-confirm').length, 0);
  await tick();
  assert.equal(timers.length, 1, 'polled on while the user compares (it keeps the service worker up)');
  $('ap-match').click();
  await settle();
  assert.deepEqual(sent('account.approval-confirm'), [{ type: 'account.approval-confirm', matches: true }]);
  assert.equal($('ap-check-part').hidden, true);
  assert.equal($('ap-msg').textContent, 'This browser is approved. Your Passyble password opens your linked vaults here.');
  assert.equal($('signed-in-note').textContent, 'Signed in as demo@example.com');
  assert.equal(timers.length, 0, 'no more polling');
});

test('approval denied, and Cancel', async () => {
  background({ approval: [{ state: 'none' }, { state: 'denied' }] });
  const { window: win, $ } = await openPage();
  $('ap-email').value = 'demo@example.com';
  submit(win, $('approve'));
  await settle();
  await tick();
  assert.equal($('ap-ask').hidden, false);
  assert.equal($('ap-msg').textContent, 'Your other device said no. Start again if that was a mistake.');
  submit(win, $('approve'));
  await settle();
  $('ap-cancel').click();
  await settle();
  assert.equal(sent('account.approval-cancel').length, 1);
  assert.equal($('ap-ask').hidden, false);
});

test('app mode: the Passyble app holds the account key; the page offers nothing', async () => {
  background({ keysState: { available: false, linked: null } });
  const { $ } = await openPage();
  assert.equal($('in-app').hidden, false);
  assert.equal($('pw-form').hidden, true);
  assert.equal($('approve').hidden, true);
  assert.equal(sent('account.approval-poll').length, 0);
});

test('attack: the fingerprint differs: a mismatch drops the keys with a loud warning', async () => {
  background({ approval: [{ state: 'check', fingerprint: 'CDCD-CDCD-CDCD-CDCD' }], confirm: () => ({ ok: true, result: { state: 'rejected' } }) });
  // A page opened again while the keys wait goes straight to the check.
  const { $ } = await openPage();
  assert.equal($('ap-check-part').hidden, false);
  assert.equal($('ap-fingerprint').textContent, 'CDCD-CDCD-CDCD-CDCD');
  $('ap-mismatch').click();
  await settle();
  assert.deepEqual(sent('account.approval-confirm'), [{ type: 'account.approval-confirm', matches: false }]);
  assert.equal($('ap-check-part').hidden, true);
  assert.equal($('ap-ask').hidden, false);
  const msg = $('ap-msg');
  assert.match(msg.textContent, /^The keys were not kept\./);
  assert.equal(msg.getAttribute('role'), 'alert');
  assert.ok(msg.classList.contains('loud'));
  assert.equal(timers.length, 0, 'no more polling');
});

test('Cancel while arrived keys wait: they are dropped, and the page says so loudly', async () => {
  background({ approval: [{ state: 'none' }, { state: 'code', code: '654321' }], cancel: { state: 'none', dropped: true } });
  const { window: win, $ } = await openPage();
  $('ap-email').value = 'demo@example.com';
  submit(win, $('approve'));
  await settle();
  await tick();
  $('ap-cancel').click();
  await settle();
  assert.equal($('ap-msg').textContent, 'Cancelled. The keys that arrived were not kept.');
  assert.ok($('ap-msg').classList.contains('loud'));
});
