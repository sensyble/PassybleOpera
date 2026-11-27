import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import { setNativeValue, fillInput, fillSplitOtp, fillOtpEntry, fillLoginGroup, fillNewPasswords, wasFilledByPass } from '../src/content/fill.js';
import { detectFields, isVisibleNoLayout } from '../src/content/detect.js';

/** Mimics React's value tracker: an instance-level `value` property that records sets. */
function installTracker(window, el) {
  const desc = Object.getOwnPropertyDescriptor(window.HTMLInputElement.prototype, 'value');
  const tracker = { value: el.value };
  Object.defineProperty(el, 'value', {
    configurable: true,
    get() { return desc.get.call(this); },
    set(v) { tracker.value = String(v); desc.set.call(this, v); },
  });
  return tracker;
}

function record(el, types) {
  const seen = [];
  for (const t of types) el.addEventListener(t, (e) => seen.push(`${t}${e.data !== undefined && e.data !== null ? `:${e.data}` : ''}`));
  return seen;
}

test('setNativeValue bypasses an instance-level setter (React value tracker sees a change)', () => {
  const { window, document } = makeDom('<input id="u">');
  const el = document.getElementById('u');
  const tracker = installTracker(window, el);
  setNativeValue(el, 'alice');
  assert.equal(el.value, 'alice');
  assert.equal(tracker.value, '', 'tracker still holds the old value, so React fires onChange on input');
});

test('fillInput dispatches the event sequence frameworks listen to', () => {
  const { document } = makeDom('<input id="u">');
  const el = document.getElementById('u');
  const seen = record(el, ['focus', 'keydown', 'beforeinput', 'input', 'keyup', 'change', 'blur']);
  const ok = fillInput(el, 'bob', { blur: true });
  assert.equal(ok, true);
  assert.equal(el.value, 'bob');
  assert.deepEqual(seen, ['focus', 'keydown', 'beforeinput:bob', 'input:bob', 'keyup', 'change', 'blur']);
  assert.equal(document.activeElement, document.body);
  assert.ok(wasFilledByPass(el));
});

test('input events bubble to a delegated listener (Vue/Angular/React root)', () => {
  const { document } = makeDom('<div id="root"><input id="u"></div>');
  const values = [];
  document.getElementById('root').addEventListener('input', (e) => values.push(e.target.value));
  fillInput(document.getElementById('u'), 'carol');
  assert.deepEqual(values, ['carol']);
});

test('readonly and disabled fields are not filled', () => {
  const { document } = makeDom('<input id="a" readonly><input id="b" disabled>');
  assert.equal(fillInput(document.getElementById('a'), 'x'), false);
  assert.equal(fillInput(document.getElementById('b'), 'x'), false);
  assert.equal(document.getElementById('a').value, '');
});

test('split OTP boxes get one digit each', () => {
  const { document } = makeDom('<div>' + '<input maxlength="1">'.repeat(6) + '</div>');
  const boxes = [...document.querySelectorAll('input')];
  assert.equal(fillSplitOtp(boxes, '123 456'), true);
  assert.deepEqual(boxes.map((b) => b.value), ['1', '2', '3', '4', '5', '6']);
});

test('split OTP falls back to a paste event when boxes reject per-box values', () => {
  const { window, document } = makeDom('<div>' + '<input maxlength="1">'.repeat(4) + '</div>');
  const boxes = [...document.querySelectorAll('input')];
  // A widget that wipes values set programmatically but handles paste itself.
  for (const b of boxes) b.addEventListener('input', () => { if (!b.dataset.ok) setNativeValue(b, ''); });
  let pasted = null;
  boxes[0].addEventListener('paste', (e) => {
    pasted = e.clipboardData?.getData('text/plain') ?? 'no-clipboard-data';
    boxes.forEach((b, i) => { b.dataset.ok = '1'; setNativeValue(b, '9876'[i]); });
  });
  if (!window.DataTransfer || !window.ClipboardEvent) {
    // jsdom lacks these: the function must still fail gracefully.
    assert.equal(fillSplitOtp(boxes, '9876'), false);
    return;
  }
  assert.equal(fillSplitOtp(boxes, '9876'), true);
  assert.equal(pasted, '9876');
});

test('fillOtpEntry handles single and split entries', () => {
  const { document } = makeDom('<input id="s"><span>' + '<input maxlength="1">'.repeat(6) + '</span>');
  assert.equal(fillOtpEntry({ kind: 'single', fields: [document.getElementById('s')] }, '654321'), true);
  assert.equal(document.getElementById('s').value, '654321');
  const boxes = [...document.querySelectorAll('span input')];
  assert.equal(fillOtpEntry({ kind: 'split', fields: boxes }, '111222'), true);
  assert.equal(fillOtpEntry(null, '1'), false);
});

test('fillLoginGroup fills username, password and the OTP of the same form', () => {
  const { document } = makeDom(`<form><input name="user"><input type="password" name="pw">
    <input name="otp" autocomplete="one-time-code"></form>`);
  const { groups } = detectFields(document, { isVisible: isVisibleNoLayout });
  const r = fillLoginGroup(groups[0], { username: 'dave', password: 's3cret', totp: { code: '123456', period: 30, remaining_secs: 10 } });
  assert.deepEqual(r, { username: true, password: true, otp: true });
  assert.equal(document.querySelector('[name=user]').value, 'dave');
  assert.equal(document.querySelector('[name=pw]').value, 's3cret');
  assert.equal(document.querySelector('[name=otp]').value, '123456');
});

test('fillLoginGroup never writes the stored password into new-password fields', () => {
  const { document } = makeDom(`<form><h2>Create account</h2><input type="email" name="e">
    <input type="password" name="p1"><input type="password" name="p2"></form>`);
  const { groups } = detectFields(document, { isVisible: isVisibleNoLayout });
  const r = fillLoginGroup(groups[0], { username: 'e@x.test', password: 'old', totp: null });
  assert.equal(r.password, false);
  assert.equal(document.querySelector('[name=p1]').value, '');
  assert.ok(fillNewPasswords(groups[0], 'Gen3rated!'));
  assert.equal(document.querySelector('[name=p1]').value, 'Gen3rated!');
  assert.equal(document.querySelector('[name=p2]').value, 'Gen3rated!');
});

test('change-password form: stored password goes to the current field only', () => {
  const { document } = makeDom(`<form><input type="password" autocomplete="current-password" name="cur">
    <input type="password" autocomplete="new-password" name="n1"></form>`);
  const { groups } = detectFields(document, { isVisible: isVisibleNoLayout });
  fillLoginGroup(groups[0], { username: '', password: 'current-pw', totp: null });
  assert.equal(document.querySelector('[name=cur]').value, 'current-pw');
  assert.equal(document.querySelector('[name=n1]').value, '');
});
