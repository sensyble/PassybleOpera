// Split OTP boxes, one character per box ([][][][][][]): which runs of inputs are one code entry, and
// how the code goes in. jsdom has no layout, so the rendered boxes come from a stubbed `rectOf`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import {
  detectFields, isVisibleNoLayout, findSplitOtpGroups, collectInputs, boxRect, narrowBox, sameSizeBoxes, nextOnRow,
  isTransparentOtpInput,
} from '../src/content/detect.js';
import { fillSplitOtp, fillOtpEntry, setNativeValue } from '../src/content/fill.js';

/** Lays the inputs out left to right on one line: `w` x `h` boxes, `gap` px apart (`gaps[i]` after box i). */
function row(inputs, { w = 44, h = 52, gap = 8, top = 200, gaps = {} } = {}) {
  const rects = new Map();
  let left = 20;
  inputs.forEach((el, i) => {
    rects.set(el, { left, top, width: w, height: h });
    left += w + (gaps[i] ?? gap);
  });
  return rects;
}

/** Detects with the boxes of `layout(inputs)` (a Map input -> rect) as their rendered geometry. */
function detect(html, layout = null) {
  const { document, window } = makeDom(html);
  const rects = layout ? layout(collectInputs(document)) : new Map();
  const rectOf = (el) => rects.get(el) || null;
  return { document, window, rects, ...detectFields(document, { isVisible: isVisibleNoLayout, rectOf }) };
}

const otpOf = (r) => r.groups.find((g) => g.otp)?.otp || null;
const boxes = (n, attrs = '') => Array.from({ length: n }, (_, i) => `<input ${attrs} name="d${i}">`).join('');

test('boxRect: null without layout (jsdom), the rendered box when there is one', () => {
  const { document } = makeDom('<input id="a">');
  const el = document.getElementById('a');
  assert.equal(boxRect(el), null);
  el.getBoundingClientRect = () => ({ left: 5, top: 6, width: 40, height: 48, right: 45, bottom: 54 });
  assert.deepEqual(boxRect(el), { left: 5, top: 6, width: 40, height: 48 });
  el.getBoundingClientRect = () => { throw new Error('gone'); };
  assert.equal(boxRect(el), null);
});

test('narrowBox, sameSizeBoxes, nextOnRow', () => {
  assert.equal(narrowBox({ left: 0, top: 0, width: 44, height: 52 }), true);
  assert.equal(narrowBox({ left: 0, top: 0, width: 140, height: 48 }), true, 'at most 3x as wide as tall');
  assert.equal(narrowBox({ left: 0, top: 0, width: 300, height: 40 }), false, 'an ordinary text field');
  assert.equal(narrowBox({ left: 0, top: 0, width: 6, height: 6 }), false, 'a speck');
  assert.equal(narrowBox(null), false);
  const a = { left: 0, top: 100, width: 44, height: 52 };
  assert.equal(sameSizeBoxes(a, { ...a, width: 47 }), true);
  assert.equal(sameSizeBoxes(a, { ...a, width: 60 }), false);
  assert.equal(nextOnRow(a, { ...a, left: 52 }), true);
  assert.equal(nextOnRow(a, { ...a, left: 52 + 40 }), true, 'a dash between two halves');
  assert.equal(nextOnRow(a, { ...a, left: 400 }), false, 'far to the right');
  assert.equal(nextOnRow(a, { ...a, left: -60 }), false, 'to the left');
  assert.equal(nextOnRow(a, { ...a, left: 0, top: 170 }), false, 'the next line');
  assert.equal(nextOnRow(a, { ...a, left: 52, top: 103 }), true, 'a few px lower');
});

test('six boxes without maxlength (the widget limits them in script): one entry when they look like it', () => {
  const html = `<form><h2>Check your phone</h2><div class="otp">${boxes(6, 'inputmode="numeric"')}</div><button>Continue</button></form>`;
  const r = detect(html, row);
  assert.equal(otpOf(r)?.kind, 'split');
  assert.equal(otpOf(r).fields.length, 6);
  assert.equal(otpOf(detect(html)), null, 'no layout, no loose boxes');
});

test('loose boxes: OTP evidence by one-time-code, wording, digits or exactly six', () => {
  assert.equal(otpOf(detect(`<div>${boxes(5, 'type="text"').replace('name="d0"', 'name="d0" autocomplete="one-time-code"')}</div>`, row))?.kind, 'split');
  assert.equal(otpOf(detect(`<div><p>Enter the verification code</p>${boxes(4)}</div>`, row))?.kind, 'split');
  assert.equal(otpOf(detect(`<div>${boxes(5, 'pattern="[0-9]"')}</div>`, row))?.kind, 'split');
  assert.equal(otpOf(detect(`<div>${boxes(6)}</div>`, row))?.kind, 'split');
  assert.equal(otpOf(detect(`<div>${boxes(5)}</div>`, row)), null, 'five letters boxes, nothing else');
  assert.equal(otpOf(detect(`<div>${boxes(4, 'inputmode="numeric"')}</div>`, row)), null, 'four digits only: a card number in 4 boxes');
});

test('loose boxes must be narrow, the same size and on one line', () => {
  const wide = (els) => row(els, { w: 200, h: 40 });
  assert.equal(otpOf(detect(`<div>${boxes(6, 'inputmode="numeric"')}</div>`, wide)), null, 'six wide text fields');
  const uneven = (els) => { const m = row(els); m.set(els[2], { ...m.get(els[2]), width: 90 }); return m; };
  assert.equal(otpOf(detect(`<div>${boxes(6, 'inputmode="numeric"')}</div>`, uneven))?.fields.length ?? 0, 0);
  const twoRows = (els) => {
    const m = new Map();
    els.forEach((el, i) => m.set(el, { left: 20 + (i % 3) * 52, top: i < 3 ? 100 : 170, width: 44, height: 52 }));
    return m;
  };
  assert.equal(otpOf(detect(`<div>${boxes(6, 'inputmode="numeric"')}</div>`, twoRows)), null, 'two lines of three');
});

test('maxlength=2 boxes only with OTP evidence', () => {
  assert.equal(otpOf(detect(`<form><h2>Two-step verification</h2><div>${boxes(6, 'maxlength="2" inputmode="numeric"')}</div></form>`, row))?.kind, 'split');
  assert.equal(otpOf(detect(`<form><div>${boxes(6, 'maxlength="2" inputmode="numeric"')}</div></form>`, row)), null);
  assert.notEqual(otpOf(detect(`<form><div>${boxes(6, 'maxlength="3" inputmode="numeric"')}</div><p>Enter the verification code</p></form>`, row))?.kind, 'split', 'maxlength 3: no box');
});

test('3 + 3 with a dash between, each half wrapped deeper than 3 levels', () => {
  const cell = (i) => `<div class="slot"><div class="ring"><div class="inner"><input maxlength="1" inputmode="numeric" name="d${i}"></div></div></div>`;
  const half = (from) => `<div class="group"><div class="row">${cell(from)}${cell(from + 1)}${cell(from + 2)}</div></div>`;
  const html = `<form><p>Enter code</p><div class="otp">${half(0)}<div class="sep"><span>-</span></div>${half(3)}</div></form>`;
  const layout = (els) => row(els, { gaps: { 2: 40 } });
  const r = detect(html, layout);
  assert.equal(otpOf(r)?.kind, 'split');
  assert.deepEqual(otpOf(r).fields.map((el) => el.name), ['d0', 'd1', 'd2', 'd3', 'd4', 'd5']);
  // Without layout the halves are too far apart in the DOM to join.
  assert.equal(otpOf(detect(html)), null);
});

test('3 + 3 loose boxes (no maxlength) with a dash between', () => {
  const html = `<div><h3>Verification code</h3><div class="a">${boxes(3)}</div><span>-</span><div class="b">${boxes(3).replace(/d(\d)/g, (_, n) => `d${Number(n) + 3}`)}</div></div>`;
  const r = detect(html, (els) => row(els, { gaps: { 2: 36 } }));
  assert.equal(otpOf(r)?.fields.length, 6);
});

test('each box wrapped deeper than 3 levels, unevenly', () => {
  const html = `<form><h2>Enter the 6-digit code</h2><div class="otp">
    <div><div><div><div><input maxlength="1" name="a"></div></div></div></div>
    <div><div><div><input maxlength="1" name="b"></div></div></div>
    <div><div><div><div><input maxlength="1" name="c"></div></div></div></div>
    <div><div><div><div><input maxlength="1" name="d"></div></div></div></div>
    <div><div><div><div><input maxlength="1" name="e"></div></div></div></div>
    <div><div><div><div><input maxlength="1" name="f"></div></div></div></div></div></form>`;
  assert.equal(otpOf(detect(html, row))?.fields.map((el) => el.name).join(''), 'abcdef');
});

test('a custom element per digit, each box in its own shadow root', () => {
  const { document } = makeDom('<form><h2>Two-factor authentication</h2><div id="otp"></div><button>Verify</button></form>');
  const holder = document.getElementById('otp');
  for (let i = 0; i < 6; i++) {
    const host = document.createElement('otp-digit');
    host.attachShadow({ mode: 'open' }).innerHTML = `<div class="box"><input maxlength="1" inputmode="numeric" name="d${i}"></div>`;
    holder.append(host);
  }
  const r = detectFields(document, { isVisible: isVisibleNoLayout, rectOf: () => null });
  assert.equal(otpOf(r)?.kind, 'split');
  assert.deepEqual(otpOf(r).fields.map((el) => el.name), ['d0', 'd1', 'd2', 'd3', 'd4', 'd5']);
});

test('the whole widget in one shadow root, loose boxes', () => {
  const { document } = makeDom('<div><h2>Enter verification code</h2><code-input id="w"></code-input></div>');
  const root = document.getElementById('w').attachShadow({ mode: 'open' });
  root.innerHTML = `<div part="boxes">${boxes(6, 'inputmode="numeric"')}</div>`;
  const rects = row([...root.querySelectorAll('input')]);
  const r = detectFields(document, { isVisible: isVisibleNoLayout, rectOf: (el) => rects.get(el) || null });
  assert.equal(otpOf(r)?.fields.length, 6);
});

test('one transparent input drawn as six boxes (input-otp style) stays a single field', () => {
  const slots = Array.from({ length: 6 }, () => '<div class="slot"></div>').join('');
  const html = `<form><h2>Verify your email</h2><div class="otp-root" style="position:relative">
    <div class="slots">${slots}</div>
    <input id="code" autocomplete="one-time-code" inputmode="numeric" maxlength="6" pattern="^\\d+$"
      style="position:absolute;inset:0;color:transparent;caret-color:transparent;background:transparent;border:0"></div></form>`;
  const r = detect(html, (els) => new Map(els.map((el) => [el, { left: 20, top: 200, width: 300, height: 52 }])));
  assert.equal(otpOf(r)?.kind, 'single');
  assert.equal(otpOf(r).fields[0].id, 'code');
  assert.equal(fillOtpEntry(otpOf(r), '482913'), true);
  assert.equal(r.document.getElementById('code').value, '482913');
  // Unnamed, with the 2FA wording next to it: still the single field.
  const r2 = detect(html.replace('autocomplete="one-time-code" ', ''), (els) => new Map(els.map((el) => [el, { left: 20, top: 200, width: 300, height: 52 }])));
  assert.equal(otpOf(r2)?.kind, 'single');
});

test('a card number in 4 boxes is no code', () => {
  const html = `<form><label>Card number</label><div>${boxes(4, 'inputmode="numeric"')}</div><input name="cvc"></form>`;
  assert.equal(otpOf(detect(html, (els) => row(els.slice(0, 4), { w: 70, h: 44 }))), null, 'no maxlength');
  const ml4 = `<form><label>Card number</label><div>${boxes(4, 'inputmode="numeric" maxlength="4"')}</div></form>`;
  assert.equal(otpOf(detect(ml4, (els) => row(els, { w: 70, h: 44 }))), null, 'maxlength 4');
  const named = `<form><div>${Array.from({ length: 4 }, (_, i) => `<input name="card${i}" inputmode="numeric">`).join('')}</div></form>`;
  assert.equal(otpOf(detect(named, row)), null, 'named for a card');
  const per = `<form><label>Credit card number</label><div>${boxes(6, 'inputmode="numeric"')}</div></form>`;
  assert.equal(otpOf(detect(per, row)), null, 'card wording next to loose boxes');
});

test('phone number parts are no code', () => {
  const parts = '<form><label>Phone</label><input name="area" maxlength="3"><input name="prefix" maxlength="3"><input name="line" maxlength="4"></form>';
  assert.equal(otpOf(detect(parts, row)), null);
  const four = `<form>${Array.from({ length: 4 }, (_, i) => `<input name="phone${i}" type="tel">`).join('')}</form>`;
  assert.equal(otpOf(detect(four, row)), null, 'four tel boxes named phone');
  const digits = `<form>${Array.from({ length: 8 }, (_, i) => `<input name="mobile_${i}" maxlength="1" type="tel">`).join('')}</form>`;
  assert.equal(otpOf(detect(digits, row)), null, 'one box per digit, named mobile');
});

test('date parts are no code', () => {
  const dmy = '<form><label>Date of birth</label><input name="dd" placeholder="DD"><input name="mm" placeholder="MM"><input name="yyyy" placeholder="YYYY"></form>';
  assert.equal(otpOf(detect(dmy, row)), null);
  const perDigit = `<form><p>Date of birth</p>${['D', 'D', 'M', 'M', 'Y', 'Y', 'Y', 'Y'].map((p, i) => `<input maxlength="1" inputmode="numeric" name="b${i}" placeholder="${p}">`).join('')}</form>`;
  assert.equal(otpOf(detect(perDigit)), null, 'D D M M Y Y Y Y, one digit each');
  const unlabelled = `<form>${['D', 'D', 'M', 'M', 'Y', 'Y', 'Y', 'Y'].map((p, i) => `<input maxlength="1" inputmode="numeric" name="b${i}" placeholder="${p}">`).join('')}</form>`;
  assert.equal(otpOf(detect(unlabelled)), null, 'the placeholders alone');
  const labelled = `<form><p>Your birthday</p><div>${boxes(8, 'maxlength="1" inputmode="numeric"')}</div></form>`;
  assert.equal(otpOf(detect(labelled)), null, 'birthday wording next to the boxes');
  const days = `<form>${['day', 'month', 'year', 'hour'].map((n) => `<input name="${n}" inputmode="numeric">`).join('')}</form>`;
  assert.equal(otpOf(detect(days, row)), null, 'named day / month / year');
});

test('a PIN pad that is no 2FA step, and a captcha', () => {
  const pin = `<form><h2>Create your PIN</h2><div>${boxes(6, 'type="password" inputmode="numeric"')}</div></form>`;
  assert.equal(otpOf(detect(pin, row)), null, 'loose boxes next to PIN wording');
  const captcha = `<form><label>Type the characters in the captcha</label><div>${boxes(6)}</div></form>`;
  assert.equal(otpOf(detect(captcha, row)), null);
  // A PIN sent as a second factor is a code.
  const sent = `<form><h2>Enter the PIN we sent you for two-step verification</h2><div>${boxes(6, 'inputmode="numeric"')}</div></form>`;
  assert.equal(otpOf(detect(sent, row))?.kind, 'split');
});

test('strict boxes still found as before, also without layout', () => {
  const r = detect(`<form><p>Enter code</p><div>${boxes(6, 'maxlength="1" inputmode="numeric"')}</div></form>`);
  assert.equal(otpOf(r)?.kind, 'split');
  const { document } = makeDom(`<div>${'<input maxlength="1" inputmode="numeric">'.repeat(10)}</div>`);
  assert.equal(findSplitOtpGroups(collectInputs(document)).length, 0, 'ten boxes: too many');
  // aria-label "Digit 1 of the verification code sent to your mobile": named a code, the phone word aside.
  const aria = `<div>${Array.from({ length: 6 }, (_, i) => `<input maxlength="1" aria-label="Digit ${i + 1} of the verification code sent to your mobile">`).join('')}</div>`;
  assert.equal(otpOf(detect(aria))?.kind, 'split');
});

/**
 * A widget that ignores values set from script and pastes: it keeps its own digits, put back on every
 * `input` event, and takes a digit only from a keydown whose `code` is Digit<n>, then moves the focus.
 */
function keyboardOnlyWidget(inputs, { movesFocus = true } = {}) {
  const state = inputs.map(() => '');
  const render = () => inputs.forEach((el, i) => setNativeValue(el, state[i]));
  inputs.forEach((el, i) => {
    el.addEventListener('input', render);
    el.addEventListener('paste', (e) => e.preventDefault());
    el.addEventListener('keydown', (e) => {
      if (!/^Digit\d$/.test(e.code) || e.key !== e.code.slice(5)) return;
      e.preventDefault();
      state[i] = e.key;
      render();
      if (movesFocus && inputs[i + 1]) inputs[i + 1].focus();
    });
  });
  return state;
}

test('a keyboard-only widget: the code is typed key by key, the widget moving the focus', () => {
  const { document } = makeDom(`<form id="f"><div>${boxes(6, 'maxlength="1" inputmode="numeric"')}</div></form>`);
  const els = [...document.querySelectorAll('input')];
  const state = keyboardOnlyWidget(els);
  let submitted = false;
  document.getElementById('f').addEventListener('submit', (e) => { submitted = true; e.preventDefault(); });
  const keys = [];
  els[0].parentElement.addEventListener('keydown', (e) => keys.push(e.target.name));
  assert.equal(fillSplitOtp(els, '305 718'), true);
  assert.deepEqual(state, ['3', '0', '5', '7', '1', '8']);
  assert.deepEqual(els.map((el) => el.value), ['3', '0', '5', '7', '1', '8']);
  assert.equal(submitted, false, 'never submitted');
  // fillInput's own keydown (code '') is ignored; the typed ones land one per box, in order.
  assert.deepEqual(keys.slice(-6), ['d0', 'd1', 'd2', 'd3', 'd4', 'd5']);
});

test('a keyboard-only widget that does not move the focus: Passyble moves it', () => {
  const { document } = makeDom(`<div>${boxes(4, 'maxlength="1"')}</div>`);
  const els = [...document.querySelectorAll('input')];
  const state = keyboardOnlyWidget(els, { movesFocus: false });
  assert.equal(fillSplitOtp(els, '9012'), true);
  assert.deepEqual(state, ['9', '0', '1', '2']);
});

test('typed keys carry key, code and data through keydown, keypress, beforeinput, input, keyup', () => {
  const { document } = makeDom(`<div>${boxes(4, 'maxlength="1"')}</div>`);
  const els = [...document.querySelectorAll('input')];
  // Rejects every value set before a keypress for its box was seen.
  const pressed = new Set();
  const seen = [];
  els.forEach((el, i) => {
    for (const t of ['keydown', 'keypress', 'beforeinput', 'input', 'keyup']) {
      el.addEventListener(t, (e) => { if (pressed.has(i) || t === 'keypress') seen.push(`${t}:${e.key ?? e.data}:${e.code ?? ''}`); });
    }
    el.addEventListener('keypress', () => pressed.add(i));
    el.addEventListener('input', () => { if (!pressed.has(i)) setNativeValue(el, ''); });
  });
  assert.equal(fillSplitOtp(els, '4821'), true);
  assert.deepEqual(els.map((el) => el.value), ['4', '8', '2', '1']);
  assert.deepEqual(seen.slice(0, 5), ['keypress:4:Digit4', 'beforeinput:4:', 'input:4:', 'keyup:4:Digit4', 'keypress:8:Digit8']);
});

test('typing starts at the first box that is wrong and stops once all hold the code', () => {
  const { document } = makeDom(`<div>${boxes(4, 'maxlength="1"')}</div>`);
  const els = [...document.querySelectorAll('input')];
  // Box 2 and 3 refuse script values until a keydown came.
  const keyed = new Set();
  els.forEach((el, i) => {
    el.addEventListener('keydown', (e) => { if (e.code) keyed.add(i); });
    el.addEventListener('input', () => { if (i >= 2 && !keyed.has(i)) setNativeValue(el, ''); });
  });
  assert.equal(fillSplitOtp(els, '7777'), true);
  assert.deepEqual([...keyed].sort(), [2, 3]);
});

test('a widget that takes nothing: false, nothing submitted', () => {
  const { document } = makeDom(`<form id="f"><div>${boxes(4, 'maxlength="1"')}</div></form>`);
  const els = [...document.querySelectorAll('input')];
  for (const el of els) el.addEventListener('input', () => setNativeValue(el, ''));
  let submitted = false;
  document.getElementById('f').addEventListener('submit', (e) => { submitted = true; e.preventDefault(); });
  assert.equal(fillSplitOtp(els, '1234'), false);
  assert.equal(submitted, false);
});

// A see-through input under drawn boxes (input-otp, shadcn/ui InputOTP).

const slotDivs = Array.from({ length: 6 }, () => '<div class="slot"></div>').join('');
const ghostRect = () => ({ left: 20, top: 200, width: 300, height: 52 });

test('input-otp: one input with opacity 0 under six drawn boxes is the OTP field and gets filled', () => {
  const { document } = makeDom(`<form><h2>Verify your email</h2><div data-input-otp-container style="position:relative">
    <div class="slots">${slotDivs}</div>
    <input id="code" data-input-otp="true" autocomplete="one-time-code" inputmode="numeric" maxlength="6"
      pattern="^\d+$" style="position:absolute;inset:0;opacity:0;color:transparent"></div><button>Verify</button></form>`);
  const el = document.getElementById('code');
  assert.equal(isVisibleNoLayout(el), false, 'ordinary visibility rejects it');
  const r = detectFields(document, { isVisible: isVisibleNoLayout, rectOf: ghostRect });
  const otp = otpOf(r);
  assert.equal(otp?.kind, 'single');
  assert.equal(otp.fields[0], el);
  assert.equal(fillOtpEntry(otp, '204816'), true);
  assert.equal(el.value, '204816');
  // Evidence without one-time-code: maxlength 6 with digits, or OTP wording.
  for (const attrs of ['inputmode="numeric" maxlength="6"', 'aria-label="One-time password"']) {
    const d = makeDom(`<div>${slotDivs}<input id="c" ${attrs} style="opacity:0"></div>`).document;
    assert.equal(otpOf(detectFields(d, { isVisible: isVisibleNoLayout, rectOf: ghostRect }))?.fields[0].id, 'c', attrs);
  }
  // A transparent ancestor counts too.
  const d = makeDom(`<div style="opacity:0"><input id="c" autocomplete="one-time-code"></div>`).document;
  assert.equal(isTransparentOtpInput(d.getElementById('c'), ghostRect), true);
});

test('see-through inputs that are no code, or not really there, stay out (honeypots)', () => {
  const login = makeDom(`<form><input name="username" style="opacity:0"><input type="password" name="password" style="opacity:0">
    <input name="email" style="opacity:0"><button>Sign in</button></form>`).document;
  const r = detectFields(login, { isVisible: isVisibleNoLayout, rectOf: ghostRect });
  assert.equal(r.groups.length, 0, 'no username, password or code from see-through fields');
  assert.equal(r.fields.size, 0);
  const check = (html, rectOf = ghostRect) => isTransparentOtpInput(makeDom(html).document.getElementById('c'), rectOf);
  assert.equal(check('<input id="c" style="opacity:0">'), false, 'no OTP evidence');
  assert.equal(check('<input id="c" maxlength="6" style="opacity:0">'), false, 'maxlength 6, letters');
  assert.equal(check('<input id="c" type="password" autocomplete="one-time-code" style="opacity:0">'), false, 'password-typed');
  assert.equal(check('<input id="c" autocomplete="one-time-code" style="opacity:0">', () => null), false, 'no rendered size');
  assert.equal(check('<input id="c" autocomplete="one-time-code" style="opacity:0">', () => ({ left: 0, top: 0, width: 1, height: 1 })), false, 'a speck');
  assert.equal(check('<input id="c" autocomplete="one-time-code" style="opacity:0">', () => ({ left: -9999, top: 0, width: 300, height: 52 })), false, 'parked off-screen');
  assert.equal(check('<input id="c" autocomplete="one-time-code" style="opacity:0;visibility:hidden">'), false, 'visibility hidden');
  assert.equal(check('<div style="display:none"><input id="c" autocomplete="one-time-code" style="opacity:0"></div>'), false, 'display none');
  assert.equal(check('<input id="c" hidden autocomplete="one-time-code">'), false, 'hidden');
  assert.equal(check('<input id="c" autocomplete="one-time-code">'), false, 'not see-through: ordinary detection handles it');
  assert.equal(check('<input id="c" name="coupon" inputmode="numeric" maxlength="6" style="opacity:0">'), false, 'a coupon code');
});
