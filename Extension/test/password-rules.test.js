// What a new-password field allows (src/content/password-rules.js): passwordrules, a letters-and-digits
// pattern, and the length from maxlength / minlength. Only the clear cases say anything.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { parsePasswordRules, parsePattern, passwordRulesOf } from '../src/content/password-rules.js';

const doc = new JSDOM('<!doctype html><body></body>').window.document;
function input(attrs) {
  const el = doc.createElement('input');
  el.type = 'password';
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

test('passwordrules: classes without special characters mean no symbols; lengths are read', () => {
  assert.deepEqual(parsePasswordRules('minlength: 8; maxlength: 16; required: lower; required: upper; required: digit;'),
    { minLength: 8, maxLength: 16, symbols: false });
  assert.deepEqual(parsePasswordRules('required: lower, upper; required: digit; allowed: [-_]'), { symbols: false }, 'only some symbols');
  assert.deepEqual(parsePasswordRules('required: upper; required: digit; required: special; minlength: 12'), { minLength: 12 });
  assert.deepEqual(parsePasswordRules('allowed: ascii-printable; maxlength: 64'), { maxLength: 64 });
  assert.deepEqual(parsePasswordRules('Allowed: Unicode'), {});
  assert.deepEqual(parsePasswordRules('maxlength: 20'), { maxLength: 20 }, 'no classes: says nothing about symbols');
  assert.deepEqual(parsePasswordRules(''), {});
  assert.deepEqual(parsePasswordRules(null), {});
});

test('pattern: only letters and digits (lookaheads allowed) means no symbols; anything else says nothing', () => {
  for (const p of ['^[A-Za-z0-9]+$', '[a-zA-Z0-9]*', '[\\w]+', '\\w+', '(?=.*\\d)(?=.*[a-z])(?=.*[A-Z])[a-zA-Z\\d]{8,}',
    '[A-Za-z0-9_-]+', '[a-z]+[0-9]+']) {
    assert.equal(parsePattern(p).symbols, false, p);
  }
  for (const p of ['.{8,}', '[^ ]+', '[A-Za-z0-9!@#]+', '(?=.*[!@#]).{8,}', '\\S+', '[A-Z]|[0-9]', '', '^$']) {
    assert.deepEqual(parsePattern(p), {}, p);
  }
  assert.deepEqual(parsePattern('[A-Za-z0-9]{8,16}'), { symbols: false, minLength: 8, maxLength: 16 });
  assert.deepEqual(parsePattern('[A-Za-z0-9]{12}'), { symbols: false, minLength: 12, maxLength: 12 });
  assert.deepEqual(parsePattern('[A-Za-z0-9]{10,}'), { symbols: false, minLength: 10, maxLength: undefined });
});

test('passwordRulesOf: the field\'s symbols and a length that fits it', () => {
  assert.deepEqual(passwordRulesOf(input({})), {});
  assert.deepEqual(passwordRulesOf(input({ pattern: '[A-Za-z0-9]{8,16}' })), { symbols: false, length: 16 });
  assert.deepEqual(passwordRulesOf(input({ maxlength: '12' })), { length: 12 });
  assert.deepEqual(passwordRulesOf(input({ maxlength: '6' })), {}, 'under 8: the generator keeps its minimum');
  assert.deepEqual(passwordRulesOf(input({ minlength: '32' })), { length: 32 });
  assert.deepEqual(passwordRulesOf(input({ minlength: '500' })), { length: 128 });
  assert.deepEqual(passwordRulesOf(input({ passwordrules: 'required: lower; required: upper; required: digit; maxlength: 15;' })), { symbols: false, length: 15 });
  assert.deepEqual(passwordRulesOf(input({ passwordrules: 'required: special; minlength: 24', maxlength: '30' })), { length: 24 });
  assert.deepEqual(passwordRulesOf(null), {});
});

test('passwordLimitsOf and fitLength: what the field allows, and a length made to fit it', async () => {
  const { passwordLimitsOf, fitLength } = await import('../src/content/password-rules.js');
  assert.deepEqual(passwordLimitsOf(input({})), {});
  assert.deepEqual(passwordLimitsOf(input({ pattern: '[A-Za-z0-9]{8,16}' })), { symbols: false, minLength: 8, maxLength: 16 });
  assert.deepEqual(passwordLimitsOf(input({ maxlength: '6' })), {}, 'under 8: no maximum');
  assert.deepEqual(passwordLimitsOf(input({ minlength: '500', maxlength: '30' })), { minLength: 128, maxLength: 30 });
  assert.deepEqual(passwordLimitsOf(null), {});
  assert.equal(fitLength(20, {}), 20);
  assert.equal(fitLength(20, { maxLength: 16 }), 16);
  assert.equal(fitLength(10, { minLength: 12 }), 12);
  assert.equal(fitLength(4, {}), 8);
});
