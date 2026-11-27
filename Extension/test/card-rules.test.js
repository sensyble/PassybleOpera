// The rules of the card save banner (src/shared/card-rules.js). Test card numbers only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  cardBrand, cardDigits, cardMonth, cardYear, cleanHolder, cleanTitle, luhnValid, parseExpiry, validCardNumber,
} from '../src/shared/card-rules.js';

test('Luhn: test card numbers pass, a changed digit fails', () => {
  for (const n of ['4242424242424242', '4000056655665556', '5555555555554444', '2223003122003222', '378282246310005',
    '6011111111111117', '3056930009020004', '3566002020360505', '6200000000000005', '4222222222222']) {
    assert.equal(luhnValid(n), true, n);
  }
  for (const n of ['4242424242424241', '5555555555554445', '378282246310006', '', 'abc']) {
    assert.equal(luhnValid(n), false, n);
  }
});

test('a number worth saving: 12 to 19 Luhn-valid digits, spaces, dashes and dots allowed, nothing else', () => {
  assert.equal(validCardNumber('4242 4242 4242 4242'), '4242424242424242');
  assert.equal(validCardNumber('4242-4242-4242-4242'), '4242424242424242');
  assert.equal(validCardNumber('4242.4242.4242.4242'), '4242424242424242');
  assert.equal(validCardNumber('378282246310005'), '378282246310005', 'Amex, 15 digits');
  assert.equal(validCardNumber('4222222222222'), '4222222222222', '13 digits');
  assert.equal(validCardNumber('4242424242424241'), '', 'not Luhn-valid');
  assert.equal(validCardNumber('42424242424'), '', 'too short');
  assert.equal(validCardNumber('42424242424242424242'), '', 'too long');
  assert.equal(validCardNumber('4242x4242x4242x4242'), '', 'letters');
  assert.equal(validCardNumber('**** **** **** 4242'), '', 'a masked number');
  assert.equal(validCardNumber(4242424242424242), '', 'not a string');
  assert.equal(cardDigits('4242 4242'), '42424242');
  assert.equal(cardDigits('1'.repeat(65)), '', 'absurdly long');
});

test('expiries in the formats fill writes; months and years checked', () => {
  const cases = {
    '04/29': { month: 4, year: 2029 }, '4/29': { month: 4, year: 2029 }, '04 / 2029': { month: 4, year: 2029 },
    '04-29': { month: 4, year: 2029 }, '04.29': { month: 4, year: 2029 }, '0429': { month: 4, year: 2029 },
    '042029': { month: 4, year: 2029 }, '12 29': { month: 12, year: 2029 }, '2029-04': { month: 4, year: 2029 },
  };
  for (const [text, want] of Object.entries(cases)) assert.deepEqual(parseExpiry(text), want, text);
  assert.deepEqual(parseExpiry('2029-4', { monthInput: true }), { month: 4, year: 2029 });
  for (const bad of ['', '13/29', '00/29', '04/', 'April', '04/290', '1/2/3', null, undefined]) {
    assert.equal(parseExpiry(bad), null, String(bad));
  }
  assert.equal(cardMonth('07'), 7);
  assert.equal(cardMonth(13), 0);
  assert.equal(cardYear('29'), 2029);
  assert.equal(cardYear('2031'), 2031);
  assert.equal(cardYear('1999'), 0);
  assert.equal(cardYear('290'), 0);
});

test('holder and title: one line, trimmed, bounded', () => {
  assert.equal(cleanHolder('  Ada   Lovelace '), 'Ada Lovelace');
  assert.equal(cleanHolder('Ada\nLovelace'), 'Ada Lovelace');
  assert.equal(cleanHolder('x'.repeat(257)), '');
  assert.equal(cleanHolder(null), '');
  assert.equal(cleanTitle(' Travel '), 'Travel');
  assert.equal(cleanTitle('a\nb'), null);
  assert.equal(cleanTitle('x'.repeat(257)), null);
});

test('brand from the leading digits, as the agent names it', () => {
  const brands = {
    '4242424242424242': 'visa', '5555555555554444': 'mastercard', '2223003122003222': 'mastercard',
    '378282246310005': 'amex', '6011111111111117': 'discover', '3566002020360505': 'jcb',
    '3056930009020004': 'diners', '6200000000000005': 'unionpay', '2200000000000004': 'mir', '9999999999999995': '',
  };
  for (const [n, brand] of Object.entries(brands)) assert.equal(cardBrand(n), brand, n);
});
