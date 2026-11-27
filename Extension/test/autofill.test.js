import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import { detectFormFields, isVisibleNoLayout } from '../src/content/detect.js';
import {
  formatExpiry, expiryFormatOf, monthValueFor, yearValueFor, monthOption, yearOption, findOption, countryName,
  fillCardGroup, fillIdentityGroup,
} from '../src/content/autofill.js';

const CARD = { cardholder_name: 'Ada King Lovelace', number: '4242424242424242', expiry_month: 4, expiry_year: 2029, security_code: '737', brand: 'visa' };
const IDENTITY = {
  honorific: 'Dr', first_name: 'Ada', middle_name: 'King', last_name: 'Lovelace', full_name: 'Ada King Lovelace',
  email: 'ada@example.org', phone: '+44 20 7946 0000', address1: "12 St James's Square", address2: 'Flat 3', address3: '',
  city: 'London', region: 'Greater London', postal_code: 'SW1Y 4JH', country: 'GB', company: 'Analytical Engines', birth_date: '',
};

function input(attrs) {
  const { document } = makeDom('');
  const el = document.createElement('input');
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  document.body.append(el);
  return el;
}

test('formatExpiry: MM, YY, YYYY in any arrangement', () => {
  assert.equal(formatExpiry(4, 2029, 'MM/YY'), '04/29');
  assert.equal(formatExpiry(4, 2029, 'MM / YYYY'), '04 / 2029');
  assert.equal(formatExpiry(11, 2031, 'MMYY'), '1131');
  assert.equal(formatExpiry(4, 2029, 'YYYY-MM'), '2029-04');
  assert.equal(formatExpiry(4, 2009, 'M/YY'), '4/09');
});

test('expiryFormatOf: from the placeholder (localized letters too), a label, the size, else MM/YY', () => {
  assert.equal(expiryFormatOf(input({ placeholder: 'MM/YY' })), 'MM/YY');
  assert.equal(expiryFormatOf(input({ placeholder: 'MM / YY' })), 'MM / YY');
  assert.equal(expiryFormatOf(input({ placeholder: 'MM / YYYY' })), 'MM / YYYY');
  assert.equal(expiryFormatOf(input({ placeholder: 'MM-JJ' })), 'MM-YY');
  assert.equal(expiryFormatOf(input({ placeholder: 'mm/aaaa' })), 'MM/YYYY');
  assert.equal(expiryFormatOf(input({ placeholder: '12/25' })), 'MM/YY');
  assert.equal(expiryFormatOf(input({ 'aria-label': 'Expiry date (MM/YYYY)' })), 'MM/YYYY');
  assert.equal(expiryFormatOf(input({ maxlength: '4' })), 'MMYY');
  assert.equal(expiryFormatOf(input({ maxlength: '7' })), 'MM/YYYY');
  assert.equal(expiryFormatOf(input({ type: 'month' })), 'YYYY-MM');
  assert.equal(expiryFormatOf(input({ name: 'exp' })), 'MM/YY');
});

test('separate month and year boxes: MM / M and YY / YYYY by size and placeholder', () => {
  assert.equal(monthValueFor(input({ placeholder: 'MM' }), 4), '04');
  assert.equal(monthValueFor(input({ placeholder: 'M' }), 4), '4');
  assert.equal(yearValueFor(input({ placeholder: 'YY' }), 2029), '29');
  assert.equal(yearValueFor(input({ maxlength: '2' }), 2029), '29');
  assert.equal(yearValueFor(input({ placeholder: 'JJ' }), 2029), '29');
  assert.equal(yearValueFor(input({ placeholder: 'YYYY' }), 2029), '2029');
  assert.equal(yearValueFor(input({}), 2029), '2029');
});

test('month and year selects: by value, by leading number, by month name; two- or four-digit years', () => {
  const { document } = makeDom(`
    <select id="m1"><option value="">MM</option><option value="01">01</option><option value="04">04</option></select>
    <select id="m2"><option value="x1">1 - January</option><option value="x4">4 - April</option></select>
    <select id="m3"><option value="jan">January</option><option value="apr">April</option></select>
    <select id="m4"><option value="a">Jan</option><option value="b">Apr</option></select>
    <select id="y1"><option>2028</option><option>2029</option></select>
    <select id="y2"><option value="28">28</option><option value="29">29</option></select>`);
  const $ = (id) => document.getElementById(id);
  assert.equal(monthOption($('m1'), 4).value, '04');
  assert.equal(monthOption($('m2'), 4).value, 'x4');
  assert.equal(monthOption($('m3'), 4).value, 'apr');
  assert.equal(monthOption($('m4'), 4).value, 'b');
  assert.equal(monthOption($('m1'), 7), null);
  assert.equal(yearOption($('y1'), 2029).value, '2029');
  assert.equal(yearOption($('y2'), 2029).value, '29');
});

test('findOption and countryName: codes and names both ways, accents and case ignored', () => {
  const { document } = makeDom(`<select id="c"><option value="">Choose</option><option value="DE">Deutschland</option>
    <option value="gb">United Kingdom</option><option value="ci">Côte d’Ivoire</option></select>`);
  const sel = document.getElementById('c');
  assert.equal(findOption(sel, ['GB']).value, 'gb');
  assert.equal(findOption(sel, ['united kingdom']).value, 'gb');
  assert.equal(findOption(sel, ['Cote']).value, 'ci');
  assert.equal(findOption(sel, ['FR']), null);
  assert.equal(countryName('GB', sel), 'United Kingdom');
  assert.equal(countryName('Wales', sel), 'Wales');
});

function cardForm(html) {
  const { document } = makeDom(html);
  const forms = detectFormFields(document, { isVisible: isVisibleNoLayout });
  return { document, group: forms.cards[0] };
}

test('fillCardGroup: number, holder, combined expiry in the field format, CVV', () => {
  const { document, group } = cardForm(`<form><input name="n" autocomplete="cc-name"><input name="num" autocomplete="cc-number">
    <input name="exp" autocomplete="cc-exp" placeholder="MM / YY"><input name="cvc" autocomplete="cc-csc"></form>`);
  const changes = [];
  document.addEventListener('change', (e) => changes.push(e.target.name), true);
  assert.equal(fillCardGroup(group, CARD, { isVisible: isVisibleNoLayout }), 4);
  const v = (n) => document.querySelector(`[name=${n}]`).value;
  assert.deepEqual([v('n'), v('num'), v('exp'), v('cvc')], ['Ada King Lovelace', '4242424242424242', '04 / 29', '737']);
  assert.deepEqual(changes, ['num', 'n', 'exp', 'cvc'], 'frameworks hear a change for each field');
});

test('fillCardGroup: split number, month / year selects, given / family name, card type select', () => {
  const { document, group } = cardForm(`<form>
    <input name="first" autocomplete="cc-given-name"><input name="last" autocomplete="cc-family-name">
    <div><input name="c1" autocomplete="cc-number" maxlength="4"><input name="c2" maxlength="4"><input name="c3" maxlength="4"><input name="c4" maxlength="4"></div>
    <select name="m" autocomplete="cc-exp-month"><option value="">--</option><option value="3">March</option><option value="4">April</option></select>
    <select name="y" autocomplete="cc-exp-year"><option value="">--</option><option value="29">29</option></select>
    <select name="t" autocomplete="cc-type"><option value="">--</option><option value="MC">MasterCard</option><option value="VI">Visa</option></select></form>`);
  fillCardGroup(group, CARD, { isVisible: isVisibleNoLayout });
  const v = (n) => document.querySelector(`[name=${n}]`).value;
  assert.deepEqual(['c1', 'c2', 'c3', 'c4'].map(v), ['4242', '4242', '4242', '4242']);
  assert.deepEqual([v('first'), v('last'), v('m'), v('y'), v('t')], ['Ada King', 'Lovelace', '4', '29', 'VI']);
});

test('fillCardGroup: a field hidden after detection is left empty', () => {
  const { document, group } = cardForm('<form><input name="num" autocomplete="cc-number"><input name="cvc" autocomplete="cc-csc"></form>');
  document.querySelector('[name=cvc]').style.display = 'none';
  assert.equal(fillCardGroup(group, CARD, { isVisible: isVisibleNoLayout }), 1);
  assert.equal(document.querySelector('[name=cvc]').value, '');
  assert.equal(document.querySelector('[name=num]').value, '4242424242424242');
});

test('fillCardGroup: unknown expiry and missing values leave the fields alone', () => {
  const { document, group } = cardForm('<form><input name="num" autocomplete="cc-number"><input name="exp" autocomplete="cc-exp" value="keep"><input name="cvc" autocomplete="cc-csc"></form>');
  fillCardGroup(group, { ...CARD, expiry_month: 0, expiry_year: 0, security_code: '' }, { isVisible: isVisibleNoLayout });
  assert.equal(document.querySelector('[name=exp]').value, 'keep');
  assert.equal(document.querySelector('[name=cvc]').value, '');
});

test('fillIdentityGroup: names, contact, address lines, region and country selects (code to name)', () => {
  const { document } = makeDom(`<form>
    <input name="fn" autocomplete="given-name"><input name="mn" autocomplete="additional-name"><input name="ln" autocomplete="family-name">
    <input name="org" autocomplete="organization"><input name="em" autocomplete="email"><input name="tel" autocomplete="tel">
    <input name="a1" autocomplete="address-line1"><input name="a2" autocomplete="address-line2"><input name="a3" autocomplete="address-line3" value="keep">
    <input name="city" autocomplete="address-level2"><select name="reg" autocomplete="address-level1"><option value="">--</option><option value="GL">Greater London</option></select>
    <input name="zip" autocomplete="postal-code"><select name="c" autocomplete="country"><option value="">--</option><option value="UK">United Kingdom</option><option value="FR">France</option></select>
  </form>`);
  const group = detectFormFields(document, { isVisible: isVisibleNoLayout }).identities[0];
  fillIdentityGroup(group, IDENTITY, { isVisible: isVisibleNoLayout });
  const v = (n) => document.querySelector(`[name=${n}]`).value;
  assert.deepEqual(['fn', 'mn', 'ln', 'org', 'em', 'tel'].map(v), ['Ada', 'King', 'Lovelace', 'Analytical Engines', 'ada@example.org', '+44 20 7946 0000']);
  assert.deepEqual(['a1', 'a2', 'a3', 'city', 'reg', 'zip', 'c'].map(v), ["12 St James's Square", 'Flat 3', 'keep', 'London', 'GL', 'SW1Y 4JH', 'UK']);
});

test('fillIdentityGroup: full name, a street textarea and a country name box', () => {
  const { document } = makeDom(`<form><input name="name" autocomplete="name">
    <textarea name="street" autocomplete="street-address"></textarea><input name="country" autocomplete="country-name"><input name="email" type="email"></form>`);
  const group = detectFormFields(document, { isVisible: isVisibleNoLayout }).identities[0];
  fillIdentityGroup(group, IDENTITY, { isVisible: isVisibleNoLayout });
  const v = (n) => document.querySelector(`[name=${n}]`).value;
  assert.equal(v('name'), 'Ada King Lovelace');
  assert.equal(v('street'), "12 St James's Square\nFlat 3");
  assert.equal(v('country'), 'United Kingdom');
  assert.equal(v('email'), 'ada@example.org');
});
