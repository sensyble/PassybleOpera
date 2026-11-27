import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import { detectFormFields, detectFields, isVisibleNoLayout, CardField, IdentityField, FieldKind, cardFieldKind, identityFieldKind } from '../src/content/detect.js';

const opts = { isVisible: isVisibleNoLayout };

function scan(html, url) {
  const { document } = makeDom(html, url ? { url } : {});
  return { document, forms: detectFormFields(document, opts), logins: detectFields(document, opts) };
}

/** kind → name / id of the element(s) detected for it. */
function kinds(group) {
  const out = {};
  for (const [kind, els] of group.fields) out[kind] = els.map((el) => el.getAttribute('name') || el.id).join(',');
  return out;
}

test('a card form with autocomplete tokens (billing section prefix allowed)', () => {
  const { forms, logins } = scan(`<form>
    <input name="ccname" autocomplete="cc-name">
    <input name="cardnumber" autocomplete="billing cc-number" inputmode="numeric">
    <input name="exp" autocomplete="cc-exp" placeholder="MM / YY">
    <input name="cvc" autocomplete="cc-csc">
    <button>Pay</button></form>`);
  assert.equal(forms.cards.length, 1);
  assert.deepEqual(kinds(forms.cards[0]), {
    [CardField.NAME]: 'ccname', [CardField.NUMBER]: 'cardnumber', [CardField.EXP]: 'exp', [CardField.CSC]: 'cvc',
  });
  assert.equal(forms.identities.length, 0, '"name on card" is not an identity');
  assert.equal(logins.groups.length, 0, 'not a login form');
});

test('a card form found by names and labels: holder, number, month / year selects, CVV as a password box', () => {
  const { document, forms, logins } = scan(`<form id="pay">
    <label for="h">Name on card</label><input id="h" name="holder">
    <label>Card number <input name="cardNumber"></label>
    <select name="expMonth"><option value="">Month</option>${Array.from({ length: 12 }, (_, i) => `<option value="${i + 1}">${i + 1}</option>`).join('')}</select>
    <select name="expYear"><option value="">Year</option>${[2026, 2027, 2028, 2029, 2030].map((y) => `<option>${y}</option>`).join('')}</select>
    <input type="password" name="securityCode" placeholder="Security code" maxlength="4">
    <button>Pay now</button></form>`);
  assert.deepEqual(kinds(forms.cards[0]), {
    [CardField.NAME]: 'holder', [CardField.NUMBER]: 'cardNumber', [CardField.EXP_MONTH]: 'expMonth', [CardField.EXP_YEAR]: 'expYear', [CardField.CSC]: 'securityCode',
  });
  // The CVV is neither the password of a login form nor a 2FA code.
  assert.ok(!logins.fields.has(document.querySelector('[name=securityCode]')), 'CVV left out of login detection');
  assert.ok(logins.groups.every((g) => !g.otp && !g.passwords.length));
});

test('month / year selects that only say "month" / "year" join a form with a card number', () => {
  const { forms } = scan(`<form><input name="card_number" autocomplete="off">
    <select name="month">${Array.from({ length: 12 }, (_, i) => `<option>${String(i + 1).padStart(2, '0')}</option>`).join('')}</select>
    <select name="year"><option>2027</option><option>2028</option><option>2029</option></select></form>`);
  assert.deepEqual(kinds(forms.cards[0]), { [CardField.NUMBER]: 'card_number', [CardField.EXP_MONTH]: 'month', [CardField.EXP_YEAR]: 'year' });
});

test('a card number split over four boxes', () => {
  const { forms } = scan(`<form><div class="num">
    <input name="cc1" placeholder="Card number" maxlength="4"><input name="cc2" maxlength="4"><input name="cc3" maxlength="4"><input name="cc4" maxlength="4">
    </div><input name="cvv" maxlength="3"></form>`);
  assert.equal(forms.cards[0].fields.get(CardField.NUMBER).length, 4);
  assert.deepEqual(kinds(forms.cards[0])[CardField.NUMBER], 'cc1,cc2,cc3,cc4');
  assert.equal(kinds(forms.cards[0])[CardField.CSC], 'cvv');
});

test('a payment iframe with just one field (explicit autocomplete) is a card form; a lone "security code" is not', () => {
  assert.equal(scan('<input name="cvc" autocomplete="cc-csc">').forms.cards.length, 1);
  assert.equal(scan('<input name="exp-date" autocomplete="cc-exp">').forms.cards.length, 1);
  // A 2FA page asking for a "security code": still the login side's OTP field, no card.
  const twofa = scan('<form><h1>Two-step verification</h1><label>Security code <input name="code" inputmode="numeric" maxlength="6"></label><button>Verify</button></form>');
  assert.equal(twofa.forms.cards.length, 0);
  assert.equal(twofa.logins.groups[0]?.otp?.fields[0]?.name, 'code');
});

test('gift cards, coupons and loyalty numbers are not payment cards', () => {
  for (const name of ['giftCardNumber', 'loyaltyCardNumber', 'couponCode', 'memberCardNo']) {
    assert.equal(scan(`<form><input name="${name}"><input name="x"></form>`).forms.cards.length, 0, name);
  }
});

test('a bank sign-in with a card number and a password stays a login form', () => {
  const { document, forms, logins } = scan(`<form><label>Card number <input name="cardnumber"></label>
    <input type="password" name="password"><button>Sign in</button></form>`);
  const g = logins.groups[0];
  assert.equal(g.username, document.querySelector('[name=cardnumber]'));
  assert.equal(g.currentPassword, document.querySelector('[name=password]'));
  // The number is also a card field; main.js gives fields detectFields claims to the login menu.
  assert.ok(forms.fields.has(document.querySelector('[name=cardnumber]')));
});

test('an address form with autocomplete tokens (shipping section)', () => {
  const { forms } = scan(`<form>
    <input name="n" autocomplete="shipping name"><input name="org" autocomplete="organization">
    <input name="a1" autocomplete="shipping address-line1"><input name="a2" autocomplete="shipping address-line2">
    <input name="city" autocomplete="shipping address-level2"><input name="state" autocomplete="shipping address-level1">
    <input name="zip" autocomplete="shipping postal-code"><select name="c" autocomplete="shipping country"><option value="GB">United Kingdom</option></select>
    <input name="e" autocomplete="email"><input name="t" autocomplete="tel-national"></form>`);
  assert.equal(forms.identities.length, 1);
  assert.deepEqual(kinds(forms.identities[0]), {
    [IdentityField.NAME]: 'n', [IdentityField.ORGANIZATION]: 'org', [IdentityField.LINE1]: 'a1', [IdentityField.LINE2]: 'a2',
    [IdentityField.CITY]: 'city', [IdentityField.REGION]: 'state', [IdentityField.POSTAL]: 'zip', [IdentityField.COUNTRY]: 'c',
    [IdentityField.EMAIL]: 'e', [IdentityField.TEL]: 't',
  });
});

test('an address form found by names and labels', () => {
  const { forms } = scan(`<form>
    <label>First name <input name="fname"></label><label>Last name <input name="lname"></label>
    <label>E-mail address <input type="email" name="mail"></label><label>Phone <input type="tel" name="phone"></label>
    <label>Street address <input name="street"></label><label>Apartment, suite <input name="apt"></label>
    <label>City <input name="town"></label><label>State / Province <select name="region"><option>CA</option></select></label>
    <label>ZIP code <input name="zip"></label><label>Country <select name="country"><option>US</option></select></label>
    <label>Company (optional) <input name="company"></label></form>`);
  assert.deepEqual(kinds(forms.identities[0]), {
    [IdentityField.GIVEN_NAME]: 'fname', [IdentityField.FAMILY_NAME]: 'lname', [IdentityField.EMAIL]: 'mail', [IdentityField.TEL]: 'phone',
    [IdentityField.LINE1]: 'street', [IdentityField.LINE2]: 'apt', [IdentityField.CITY]: 'town', [IdentityField.REGION]: 'region',
    [IdentityField.POSTAL]: 'zip', [IdentityField.COUNTRY]: 'country', [IdentityField.ORGANIZATION]: 'company',
  });
});

test('no identity form for a sign-in, a newsletter box or a search field', () => {
  assert.equal(scan('<form><input type="email" name="email"><input type="password" name="password"><button>Sign in</button></form>').forms.identities.length, 0);
  assert.equal(scan('<form><input type="email" name="newsletter" placeholder="Your e-mail"><button>Subscribe</button></form>').forms.identities.length, 0);
  assert.equal(scan('<form><input name="q" placeholder="Search"><button>Go</button></form>').forms.identities.length, 0);
  assert.equal(scan('<form><input name="user_name" placeholder="Username"><input name="nickname"><input name="display_name"></form>').forms.identities.length, 0);
});

test('a sign-up form: the login detection is unchanged; the name fields are an identity form', () => {
  const { document, forms, logins } = scan(`<form><h1>Create account</h1>
    <input name="first_name" placeholder="First name"><input name="last_name" placeholder="Last name">
    <input type="email" name="email" placeholder="Email"><input type="password" name="password" autocomplete="new-password">
    <button>Create account</button></form>`);
  const g = logins.groups[0];
  assert.equal(g.username, document.querySelector('[name=email]'));
  assert.deepEqual(g.newPasswords, [document.querySelector('[name=password]')]);
  assert.equal(logins.fields.get(document.querySelector('[name=first_name]')), undefined);
  assert.equal(forms.fields.get(document.querySelector('[name=first_name]'))?.kind, IdentityField.GIVEN_NAME);
  assert.equal(forms.fields.get(document.querySelector('[name=password]')), undefined, 'never a password field');
});

test('a 2FA page and a login form give no card or identity fields', () => {
  const twofa = scan('<form><p>Enter the code from your authenticator app</p><input name="otp" autocomplete="one-time-code"></form>');
  assert.equal(twofa.forms.fields.size, 0);
  assert.equal(twofa.logins.groups[0].otp.fields[0].name, 'otp');
});

test('hidden and disabled fields are never detected (so never filled)', () => {
  const { document, forms } = scan(`<form>
    <input name="cardnumber" autocomplete="cc-number"><input name="cvc" autocomplete="cc-csc" style="display:none">
    <input name="exp" autocomplete="cc-exp" disabled><input type="hidden" name="cc-name" autocomplete="cc-name">
    <div hidden><input name="cvc2" autocomplete="cc-csc"></div></form>`);
  assert.deepEqual(kinds(forms.cards[0]), { [CardField.NUMBER]: 'cardnumber' });
  assert.ok(!forms.fields.has(document.querySelector('[name=cvc]')));
});

test('field classifiers: card and identity hints in a few languages', () => {
  const { document } = makeDom(`
    <input id="a" placeholder="Kartennummer"><input id="b" placeholder="Numéro de carte"><input id="c" name="cvv2">
    <input id="d" placeholder="MM/JJ"><input id="e" name="exp_year" placeholder="YYYY"><input id="f" type="month" name="expiry">
    <input id="g" name="nachname"><input id="h" name="postleitzahl"><input id="i" name="ville"><input id="j" placeholder="Email address">
    <input id="k" name="username" autocomplete="username"><input id="l" name="otp" autocomplete="one-time-code">`);
  const $ = (id) => document.getElementById(id);
  assert.equal(cardFieldKind($('a')), CardField.NUMBER);
  assert.equal(cardFieldKind($('b')), CardField.NUMBER);
  assert.equal(cardFieldKind($('c')), CardField.CSC);
  assert.equal(cardFieldKind($('d')), CardField.EXP);
  assert.equal(cardFieldKind($('e')), CardField.EXP_YEAR);
  assert.equal(cardFieldKind($('f')), CardField.EXP);
  assert.equal(identityFieldKind($('g')), IdentityField.FAMILY_NAME);
  assert.equal(identityFieldKind($('h')), IdentityField.POSTAL);
  assert.equal(identityFieldKind($('i')), IdentityField.CITY);
  assert.equal(identityFieldKind($('j')), IdentityField.EMAIL, '"Email address" is the e-mail, not a postal address');
  for (const id of ['k', 'l']) {
    assert.equal(cardFieldKind($(id)), null, id);
    assert.equal(identityFieldKind($(id)), null, id);
  }
  assert.equal(FieldKind.OTP, 'otp');
});
