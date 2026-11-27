import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import {
  detectFields, isVisibleNoLayout, FieldKind, normalizeHint, otpScore, usernameScore,
  classifyPasswords, findSplitOtpGroups, collectInputs, labelText, isWebauthnField, formIntent, couldBeCodeField,
  adoptableCodeField, nearRichEditor,
} from '../src/content/detect.js';

const detect = (html, opts) => {
  const { document } = makeDom(html, opts);
  return { document, ...detectFields(document, { isVisible: isVisibleNoLayout }) };
};
const $ = (doc, sel) => doc.querySelector(sel);

test('normalizeHint splits camelCase and punctuation', () => {
  assert.equal(normalizeHint('userName'), 'user name');
  assert.equal(normalizeHint('mfa_code-input'), 'mfa code input');
  assert.equal(normalizeHint('  OTP[code] '), 'otp code');
  assert.equal(normalizeHint('verificationCode'), 'verification code');
});

test('classic sign-in form: e-mail + password', () => {
  const { document, groups, fields } = detect(`
    <form id="f"><input type="email" name="email"><input type="password" name="pass"><button>Sign in</button></form>`);
  assert.equal(groups.length, 1);
  const g = groups[0];
  assert.equal(g.form, $(document, '#f'));
  assert.equal(g.username, $(document, '[name=email]'));
  assert.equal(g.currentPassword, $(document, '[name=pass]'));
  assert.deepEqual(g.newPasswords, []);
  assert.equal(g.otp, null);
  assert.equal(fields.get($(document, '[name=pass]')).kind, FieldKind.CURRENT_PASSWORD);
});

test('autocomplete attributes win over names', () => {
  const { document, groups } = detect(`
    <form><input name="a1" autocomplete="username"><input name="search_q">
      <input type="password" name="x" autocomplete="current-password"></form>`);
  assert.equal(groups[0].username, $(document, '[name=a1]'));
  assert.equal(groups[0].currentPassword, $(document, '[name=x]'));
});

test('text field right before the password counts as username; later fields do not', () => {
  const { document, groups } = detect(`
    <form><input type="text" name="login_field"><input type="password" name="password">
      <input type="text" name="after"></form>`);
  assert.equal(groups[0].username, $(document, '[name=login_field]'));
});

test('sign-up form: password + confirmation are new passwords', () => {
  const { document, groups } = detect(`
    <form><h2>Create your account</h2><input type="email" name="email">
      <input type="password" name="password"><input type="password" name="password_confirm">
      <button>Sign up</button></form>`);
  const g = groups[0];
  assert.equal(g.currentPassword, null);
  assert.deepEqual(g.newPasswords, [$(document, '[name=password]'), $(document, '[name=password_confirm]')]);
  assert.equal(g.username, $(document, '[name=email]'));
});

test('single password on a sign-up page is a new password', () => {
  const { groups } = detect(`<form><input type="email" name="email"><input type="password" name="pw"><button>Register</button></form>`);
  assert.equal(groups[0].currentPassword, null);
  assert.equal(groups[0].newPasswords.length, 1);
});

test('change-password form: current + new + confirm', () => {
  const { document, groups } = detect(`
    <form><label for="o">Current password</label><input id="o" type="password">
      <label for="n">New password</label><input id="n" type="password">
      <label for="c">Confirm new password</label><input id="c" type="password"></form>`);
  const g = groups[0];
  assert.equal(g.currentPassword, $(document, '#o'));
  assert.deepEqual(g.newPasswords, [$(document, '#n'), $(document, '#c')]);
});

test('classifyPasswords without hints: three fields -> current, new, new', () => {
  const { document } = makeDom('<input type="password"><input type="password"><input type="password">');
  const els = [...document.querySelectorAll('input')];
  assert.deepEqual(classifyPasswords(els, 'Account settings'), [FieldKind.CURRENT_PASSWORD, FieldKind.NEW_PASSWORD, FieldKind.NEW_PASSWORD]);
  assert.deepEqual(classifyPasswords(els.slice(0, 1), 'Log in'), [FieldKind.CURRENT_PASSWORD]);
});

test('hidden, disabled, readonly and honeypot fields are ignored', () => {
  const { document, groups } = detect(`
    <form>
      <input type="text" name="trap" style="display:none">
      <div hidden><input type="text" name="hidden_user"></div>
      <input type="hidden" name="csrf" value="x">
      <input type="text" name="ro" readonly>
      <input type="email" name="email">
      <input type="password" name="disabled_pw" disabled>
      <input type="password" name="pw" style="visibility:hidden">
      <input type="password" name="real">
      <div style="opacity:0"><input type="password" name="invisible"></div>
    </form>`);
  const g = groups[0];
  assert.equal(g.username, $(document, '[name=email]'));
  assert.equal(g.currentPassword, $(document, '[name=real]'));
  assert.equal(g.passwords.length, 1);
});

test('form-less login (SPA) is still one group', () => {
  const { document, groups } = detect(`
    <div class="login"><input type="text" placeholder="Username or email"><input type="password" placeholder="Password">
    <div role="button">Log in</div></div>`);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].form, null);
  assert.equal(groups[0].username, $(document, 'input[type=text]'));
});

test('identifier-first step: a lone username field is detected only when confident', () => {
  let r = detect('<form><input type="email" name="identifier" autocomplete="username"><button>Next</button></form>');
  assert.equal(r.groups.length, 1);
  assert.equal(r.groups[0].username, $(r.document, 'input'));
  r = detect('<form><h1>Sign in</h1><input type="email" name="email"><button>Continue</button></form>');
  assert.equal(r.groups.length, 1, 'login wording + email field');
  r = detect('<form><h3>Our newsletter</h3><input type="email" name="email"><button>Subscribe</button></form>');
  assert.equal(r.groups.length, 0, 'newsletter boxes are left alone');
  r = detect('<form role="search"><input type="search" name="q"><input type="text" name="query"></form>');
  assert.equal(r.groups.length, 0, 'search boxes are not usernames');
});

test('passkey autofill field is a username and flagged webauthn', () => {
  const { document, groups } = detect('<form><input name="u" autocomplete="username webauthn"></form>');
  assert.equal(groups[0].username, $(document, 'input'));
  assert.ok(isWebauthnField($(document, 'input')));
});

test('OTP via autocomplete="one-time-code"', () => {
  const { document, groups, fields } = detect('<form><input name="whatever" autocomplete="one-time-code"></form>');
  assert.equal(groups[0].otp.kind, 'single');
  assert.equal(groups[0].otp.fields[0], $(document, 'input'));
  assert.equal(fields.get($(document, 'input')).kind, FieldKind.OTP);
});

test('OTP via names and labels in several languages', () => {
  for (const html of [
    '<input name="otp">',
    '<input id="totpCode">',
    '<input name="mfa_code">',
    '<input name="two_factor_code">',
    '<label>Authenticator code <input name="c1"></label>',
    '<label for="v">Verification code</label><input id="v" inputmode="numeric">',
    '<input aria-label="Bestätigungscode">',
    '<input placeholder="Code de vérification">',
    '<input placeholder="Código de verificación">',
    '<input placeholder="認証コード">',
    '<input type="password" name="otp_password">',
  ]) {
    const { groups } = detect(`<form>${html}</form>`);
    assert.equal(groups.length, 1, html);
    assert.ok(groups[0].otp, html);
  }
});

test('weak "code" hint needs numeric shape or 2FA context', () => {
  let r = detect('<form><p>Enter the code from your authenticator app</p><input type="text" name="code"></form>');
  assert.ok(r.groups[0]?.otp, '2FA wording in the form');
  r = detect('<form><input type="tel" name="code" maxlength="6"></form>');
  assert.ok(r.groups[0]?.otp, 'numeric 6-char field named code');
  r = detect('<form><p>Contact us</p><input type="text" name="token_description"><input type="text" name="message"></form>');
  assert.equal(r.groups.length, 0);
});

test('codes that are not OTPs: zip, promo, card security code, country code', () => {
  for (const html of [
    '<input name="zip_code" maxlength="5" inputmode="numeric">',
    '<input name="promo_code">',
    '<input name="security_code" autocomplete="cc-csc">',
    '<label>Card security code <input name="cvc" maxlength="4"></label>',
    '<input name="country_code" type="tel">',
    '<input name="postal-code" autocomplete="postal-code">',
  ]) {
    const { groups } = detect(`<form>${html}</form>`);
    assert.ok(!groups.some((g) => g.otp), html);
  }
});

test('"verify password" is a confirmation, not an OTP', () => {
  const { groups } = detect('<form><input type="password" name="password"><input type="password" name="verify_password"></form>');
  assert.equal(groups[0].otp, null);
  assert.equal(groups[0].newPasswords.length, 2);
});

test('split OTP: six single-character boxes', () => {
  const boxes = Array.from({ length: 6 }, (_, i) => `<div class="cell"><input maxlength="1" inputmode="numeric" name="d${i}"></div>`).join('');
  const { document, groups } = detect(`<form><p>Enter code</p><div class="otp">${boxes}</div><button>Verify</button></form>`);
  assert.equal(groups[0].otp.kind, 'split');
  assert.deepEqual(groups[0].otp.fields, [...document.querySelectorAll('input')]);
});

test('split OTP: four boxes need a hint; unrelated single-char inputs are not grouped', () => {
  let r = detect('<form><input maxlength="1"><input maxlength="1"><input maxlength="1"><input maxlength="1"></form>');
  assert.equal(r.groups.length, 0, 'four anonymous boxes, no hint');
  r = detect('<form><p>Two-factor authentication</p><input maxlength="1"><input maxlength="1"><input maxlength="1"><input maxlength="1"></form>');
  assert.equal(r.groups[0].otp.kind, 'split');
  r = detect('<form><div><input maxlength="1"><input maxlength="1"><input maxlength="1"></div><section><div><div><input maxlength="1"><input maxlength="1"><input maxlength="1"></div></div></section></form>');
  assert.equal(r.groups.length, 0, 'two runs of three, far apart');
});

test('findSplitOtpGroups respects the 4..8 range', () => {
  const { document } = makeDom(`<div>${'<input maxlength="1" inputmode="numeric">'.repeat(10)}</div>`);
  assert.equal(findSplitOtpGroups(collectInputs(document)).length, 0);
});

test('login form with an OTP field in the same form', () => {
  const { document, groups } = detect(`
    <form><input name="username"><input type="password" name="password">
      <input name="otp" autocomplete="one-time-code"></form>`);
  const g = groups[0];
  assert.equal(g.username, $(document, '[name=username]'));
  assert.equal(g.currentPassword, $(document, '[name=password]'));
  assert.equal(g.otp.fields[0], $(document, '[name=otp]'));
});

test('two forms on a page give two groups', () => {
  const { groups } = detect(`
    <form id="login"><input type="email" name="e"><input type="password" name="p"></form>
    <form id="signup"><input type="email" name="e2"><input type="password" name="p2" autocomplete="new-password"></form>`);
  assert.equal(groups.length, 2);
  assert.ok(groups[0].currentPassword);
  assert.equal(groups[1].newPasswords.length, 1);
});

test('inputs inside open shadow roots are found', () => {
  const { document, window } = makeDom('<form><login-box></login-box></form>');
  const host = document.querySelector('login-box');
  const root = host.attachShadow({ mode: 'open' });
  root.innerHTML = '<input type="email" name="email"><input type="password" name="password">';
  const { groups } = detectFields(document, { isVisible: isVisibleNoLayout });
  assert.equal(groups.length, 1);
  assert.equal(groups[0].username, root.querySelector('[name=email]'));
  assert.equal(groups[0].currentPassword, root.querySelector('[name=password]'));
  assert.equal(groups[0].form, document.querySelector('form'), 'form found across the shadow boundary');
  assert.ok(window);
});

test('labelText reads <label for>, wrapping labels and aria-labelledby', () => {
  const { document } = makeDom(`
    <label for="a">Email address</label><input id="a">
    <label>User name <input id="b"></label>
    <span id="lbl">Your login</span><input id="c" aria-labelledby="lbl">`);
  assert.match(labelText(document.getElementById('a')), /Email address/);
  assert.match(labelText(document.getElementById('b')), /User name/);
  assert.match(labelText(document.getElementById('c')), /Your login/);
});

test('scores: usernameScore and otpScore basics', () => {
  const { document } = makeDom(`
    <input id="u1" autocomplete="username"><input id="u2" type="email"><input id="u3" name="first_name">
    <input id="u4" type="password"><input id="o1" autocomplete="one-time-code"><input id="o2" name="email" type="email">`);
  const g = (id) => document.getElementById(id);
  assert.equal(usernameScore(g('u1')), 100);
  assert.ok(usernameScore(g('u2')) >= 50);
  assert.equal(usernameScore(g('u3')), 0);
  assert.equal(usernameScore(g('u4')), 0);
  assert.equal(otpScore(g('o1')), 100);
  assert.equal(otpScore(g('o2')), 0);
});

test('sign-up with a "Sign in" link: the submit button decides, so the single password is new', () => {
  const { groups } = detect(`<form><h2>Welcome</h2><input type="email" name="email"><input type="password" name="pw">
    <p>Already have an account? <a href="/login">Sign in</a></p><button type="submit">Create account</button></form>`);
  assert.equal(groups[0].intent, 'signup');
  assert.equal(groups[0].currentPassword, null);
  assert.equal(groups[0].newPasswords.length, 1);
});

test('sign-in with a "Sign up" link stays a sign-in form', () => {
  const { groups } = detect(`<form><input type="email" name="email"><input type="password" name="pw">
    <a href="/join">No account? Sign up</a><button type="submit">Sign in</button></form>`);
  assert.equal(groups[0].intent, 'login');
  assert.ok(groups[0].currentPassword);
  assert.equal(groups[0].newPasswords.length, 0);
});

test('neutral wording: the page path decides (/register → sign-up)', () => {
  const html = `<form><input type="email" name="email"><input type="password" name="pw"><button type="submit">Continue</button></form>`;
  assert.equal(detect(html, { url: 'https://example.com/register' }).groups[0].newPasswords.length, 1);
  assert.ok(detect(html, { url: 'https://example.com/login' }).groups[0].currentPassword);
  assert.ok(detect(html, { url: 'https://example.com/' }).groups[0].currentPassword, 'unknown stays a sign-in');
});

test('formIntent', () => {
  assert.equal(formIntent({ submitText: 'Create account', text: 'Sign in instead' }), 'signup');
  assert.equal(formIntent({ submitText: 'Log in', text: 'Sign up for free' }), 'login');
  assert.equal(formIntent({ text: 'Register now' }), 'signup');
  assert.equal(formIntent({ text: 'Sign in or sign up' }), null);
  assert.equal(formIntent({ path: '/users/sign_up' }), 'signup');
  assert.equal(formIntent({}), null);
});


// 2FA steps as real sites build them.

const otpOf = (html, opts) => {
  const { document, groups } = detect(html, opts);
  const g = groups.find((x) => x.otp);
  return { document, field: g?.otp.kind === 'single' ? g.otp.fields[0] : null, otp: g?.otp || null, groups };
};
const detectWithPage = (html) => {
  const { document } = makeDom(html);
  return { document, ...detectFields(document, { isVisible: isVisibleNoLayout, pageText: () => document.body.textContent }) };
};

test('look-alikes of well-known 2FA pages', () => {
  const cases = {
    github: '<form><h1>Two-factor authentication</h1><input type="text" name="app_otp" id="app_totp" autocomplete="one-time-code" inputmode="numeric"></form>',
    google: '<form><input type="tel" name="totpPin" id="totpPin" autocomplete="off" pattern="[0-9 ]*" aria-label="Enter code"></form>',
    microsoft: '<div><input name="otc" type="tel" id="idTxtBx_SAOTCC_OTC" maxlength="6" aria-label="Code" placeholder="Code" autocomplete="off"></div>',
    aws: '<form><input id="mfacode" name="mfacode" type="text" autocomplete="off"></form>',
    cloudflare: '<form><input data-testid="two-factor-login-code-input" name="twofactor_token" type="text" inputmode="numeric"></form>',
    'verification_code': '<form><input name="verification_code" type="text"></form>',
    'mfa_code numeric': '<form><input name="mfa_code" inputmode="numeric"></form>',
    'otpCode': '<form><input name="otpCode"></form>',
    'smstoken': '<form><input name="smstoken"></form>',
  };
  for (const [name, html] of Object.entries(cases)) {
    const { field, document } = otpOf(html);
    assert.equal(field, document.querySelector('input'), name);
  }
});

test('unnamed numeric code field: the heading above the form says 2FA (next to it, or a short page)', () => {
  const html = `<h1>Two-factor authentication</h1><p>Enter the 6-digit code from your authenticator app.</p>
    <form><input id="c" type="text" inputmode="numeric" maxlength="6" autocomplete="off"><button>Continue</button></form>`;
  const { document, groups } = detectWithPage(html);
  assert.equal(groups.find((g) => g.otp)?.otp.fields[0], $(document, '#c'));
  // The heading sits next to the form: no page text needed.
  assert.equal(otpOf(html).field?.id, 'c');
  // Far from the field, on a short page with this one input: the page text still says it.
  const filler = '<div>' + '<p>Some navigation and footer text here.</p>'.repeat(20) + '</div>';
  const far = `<h1>Two-factor authentication</h1><p>Enter the 6-digit code from your authenticator app.</p>${filler}
    <div><div><form><input id="c" type="text" inputmode="numeric" maxlength="6"><button>Continue</button></form></div></div>`;
  assert.equal(detectWithPage(far).groups.find((g) => g.otp)?.otp.fields[0].id, 'c');
  assert.equal(otpOf(far).field, null, 'without the page text nothing near the field says 2FA');
});

// Not a 2FA code: mail, search, coupons (Gmail's compose Subject box must never take a code).

const INBOX = Array.from({ length: 40 }, (_, i) =>
  `<tr><td>Google</td><td>${i % 3 ? 'Your verification code is 123456' : '2-Step Verification turned on'}</td><td>Use this code with your authenticator app. Message ${i}.</td></tr>`).join('');
const GMAIL = `<header><form role="search"><input name="q" aria-label="Search mail" placeholder="Search mail"></form></header>
  <table>${INBOX}</table>
  <div role="dialog" aria-label="New Message"><div>New Message</div>
    <form enctype="multipart/form-data" method="post">
      <input type="hidden" name="draft" value="x">
      <div><div id="to" role="combobox" aria-label="To recipients"><input id="to-chip" role="combobox" aria-autocomplete="list" hidden></div></div>
      <div><input id="subject" name="subjectbox" placeholder="Subject" aria-label="Subject"></div>
      <div><div id="body" contenteditable="true" role="textbox" aria-label="Message Body">Your verification code is 123456</div></div>
      <div role="button">Send</div>
    </form>
  </div>`;

test('Gmail-like compose on an inbox full of verification codes: the Subject is no code field', () => {
  const { document, groups, fields } = detectWithPage(GMAIL);
  assert.equal(groups.find((g) => g.otp), undefined);
  assert.equal(fields.get($(document, '#subject')), undefined);
  assert.equal(couldBeCodeField($(document, '#subject')), false, 'named Subject');
  assert.equal(couldBeCodeField($(document, '#to-chip')), false, 'a combobox');
  // Even an unnamed code-sized box alone in the compose form is no code field: it sits next to a
  // rich-text editor.
  const bare = GMAIL.replace('name="subjectbox" placeholder="Subject" aria-label="Subject"', 'maxlength="6"');
  const r = detectWithPage(bare);
  assert.equal(r.groups.find((g) => g.otp), undefined);
  assert.equal(nearRichEditor($(r.document, '#subject')), true);
  const page = { pageText: () => r.document.body.textContent, inputCount: () => 3, loginPath: false };
  assert.equal(adoptableCodeField($(r.document, '#subject'), page), false);
});

test('a lone text box on a long page that talks about verification codes is no code field', () => {
  const article = '<article><h1>How 2-Step Verification works</h1>' +
    '<p>When you sign in, enter the verification code from your authenticator app. </p>'.repeat(60) + '</article>';
  for (const box of ['<form><input id="x" type="text"><button>Go</button></form>', '<div><input id="x"></div>',
    '<form><input id="x" type="text" maxlength="8"><button>Go</button></form>']) {
    const { document, groups } = detectWithPage(`${article}<aside>${box}</aside>`);
    assert.equal(groups.find((g) => g.otp), undefined, box);
    const page = { pageText: () => document.body.textContent, inputCount: () => 1, loginPath: false };
    if (!/maxlength/.test(box)) assert.equal(adoptableCodeField($(document, '#x'), page), false, box);
  }
  // a site search box with verification wording right next to it
  const { document, groups } = detectWithPage('<form><label for="s">Search the help center</label><input id="s" name="term"><p>Try "verification code" or "2FA"</p></form>');
  assert.equal(groups.find((g) => g.otp), undefined);
  assert.equal(couldBeCodeField($(document, '#s')), false);
});

test('coupon, promo, gift card, referral, postal and captcha codes are never 2FA codes', () => {
  const fields = [
    '<input name="coupon_code" maxlength="8">', '<input placeholder="Promo code" inputmode="numeric">',
    '<input aria-label="Gift card code">', '<input name="voucher">', '<input placeholder="Discount code">',
    '<input name="referral_code">', '<input placeholder="Invite code">', '<input name="zip" maxlength="5" inputmode="numeric">',
    '<input placeholder="Postal code">', '<input name="captcha" maxlength="6">', '<input placeholder="Gutscheincode">',
    '<input placeholder="Código de descuento">', '<input placeholder="クーポンコード">', '<input placeholder="优惠码">',
    '<input placeholder="Kode promo">', '<input placeholder="Redeem code">',
  ];
  for (const f of fields) {
    // even on a 2FA-looking page, alone in a form that talks about verification codes
    const { document, groups } = detectWithPage(`<form><h1>Verification code</h1><p>Enter the code</p>${f}<button>Apply</button></form>`);
    assert.equal(groups.find((g) => g.otp), undefined, f);
    const el = document.querySelector('input');
    assert.equal(otpScore(el, 'two-factor authentication'), 0, f);
    assert.equal(couldBeCodeField(el), false, f);
  }
});

test('ordinary text fields are not code fields, unless they also name a code', () => {
  const no = ['name="subject"', 'placeholder="Subject"', 'placeholder="Betreff"', 'placeholder="Objet"', 'placeholder="Asunto"',
    'placeholder="件名"', 'placeholder="제목"', 'placeholder="विषय"', 'placeholder="Subjek"', 'placeholder="Тема"',
    'name="title"', 'placeholder="Write a message"', 'aria-label="Add a comment"', 'placeholder="Reply"',
    'name="note"', 'placeholder="Caption"', 'name="description"', 'name="keywords"', 'placeholder="Amount"', 'name="full_name"'];
  for (const attrs of no) {
    const { document } = makeDom(`<input ${attrs}>`);
    assert.equal(couldBeCodeField(document.querySelector('input')), false, attrs);
  }
  const yes = ['aria-label="Code from the text message"', 'placeholder="Verification code"', 'name="answer"',
    'placeholder="Authentication code"', 'placeholder="One-time code"', 'name="otp"', 'placeholder="6-digit code"',
    'placeholder="Security code"', 'placeholder="Kode verifikasi"', 'placeholder="सत्यापन कोड"'];
  for (const attrs of yes) {
    const { document } = makeDom(`<input ${attrs}>`);
    assert.equal(couldBeCodeField(document.querySelector('input')), true, attrs);
  }
  // a "system" (Cyrillic) is no "subject" (тема)
  const { document } = makeDom('<input placeholder="Код из системы">');
  assert.equal(couldBeCodeField(document.querySelector('input')), true);
});

test('real 2FA steps still found: a lone unnamed box with the wording next to it, named fields, split boxes', () => {
  let r = detectWithPage('<main><h2>Enter the code from your authenticator app</h2><form><input id="c" type="text"><button>Verify</button></form></main>');
  assert.equal(r.groups.find((g) => g.otp)?.otp.fields[0].id, 'c');
  r = detectWithPage('<div class="card"><p>Two-step verification</p><div><input id="c"></div><button>Next</button></div>');
  assert.equal(r.groups.find((g) => g.otp)?.otp.fields[0].id, 'c');
  r = detectWithPage(`${INBOX}<form><label>Verification code</label><input id="c" name="vc"></form>`);
  assert.equal(r.groups.find((g) => g.otp)?.otp.fields[0].id, 'c', 'named, on a long page');
  r = detectWithPage(`${INBOX}<form><input id="c" autocomplete="one-time-code"></form>`);
  assert.equal(r.groups.find((g) => g.otp)?.otp.fields[0].id, 'c');
  r = detectWithPage(`<form><h1>Enter your verification code</h1><div>${'<input maxlength="1" inputmode="numeric">'.repeat(6)}</div></form>`);
  assert.equal(r.groups.find((g) => g.otp)?.otp.kind, 'split');
});

test('adoptableCodeField: who may take a pending code on focus', () => {
  const page = (doc, extra = {}) => ({ pageText: () => doc.body.textContent, inputCount: () => 1, loginPath: false, ...extra });
  // shaped like a code, or named a code
  let { document } = makeDom('<form><input id="a" inputmode="numeric" maxlength="6"></form><form><input id="b" placeholder="Code"></form>');
  assert.equal(adoptableCodeField($(document, '#a'), page(document)), true);
  assert.equal(adoptableCodeField($(document, '#b'), page(document)), true);
  // a plain box on a short sign-in step page (the e2e "unknown" step), or a short 2FA page
  ({ document } = makeDom('<form><h1>One more step</h1><p>Type the number you see.</p><input id="c" name="answer"><button>OK</button></form>'));
  assert.equal(adoptableCodeField($(document, '#c'), page(document, { loginPath: true })), true);
  assert.equal(adoptableCodeField($(document, '#c'), page(document)), false, 'nothing says 2FA and not a sign-in URL');
  // never a field with text in it, a username, or one on a long page with nothing near it
  ({ document } = makeDom('<form><input id="d" inputmode="numeric" value="42"><input id="e" name="login"></form>'));
  assert.equal(adoptableCodeField($(document, '#d'), page(document)), false);
  assert.equal(adoptableCodeField($(document, '#e'), page(document, { loginPath: true })), false);
  ({ document } = makeDom(`<table>${INBOX}</table><div><input id="f"></div>`));
  assert.equal(adoptableCodeField($(document, '#f'), page(document, { loginPath: true })), false, 'a long page');
  assert.equal(adoptableCodeField($(document, '#f'), page(document, { inputCount: () => 9 })), false);
});

test('the only text field of a 2FA form is its code field', () => {
  const { field, document } = otpOf('<form><h1>2-Step Verification</h1><p>Enter the code shown in your authenticator app</p><input id="c" name="response" type="text"><button>Next</button></form>');
  assert.equal(field, $(document, '#c'));
});

test('unnamed fallbacks stay away from sign-in, phone, e-mail and username fields', () => {
  const twoFa = '<p>Protected by two-factor authentication (2FA).</p>';
  // a sign-in form with a numeric username on a page that mentions 2FA
  let r = detectWithPage(`${twoFa}<form><input id="u" type="tel" maxlength="8"><input type="password"></form>`);
  assert.equal(r.groups[0].otp, null);
  // identifier-first with 2FA wording around it
  r = detectWithPage(`${twoFa}<form><h1>Sign in</h1><input id="u" name="loginfmt" type="text"></form>`);
  assert.equal(r.groups.find((g) => g.otp), undefined);
  // phone number to send the code to
  r = detectWithPage(`<form><h1>Set up 2-step verification</h1><label for="p">Phone number</label><input id="p" type="tel" maxlength="10"></form>`);
  assert.equal(r.groups.find((g) => g.otp), undefined);
  // e-mail field on a 2FA recovery page
  r = detectWithPage('<form><h1>Lost your authenticator?</h1><input type="email" name="recovery"></form>');
  assert.equal(r.groups.find((g) => g.otp), undefined);
  // a numeric field on a page with nothing about 2FA
  r = detectWithPage('<form><h1>Order</h1><input name="qty" type="number" maxlength="6"></form>');
  assert.equal(r.groups.find((g) => g.otp), undefined);
});

test('couldBeCodeField: text-like fields yes; e-mail, password, phone, card, search no', () => {
  const { document } = makeDom(`<input id="a" name="answer"><input id="b" type="tel" name="x"><input id="c" type="email">
    <input id="d" type="password"><input id="e" name="phone"><input id="f" autocomplete="cc-number"><input id="g" name="search">
    <input id="h" autocomplete="one-time-code" type="text"><input id="i" type="checkbox"><input id="j" disabled>`);
  const yes = ['a', 'b', 'h'];
  for (const id of 'abcdefghij') assert.equal(couldBeCodeField($(document, `#${id}`)), yes.includes(id), id);
});
// Bootstrap sign-in forms: type=email without autocomplete, labelled "Email address".
const BS_EMAIL = '<input type="email" class="form-control" name="username" id="inputEmail" placeholder="name@example.com" autofocus="">';
const BS_REMEMBER = '<div class="checkbox"><label><input type="checkbox" value="remember-me"> Remember me</label></div>';

test('e-mail sign-in fields: type=email is the username of a login form, "Email address" labels included', () => {
  const variants = {
    exact: `${BS_EMAIL}<input type="password" id="inputPassword">`,
    'sr-only label': `<label for="inputEmail" class="sr-only">Email address</label>${BS_EMAIL}<label for="inputPassword" class="sr-only">Password</label><input type="password" id="inputPassword">`,
    'floating label': `<div class="form-floating"><input type="email" class="form-control" id="inputEmail" placeholder="name@example.com"><label for="inputEmail">Email address</label></div><input type="password" id="inputPassword">`,
    'no name': `<label for="inputEmail">E-mail address</label><input type="email" id="inputEmail"><input type="password" id="inputPassword">`,
    'autocomplete=email': `<label for="inputEmail">Email address</label><input type="email" id="inputEmail" autocomplete="email"><input type="password" id="inputPassword">`,
    'type=email autocomplete=username': `<input type="email" id="inputEmail" autocomplete="username"><input type="password" id="inputPassword">`,
  };
  for (const [name, fields] of Object.entries(variants)) {
    const { document, groups, fields: kinds } = detect(`<form><h1>Please sign in</h1>${fields}${BS_REMEMBER}<button type="submit">Sign in</button></form>`);
    assert.equal(groups.length, 1, name);
    assert.equal(groups[0].username, $(document, '#inputEmail'), name);
    assert.equal(groups[0].currentPassword, $(document, '#inputPassword'), name);
    assert.equal(kinds.get($(document, '#inputEmail')).kind, FieldKind.USERNAME, name);
    assert.ok(usernameScore($(document, '#inputEmail')) >= 60, name);
  }
});

test('"Email address" still is no postal address; real address fields stay out', () => {
  const { document } = makeDom('<input id="a" type="email" placeholder="Email address"><input id="b" name="street_address"><input id="c" placeholder="Your address">');
  assert.ok(usernameScore($(document, '#a')) > 0);
  assert.equal(usernameScore($(document, '#b')), 0);
  assert.equal(usernameScore($(document, '#c')), 0);
});

test('identifier-first e-mail step: detected with sign-in wording, a username name or a sign-in path', () => {
  // sign-in wording in the form
  let r = detect(`<form><h1>Please sign in</h1><label for="inputEmail">Email address</label>${BS_EMAIL}<button type="submit">Next</button></form>`, { url: 'https://example.com/start' });
  assert.equal(r.groups[0]?.username, $(r.document, '#inputEmail'));
  // no wording, but name="username"
  r = detect(`<form><label for="inputEmail">Email address</label>${BS_EMAIL}<button type="submit">Continue</button></form>`, { url: 'https://example.com/start' });
  assert.equal(r.groups[0]?.username, $(r.document, '#inputEmail'));
  // nothing but a sign-in path
  r = detect('<form><label for="e">Email address</label><input type="email" id="e"><button>Continue</button></form>', { url: 'https://example.com/signin' });
  assert.equal(r.groups[0]?.username, $(r.document, '#e'));
  // a plain e-mail box elsewhere stays alone
  r = detect('<form><label for="e">Email address</label><input type="email" id="e"><button>Continue</button></form>', { url: 'https://example.com/contact' });
  assert.equal(r.groups.length, 0);
  // and a newsletter box on a sign-in page too
  r = detect('<form><p>Get our offers</p><input type="email" name="email" placeholder="Email address"><button>Subscribe</button></form>', { url: 'https://example.com/login' });
  assert.equal(r.groups.length, 0);
});
