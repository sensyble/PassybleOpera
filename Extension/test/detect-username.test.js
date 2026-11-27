import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import { detectFields, isVisibleNoLayout, usernameScore, FieldKind } from '../src/content/detect.js';
import { fillLoginGroup, loginPasswordField } from '../src/content/fill.js';

const detect = (html, opts) => {
  const { document } = makeDom(html, opts);
  return { document, ...detectFields(document, { isVisible: isVisibleNoLayout }) };
};
const $ = (doc, sel) => doc.querySelector(sel);
const CREDS = { username: 'alice@example.com', password: 'hunter2' };

// A CMS editor: a "Publish" field, more fields, a post password at the bottom.
const CMS_EDITOR = `
  <form id="post" action="/admin/post">
    <h1>Edit post</h1>
    <label for="title">Title</label><input id="title" name="post_title">
    <label for="slug">Permalink</label><input id="slug" name="slug">
    <textarea name="content"></textarea>
    <div class="panel"><h2>Publish</h2>
      <label for="pub">Publish</label><input id="pub" name="publish" placeholder="Immediately">
      <select name="status"><option>Draft</option><option>Published</option></select>
      <label for="pw">Password</label><input id="pw" type="password" name="post_password">
      <button type="submit" name="save">Save draft</button><button type="submit" name="go">Publish</button>
    </div>
  </form>`;

test('CMS editor: no username on the Publish field; the post password fills alone and stays quiet', () => {
  const { document, groups, fields } = detect(CMS_EDITOR);
  assert.equal(groups.length, 1);
  const g = groups[0];
  assert.equal(g.username, null);
  for (const sel of ['#pub', '#title', '#slug']) assert.equal(fields.get($(document, sel)), undefined, sel);
  assert.equal(g.currentPassword, $(document, '#pw'));
  assert.equal(g.quiet, true);
  const r = fillLoginGroup(g, CREDS);
  assert.deepEqual(r, { username: false, password: true, otp: false });
  assert.equal($(document, '#pw').value, 'hunter2');
  assert.equal($(document, '#pub').value, '');
});

test('a small form with a Publish field and a password: never the username, whatever the markup', () => {
  for (const html of [
    '<form><label>Publish<input name="f1"></label><label>Password<input type="password" name="f2"></label><button>Save</button></form>',
    '<form><input name="publish_date"><input type="password" name="f2"></form>',
    '<form><input placeholder="Publish on"><input type="password"></form>',
    '<form><div>Publish</div><div><input id="f1"></div><div>Password</div><div><input type="password" id="f2"></div></form>',
    'Publish <input id="f1"> Password <input type="password" id="f2">',
    '<div class="sidebar"><span>Publish</span><input id="f1"><span>Password protected</span><input type="password" id="f2"></div>',
    '<form><input name="f1" aria-label="Veröffentlichen"><input type="password"></form>',
    '<form><input name="f1" placeholder="公開日時"><input type="password"></form>',
    '<form><input name="f1" placeholder="게시 날짜"><input type="password"></form>',
    '<form><input name="f1" placeholder="发布时间"><input type="password"></form>',
    '<form><input name="f1" placeholder="प्रकाशित करें"><input type="password"></form>',
    '<form><input name="f1" placeholder="Tanggal terbit"><input type="password"></form>',
    '<form><input name="f1" placeholder="Fecha de publicación"><input type="password"></form>',
    '<form><input name="f1" placeholder="Date de publication"><input type="password"></form>',
  ]) {
    const { document, groups } = detect(html);
    assert.equal(groups[0].username, null, html);
    assert.ok(groups[0].passwords.length, html);
    assert.notEqual($(document, 'input[type=password]'), null);
  }
});

test('negative words win over a login word, and over the position', () => {
  for (const attrs of [
    'name="login_date"', 'name="user_comment"', 'name="account_title"', 'name="email_subject"', 'placeholder="Search users"',
    'name="post_slug"', 'name="tags"', 'name="category"', 'name="url"', 'placeholder="Website"', 'name="price"',
    'name="quantity"', 'name="company_name"', 'name="first_name"', 'name="promo_code"', 'name="time"',
    'autocomplete="organization"', 'autocomplete="cc-name"', 'autocomplete="address-line1"', 'autocomplete="one-time-code"',
    'list="suggestions"', 'role="combobox"',
  ]) {
    const { document, groups, fields } = detect(`<form><input id="x" ${attrs}><input type="password"><button>Go</button></form>`);
    assert.notEqual(groups[0].username, $(document, '#x'), attrs);
    assert.notEqual(fields.get($(document, '#x'))?.kind, FieldKind.USERNAME, attrs);
  }
});

test('autocomplete=off is no evidence against a username', () => {
  const { document, groups } = detect('<form><input id="x" name="username" autocomplete="off"><input type="password" autocomplete="off"></form>');
  assert.equal(groups[0].username, $(document, '#x'));
});

test('the unlabelled classic login form still works', () => {
  for (const html of [
    '<form><input id="x" name="f1"><input type="password" name="f2"><button>Sign in</button></form>',
    '<form><input id="x"><input type="password"><input type="submit" value="Go"></form>',
    '<form><input id="x" type="text"><input type="password"><label><input type="checkbox"> Keep me</label><button>OK</button></form>',
    '<form><input id="x" type="tel"><input type="password"><button>Entrar</button></form>',
    '<div class="box"><input id="x"><input type="password"><div role="button">Log in</div></div>',
    '<form><table><tr><td><input id="x" name="a"></td></tr><tr><td><input type="password" name="b"></td></tr></table><button>Login</button></form>',
    // labels in a language without a word list
    '<form><label for="x">ชื่อผู้ใช้</label><input id="x"><label for="p">รหัสผ่าน</label><input id="p" type="password"><button>ตกลง</button></form>',
    // a whole-page form (ASP.NET style) with a search box in the header and a login box inside it
    `<form><header><input name="q" placeholder="Search"></header><main><div class="login"><input id="x" name="a1"><input type="password" name="a2"><button>Log in</button></div></main>
       <footer><input name="newsletter" placeholder="Newsletter"></footer></form>`,
  ]) {
    const { document, groups } = detect(html);
    const g = groups.find((x) => x.passwords.length);
    assert.equal(g.username, $(document, '#x'), html);
    assert.equal(g.quiet, false, html);
  }
});

test('the unlabelled rule stays narrow: a second field, a select or a text area, or other wording', () => {
  for (const html of [
    '<form><input name="a"><input name="b"><input type="password"><button>Go</button></form>',
    '<form><select name="s"><option>1</option></select><input name="a"><input type="password"><button>Sign in</button></form>',
    '<form><input name="a"><textarea></textarea><input type="password"><button>Sign in</button></form>',
    '<form><input name="a"><div contenteditable="true"></div><input type="password"><button>Sign in</button></form>',
    '<form><input name="a"><input type="date" name="d"><input type="password"><button>Sign in</button></form>',
    '<form><input name="a"><input type="password"><button>Save</button></form>',
    '<form><input name="a"><input type="password"><button>Publish</button></form>',
    '<form><input name="a"><input type="password"><button>Speichern</button></form>',
    '<form><input name="a"><input type="password"><input type="password"><button>OK</button></form>',
    // a small pair inside a busy form with no sign-in wording
    '<form><input name="t"><input name="u"><select name="s"><option>1</option></select><div><input name="a"><input type="password"></div><button>Go</button></form>',
    // a bare "name" needs sign-in wording
    '<form><input name="name"><input type="password"><button>Go</button></form>',
    // a date picker
    '<form><input name="a" aria-autocomplete="list"><input type="password"><button>Sign in</button></form>',
    // many buttons, nothing about signing in
    `<form><input name="a"><input type="password">${'<button type="button">x</button>'.repeat(7)}</form>`,
  ]) {
    const { groups } = detect(html);
    assert.equal(groups.find((x) => x.passwords.length).username, null, html);
  }
  // a bare "name" under sign-in wording is the username (old forms use it)
  const { document, groups } = detect('<form><input id="x" name="name"><input type="password"><button>Log in</button></form>');
  assert.equal(groups[0].username, $(document, '#x'));
});

test('username + password forms: every kind of evidence', () => {
  for (const attrs of [
    'name="login"', 'name="username"', 'name="user"', 'id="userName"', 'type="email"', 'name="email"', 'name="e-mail"',
    'autocomplete="username"', 'autocomplete="email"', 'autocomplete="username webauthn"', 'name="phone"', 'type="tel" name="mobile"',
    'name="member_id"', 'name="customer_id"', 'name="account"', 'name="id"', 'placeholder="Email or phone"',
    'aria-label="Phone number, username, or email"', 'name="loginfmt"', 'name="session_key" id="username"', 'name="f1" placeholder="Email address"',
    'placeholder="Company email"', 'placeholder="Domain\\Username"',
    // the app's languages
    'placeholder="Benutzername"', 'placeholder="E-Mail-Adresse"', 'placeholder="Nom d\'utilisateur"', 'placeholder="Adresse e-mail"',
    'placeholder="Nombre de usuario"', 'placeholder="Correo electrónico"', 'placeholder="उपयोगकर्ता नाम"', 'placeholder="ईमेल पता"',
    'placeholder="Nama pengguna"', 'placeholder="Alamat surel"', 'placeholder="ユーザー名"', 'placeholder="メールアドレス"',
    'placeholder="아이디"', 'placeholder="이메일 주소"', 'placeholder="사용자 이름"', 'placeholder="用户名"', 'placeholder="电子邮件地址"', 'placeholder="账号"',
  ]) {
    // Other fields around it, so only evidence can make it the username.
    const { document, groups } = detect(`<form><input name="other"><input class="x" ${attrs}><input type="password" name="p"><button>Go</button></form>`);
    assert.equal(groups[0].username, $(document, '.x'), attrs);
    assert.ok(usernameScore($(document, '.x')) > 0, attrs);
  }
});

test('an id that merely holds "id" is no evidence; a login form\'s own words are', () => {
  const { document } = makeDom('<input id="a" data-testid="field-id-3"><input id="post-id"><input id="b" name="id"><input id="c" placeholder="ID">');
  assert.equal(usernameScore($(document, '#a')), 0);
  assert.equal(usernameScore($(document, '#post-id')), 0);
  assert.ok(usernameScore($(document, '#b')) > 0);
  assert.ok(usernameScore($(document, '#c')) > 0);
});

test('multi-step sign-in: the username page, then the password page', () => {
  let r = detect('<form><h1>Sign in</h1><input id="u" type="email" name="identifier" autocomplete="username webauthn"><button>Next</button></form>');
  assert.equal(r.groups[0].username, $(r.document, '#u'));
  assert.equal(r.groups[0].quiet, false);
  r = detect('<form><h1>Welcome back</h1><p>alice@example.com</p><input id="p" type="password" name="Passwd" autocomplete="current-password"><button>Next</button></form>');
  assert.equal(r.groups[0].username, null);
  assert.equal(r.groups[0].currentPassword, $(r.document, '#p'));
  assert.equal(r.groups[0].quiet, false);
  const res = fillLoginGroup(r.groups[0], CREDS);
  assert.deepEqual(res, { username: false, password: true, otp: false });
  // a plain password step, with nothing named
  r = detect('<form><input id="p" type="password"><button>Continue</button></form>');
  assert.equal(r.groups[0].quiet, false);
  // a username shown read-only on the password step isn't filled
  r = detect('<form><input id="u" name="username" value="me" readonly><input id="p" type="password"><button>Sign in</button></form>');
  assert.equal(r.groups[0].username, null);
  assert.equal(fillLoginGroup(r.groups[0], CREDS).password, true);
  assert.equal($(r.document, '#u').value, 'me');
});

test('password-only re-authentication page: fills the password, the menu may open', () => {
  const { document, groups, fields } = detect(`
    <form action="/sudo"><h2>Confirm access</h2><p>Signed in as alice</p><label for="p">Password</label><input id="p" type="password" name="sudo_password">
      <button>Confirm</button></form>`);
  assert.equal(groups[0].username, null);
  assert.equal(groups[0].quiet, false);
  assert.equal(fields.get($(document, '#p')).kind, FieldKind.CURRENT_PASSWORD);
  assert.deepEqual(fillLoginGroup(groups[0], CREDS), { username: false, password: true, otp: false });
});

test('sign-up forms keep their username and new-password fields, also among many fields', () => {
  const { document, groups } = detect(`
    <form><h1>Create your account</h1>
      <input name="first_name" placeholder="First name"><input name="last_name" placeholder="Last name">
      <input name="company" placeholder="Company"><input name="phone" placeholder="Phone">
      <input type="email" id="e" name="email" placeholder="Email address"><select name="country"><option>IN</option></select>
      <textarea name="about"></textarea>
      <input type="password" id="p1" name="password" autocomplete="new-password"><input type="password" id="p2" name="password2">
      <button>Sign up</button></form>`);
  const g = groups[0];
  assert.equal(g.username, $(document, '#e'));
  assert.deepEqual(g.newPasswords, [$(document, '#p1'), $(document, '#p2')]);
  assert.equal(g.quiet, false);
  assert.equal(loginPasswordField(g), null, 'a stored password never goes into a new-password field');
});

test('an unlabelled sign-up: the field before a password and its confirmation', () => {
  const { document, groups } = detect('<form><input id="x" name="a"><input type="password"><input type="password"><button>Register</button></form>');
  assert.equal(groups[0].username, $(document, '#x'));
  assert.equal(groups[0].newPasswords.length, 2);
});

test('change-password form: the generator stays, nothing else is a username', () => {
  const { document, groups } = detect(`
    <form><label for="o">Current password</label><input id="o" type="password" autocomplete="current-password">
      <label for="n">New password</label><input id="n" type="password" autocomplete="new-password">
      <label for="c">Confirm new password</label><input id="c" type="password"><button>Update password</button></form>`);
  const g = groups[0];
  assert.equal(g.username, null);
  assert.equal(g.quiet, false);
  assert.equal(g.currentPassword, $(document, '#o'));
  assert.equal(g.newPasswords.length, 2);
});

test('settings page with many fields and a current-password field: no username, the password fills alone', () => {
  const { document, groups, fields } = detect(`
    <form><h1>Profile settings</h1>
      <input name="name" placeholder="Name"><input type="email" id="e" name="email" placeholder="Email">
      <input name="phone" placeholder="Phone"><input name="website" placeholder="Website"><input name="location" placeholder="Location">
      <textarea name="bio"></textarea>
      <label for="p">Current password</label><input id="p" type="password" name="current_password">
      <button>Save changes</button></form>`);
  const g = groups[0];
  assert.equal(g.username, null);
  assert.equal(fields.get($(document, '#e')), undefined);
  assert.equal(g.currentPassword, $(document, '#p'));
  assert.equal(g.quiet, false, 'it says "current password"');
  assert.deepEqual(fillLoginGroup(g, CREDS), { username: false, password: true, otp: false });
});

test('admin form with many fields and a plain password: quiet, unless it says sign in', () => {
  let r = detect(`<form><input name="host" placeholder="Host"><input name="port"><input name="db"><input name="user2" type="number">
    <input type="password" name="pw"><button>Save</button></form>`);
  assert.equal(r.groups[0].username, null);
  assert.equal(r.groups[0].quiet, true);
  // a real sign-in with a few more fields keeps its username
  r = detect(`<form><h1>Sign in</h1><select name="region"><option>EU</option></select><input name="tenant" placeholder="Tenant"><input name="org" placeholder="Organisation">
    <input id="u" name="username"><input type="password" name="pw"><button>Sign in</button></form>`);
  assert.equal(r.groups[0].username, $(r.document, '#u'));
  assert.equal(r.groups[0].quiet, false);
});

test('GitHub-style and Google-style forms', () => {
  let r = detect(`<form action="/session"><label for="login_field">Username or email address</label>
    <input id="login_field" name="login" type="text" autocomplete="username webauthn" autofocus>
    <label for="password">Password</label><input id="password" name="password" type="password" autocomplete="current-password">
    <input type="submit" name="commit" value="Sign in"></form>`, { url: 'https://github.com/login' });
  assert.equal(r.groups[0].username, $(r.document, '#login_field'));
  assert.equal(r.groups[0].currentPassword, $(r.document, '#password'));
  r = detect(`<form><input type="email" id="identifierId" name="identifier" autocomplete="username webauthn" aria-label="Email or phone">
    <button type="button">Forgot email?</button><button type="button">Next</button></form>`, { url: 'https://accounts.google.com/signin' });
  assert.equal(r.groups[0].username, $(r.document, '#identifierId'));
  r = detect(`<form><input type="password" name="Passwd" autocomplete="current-password" aria-label="Enter your password">
    <label><input type="checkbox"> Show password</label><button type="button">Forgot password?</button><button type="button">Next</button></form>`, { url: 'https://accounts.google.com/signin/challenge' });
  assert.equal(r.groups[0].quiet, false);
  // Microsoft, LinkedIn, Facebook, Amazon
  for (const [user, attrs] of [
    ['x', 'type="email" name="loginfmt" placeholder="Email, phone, or Skype"'],
    ['x', 'name="session_key" id="username" aria-label="Email or phone"'],
    ['x', 'name="email" placeholder="Email address or phone number" type="text"'],
    ['x', 'type="email" name="email" id="ap_email"'],
  ]) {
    r = detect(`<form><input id="${user}" ${attrs}><input type="password" name="pass"><button>Log in</button></form>`);
    assert.equal(r.groups[0].username, $(r.document, `#${user}`), attrs);
  }
});

test('a password field on a search-heavy page: the search and filter boxes are never the username', () => {
  // in its own form
  let r = detect(`<header><form role="search"><input name="q" placeholder="Search"></form></header>
    <aside><input name="min_price" placeholder="Min price"><input name="max_price"><input name="brand" placeholder="Brand"></aside>
    <form><h2>Enter the password</h2><input id="p" type="password"><button>Continue</button></form>`);
  let g = r.groups.find((x) => x.passwords.length);
  assert.equal(g.username, null);
  assert.equal(g.quiet, false);
  // all form-less: one group for the page, nothing there says sign-in
  r = detect(`<header><input name="q" placeholder="Search"></header>
    <aside><input name="min_price" placeholder="Min price"><input name="max_price" placeholder="Max price"><input id="b" name="brand"></aside>
    <main><p>Results</p><input id="p" type="password"></main>`);
  g = r.groups[0];
  assert.equal(g.username, null);
  assert.equal(r.fields.get($(r.document, '#b')), undefined);
  assert.equal(g.quiet, true);
});

test('form-less fields far apart are not one login', () => {
  const lorem = 'Lorem ipsum dolor sit amet. '.repeat(100);
  const { document, groups, fields } = detect(`<div><input id="e" type="email" name="email"><button>Notify me</button></div><article>${lorem}</article><div><input type="password" id="p"></div>`);
  assert.equal(groups[0].username, null);
  assert.equal(fields.get($(document, '#e')), undefined);
});

test('passwords that protect a post, a page or a file: quiet, with or without a form around', () => {
  for (const html of [
    '<form><label for="p">Password protect this post</label><input id="p" type="password"></form>',
    '<form action="/wp-login.php?action=postpass"><p>This content is password protected. To view it please enter your password below:</p><label>Password: <input name="post_password" id="p" type="password"></label><input type="submit" value="Enter"></form>',
    '<div><h3>Visibility</h3><label><input type="radio" name="v"> Password protected</label><input id="p" type="password" placeholder="Use a secure password"></div>',
    '<form><input id="p" type="password" name="page_password"><button>OK</button></form>',
    '<form><input id="p" type="password" placeholder="PDF password"><button>Open</button></form>',
    '<form><input id="p" type="password" autocomplete="new-password" name="share_password"><button>Create link</button></form>',
    '<form><input id="p" type="password" placeholder="Beitrag schützen"></form>',
    '<form><input id="p" type="password" placeholder="パスワード保護"></form>',
  ]) {
    const { groups } = detect(html);
    assert.equal(groups[0].quiet, true, html);
    assert.equal(groups[0].username, null, html);
  }
  // an account's words win
  for (const html of [
    '<form><input id="p" type="password" name="login-page-password"></form>',
    '<form><label for="p">Password (case sensitive, see the note below)</label><input id="p" type="password"><button>Continue</button></form>',
    '<form><input id="p" type="password" name="page_password"><button>Log in</button></form>',
    '<form><p>Your account is protected.</p><input type="email" name="email"><input id="p" type="password"><button>Sign in</button></form>',
    '<form><p>Protect this post</p><input id="p" type="password"><button>Log in</button></form>',
  ]) {
    assert.equal(detect(html).groups[0].quiet, false, html);
  }
});

test('2FA and card detection are unchanged next to all this', () => {
  let r = detect('<form><input name="username" id="u"><input type="password"><input name="otp" autocomplete="one-time-code" id="o"></form>');
  assert.equal(r.groups[0].username, $(r.document, '#u'));
  assert.equal(r.groups[0].otp.fields[0], $(r.document, '#o'));
  // the unlabelled form with a code field in it
  r = detect('<form><input id="u"><input type="password"><input name="otp" id="o"><button>Log in</button></form>');
  assert.equal(r.groups[0].username, $(r.document, '#u'));
  assert.equal(r.groups[0].otp.fields[0], $(r.document, '#o'));
  // a card form's security code (type=password) is no password, and the name on the card no username
  r = detect('<form><input name="cc_name" placeholder="Name on card"><input name="cardnumber" autocomplete="cc-number"><input type="password" name="cvv" placeholder="CVV"><button>Pay</button></form>');
  assert.equal(r.groups.length, 0);
});

test('inputs in shadow roots: the box is found across them', () => {
  const { document } = makeDom('<form><a-field id="a"></a-field><a-field id="b"></a-field><button>Log in</button></form>');
  const a = document.getElementById('a').attachShadow({ mode: 'open' });
  a.innerHTML = '<input id="x" name="f1">';
  const b = document.getElementById('b').attachShadow({ mode: 'open' });
  b.innerHTML = '<input type="password">';
  const { groups } = detectFields(document, { isVisible: isVisibleNoLayout });
  assert.equal(groups[0].username, a.getElementById('x'));
});

test('a recaptcha response text area does not make a login form busy', () => {
  const { document, groups } = detect('<form><input id="x" name="a"><input type="password"><textarea name="g-recaptcha-response" id="g-recaptcha-response"></textarea><button>Sign in</button></form>');
  assert.equal(groups[0].username, $(document, '#x'));
});
