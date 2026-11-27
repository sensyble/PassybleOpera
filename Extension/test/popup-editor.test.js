import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
const storageWrites = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

const ok = (result) => ({ ok: true, result });
const fail = (code, message = code) => ({ ok: false, error: { code, message } });

const ITEMS = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: true, has_passkey: false }];
const STATE = { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null, items: ITEMS, can_edit: true, can_scan: true };
const EDIT = {
  id: 'gh', title: 'GitHub', username: 'octo', password: 'hunter2', notes: 'old notes',
  urls: ['https://github.com'], has_passkey: false,
  totp: { issuer: 'GitHub', account: 'octo', digits: 6, period: 30, algorithm: 'SHA1', code: '123456', remaining_secs: 20 },
};

/** Default agent behaviour through the background; `overrides[type]` replaces one handler. */
function agent(overrides = {}) {
  return (msg) => {
    if (overrides[msg.type]) return overrides[msg.type](msg);
    switch (msg.type) {
      case 'popup.state': return ok(STATE);
      case 'popup.edit-get': return ok(EDIT);
      case 'popup.edit-save': return ok({ id: msg.id || 'new', title: 'GitHub' });
      case 'popup.totp': return ok({ id: 'gh', title: 'GitHub', code: '654321', period: 30, remaining_secs: 25 });
      default: return ok({});
    }
  };
}

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  messages.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, document: dom.window.document, $ };
}

const flush = async (n = 3) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const sent = (type) => messages.filter((m) => m.type === type);
/** Edit lives in the row's ⋯ menu: a stand-in button that opens the menu and picks Edit. */
const editButton = ($) => {
  const more = $('list').querySelector('button[title="More"]');
  return more && { click: () => { more.click(); more.ownerDocument.getElementById('row-edit').click(); } };
};
/** Picks `id` (ed-open, ed-delete) from the editor's ⋯ menu. */
const editorMenu = ($, id) => { $('ed-more').click(); return $(id); };

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: { query: async () => [{ id: 1, url: 'https://github.com/login' }] },
    storage: {
      local: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
      sync: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
    },
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

test('Edit opens the login; password hidden until shown; Save sends the fields and goes back', async () => {
  reply = agent();
  const { $, document } = await openPopup();
  assert.ok(editButton($), 'Edit per login');
  assert.equal($('add-login').hidden, false, 'Add login for this site');
  editButton($).click();
  await flush();
  assert.deepEqual(sent('popup.edit-get'), [{ type: 'popup.edit-get', tabId: 1, id: 'gh' }]);
  assert.equal($('view-edit').hidden, false);
  assert.equal($('gen'), null, 'no password generator in the popup');
  assert.equal($('edit-heading').textContent, 'Edit login');
  assert.equal($('ed-username').value, 'octo');
  assert.equal($('ed-password').value, 'hunter2');
  assert.equal($('ed-password').type, 'password');
  assert.equal($('ed-password').getAttribute('value'), null, 'never in the markup');
  $('ed-reveal').click();
  assert.equal($('ed-password').type, 'text');
  assert.equal($('ed-reveal').title, 'Hide password');
  assert.match($('ed-totp').textContent, /123 456/);

  $('ed-username').value = 'octocat';
  $('ed-password').value = 'new-secret';
  $('ed-notes').value = 'new notes';
  $('ed-url-add').click();
  const urlInputs = document.querySelectorAll('#ed-urls input');
  urlInputs[urlInputs.length - 1].value = 'gist.github.com';
  $('ed-save').click();
  await flush();
  const [save] = sent('popup.edit-save');
  assert.deepEqual(save, { type: 'popup.edit-save', tabId: 1, id: 'gh', fields: {
    title: 'GitHub', username: 'octocat', password: 'new-secret', notes: 'new notes',
    urls: ['https://github.com', 'gist.github.com'] } }, 'no totp key: 2FA unchanged');
  assert.equal($('view-list').hidden, false, 'back to the list');
  assert.equal(sent('popup.state').length, 2, 'list reloaded');
  assert.equal($('editor').childElementCount, 0, 'form gone');
  assert.equal(document.querySelector('#editor input'), null);
  assert.equal($('snack').textContent, 'Saved');
});

test('Add login: title and website from the tab; saved without an id', async () => {
  reply = agent({ 'popup.generate': () => fail('agent_unavailable', 'not running') });
  const { $ } = await openPopup();
  $('add-login').click();
  await flush();
  assert.equal($('view-edit').hidden, false);
  assert.equal($('edit-heading').textContent, 'Add login');
  assert.equal($('ed-title').value, 'github.com');
  assert.equal(sent('popup.edit-get').length, 0);
  assert.equal($('ed-more'), null, 'nothing to delete or open yet');
  $('ed-username').value = 'octo';
  $('ed-generate').click();
  await flush();
  assert.equal($('ed-password').value.length, 20, 'generated locally when the desktop app does not answer');
  assert.equal($('ed-password').type, 'text', 'shown after generating');
  $('ed-save').click();
  await flush();
  const [save] = sent('popup.edit-save');
  assert.equal(save.id, undefined);
  assert.deepEqual(save.fields.urls, ['https://github.com']);
  assert.equal(save.fields.username, 'octo');
});

test('More details: a new login shows Title, Website, Username, Password, 2FA and Notes; the toggle opens the rest', async () => {
  reply = agent();
  const { $, document } = await openPopup();
  $('add-login').click();
  await flush();
  const toggle = $('ed-details-toggle');
  assert.equal(toggle.tagName, 'BUTTON');
  assert.equal(toggle.type, 'button');
  assert.equal(toggle.getAttribute('aria-expanded'), 'false', 'closed for a new login');
  assert.equal(toggle.getAttribute('aria-controls'), 'ed-details');
  assert.equal(toggle.textContent, 'More details');
  assert.equal($('ed-details').hidden, true);
  assert.ok($('ed-details').contains($('ed-url-add')), 'Add website is what the toggle opens');
  const labels = [...document.querySelectorAll('#editor .ed-body > .ed-field > .ed-label')].map((l) => l.textContent);
  assert.deepEqual(labels, ['Title', 'Website', 'Username', 'Password', '2FA', 'Notes']);
  assert.ok(!$('ed-details').contains($('ed-notes')) && !$('ed-details').contains($('ed-totp')), '2FA and notes are not under More details');
  toggle.click();
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  assert.equal($('ed-details').hidden, false);
  assert.equal($('ed-url-add').hidden, false);
  assert.ok(!$('ed-vault'), 'one vault: no picker');
  $('ed-url-add').click();
  assert.equal($('ed-urls').children.length, 2);
  // Closed again: only the first website shows; the second is kept and saved.
  $('ed-urls').children[1].querySelector('input').value = 'https://gist.github.com';
  toggle.click();
  assert.equal($('ed-urls').children[1].hidden, true);
  $('ed-save').click();
  await flush();
  assert.deepEqual(sent('popup.edit-save')[0].fields.urls, ['https://github.com', 'https://gist.github.com']);
});

test('More details: a new login with several vaults also opens the vault choice, and the pick is where it is saved', async () => {
  reply = agent({
    'popup.state': () => ok({ ...STATE, can_move: true, can_vaults: true }),
    'popup.vaults': () => ok({ vaults: [{ id: 'home', name: 'Personal', home: true, open: true, can_edit: true },
      { id: 'eng', name: 'Engineering', home: false, open: true, can_edit: true }] }),
  });
  const { $ } = await openPopup();
  $('add-login').click();
  await flush();
  const toggle = $('ed-details-toggle');
  assert.equal($('ed-details').hidden, true);
  toggle.click();
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  assert.equal($('ed-details').hidden, false);
  assert.ok($('ed-details').contains($('ed-url-add')));
  assert.ok($('ed-details').contains($('ed-vault')), 'vault choice under More details');
  assert.equal($('ed-vault').value, 'home', 'the home vault is the default');
  $('ed-title').value = 'Work';
  $('ed-vault').value = 'eng';
  $('ed-save').click();
  await flush();
  $('ed-move-ok')?.click();
  await flush();
  assert.equal(sent('popup.edit-save')[0].vault, 'eng');
  assert.equal(sent('popup.edit-move').length, 0, 'a new login is created there, not moved');
});

test('More details: the toggle works from the keyboard and is never empty', async () => {
  reply = agent();
  const { $, document, window } = await openPopup();
  $('add-login').click();
  await flush();
  const toggle = $('ed-details-toggle');
  toggle.focus();
  assert.equal(document.activeElement, toggle);
  assert.equal(toggle.tagName, 'BUTTON', 'a real button: Enter and Space click it');
  toggle.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  assert.equal(toggle.getAttribute('aria-expanded'), 'true');
  assert.ok($('ed-details').children.length > 0 && !$('ed-details').hidden, 'something to see for any new login');
  toggle.click();
  assert.equal(toggle.getAttribute('aria-expanded'), 'false');
  assert.equal($('ed-details').hidden, true);
});

test('More details: open for a saved login that has a second website; closed with 2FA and notes alone', async () => {
  reply = agent();
  let { $ } = await openPopup();
  editButton($).click();
  await flush();
  assert.equal($('ed-details-toggle').getAttribute('aria-expanded'), 'false', 'notes and 2FA are up front: closed');
  assert.equal($('ed-details').hidden, true);
  assert.match($('ed-notes').value, /old notes/);
  assert.match($('ed-totp').textContent, /123 456/);

  reply = agent({ 'popup.edit-get': () => ok({ ...EDIT, urls: ['https://github.com', 'https://gist.github.com'] }) });
  ({ $ } = await openPopup());
  editButton($).click();
  await flush();
  assert.equal($('ed-details-toggle').getAttribute('aria-expanded'), 'true', 'a second website: open');
  assert.equal($('ed-details').hidden, false);
});

test('Generate: no answer in time from the desktop app generates here too, without an error', async () => {
  reply = agent({ 'popup.generate': () => fail('timeout', 'Passyble did not answer "generate" in time') });
  const { $ } = await openPopup();
  $('add-login').click();
  await flush();
  $('ed-generate').click();
  await flush();
  assert.equal($('ed-password').value.length, 20);
  assert.equal($('snack').textContent, '');
});

test('2FA: paste a secret (checked by the agent), saved with the login', async () => {
  reply = agent({
    'popup.edit-get': () => ok({ ...EDIT, totp: null }),
    'popup.totp-check': (m) => (m.totp === 'bad' ? fail('invalid_params', '2FA secret is not valid')
      : ok({ issuer: null, account: null, code: '111222', remaining_secs: 10 })),
  });
  const { $ } = await openPopup();
  editButton($).click();
  await flush();
  $('ed-totp-add').click();
  assert.ok($('ed-totp-scan'), 'Scan QR on this page');
  $('ed-totp-secret').value = 'bad';
  $('ed-totp-ok').click();
  await flush();
  assert.equal($('snack').textContent, "That 2FA secret isn't valid. Check it and try again.");
  $('ed-totp-secret').value = 'JBSW Y3DP EHPK 3PXP';
  $('ed-totp-ok').click();
  await flush();
  assert.match($('ed-totp').textContent, /111 222/);
  assert.match($('ed-totp').textContent, /saved on Save/);
  $('ed-save').click();
  await flush();
  assert.equal(sent('popup.edit-save')[0].fields.totp, 'JBSW Y3DP EHPK 3PXP');
});

test('2FA: Scan QR on this page asks the background to capture the tab', async () => {
  const link = 'otpauth://totp/GitHub:octo?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
  let scans = 0;
  reply = agent({
    'popup.edit-get': () => ok({ ...EDIT, totp: null }),
    'popup.totp-scan': () => (++scans === 1 ? fail('not_found', 'No 2FA QR code found on this page')
      : ok({ totp: link, issuer: 'GitHub', account: 'octo', code: '333444', remaining_secs: 9 })),
  });
  const { $ } = await openPopup();
  editButton($).click();
  await flush();
  $('ed-totp-add').click();
  $('ed-totp-scan').click();
  await flush();
  assert.deepEqual(sent('popup.totp-scan'), [{ type: 'popup.totp-scan', tabId: 1 }]);
  assert.equal($('snack').textContent, 'No 2FA QR code on this page.');
  $('ed-totp-scan').click();
  await flush();
  assert.match($('ed-totp').textContent, /GitHub · octo/);
  $('ed-save').click();
  await flush();
  assert.equal(sent('popup.edit-save')[0].fields.totp, link);
});

test('2FA: Scan QR errors from the background are translated, each with its own text', async () => {
  const errors = [
    ['cant_read_page', "Can't read this page", "Passyble can't read this page."],
    ['open_qr_page_first', 'Open the page with the QR code first', 'Open the page with the QR code first.'],
    ['page_too_large', 'The page is too large to scan', 'The page is too large to scan.'],
    ['not_found', 'whatever', 'No 2FA QR code on this page.'],
    ['invalid_params', 'Bad something', 'Something went wrong. Try again.'],
  ];
  let n = 0;
  reply = agent({
    'popup.edit-get': () => ok({ ...EDIT, totp: null }),
    'popup.totp-scan': () => fail(errors[n++][0], 'English text the person must not see'),
  });
  const { $ } = await openPopup();
  editButton($).click();
  await flush();
  $('ed-totp-add').click();
  for (const [code, , shown] of errors) {
    $('ed-totp-scan').click();
    await flush();
    assert.equal($('snack').textContent, shown, code);
  }
});

test('2FA: no Scan button when the desktop app cannot read QR codes; Remove sends totp: null', async () => {
  reply = agent({ 'popup.state': () => ok({ ...STATE, can_scan: false }) });
  const { $ } = await openPopup();
  editButton($).click();
  await flush();
  $('ed-totp').querySelector('button[title="Remove 2FA"]').click();
  assert.match($('ed-totp').textContent, /2FA removed on Save/);
  $('ed-totp-add').click();
  assert.equal($('ed-totp-scan'), null);
  $('ed-save').click();
  await flush();
  assert.equal(sent('popup.edit-save')[0].fields.totp, null);
});

test('Delete goes back to the list with an Undo that restores the login', async () => {
  reply = agent({ 'popup.edit-delete': () => ok({ undo_secs: 60 }), 'popup.edit-restore': () => ok({ id: 'gh' }) });
  const { $, document } = await openPopup();
  editButton($).click();
  await flush();
  editorMenu($, 'ed-delete').click();
  await flush();
  assert.equal(document.querySelector('.popover'), null, 'menu closed');
  assert.deepEqual(sent('popup.edit-delete'), [{ type: 'popup.edit-delete', tabId: 1, id: 'gh' }]);
  assert.equal($('view-list').hidden, false);
  assert.match($('snack').textContent, /^Deleted GitHub/);
  const undo = $('snack').querySelector('button');
  assert.equal(undo.textContent, 'Undo');
  undo.click();
  await flush();
  assert.deepEqual(sent('popup.edit-restore'), [{ type: 'popup.edit-restore', tabId: 1, id: 'gh' }]);
  assert.equal($('snack').textContent, 'Restored');
});

test('Open in Passyble asks the desktop app to show the login', async () => {
  reply = agent();
  const { $ } = await openPopup();
  editButton($).click();
  await flush();
  editorMenu($, 'ed-open').click();
  await flush();
  assert.deepEqual(sent('popup.show-item'), [{ type: 'popup.show-item', tabId: 1, id: 'gh' }]);
  assert.equal($('snack').textContent, 'Opened in Passyble');
});

test('older desktop app: "Update Passyble" instead of an editor', async () => {
  // It doesn't advertise editing: nothing is asked.
  reply = agent({ 'popup.state': () => ok({ ...STATE, can_edit: false }) });
  let popup = await openPopup();
  editButton(popup.$).click();
  await flush();
  assert.equal(sent('popup.edit-get').length, 0);
  assert.equal(popup.$('view-edit').hidden, true);
  assert.equal(popup.$('snack').textContent, 'Update Passyble to edit logins here.');
  // It answers not_supported.
  reply = agent({ 'popup.state': () => ok({ ...STATE, can_edit: undefined }),
    'popup.edit-get': () => fail('not_supported', 'This Passyble desktop app is too old to edit logins') });
  popup = await openPopup();
  editButton(popup.$).click();
  await flush();
  assert.equal(popup.$('view-edit').hidden, true);
  assert.equal(popup.$('snack').textContent, 'Update Passyble to edit logins here.');
});

test('errors keep the editor open; Esc and Back close it and clear the form', async () => {
  reply = agent({ 'popup.edit-save': () => fail('cancelled', 'user verification cancelled') });
  const { $, window, document } = await openPopup();
  editButton($).click();
  await flush();
  $('ed-save').click();
  await flush();
  assert.equal($('view-edit').hidden, false);
  assert.equal($('snack').textContent, 'Cancelled.');
  assert.equal($('ed-save').disabled, false);
  document.dispatchEvent(new window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  await flush();
  assert.equal($('view-list').hidden, false);
  assert.equal(document.querySelector('#editor input'), null);
  assert.equal(sent('popup.state').length, 1, 'nothing changed: no reload');

  editButton($).click();
  await flush();
  $('edit-back').click();
  assert.equal($('editor').childElementCount, 0);
});

test('closing the popup clears the form; nothing goes to extension storage', async () => {
  reply = agent();
  const { $, window } = await openPopup();
  editButton($).click();
  await flush();
  const password = $('ed-password');
  window.dispatchEvent(new window.Event('pagehide'));
  assert.equal(password.value, '');
  assert.equal($('editor').childElementCount, 0);
  // Only the first popup's marker for the browser's own autofill (no form data).
  assert.deepEqual(storageWrites.filter((w) => !('browserAutofillOff' in w)), []);
});

test('lookups of another site have no Edit (editing is bound to the tab)', async () => {
  reply = agent({ 'popup.find': () => ok({ items: [{ id: 'x', title: 'Example', username: 'a', has_totp: false, has_passkey: false }] }) });
  const { $ } = await openPopup();
  $('search').value = 'example.com';
  $('search').dispatchEvent(new globalThis.Event('input'));
  $('lookup').querySelector('button').click();
  await flush();
  assert.equal($('other-list').querySelectorAll('button[title="More"]').length, 0, 'no ⋯ menu: no Edit, no Open in Passyble');
  assert.equal($('other-list').querySelectorAll('button[title="Copy password"]').length, 1);
});

// Password check: live, debounced, codes only.

const issueTexts = ($) => [...$('ed-check').querySelectorAll('li')].map((li) => li.textContent);
const wait = (ms) => new Promise((r) => setTimeout(r, ms));
const typeInto = (input, value) => { input.value = value; input.dispatchEvent(new Event('input', { bubbles: true })); };

test('password check: on open, then again once typing pauses; stale answers are dropped; never asks to unlock', async () => {
  let answer = (msg) => ({ score: 0, label: 'very_weak', vault_checked: true, issues: [
    { code: 'weak', severity: 'high' }, { code: 'reused', severity: 'high', count: 1 }, { code: 'contains_username', severity: 'medium' }] });
  reply = agent({ 'popup.password-check': (msg) => ok(answer(msg)) });
  const { $ } = await openPopup();
  editButton($).click();
  await flush(6);
  const checks = () => sent('popup.password-check');
  assert.deepEqual(checks(), [{ type: 'popup.password-check', tabId: 1, password: 'hunter2', username: 'octo', title: 'GitHub', id: 'gh' }],
    'the edited login is named: its own password is not "reused"; no `inline`/unlock');
  assert.deepEqual(issueTexts($), ['This password is easy to guess.', 'You use this password for 1 other login.',
    'This password contains your username.']);
  assert.ok($('ed-use-strong'), 'the fix is offered');

  // Typing: one check after the pause, for the last value only.
  for (const v of ['a', 'ab', 'abc']) typeInto($('ed-password'), v);
  await wait(100);
  assert.equal(checks().length, 1, 'debounced');
  let release;
  const slow = new Promise((r) => { release = r; });
  answer = (msg) => (msg.password === 'abc' ? slow : { score: 4, label: 'strong', vault_checked: true, issues: [] });
  reply = agent({ 'popup.password-check': async (msg) => ok(await answer(msg)) });
  await wait(400);
  assert.equal(checks().length, 2);
  assert.equal(checks()[1].password, 'abc');
  // A newer value is checked while the older answer is still on its way.
  typeInto($('ed-password'), 'Xk9#mQ2!vLp7@wZ4');
  await wait(450);
  await flush();
  assert.match($('ed-check').textContent, /^Strong$/, 'no issues and a good score: a subtle "Strong"');
  release({ score: 0, label: 'very_weak', vault_checked: true, issues: [{ code: 'common', severity: 'high' }] });
  await flush();
  assert.match($('ed-check').textContent, /^Strong$/, 'the late answer for "abc" is dropped');

  typeInto($('ed-password'), '');
  await flush();
  assert.equal($('ed-check').childElementCount, 0, 'empty password: nothing');
  $('ed-cancel').click();
});

test('password check: "Use a strong password instead" fills a generated one and checks it; low-only hints get no fix', async () => {
  reply = agent({
    'popup.generate': () => ok({ password: 'Gen-Erated-Strong-Pass-20' }),
    'popup.password-check': (msg) => ok(msg.password === 'Gen-Erated-Strong-Pass-20'
      ? { score: 4, label: 'strong', vault_checked: true, issues: [] }
      : msg.password === 'Xk9#mQ2!vL'
        ? { score: 3, label: 'good', vault_checked: true, issues: [{ code: 'short', severity: 'low', min_length: 12 }] }
        : { score: 0, label: 'very_weak', vault_checked: true, issues: [{ code: 'common', severity: 'high' }] }),
  });
  const { $ } = await openPopup();
  editButton($).click();
  await flush(6);
  assert.deepEqual(issueTexts($), ['This is one of the most common passwords.']);
  $('ed-use-strong').click();
  await flush(6);
  assert.equal($('ed-password').value, 'Gen-Erated-Strong-Pass-20');
  assert.equal($('ed-password').type, 'text', 'shown after generating');
  assert.equal(sent('popup.password-check').at(-1).password, 'Gen-Erated-Strong-Pass-20');
  assert.match($('ed-check').textContent, /^Strong$/);

  typeInto($('ed-password'), 'Xk9#mQ2!vL');
  await wait(450);
  await flush();
  assert.deepEqual(issueTexts($), ['Short: use at least 12 characters.']);
  assert.equal($('ed-use-strong'), null, 'a low-severity hint only: no fix button');
  // Saving is never blocked.
  $('ed-save').click();
  await flush();
  assert.equal(sent('popup.edit-save').at(-1).fields.password, 'Xk9#mQ2!vL');
});

test('password check: an older desktop app (or an error) shows nothing', async () => {
  reply = agent({ 'popup.password-check': () => fail('agent_unavailable', 'not running') });
  const { $ } = await openPopup();
  editButton($).click();
  await flush(6);
  assert.equal(sent('popup.password-check').length, 1);
  assert.equal($('ed-check').childElementCount, 0);
  assert.equal($('snack').textContent, '', 'no error shown for it');
  $('ed-cancel').click();
});

const keydown = (window, target, init) => target.dispatchEvent(new window.KeyboardEvent('keydown', { bubbles: true, cancelable: true, ...init }));

/** chrome.storage.local backed by `store` for the length of `fn`. */
async function withStore(store, fn) {
  const realLocal = chrome.storage.local;
  chrome.storage.local = {
    get: async (keys) => Object.fromEntries([keys].flat().filter((k) => k in store).map((k) => [k, store[k]])),
    set: async (o) => { Object.assign(store, o); },
  };
  try { await fn(); } finally { chrome.storage.local = realLocal; }
}

const tick = (input, checked) => { input.checked = checked; input.dispatchEvent(new Event('change', { bubbles: true })); };
const until = async (ok, ms = 3000) => { for (const end = Date.now() + ms; !ok() && Date.now() < end;) await wait(10); };
const slide = (input, value) => { input.value = String(value); input.dispatchEvent(new Event('input', { bubbles: true })); };

test('generator: one click fills one with the saved options; the chevron opens them, every change fills a new one and is remembered', async () => {
  const store = { generateOptions: { mode: 'password', length: 24, lowercase: true, uppercase: true, digits: true, words: 6 } };
  await withStore(store, async () => {
    reply = agent({ 'popup.generate': (m) => ok({ password: m.symbols === false ? 'A'.repeat(m.length) : '#'.repeat(m.length) }) });
    const { $, document } = await openPopup();
    $('add-login').click();
    await flush();
    assert.equal($('ed-gen-panel').hidden, true);
    $('ed-generate').click();
    await flush(6);
    assert.deepEqual(sent('popup.generate').at(-1), { type: 'popup.generate', length: 24 }, 'the saved length');
    assert.equal($('ed-password').value, '#'.repeat(24));
    assert.equal($('ed-password').type, 'text', 'shown after generating');

    const toggle = $('ed-gen-toggle');
    toggle.click();
    await flush();
    assert.equal($('ed-gen-panel').hidden, false);
    assert.equal(toggle.getAttribute('aria-expanded'), 'true');
    assert.equal(document.activeElement, $('ed-gen-password'), 'the focus goes into the options');
    assert.equal($('ed-gen-length').value, '24');
    assert.equal(sent('popup.generate').length, 1, 'a password there already: opening keeps it');

    slide($('ed-gen-length'), 30);
    await flush(6);
    assert.equal($('ed-password').value, '#'.repeat(30), 'live');
    assert.equal(store.generateOptions.length, 30, 'remembered as the generator options');

    tick($('ed-gen-symbols'), false);
    await flush(6);
    assert.deepEqual(sent('popup.generate').at(-1), { type: 'popup.generate', length: 30, symbols: false });
    assert.equal($('ed-password').value, 'A'.repeat(30));
    assert.deepEqual(store.generateNoSymbols, ['github.com'], "special characters stay the site's choice");

    tick($('ed-gen-digits'), false);
    tick($('ed-gen-lowercase'), false);
    await flush(6);
    assert.match($('ed-password').value, /^[A-Z]{30}$/, 'upper case only: made here, not by the desktop app');
    assert.equal($('ed-gen-uppercase').disabled, true, 'the last type on stays on');
    assert.equal(sent('popup.generate').length, 3);
    const before = $('ed-password').value;
    $('ed-gen-regenerate').click();
    await flush(6);
    assert.notEqual($('ed-password').value, before, 'Regenerate: a new one, same options');
    assert.deepEqual({ ...store.generateOptions }, { mode: 'password', length: 30, lowercase: false, uppercase: true, digits: false, words: 6 });
    $('ed-cancel').click();
    await flush();

    // The next editor starts from what was remembered.
    $('add-login').click();
    await flush();
    $('ed-gen-toggle').click();
    await flush(6);
    assert.equal($('ed-gen-symbols').checked, false);
    assert.equal($('ed-gen-length').value, '30');
    assert.match($('ed-password').value, /^[A-Z]{30}$/, 'opened with no password: one is filled at once');
  });
});

test("generator: a passphrase with its word count, hyphens or none (the site's choice); made here", async () => {
  await withStore({}, async () => {
    reply = agent({ 'popup.generate': () => ok({ password: 'Gen-Erated-Strong-Pass-20' }) });
    const { $ } = await openPopup();
    editButton($).click();
    await flush();
    $('ed-gen-toggle').click();
    await flush();
    tick($('ed-gen-passphrase'), true);
    // The wordlist loads the first time (a dynamic import).
    await until(() => $('ed-password').value.split('-').length === 6);
    assert.equal($('ed-gen-length').closest('.ed-gen-part').hidden, true);
    assert.equal($('ed-gen-words').value, '6');
    assert.equal($('ed-password').value.split('-').length, 6);
    assert.match($('ed-password').value, /\d/, 'one digit');
    slide($('ed-gen-words'), 4);
    await flush(10);
    assert.equal($('ed-password').value.split('-').length, 4);
    tick($('ed-gen-hyphens'), false);
    await flush(10);
    assert.match($('ed-password').value, /^([A-Z][a-z]*\d?){4}$/, 'CamelCase without hyphens');
    assert.equal(sent('popup.generate').length, 0, 'a passphrase never comes from the desktop app');
    $('ed-cancel').click();
  });
});

test('generator: Esc closes the options first (the focus back on the chevron), then the editor; Ctrl+S waits', async () => {
  await withStore({}, async () => {
    reply = agent();
    const { $, document, window } = await openPopup();
    editButton($).click();
    await flush();
    $('ed-gen-toggle').click();
    await flush();
    keydown(window, document.activeElement, { key: 's', ctrlKey: true });
    await flush();
    assert.equal(sent('popup.edit-save').length, 0, 'not while the options are open');
    keydown(window, $('ed-gen-length'), { key: 'Escape' });
    assert.equal($('ed-gen-panel').hidden, true);
    assert.equal(document.activeElement, $('ed-gen-toggle'));
    assert.equal($('view-edit').hidden, false);
    keydown(window, document.activeElement, { key: 'Escape' });
    await flush();
    assert.equal($('view-list').hidden, false);
  });
});

// Websites as rows, each with its rule (url_rules).

const rows = (document) => [...document.querySelectorAll('#ed-urls .ed-url-row')];
const badgeOf = (row) => { const b = row.querySelector('.ed-badge'); return b.hidden ? '' : b.textContent; };

test('websites: each row has its rule (gear menu, badges, "Suggested" for shared hosting); Save sends url_rules', async () => {
  reply = agent({
    'popup.state': () => ok({ ...STATE, can_url_rules: true }),
    'popup.edit-get': () => ok({ ...EDIT, urls: ['https://github.com', 'https://gist.github.com'],
      url_rules: [{ url: 'https://gist.github.com', rule: 'host' }] }),
    'popup.rule-hint': (m) => ok({ suggested: m.url === 'alice.github.io' ? 'host' : null }),
  });
  const { $, document, window } = await openPopup();
  editButton($).click();
  await flush();
  assert.deepEqual(rows(document).map(badgeOf), ['', 'Same host']);

  const gear = rows(document)[0].querySelector('.ed-rule');
  assert.equal(gear.getAttribute('aria-haspopup'), 'menu');
  gear.click();
  await flush();
  assert.equal(document.activeElement.id, 'ed-rule-subdomains', 'the focus starts on the current rule');
  assert.equal($('ed-rule-subdomains').getAttribute('aria-checked'), 'true');
  assert.match($('ed-rule-subdomains').textContent, /This site and all its subdomains/);
  assert.doesNotMatch($('ed-rule-host').textContent, /Suggested/);
  $('ed-rule-never').click();
  assert.deepEqual(rows(document).map(badgeOf), ['Hidden', 'Same host']);
  assert.equal(document.activeElement, gear, 'the focus goes back to the gear');
  assert.equal(gear.getAttribute('aria-expanded'), 'false');

  $('ed-url-add').click();
  const added = rows(document)[2];
  assert.equal(added.dataset.rule, 'subdomains', 'a new row is Subdomains');
  added.querySelector('input').value = 'alice.github.io';
  added.querySelector('.ed-rule').click();
  await flush();
  assert.deepEqual(sent('popup.rule-hint').at(-1), { type: 'popup.rule-hint', url: 'alice.github.io' });
  assert.match($('ed-rule-host').textContent, /Same host only\s*Suggested/);
  assert.equal(added.dataset.rule, 'subdomains', 'only a suggestion');
  keydown(window, document.activeElement, { key: 'Escape' });
  assert.equal(document.querySelector('.popover'), null, 'Esc closes the menu first');
  assert.equal(document.activeElement, added.querySelector('.ed-rule'));
  assert.equal($('view-edit').hidden, false, 'the editor stays open');

  rows(document)[1].querySelector('button[title="Remove website"]').click();
  assert.equal(document.activeElement, rows(document)[1].querySelector('input'), 'the focus goes to the next row');
  $('ed-save').click();
  await flush();
  const { fields } = sent('popup.edit-save')[0];
  assert.deepEqual(fields.urls, ['https://github.com', 'alice.github.io']);
  assert.deepEqual(fields.url_rules, [{ url: 'https://github.com', rule: 'never' }],
    'every rule sent, the default left out; the removed website\'s rule goes with it');
});

test('websites: without url_rules from the desktop app, rows have no gear and Save sends no url_rules', async () => {
  reply = agent({ 'popup.edit-get': () => ok({ ...EDIT, url_rules: [{ url: 'https://github.com', rule: 'host' }] }) });
  const { $, document } = await openPopup();
  editButton($).click();
  await flush();
  assert.equal(document.querySelector('#ed-urls .ed-rule'), null);
  assert.deepEqual(rows(document).map(badgeOf), ['Same host'], 'what the login has still shows');
  $('ed-save').click();
  await flush();
  assert.equal('url_rules' in sent('popup.edit-save')[0].fields, false);
});

test('keys: Esc with the focus on the body closes the editor; Ctrl+S and Cmd+S save; an open menu takes them first', async () => {
  reply = agent({ 'popup.state': () => ok({ ...STATE, can_url_rules: true }) });
  const { $, document, window } = await openPopup();
  editButton($).click();
  await flush();
  document.activeElement.blur();
  assert.equal(document.activeElement, document.body);
  assert.equal(keydown(window, document.body, { key: 'Escape' }), false, 'handled');
  await flush();
  assert.equal($('view-list').hidden, false);
  assert.equal($('editor').childElementCount, 0);

  editButton($).click();
  await flush();
  rows(document)[0].querySelector('.ed-rule').click();
  await flush();
  keydown(window, document.activeElement, { key: 's', ctrlKey: true });
  await flush();
  assert.equal(sent('popup.edit-save').length, 0, 'not while a menu is open');
  assert.ok(document.querySelector('.popover'));
  keydown(window, document.activeElement, { key: 'Escape' });
  document.activeElement.blur();
  assert.equal(keydown(window, document.body, { key: 's', ctrlKey: true }), false, 'the browser\'s Save page is kept out');
  await flush();
  assert.equal(sent('popup.edit-save').length, 1);
  assert.equal($('view-list').hidden, false, 'saved and closed');

  editButton($).click();
  await flush();
  $('ed-notes').focus();
  keydown(window, $('ed-notes'), { key: 'S', metaKey: true });
  await flush();
  assert.equal(sent('popup.edit-save').length, 2, 'Cmd+S from a field');
});

// Popular sites for a new login (sites.suggest, sites.name_for).

const SITES = { net: [{ name: 'Netflix', domain: 'netflix.com' }, { name: 'Netlify', domain: 'netlify.com' }], gitl: [{ name: 'GitLab', domain: 'gitlab.com' }] };
const NAMES = { 'https://github.com': 'GitHub', 'https://gitlab.com': 'GitLab' };
const siteAgent = () => agent({
  'popup.state': () => ok({ ...STATE, can_sites: true }),
  'popup.site-suggest': (m) => ok({ sites: SITES[m.query] || [] }),
  'popup.site-name': (m) => ok({ name: NAMES[m.url] ?? null }),
});
const typeIn = (input, value) => { input.focus(); typeInto(input, value); };
const options = (list) => [...list.querySelectorAll('[role="option"]')].map((li) => li.textContent);

test('popular sites: a new login is named from its website; the Name lists popular sites, picking one fills it and an empty first website', async () => {
  reply = siteAgent();
  const { $, document, window } = await openPopup();
  $('add-login').click();
  await flush();
  assert.equal($('ed-title').value, 'GitHub', "the tab's site by its proper name");
  assert.deepEqual(sent('popup.site-name')[0], { type: 'popup.site-name', url: 'https://github.com' });

  const site = () => document.querySelector('#ed-urls .ed-url-row input');
  typeIn(site(), 'https://gitlab.com');
  await wait(200);
  assert.equal($('ed-title').value, 'GitLab', 'the Name follows the first website while it is the one given here');

  const title = $('ed-title');
  typeIn(title, 'net');
  await wait(200);
  const list = $('ed-title-sites');
  assert.equal(list.hidden, false);
  assert.equal(title.getAttribute('aria-expanded'), 'true');
  assert.deepEqual(options(list), ['NNetflixnetflix.com', 'NNetlifynetlify.com']);
  assert.deepEqual(sent('popup.site-suggest').at(-1), { type: 'popup.site-suggest', query: 'net' });
  keydown(window, title, { key: 'ArrowDown' });
  keydown(window, title, { key: 'ArrowDown' });
  assert.equal(title.getAttribute('aria-activedescendant'), 'ed-title-sites-1');
  keydown(window, title, { key: 'Enter' });
  assert.equal(title.value, 'Netlify');
  assert.equal(list.hidden, true);
  assert.equal(site().value, 'https://gitlab.com', 'a website already there stays');

  typeIn(site(), '');
  typeIn(title, 'net');
  await wait(200);
  list.querySelector('[role="option"]').click();
  assert.equal(title.value, 'Netflix');
  assert.equal(site().value, 'https://netflix.com', 'an empty first website gets the site');

  typeIn(site(), 'https://gitlab.com');
  await wait(200);
  assert.equal(title.value, 'Netflix', 'a Name the user chose stays');
  $('ed-save').click();
  await flush();
  assert.deepEqual(sent('popup.edit-save')[0].fields, { title: 'Netflix', username: '', password: '', notes: '', urls: ['https://gitlab.com'] });
});

test('popular sites: a website row suggests domains; Esc closes the list before the editor; Ctrl+S waits', async () => {
  reply = siteAgent();
  const { $, document, window } = await openPopup();
  $('add-login').click();
  await flush();
  $('ed-url-add').click();
  const input = document.querySelectorAll('#ed-urls .ed-url-row input')[1];
  typeIn(input, 'https://www.gitl');
  await wait(200);
  assert.deepEqual(sent('popup.site-suggest').at(-1).query, 'gitl', 'the host as typed');
  const list = document.getElementById(input.getAttribute('aria-controls'));
  assert.deepEqual(options(list), ['GGitLabgitlab.com']);
  keydown(window, input, { key: 's', ctrlKey: true });
  await flush();
  assert.equal(sent('popup.edit-save').length, 0, 'not while the list is open');
  keydown(window, input, { key: 'Escape' });
  assert.equal(list.hidden, true);
  assert.equal($('view-edit').hidden, false, 'the editor stays open');
  typeIn(input, 'https://www.gitl');
  await wait(200);
  keydown(window, input, { key: 'ArrowDown' });
  keydown(window, input, { key: 'Enter' });
  assert.equal(input.value, 'https://gitlab.com');
  assert.equal($('ed-title').value, 'GitHub', 'only the first website names the login');
  keydown(window, input, { key: 'Escape' });
  await flush();
  assert.equal($('view-list').hidden, false);
});

test('popular sites: not for a saved login, nor without sites.suggest', async () => {
  reply = siteAgent();
  let popup = await openPopup();
  editButton(popup.$).click();
  await flush();
  assert.equal(popup.$('ed-title').getAttribute('role'), null);
  assert.equal(popup.document.querySelector('.ed-sites'), null);
  reply = agent();
  popup = await openPopup();
  popup.$('add-login').click();
  await flush();
  assert.equal(popup.$('ed-title').value, 'github.com');
  assert.equal(popup.document.querySelector('.ed-sites'), null);
  assert.equal(sent('popup.site-name').length, 0);
});
