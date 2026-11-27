// The popup's quick actions (real popup.html + popup.js + quick-actions.js in jsdom, a fake BarcodeDetector over a
// fake screenshot): nothing stays behind or goes anywhere it shouldn't. Demo data only.
import { test, before, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
const storageWrites = [];
const captures = [];
const clipboard = [];
let reply = () => ({ ok: true, result: null });
let qrTexts = [];
let captureFails = false;
let instance = 0;

const ok = (result) => ({ ok: true, result });
const fail = (code, message = code) => ({ ok: false, error: { code, message } });
const LINK = 'otpauth://totp/GitHub:octo%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
const SHOT = 'data:image/png;base64,iVBORw0KGgo=';

const ITEMS = [{ id: 'gh', title: 'GitHub', username: 'octo', has_totp: false, has_passkey: false }];
const STATE = { url: 'https://github.com/login', supported: true, locked: false, pending_otp: null, items: ITEMS,
  can_edit: true, can_notes: true, can_search: true };

function agent(overrides = {}, state = STATE) {
  return (msg) => {
    if (overrides[msg.type]) return overrides[msg.type](msg);
    switch (msg.type) {
      case 'popup.state': return ok(state);
      case 'popup.totp-attach': return ok({ id: msg.id, title: 'GitHub', has_totp: true });
      case 'popup.edit-save': return ok({ id: 'new', title: msg.fields?.title || 'github.com' });
      case 'popup.note-create': return ok({ id: 'n1', title: msg.fields.title });
      case 'popup.generate': return ok({ password: 'Generated-Pw-123!' });
      case 'popup.generate-copy': return ok({ copied: true });
      case 'popup.totp': return ok({ id: msg.id, title: 'GitHub', code: '123456', period: 30, remaining_secs: 20 });
      case 'clipboard.copied': return ok({ scheduled: true });
      default: return ok({});
    }
  };
}

async function openPopup() {
  const html = readFileSync(new URL('../src/popup/popup.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  Object.defineProperty(globalThis, 'navigator', {
    value: { clipboard: { writeText: async (t) => { clipboard.push(t); } } }, configurable: true,
  });
  globalThis.window = { close: () => {} };
  messages.length = 0;
  captures.length = 0;
  clipboard.length = 0;
  await import(`../src/popup/popup.js?instance=${++instance}`);
  await flush();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, document: dom.window.document, $ };
}

const flush = async (n = 12) => { for (let i = 0; i < n; i++) await new Promise((r) => setTimeout(r, 0)); };
const sent = (type) => messages.filter((m) => m.type === type);
const visible = (node) => { for (let n = node; n; n = n.parentElement) if (n.hidden) return false; return true; };

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      openOptionsPage: () => {},
    },
    tabs: {
      query: async () => [{ id: 1, windowId: 7, url: 'https://github.com/login' }],
      captureVisibleTab: async (windowId, opts) => {
        captures.push([windowId, opts]);
        if (captureFails) throw new Error('Cannot access contents of the page');
        return SHOT;
      },
    },
    storage: {
      local: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
      sync: { get: async () => ({}), set: async (o) => { storageWrites.push(o); } },
    },
  };
  // The screenshot's QR codes, as the browser's BarcodeDetector reads them (qrTexts).
  globalThis.createImageBitmap = async (blob) => ({ width: 1280, height: 720, blob, close() {} });
  globalThis.BarcodeDetector = class {
    static async getSupportedFormats() { return ['qr_code']; }
    async detect() { return qrTexts.map((rawValue) => ({ rawValue })); }
  };
  const realSetInterval = globalThis.setInterval;
  globalThis.setInterval = (fn, ms) => { const t = realSetInterval(fn, ms); t.unref?.(); return t; };
});

/** On the list the quick actions are in the More menu: opens it and picks entry `id`. */
function fromMenu($, id) {
  $('menu-btn').click();
  $(id).click();
}

afterEach(() => {
  qrTexts = [];
  captureFails = false;
});

test('on the list: Scan QR, New note and Generate are in the More menu, no row of buttons over the list', async () => {
  reply = agent();
  const { $, document } = await openPopup();
  assert.equal(visible($('qa-row')), false, 'no row on the list');
  $('menu-btn').click();
  const items = [...document.querySelectorAll('.popover .menu-item')];
  assert.deepEqual(items.slice(0, 3).map((b) => b.id), ['menu-scan', 'menu-note', 'menu-generate']);
  assert.deepEqual(items.slice(0, 3).map((b) => b.querySelector('svg').getAttribute('data-icon')), ['qr', 'note', 'dice']);
  assert.match($('menu-scan').textContent, /^Scan QR/);
  assert.match($('menu-scan').textContent, /Add the 2FA QR code shown on this page/);
  assert.equal($('menu-note').textContent, 'New note');
  assert.equal($('menu-generate').textContent, 'Generate a strong password');
  assert.equal(items[3].id, 'options', 'then the usual entries');
  $('menu-btn').click();

  // A desktop app without notes.create: no New note; without editing: no Scan QR.
  reply = agent({}, { ...STATE, can_notes: false, can_edit: false });
  const older = await openPopup();
  older.$('menu-btn').click();
  assert.equal(older.$('menu-note'), null);
  assert.equal(older.$('menu-scan'), null);
  assert.ok(older.$('menu-generate'));
  older.$('menu-btn').click();

  // A page Passyble can't fill: no quick actions at all.
  reply = agent({ 'popup.state': () => ok({ url: 'chrome://newtab/', supported: false }) });
  const none = await openPopup();
  assert.equal(visible(none.$('qa-row')), false);
  none.$('menu-btn').click();
  assert.equal(none.$('menu-generate'), null);
});

test('Scan QR without a QR code in view: the clear message; one screenshot, read in the popup, sent nowhere', async () => {
  reply = agent();
  const { $ } = await openPopup();
  qrTexts = [];
  fromMenu($, 'menu-scan');
  await flush();
  assert.deepEqual(captures, [[7, { format: 'png' }]]);
  assert.equal($('snack').textContent, 'No QR code visible on this page. Scroll it into view and try again.');
  assert.equal($('view-list').hidden, false);
  assert.ok(!messages.some((m) => JSON.stringify(m).includes('data:image')), 'the image never goes to the background');

  // Not an authenticator code; a Google Authenticator export; HOTP; a page the browser won't capture.
  for (const [texts, text] of [
    [['https://example.com/'], "This QR code isn't for an authenticator app."],
    [['otpauth-migration://offline?data=CjEK'], 'This QR code is a Google Authenticator export. Import it in the Passyble app.'],
    [['otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP'], "This QR code is for counter-based codes (HOTP), which Passyble doesn't support."],
  ]) {
    qrTexts = texts;
    fromMenu($, 'menu-scan');
    await flush();
    assert.equal($('snack').textContent, text);
  }
  captureFails = true;
  fromMenu($, 'menu-scan');
  await flush();
  assert.equal($('snack').textContent, "Passyble can't read this page.");
  assert.equal(sent('popup.totp-attach').length + sent('popup.edit-save').length, 0);
});

test('Scan QR with the site\'s only login: chosen at once; Add 2FA attaches the code there and says so', async () => {
  reply = agent();
  const { $, document } = await openPopup();
  qrTexts = ['https://example.com/other', LINK];
  fromMenu($, 'menu-scan');
  await flush();
  assert.equal($('view-qa').hidden, false);
  assert.equal($('qa-heading').textContent, 'Add 2FA code');
  assert.equal($('qa-found-title').textContent, 'GitHub');
  assert.equal($('qa-found-account').textContent, 'octo@example.com');
  const radios = [...document.querySelectorAll('input[name="qa-target"]')];
  assert.equal(radios.length, 2, 'the login and "New login for github.com"');
  assert.equal(radios[0].checked, true, 'the only login is chosen');
  assert.match(document.querySelector('.qa-options').textContent, /New login for github\.com/);
  assert.equal($('qa-save').disabled, false);
  $('qa-save').click();
  await flush();
  assert.deepEqual(sent('popup.totp-attach'), [{ type: 'popup.totp-attach', tabId: 1, id: 'gh', totp: LINK }]);
  assert.equal($('snack').textContent, '2FA code added to GitHub');
  assert.equal($('view-list').hidden, false, 'back to the list');
  assert.equal(sent('popup.state').length, 2, 'the list is loaded again');
  assert.equal($('qa-body').childElementCount, 0, 'nothing of the code stays');
  assert.ok(!JSON.stringify(storageWrites).includes('JBSWY3DP'), 'never in extension storage');
});

test('Scan QR with several logins: the one with the code\'s account first and chosen (replacing its code); none: pick, or a new login', async () => {
  const items = [
    { id: 'a', title: 'GitHub', username: 'ada', has_totp: false },
    { id: 'b', title: 'GitHub work', username: 'octo@example.com', has_totp: true },
  ];
  reply = agent({}, { ...STATE, items });
  const { $, document } = await openPopup();
  qrTexts = [LINK];
  fromMenu($, 'menu-scan');
  await flush();
  const radios = () => [...document.querySelectorAll('input[name="qa-target"]')];
  assert.deepEqual(radios().map((r) => r.value).slice(0, 2), ['b', 'a']);
  assert.equal(radios()[0].checked, true);
  assert.equal($('qa-hint').textContent, 'Its current 2FA code will be replaced.');
  assert.match(radios()[0].closest('label').textContent, /Has 2FA/);
  // A new login instead: the issuer as its title, the account as its username.
  const fresh = radios().at(-1);
  fresh.checked = true;
  fresh.dispatchEvent(new Event('change'));
  assert.equal($('qa-hint').textContent, '');
  $('qa-save').click();
  await flush();
  assert.deepEqual(sent('popup.edit-save'), [{ type: 'popup.edit-save', tabId: 1, fields: { title: 'GitHub', username: 'octo@example.com', totp: LINK } }]);
  assert.equal($('snack').textContent, 'Saved as a new login: GitHub');

  // No login with that account: nothing chosen, Add 2FA waits for a pick.
  reply = agent({}, { ...STATE, items: [items[0], { ...items[1], username: 'grace' }] });
  const again = await openPopup();
  qrTexts = [LINK];
  fromMenu(again.$, 'menu-scan');
  await flush();
  assert.equal(again.$('qa-save').disabled, true);
  assert.equal(again.$('qa-hint').textContent, 'Choose the login to add it to.');
  // Esc goes back without saving.
  again.document.dispatchEvent(new again.window.KeyboardEvent('keydown', { key: 'Escape', bubbles: true }));
  await flush();
  assert.equal(again.$('view-list').hidden, false);
  assert.equal(again.$('qa-body').childElementCount, 0);
  assert.equal(sent('popup.totp-attach').length, 0);
});

test('Scan QR: the agent refusing the code is said in the popup words and the view stays', async () => {
  reply = agent({ 'popup.totp-attach': () => fail('invalid_params', '2FA secret is too short') });
  const { $ } = await openPopup();
  qrTexts = [LINK];
  fromMenu($, 'menu-scan');
  await flush();
  $('qa-save').click();
  await flush();
  assert.equal($('snack').textContent, "That 2FA secret isn't valid. Check it and try again.", 'the popup\'s words, never the agent\'s English');
  assert.equal($('view-qa').hidden, false);
  assert.equal($('qa-save').disabled, false, 'can try again');
});

test('New note: the recovery codes suggestion, monospace text, Save only with text, "Note saved"', async () => {
  reply = agent();
  const { $ } = await openPopup();
  fromMenu($, 'menu-note');
  await flush();
  assert.equal($('view-qa').hidden, false);
  assert.equal($('qa-heading').textContent, 'New note');
  assert.equal($('qa-note-text').tagName, 'TEXTAREA');
  assert.ok($('qa-note-text').classList.contains('qa-mono'));
  assert.equal($('qa-note-text').getAttribute('spellcheck'), 'false');
  assert.equal($('qa-note-save').disabled, true, 'nothing to save yet');
  $('qa-note-recovery').click();
  assert.equal($('qa-note-title').value, 'Recovery codes for github.com');
  $('qa-note-text').value = 'abcd-efgh\nijkl-mnop';
  $('qa-note-text').dispatchEvent(new Event('input'));
  assert.equal($('qa-note-save').disabled, false);
  $('qa-note-save').click();
  await flush();
  assert.deepEqual(sent('popup.note-create'), [{ type: 'popup.note-create', fields: { title: 'Recovery codes for github.com', notes: 'abcd-efgh\nijkl-mnop' } }]);
  assert.equal($('snack').textContent, 'Note saved');
  assert.equal($('view-list').hidden, false);
  assert.equal($('qa-body').childElementCount, 0, 'the note is gone from the popup');
  assert.ok(!JSON.stringify(storageWrites).includes('abcd-efgh'), 'never in extension storage');

  // No title: "Secure note". An older desktop app: "Update Passyble to add notes here."
  reply = agent({ 'popup.note-create': () => fail('not_supported', 'This Passyble desktop app is too old to edit logins') });
  const old = await openPopup();
  fromMenu(old.$, 'menu-note');
  await flush();
  old.$('qa-note-text').value = 'x';
  old.$('qa-note-text').dispatchEvent(new Event('input'));
  old.$('qa-note-save').click();
  await flush();
  assert.equal(sent('popup.note-create')[0].fields.title, 'Secure note');
  assert.equal(old.$('snack').textContent, 'Update Passyble to add notes here.');
  assert.equal(old.$('view-qa').hidden, false, 'the text stays for another try');
});

test('locked: the row is on the unlock card; New note unlocks first (the popup\'s form), then opens; Cancel goes back to the card', async () => {
  const LOCKED = { url: 'https://github.com/login', supported: true, locked: true, can_unlock_inline: true, unlock_hello: false,
    ask_unlock: false, can_edit: true, can_notes: true };
  let locked = true;
  reply = agent({
    'popup.state': () => ok(locked ? LOCKED : { ...STATE, can_unlock_inline: true }),
    'popup.unlock-password': (m) => { if (m.password !== 'master') return fail('wrong_password'); locked = false; return ok({ locked: false }); },
  });
  const { $, window } = await openPopup();
  assert.equal($('view-locked').hidden, false);
  assert.ok(visible($('qa-row')));
  assert.equal($('qa-row').parentElement, $('view-locked'), 'on the unlock card');

  // Cancel: back to the card, nothing opened.
  $('qa-note').click();
  await flush();
  assert.equal($('unlock-cancel').hidden, false);
  assert.equal(visible($('qa-row')), false, 'no second action while this one waits');
  $('unlock-cancel').click();
  await flush();
  assert.equal($('view-locked').hidden, false);
  assert.equal($('view-qa').hidden, true);

  $('qa-note').click();
  await flush();
  $('master').value = 'master';
  $('unlock-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await flush();
  assert.equal($('view-qa').hidden, false, 'unlocked, then on to the note');
  $('qa-note-text').value = '1111 2222';
  $('qa-note-text').dispatchEvent(new Event('input'));
  $('qa-note-save').click();
  await flush();
  assert.deepEqual(sent('popup.note-create').at(-1), { type: 'popup.note-create', fields: { title: 'Secure note', notes: '1111 2222' }, inline: true });
  assert.equal($('snack').textContent, 'Note saved');
});

test('Generate: the desktop app\'s password, New password, Copy by the desktop app; without it, made and copied here', async () => {
  let n = 0;
  reply = agent({ 'popup.generate': () => ok({ password: `Generated-Pw-${++n}` }) });
  const { $ } = await openPopup();
  fromMenu($, 'menu-generate');
  await flush();
  assert.equal($('view-qa').hidden, false);
  assert.equal($('qa-heading').textContent, 'Generate password');
  assert.equal($('qa-password').textContent, 'Generated-Pw-1');
  assert.deepEqual(sent('popup.generate'), [{ type: 'popup.generate', length: 20 }]);
  $('qa-regenerate').click();
  await flush();
  assert.equal($('qa-password').textContent, 'Generated-Pw-2');
  $('qa-copy').click();
  await flush();
  assert.deepEqual(sent('popup.generate-copy'), [{ type: 'popup.generate-copy', password: 'Generated-Pw-2' }]);
  assert.equal($('snack').textContent, 'Password copied by Passyble (clears in 45 s)');
  assert.deepEqual(clipboard, [], 'the desktop app copied it, not the popup');
  $('qa-back').click();
  await flush();
  assert.equal($('view-list').hidden, false);
  assert.equal($('qa-body').childElementCount, 0);

  // Passyble not answering: a password made here (same rules), copied with the browser's clipboard, cleared in 45 s.
  reply = agent({ 'popup.generate': () => fail('agent_unavailable', 'not running') });
  const here = await openPopup();
  fromMenu(here.$, 'menu-generate');
  await flush();
  const made = here.$('qa-password').textContent;
  assert.equal(made.length, 20);
  here.$('qa-copy').click();
  await flush();
  assert.deepEqual(clipboard, [made]);
  assert.equal(sent('popup.generate-copy').length, 0);
  assert.deepEqual(sent('clipboard.copied'), [{ type: 'clipboard.copied', value: made }]);
  assert.equal(here.$('snack').textContent, 'Password copied (clears in 45 s)');
  assert.ok(!JSON.stringify(storageWrites).includes(made), 'never in extension storage');
});

test('Generate: "Letters and numbers only" generates again at once and is remembered for the tab\'s site', async () => {
  const store = {};
  const realLocal = chrome.storage.local;
  chrome.storage.local = {
    get: async (keys) => Object.fromEntries([keys].flat().filter((k) => k in store).map((k) => [k, store[k]])),
    set: async (o) => { Object.assign(store, o); },
  };
  try {
    reply = agent({ 'popup.generate': (m) => ok({ password: m.symbols === false ? 'PlainGeneratedPw2345' : 'Generated-Pw-123!' }) });
    const { $ } = await openPopup();
    fromMenu($, 'menu-generate');
    await flush();
    const box = $('qa-no-symbols');
    assert.equal(box.type, 'checkbox');
    assert.equal(box.checked, false);
    assert.equal(box.closest('label').textContent, 'Letters and numbers only');
    assert.equal($('qa-password').textContent, 'Generated-Pw-123!');
    box.checked = true;
    box.dispatchEvent(new Event('change'));
    await flush();
    assert.equal($('qa-password').textContent, 'PlainGeneratedPw2345');
    assert.deepEqual(sent('popup.generate').at(-1), { type: 'popup.generate', length: 20, symbols: false });
    assert.deepEqual(store.generateNoSymbols, ['github.com']);
    $('qa-regenerate').click();
    await flush();
    assert.equal(sent('popup.generate').at(-1).symbols, false, 'New password keeps the choice');
    $('qa-back').click();
    await flush();

    // Next time on this site: ticked from the start. A password the agent copies only when it made it.
    reply = agent({ 'popup.generate': () => ok({ password: 'LocalPlainPassword23', local: true }) });
    const again = await openPopup();
    fromMenu(again.$, 'menu-generate');
    await flush();
    assert.equal(again.$('qa-no-symbols').checked, true);
    assert.deepEqual(sent('popup.generate'), [{ type: 'popup.generate', length: 20, symbols: false }]);
    again.$('qa-copy').click();
    await flush();
    assert.equal(sent('popup.generate-copy').length, 0, 'generated in the background: the browser copies it');
    assert.ok(clipboard.includes('LocalPlainPassword23'));

    // Unticked: with symbols, and the site is forgotten.
    const box2 = again.$('qa-no-symbols');
    box2.checked = false;
    box2.dispatchEvent(new Event('change'));
    await flush();
    assert.deepEqual(store.generateNoSymbols, []);
    assert.equal(sent('popup.generate').at(-1).symbols, undefined);
  } finally {
    chrome.storage.local = realLocal;
  }
});

// The keyboard shortcuts (background/commands.js): `popup.state` `quick_action`.

test('shortcut Scan QR: the popup scans the visible tab as it opens, the same flow as the button', async () => {
  qrTexts = [LINK];
  reply = agent({}, { ...STATE, quick_action: 'scan' });
  const { $, document } = await openPopup();
  await flush();
  assert.deepEqual(captures, [[7, { format: 'png' }]], 'one screenshot of the visible tab');
  assert.equal($('view-qa').hidden, false);
  assert.equal($('qa-heading').textContent, 'Add 2FA code');
  assert.equal(document.querySelector('input[name="qa-target"]').checked, true, 'the site\'s only login is chosen');
  assert.ok(!messages.some((m) => JSON.stringify(m).includes('data:image')), 'the image never goes to the background');
  assert.ok(!JSON.stringify(storageWrites).includes('data:image'), 'nor into storage');
});

test('shortcut Scan QR with no QR code in view: the clear message, on the list', async () => {
  qrTexts = [];
  reply = agent({}, { ...STATE, quick_action: 'scan' });
  const { $ } = await openPopup();
  await flush();
  assert.equal(captures.length, 1);
  assert.equal($('snack').textContent, 'No QR code visible on this page. Scroll it into view and try again.');
  assert.equal($('view-list').hidden, false);
});

test('shortcut Scan QR where it can\'t work: a page Passyble can\'t read, or a desktop app that can\'t edit', async () => {
  reply = agent({ 'popup.state': () => ok({ url: 'chrome://newtab/', supported: false, quick_action: 'scan' }) });
  const page = await openPopup();
  await flush();
  assert.equal(captures.length, 0);
  assert.equal(page.$('snack').textContent, 'Passyble can\'t read this page.');

  reply = agent({}, { ...STATE, can_edit: false, quick_action: 'scan' });
  const older = await openPopup();
  await flush();
  assert.equal(captures.length, 0);
  assert.match(older.$('snack').textContent, /update/i);
});

test('shortcut New note: the note editor opens at once; locked, the unlock form comes first', async () => {
  reply = agent({}, { ...STATE, quick_action: 'note' });
  const { $, document } = await openPopup();
  await flush();
  assert.equal($('view-qa').hidden, false);
  assert.equal($('qa-heading').textContent, 'New note');
  assert.equal(document.activeElement, $('qa-note-title'));

  const LOCKED = { url: 'https://github.com/login', supported: true, locked: true, can_unlock_inline: true, unlock_hello: false,
    ask_unlock: false, can_edit: true, can_notes: true };
  let locked = true;
  let first = true;
  reply = agent({
    'popup.state': () => {
      const out = locked ? { ...LOCKED, ...(first ? { quick_action: 'note' } : {}) } : { ...STATE, can_unlock_inline: true };
      first = false;
      return ok(out);
    },
    'popup.unlock-password': () => { locked = false; return ok({ locked: false }); },
  });
  const lockedPopup = await openPopup();
  await flush();
  assert.equal(lockedPopup.$('view-locked').hidden, false);
  assert.equal(lockedPopup.$('unlock-cancel').hidden, false, 'the unlock is for the note');
  lockedPopup.$('master').value = 'master';
  lockedPopup.$('unlock-form').dispatchEvent(new lockedPopup.window.Event('submit', { cancelable: true }));
  await flush();
  assert.equal(lockedPopup.$('view-qa').hidden, false, 'unlocked, then on to the note');

  // New note on a page Passyble can't fill works too.
  reply = agent({ 'popup.state': () => ok({ url: 'chrome://newtab/', supported: false, quick_action: 'note' }) });
  const anyPage = await openPopup();
  await flush();
  assert.equal(anyPage.$('view-qa').hidden, false);
});

test('the popup\'s own shortcut: the focus is in the search field (on a page Passyble can\'t fill: on Search vault)', async () => {
  reply = agent();
  const { $, document } = await openPopup();
  assert.equal(document.activeElement, $('search'));
  assert.equal(captures.length, 0, 'no quick action without a shortcut asking for one');
  reply = agent({ 'popup.state': () => ok({ url: 'chrome://newtab/', supported: false }) });
  const other = await openPopup();
  assert.equal(other.document.activeElement, other.$('search-vault'));
});
