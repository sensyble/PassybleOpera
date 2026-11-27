import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
const created = [];
const downloads = [];
const timers = []; // timers of 1 s or more (the sync refresh, the "Saved" flash): kept, run by hand
let reply = () => ({ ok: true, result: null });
let instance = 0;

const flush = () => new Promise((r) => setTimeout(r, 0));
const settle = async () => { for (let i = 0; i < 8; i++) await flush(); };
const sent = (type) => messages.filter((m) => m.type === type);

async function openOptions() {
  const html = readFileSync(new URL('../src/options/options.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: 'https://extension.test/src/options/options.html', pretendToBeVisual: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  dom.window.HTMLAnchorElement.prototype.click = function click() { downloads.push(this.download); };
  messages.length = 0;
  created.length = 0;
  downloads.length = 0;
  timers.length = 0;
  await import(`../src/options/options.js?vault=${++instance}`);
  await settle();
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $ };
}

before(() => {
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => { messages.push(msg); return reply(msg); },
      onMessage: { addListener: () => {} },
      getManifest: () => ({ version: '1.2.3' }),
      getURL: (p) => `chrome-extension://pass-ext/${p}`,
    },
    tabs: { create: async (o) => { created.push(o); } },
    storage: { local: { get: async () => ({}), set: async () => {} }, sync: { get: async () => ({}), set: async () => {} } },
    commands: { getAll: async () => [] },
  };
  globalThis.URL.createObjectURL = () => 'blob:vault';
  globalThis.URL.revokeObjectURL = () => {};
  const realSetTimeout = globalThis.setTimeout;
  globalThis.setTimeout = (fn, ms, ...args) => {
    if (ms < 1000) return realSetTimeout(fn, ms, ...args);
    const timer = { fn, ms, unref() {} };
    timers.push(timer);
    return timer;
  };
});

const SETTINGS = { vaultAutoLockMins: 15, vaultLockOnIdle: true, vaultVerifyEachFill: false };
const APP = { mode: 'app', supported: true, host: 'present', has_vault: false, locked: true, source: null,
  backed_up_at: 0, created_at: 0, name: null, settings: SETTINGS, local_only: false, drive_needs_app: false, reminder: false };
/** Browser mode with a vault kept only in this browser (no sync). */
const LOCAL = { ...APP, mode: 'browser', host: 'missing', has_vault: true, locked: false, local_only: true, reminder: true };
/** Browser mode with a Google Drive vault record ("needs the app"). */
const DRIVE_RECORD = { ...LOCAL, source: 'drive', name: 'Personal', local_only: false, drive_needs_app: true, reminder: false };
/** What vault.state says once this browser has no vault (deleted). */
const gone = (state) => ({ ...state, has_vault: false, source: null, local_only: false, drive_needs_app: false, reminder: false });

/** A background; `on` overrides answers by message type (a function of the message and the state). */
function background(state, on = {}) {
  let current = state;
  const set = (next) => { current = next; };
  reply = (msg) => {
    if (on[msg.type]) return on[msg.type](msg, current, set);
    switch (msg.type) {
      case 'vault.state': return { ok: true, result: current };
      case 'vault.settings': current = { ...current, settings: { ...current.settings, ...msg.settings } }; return { ok: true, result: current.settings };
      case 'vault.set-mode': current = { ...current, mode: msg.mode }; return { ok: true, result: current };
      case 'vault.export': current = { ...current, backed_up_at: Date.now() }; return { ok: true, result: { file: 'AQID', name: 'Passyble-2026-11-06.vault' } };
      case 'vault.delete':
        if (msg.password !== 'master pw 1') return { ok: false, error: { code: 'wrong_password', message: 'x' } };
        current = gone(current);
        return { ok: true, result: current };
      default: return { ok: true, result: null };
    }
  };
  return { set };
}

const WELCOME = 'chrome-extension://pass-ext/src/welcome/welcome.html';

test('an older background (or Firefox): no vault cards', async () => {
  reply = () => ({ ok: true, result: null });
  const { $ } = await openOptions();
  assert.equal($('vault-mode').hidden, true);
  assert.equal($('vault').hidden, true);
  assert.equal($('server').hidden, false);
});

test('app mode: where the vault is, and "Use a vault in this browser" opens the setup guide (no switch on its own)', async () => {
  background(APP);
  const { $ } = await openOptions();
  assert.equal($('vault-mode').hidden, false);
  assert.equal($('vault').hidden, true);
  assert.equal($('mode-name').textContent, 'In the Passyble app');
  assert.equal($('mode-switch').textContent.trim(), 'Use a vault in this browser');
  assert.equal($('mode-text').hidden, true, 'no explanation');
  $('mode-switch').click();
  await settle();
  assert.deepEqual(created, [{ url: `${WELCOME}#browser` }]);
  assert.equal(sent('vault.set-mode').length, 0);
});

test('app mode with a vault kept in this browser: "Use a vault in this browser" switches', async () => {
  background({ ...LOCAL, mode: 'app', host: 'present', locked: true });
  const { $ } = await openOptions();
  $('mode-switch').click();
  await settle();
  assert.deepEqual(sent('vault.set-mode'), [{ type: 'vault.set-mode', mode: 'browser' }]);
  assert.equal($('mode-name').textContent, 'In this browser');
  assert.equal($('local-only-row').hidden, false);
});

test('browser mode, a vault kept only here: the Vault card with its settings and "This vault is only on this device"; Passyble Server and the app status are left out', async () => {
  background(LOCAL);
  const { $, window } = await openOptions();
  assert.equal($('vault').hidden, false);
  assert.equal($('server').hidden, true);
  assert.equal($('app-status-row').hidden, true);
  assert.equal($('mode-name').textContent, 'In this browser');
  assert.equal($('mode-text').textContent, 'Unlocked');
  assert.equal($('local-only-row').hidden, false);
  assert.equal($('local-only-title').textContent, 'This vault is only on this device');
  assert.equal($('local-only-text').textContent, 'If this device is lost, stolen, broken or reset, the passwords in this vault are gone for good. Turn on sync or backup (Google Drive is free), or export a backup copy regularly.');
  assert.equal($('local-only-sync').textContent.trim(), 'Set up sync');
  for (const gone of ['drive-row', 'drive-sync', 'drive-signout', 'drive-signout-form', 'browser-only-row', 'drive-move']) assert.equal($(gone), null, gone);
  assert.equal($('delete-row').hidden, false);
  const select = $('v-autolock');
  assert.deepEqual([...select.options].map((o) => o.textContent), ['1 min', '5 min', '15 min', '30 min', '60 min', 'Only when the browser closes']);
  assert.equal(select.value, '15');
  assert.equal($('v-lockOnIdle').checked, true);
  assert.equal($('v-verifyEachFill').checked, false);
  select.value = '0';
  select.dispatchEvent(new window.Event('change'));
  $('v-verifyEachFill').checked = true;
  $('v-verifyEachFill').dispatchEvent(new window.Event('change'));
  await settle();
  assert.deepEqual(sent('vault.settings').map((m) => m.settings), [{ vaultAutoLockMins: 0 }, { vaultVerifyEachFill: true }]);
  for (const row of $('vault').querySelectorAll('.card > .row')) {
    assert.equal(row.querySelectorAll(':scope > .row-icon > svg.pass-icon').length, 1);
    const label = row.querySelector('.name')?.textContent.trim() || '';
    assert.ok(label.length > 0 && label.length <= 44, label);
  }
  $('local-only-sync').click();
  await settle();
  assert.deepEqual(created, [{ url: `${WELCOME}#sync` }], 'Set up sync: the setup guide, where Google Drive needs the app');
});

test('a vault record of the builds that synced Google Drive themselves: "Google Drive sync needs the app", Set up sync, and Delete like any vault here', async () => {
  background(DRIVE_RECORD);
  const { $ } = await openOptions();
  assert.equal($('mode-name').textContent, 'In this browser');
  assert.equal($('local-only-row').hidden, false);
  assert.equal($('local-only-title').textContent, 'Google Drive sync needs the app');
  assert.match($('local-only-text').textContent, /synced with Google Drive in an older version/);
  assert.equal($('delete-row').hidden, false);
  $('local-only-sync').click();
  await settle();
  assert.deepEqual(created, [{ url: `${WELCOME}#sync` }]);
});

test('a vault kept only in this browser: Download a copy; Delete needs a copy from the last hour and the master password', async () => {
  background(LOCAL);
  const { $, window } = await openOptions();
  assert.equal($('backup-download').closest('.row').querySelector('.name').textContent, 'Download a copy');
  $('delete-start').click();
  assert.equal($('delete-form').hidden, false);
  assert.equal($('delete-confirm').disabled, true, 'no copy in the last hour');
  assert.equal($('delete-msg').textContent, 'Download a copy first.');
  $('delete-cancel').click();
  assert.equal($('delete-form').hidden, true);

  $('backup-download').click();
  await settle();
  assert.deepEqual(sent('vault.export'), [{ type: 'vault.export' }]);
  assert.deepEqual(downloads, ['Passyble-2026-11-06.vault']);
  assert.equal($('saved').textContent, 'Copy saved.');

  $('delete-start').click();
  assert.equal($('delete-confirm').disabled, false);
  $('delete-pw').value = 'wrong';
  $('delete-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await settle();
  assert.match($('delete-msg').textContent, /Wrong master password/);
  assert.equal($('delete-pw').value, '');
  $('delete-pw').value = 'master pw 1';
  $('delete-form').dispatchEvent(new window.Event('submit', { cancelable: true }));
  await settle();
  assert.deepEqual(sent('vault.delete').at(-1), { type: 'vault.delete', password: 'master pw 1' });
  assert.equal($('vault').hidden, true, 'no vault card without a vault');
  assert.equal($('mode-text').textContent, 'No vault yet');
});

test('browser mode: "Use the app" switches back (the vault here is kept)', async () => {
  background(LOCAL);
  const { $ } = await openOptions();
  assert.equal($('mode-switch').textContent.trim(), 'Use the app');
  $('mode-switch').click();
  await settle();
  assert.deepEqual(sent('vault.set-mode'), [{ type: 'vault.set-mode', mode: 'app' }]);
  assert.equal($('vault').hidden, true);
  assert.equal($('server').hidden, false);
});

test('the master password tip: a calm row in the Vault card while `master_tip` says so; Dismiss hides it', async () => {
  background(LOCAL);
  let { $ } = await openOptions();
  assert.equal($('master-tip-row').hidden, true, 'no tip without master_tip');
  background({ ...LOCAL, master_tip: true }, {
    'vault.master-tip-dismiss': (msg, current, set) => { const next = { ...current, master_tip: false }; set(next); return { ok: true, result: next }; },
  });
  ({ $ } = await openOptions());
  const row = $('master-tip-row');
  assert.equal(row.hidden, false);
  assert.equal(row.querySelector('.name').textContent, 'Master password');
  assert.equal(row.querySelector('.caption').textContent, 'Your master password is easier to guess than Passyble now allows for new ones. It still works.');
  assert.equal(row.querySelector('.row-icon').classList.contains('warn'), false, 'not a warning');
  assert.equal($('master-tip-dismiss').textContent.trim(), 'Dismiss');
  $('master-tip-dismiss').click();
  await settle();
  assert.deepEqual(sent('vault.master-tip-dismiss'), [{ type: 'vault.master-tip-dismiss' }]);
  assert.equal(row.hidden, true);
  // Opened again: the background remembers.
  ({ $ } = await openOptions());
  assert.equal($('master-tip-row').hidden, true);
});

// The Passyble app always wins.

const MOVE = { state: 'later', vault_id: 'v1', count: 23, total: 0, added: 0, skipped: 0, failed_count: 0, failed: [], at: 0 };

test('the app installed: one line says so, no way to the vault in this browser; the page asks for a fresh look', async () => {
  background({ ...APP, app_installed: true });
  const { $ } = await openOptions();
  assert.deepEqual(sent('vault.state')[0], { type: 'vault.state', probe: true });
  assert.equal($('mode-text').hidden, false);
  assert.equal($('mode-text').textContent, 'The Passyble app is installed on this computer, so Passyble uses it here.');
  assert.equal($('mode-switch').hidden, true);
  assert.equal($('move').hidden, true, 'no vault here: nothing to move');
});

test('the app gone (several checks): Options says so and offers the vault in this browser again', async () => {
  background({ ...APP, host: 'missing', app_installed: false, app_gone: true });
  const { $ } = await openOptions();
  assert.equal($('mode-text').textContent, 'The Passyble app is no longer on this computer. You can keep a vault in this browser instead.');
  assert.equal($('mode-switch').hidden, false);
  $('mode-switch').click();
  await settle();
  assert.deepEqual(created, [{ url: `${WELCOME}#browser` }], 'the setup guide: nothing created on its own');
});

test('the move card: "Move 23 items", the form (master password, the app\'s vault), moved, then Delete with a confirmation', async () => {
  const state = { ...APP, app_installed: true, has_vault: true, move: MOVE };
  background(state, {
    'vault.move-targets': () => ({ ok: true, result: { vaults: [{ id: 'home', name: 'Personal', home: true }, { id: 'team', name: 'Team', home: false }], linked: null } }),
    'vault.move': (msg, current, set) => {
      if (msg.password !== 'master pw 1') return { ok: false, error: { code: 'wrong_password', message: 'x' } };
      const next = { ...current, move: { ...MOVE, state: 'moved', total: 23, added: 20, skipped: 3 } };
      set(next);
      return { ok: true, result: next };
    },
    'vault.delete-moved': (msg, current, set) => {
      const next = { ...current, has_vault: false, move: null };
      set(next);
      return { ok: true, result: next };
    },
  });
  const { $ } = await openOptions();
  assert.equal($('move').hidden, false);
  assert.equal($('move-title').textContent, 'Move 23 items from this browser into the Passyble app');
  assert.equal($('move-text').textContent, 'They stay in this browser too, until you delete the vault here.');
  assert.equal($('move-delete-start').hidden, true, 'nothing to delete before the move');
  $('move-start').click();
  await settle();
  assert.equal($('move-form').hidden, false);
  assert.equal($('move-pw-label').textContent, 'Master password');
  assert.equal($('move-vault-part').hidden, false, 'two vaults to choose from');
  assert.deepEqual([...$('move-vault').options].map((o) => o.textContent), ['Personal', 'Team']);
  // Empty, then wrong, then right.
  $('move-form').dispatchEvent(new globalThis.Event('submit', { cancelable: true }));
  await settle();
  assert.equal(sent('vault.move').length, 0);
  $('move-pw').value = 'nope';
  $('move-form').dispatchEvent(new globalThis.Event('submit', { cancelable: true }));
  await settle();
  assert.equal($('move-pw').value, '', 'cleared');
  assert.match($('move-msg').className, /error/);
  $('move-vault').value = 'team';
  $('move-pw').value = 'master pw 1';
  $('move-form').dispatchEvent(new globalThis.Event('submit', { cancelable: true }));
  await settle();
  assert.deepEqual(sent('vault.move').at(-1), { type: 'vault.move', password: 'master pw 1', vault: 'team' });
  assert.equal($('move-form').hidden, true);
  assert.equal($('move-title').textContent, 'Moved into the Passyble app');
  assert.equal($('move-text').textContent, 'Added: 20. Already in the app: 3. The vault in this browser is kept until you delete it.');
  assert.equal($('move-start').hidden, true);
  // Delete: a confirmation first, nothing sent before it.
  $('move-delete-start').click();
  await settle();
  assert.equal($('move-delete-form').hidden, false);
  assert.equal(sent('vault.delete-moved').length, 0);
  $('move-delete-cancel').click();
  assert.equal($('move-delete-form').hidden, true);
  $('move-delete-start').click();
  $('move-delete-form').dispatchEvent(new globalThis.Event('submit', { cancelable: true }));
  await settle();
  assert.deepEqual(sent('vault.delete-moved'), [{ type: 'vault.delete-moved', confirmed: true }]);
  assert.equal($('move').hidden, true, 'no vault here any more');
});

test('the move card after a partial move: what could not move, listed; Try again; no Delete', async () => {
  background({ ...APP, app_installed: true, has_vault: true,
    move: { ...MOVE, state: 'partial', total: 23, added: 18, skipped: 3, failed_count: 2, failed: ['Bank', 'Wi-Fi'] } });
  const { $ } = await openOptions();
  assert.equal($('move-title').textContent, 'Some items could not move');
  assert.equal($('move-text').textContent, 'Added: 18. Already in the app: 3. Could not move: 2. Those are still in this browser.');
  assert.deepEqual([...$('move-failed').querySelectorAll('li')].map((li) => li.textContent), ['Bank', 'Wi-Fi']);
  assert.equal($('move-start').textContent.trim(), 'Try again');
  assert.equal($('move-delete-start').hidden, true);
});

test('the move card without a count (the vault here was locked), and for a vault linked to a Passyble account', async () => {
  background({ ...APP, app_installed: true, has_vault: true, move: { ...MOVE, count: null } }, {
    'vault.move-targets': () => ({ ok: true, result: { vaults: [{ id: 'home', name: '', home: true }], linked: { secret_key_needed: true } } }),
  });
  const { $ } = await openOptions();
  assert.equal($('move-title').textContent, 'Move the items in this browser into the Passyble app');
  $('move-start').click();
  await settle();
  assert.equal($('move-pw-label').textContent, 'Passyble password');
  assert.equal($('move-sk-part').hidden, false);
  assert.equal($('move-vault-part').hidden, true, 'one vault: no choice');
});
