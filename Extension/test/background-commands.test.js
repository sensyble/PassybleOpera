// The keyboard shortcuts the background handles (src/background/commands.js), with fakes for the browser and
// the background's helpers.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createCommands, POPUP_ACTION_TTL_MS } from '../src/background/commands.js';
import { syncOutcome } from '../src/shared/sync.js';

const WEB_TAB = { id: 7, windowId: 3, url: 'https://github.com/settings/security' };
const NEW_TAB = { id: 8, windowId: 3, url: 'chrome://newtab/' };

function setup({ openPopup = async () => {}, frame = async () => ({ ok: true }), blocked = false, lock = async () => ({ locked: true }),
  generated = { password: 'Gen-Pass-123!', byAgent: true }, copied = { ok: true, byApp: true }, active = WEB_TAB,
  sync = async () => ({ synced: 2, failed: [], no_sync: false }) } = {}) {
  const log = { opened: [], frames: [], notices: [], generated: [], copied: [], locks: 0, syncs: 0 };
  let clock = 1_000;
  const ext = {
    action: openPopup ? { openPopup: (opts) => { log.opened.push(opts); return openPopup(opts); } } : {},
    tabs: { query: async () => [active] },
  };
  const commands = createCommands({
    ext,
    isWebUrl: (url) => /^https?:/.test(url || ''),
    blocked: async () => blocked,
    sendToFillFrame: async (tabId, message) => { log.frames.push([tabId, message]); return frame(tabId, message); },
    notify: async (tabId, text) => { log.notices.push([tabId, text]); },
    lock: async () => { log.locks++; return lock(); },
    generate: async (url) => { log.generated.push(url); return generated; },
    copy: async (password, byAgent) => { log.copied.push([password, byAgent]); return copied; },
    sync: async () => { log.syncs++; return sync(); },
    syncText: (outcome) => syncOutcome(outcome).text,
    t: (key) => `<${key}>`,
    errorText: (err) => `error: ${err.code}`,
    now: () => clock,
  });
  return { commands, log, tick: (ms) => { clock += ms; } };
}

test('scan-qr: openPopup is called at once (Firefox allows it only during the key press), and the popup gets "scan" once', async () => {
  const { commands, log } = setup();
  const done = commands.handle('scan-qr', WEB_TAB);
  assert.deepEqual(log.opened, [{ windowId: 3 }], 'called before anything was awaited');
  assert.deepEqual(await done, { opened: true });
  assert.equal(commands.takePopupAction(99), null, 'another tab\'s popup does not start it');
  assert.equal(commands.takePopupAction(7), 'scan');
  assert.equal(commands.takePopupAction(7), null, 'only once');
  assert.deepEqual(log.notices, []);
  assert.deepEqual(log.frames, [], 'no screenshot or page message from the background');
});

test('new-note: the popup starts the note editor, on any page (a new tab page too)', async () => {
  const { commands, log } = setup({ active: NEW_TAB });
  assert.deepEqual(await commands.handle('new-note', NEW_TAB), { opened: true });
  assert.equal(commands.takePopupAction(8), 'note');
  assert.deepEqual(log.notices, []);
});

test('popup action: forgotten after a minute; a later shortcut replaces it', async () => {
  const { commands, tick } = setup();
  await commands.handle('scan-qr', WEB_TAB);
  tick(POPUP_ACTION_TTL_MS + 1);
  assert.equal(commands.takePopupAction(7), null);
  await commands.handle('scan-qr', WEB_TAB);
  await commands.handle('new-note', WEB_TAB);
  assert.equal(commands.takePopupAction(7), 'note');
});

test('popup not allowed (or no openPopup): the page says to click Passyble in the toolbar; that popup starts the action', async () => {
  const { commands, log } = setup({ openPopup: async () => { throw new Error('not allowed'); } });
  assert.deepEqual(await commands.handle('scan-qr', WEB_TAB), { opened: false });
  assert.deepEqual(log.notices, [[7, '<cmdUseToolbar>']]);
  assert.equal(commands.takePopupAction(7), 'scan');

  const none = setup({ openPopup: null });
  assert.deepEqual(await none.commands.handle('new-note', undefined), { opened: false });
  assert.deepEqual(none.log.notices, [[7, '<cmdUseToolbar>']], 'the active tab, when the browser gives none');
  assert.equal(none.commands.takePopupAction(7), 'note');

  const notWeb = setup({ openPopup: null, active: NEW_TAB });
  await notWeb.commands.handle('new-note', NEW_TAB);
  assert.deepEqual(notWeb.log.notices, [], 'no content script on a browser page');
});

test('generate-password: the focused password field takes it (the site\'s own symbols choice); nothing is copied', async () => {
  const { commands, log } = setup();
  assert.deepEqual(await commands.handle('generate-password', WEB_TAB), { done: 'filled' });
  assert.deepEqual(log.frames, [[7, { type: 'cmd.generate-here', focused: true }]]);
  assert.equal('symbols' in log.frames[0][1], false, 'the frame applies the site\'s choice');
  assert.deepEqual(log.copied, []);
  assert.deepEqual(log.notices, []);
});

test('generate-password: no password field in focus, so it is copied (by the desktop app when it generated it), and the page says so', async () => {
  const { commands, log } = setup({ frame: async () => ({ ok: false }) });
  assert.deepEqual(await commands.handle('generate-password', WEB_TAB), { done: 'copied' });
  assert.deepEqual(log.generated, ['https://github.com/settings/security'], 'generated with the site\'s choice');
  assert.deepEqual(log.copied, [['Gen-Pass-123!', true]]);
  assert.deepEqual(log.notices, [[7, '<cmdGeneratedCopiedByApp>']]);

  const local = setup({ frame: async () => { throw new Error('no content script'); }, generated: { password: 'Here-1', byAgent: false },
    copied: { ok: true, byApp: false } });
  await local.commands.handle('generate-password', WEB_TAB);
  assert.deepEqual(local.log.copied, [['Here-1', false]]);
  assert.deepEqual(local.log.notices, [[7, '<cmdGeneratedCopied>']]);

  const failed = setup({ frame: async () => ({ ok: false }), copied: { ok: false, byApp: false } });
  assert.deepEqual(await failed.commands.handle('generate-password', WEB_TAB), { done: false });
  assert.deepEqual(failed.log.notices, [[7, '<cmdGenerateCopyFailed>']]);
});

test('generate-password on a browser page: copied (no site, no page to tell)', async () => {
  const { commands, log } = setup({ active: NEW_TAB });
  assert.deepEqual(await commands.handle('generate-password', NEW_TAB), { done: 'copied' });
  assert.deepEqual(log.frames, []);
  assert.deepEqual(log.generated, ['']);
  assert.deepEqual(log.notices, []);
});

test('lock: locks the vault and says so; an error is shown as such', async () => {
  const { commands, log } = setup();
  assert.deepEqual(await commands.handle('lock', WEB_TAB), { done: 'locked' });
  assert.equal(log.locks, 1);
  assert.deepEqual(log.notices, [[7, '<cmdLocked>']]);

  const offline = setup({ lock: async () => { throw Object.assign(new Error('x'), { code: 'agent_unavailable' }); } });
  assert.deepEqual(await offline.commands.handle('lock', WEB_TAB), { done: false });
  assert.deepEqual(offline.log.notices, [[7, 'error: agent_unavailable']]);
});

test('fill-login / fill-otp: sent to the frame with the user\'s field, on web pages only', async () => {
  const { commands, log } = setup();
  await commands.handle('fill-login', WEB_TAB);
  await commands.handle('fill-otp', undefined);
  assert.deepEqual(log.frames, [[7, { type: 'cmd.fill-login' }], [7, { type: 'cmd.fill-otp' }]]);
  const notWeb = setup({ active: NEW_TAB });
  assert.deepEqual(await notWeb.commands.handle('fill-login', NEW_TAB), { done: false });
  assert.deepEqual(notWeb.log.frames, []);
});

test('sync-now: syncs, and the page says "Synced just now"', async () => {
  const { commands, log } = setup();
  assert.deepEqual(await commands.handle('sync-now', WEB_TAB), { done: 'synced' });
  assert.equal(log.syncs, 1);
  assert.deepEqual(log.notices, [[7, 'Synced just now']]);
});

test('sync-now: a vault that did not sync, an older desktop app, no vault that syncs, Passyble not running', async () => {
  const failed = setup({ sync: async () => ({ synced: 1, failed: [{ vault: 'Family', reason: "Couldn't reach the server" }], no_sync: false }) });
  assert.deepEqual(await failed.commands.handle('sync-now', WEB_TAB), { done: 'synced' });
  assert.deepEqual(failed.log.notices, [[7, "Family didn't sync: Couldn't reach the server"]]);

  const old = setup({ sync: async () => { throw Object.assign(new Error('unknown method'), { code: 'not_supported', reason: 'needs_update' }); } });
  assert.deepEqual(await old.commands.handle('sync-now', WEB_TAB), { done: false });
  assert.deepEqual(old.log.notices, [[7, 'Update the Passyble app to sync from here']]);

  const none = setup({ sync: async () => ({ synced: 0, failed: [], no_sync: true }) });
  await none.commands.handle('sync-now', undefined);
  assert.deepEqual(none.log.notices, [[7, 'No vault syncs yet. Set it up in the Passyble app.']], 'the active tab');

  const browser = setup({ sync: async () => ({ synced: 0, failed: [], no_sync: true, browser: true }) });
  await browser.commands.handle('sync-now', WEB_TAB);
  assert.deepEqual(browser.log.notices, [[7, 'No vault syncs yet: this vault is only in this browser.']]);

  const offline = setup({ sync: async () => { throw Object.assign(new Error('x'), { code: 'agent_unavailable' }); } });
  assert.deepEqual(await offline.commands.handle('sync-now', WEB_TAB), { done: false });
  assert.equal(offline.log.notices.length, 1);
  assert.match(offline.log.notices[0][1], /Passyble/);

  const notWeb = setup({ active: NEW_TAB });
  assert.deepEqual(await notWeb.commands.handle('sync-now', NEW_TAB), { done: 'synced' });
  assert.equal(notWeb.log.syncs, 1, 'synced on a browser page too');
  assert.deepEqual(notWeb.log.notices, [], 'no content script there to tell');
});

test('read-only until updated: nothing fills, generates, locks or syncs', async () => {
  const { commands, log } = setup({ blocked: true });
  for (const name of ['fill-login', 'fill-otp', 'generate-password', 'lock', 'sync-now']) assert.deepEqual(await commands.handle(name, WEB_TAB), { done: false });
  assert.deepEqual(log.frames, []);
  assert.deepEqual(log.copied, []);
  assert.equal(log.locks, 0);
  assert.equal(log.syncs, 0);
});

test('unknown commands do nothing', async () => {
  const { commands, log } = setup();
  assert.deepEqual(await commands.handle('_execute_action', WEB_TAB), { done: false });
  assert.deepEqual(await commands.handle('something-else', WEB_TAB), { done: false });
  assert.deepEqual([log.opened, log.frames, log.notices], [[], [], []]);
});
