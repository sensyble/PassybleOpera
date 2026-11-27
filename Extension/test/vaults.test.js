// Linked vaults (Teams, Family, direct shares): how answers that name vaults are shown (src/shared/vaults.js).
// Demo vaults only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  canEdit, canReveal, chosenVault, filterVaults, isMultiVault, itemRights, moveTargets, newLoginVaultChoice, pinnedFirst, pinsOf,
  sharedWithMe, teamsErrorKey, teamsSection, togglePin, vaultLabel, vaultRef, vaultTable,
} from '../src/shared/vaults.js';
import { friendlyError, MSG } from '../src/shared/messages.js';
import { fileErrorCode } from '../src/background/teams/cloud-files.js';

const HOME = { id: 'home', name: '', home: true, kind: 'personal', role: null, can_edit: true, can_reveal: true };
const ENG = { id: 'eng', name: 'Engineering', home: false, kind: 'org', role: 'edit', can_edit: true, can_reveal: true };
const SUPPORT = { id: 'sup', name: 'Support', home: false, kind: 'org', role: 'view', can_edit: false, can_reveal: true };
const DEPLOY = { id: 'dep', name: 'Deploy', home: false, kind: 'org', role: 'fill', can_edit: false, can_reveal: false };

test('one vault (an older desktop app, a browser vault alone): nothing changes', () => {
  const table = vaultTable([HOME]);
  assert.equal(isMultiVault(table), false);
  const item = { id: 'a', vault_id: 'home' };
  assert.equal(vaultLabel(item, table), '');
  assert.deepEqual(itemRights({ id: 'x' }, vaultTable(undefined)), { reveal: true, edit: true, view: false, open: true });
});

test('the table keeps the home vault first and refuses malformed entries', () => {
  const table = vaultTable([ENG, { id: '' }, null, 'x'], [HOME, ENG]);
  assert.deepEqual([...table.keys()], ['home', 'eng']);
  assert.equal(vaultRef({ id: 'v', role: 'owner', kind: 'weird', name: 'x'.repeat(500) }).role, null);
  assert.equal(vaultRef({ id: 'v', name: 'x'.repeat(500) }).name.length, 120);
});

test('roles decide what the popup offers', () => {
  const table = vaultTable([HOME, ENG, SUPPORT, DEPLOY]);
  assert.deepEqual(itemRights({ vault_id: 'eng' }, table), { reveal: true, edit: true, view: false, open: true });
  assert.deepEqual(itemRights({ vault_id: 'sup' }, table), { reveal: true, edit: false, view: true, open: true });
  // A fill member: filled only, never shown or copied, and no editor (it would show the password).
  assert.deepEqual(itemRights({ vault_id: 'dep' }, table), { reveal: false, edit: false, view: false, open: false });
  assert.equal(canReveal({ vault_id: 'eng', can_reveal: false }, table), false, 'the item says so itself');
  assert.equal(canEdit({ vault_id: 'unknown' }, table), true, 'an unknown vault: the agent decides');
  assert.equal(vaultLabel({ vault_id: 'eng' }, table), 'Engineering');
});

test('the save banner offers the vaults a new login can go to', () => {
  const answer = { action: 'save_new', vaults: [HOME, ENG, SUPPORT], default_vault: 'eng' };
  const choice = newLoginVaultChoice(answer);
  assert.deepEqual(choice, { vaults: [{ id: 'home', name: '' }, { id: 'eng', name: 'Engineering' }], selected: 'eng' });
  assert.equal(newLoginVaultChoice({ vaults: [HOME] }), null, 'one vault: nothing to ask');
  assert.equal(newLoginVaultChoice({ vaults: [HOME, ENG], default_vault: 'sup' }).selected, 'home');
  // Only an id the banner offered goes to the agent.
  assert.equal(chosenVault(choice, 'eng'), 'eng');
  assert.equal(chosenVault(choice, 'sup'), undefined);
  assert.equal(chosenVault(null, 'eng'), undefined);
});

test('the save banner never offers a vault the user cannot edit, nor one that does not say it can be edited', () => {
  const vague = { id: 'old', name: 'No flags', home: false, kind: 'org', role: 'edit' };
  const lying = { ...DEPLOY, id: 'dep2', can_edit: true };
  const emergency = { id: 'em', name: 'Mum', home: false, kind: 'emergency', role: null, can_edit: true, can_reveal: true };
  const choice = newLoginVaultChoice({ vaults: [SUPPORT, HOME, DEPLOY, vague, lying, emergency, ENG], default_vault: 'sup' });
  assert.deepEqual(choice, { vaults: [{ id: 'home', name: '' }, { id: 'eng', name: 'Engineering' }], selected: 'home' });
  assert.equal(newLoginVaultChoice({ vaults: [HOME, SUPPORT, DEPLOY] }), null, 'only one editable vault: nothing to ask');
});

test('pins: the agent\'s list in order (max 5), pinned vaults first, a 6th pin refused, unknown ids kept', () => {
  assert.deepEqual(pinsOf({ pins: ['eng', 7, '', 'gone'], max: 5 }), { pins: ['eng', 'gone'], max: 5 });
  assert.deepEqual(pinsOf(null), { pins: [], max: 5 });
  const list = [HOME, ENG, SUPPORT, DEPLOY];
  assert.deepEqual(pinnedFirst(list, ['dep', 'gone', 'eng']).map((v) => v.id), ['dep', 'eng', 'home', 'sup']);
  assert.deepEqual(pinnedFirst([{ vault_id: 'b' }, { vault_id: 'a' }, { vault_id: null }], ['a'], 'vault_id').map((v) => v.vault_id), ['a', 'b', null]);
  // The active vault before the pinned ones, pinned or not.
  assert.deepEqual(pinnedFirst(list, ['dep', 'eng'], 'id', (v) => v.id === 'sup').map((v) => v.id), ['sup', 'dep', 'eng', 'home']);
  assert.deepEqual(pinnedFirst(list, ['eng', 'home'], 'id', (v) => v.home).map((v) => v.id), ['home', 'eng', 'sup', 'dep']);
  const pins = { pins: ['gone', 'eng'], max: 5 };
  assert.deepEqual(togglePin(pins, 'sup', true), ['gone', 'eng', 'sup'], 'a vault this browser does not show keeps its pin');
  assert.deepEqual(togglePin(pins, 'eng', false), ['gone']);
  assert.deepEqual(togglePin(pins, 'eng', true), ['gone', 'eng']);
  const full = { pins: ['a', 'b', 'c', 'd', 'gone'], max: 5 };
  assert.equal(togglePin(full, 'eng', true), null, 'five pins (one of a vault not shown here): no sixth');
  assert.deepEqual(togglePin(full, 'gone', false), ['a', 'b', 'c', 'd']);
});

test('the vault filter offers every vault that opened; the editor moves logins only between open, editable vaults', () => {
  const list = [
    { ...HOME, open: true, error: null }, { ...ENG, open: true, error: null }, { ...SUPPORT, open: true, error: null },
    { ...DEPLOY, open: true, error: null }, { id: 'shut', name: 'Shut', kind: 'org', role: 'edit', can_edit: true, can_reveal: true, open: false, error: null },
    { id: 'bad', name: 'Bad', kind: 'org', role: 'edit', can_edit: true, can_reveal: true, open: false, error: { code: 'untrusted' } },
  ];
  assert.deepEqual([...filterVaults(list).keys()], ['home', 'eng', 'sup', 'dep', 'shut']);
  assert.deepEqual([...filterVaults([ENG], [HOME]).keys()], ['home', 'eng'], 'browser mode: the home vault of the answers first');
  assert.deepEqual(moveTargets(list).map((v) => v.id), ['home', 'eng']);
  assert.deepEqual(moveTargets(undefined, [HOME]).map((v) => v.id), ['home']);
});

test('the "Shared with me" line from vaults.list', () => {
  const list = {
    vaults: [
      { ...HOME, items: 3, open: true, error: null },
      { ...ENG, items: 5, open: true, error: null },
      { ...SUPPORT, items: 0, open: false, error: { code: 'untrusted', message: 'x' } },
      { id: null, name: 'Never opened', open: false },
    ],
    teams: { invites: 1, to_confirm: 2, notices: 0 },
  };
  const model = sharedWithMe(list);
  assert.equal(model.show, true);
  assert.deepEqual(model.vaults.map((v) => [v.id, v.open, v.errorCode, v.fixInApp]), [['eng', true, '', false], ['sup', false, 'untrusted', true]]);
  assert.deepEqual([model.open, model.errors, model.invites, model.toConfirm], [1, 1, 1, 2]);
  assert.equal(teamsSection(model), 'confirm');
  assert.equal(teamsSection({ ...model, toConfirm: 0 }), 'invites');
  // No Team, Family or share: nothing shows.
  assert.equal(sharedWithMe({ vaults: [HOME], teams: null }).show, false);
  assert.equal(sharedWithMe(null).show, false);
  assert.equal(teamsErrorKey('no_such_code'), 'teamsErrInternal');
  assert.equal(teamsErrorKey('vault_limit'), 'teamsErrVaultLimit');
  assert.equal(fileErrorCode(403, 'vault_limit'), 'vault_limit');
  assert.equal(fileErrorCode(403, ''), 'internal');
});

test('the agent\'s role errors are worded', () => {
  assert.equal(friendlyError({ code: 'read_only', message: 'x' }), MSG.readOnly);
  assert.equal(friendlyError({ code: 'fill_only', message: 'x' }), MSG.fillOnly);
  assert.match(MSG.fillOnly, /not shown or copied/);
});
