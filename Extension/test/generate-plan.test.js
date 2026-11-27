// The in-page generator's plan for a field (src/content/generate-plan.js): the user's options made to
// fit what the field allows, with a note for every change the field forces, and what is made here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { planFor, agentCanMake, makeLocally, strengthOf, PASSPHRASE_MIN_CHARS } from '../src/content/generate-plan.js';
import { DEFAULT_OPTIONS } from '../src/shared/generate-prefs.js';
import { wordsOf } from '../src/shared/generator.js';
import { PASSPHRASE_WORDS } from '../src/shared/passphrase-words.js';

const words = wordsOf(PASSPHRASE_WORDS);
const opts = (o = {}) => ({ ...DEFAULT_OPTIONS, ...o });
const keys = (plan) => plan.notes.map((n) => (n.count === undefined ? n.key : `${n.key}:${n.count}`));

test('planFor: the options as they are when the field says nothing', () => {
  const plan = planFor(opts(), {}, true);
  assert.deepEqual({ ...plan, notes: undefined }, { ...opts(), symbols: true, notes: undefined });
  assert.deepEqual(plan.notes, []);
  assert.equal(planFor(opts(), {}, false).symbols, false, 'the site\'s choice, without a note');
  assert.deepEqual(planFor(opts(), {}, false).notes, []);
});

test('planFor: what the field forces, each with a note', () => {
  let plan = planFor(opts(), { symbols: false, maxLength: 16 }, true);
  assert.equal(plan.symbols, false);
  assert.equal(plan.length, 16);
  assert.deepEqual(keys(plan), ['genNoteNoSymbols', 'genNoteMaxLength:16']);
  plan = planFor(opts({ length: 12 }), { minLength: 24 }, true);
  assert.equal(plan.length, 24);
  assert.deepEqual(keys(plan), ['genNoteMinLength:24']);
  plan = planFor(opts({ lowercase: false, uppercase: false, digits: false }), { symbols: false }, true);
  assert.deepEqual([plan.lowercase, plan.uppercase, plan.digits, plan.symbols], [true, true, true, false]);
  assert.deepEqual(keys(plan), ['genNoteNoSymbols', 'genNoteLettersDigits']);
  plan = planFor(opts({ mode: 'passphrase' }), { maxLength: PASSPHRASE_MIN_CHARS - 1 }, true);
  assert.equal(plan.mode, 'password');
  assert.equal(plan.length, PASSPHRASE_MIN_CHARS - 1);
  assert.deepEqual(keys(plan), ['genNotePassphraseTooLong', `genNoteMaxLength:${PASSPHRASE_MIN_CHARS - 1}`]);
  plan = planFor(opts({ mode: 'passphrase' }), { maxLength: 40, minLength: 30 }, true);
  assert.equal(plan.mode, 'passphrase');
  assert.deepEqual(keys(plan), ['genNoteMaxLength:40', 'genNoteMinLength:30']);
});

test('agentCanMake: the desktop app makes passwords with every letter and digit type only', () => {
  assert.equal(agentCanMake(planFor(opts(), {}, true)), true);
  assert.equal(agentCanMake(planFor(opts(), {}, false)), true, 'without symbols too');
  assert.equal(agentCanMake(planFor(opts({ digits: false }), {}, true)), false);
  assert.equal(agentCanMake(planFor(opts({ mode: 'passphrase' }), {}, true)), false);
});

test('makeLocally: a password as planned, a passphrase that fits the field, else a password with a note', () => {
  let plan = planFor(opts({ length: 24, uppercase: false }), {}, true);
  let made = makeLocally(plan, {});
  assert.equal(made.mode, 'password');
  assert.equal(made.password.length, 24);
  assert.ok(!/[A-Z]/.test(made.password));

  const limits = { maxLength: 30 };
  plan = planFor(opts({ mode: 'passphrase', words: 6 }), limits, true);
  for (let i = 0; i < 20; i++) {
    made = makeLocally(plan, limits, { words });
    assert.ok(made.password.length <= 30, made.password);
    assert.equal(made.mode, made.words ? 'passphrase' : 'password');
  }
  made = makeLocally(planFor(opts({ mode: 'passphrase', words: 6 }), {}, false), {}, { words });
  assert.equal(made.words, 6);
  assert.match(made.password, /^(?:[A-Z][a-z]+\d?){6}$/, made.password);
  assert.equal(strengthOf(made).bits, 83);

  // A passphrase can't be 20 to 21 characters with 4 or more words often enough: a password, noted.
  const tight = { minLength: 20, maxLength: 20 };
  made = makeLocally(planFor(opts({ mode: 'passphrase', words: 12 }), tight, true), tight, { words: ['abcdefghij'] });
  assert.equal(made.mode, 'password');
  assert.equal(made.password.length, 20);
  assert.ok(made.notes.some((n) => n.key === 'genNotePassphraseTooLong'));
  made = makeLocally(planFor(opts({ mode: 'passphrase' }), {}, true), {}, { words: null });
  assert.equal(made.mode, 'password', 'no wordlist: a password');
});
