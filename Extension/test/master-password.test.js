// The master password rule's texts (src/shared/master-password.js). The rule itself is the core's and isn't tested here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MASTER_CHECK_DEBOUNCE_MS, MASTER_MIN_LENGTH, masterIssueTexts, masterOkText, masterRefusal } from '../src/shared/master-password.js';

const refused = (issues, extra = {}) => ({ ok: false, score: 1, label: 'weak', entropy_bits: 30, issues, name: '', min_length: 12, ...extra });

test('every reason in the core\'s order, with the minimum length the answer names', () => {
  assert.deepEqual(masterIssueTexts(refused(['too_short', 'common', 'contains_name', 'pattern', 'guessable'])).map((i) => i.text), [
    'Use at least 12 characters.',
    'This is one of the most common passwords. Choose something else.',
    "Leave out your e-mail address, username and the vault's name.",
    'Avoid repeated characters, sequences like abcd or 1234 and keyboard rows like qwerty.',
    'Too easy to guess. Add more words or random characters: four or more unrelated words work well.',
  ]);
  assert.equal(masterIssueTexts(refused(['too_short'], { min_length: 14 }))[0].text, 'Use at least 14 characters.');
  assert.equal(masterIssueTexts(refused(['too_short'], { min_length: 'x' }))[0].text, 'Use at least 12 characters.');
});

test('nothing to say for a password that passes, for an empty one and without an answer; unknown codes', () => {
  assert.deepEqual(masterIssueTexts({ ok: true, score: 3, label: 'good', issues: [] }), []);
  assert.deepEqual(masterIssueTexts(refused([], { score: 0, label: '' })), [], 'empty password');
  assert.deepEqual(masterIssueTexts(null), []);
  assert.deepEqual(masterIssueTexts(refused(['pattern', 'from_a_newer_core', 'pattern'])).map((i) => i.code), ['pattern'], 'unknown and repeated codes left out');
  assert.deepEqual(masterIssueTexts(refused(['from_a_newer_core'])).map((i) => i.code), ['guessable'], 'only unknown ones: still refused, with a reason');
});

test('"strong enough" with the app\'s Good or Strong, only once it passes', () => {
  assert.equal(masterOkText({ ok: true, label: 'good' }), 'Good: strong enough for a master password.');
  assert.equal(masterOkText({ ok: true, label: 'strong' }), 'Strong: strong enough for a master password.');
  assert.equal(masterOkText(refused(['guessable'], { label: 'strong' })), '');
  assert.equal(masterOkText(null), '');
});

test('a submit is refused with the first reason (the minimum length when empty), never once it passes', () => {
  assert.equal(masterRefusal(refused(['common', 'guessable'])), 'This is one of the most common passwords. Choose something else.');
  assert.equal(masterRefusal(refused([])), 'Use at least 12 characters.');
  assert.equal(masterRefusal(null), 'Use at least 12 characters.');
  assert.equal(masterRefusal({ ok: true, label: 'good', issues: [] }), '');
  assert.equal(MASTER_MIN_LENGTH, 12);
  assert.equal(MASTER_CHECK_DEBOUNCE_MS, 150);
});
