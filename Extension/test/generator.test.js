import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  generatePassword, generatePassphrase, passwordStrength, passphraseStrength, isPlainPassword, wordsOf, CHARSETS, DEFAULT_LENGTH,
} from '../src/shared/generator.js';
import { PASSPHRASE_WORDS } from '../src/shared/passphrase-words.js';

test('charsets match the core defaults (look-alikes Il1O0o left out)', () => {
  const all = Object.values(CHARSETS).join('');
  for (const c of 'Il1O0o') assert.ok(!all.includes(c), c);
  assert.equal(CHARSETS.symbols, '!@#$%^&*()-_=+[]{};:,.?/~');
  assert.equal(CHARSETS.lowercase.length, 24);
  assert.equal(CHARSETS.uppercase.length, 24);
  assert.equal(CHARSETS.digits.length, 8);
});

test('generatePassword: default length 20, every class present, only allowed characters', () => {
  const all = Object.values(CHARSETS).join('');
  for (let i = 0; i < 200; i++) {
    const pw = generatePassword();
    assert.equal(pw.length, DEFAULT_LENGTH);
    assert.ok([...pw].every((c) => all.includes(c)), pw);
    for (const set of Object.values(CHARSETS)) assert.ok([...pw].some((c) => set.includes(c)), `${pw} lacks ${set}`);
  }
});

test('generatePassword: length is clamped to 8..128 like the agent', () => {
  assert.equal(generatePassword({ length: 3 }).length, 8);
  assert.equal(generatePassword({ length: 500 }).length, 128);
  assert.equal(generatePassword({ length: 32 }).length, 32);
});

test('generatePassword: rejection sampling skips biased values', () => {
  const values = [0xFFFFFFFF, 0, 0xFFFFFFFE, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];
  let i = 0;
  const rng = (buf) => { buf[0] = values[i++ % values.length]; };
  const pw = generatePassword({ length: 8, rng });
  assert.equal(pw.length, 8);
});

test('passwordStrength', () => {
  assert.deepEqual(passwordStrength('abc'), { bits: 14, label: 'Weak', length: 3 });
  assert.equal(passwordStrength(generatePassword()).label, 'Very strong');
  assert.equal(passwordStrength('').bits, 0);
});

test('generatePassword { symbols: false }: letters and digits only, every one of those classes, same length rules', () => {
  for (let i = 0; i < 200; i++) {
    const pw = generatePassword({ symbols: false });
    assert.equal(pw.length, DEFAULT_LENGTH);
    assert.ok(isPlainPassword(pw), pw);
    for (const set of [CHARSETS.lowercase, CHARSETS.uppercase, CHARSETS.digits]) assert.ok([...pw].some((c) => set.includes(c)), `${pw} lacks ${set}`);
    assert.ok(![...pw].some((c) => 'Il1O0o'.includes(c)), 'no look-alikes');
  }
  assert.equal(generatePassword({ symbols: false, length: 3 }).length, 8);
  assert.equal(passwordStrength(generatePassword({ symbols: false })).label, 'Very strong');
});

test('isPlainPassword', () => {
  for (const v of ['Abc123xyz', 'abc']) assert.equal(isPlainPassword(v), true, v);
  for (const v of ['Abc-123', 'Abc 123', '', null, 42, 'Äbc123']) assert.equal(isPlainPassword(v), false, String(v));
});

test('generatePassword: character types left out, and letters and digits when none is left', () => {
  for (let i = 0; i < 100; i++) {
    const pw = generatePassword({ length: 16, uppercase: false, symbols: false });
    assert.match(pw, /^[a-z0-9]{16}$/, pw);
    assert.ok(/[a-z]/.test(pw) && /[0-9]/.test(pw), 'both types it has');
    assert.match(generatePassword({ length: 12, lowercase: false, uppercase: false, digits: false }), /^[!@#$%^&*()\-_=+[\]{};:,.?/~]{12}$/);
    assert.match(generatePassword({ lowercase: false, uppercase: false, digits: false, symbols: false }), /^[A-Za-z0-9]{20}$/);
  }
});

test('the passphrase words are the core\'s EFF large wordlist', () => {
  const words = wordsOf(PASSPHRASE_WORDS);
  assert.equal(words.length, 7776);
  assert.equal(new Set(words).size, 7776);
  assert.equal(words[0], 'abacus');
  assert.ok(words.every((w) => /^[a-z-]+$/.test(w)));
});

test('generatePassphrase: words, one digit, hyphens; plain: CamelCase letters and one digit', () => {
  const list = ['alpha', 'bravo', 't-shirt', 'delta'];
  for (let i = 0; i < 100; i++) {
    const pp = generatePassphrase(list, { words: 5 });
    const parts = pp.split(/-(?=[a-z])/).length;
    assert.ok(parts >= 5, pp);
    assert.equal((pp.match(/\d/g) || []).length, 1, pp);
    const plain = generatePassphrase(list, { words: 4, plain: true });
    assert.ok(isPlainPassword(plain), plain);
    assert.match(plain, /^(?:(?:Alpha|Bravo|Tshirt|Delta)\d?){4}$/, plain);
  }
  assert.equal(generatePassphrase(['ab', 'cd'], { words: 1 }).split('-').length, 4, 'at least 4 words');
  assert.equal(generatePassphrase(['ab', 'cd'], { words: 50 }).split('-').length, 20, 'at most 20');
  assert.throws(() => generatePassphrase([], {}));
});

test('passphraseStrength: by the words, not the characters', () => {
  assert.equal(passphraseStrength('x', 6).bits, 83);
  assert.equal(passphraseStrength('x', 4).label, 'Fair');
  assert.equal(passphraseStrength('x', 8).label, 'Very strong');
  assert.equal(passphraseStrength('correct-horse', 6).length, 13);
});
