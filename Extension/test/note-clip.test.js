// The selection as "Save selection to Passyble note" saves it (src/shared/note-clip.js).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { MAX_NOTE_CHARS, charCount, cleanSelection, clipText, noteTitleFor, recentFirst, siteOf, titleMatches } from '../src/shared/note-clip.js';

test('cleanSelection: line breaks kept as \\n, tabs kept, other control characters dropped, trimmed', () => {
  assert.equal(cleanSelection('  one\r\ntwo\rthree\tfour\u0007\u001b\u0085 \n'), 'one\ntwo\nthree\tfour');
  assert.equal(cleanSelection(' \n\t '), '');
  assert.equal(cleanSelection(undefined), '');
  assert.equal(cleanSelection(42), '');
});

test('clipText: the page address only when asked for, and only a web address', () => {
  assert.equal(clipText(' Demo quote ', 'https://blog.example/post', false), 'Demo quote');
  assert.equal(clipText(' Demo quote ', 'https://blog.example/post', true), 'Demo quote\nhttps://blog.example/post');
  assert.equal(clipText('Demo quote', 'file:///C:/secret.txt', true), 'Demo quote');
  assert.equal(clipText('Demo quote', '', true), 'Demo quote');
});

test('noteTitleFor: the page title on one line, else the site', () => {
  assert.equal(noteTitleFor('  Demo\n  post ', 'https://blog.example/'), 'Demo post');
  assert.equal(noteTitleFor('', 'https://www.blog.example/post'), 'blog.example');
  assert.equal(noteTitleFor(undefined, 'chrome://settings'), '');
  assert.equal(noteTitleFor('x'.repeat(300), '').length, 256);
  assert.equal(siteOf('http://shop.example:8080/a'), 'shop.example');
});

test('recentFirst and titleMatches: newest change first; every word of the search in the title', () => {
  const notes = [{ id: 'a', title: 'B', updated: 1 }, { id: 'b', title: 'A', updated: 5 }, { id: 'c', title: 'A' }, null, { title: 'no id' }];
  assert.deepEqual(recentFirst(notes).map((n) => n.id), ['b', 'a', 'c']);
  assert.deepEqual(recentFirst(undefined), []);
  assert.ok(titleMatches('Reading list 2026', 'list read'));
  assert.ok(!titleMatches('Reading list', 'list ideas'));
  assert.ok(titleMatches('Anything', '  '));
});

test('charCount counts characters as the agent does: an emoji is one', () => {
  assert.equal(charCount('aé中😀'), 4);
  assert.equal(MAX_NOTE_CHARS, 20_000);
});
