import { test } from 'node:test';
import assert from 'node:assert/strict';
import { notesCount } from '../src/popup/notes-counter.js';
import { MAX_NOTE_CHARS } from '../src/shared/note-clip.js';

test('the notes counter shows from 90% of the 20,000 character cap', () => {
  assert.equal(MAX_NOTE_CHARS, 20_000);
  assert.equal(notesCount(0), null);
  assert.equal(notesCount(17_999), null);
  assert.deepEqual(notesCount(18_000), { count: 18_000, max: 20_000, full: false });
  assert.deepEqual(notesCount(20_000), { count: 20_000, max: 20_000, full: true });
});
