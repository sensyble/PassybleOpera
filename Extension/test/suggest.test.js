import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { matchLogins } from '../src/content/suggest.js';

const ITEMS = [
  { id: 'a', title: 'Example', username: 'alice@example.com' },
  { id: 'b', title: 'Alpha shop', username: 'bob' },
  { id: 'c', title: 'Work mail', username: 'carol.alice@corp.test' },
  { id: 'd', title: 'Other', username: 'dave' },
];
const ids = (list) => list.map((i) => i.id);

test('empty: every login, in the order given', () => {
  assert.deepEqual(ids(matchLogins(ITEMS, '')), ['a', 'b', 'c', 'd']);
  assert.deepEqual(ids(matchLogins(ITEMS, '   ')), ['a', 'b', 'c', 'd']);
});

test('username prefix first, then title prefix, then a word, then anywhere; case-insensitive', () => {
  assert.deepEqual(ids(matchLogins(ITEMS, 'AL')), ['a', 'b', 'c']);
  assert.deepEqual(ids(matchLogins(ITEMS, 'alice')), ['a', 'c']);
  assert.deepEqual(ids(matchLogins(ITEMS, 'corp')), ['c'], 'a word of the e-mail address');
  assert.deepEqual(ids(matchLogins(ITEMS, 'ave')), ['d'], 'anywhere');
  assert.deepEqual(ids(matchLogins(ITEMS, 'zzz')), []);
});

test('the same kind of match keeps the agent\'s order (best match, favorites, most used)', () => {
  const items = [{ id: 'x', title: 'Mail 2', username: 'm2' }, { id: 'y', title: 'Mail 1', username: 'm1' }];
  assert.deepEqual(ids(matchLogins(items, 'mail')), ['x', 'y']);
});

test('the in-page menu and its icon have no colored glow', () => {
  const src = readFileSync(new URL('../src/content/menu.js', import.meta.url), 'utf8');
  const css = src.slice(src.indexOf('const ICON_CSS'), src.indexOf('const ICON_SIZE '));
  assert.ok(css.length > 100);
  assert.doesNotMatch(css, /--ring/, 'no focus-ring glow');
  assert.doesNotMatch(css, /box-shadow:[^;]*var\(--accent\)/, 'no accent-colored shadow');
  assert.match(css, /\.menu \{[^}]*box-shadow: var\(--shadow\)/, 'the neutral popover shadow stays');
});
