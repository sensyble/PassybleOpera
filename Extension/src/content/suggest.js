// Filters the in-page menu's logins by what the user typed into the username field.

const WORD_RE = /[^\p{L}\p{N}]+/u;

/** Rank of `item` for lower-case `query`: 0 username prefix, 1 title prefix, 2 word prefix, 3 substring, -1 none. */
function score(item, query) {
  const username = String(item.username || '').toLowerCase();
  const title = String(item.title || '').toLowerCase();
  if (username.startsWith(query)) return 0;
  if (title.startsWith(query)) return 1;
  const words = [...username.split(WORD_RE), ...title.split(WORD_RE)];
  if (words.some((w) => w && w.startsWith(query))) return 2;
  if (username.includes(query) || title.includes(query)) return 3;
  return -1;
}

/** Logins matching `typed`, best first. Ties keep the given order. An empty `typed` keeps all. */
export function matchLogins(items, typed) {
  const query = String(typed || '').trim().toLowerCase();
  if (!query) return [...items];
  return items
    .map((item, i) => ({ item, i, s: score(item, query) }))
    .filter((x) => x.s >= 0)
    .sort((a, b) => a.s - b.s || a.i - b.i)
    .map((x) => x.item);
}
