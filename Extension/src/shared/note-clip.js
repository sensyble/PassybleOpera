// "Save selection to Passyble note": the text the browser hands the context menu (info.selectionText), cleaned the
// way the agent checks it, and what the chooser shows. The selection only ever goes to the agent; nothing here logs it.

/** A note's text, in characters, as the agent counts them: a new note, and a note with a line added. */
export const MAX_NOTE_CHARS = 20_000;
export const MAX_NOTE_TITLE = 256;

// Control characters the agent refuses: all but tab and line breaks.
const CONTROL_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

/** Characters as the agent counts them (code points, so an emoji is one). */
export function charCount(text) {
  return [...text].length;
}

/** The selection as one block of text: line breaks as `\n`, no control characters, trimmed. */
export function cleanSelection(value) {
  if (typeof value !== 'string') return '';
  return value.replace(/\r\n?/g, '\n').replace(CONTROL_RE, '').trim();
}

function webAddress(url) {
  try {
    const u = new URL(url);
    return u.protocol === 'https:' || u.protocol === 'http:' ? u.href : '';
  } catch {
    return '';
  }
}

/** The text that goes into the note: the selection, and with `withUrl` the page address on the line after it. */
export function clipText(selection, url, withUrl) {
  const text = cleanSelection(selection);
  const address = withUrl ? webAddress(url) : '';
  return address ? `${text}\n${address}` : text;
}

/** The site of a web page without `www.`, or ''. */
export function siteOf(url) {
  const address = webAddress(url);
  return address ? new URL(address).hostname.replace(/^www\./, '') : '';
}

/** A new note's title: the page title on one line, else the site's name. */
export function noteTitleFor(pageTitle, url) {
  const title = typeof pageTitle === 'string' ? pageTitle.replace(/\s+/g, ' ').trim() : '';
  return (title || siteOf(url)).slice(0, MAX_NOTE_TITLE);
}

/** The most recently changed notes first; then by title. */
export function recentFirst(notes) {
  const list = Array.isArray(notes) ? notes.filter((n) => n && typeof n.id === 'string') : [];
  return list.sort((a, b) => (Number(b.updated) || 0) - (Number(a.updated) || 0)
    || String(a.title || '').localeCompare(String(b.title || '')));
}

/** Every word of `query` is in the title (case ignored), as the popup's note search. */
export function titleMatches(title, query) {
  const words = String(query || '').toLowerCase().split(/\s+/).filter(Boolean);
  const lower = String(title || '').toLowerCase();
  return words.every((w) => lower.includes(w));
}
