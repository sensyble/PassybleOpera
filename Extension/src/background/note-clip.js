// "Save selection to Passyble note" (context menu on selected text). The click keeps the browser's selection text
// (info.selectionText, no page access beyond it) under a one-time token and opens a small chooser window
// (src/clip/clip.html), which takes it once and adds it to a note (`notes.append`) or saves a new one
// (`notes.create`). The selection goes to the agent only and is never logged or stored.
import { ErrorCode, PassError } from '../shared/errors.js';
import { MAX_NOTE_CHARS, charCount, cleanSelection, noteTitleFor, recentFirst, siteOf } from '../shared/note-clip.js';

export const MENU_SAVE_SELECTION = 'pass-save-selection';
export const CLIP_TTL_MS = 2 * 60_000;
const NOTES_LIMIT = 200;
const WINDOW_SIZE = Object.freeze({ width: 380, height: 540 });

export function createNoteClip({ ext, agent, editCall, noteFields, itemId, now = Date.now }) {
  const clips = new Map(); // token -> { text, url, title, at }

  function prune() {
    for (const [token, clip] of clips) if (now() - clip.at > CLIP_TTL_MS) clips.delete(token);
  }

  async function chooserPlace(tab) {
    try {
      const w = await ext.windows.get(tab.windowId);
      return {
        left: Math.round(w.left + Math.max(0, (w.width - WINDOW_SIZE.width) / 2)),
        top: Math.round(w.top + Math.max(0, Math.min(120, (w.height - WINDOW_SIZE.height) / 2))),
      };
    } catch {
      return {}; // the browser places it
    }
  }

  /** The menu was clicked: keep the selection for the chooser and open it. */
  async function onMenuClick(info, tab) {
    const text = cleanSelection(info?.selectionText);
    if (!text) return { opened: false };
    prune();
    const url = siteOf(info?.pageUrl) ? info.pageUrl : siteOf(tab?.url) ? tab.url : '';
    const token = crypto.randomUUID();
    clips.set(token, { text, url, title: noteTitleFor(tab?.title, url), at: now() });
    await ext.windows.create({
      url: ext.runtime.getURL(`src/clip/clip.html?clip=${encodeURIComponent(token)}`),
      type: 'popup', focused: true, ...WINDOW_SIZE, ...(await chooserPlace(tab)),
    });
    return { opened: true };
  }

  function features(status) {
    const list = Array.isArray(status?.features) ? status.features : [];
    return { can_append: list.includes('notes.append') && list.includes('notes.list'), can_create: list.includes('notes.create') };
  }

  /** The text to add, checked as the agent will. */
  function clipParam(value) {
    const text = cleanSelection(value);
    if (!text) throw new PassError(ErrorCode.INVALID_PARAMS, 'Nothing to add');
    if (charCount(text) > MAX_NOTE_CHARS) throw new PassError(ErrorCode.INVALID_PARAMS, 'The selection is too long');
    return text;
  }

  const pageHandlers = {
    /** The chooser's selection, once: its token is then spent. */
    async 'clip.take'(msg) {
      prune();
      const token = typeof msg.token === 'string' ? msg.token : '';
      const clip = clips.get(token);
      if (!clip) throw new PassError(ErrorCode.NOT_FOUND, 'This selection is gone');
      clips.delete(token);
      return { text: clip.text, url: clip.url, site: siteOf(clip.url), title: clip.title };
    },

    /** What the chooser can offer: the notes (titles only, most recent first), or `locked`. */
    async 'clip.state'() {
      const status = await agent('status');
      const can = features(status);
      if (!can.can_append) return { ...can, locked: !!status?.locked, notes: [] };
      if (status?.locked && !status?.soft_locked) return { ...can, locked: true, notes: [] };
      try {
        const res = await agent('notes.list', { limit: NOTES_LIMIT });
        return { ...can, locked: !!res?.locked, notes: recentFirst(res?.items), vaults: Array.isArray(res?.vaults) ? res.vaults : [] };
      } catch (err) {
        if (PassError.from(err).code === ErrorCode.LOCKED) return { ...can, locked: true, notes: [] };
        throw err;
      }
    },

    /** The desktop app's unlock prompt, or the browser vault's own ask. */
    async 'clip.unlock'() {
      await agent('unlock');
      return { locked: false };
    },

    async 'clip.append'(msg) {
      const res = await editCall('notes.append', { id: itemId(msg.id), text: clipParam(msg.text) }, { prompt: true });
      return { id: res?.id, title: res?.title };
    },

    async 'clip.create'(msg) {
      const text = clipParam(msg.text);
      const res = await editCall('notes.create', { fields: noteFields({ title: msg.title, notes: text }) }, { prompt: true });
      return { id: res?.id, title: res?.title };
    },
  };

  return { onMenuClick, pageHandlers };
}
