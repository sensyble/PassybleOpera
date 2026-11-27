// The note text lives in this view's DOM only and is dropped when the view closes. Copy goes through the agent
// (kept out of clipboard history, cleared after 45 s); only an app that can't copy leaves it to the browser's clipboard.
import { t } from '../shared/i18n.js';
import { icon } from '../shared/svg-icon.js';
import { friendlyError } from '../shared/messages.js';

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === undefined || v === null || v === false) continue;
    if (k === 'class') node.className = v;
    else if (k.startsWith('on')) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v === true ? '' : String(v));
  }
  for (const c of children.flat()) if (c !== null && c !== undefined && c !== false) node.append(c instanceof Node ? c : String(c));
  return node;
}

export function mountNoteViewer({ body, setHeading, call, showView, onClose, snack, copy }) {
  let current = null; // { id, text } of the note on screen
  let seq = 0;        // the latest open wins; Close calls off one still on its way

  const report = (err) => { if (err?.code !== 'cancelled') snack(friendlyError(err)); };

  function clear() {
    current = null;
    body.replaceChildren();
  }

  function close() {
    seq++;
    clear();
    onClose();
  }

  async function open(note) {
    const mine = ++seq;
    let res;
    try {
      res = await call('popup.note-get', { id: note.id });
    } catch (err) {
      if (mine === seq) report(err);
      return;
    }
    if (mine !== seq) return;
    const text = typeof res?.notes === 'string' ? res.notes : '';
    current = { id: note.id, text };
    setHeading(res?.title || note.title || t('popupUntitled'));
    const content = text
      ? el('pre', { class: 'note-text', id: 'note-text', tabindex: 0, 'aria-label': t('popupNoteText') }, text)
      : el('p', { class: 'muted note-empty', id: 'note-text' }, t('popupNoteEmpty'));
    const closeBtn = el('button', { class: 'btn', type: 'button', id: 'note-close', onclick: () => close() }, t('commonClose'));
    const copyBtn = el('button', { class: 'btn primary', type: 'button', id: 'note-copy', disabled: !text,
      onclick: () => copyNote(note) }, icon('copy'), t('popupCopyNote'));
    body.replaceChildren(content, el('div', { class: 'ed-actions note-actions' }, closeBtn, copyBtn));
    showView();
    content.focus?.();
  }

  async function copyNote(note) {
    try {
      const res = await call('popup.note-get', { id: note.id, copy: true });
      snack(res?.copied === true ? t('popupCopiedNoteClears') : t('popupNoteEmpty'));
    } catch (err) {
      // An app that can't copy: the text on screen goes through the browser's clipboard instead.
      if (err?.code === 'not_supported' && current?.id === note.id && current.text) {
        await copy(current.text, 'note');
        return;
      }
      report(err);
    }
  }

  return {
    open,
    copy: copyNote,
    close,
    clear,
    get isOpen() { return current !== null; },
  };
}
