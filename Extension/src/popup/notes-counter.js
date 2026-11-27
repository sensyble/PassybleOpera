// The counter under a notes box (the editor's Notes, New note): shown from 90% of the cap pass-core puts on notes.
import { t } from '../shared/i18n.js';
import { MAX_NOTE_CHARS } from '../shared/note-clip.js';

/** `null` below 90% of `max`, else `{ count, max, full }`; `length` as the box's `maxlength` counts it. */
export function notesCount(length, max = MAX_NOTE_CHARS) {
  if (length < max * 0.9) return null;
  return { count: length, max, full: length >= max };
}

/** A line that follows `box` (a textarea with `maxlength`), updated as the user types. */
export function notesCounter(box) {
  const line = document.createElement('p');
  line.className = 'ed-note ed-count';
  line.setAttribute('aria-live', 'polite');
  const update = () => {
    const c = notesCount(box.value.length);
    line.hidden = !c;
    line.textContent = c ? t('editorNotesCount', c.count, c.max) : '';
    line.classList.toggle('full', !!c?.full);
  };
  box.addEventListener('input', update);
  update();
  return line;
}
