// Only an HMAC-SHA-256 of the copied value is kept, never the value, under a random in-memory key: a plain hash of a
// 6-digit code is reversed at once. Without read access the clipboard is cleared anyway, since Passyble's copy was
// the last one it knows about.

export const CLEAR_AFTER_MS = 45_000;
export const MAX_CLEAR_VALUE_LENGTH = 1024;

const toHex = (bytes) => [...new Uint8Array(bytes)].map((b) => b.toString(16).padStart(2, '0')).join('');

export function randomKeyHex() {
  return toHex(crypto.getRandomValues(new Uint8Array(32)));
}

export async function hmacHex(keyHex, text) {
  const raw = new Uint8Array((String(keyHex).match(/[0-9a-f]{2}/g) || []).map((b) => parseInt(b, 16)));
  const key = await crypto.subtle.importKey('raw', raw, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(String(text))));
}

function withTimeout(promise, ms) {
  let timer;
  return Promise.race([promise, new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('timeout')), ms); })])
    .finally(() => clearTimeout(timer));
}

/** Clipboard text, or null when the browser does not let this document read it. */
async function readClipboard(doc) {
  const clip = doc.defaultView?.navigator?.clipboard;
  if (clip?.readText) {
    try { return await withTimeout(clip.readText(), 1000); } catch { /* not allowed here */ }
  }
  // Chrome offscreen documents: execCommand('paste') works only with the clipboardRead permission.
  const ta = doc.createElement('textarea');
  try {
    doc.body.appendChild(ta);
    ta.focus();
    if (doc.execCommand?.('paste')) return ta.value;
  } catch { /* not allowed */ } finally {
    ta.remove();
  }
  return null;
}

export async function writeEmptyClipboard(doc) {
  const clip = doc.defaultView?.navigator?.clipboard;
  if (clip?.writeText) {
    try { await withTimeout(clip.writeText(''), 1000); return true; } catch { /* e.g. offscreen: not focused */ }
  }
  // execCommand('copy') needs a selection; the copy handler swaps the selected space for ''.
  const ta = doc.createElement('textarea');
  ta.value = ' ';
  const onCopy = (e) => {
    e.clipboardData?.setData('text/plain', '');
    e.preventDefault();
  };
  doc.addEventListener('copy', onCopy, true);
  try {
    doc.body.appendChild(ta);
    ta.select();
    return !!doc.execCommand?.('copy');
  } catch {
    return false;
  } finally {
    doc.removeEventListener('copy', onCopy, true);
    ta.remove();
  }
}

/** Clears the clipboard unless it is readable and no longer holds the copied value. Without `key` it clears. */
export async function clearClipboard(doc, { mac = '', key = null } = {}) {
  const current = typeof key === 'string' && key ? await readClipboard(doc) : null;
  if (current !== null && (await hmacHex(key, current)) !== mac) return 'changed';
  return (await writeEmptyClipboard(doc)) ? 'cleared' : 'failed';
}

/** Writes `text` without a user gesture (offscreen document). A browser cannot keep this out of Windows clipboard history. */
export async function writeClipboardText(doc, text) {
  const value = String(text ?? '');
  const clip = doc.defaultView?.navigator?.clipboard;
  if (clip?.writeText) {
    try { await withTimeout(clip.writeText(value), 1000); return true; } catch { /* offscreen: not focused */ }
  }
  const ta = doc.createElement('textarea');
  ta.value = value;
  try {
    doc.body.appendChild(ta);
    ta.select();
    return !!doc.execCommand?.('copy');
  } catch {
    return false;
  } finally {
    ta.value = '';
    ta.remove();
  }
}
