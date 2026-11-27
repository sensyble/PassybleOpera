// Clears the clipboard after a copy. Stores an HMAC of the copied secret and arms an alarm, since the
// service worker may be suspended before the clear is due.
//
// The HMAC key stays in memory only, never in storage.session next to the HMAC, so the stored value
// can't be brute-forced back to a short code. If the worker restarts, the key is gone and it clears
// unconditionally, as when the clipboard can't be read.
import { CLEAR_AFTER_MS, MAX_CLEAR_VALUE_LENGTH, hmacHex, randomKeyHex, clearClipboard, writeClipboardText } from '../shared/clipboard.js';

export const CLEAR_ALARM = 'pass-clipboard-clear';
const STATE_KEY = 'passClipboardClear';
export const OFFSCREEN_URL = 'src/offscreen/offscreen.html';

export function createClipboardClearer({ ext, clearNow, now = Date.now }) {
  let memoryState = null;
  let key = null;
  const session = ext.storage?.session;

  async function save(state) {
    if (session) {
      if (state) await session.set({ [STATE_KEY]: state });
      else await session.remove(STATE_KEY);
    } else {
      memoryState = state;
    }
  }

  async function load() {
    if (!session) return memoryState;
    return (await session.get(STATE_KEY))[STATE_KEY] || null;
  }

  return {
    async schedule(value) {
      if (typeof value !== 'string' || !value || value.length > MAX_CLEAR_VALUE_LENGTH) return false;
      const when = now() + CLEAR_AFTER_MS;
      if (!key) key = randomKeyHex();
      await save({ mac: await hmacHex(key, value), when });
      await ext.alarms.create(CLEAR_ALARM, { when });
      return true;
    },

    async onAlarm(alarm) {
      if (alarm?.name !== CLEAR_ALARM) return null;
      const state = await load();
      if (!state) return null;
      await save(null);
      return clearNow({ mac: String(state.mac || ''), key });
    },
  };
}

export async function clearViaOffscreen(ext, { mac, key }) {
  try {
    await ext.offscreen.createDocument({
      url: OFFSCREEN_URL,
      reasons: ['CLIPBOARD'],
      justification: 'Clear a password or 2FA code Passyble copied, 45 seconds after copying it',
    });
  } catch (err) {
    // Already open is fine.
    if (!/single offscreen|already/i.test(String(err?.message))) throw err;
  }
  try {
    const res = await ext.runtime.sendMessage({ target: 'offscreen', type: 'clipboard.clear', mac, key });
    return res?.result ?? 'failed';
  } finally {
    await ext.offscreen.closeDocument().catch(() => {});
  }
}

export function defaultClearNow(ext) {
  return async (what) => {
    if (ext.offscreen?.createDocument) return clearViaOffscreen(ext, what);
    if (typeof document !== 'undefined') return clearClipboard(document, what); // Firefox event page
    return 'failed';
  };
}

// One offscreen document at a time, so a write and a clear never race.
let offscreenQueue = Promise.resolve();

/** Writes a value the browser vault released as a `copy` effect (offscreen in Chrome/Edge). */
export function writeClipboard(ext, text) {
  const run = offscreenQueue.then(async () => {
    if (!ext.offscreen?.createDocument) {
      if (typeof document !== 'undefined') return writeClipboardText(document, text);
      return false;
    }
    try {
      await ext.offscreen.createDocument({
        url: OFFSCREEN_URL,
        reasons: ['CLIPBOARD'],
        justification: 'Copy a password or 2FA code the user asked Passyble to copy',
      });
    } catch (err) {
      if (!/single offscreen|already/i.test(String(err?.message))) throw err;
    }
    try {
      const res = await ext.runtime.sendMessage({ target: 'offscreen', type: 'clipboard.write', text });
      return res?.result === 'written';
    } finally {
      await ext.offscreen.closeDocument().catch(() => {});
    }
  });
  offscreenQueue = run.catch(() => {});
  return run;
}
