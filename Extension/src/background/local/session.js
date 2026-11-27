// Keeps the unlocked vault key across service worker restarts. A Manifest V3 worker stops after about
// 30 s idle and its WebAssembly memory goes with it. chrome.storage.session is memory only, cleared on
// browser exit or extension reload, and restricted to trusted contexts. Removed on every lock.
// `lastUseAt` carries the idle time over a restart for auto-lock.
import { b64urlDecode, b64urlEncode } from '../../shared/b64url.js';

export const SESSION_KEY = 'passBrowserVault';
export const UNSAVED_KEY = 'passBrowserVaultUnsaved';

export function keySession(area) {
  let memory = null;
  let memoryUnsaved = null;
  try { area?.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' })?.catch?.(() => {}); } catch { /* older browser: the default is trusted contexts */ }
  return {
    async load() {
      const raw = area ? (await area.get(SESSION_KEY))?.[SESSION_KEY] : memory;
      if (!raw || typeof raw.key !== 'string' || typeof raw.vaultId !== 'string') return null;
      try {
        const key = b64urlDecode(raw.key);
        if (key.length !== 32) return null;
        return { key, vaultId: raw.vaultId, lastUseAt: Number(raw.lastUseAt) || 0 };
      } catch {
        return null;
      }
    },
    async save({ key, vaultId, lastUseAt }) {
      const value = { key: b64urlEncode(key), vaultId, lastUseAt };
      if (area) await area.set({ [SESSION_KEY]: value });
      else memory = value;
    },
    async clear() {
      if (area) await area.remove(SESSION_KEY);
      memory = null;
    },
    async keepUnsaved({ vaultId, file, fields = {} }) {
      const value = { vaultId, file: b64urlEncode(file), fields: { ...fields } };
      if (area) await area.set({ [UNSAVED_KEY]: value });
      else memoryUnsaved = value;
    },
    async loadUnsaved() {
      const raw = area ? (await area.get(UNSAVED_KEY))?.[UNSAVED_KEY] : memoryUnsaved;
      if (!raw || typeof raw.vaultId !== 'string' || typeof raw.file !== 'string') return null;
      try {
        const file = b64urlDecode(raw.file);
        if (!file.length) return null;
        const fields = raw.fields && typeof raw.fields === 'object' ? raw.fields : {};
        return { vaultId: raw.vaultId, file, fields };
      } catch {
        return null;
      }
    },
    async clearUnsaved() {
      if (area) await area.remove(UNSAVED_KEY);
      memoryUnsaved = null;
    },
  };
}
