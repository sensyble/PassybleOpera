// The browser's own password manager and autofill compete with Passyble, so the first popup turns them off
// through `privacy.services` (with Undo). Settings controlled by policy or another extension are left alone.

import { ext } from './api.js';

/** storage.local: `{ at, changed }` once the first popup handled it (also when nothing changed). */
export const BROWSER_AUTOFILL_KEY = 'browserAutofillOff';

const BROWSER_AUTOFILL_SETTINGS = ['passwordSavingEnabled', 'autofillAddressEnabled', 'autofillCreditCardEnabled'];

const CONTROLLABLE = new Set(['controllable_by_this_extension', 'controlled_by_this_extension']);

function setting(api, name) {
  return api?.privacy?.services?.[name] ?? null;
}

export async function turnOffBrowserAutofill(api = ext) {
  const changed = [];
  for (const name of BROWSER_AUTOFILL_SETTINGS) {
    const s = setting(api, name);
    if (!s) continue;
    try {
      const { value, levelOfControl } = await s.get({});
      if (value === false || !CONTROLLABLE.has(levelOfControl)) continue;
      await s.set({ value: false });
      changed.push(name);
    } catch {
      // Not supported by this browser version: leave it.
    }
  }
  return changed;
}

/** Undo: `clear` hands the settings back to the browser, which restores the user's own choice. */
export async function restoreBrowserAutofill(names = BROWSER_AUTOFILL_SETTINGS, api = ext) {
  for (const name of names) {
    try {
      await setting(api, name)?.clear({});
    } catch {
    }
  }
}

export async function turnOffOnFirstPopup(api = ext) {
  const stored = await api.storage.local.get(BROWSER_AUTOFILL_KEY);
  if (stored?.[BROWSER_AUTOFILL_KEY]) return null;
  const changed = await turnOffBrowserAutofill(api);
  await api.storage.local.set({ [BROWSER_AUTOFILL_KEY]: { at: Date.now(), changed } });
  return changed;
}
