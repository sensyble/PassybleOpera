// Chromium lets only the browser change a shortcut (Options opens its shortcuts page); Firefox has no such page
// but lets the extension set its own with `commands.update`.
import { t } from './i18n.js';
import { chromiumPlatform, Platform } from './app-versions.js';

export const COMMAND_ORDER = Object.freeze(['_execute_action', 'fill-login', 'fill-otp', 'scan-qr', 'generate-password', 'new-note', 'lock', 'sync-now']);

export function commandLabel(name) {
  const labels = {
    _execute_action: t('optionsShortcutOpenPopup'),
    'fill-login': t('optionsShortcutFillLogin'),
    'fill-otp': t('optionsShortcutFillOtp'),
    'scan-qr': t('optionsShortcutScanQr'),
    'generate-password': t('optionsShortcutGenerate'),
    'new-note': t('optionsShortcutNewNote'),
    lock: t('optionsShortcutLock'),
    'sync-now': t('optionsShortcutSync'),
  };
  return labels[name] || '';
}

export function sortCommands(commands) {
  const rank = (name) => {
    const i = COMMAND_ORDER.indexOf(name);
    return i < 0 ? COMMAND_ORDER.length : i;
  };
  return (Array.isArray(commands) ? commands : [])
    .filter((c) => c && typeof c.name === 'string' && c.name)
    .map((c, i) => ({ name: c.name, label: commandLabel(c.name) || c.description || c.name, shortcut: typeof c.shortcut === 'string' ? c.shortcut : '', i }))
    .sort((a, b) => rank(a.name) - rank(b.name) || a.i - b.i)
    .map(({ i, ...c }) => c);
}

export function shortcutsPageUrl({ gecko = false, nav = globalThis.navigator } = {}) {
  if (gecko) return null;
  return chromiumPlatform(nav) === Platform.EDGE ? 'edge://extensions/shortcuts' : 'chrome://extensions/shortcuts';
}

// Firefox's shortcut keys (MDN, manifest.json `commands`), by `KeyboardEvent.code`.
const NAMED_KEYS = Object.freeze({
  Comma: 'Comma', Period: 'Period', Space: 'Space', Home: 'Home', End: 'End', PageUp: 'PageUp', PageDown: 'PageDown',
  Insert: 'Insert', Delete: 'Delete', ArrowUp: 'Up', ArrowDown: 'Down', ArrowLeft: 'Left', ArrowRight: 'Right',
});

function keyName(code) {
  const c = String(code || '');
  let m = /^Key([A-Z])$/.exec(c);
  if (m) return m[1];
  m = /^(?:Digit|Numpad)([0-9])$/.exec(c);
  if (m) return m[1];
  if (/^F(?:[1-9]|1[0-2])$/.test(c)) return c;
  return NAMED_KEYS[c] || '';
}

/** A key press as Firefox's shortcut text for `commands.update`; `{ shortcut: '' }` while only modifiers are down, `{ error }` when Firefox refuses it. */
export function shortcutFromKeyEvent(e, { mac = false } = {}) {
  if (!e || ['Shift', 'Control', 'Alt', 'Meta', 'OS', 'AltGraph'].includes(e.key)) return { shortcut: '' };
  const key = keyName(e.code);
  if (!key) return { error: 'key' };
  const mods = [];
  // In the order Firefox's own shortcut page writes them.
  if (mac) {
    if (e.ctrlKey) mods.push('MacCtrl');
    if (e.altKey) mods.push('Alt');
    if (e.metaKey) mods.push('Command');
  } else {
    if (e.ctrlKey) mods.push('Ctrl');
    if (e.altKey) mods.push('Alt');
  }
  const real = mods.length;
  if (e.shiftKey) mods.push('Shift');
  // A function key works alone; anything else (and Shift with a function key) needs a real modifier.
  if (!real && (mods.length || !/^F\d+$/.test(key))) return { error: 'modifier' };
  // Firefox takes two modifiers at most (a modifier and a second one, such as Shift).
  if (mods.length > 2) return { error: 'modifier' };
  return { shortcut: [...mods, key].join('+') };
}
