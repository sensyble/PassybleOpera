// Classic content scripts cannot be modules, so this imports main.js. main.js and its imports are
// listed in web_accessible_resources so import() can reach them.
(() => {
  'use strict';
  const ext = globalThis.browser ?? globalThis.chrome;
  let alive = false;
  try { alive = !!ext?.runtime?.id; } catch { /* context invalidated */ }
  if (!alive) return;
  // A previous instance (e.g. before an extension update) leaves a stale flag with a dead runtime.
  if (globalThis.__passContent?.alive()) return;
  globalThis.__passContent = { alive: () => { try { return !!ext.runtime.id; } catch { return false; } } };
  // A passkey request the page makes meanwhile waits for main.js to show its card (bridge.js).
  try { globalThis.__passBridge?.contentStarting?.(); } catch { /* an older bridge */ }
  import(ext.runtime.getURL('src/content/main.js'))
    .then((m) => m.start())
    .catch((err) => console.debug('[Passyble] content script not started:', err));
})();
