// "Sync now": one sync at a time for every caller, and a call soon after a finished sync gets its answer
// again (a double click, the button and the shortcut together). Errors are never kept.
import { syncResult } from '../shared/sync.js';

export const SYNC_REPEAT_MS = 3_000;

export function createSync({ browserMode, appSync, browserSync, now = Date.now }) {
  let running = null;
  let last = null;

  async function run() {
    const browser = await browserMode();
    const raw = browser ? await browserSync() : await appSync();
    return syncResult({ ...(raw && typeof raw === 'object' ? raw : {}), browser });
  }

  function syncNow() {
    if (running) return running;
    if (last && now() - last.at < SYNC_REPEAT_MS) return Promise.resolve(last.result);
    running = run().then((result) => {
      last = { at: now(), result };
      return result;
    }).finally(() => { running = null; });
    return running;
  }

  return { syncNow };
}
