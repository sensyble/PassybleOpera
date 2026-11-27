// Safari has no native messaging host: each message goes with `runtime.sendNativeMessage` to the containing
// app's extension handler. There is no long-lived port, so no pushed events: the lock state comes from the
// next `status`. safariPort() looks like a connectNative Port so NativeClient works unchanged.
import { ErrorCode } from '../shared/errors.js';

/** Safari: sendNativeMessage without Firefox's getBrowserInfo; the user agent tells it from Chromium. */
export function isSafariExtension(scope = globalThis) {
  try {
    const api = scope.browser;
    if (!api?.runtime?.sendNativeMessage || typeof api.runtime.getBrowserInfo === 'function') return false;
    const ua = scope.navigator?.userAgent || '';
    return /Safari\//.test(ua) && !/(Chrome|Chromium|Edg|OPR)\//.test(ua);
  } catch {
    return false;
  }
}

function listeners() {
  const set = new Set();
  return {
    addListener: (fn) => set.add(fn),
    removeListener: (fn) => set.delete(fn),
    hasListener: (fn) => set.has(fn),
    emit: (...args) => { for (const fn of [...set]) { try { fn(...args); } catch { /* the listener's own */ } } },
  };
}

export function safariPort(sendNativeMessage, hostName) {
  const onMessage = listeners();
  const onDisconnect = listeners();
  let open = true;
  return {
    name: hostName,
    onMessage,
    onDisconnect,
    postMessage(msg) {
      if (!open) throw new Error('Port closed');
      const id = msg?.id ?? null;
      Promise.resolve()
        .then(() => sendNativeMessage(hostName, msg))
        .then((reply) => {
          if (!open) return;
          if (reply && typeof reply === 'object' && reply.id !== undefined) onMessage.emit(reply);
          else onMessage.emit({ id, error: { code: 'internal', message: `no reply from the Safari extension handler` } });
        }, (err) => {
          if (!open) return;
          onMessage.emit({ id, error: { code: ErrorCode.AGENT_UNAVAILABLE, message: String(err?.message || err || `sendNativeMessage failed`) } });
        });
    },
    disconnect() {
      open = false;
    },
  };
}
