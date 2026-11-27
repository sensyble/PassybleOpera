// Test-only: imported before background.js by the e2e copy of the extension. Every native port
// disconnects at once with Chromium's "Specified native messaging host not found.", so a native host
// registered on the test machine (which could start the desktop app) is never reached.
const runtime = globalThis.chrome.runtime;

function missingHost(name) {
  const onDisconnect = new Set();
  let open = true;
  const port = {
    name,
    onMessage: { addListener: () => {}, removeListener: () => {} },
    onDisconnect: { addListener: (f) => onDisconnect.add(f), removeListener: (f) => onDisconnect.delete(f) },
    postMessage() {
      if (!open) throw new Error('Attempting to use a disconnected port object');
      setTimeout(() => {
        if (!open) return;
        open = false;
        for (const f of onDisconnect) f({ ...port, error: { message: 'Specified native messaging host not found.' } });
      }, 0);
    },
    disconnect() { open = false; },
  };
  return port;
}

try {
  runtime.connectNative = missingHost;
} catch { /* read-only binding */ }
if (runtime.connectNative !== missingHost) Object.defineProperty(runtime, 'connectNative', { value: missingHost, configurable: true });
