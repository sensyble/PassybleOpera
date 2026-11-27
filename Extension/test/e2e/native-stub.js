// Test-only, imported before background.js by the e2e copy of the extension: replaces runtime.connectNative with
// a port that sends each request to the mock agent over HTTP. AGENT_URL is filled in when the file is copied.
const AGENT_URL = '__AGENT_URL__';
const HOST = 'com.sensyble.pass';
const runtime = globalThis.chrome.runtime;
const realConnect = runtime.connectNative.bind(runtime);

function connectMock(name) {
  const onMessage = new Set();
  const onDisconnect = new Set();
  let open = true;
  const port = {
    name,
    onMessage: { addListener: (f) => onMessage.add(f), removeListener: (f) => onMessage.delete(f) },
    onDisconnect: { addListener: (f) => onDisconnect.add(f), removeListener: (f) => onDisconnect.delete(f) },
    postMessage(msg) {
      if (!open) throw new Error('Attempting to use a disconnected port object');
      fetch(AGENT_URL, { method: 'POST', body: JSON.stringify(msg) })
        .then((r) => r.json())
        .then((reply) => { if (open) for (const f of onMessage) f(reply); })
        .catch(() => {
          if (!open) return;
          open = false;
          for (const f of onDisconnect) f(port);
        });
    },
    disconnect() { open = false; },
  };
  return port;
}

const patched = (name) => (name === HOST ? connectMock(name) : realConnect(name));
try {
  runtime.connectNative = patched;
} catch { /* read-only binding */ }
if (runtime.connectNative !== patched) Object.defineProperty(runtime, 'connectNative', { value: patched, configurable: true });
