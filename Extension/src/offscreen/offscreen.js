// Chrome/Edge offscreen document (reason CLIPBOARD): the service worker has no DOM. Messages carry the copy's HMAC
// and the worker's key, never the value. With the vault in this browser it also writes copies the vault released.
import { clearClipboard, writeClipboardText } from '../shared/clipboard.js';

const runtime = (globalThis.browser ?? globalThis.chrome).runtime;

runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.target !== 'offscreen' || sender.id !== runtime.id) return false;
  if (msg.type === 'clipboard.write') {
    if (typeof msg.text !== 'string') return false;
    writeClipboardText(document, msg.text).then((ok) => sendResponse({ result: ok ? 'written' : 'failed' }), () => sendResponse({ result: 'failed' }));
    return true;
  }
  if (msg.type !== 'clipboard.clear') return false;
  if (typeof msg.mac !== 'string' || (msg.key !== null && typeof msg.key !== 'string')) return false;
  clearClipboard(document, { mac: msg.mac, key: msg.key }).then((result) => sendResponse({ result }), () => sendResponse({ result: 'failed' }));
  return true;
});
