// No `downloads` permission: saving is an <a download> of a Blob in the page itself.
import { b64urlDecode, b64urlEncode } from './b64url.js';

/** Saves `{ file, name }` (from `vault.export`) as a download of the page `doc`. */
export function downloadVaultFile({ file, name }, doc = globalThis.document) {
  const blob = new Blob([b64urlDecode(file)], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = doc.createElement('a');
  a.href = url;
  a.download = name || 'Passyble.vault';
  a.hidden = true;
  doc.body.append(a);
  try {
    a.click();
  } finally {
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 60_000);
  }
}

/** A picked File as base64url, for `vault.open-file`. */
export async function readVaultFile(file) {
  return b64urlEncode(new Uint8Array(await file.arrayBuffer()));
}
