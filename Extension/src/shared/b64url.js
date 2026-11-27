// base64url (RFC 4648 §5) without padding, as used by the Passyble protocol for all binary values.

/** Returns a Uint8Array view of ArrayBuffer / TypedArray / DataView input. */
export function toBytes(data) {
  if (data instanceof Uint8Array) return data;
  if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  // Cross-realm buffers (e.g. from another frame or a vm context) fail instanceof.
  if (data && Object.prototype.toString.call(data) === '[object ArrayBuffer]') return new Uint8Array(data);
  throw new TypeError('Expected an ArrayBuffer or ArrayBufferView');
}

export function b64urlEncode(data) {
  const bytes = toBytes(data);
  let bin = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + CHUNK));
  }
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Decodes base64url (padding and standard base64 alphabet tolerated). Throws on malformed input. */
export function b64urlDecode(str) {
  if (typeof str !== 'string') throw new TypeError('Expected a base64url string');
  const clean = str.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/]*$/.test(clean) || clean.length % 4 === 1) {
    throw new TypeError('Invalid base64url string');
  }
  const bin = atob(clean + '==='.slice((clean.length + 3) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
