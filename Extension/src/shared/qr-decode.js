// Reads QR codes from a visible-tab screenshot: BarcodeDetector where it supports QR, else the vendored jsQR.
// The image never leaves this page: no network, no native messaging, nothing stored.

/** jsQR is slow on big images: a screenshot is read at most this many pixels on its longer side first. */
export const FIRST_PASS_PX = 1600;
/** Then once more, sharper, up to this (small QR codes on a large or high-DPI screen). */
const SECOND_PASS_PX = 3200;

export function passScales(w, h) {
  const longest = Math.max(Number(w) || 0, Number(h) || 0);
  if (!longest || longest <= FIRST_PASS_PX) return [1];
  const out = [FIRST_PASS_PX / longest, Math.min(1, SECOND_PASS_PX / longest)];
  return out[1] > out[0] ? out : [out[0]];
}

export function dataUrlToBlob(dataUrl) {
  const text = String(dataUrl || '');
  const comma = text.indexOf(',');
  const head = comma > 0 ? text.slice(0, comma) : '';
  const m = /^data:([\w/+.-]+);base64$/i.exec(head);
  if (!m) throw new Error('not a base64 data URL');
  const bin = atob(text.slice(comma + 1));
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type: m[1] });
}

export async function qrDetector(env = globalThis) {
  const Detector = env.BarcodeDetector;
  if (typeof Detector !== 'function') return null;
  try {
    const formats = typeof Detector.getSupportedFormats === 'function' ? await Detector.getSupportedFormats() : [];
    if (!formats.includes('qr_code')) return null;
    return new Detector({ formats: ['qr_code'] });
  } catch {
    return null;
  }
}

/** The vendored jsQR (its UMD build sets `self.jsQR` when imported as a module). */
async function loadJsQr(env = globalThis) {
  const loaded = () => [env.jsQR, globalThis.jsQR].find((f) => typeof f === 'function') || null;
  if (!loaded()) await import('../vendor/jsqr/jsQR.js');
  const jsQR = loaded();
  if (!jsQR) throw new Error('jsQR did not load');
  return jsQR;
}

function pixels(bitmap, scale, env) {
  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = typeof env.OffscreenCanvas === 'function'
    ? new env.OffscreenCanvas(width, height)
    : Object.assign(env.document.createElement('canvas'), { width, height });
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  ctx.imageSmoothingEnabled = scale < 1;
  ctx.drawImage(bitmap, 0, 0, width, height);
  const img = ctx.getImageData(0, 0, width, height);
  return { data: img.data, width, height };
}

/** The texts of the QR codes in a PNG / JPEG data URL, [] when there are none. `deps` are test seams. */
export async function decodeQrImage(dataUrl, { env = globalThis, jsQR = () => loadJsQr(env), pixels: read = (b, s) => pixels(b, s, env) } = {}) {
  const bitmap = await env.createImageBitmap(dataUrlToBlob(dataUrl));
  try {
    const detector = await qrDetector(env);
    if (detector) {
      try {
        const codes = await detector.detect(bitmap);
        return (codes || []).map((c) => c?.rawValue).filter((v) => typeof v === 'string' && v);
      } catch { /* a detector that fails on this image: jsQR below */ }
    }
    const decode = await jsQR();
    for (const scale of passScales(bitmap.width, bitmap.height)) {
      const img = read(bitmap, scale);
      const hit = decode(img.data, img.width, img.height);
      if (typeof hit?.data === 'string' && hit.data) return [hit.data];
    }
    return [];
  } finally {
    bitmap.close?.();
  }
}
