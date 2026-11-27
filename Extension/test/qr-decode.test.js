// Reading QR codes from a screenshot (src/shared/qr-decode.js): the browser's BarcodeDetector where it reads QR codes,
// else the vendored jsQR, run for real here on a demo QR code (test/fixtures/qr-otpauth-demo.json).
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dataUrlToBlob, decodeQrImage, passScales, qrDetector, FIRST_PASS_PX } from '../src/shared/qr-decode.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/qr-otpauth-demo.json', import.meta.url), 'utf8'));
const PNG = 'data:image/png;base64,iVBORw0KGgo=';

before(() => {
  // The vendored jsQR is a UMD build: imported as a module it sets `self.jsQR`, as in the popup.
  globalThis.self ??= globalThis;
});

/** The fixture's modules as RGBA pixels, `scale` px per module (black on white). */
function render(scale) {
  const n = fixture.rows.length;
  const w = n * scale;
  const data = new Uint8ClampedArray(w * w * 4);
  for (let y = 0; y < w; y++) {
    for (let x = 0; x < w; x++) {
      const v = fixture.rows[Math.floor(y / scale)][Math.floor(x / scale)] === '1' ? 0 : 255;
      data.set([v, v, v, 255], (y * w + x) * 4);
    }
  }
  return { data, width: w, height: w };
}

/** createImageBitmap stand-in: a bitmap of `w` x `h` that records being closed. */
function bitmaps(w, h) {
  const made = [];
  return {
    made,
    createImageBitmap: async (blob) => {
      assert.ok(blob instanceof Blob);
      const b = { width: w, height: h, closed: false, close() { this.closed = true; } };
      made.push(b);
      return b;
    },
  };
}

test('passScales: small screenshots once at full size; big ones smaller first, then sharper', () => {
  assert.deepEqual(passScales(1280, 720), [1]);
  assert.deepEqual(passScales(FIRST_PASS_PX, 900), [1]);
  assert.deepEqual(passScales(3200, 1800), [0.5, 1]);
  const [a, b] = passScales(6400, 3600);
  assert.equal(a, 0.25);
  assert.equal(b, 0.5);
  assert.deepEqual(passScales(0, 0), [1]);
});

test('dataUrlToBlob: a base64 data URL as a Blob of its type; anything else throws', async () => {
  const blob = dataUrlToBlob('data:image/png;base64,AAEC');
  assert.equal(blob.type, 'image/png');
  assert.deepEqual([...new Uint8Array(await blob.arrayBuffer())], [0, 1, 2]);
  assert.throws(() => dataUrlToBlob('https://example.com/x.png'));
  assert.throws(() => dataUrlToBlob('data:image/png,plain'));
});

test('BarcodeDetector where it reads QR codes: every QR code it finds; jsQR is not loaded', async () => {
  const env = bitmaps(1920, 1080);
  const seen = [];
  env.BarcodeDetector = class {
    static async getSupportedFormats() { return ['ean_13', 'qr_code']; }
    constructor(opts) { seen.push(opts); }
    async detect(bitmap) { assert.equal(bitmap, env.made[0]); return [{ rawValue: fixture.text }, { rawValue: 'https://example.com/' }, { rawValue: '' }]; }
  };
  const texts = await decodeQrImage(PNG, { env, jsQR: () => { throw new Error('jsQR must not load'); } });
  assert.deepEqual(texts, [fixture.text, 'https://example.com/']);
  assert.deepEqual(seen, [{ formats: ['qr_code'] }]);
  assert.equal(env.made[0].closed, true, 'the bitmap is let go');
});

test('no BarcodeDetector for QR codes (Chrome on Windows, Firefox, Safari): the vendored jsQR reads the demo code', async () => {
  for (const Detector of [undefined, class { static async getSupportedFormats() { return []; } }]) {
    const env = bitmaps(fixture.rows.length * 4, fixture.rows.length * 4);
    env.BarcodeDetector = Detector;
    assert.equal(await qrDetector(env), null);
    const scales = [];
    const texts = await decodeQrImage(PNG, { env, pixels: (bitmap, scale) => { scales.push(scale); return render(4); } });
    assert.deepEqual(texts, [fixture.text], 'decoded by the real jsQR');
    assert.deepEqual(scales, [1]);
    assert.equal(env.made[0].closed, true);
  }
  assert.equal(typeof globalThis.jsQR, 'function', 'loaded on demand from src/vendor/jsqr/');
});

test('jsQR: a big screenshot is read smaller first, then sharper; nothing found is []', async () => {
  const env = bitmaps(4000, 2000);
  const scales = [];
  const blank = { data: new Uint8ClampedArray(40 * 40 * 4).fill(255), width: 40, height: 40 };
  const texts = await decodeQrImage(PNG, { env, pixels: (bitmap, scale) => { scales.push(scale); return scales.length === 1 ? blank : render(3); } });
  assert.deepEqual(scales, [0.4, 0.8]);
  assert.deepEqual(texts, [fixture.text]);

  const none = bitmaps(800, 600);
  assert.deepEqual(await decodeQrImage(PNG, { env: none, pixels: () => blank }), []);
  assert.equal(none.made[0].closed, true);
});

test('a detector that fails on the image falls back to jsQR', async () => {
  const env = bitmaps(200, 200);
  env.BarcodeDetector = class {
    static async getSupportedFormats() { return ['qr_code']; }
    async detect() { throw new Error('backend failed'); }
  };
  assert.deepEqual(await decodeQrImage(PNG, { env, pixels: () => render(4) }), [fixture.text]);
});
