import { test } from 'node:test';
import assert from 'node:assert/strict';
import { b64urlEncode, b64urlDecode, toBytes } from '../src/shared/b64url.js';

test('encodes without padding using the URL-safe alphabet', () => {
  assert.equal(b64urlEncode(new Uint8Array([])), '');
  assert.equal(b64urlEncode(new Uint8Array([1, 2, 3])), 'AQID');
  assert.equal(b64urlEncode(new Uint8Array([0xfb, 0xff])), '-_8');
  assert.equal(b64urlEncode(new Uint8Array([0xff])), '_w');
  assert.equal(b64urlEncode(new TextEncoder().encode('hello')), 'aGVsbG8');
});

test('accepts ArrayBuffer, typed array views and DataView (respecting offsets)', () => {
  const buf = new Uint8Array([9, 1, 2, 3, 9]).buffer;
  assert.equal(b64urlEncode(buf), 'CQECAwk');
  assert.equal(b64urlEncode(new Uint8Array(buf, 1, 3)), 'AQID');
  assert.equal(b64urlEncode(new DataView(buf, 1, 3)), 'AQID');
  assert.equal(b64urlEncode(new Uint16Array([0x0201])), 'AQI');
  assert.throws(() => toBytes('nope'), TypeError);
});

test('round-trips random data of every length mod 3', () => {
  for (let len = 0; len < 70; len++) {
    const data = new Uint8Array(len).map((_, i) => (i * 37 + len) & 0xff);
    assert.deepEqual(b64urlDecode(b64urlEncode(data)), data);
  }
});

test('large inputs do not overflow the call stack', () => {
  const big = new Uint8Array(200_000).fill(7);
  assert.equal(b64urlDecode(b64urlEncode(big)).length, big.length);
});

test('decodes padded and standard-alphabet input, rejects garbage', () => {
  assert.deepEqual(b64urlDecode('AQID'), new Uint8Array([1, 2, 3]));
  assert.deepEqual(b64urlDecode('_w=='), new Uint8Array([0xff]));
  assert.deepEqual(b64urlDecode('+/8'), new Uint8Array([0xfb, 0xff]));
  assert.throws(() => b64urlDecode('a'), TypeError);
  assert.throws(() => b64urlDecode('ab$c'), TypeError);
  assert.throws(() => b64urlDecode(42), TypeError);
});
