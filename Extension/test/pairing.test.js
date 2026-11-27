// Pairing link parser (src/shared/pairing.js) against pass-core's vectors.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { parsePairingLink, extractPairingLink, MAX_LINK_LEN } from '../src/shared/pairing.js';
import { PassError } from '../src/shared/errors.js';

/** `{ ok: true, info }` or `{ ok: false, message }` (the PassError's user-facing message). */
function checkPairingLink(input) {
  try {
    return { ok: true, info: parsePairingLink(input) };
  } catch (err) {
    return { ok: false, message: PassError.from(err).message };
  }
}

const { vectors } = JSON.parse(readFileSync(new URL('../../Core/core/tests/pairing_vectors.json', import.meta.url), 'utf8'));

test('accepts every valid vector with the same fields as pass-core (minus the token)', () => {
  const valid = vectors.filter((v) => v.expect);
  assert.ok(valid.length >= 5);
  for (const { link, expect } of valid) {
    const info = parsePairingLink(link);
    assert.deepEqual(info, {
      kind: 'pairing', codeKind: null, url: expect.url, host: expect.host, username: expect.username, deviceName: expect.device_name,
      pins: expect.pins, https: expect.https,
    }, link);
    assert.ok(!JSON.stringify(info).includes(expect.token), 'token never returned');
  }
});

test('accepts every sign-in vector (no token) like pass_core::parse_server_link, never returning the code', () => {
  const signin = vectors.filter((v) => v.signin);
  assert.ok(signin.length >= 5);
  for (const { link, signin: want } of signin) {
    const info = parsePairingLink(link);
    assert.equal(info.kind, 'invite', link);
    assert.equal(info.url, want.server_url, link);
    assert.equal(info.host, want.host, link);
    assert.equal(info.username, want.username, link);
    assert.deepEqual(info.pins, want.pins, link);
    assert.equal(info.https, want.https, link);
    assert.equal(info.codeKind, want.code ? want.code[0] : null, link);
    if (want.code) assert.ok(!JSON.stringify(info).includes(want.code[1]), 'code never returned');
  }
});

test('rejects every invalid vector with invalid_params and a message', () => {
  const invalid = vectors.filter((v) => !v.expect && !v.signin);
  assert.ok(invalid.length >= 10);
  for (const { link } of invalid) {
    assert.throws(() => parsePairingLink(link), (err) => err.code === 'invalid_params' && err.message.length > 5, link);
  }
});

test('links without a token are sign-in links (invites); token and codes are exclusive', () => {
  const info = parsePairingLink('pass+server://pass.example.com:8443/?v=1&user=alice&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g');
  assert.deepEqual(info, {
    kind: 'invite', codeKind: null, url: 'https://pass.example.com:8443', host: 'pass.example.com:8443',
    username: 'alice', deviceName: null, pins: ['sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g'], https: true,
  });
  assert.equal(parsePairingLink('pass+server://h/?v=1&user=a&invite=psc_1').codeKind, 'invite');
  assert.equal(parsePairingLink('pass+server://h/?v=1&user=a&reset=psc_1').codeKind, 'reset');
  assert.equal(parsePairingLink('pass+server://h/p?v=1&user=a&token=pst_t').kind, 'pairing');
  for (const bad of ['pass+server://h/p?user=a', 'pass+server://h/p?v=2&user=a', 'pass+server://h/p?v=1',
    'pass+server://h/p?v=1&user=', 'pass+server:///p?v=1&user=a', 'pass+server://h/p?v=1&user=a&token=',
    'pass+server://h/?v=1&user=a&invite=', 'pass+server://h/?v=1&user=a&invite=x&reset=y',
    'pass+server://h/dav/a/p.vault?v=1&user=a&token=t&invite=x', 'pass+server://h?v=1&user=a&token=t']) {
    assert.equal(checkPairingLink(bad).ok, false, bad);
  }
});

test('trims surrounding whitespace; rejects empty and over-long links', () => {
  const link = 'pass+server://h/dav/a.vault?v=1&user=a&token=pst_t';
  assert.equal(parsePairingLink(`\n  ${link}  \r\n`).host, 'h');
  assert.equal(checkPairingLink('').ok, false);
  assert.equal(checkPairingLink(undefined).ok, false);
  const long = `${link}&x=${'a'.repeat(MAX_LINK_LEN)}`;
  assert.match(checkPairingLink(long).message, /too long/);
});

test('version and unknown parameters: v=2 asks to update, unknown keys are ignored', () => {
  assert.match(checkPairingLink('pass+server://h/p?v=2&user=a&token=t').message, /from a newer Passyble Server/);
  assert.equal(checkPairingLink('pass+server://h/p?v=1&user=a&token=t&later=x').ok, true);
});

test('error messages never contain the token', () => {
  const token = 'pst_SECRETSECRETSECRET';
  for (const link of [`pass+server://h/p?v=3&user=a&token=${token}`, `pass+server://h/p?v=1&user=a&token=${token}&scheme=ftp`,
    `pass+server://h/p?v=1&user=a&token=${token}&pin=md5:x`, `pass+server://h?v=1&user=a&token=${token}`]) {
    const res = checkPairingLink(link);
    assert.equal(res.ok, false, link);
    assert.ok(!res.message.includes(token), res.message);
  }
});

test('extractPairingLink finds the link in pasted or dropped text', () => {
  const link = 'pass+server://h/dav/a.vault?v=1&user=a&token=pst_t&name=My%20PC';
  assert.equal(extractPairingLink(`Pairing link:\n  ${link}\n(scan the QR code)`), link);
  assert.equal(extractPairingLink(`"${link}"`), link);
  assert.equal(extractPairingLink('  not a link  '), 'not a link');
  assert.equal(extractPairingLink(null), '');
});

test('error messages are plain language: no parameter names, schemes, encodings or pins', () => {
  const bad = [
    'pass+server://h/p?user=a&token=t', // no version
    'pass+server://h/p?v=2&user=a&token=t', // newer version
    'pass+server://h/p?v=1&token=t', // no account
    'pass+server://h/p?v=1&user=a&token=', // empty token
    'pass+server://h?v=1&user=a&token=t', // no path
    'pass+server://h/p?v=1&user=a&token=t&invite=x', // token and code
    'pass+server://h?v=1&user=a&invite=x&reset=y', // two codes
    'pass+server://h/p?v=1&user=a&token=t&scheme=ftp', // scheme
    'pass+server://h/p?v=1&user=a&token=t&pin=md5:x', // pin
    'pass+server://h/p?v=1&user=%ZZ%C3%28&token=t', // bad percent-encoding
    'pass+server://@h/p?v=1&user=a&token=t', // no address
    'https://example.com', // not a link
  ];
  const DEV = /\b(?:v=1|user=|token=|token|scheme|percent|encoding|pin|pins|non-empty|query|parameter)\b|[?&]\w+=/i;
  for (const link of bad) {
    const res = checkPairingLink(link);
    assert.equal(res.ok, false, link);
    assert.ok(res.message && !DEV.test(res.message), `${link}: ${res.message}`);
  }
});
