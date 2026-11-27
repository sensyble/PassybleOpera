// "Add Passyble Server" input (src/shared/pairing.js): plain server addresses (like pass-core's
// normalize_server_url) and pass+server:// links picked out of surrounding text.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeServerAddress, parseServerInput, checkServerInput, extractPairingLink } from '../src/shared/pairing.js';

const LINK = 'pass+server://pass.example.com/dav/alice/personal.vault?v=1&user=alice&token=pst_t0k3n';

test('normalizeServerAddress: the forms people type', () => {
  for (const [input, url, host, https] of [
    ['pass.example.com', 'https://pass.example.com', 'pass.example.com', true],
    ['pass.example.com/', 'https://pass.example.com', 'pass.example.com', true],
    ['  pass.example.com:8443  ', 'https://pass.example.com:8443', 'pass.example.com:8443', true],
    ['https://pass.example.com', 'https://pass.example.com', 'pass.example.com', true],
    ['https://pass.example.com:443/', 'https://pass.example.com', 'pass.example.com', true],
    ['HTTPS://Pass.Example.COM/pass/', 'https://pass.example.com/pass', 'pass.example.com', true],
    ['https://example.com/tools/pass//', 'https://example.com/tools/pass', 'example.com', true],
    ['http://192.168.1.20:8080', 'http://192.168.1.20:8080', '192.168.1.20:8080', false],
    ['http://localhost:8080/', 'http://localhost:8080', 'localhost:8080', false],
    ['[::1]:8443', 'https://[::1]:8443', '[::1]:8443', true],
    ['pass\n', 'https://pass', 'pass', true],
  ]) {
    assert.deepEqual(normalizeServerAddress(input), { url, host, https }, JSON.stringify(input));
  }
});

test('normalizeServerAddress: refuses what pass-core refuses, with a message', () => {
  for (const [input, message] of [
    ['', /Enter the address/],
    ['   ', /Enter the address/],
    ['alice@example.com', /e-mail address/],
    ['https://alice@pass.example.com', /user name or password/],
    ['https://alice:secret@pass.example.com/', /user name or password/],
    ['pass.example.com/?token=x', /without the rest of the web address/],
    ['pass.example.com#top', /without the rest of the web address/],
    ['https://pass.example.com/?', /without the rest of the web address/],
    ['ftp://pass.example.com', /https:\/\//],
    ['pass+server://x', /https:\/\//],
    ['javascript://alert(1)', /https:\/\//],
    ['https://', /isn't a valid server address/],
    ['https:/pass.example.com', /isn't a valid server address/],
    ['pass example.com', /no spaces/],
    ['pass.example.com:99999', /isn't a valid server address/],
    ['x'.repeat(5000), /too long/],
  ]) {
    assert.throws(() => normalizeServerAddress(input), (err) => {
      assert.equal(err.code, 'invalid_params', input);
      assert.match(err.message, message, input);
      return true;
    }, input);
  }
});

test('extractPairingLink: the first pass+server:// link in pasted text, without what is around it', () => {
  assert.equal(extractPairingLink(LINK), LINK);
  assert.equal(extractPairingLink(`  ${LINK}\n`), LINK);
  assert.equal(extractPairingLink(`Link: ${LINK}`), LINK);
  assert.equal(extractPairingLink(`<${LINK}>`), LINK);
  assert.equal(extractPairingLink(`Your link: "${LINK}".`), LINK);
  assert.equal(extractPairingLink(`(${LINK})`), LINK);
  assert.equal(extractPairingLink(`\`${LINK}\``), LINK);
  assert.equal(extractPairingLink(`first ${LINK} second ${LINK.replace('alice', 'bob')}`), LINK);
  assert.equal(extractPairingLink(LINK.replace('pass+server', 'PASS+SERVER')), LINK, 'scheme case');
  assert.equal(extractPairingLink('  not a link  '), 'not a link');
});

test('parseServerInput: a link (anywhere in the text) or a plain address', () => {
  const link = parseServerInput(`Hi Alice, here is your link:\n${LINK}\nCheers`);
  assert.equal(link.type, 'link');
  assert.equal(link.link, LINK);
  assert.equal(link.info.host, 'pass.example.com');
  assert.ok(!JSON.stringify(link.info).includes('pst_t0k3n'), 'parsed info has no token');

  assert.deepEqual(parseServerInput('pass.example.com'), { type: 'address', address: 'https://pass.example.com', host: 'pass.example.com', https: true });
  assert.deepEqual(parseServerInput('Server: https://pass.example.com/.'),
    { type: 'address', address: 'https://pass.example.com', host: 'pass.example.com', https: true });

  // A broken link is reported as a link problem, not as a bad address.
  assert.match(checkServerInput('pass+server://x/y?v=2&user=a&token=b').message, /from a newer Passyble Server/);
  assert.equal(checkServerInput('').ok, false);
  assert.equal(checkServerInput('pass.example.com').ok, true);
});
