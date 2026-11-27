// Authenticator QR codes (src/shared/otpauth.js) for the popup's Scan QR. Demo secrets only (JBSWY3DPEHPK3PXP is the
// usual example secret).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { matchLogins, newLoginFields, parseOtpauth, pickAuthenticator } from '../src/shared/otpauth.js';

const LINK = 'otpauth://totp/GitHub:octo%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';

test('parseOtpauth: an otpauth://totp/ link with its issuer, account and settings; the link itself is kept', () => {
  assert.deepEqual(parseOtpauth(LINK), { kind: 'totp', uri: LINK, issuer: 'GitHub', account: 'octo@example.com', digits: 6, period: 30, algorithm: 'SHA1' });
  // The issuer parameter wins over the label's; no label issuer; settings from the query.
  const custom = parseOtpauth('  OTPAUTH://TOTP/Old%20Name:ada?secret=jbsw y3dp-ehpk 3pxp&issuer=New%20Co&digits=8&period=60&algorithm=sha256 ');
  assert.equal(custom.kind, 'totp');
  assert.deepEqual([custom.issuer, custom.account, custom.digits, custom.period, custom.algorithm], ['New Co', 'ada', 8, 60, 'SHA256']);
  assert.equal(custom.uri.startsWith('OTPAUTH://'), true, 'trimmed, otherwise as scanned (the agent stores it)');
  const bare = parseOtpauth('otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP');
  assert.deepEqual([bare.issuer, bare.account], ['', 'ada']);
});

test('parseOtpauth: what is not a usable time-based code', () => {
  assert.equal(parseOtpauth('https://example.com/'), null, 'not otpauth at all');
  assert.equal(parseOtpauth(''), null);
  assert.equal(parseOtpauth(null), null);
  assert.deepEqual(parseOtpauth('otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8'), { kind: 'migration' });
  assert.deepEqual(parseOtpauth('otpauth://hotp/ada?secret=JBSWY3DPEHPK3PXP&counter=1'), { kind: 'hotp' });
  for (const bad of [
    'otpauth://totp/ada', // no secret
    'otpauth://totp/ada?secret=JBSWY3DP', // 40 bits: too short
    'otpauth://totp/ada?secret=NOT_BASE32!!', // not base32
    'otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&digits=4',
    'otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&period=0',
    'otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&algorithm=MD5',
    'otpauth://steam/ada?secret=JBSWY3DPEHPK3PXP',
    `otpauth://totp/ada?secret=JBSWY3DPEHPK3PXP&x=${'a'.repeat(2100)}`,
  ]) assert.deepEqual(parseOtpauth(bad), { kind: 'invalid' }, bad);
});

test('pickAuthenticator: the first usable code among several QR codes, else the most telling problem', () => {
  assert.deepEqual(pickAuthenticator([]), { problem: 'none' });
  assert.deepEqual(pickAuthenticator(undefined), { problem: 'none' });
  assert.deepEqual(pickAuthenticator(['https://example.com/app']), { problem: 'not_otp' });
  assert.equal(pickAuthenticator(['https://example.com/app', LINK]).totp.uri, LINK);
  assert.deepEqual(pickAuthenticator(['otpauth://totp/x', 'otpauth-migration://offline?data=x']), { problem: 'migration' });
  assert.deepEqual(pickAuthenticator(['otpauth://totp/x', 'otpauth://hotp/x?secret=JBSWY3DPEHPK3PXP']), { problem: 'hotp' });
  assert.deepEqual(pickAuthenticator(['otpauth://totp/x']), { problem: 'invalid' });
});

const info = parseOtpauth(LINK);
const login = (id, username, extra = {}) => ({ id, title: `Login ${id}`, username, has_totp: false, ...extra });

test('matchLogins: the only login of the site is chosen; with several, the one with the code\'s account (first in the list)', () => {
  assert.deepEqual(matchLogins([login('a', 'someone-else')], info), { candidates: [login('a', 'someone-else')], preselect: 'a' });
  const several = [login('a', 'ada'), login('b', ' OCTO@example.com '), login('c', 'grace')];
  const m = matchLogins(several, info);
  assert.equal(m.preselect, 'b', 'the username is compared trimmed, any case');
  assert.deepEqual(m.candidates.map((i) => i.id), ['b', 'a', 'c']);
  // Two with that username, or none: the user picks.
  assert.equal(matchLogins([login('a', 'octo@example.com'), login('b', 'octo@example.com')], info).preselect, null);
  assert.equal(matchLogins([login('a', 'ada'), login('b', 'grace')], info).preselect, null);
  assert.equal(matchLogins([login('a', 'ada'), login('b', 'grace')], { ...info, account: '' }).preselect, null);
  assert.deepEqual(matchLogins([], info), { candidates: [], preselect: null });
  assert.deepEqual(matchLogins(null, info).candidates, []);
  assert.deepEqual(matchLogins([null, { title: 'no id' }, login('a', 'x')], info).preselect, 'a', 'rows without an id are left out');
});

test('newLoginFields: the issuer as the title (else the site), the account as the username, the link as 2FA', () => {
  assert.deepEqual(newLoginFields(info, 'github.com'), { title: 'GitHub', username: 'octo@example.com', totp: LINK });
  const bare = parseOtpauth('otpauth://totp/?secret=JBSWY3DPEHPK3PXP');
  assert.deepEqual(newLoginFields(bare, 'example.com'), { title: 'example.com', totp: bare.uri });
  const same = parseOtpauth('otpauth://totp/Acme?secret=JBSWY3DPEHPK3PXP&issuer=Acme');
  assert.deepEqual(newLoginFields(same, 'acme.test'), { title: 'Acme', totp: same.uri }, 'an account that only repeats the issuer is no username');
});
