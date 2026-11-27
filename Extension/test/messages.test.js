import { test } from 'node:test';
import assert from 'node:assert/strict';
import { friendlyError, isHostMissing, MSG } from '../src/shared/messages.js';
import { PassError, ErrorCode, Reason } from '../src/shared/errors.js';
import { t } from '../src/shared/i18n.js';

const e = (code, message) => Object.assign(new Error(message || code), { code });

test('protocol codes get a message with a next step', () => {
  assert.equal(friendlyError(e('agent_unavailable', 'The Passyble desktop app is not running')), "Passyble isn't running.");
  assert.equal(friendlyError(e('locked')), 'Passyble is locked. Unlock it to continue.');
  assert.equal(friendlyError(e('url_mismatch', 'item does not match')), 'That login is saved for a different site.');
  assert.equal(friendlyError(e('cancelled')), 'Cancelled.');
  assert.equal(friendlyError(e('not_found', 'no item')), 'Nothing saved for this site yet.');
  assert.equal(friendlyError(e('not_supported', 'unknown')), 'This needs a newer Passyble app. Update Passyble, then try again.');
  assert.equal(friendlyError(new PassError('locked', 'vault locked')), MSG.locked, 'PassError');
  assert.equal(friendlyError({ code: 'locked', message: 'x' }), MSG.locked, 'plain { code, message } from the background');
});

test('a timeout and a reloaded extension are not "not running"', () => {
  assert.equal(friendlyError(e('timeout', 'Passyble did not answer "logins.fill" in time')), "Passyble didn't answer. Check for an open Passyble window.");
  assert.equal(friendlyError(e('extension_reloaded', 'Extension was reloaded')), 'Passyble was updated. Reload this page to use it.');
  assert.equal(isHostMissing(e('timeout', 'Passyble did not answer "status" in time')), false);
  assert.notEqual(friendlyError(e('timeout')), MSG.agentUnavailable);
});

test('a missing native host registration is told apart from Passyble not running', () => {
  for (const message of [
    'Specified native messaging host not found.', // Chrome / Edge
    'No such native application com.sensyble.pass', // Firefox
    'Access to the specified native messaging host is forbidden.',
    'Failed to start native messaging host.',
  ]) {
    const err = e('agent_unavailable', message);
    assert.equal(isHostMissing(err), true, message);
    assert.equal(friendlyError(err), "Can't connect to Passyble. Check Passyble → Settings → Autofill.");
  }
  assert.equal(isHostMissing(e('agent_unavailable', 'The Passyble desktop app is not running')), false);
  assert.equal(isHostMissing(e('agent_unavailable', 'Native host has exited.')), false);
  assert.equal(isHostMissing(e('not_found', 'not found')), false, 'other codes never count');
  assert.equal(isHostMissing(new Error('Specified native messaging host not found.')), true, 'connectNative error without a code');
  assert.equal(isHostMissing(null), false);
});

test('"Add Passyble Server" context', () => {
  assert.equal(friendlyError(e('invalid_params', 'bad link'), { context: 'server-pair' }),
    "That isn't a server address or pass+server:// link.");
  // Desktop apps without server.pair answer an address with invalid_params (or not_supported).
  for (const code of ['invalid_params', 'not_supported']) {
    assert.equal(friendlyError(e(code, 'not a pass+server link'), { context: 'server-address' }),
      'Update the Passyble desktop app to add a server by address, or paste the pass+server:// link instead.');
  }
  assert.equal(friendlyError(e('agent_unavailable'), { context: 'server-address' }), MSG.agentUnavailable);
});

test('anything else: a translated generic text, never the raw English message or a stack', () => {
  const GENERIC = 'Something went wrong. Try again.';
  assert.equal(MSG.generic, GENERIC);
  for (const code of ['invalid_params', 'invalid_state', 'not_supported_elsewhere', 'surprise', undefined]) {
    assert.equal(friendlyError(e(code, 'Bad challenge')), GENERIC, String(code));
  }
  assert.equal(friendlyError(e('invalid_state', 'Bad challenge'), { context: 'edit' }), GENERIC);
  assert.equal(friendlyError('plain string'), GENERIC);
  assert.equal(friendlyError(new Error('Boom')), GENERIC);
  assert.ok(!friendlyError({ message: 'oops\n    at a (b.js:1:1)' }).includes(' at '));
  for (const empty of [undefined, null, {}, new Error(''), e('internal', 'internal'), e('internal', 'No response'), e('internal', '')]) {
    assert.equal(friendlyError(empty), GENERIC, String(empty?.message));
  }
});

test('internal errors: the generic text only; the detail goes to the console (debug), never into the text', (t) => {
  const logged = [];
  t.mock.method(console, 'debug', (...args) => { logged.push(args.join(' ')); });
  assert.equal(friendlyError(e('internal', 'disk full')), 'Something went wrong. Try again.');
  const withStack = e('internal', 'TypeError: x is undefined\n    at foo (popup.js:3:4)');
  assert.equal(friendlyError(withStack), 'Something went wrong. Try again.');
  assert.ok(logged.some((l) => l.includes('disk full')), 'disk full logged');
  assert.ok(logged.some((l) => l.includes('x is undefined') && !l.includes('popup.js')), 'first line only');
});

// Every code the agent or the extension uses, plus unknown ones, in every context: the text is one of
// this extension's own messages, never the raw message (nor a part of it).
const RAW = 'RAWTEXT unknown method frobnicate at C:\\pass\\agent.rs:12 (token=pst_secret)';
const CODES = [...Object.values(ErrorCode), 'disabled', 'surprise', '', undefined];
const CONTEXTS = [undefined, 'server-pair', 'server-address', 'edit', 'unlock', 'generate'];

test('friendlyError never shows the raw message, for any code, reason or context', (t) => {
  t.mock.method(console, 'debug', () => {});
  const own = new Set(Object.values(MSG));
  for (const code of CODES) {
    for (const context of CONTEXTS) {
      for (const reason of [undefined, ...Object.values(Reason), 'some_future_reason']) {
        for (const err of [e(code, RAW), { code, message: RAW, reason }, new PassError(code || 'internal', RAW, reason)]) {
          // The one documented pass-through: the core's translated sentence for generate.* (next tests).
          if (context === 'generate' && !err.reason && ['invalid_params', 'internal'].includes(err.code)) continue;
          const text = friendlyError(err, { context });
          const label = `${code} / ${context} / ${reason}`;
          assert.ok(own.has(text), `${label}: "${text}" is a message of the extension`);
          assert.ok(!/RAWTEXT|frobnicate|agent\.rs|token=|pst_secret/.test(text), `${label}: ${text}`);
        }
      }
    }
  }
  for (const err of [new Error(RAW), new TypeError(RAW), RAW, 42, null, undefined, {}, [], { message: { nested: RAW } }]) {
    for (const context of CONTEXTS) assert.equal(friendlyError(err, { context }), MSG.generic, String(err));
  }
});

test('not_supported in the unlock context shows the desktop app\'s own (translated) reason; other contexts do not', () => {
  assert.equal(friendlyError(e('not_supported', 'Windows Hello is turned off in Passyble'), { context: 'unlock' }), 'Windows Hello is turned off in Passyble.');
  assert.equal(friendlyError(e('not_supported', 'unknown method unlock.hello'), { context: 'unlock' }), MSG.unlockNeedsUpdate);
  assert.equal(friendlyError(new PassError('not_supported', 'unknown method', Reason.NEEDS_UPDATE), { context: 'unlock' }), MSG.unlockNeedsUpdate);
  assert.equal(friendlyError(e('not_supported', 'Windows Hello is turned off in Passyble')), MSG.notSupported);
  assert.equal(friendlyError({ code: 'not_supported', message: '' }, { context: 'unlock' }), MSG.unlockFailed);
});

test('the unlock context: a failed unlock and an empty password have their own texts, never the desktop app\'s English', (t) => {
  t.mock.method(console, 'debug', () => {});
  assert.equal(friendlyError(e('internal', 'corrupt: header mismatch'), { context: 'unlock' }), "Passyble couldn't unlock. Try again, or unlock in the Passyble app.");
  assert.equal(friendlyError(e('invalid_params', 'Enter your master password'), { context: 'unlock' }), 'Enter your master password.');
  assert.equal(friendlyError(e('wrong_password', 'x'), { context: 'unlock' }), MSG.wrongPassword);
  assert.equal(friendlyError(e('rate_limited', 'x'), { context: 'unlock' }), MSG.tooManyAttempts);
});

test('reasons set by the background say exactly what happened (the code stays for older callers)', () => {
  for (const [code, reason, text] of [
    ['not_supported', Reason.FORMS_OFF, 'Turn on "Offer cards and addresses" in Settings.'],
    ['not_found', Reason.WEB_PAGES_ONLY, 'Passyble works on normal web pages only.'],
    ['invalid_params', Reason.WEB_PAGES_ONLY, 'Passyble works on normal web pages only.'],
    ['not_found', Reason.PICK_IN_POPUP, 'Pick the login in the Passyble popup first.'],
    ['not_found', Reason.NOTHING_TO_SAVE, 'This save prompt has expired. Sign in again to save the login.'],
    ['not_found', Reason.NOTHING_TO_UNDO, "There's nothing to undo anymore."],
    ['not_supported', Reason.NEEDS_UPDATE, MSG.notSupported],
  ]) {
    for (const err of [new PassError(code, 'English for logs', reason), new PassError(code, 'English for logs', reason).toJSON()]) {
      assert.equal(friendlyError(err), text, reason);
      // Also where the code alone would mean something else (generate: not_found is "not set up").
      assert.equal(friendlyError(err, { context: 'generate' }), text, `${reason} (generate)`);
    }
    if (reason !== Reason.NEEDS_UPDATE) assert.notEqual(friendlyError({ code }), text, `${code} alone is not ${reason}`);
  }
  assert.equal(friendlyError(new PassError('not_supported', 'x', Reason.NEEDS_UPDATE), { context: 'edit' }), MSG.editNeedsUpdate);
  assert.equal(friendlyError(new PassError('not_supported', 'x', Reason.NEEDS_UPDATE), { context: 'server-address' }), MSG.addressNeedsUpdate);
  assert.equal(PassError.from({ code: 'not_found', message: 'x', reason: Reason.NOTHING_TO_UNDO }).reason, Reason.NOTHING_TO_UNDO, 'kept by PassError.from');
  assert.deepEqual(new PassError('locked', 'x').toJSON(), { code: 'locked', message: 'x' }, 'no reason: as before');
  assert.equal(PassError.from(new TypeError('boom')).reason, Reason.UNEXPECTED, 'an exception is marked unexpected');
});

test('the generate context: the core\'s translated sentence, else a text chosen by code', (t) => {
  t.mock.method(console, 'debug', () => {});
  assert.equal(friendlyError(e('internal', "SimpleLogin n'a pas accepté le jeton"), { context: 'generate' }), "SimpleLogin n'a pas accepté le jeton.");
  assert.equal(friendlyError(e('invalid_params', 'the catch-all domain is not valid'), { context: 'generate' }), 'The catch-all domain is not valid.');
  assert.equal(friendlyError(e('not_found', 'Set up the e-mail generator in Passyble: Settings, Generator.'), { context: 'generate' }), MSG.generateNotSetUp);
  assert.equal(friendlyError(e('not_supported', 'This build has no e-mail alias services.'), { context: 'generate' }), MSG.aliasNotSupported);
  assert.equal(friendlyError(e('not_supported', 'unknown method generate.email'), { context: 'generate' }), MSG.notSupported);
  assert.equal(friendlyError(e('rate_limited', 'Too many new aliases. Wait a minute.'), { context: 'generate' }), MSG.aliasRateLimited);
  // The desktop app's own English for requests the extension doesn't send, and the extension's own exceptions.
  for (const message of ['unknown service nosuch', 'unknown kind x', 'no alias requested', 'not a web page']) {
    assert.equal(friendlyError(e('invalid_params', message), { context: 'generate' }), MSG.generic, message);
  }
  assert.equal(friendlyError(PassError.from(new TypeError('x is undefined')), { context: 'generate' }), MSG.generic);
  assert.equal(friendlyError(PassError.from(new TypeError('x is undefined')).toJSON(), { context: 'generate' }), MSG.generic);
  assert.equal(friendlyError(e('internal', 'the service is down\n    at x (y.rs:1)'), { context: 'generate' }), 'The service is down.', 'first line only');
});

test('errors raised by the background itself have their own translated text, chosen by code', () => {
  for (const [code, text] of [
    [ErrorCode.CANT_READ_PAGE, "Passyble can't read this page."],
    [ErrorCode.OPEN_QR_PAGE_FIRST, 'Open the page with the QR code first.'],
    [ErrorCode.PAGE_TOO_LARGE, 'The page is too large to scan.'],
    [ErrorCode.CANNOT_RUN_HERE, 'Passyble cannot run on this page.'],
    [ErrorCode.NEEDS_SECURE_PAGE, 'Passyble fills cards and addresses only on secure (https) pages.'],
  ]) {
    assert.equal(friendlyError(e(code, 'some other words')), text, code);
    assert.equal(friendlyError(e(code, 'some other words'), { context: 'edit' }), text, code);
  }
  assert.notEqual(MSG.cantReadPage, MSG.generic);
  assert.notEqual(MSG.openQrPageFirst, t('editorNoQr'));
});
