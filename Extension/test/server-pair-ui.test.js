// "Add Passyble Server" form (src/ui/server-pair.js) in jsdom with a fake background `send`.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { makeDom } from './helpers/dom.js';
import { mountServerPair, pairErrorText, HINT, SIGN_IN_OPENED } from '../src/ui/server-pair.js';

const TOKEN = 'pst_kr3RuvCRcaQ29nq0oGvtM8RWx1_YAaPvx1qy-J047Hw';
const LINK = `pass+server://pass.example.com:8443/dav/alice/personal.vault?v=1&user=alice&token=${TOKEN}&name=Pixel%209&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g`;

function setup(reply = async () => ({ shown: true, host: 'pass.example.com:8443', user: 'alice' })) {
  const { window, document } = makeDom('<div id="root"></div>');
  const sent = [];
  const send = async (type, payload) => { sent.push([type, payload]); return reply(type, payload); };
  const root = document.getElementById('root');
  const form = mountServerPair(root, { send });
  const q = (sel) => root.querySelector(sel);
  const type = (value) => {
    form.input.value = value;
    form.input.dispatchEvent(new window.Event('input', { bubbles: true }));
  };
  const flush = () => new Promise((r) => setTimeout(r, 0));
  return { window, document, root, form, sent, q, type, flush };
}

test('a valid link shows host, account, device and pinning, never the token', () => {
  const { q, type } = setup();
  assert.equal(q('.sp-send').disabled, true, 'nothing to send yet');
  type(LINK);
  assert.equal(q('.sp-preview').hidden, false);
  const text = q('.sp-preview').textContent;
  for (const s of ['Device pairing link', 'pass.example.com:8443', 'alice', 'Pixel 9', 'Self-signed, verified by this link', 'Sign-in key', 'Included (hidden)']) {
    assert.ok(text.includes(s), s);
  }
  assert.ok(!q('.sp-preview').textContent.includes(TOKEN));
  assert.equal(q('.sp-error').hidden, true);
  assert.equal(q('.sp-send').disabled, false);
});

test('the input is not remembered or spell-checked by the browser', () => {
  const { form } = setup();
  assert.equal(form.input.getAttribute('autocomplete'), 'off');
  assert.equal(form.input.getAttribute('spellcheck'), 'false');
  assert.equal(form.input.hasAttribute('name'), false);
});

test('http links get a warning; links without pins say publicly trusted', () => {
  const { q, type } = setup();
  type('pass+server://[::1]:8080/pass/dav/bob/work.vault?v=1&user=bob&token=pst_t&scheme=http');
  assert.equal(q('.sp-warn').hidden, false);
  assert.match(q('.sp-warn').textContent, /This connection isn't encrypted/);
  type('pass+server://pass.example.com/dav/alice/personal.vault?v=1&user=alice&token=pst_t');
  assert.equal(q('.sp-warn').hidden, true);
  assert.match(q('.sp-preview').textContent, /Publicly trusted certificate/);
  assert.match(q('.sp-preview').textContent, /\(not named\)/);
});

test('invalid links show why and cannot be sent', async () => {
  const { q, type, sent, form, flush } = setup();
  type('pass+server://x/y?v=2&user=a&token=b');
  assert.equal(q('.sp-error').hidden, false);
  assert.match(q('.sp-error').textContent, /from a newer Passyble Server/);
  assert.equal(q('.sp-send').disabled, true);
  type('ftp://pass.example.com/');
  assert.match(q('.sp-error').textContent, /https:\/\//);
  assert.equal(q('.sp-hint').hidden, true, 'the error replaces the hint');
  form.input.dispatchEvent(new form.input.ownerDocument.defaultView.KeyboardEvent('keydown', { key: 'Enter' }));
  q('.sp-send').click();
  await flush();
  assert.equal(sent.length, 0);
  type('');
  assert.equal(q('.sp-error').hidden, true, 'empty field: no error');
});

test('Send hands the link to the background, shows the follow-up and clears the field', async () => {
  const { q, type, sent, form, flush } = setup();
  type(`  ${LINK}  `);
  q('.sp-send').click();
  assert.equal(q('.sp-result').textContent, 'Opening Passyble…');
  assert.equal(form.input.disabled, true);
  await flush();
  assert.deepEqual(sent, [['popup.server-pair', { link: LINK }]]);
  assert.equal(q('.sp-result').dataset.kind, 'ok');
  assert.match(q('.sp-result').textContent, /Check the Passyble window to finish connecting to pass\.example\.com:8443 as alice/);
  assert.equal(form.input.value, '', 'link (and token) cleared');
  assert.equal(form.input.disabled, false);
  assert.equal(q('.sp-preview').hidden, true);
  assert.equal(q('.sp-send').disabled, true);
});

test('Enter sends too', async () => {
  const { type, sent, form, flush } = setup();
  type(LINK);
  form.input.dispatchEvent(new form.input.ownerDocument.defaultView.KeyboardEvent('keydown', { key: 'Enter' }));
  await flush();
  assert.equal(sent.length, 1);
});

for (const [code, message, expected] of [
  ['agent_unavailable', 'Passyble desktop app is not running', /^Passyble isn't running\.$/],
  ['agent_unavailable', 'Specified native messaging host not found.', /^Can't connect to Passyble\. Check Passyble → Settings → Autofill/],
  ['not_supported', "this Passyble app can't connect to Passyble Server", /This needs a newer Passyble app\. Update Passyble/],
  ['invalid_params', 'link has no vault path', /^That isn't a server address or pass\+server:\/\/ link\./],
  ['internal', 'boom', /^Something went wrong\. Try again\.$/],
]) {
  test(`errors: ${code} (${message}) is explained and the field is still cleared`, async () => {
    const { q, type, form, flush } = setup(async () => { throw Object.assign(new Error(message), { code }); });
    type(LINK);
    q('.sp-send').click();
    await flush();
    assert.equal(q('.sp-result').dataset.kind, 'error');
    assert.match(q('.sp-result').textContent, expected);
    assert.equal(form.input.value, '');
    assert.ok(!q('.sp-result').textContent.includes(TOKEN));
  });
}

test('pairErrorText: unknown errors fall back to a generic message; addresses explain old desktop apps', () => {
  assert.equal(pairErrorText(undefined), 'Something went wrong. Try again.');
  assert.equal(pairErrorText({ code: 'invalid_params', message: 'not a pass+server link' }, { address: true }),
    'Update the Passyble desktop app to add a server by address, or paste the pass+server:// link instead.');
});

test('dropping text with a link fills the field and validates it', () => {
  const { window, root, form, q } = setup();
  const data = new Map([['text/plain', `Pairing link for alice:\n${LINK}\n`]]);
  const dataTransfer = { types: [...data.keys()], getData: (t) => data.get(t) || '', dropEffect: 'none' };
  const over = new window.Event('dragover', { bubbles: true, cancelable: true });
  over.dataTransfer = dataTransfer;
  root.dispatchEvent(over);
  assert.equal(over.defaultPrevented, true, 'drop allowed');
  assert.ok(q('.sp-drop').classList.contains('over'));
  const drop = new window.Event('drop', { bubbles: true, cancelable: true });
  drop.dataTransfer = dataTransfer;
  q('.sp-drop').dispatchEvent(drop);
  assert.equal(drop.defaultPrevented, true);
  assert.equal(form.input.value, LINK);
  assert.equal(q('.sp-preview').hidden, false);
  assert.ok(!q('.sp-drop').classList.contains('over'));
});

test('dragging something that is not text is left to the browser', () => {
  const { window, root } = setup();
  const over = new window.Event('dragover', { bubbles: true, cancelable: true });
  over.dataTransfer = { types: ['Files'], getData: () => '' };
  root.dispatchEvent(over);
  assert.equal(over.defaultPrevented, false);
});

test('the link is not persisted in page storage', async () => {
  const { window, q, type, flush } = setup();
  type(LINK);
  q('.sp-send').click();
  await flush();
  assert.equal(window.localStorage.length, 0);
  assert.equal(window.sessionStorage.length, 0);
  assert.ok(!window.document.documentElement.outerHTML.includes(TOKEN), 'not left in the DOM');
});

test('reset() clears the field and the preview', () => {
  const { form, q, type } = setup();
  type(LINK);
  form.reset();
  assert.equal(form.input.value, '');
  assert.equal(q('.sp-preview').hidden, true);
});

test('an invite (no token) is labelled as such and forwarded unchanged', async () => {
  const invite = 'pass+server://pass.example.com:8443/dav/alice/personal.vault?v=1&user=alice&pin=sha256:novcWsacBi2IRLwBIN7QCQVpLOAGPBXRFHKFijjSE-g';
  const { q, type, sent, flush } = setup();
  type(invite);
  const text = q('.sp-preview').textContent;
  assert.ok(text.includes("Sign-in link: you'll sign in in the Passyble app"), text);
  assert.ok(text.includes('Asked in the Passyble app'));
  assert.ok(!text.includes('Token'), 'no token row');
  assert.ok(!text.includes('Device pairing link'));
  assert.equal(q('.sp-send').disabled, false);
  q('.sp-send').click();
  await flush();
  assert.deepEqual(sent, [['popup.server-pair', { link: invite }]]);
  assert.equal(q('.sp-result').textContent, SIGN_IN_OPENED);
});

test('the field explains what to paste, has no error while empty, and Enter submits', () => {
  const { q, form } = setup();
  assert.equal(q('.sp-hint').textContent, HINT);
  assert.equal(q('.sp-hint').hidden, false);
  assert.equal(form.input.getAttribute('aria-describedby'), q('.sp-hint').id);
  assert.match(form.input.placeholder, /pass\.example\.com/);
  assert.equal(q('.sp-error').hidden, true);
});

for (const [typed, address, host] of [
  ['pass.example.com', 'https://pass.example.com', 'pass.example.com'],
  ['  pass.example.com:8443/  ', 'https://pass.example.com:8443', 'pass.example.com:8443'],
  ['https://Pass.Example.com/vault/', 'https://pass.example.com/vault', 'pass.example.com'],
  ['http://192.168.1.20:8080', 'http://192.168.1.20:8080', '192.168.1.20:8080'],
  ['Server: https://pass.example.com/', 'https://pass.example.com', 'pass.example.com'],
]) {
  test(`a plain address (${typed.trim()}) is normalized and sent as server.pair's link`, async () => {
    const { q, type, sent, form, flush } = setup(async () => ({ shown: true, host, user: null, sign_in: true, address: true }));
    type(typed);
    assert.equal(q('.sp-error').hidden, true);
    assert.equal(q('.sp-preview').hidden, false);
    assert.ok(q('.sp-preview').textContent.includes(`Server${host}`), q('.sp-preview').textContent);
    assert.match(q('.sp-preview').textContent, /Sign in in the Passyble app/);
    assert.equal(q('.sp-warn').hidden, address.startsWith('https:'), 'http gets the warning');
    form.input.dispatchEvent(new form.input.ownerDocument.defaultView.KeyboardEvent('keydown', { key: 'Enter' }));
    await flush();
    assert.deepEqual(sent, [['popup.server-pair', { link: address }]]);
    assert.equal(q('.sp-result').dataset.kind, 'ok');
    assert.equal(q('.sp-result').textContent, 'Passyble opened the sign-in window. Finish there.');
    assert.equal(form.input.value, '');
  });
}

for (const [typed, expected] of [
  ['alice@example.com', /e-mail address/],
  ['https://alice:pw@pass.example.com', /user name or password/],
  ['pass.example.com/?x=1', /without the rest of the web address/],
  ['ftp://pass.example.com', /https:\/\//],
  ['pass example com', /no spaces/],
]) {
  test(`a bad address (${typed}) is explained and not sent`, async () => {
    const { q, type, sent, flush } = setup();
    type(typed);
    assert.equal(q('.sp-error').hidden, false);
    assert.match(q('.sp-error').textContent, expected);
    assert.equal(q('.sp-send').disabled, true);
    q('.sp-send').click();
    await flush();
    assert.equal(sent.length, 0);
  });
}

test('typing waits for a pause before showing an error; pasting shows it at once', async () => {
  const { window, q, form } = setup();
  form.input.value = 'alice@';
  form.input.dispatchEvent(new window.InputEvent('input', { bubbles: true, inputType: 'insertText', data: '@' }));
  assert.equal(q('.sp-error').hidden, true, 'no red text mid-typing');
  assert.equal(q('.sp-send').disabled, true);
  await new Promise((r) => setTimeout(r, 750));
  assert.equal(q('.sp-error').hidden, false);
  form.input.value = 'x y';
  form.input.dispatchEvent(new window.InputEvent('input', { bubbles: true, inputType: 'insertFromPaste' }));
  assert.equal(q('.sp-error').hidden, false);
  assert.match(q('.sp-error').textContent, /no spaces/);
});

test('an old desktop app that only takes links: explained, with the link as the way out', async () => {
  const { q, type, flush } = setup(async () => { throw Object.assign(new Error('not a pass+server link'), { code: 'invalid_params' }); });
  type('pass.example.com');
  q('.sp-send').click();
  await flush();
  assert.equal(q('.sp-result').dataset.kind, 'error');
  assert.equal(q('.sp-result').textContent, 'Update the Passyble desktop app to add a server by address, or paste the pass+server:// link instead.');
});

test('a link wrapped in text, angle brackets and punctuation is picked out', async () => {
  const { q, type, sent, flush } = setup();
  type(`Link: <${LINK}>.`);
  assert.equal(q('.sp-error').hidden, true);
  q('.sp-send').click();
  await flush();
  assert.deepEqual(sent, [['popup.server-pair', { link: LINK }]]);
});

test('the send button is a plain text pill (no icon)', () => {
  const { q } = setup();
  assert.equal(q('.sp-send svg'), null, 'no icon in the button');
  assert.equal(q('.sp-send').textContent.trim(), 'Continue');
});
