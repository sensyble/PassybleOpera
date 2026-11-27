// The master password page inside the in-page menu: the menu around it only hears how the unlock
// went (`ready`, `unlocked`, `escape`), never the password.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';

const messages = [];
let reply = () => ({ ok: true, result: null });
let instance = 0;

async function openFrame({ search = '' } = {}) {
  const html = readFileSync(new URL('../src/unlock/frame.html', import.meta.url), 'utf8').replace(/<script[^>]*><\/script>/g, '');
  const dom = new JSDOM(html, { url: `https://extension.test/src/unlock/frame.html${search}`, pretendToBeVisual: true });
  const posted = [];
  const parent = { postMessage: (data, origin) => posted.push([data, origin]) };
  Object.defineProperty(dom.window, 'parent', { value: parent, configurable: true });
  for (const k of ['document', 'Node', 'HTMLElement', 'Event', 'KeyboardEvent']) globalThis[k] = dom.window[k];
  globalThis.window = dom.window;
  globalThis.location = dom.window.location;
  messages.length = 0;
  await import(`../src/unlock/frame.js?instance=${++instance}`);
  // The frame asks once whether the vault is linked to a Passyble account (its label); the tests below
  // count what the form sends.
  await flush();
  const asked = messages.filter((m) => m.type === 'account.keys-state').length;
  messages.length = 0;
  const $ = (id) => dom.window.document.getElementById(id);
  return { window: dom.window, $, posted, parent, asked };
}

const flush = () => new Promise((r) => setTimeout(r, 0));

before(() => {
  globalThis.chrome = {
    runtime: { id: 'pass-ext', sendMessage: async (msg) => { messages.push(msg); return reply(msg); } },
  };
});

function submit(win, $) {
  $('form').dispatchEvent(new win.Event('submit', { cancelable: true, bubbles: true }));
}

test('frame: says it is ready, with its height; takes the focus only with ?focus=1', async () => {
  const plain = await openFrame();
  assert.deepEqual(plain.posted.map(([d]) => d.passybleUnlock), ['ready']);
  assert.equal(typeof plain.posted[0][0].height, 'number');
  assert.notEqual(plain.window.document.activeElement, plain.$('master'));
  assert.match(plain.$('msg').textContent, /can't see what you type/);
  assert.equal(plain.$('master').getAttribute('type'), 'password');
  assert.equal(plain.$('master').getAttribute('autocomplete'), 'off');
  const focused = await openFrame({ search: '?focus=1' });
  assert.equal(focused.window.document.activeElement, focused.$('master'));
});

test('frame: unlocks through the background once, clears the field, tells the menu without the password', async () => {
  reply = (msg) => (msg.password === 'master'
    ? { ok: true, result: { locked: false } }
    : { ok: false, error: { code: 'wrong_password', message: 'Wrong master password. Check Caps Lock and try again.' } });
  const { window: win, $, posted } = await openFrame({ search: '?focus=1' });
  submit(win, $);
  await flush();
  assert.equal(messages.length, 0, 'nothing sent for an empty field');
  assert.match($('msg').textContent, /Enter your master password/);
  assert.ok($('msg').classList.contains('error'));
  $('master').value = 'nope';
  submit(win, $);
  await flush();
  await flush();
  assert.deepEqual(messages.at(-1), { type: 'popup.unlock-password', password: 'nope' });
  assert.equal($('master').value, '', 'cleared after a wrong password');
  assert.match($('msg').textContent, /Wrong master password/);
  $('master').value = 'master';
  submit(win, $);
  await flush();
  await flush();
  assert.equal(messages.length, 2);
  assert.equal($('master').value, '');
  assert.deepEqual(posted.map(([d]) => d.passybleUnlock), ['ready', 'unlocked']);
  assert.ok(posted.every(([d]) => !JSON.stringify(d).includes('master')), 'the password never leaves in a message');
});

test('frame: a vault linked to a Passyble account asks for the Passyble password', async () => {
  reply = (msg) => (msg.type === 'account.keys-state'
    ? { ok: true, result: { available: true, linked: { account: 'acc_demo', email: 'demo@example.com', secret_key_needed: false } } }
    : { ok: true, result: { locked: false } });
  const linked = await openFrame();
  assert.equal(linked.asked, 1);
  assert.equal(linked.window.document.querySelector('label[for="master"]').textContent, 'Passyble password');
  assert.equal(linked.$('master').getAttribute('aria-label'), 'Passyble password');
  reply = () => ({ ok: true, result: { available: false, linked: null } });
  const plain = await openFrame();
  assert.equal(plain.window.document.querySelector('label[for="master"]').textContent, 'Master password');
});

test('frame: Esc asks the menu to close; a focus request from the parent focuses the field', async () => {
  const { window: win, $, posted, parent } = await openFrame();
  win.document.dispatchEvent(new win.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true }));
  assert.deepEqual(posted.map(([d]) => d.passybleUnlock), ['ready', 'escape']);
  win.dispatchEvent(new win.MessageEvent('message', { data: { passybleUnlock: 'focus' }, source: null }));
  assert.notEqual(win.document.activeElement, $('master'), 'not from someone else');
  const ev = new win.MessageEvent('message', { data: { passybleUnlock: 'focus' } });
  Object.defineProperty(ev, 'source', { value: parent });
  win.dispatchEvent(ev);
  assert.equal(win.document.activeElement, $('master'));
});
