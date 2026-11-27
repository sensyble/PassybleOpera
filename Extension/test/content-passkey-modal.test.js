import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://login.example.com/start', pretendToBeVisual: true });
const w = dom.window;
const doc = w.document;

w.Element.prototype.getBoundingClientRect = function () {
  return { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
};
const shadowRoots = new Map();
const attachShadow = w.Element.prototype.attachShadow;
w.Element.prototype.attachShadow = function (init) {
  const root = attachShadow.call(this, init);
  shadowRoots.set(this, root);
  return root;
};

const ORIGIN = 'chrome-extension://pass-ext';
const ALICE = { id: 'ex-alice', title: 'Example', user_name: 'alice@example.com', user_display_name: 'Alice', credential_id: 'QUxJQ0U' };
const BOB = { id: 'ex-bob', title: 'Example work', user_name: 'bob', user_display_name: '', credential_id: 'Qk9C' };
const LOGINS = [
  { id: 'ex-alice', title: 'Example', username: 'alice@example.com' },
  { id: 'ex-carol', title: 'Example', username: 'carol' },
];

const sent = [];
let runtimeListener;
let locked = false;   // the vault
let soft = true;      // locked with the list kept
let found = [ALICE];
let findError = null;
let createOpts = { candidates: LOGINS, suggested: 'ex-alice', excluded: false, vault: null };
let createError = null;
let unlockOpts = { inline: true, hello: true };
let helloAnswer = () => { locked = false; return { ok: true, result: { locked: false } }; };
let startAnswer = () => { findError = null; createError = null; return { ok: true, result: { locked: false } }; };
const lockedError = { ok: false, error: { code: 'locked', message: 'Vault is locked' } };
const responses = {
  'otp.context': () => ({ ok: true, result: { pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] } }),
  'logins.find': () => ({ ok: true, result: { items: [], pending_otp: null, locked } }),
  'passkey.find': () => {
    if (findError) return { ok: false, error: findError };
    if (locked && !soft) return lockedError;
    return { ok: true, result: { rp_id: 'example.com', items: found, locked } };
  },
  'passkey.create_options': () => {
    if (createError) return { ok: false, error: createError };
    if (locked && !soft) return lockedError;
    return { ok: true, result: { rp_id: 'example.com', locked, ...createOpts } };
  },
  'unlock.options': () => ({ ok: true, result: { ...unlockOpts, locked } }),
  'unlock.hello': () => helloAnswer(),
  'unlock.cancel': () => ({ ok: true, result: { cancelled: true } }),
  'passkey.start_app': () => startAnswer(),
  'save.query': () => ({ ok: true, result: null }),
};

/** bridge.js as the content script sees it: one parked get() / create() at a time. */
const bridge = {
  modal: null,
  handler: null,
  listeners: new Set(),
  completed: [],
  ended: [],
  passed: [],
  answer: () => ({ ok: true, result: { credentialId: 'x' } }),
  alive: () => true,
  hasConditional: () => false,
  conditionalRequest: () => null,
  onConditionalChange: () => () => {},
  onModalRequest(fn) { this.handler = fn; return () => { if (this.handler === fn) this.handler = null; }; },
  onModalChange(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); },
  hasModal(rid) { return !!this.modal && this.modal.rid === rid; },
  async completeModal(rid, choice) {
    if (!this.hasModal(rid)) return { ok: false, error: { code: 'cancelled' } };
    this.completed.push([rid, choice]);
    const res = this.answer(choice);
    if (res.ok) this.finish();
    return res;
  },
  endModal(rid, outcome) {
    if (!this.hasModal(rid)) return false;
    this.ended.push([rid, outcome]);
    this.finish();
    return true;
  },
  passModal(rid) {
    if (!this.hasModal(rid)) return false;
    this.passed.push(rid);
    this.finish();
    return true;
  },
  finish() {
    this.modal = null;
    for (const fn of this.listeners) fn(null);
  },
  /** The page asks (`info` as bridge.js describes it); returns its rid. */
  ask(info) {
    const rid = `r${++this.n}`;
    this.modal = Object.freeze({ rid, userActivated: true, ...info });
    this.handler(this.modal);
    return rid;
  },
  /** The page gives up (AbortSignal). */
  abort() { this.finish(); },
  n: 0,
};

let main;
let ui;
let prompt;
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  globalThis.__passBridge = bridge;
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      getURL: (p) => `${ORIGIN}/${p}`,
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : { ok: true, result: {} };
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: { local: { get: async () => ({}) }, sync: { get: async () => ({}) }, onChanged: { addListener: () => {} } },
  };
  doc.body.innerHTML = '<h1>Example</h1><button id="go">Sign in with a passkey</button>';
  main = await import('../src/content/main.js');
  ui = await import('../src/content/ui-common.js');
  prompt = await import('../src/content/passkey-prompt.js');
  await main.start();
});

after(() => {
  main.stop();
  delete globalThis.__passBridge;
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const settle = () => tick(ui.MIN_VISIBLE_MS + 30);
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true, button: 0 }));
const key = (el, k) => dispatchTrusted(el, new w.KeyboardEvent('keydown', { key: k, bubbles: true, composed: true, cancelable: true }));
const card = () => {
  const host = doc.querySelector('pass-passkey');
  return host ? shadowRoots.get(host) : null;
};
const cardText = () => card()?.querySelector('.card-box').textContent || '';
/** "No passkey for <site> in Passyble" (showPasskeyNone), or null. */
const noneBox = () => {
  const host = doc.querySelector('pass-passkey-none');
  return host ? shadowRoots.get(host).querySelector('.none-box') : null;
};
const noneText = () => noneBox()?.querySelector('.title').textContent ?? null;
/** The button with `text` the user can see (the card's own row hides while it unlocks). */
const button = (text) => [...(card()?.querySelectorAll('button') || [])].find((b) => b.textContent.trim() === text && !b.closest('[hidden]'));
const count = (type) => sent.filter((m) => m.type === type).length;
const frame = () => card()?.querySelector('iframe.unlock-frame') || null;
const GET = { kind: 'get', rpId: 'example.com', allowCredentials: [] };
const CREATE = {
  kind: 'create', rpId: 'example.com', rpName: 'Example', user: { name: 'alice@example.com', displayName: 'Alice' }, excludeCredentials: [],
};

function reset() {
  bridge.completed.length = 0;
  bridge.ended.length = 0;
  bridge.passed.length = 0;
  bridge.answer = () => ({ ok: true, result: { credentialId: 'x' } });
  locked = false;
  soft = true;
  found = [ALICE];
  findError = null;
  createOpts = { candidates: LOGINS, suggested: 'ex-alice', excluded: false, vault: null };
  createError = null;
  unlockOpts = { inline: true, hello: true };
  helloAnswer = () => { locked = false; return { ok: true, result: { locked: false } }; };
  startAnswer = () => { findError = null; createError = null; return { ok: true, result: { locked: false } }; };
}

async function pageAsks(info) {
  const rid = bridge.ask(info);
  await tick(20);
  return rid;
}

test("the page's own get(): its passkeys in the card, and nothing signs before a real, visible click", async () => {
  reset();
  const rid = await pageAsks(GET);
  assert.ok(card(), 'the card');
  assert.equal(doc.querySelector('pass-passkey').shadowRoot, null, 'closed shadow root');
  assert.match(cardText(), /Sign in with your passkey\?/);
  assert.match(cardText(), /example\.com/);
  assert.match(cardText(), /alice@example\.com/);
  assert.ok(button('Use another device'));
  assert.ok(button('Cancel'), 'the page waits for an answer: Cancel, not "Not now"');
  const find = sent.filter((m) => m.type === 'passkey.find').at(-1);
  assert.deepEqual(find.options, { rpId: 'example.com', allowCredentials: [] });
  assert.equal(find.automatic, false, 'the user waits: Passyble is asked even right after it was away');

  button('Sign in').click();          // a script's click
  await click(button('Sign in'));     // right as it appeared
  await tick(10);
  assert.deepEqual(bridge.completed, []);
  await settle();
  await click(button('Sign in'));
  await tick(20);
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-alice', credentialId: 'QUxJQ0U' }]]);
  assert.equal(card(), null, 'signed in: the card goes');
  assert.equal(count('unlock'), 0);
});

test('several passkeys: the user picks the account', async () => {
  reset();
  found = [ALICE, BOB];
  const rid = await pageAsks(GET);
  assert.match(cardText(), /Choose a passkey to sign in/);
  const rows = [...card().querySelectorAll('button.acct')];
  assert.equal(rows.length, 2);
  await settle();
  await click(rows[1]);
  await tick(20);
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-bob', credentialId: 'Qk9C' }]]);
});

test('"Use another device" hands the request to the browser, for a real, visible click only; Cancel, the close button and Esc fail it', async () => {
  reset();
  let rid = await pageAsks(GET);
  button('Use another device').click();       // a script's click
  await click(button('Use another device'));  // right as the card appeared
  await tick(10);
  assert.deepEqual(bridge.ended, [], 'not before the card was plainly visible for a moment');
  await settle();
  await click(button('Use another device'));
  await tick(10);
  assert.deepEqual(bridge.ended, [[rid, 'fallback']]);
  assert.equal(card(), null);

  for (const how of ['Cancel', 'close', 'Escape']) {
    bridge.ended.length = 0;
    rid = await pageAsks(GET);
    if (how === 'Cancel') await click(button('Cancel'));
    else if (how === 'close') await click(card().querySelector('.x'));
    else await key(card().querySelector('.card-box'), 'Escape');
    await tick(10);
    assert.deepEqual(bridge.ended, [[rid, 'cancel']], how);
    assert.equal(card(), null, how);
  }
  assert.deepEqual(bridge.completed, []);
});

test('nothing in Passyble for the site (unlocked): no card, no wait; the browser\'s own WebAuthn at once and "No passkey for <site> in Passyble"', async () => {
  reset();
  found = [];
  const rid = bridge.ask(GET);
  await tick(5); // passkey.find answers: nothing more to wait for
  assert.deepEqual(bridge.ended, [[rid, 'fallback']], "handed to the browser's own WebAuthn (security keys, phones) at once");
  assert.equal(card(), null, 'no card to click through');
  assert.equal(count('passkey.get'), 0, 'Passyble signs nothing');
  assert.equal(noneText(), 'No passkey for example.com in Passyble');
  const notice = noneBox();
  assert.equal(notice.getAttribute('role'), 'status', 'a status line, not a dialog');
  assert.equal(notice.querySelectorAll('button').length, 1, 'nothing to choose: only close');
  assert.notEqual(doc.activeElement?.tagName, 'PASS-PASSKEY-NONE', 'it never takes the focus');
  await click(notice.querySelector('.x'));
  assert.equal(noneText(), null, 'the close button takes it away');

  // Locked with the list kept, and nothing for the site in it: the same list, so the same hand-off.
  bridge.ended.length = 0;
  locked = true;
  const kept = bridge.ask(GET);
  await tick(5);
  assert.deepEqual(bridge.ended, [[kept, 'fallback']]);
  assert.equal(card(), null);
  assert.equal(count('unlock.options'), 0, 'no unlock for a site Passyble has nothing for');
  assert.equal(noneText(), 'No passkey for example.com in Passyble');

  // It goes by itself after a few seconds.
  await tick(prompt.NONE_NOTICE_MS + 50);
  assert.equal(noneText(), null);
});

test('a passkey for the site: the card as before, no "No passkey" notice (a card takes one still up away)', async () => {
  reset();
  found = [];
  bridge.ask(GET);
  await tick(5);
  assert.ok(noneText(), 'the notice from a request before');
  bridge.ended.length = 0;
  found = [ALICE];
  const rid = await pageAsks(GET);
  assert.match(cardText(), /Sign in with your passkey\?/);
  assert.equal(noneText(), null, 'the card comes up in its place');
  assert.deepEqual(bridge.ended, []);
  assert.ok(bridge.hasModal(rid), 'the request waits for the pick');
  bridge.abort();
  await tick(10);
});

test('Passyble not running: "Passyble isn\'t running" with "Open Passyble", which starts it and goes on in the card', async () => {
  reset();
  findError = { code: 'agent_unavailable', message: 'Passyble desktop app is not running' };
  const rid = await pageAsks(GET);
  assert.match(cardText(), /Passyble isn't running/);
  assert.ok(button('Use another device'));
  assert.ok(button('Cancel'));
  assert.deepEqual(bridge.ended, []);
  const starts = count('passkey.start_app');
  await click(button('Open Passyble'));
  await tick(10);
  assert.equal(count('passkey.start_app'), starts, 'not right as it appeared');
  await settle();
  await click(button('Open Passyble'));
  await tick(40);
  assert.equal(count('passkey.start_app'), starts + 1);
  assert.match(cardText(), /Sign in with your passkey\?/, 'started: the passkeys of the site');
  assert.match(cardText(), /alice@example\.com/);
  await settle();
  await click(button('Sign in'));
  await tick(20);
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-alice', credentialId: 'QUxJQ0U' }]]);
  assert.deepEqual(bridge.ended, []);

  // It doesn't start: the card says so and stays.
  reset();
  findError = { code: 'agent_unavailable', message: 'x' };
  startAnswer = () => ({ ok: false, error: { code: 'agent_unavailable', message: 'Passyble desktop app is not running' } });
  const again = await pageAsks(GET);
  await settle();
  await click(button('Open Passyble'));
  await tick(40);
  assert.match(card().querySelector('.status').textContent, /Start menu/);
  assert.ok(bridge.hasModal(again));
  assert.deepEqual(bridge.ended, []);
  bridge.abort();
  await tick(10);

  // No native host for this browser: what to set up, no "Open Passyble".
  reset();
  findError = { code: 'agent_unavailable', message: 'Specified native messaging host not found.' };
  await pageAsks(GET);
  assert.match(cardText(), /Can't connect to Passyble/);
  assert.equal(button('Open Passyble'), undefined);
  assert.ok(button('Use another device').classList.contains('primary'));
  bridge.abort();
  await tick(10);
});

test('an error from Passyble: what happened, "Try again" and "Use another device"; never the browser\'s own by itself', async () => {
  for (const error of [{ code: 'timeout', message: 'x' }, { code: 'internal', message: 'boom' }, { code: 'invalid_params', message: 'Bad credential id' }]) {
    reset();
    findError = error;
    const rid = await pageAsks(GET);
    assert.match(cardText(), /Passyble can't answer right now/, error.code);
    assert.doesNotMatch(cardText(), /boom|Bad credential/, 'never the raw message');
    assert.ok(button('Use another device'), error.code);
    assert.deepEqual(bridge.ended, [], error.code);
    findError = null;
    await settle();
    await click(button('Try again'));
    await tick(30);
    assert.match(cardText(), /alice@example\.com/, `${error.code}: tried again`);
    assert.ok(bridge.hasModal(rid));
    bridge.abort();
    await tick(10);
  }
  // A frame of another site (left to the browser's permissions policy): a card too.
  reset();
  findError = { code: 'not_found', message: 'Cross-origin frame' };
  let rid = await pageAsks(GET);
  assert.match(cardText(), /Passyble can't answer here/);
  assert.match(cardText(), /can't answer here/);
  assert.deepEqual(bridge.ended, []);
  await settle();
  await click(button('Use another device'));
  await tick(10);
  assert.deepEqual(bridge.ended, [[rid, 'fallback']]);
  // An RP ID this origin may not use: the page's SecurityError, as the browser would answer; no dialog.
  reset();
  findError = { code: 'url_mismatch', message: 'evil.com is not valid for https://login.example.com' };
  rid = await pageAsks(GET);
  assert.equal(card(), null);
  assert.equal(bridge.ended.at(-1)[0], rid);
  assert.equal(bridge.ended.at(-1)[1].error.code, 'url_mismatch');
  // An older desktop app: the request goes to the background as it is (the desktop app asks).
  reset();
  findError = { code: 'not_supported', message: 'unknown method' };
  rid = await pageAsks(GET);
  assert.equal(card(), null);
  assert.deepEqual(bridge.passed, [rid]);
  findError = null;
});

test('a failed sign-in keeps the card with what happened, "Use another device" there too', async () => {
  reset();
  bridge.answer = () => ({ ok: false, error: { code: 'cancelled', message: 'user verification cancelled' } });
  let rid = await pageAsks(GET);
  await settle();
  await click(button('Sign in'));
  await tick(20);
  assert.ok(card(), 'still there');
  assert.match(card().querySelector('.status').textContent, /Cancel/i);
  assert.equal(button('Sign in').disabled, false, 'the user can try again');
  assert.ok(bridge.hasModal(rid));
  bridge.abort();
  await tick(10);
  assert.equal(card(), null, 'the page gave up: the card goes with it');

  // userVerification "required" and no Windows Hello now, the passkey gone meanwhile, an internal
  // error: the card says so and stays; the browser's own WebAuthn only with "Use another device".
  for (const [error, text] of [
    [{ code: 'not_supported', message: 'user verification is required' }, /requires Windows Hello/],
    [{ code: 'not_found', message: 'no passkey for this site in Passyble' }, /No Passyble passkey for this site/],
    [{ code: 'internal', message: 'boom' }, /./],
  ]) {
    bridge.ended.length = 0;
    bridge.answer = () => ({ ok: false, error });
    rid = await pageAsks(GET);
    await settle();
    await click(button('Sign in'));
    await tick(20);
    assert.ok(card(), error.code);
    assert.match(card().querySelector('.status').textContent, text, error.code);
    assert.doesNotMatch(card().querySelector('.status').textContent, /boom/);
    assert.deepEqual(bridge.ended, [], error.code);
    assert.ok(button('Use another device'));
    bridge.abort();
    await tick(10);
  }
  // Already in Passyble: the page's InvalidStateError (final), no card.
  bridge.answer = () => ({ ok: false, error: { code: 'invalid_state', message: 'excluded' } });
  rid = await pageAsks(GET);
  await settle();
  await click(button('Sign in'));
  await tick(20);
  assert.equal(card(), null);
  assert.equal(bridge.ended.at(-1)[0], rid);
  assert.equal(bridge.ended.at(-1)[1].error.code, 'invalid_state');
});

test('fully locked: "Sign in with a Passyble passkey?", nothing of the vault; "Unlock" unlocks in the card (Windows Hello at once), then signs in', async () => {
  reset();
  locked = true;
  soft = false;
  const rid = await pageAsks(GET);
  assert.match(cardText(), /Sign in with a Passyble passkey\?/);
  assert.match(cardText(), /Passyble is locked\. Unlock it to use your passkeys for this site\./);
  assert.equal(card().querySelectorAll('.acct').length, 0, 'no account');
  assert.ok(button('Use another device'));
  assert.equal(button('Unlock and sign in'), undefined, 'nothing to sign in with yet: "Unlock"');
  const hellos = count('unlock.hello');
  await settle();
  await click(button('Unlock'));
  await tick(40);
  const asked = sent.filter((m) => m.type === 'unlock.options').at(-1);
  assert.equal(asked.for, undefined, 'for no login in particular');
  assert.equal(count('unlock.hello'), hellos + 1, 'Windows Hello without another click');
  assert.equal(count('unlock'), 0, "never the desktop app's unlock window");
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-alice', credentialId: 'QUxJQ0U' }]], 'the one passkey, once unlocked');
  assert.equal(card(), null);
});

test('fully locked, several passkeys behind it: after the unlock the user picks one', async () => {
  reset();
  locked = true;
  soft = false;
  found = [ALICE, BOB];
  const rid = await pageAsks(GET);
  await settle();
  await click(button('Unlock'));
  await tick(40);
  assert.deepEqual(bridge.completed, []);
  assert.match(cardText(), /Choose a passkey to sign in/);
  const rows = [...card().querySelectorAll('button.acct')];
  await settle();
  await click(rows[0]);
  await tick(20);
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-alice', credentialId: 'QUxJQ0U' }]]);
});

test('fully locked and nobody clicked (a page asking as it loads, a tab restored after boot): the card all the same, nothing before a click', async () => {
  reset();
  locked = true;
  soft = false;
  const hellos = count('unlock.hello');
  const rid = await pageAsks({ ...GET, userActivated: false });
  assert.match(cardText(), /Sign in with a Passyble passkey\?/);
  assert.ok(button('Unlock'));
  assert.ok(button('Use another device'));
  assert.deepEqual(bridge.ended, [], 'not the browser\'s own WebAuthn');
  await tick(50);
  assert.equal(count('unlock.hello'), hellos, 'no Windows Hello before a click');
  assert.equal(count('unlock'), 0);
  await settle();
  await click(button('Unlock'));
  await tick(40);
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-alice', credentialId: 'QUxJQ0U' }]]);
});

test('fully locked: the card asks to unlock first (Passyble can\'t tell yet); nothing in Passyble once unlocked: the browser\'s own at once, with the notice', async () => {
  reset();
  locked = true;
  soft = false;
  found = [];
  const rid = await pageAsks(GET);
  assert.match(cardText(), /Sign in with a Passyble passkey\?/, 'locked: the unlock card as before');
  assert.deepEqual(bridge.ended, [], 'locked: nothing handed on before the unlock');
  assert.equal(noneText(), null);
  await settle();
  await click(button('Unlock'));
  await tick(40);
  assert.equal(locked, false);
  assert.deepEqual(bridge.ended, [[rid, 'fallback']], 'unlocked and none: handed on at once');
  assert.deepEqual(bridge.completed, []);
  assert.equal(card(), null);
  assert.equal(noneText(), 'No passkey for example.com in Passyble');
  noneBox().querySelector('.x').dispatchEvent(new w.MouseEvent('click')); // a script's click: stays
  assert.ok(noneText());
  await click(noneBox().querySelector('.x'));
});

test('locked with the list kept: the accounts, and the sign-in unlocks for that login first', async () => {
  reset();
  locked = true;
  const rid = await pageAsks(GET);
  assert.match(cardText(), /alice@example\.com/);
  assert.match(cardText(), /Unlock and sign in/);
  await settle();
  await click(button('Unlock and sign in'));
  await tick(40);
  assert.equal(sent.filter((m) => m.type === 'unlock.options').at(-1).for, 'ex-alice', 'the unlock is for that login');
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-alice', credentialId: 'QUxJQ0U' }]]);
  assert.equal(count('unlock'), 0);
});

test('Windows Hello cancelled or not offered: the master password frame in the card; only that frame unlocks', async () => {
  reset();
  locked = true;
  helloAnswer = () => ({ ok: false, error: { code: 'cancelled', message: 'cancelled' } });
  const rid = await pageAsks(GET);
  await settle();
  await click(button('Unlock and sign in'));
  await tick(40);
  const el = frame();
  assert.ok(el, 'the master password frame, in the card');
  assert.equal(el.getAttribute('src'), `${ORIGIN}/src/unlock/frame.html?focus=1`);
  assert.match(cardText(), /Windows Hello was cancelled\. Enter your master password\./);
  assert.ok(button('Unlock with Windows Hello'), 'Windows Hello one click away');
  assert.equal(card().querySelector('input'), null, 'no password field of our own in the page');
  // Someone else's message does nothing.
  locked = false;
  w.dispatchEvent(new w.MessageEvent('message', { data: { passybleUnlock: 'unlocked' }, origin: 'https://login.example.com', source: el.contentWindow }));
  w.dispatchEvent(new w.MessageEvent('message', { data: { passybleUnlock: 'unlocked' }, origin: ORIGIN, source: w }));
  await tick(20);
  assert.deepEqual(bridge.completed, []);
  w.dispatchEvent(new w.MessageEvent('message', { data: { passybleUnlock: 'unlocked' }, origin: ORIGIN, source: el.contentWindow }));
  await tick(30);
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-alice', credentialId: 'QUxJQ0U' }]]);
  assert.equal(card(), null);
});

test('an unlock elsewhere (the popup, the desktop app) while the card waits for it goes on from there', async () => {
  reset();
  locked = true;
  unlockOpts = { inline: true, hello: false };
  const rid = await pageAsks(GET);
  await settle();
  await click(button('Unlock and sign in'));
  await tick(30);
  assert.ok(frame());
  locked = false;
  await new Promise((resolve) => runtimeListener({ type: 'lock_state', locked: false }, { id: 'pass-ext' }, resolve));
  await tick(30);
  assert.deepEqual(bridge.completed, [[rid, { id: 'ex-alice', credentialId: 'QUxJQ0U' }]]);
});

test('Cancel in the unlock goes back to the card; the request stays', async () => {
  reset();
  locked = true;
  unlockOpts = { inline: true, hello: false };
  const rid = await pageAsks(GET);
  await settle();
  await click(button('Unlock and sign in'));
  await tick(30);
  assert.ok(frame());
  await click(button('Cancel'));
  await tick(20);
  assert.equal(frame(), null);
  assert.ok(button('Unlock and sign in'), 'the card again');
  assert.ok(bridge.hasModal(rid));
  assert.deepEqual(bridge.ended, []);
  await click(button('Cancel'));
  await tick(10);
  assert.deepEqual(bridge.ended, [[rid, 'cancel']]);
});

test("the page's own create(): \"Save a passkey for <site> in Passyble?\", kept with the login chosen", async () => {
  reset();
  const rid = await pageAsks(CREATE);
  assert.match(cardText(), /Save passkey\?/);
  assert.equal(card().querySelector('.card-box').getAttribute('aria-label'), 'Save a passkey for example.com in Passyble?');
  assert.match(cardText(), /alice@example\.com/);
  assert.match(cardText(), /Alice/);
  const select = card().querySelector('select');
  assert.deepEqual([...select.options].map((o) => o.textContent), ['Example · alice@example.com', 'Example · carol', 'New login']);
  assert.equal(select.value, 'ex-alice', 'the login with that user name');
  assert.ok(button('Use another device'));
  const asked = sent.filter((m) => m.type === 'passkey.create_options').at(-1);
  assert.deepEqual(asked.options, { rpId: 'example.com', userName: 'alice@example.com', excludeCredentials: [] });
  await click(button('Save passkey'));
  await tick(10);
  assert.deepEqual(bridge.completed, [], 'not right as it appeared');
  await settle();
  await click(button('Save passkey'));
  await tick(20);
  assert.deepEqual(bridge.completed, [[rid, { itemId: 'ex-alice' }]]);
  assert.equal(card(), null);

  bridge.completed.length = 0;
  const again = await pageAsks(CREATE);
  card().querySelector('select').value = '';
  await settle();
  await click(button('Save passkey'));
  await tick(20);
  assert.deepEqual(bridge.completed, [[again, { itemId: null }]]);
});

test('the vault it goes to, when there are several; no logins for the site: no list', async () => {
  reset();
  createOpts = { candidates: [], suggested: null, excluded: false, vault: 'Work' };
  const rid = await pageAsks(CREATE);
  assert.equal(card().querySelector('select'), null);
  assert.match(cardText(), /In your Work vault/);
  await settle();
  await click(button('Save passkey'));
  await tick(20);
  assert.deepEqual(bridge.completed, [[rid, { itemId: null }]]);
});

test('already in Passyble (excludeCredentials): InvalidStateError at once; not running or an error: a card; an older desktop app: as before', async () => {
  reset();
  createOpts = { ...createOpts, excluded: true };
  let rid = await pageAsks(CREATE);
  assert.equal(card(), null);
  assert.equal(bridge.ended.at(-1)[0], rid);
  assert.equal(bridge.ended.at(-1)[1].error.code, 'invalid_state');
  reset();
  createError = { code: 'agent_unavailable', message: 'x' };
  rid = await pageAsks(CREATE);
  assert.match(cardText(), /Passyble isn't running/);
  assert.ok(button('Open Passyble'));
  assert.deepEqual(bridge.ended, []);
  await settle();
  await click(button('Open Passyble'));
  await tick(40);
  assert.match(cardText(), /Save passkey\?/, 'started: the save card');
  bridge.abort();
  await tick(10);
  createError = { code: 'timeout', message: 'x' };
  rid = await pageAsks(CREATE);
  assert.match(cardText(), /Passyble can't answer right now/);
  assert.ok(button('Try again'));
  assert.deepEqual(bridge.ended, []);
  bridge.abort();
  await tick(10);
  createError = { code: 'not_supported', message: 'unknown method' };
  rid = await pageAsks(CREATE);
  assert.deepEqual(bridge.passed, [rid]);
  createError = null;
});

test('create() while locked with the list kept: "Unlock and save" unlocks in the card, then saves with the login chosen', async () => {
  reset();
  locked = true;
  const rid = await pageAsks(CREATE);
  assert.match(cardText(), /Unlock and save/);
  card().querySelector('select').value = 'ex-carol';
  await settle();
  await click(button('Unlock and save'));
  await tick(40);
  assert.equal(count('unlock'), 0);
  assert.deepEqual(bridge.completed, [[rid, { itemId: 'ex-carol' }]]);
});

test('create() fully locked: after the unlock, the logins to choose from; none: saved at once', async () => {
  reset();
  locked = true;
  soft = false;
  let rid = await pageAsks(CREATE);
  assert.equal(card().querySelector('select'), null, 'nothing of the vault while locked');
  await settle();
  await click(button('Unlock and save'));
  await tick(40);
  assert.deepEqual(bridge.completed, [], 'the choice first');
  assert.ok(card().querySelector('select'));
  await settle();
  await click(button('Save passkey'));
  await tick(20);
  assert.deepEqual(bridge.completed, [[rid, { itemId: 'ex-alice' }]]);

  reset();
  locked = true;
  soft = false;
  createOpts = { candidates: [], suggested: null, excluded: false, vault: null };
  rid = await pageAsks(CREATE);
  await settle();
  await click(button('Unlock and save'));
  await tick(40);
  assert.deepEqual(bridge.completed, [[rid, { itemId: null }]]);
});

test('Use another device and Cancel for create() too; fully locked and nobody clicked: the save card all the same', async () => {
  reset();
  let rid = await pageAsks(CREATE);
  await settle();
  await click(button('Use another device'));
  await tick(10);
  assert.deepEqual(bridge.ended, [[rid, 'fallback']]);
  rid = await pageAsks(CREATE);
  await click(button('Cancel'));
  await tick(10);
  assert.deepEqual(bridge.ended.at(-1), [rid, 'cancel']);
  assert.deepEqual(bridge.completed, []);

  reset();
  locked = true;
  soft = false;
  rid = await pageAsks({ ...CREATE, userActivated: false });
  assert.match(cardText(), /Save passkey\?/);
  assert.equal(card().querySelector('.card-box').getAttribute('aria-label'), 'Save a passkey for example.com in Passyble?');
  assert.ok(button('Unlock and save'));
  assert.deepEqual(bridge.ended, []);
  bridge.abort();
  await tick(10);
});

test('the vault in this browser (passkeys come later there): the card says so; "Use another device" goes on', async () => {
  reset();
  findError = { code: 'not_supported', message: 'Passkeys need the Passyble app for now', reason: 'passkeys_need_app' };
  const rid = await pageAsks(GET);
  assert.ok(card(), 'a card, not an older app\'s path');
  assert.match(cardText(), /Passkeys need the Passyble app for now/);
  assert.match(cardText(), /Passkeys need the Passyble app for now/);
  assert.deepEqual(bridge.passed, [], 'not handed to the background as an older desktop app\'s request');
  await settle();
  await click(button('Use another device'));
  await tick(10);
  assert.deepEqual(bridge.ended, [[rid, 'fallback']]);
  findError = null;
});
