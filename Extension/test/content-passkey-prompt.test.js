import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';

const dom = new JSDOM('<!doctype html><html><body></body></html>', { url: 'https://login.example.com/signin', pretendToBeVisual: true });
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

const ALICE = { id: 'ex-alice', title: 'Example', user_name: 'alice@example.com', user_display_name: 'Alice', credential_id: 'QUxJQ0U' };
const BOB = { id: 'ex-bob', title: 'Example work', user_name: 'bob', user_display_name: '', credential_id: 'Qk9C' };

const sent = [];
let runtimeListener;
let settingsListener;
let stored = {};
let found = { rp_id: 'example.com', items: [ALICE], locked: false };
let findError = null;
let locked = false;
const responses = {
  'otp.context': () => ({ ok: true, result: { pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] } }),
  'logins.find': () => ({ ok: true, result: { items: [{ id: 'ex-alice', title: 'Example', username: 'alice@example.com', has_totp: false, has_passkey: true }], pending_otp: null, locked } }),
  'passkey.find': () => (findError ? { ok: false, error: findError } : { ok: true, result: { ...found, locked } }),
  'unlock.options': () => ({ ok: true, result: { inline: true, locked, hello: true } }),
  'unlock.hello': () => { locked = false; return { ok: true, result: { locked: false } }; },
  'save.query': () => ({ ok: true, result: null }),
};

/** bridge.js as main.js sees it: one pending conditional request, completed by a pick. */
const bridge = {
  pending: null,
  listeners: new Set(),
  completed: [],
  answer: () => ({ ok: true, result: { credentialId: 'x' } }),
  alive: () => true,
  hasConditional() { return !!this.pending; },
  conditionalRequest() { return this.pending; },
  onConditionalChange(fn) { this.listeners.add(fn); return () => this.listeners.delete(fn); },
  async completeConditional(id, credentialId) {
    this.completed.push([id, credentialId]);
    const res = this.answer(id, credentialId);
    if (res.ok) this.request(null);
    return res;
  },
  stepped: [],
  /** Passyble has none for the request: only the browser's own conditional request is left. */
  endConditional(rid) {
    if (!this.pending || this.pending.rid !== rid) return false;
    this.stepped.push(rid);
    this.request(null);
    return true;
  },
  request(req) {
    this.pending = req ? Object.freeze({ allowCredentials: [], ...req }) : null;
    for (const fn of this.listeners) fn(!!req);
  },
};

let main;
let ui;
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
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : { ok: true, result: {} };
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: {
      local: { get: async () => ({ ...stored }) },
      sync: { get: async () => ({}) },
      onChanged: { addListener: (f) => { settingsListener = f; } },
    },
  };
  doc.body.innerHTML = '<form><h1>Sign in</h1><input type="text" name="user" autocomplete="username webauthn"><input type="password" name="password"><button>Sign in</button></form>';
  main = await import('../src/content/main.js');
  ui = await import('../src/content/ui-common.js');
  await main.start();
});

after(() => {
  main.stop();
  delete globalThis.__passBridge;
  w.close();
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const click = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true, button: 0 }));
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
const button = (text) => [...(card()?.querySelectorAll('button') || [])].find((b) => b.textContent.trim() === text);
const count = (type) => sent.filter((m) => m.type === type).length;
let rid = 0;

async function pageAsks(extra = {}) {
  bridge.request({ rid: `r${++rid}`, rpId: 'example.com', ...extra });
  await tick(20);
}

async function settle() {
  await tick(ui.MIN_VISIBLE_MS + 30);
}

test('the page asks for passkey sign-in: Passyble looks up its passkeys and offers the one it has', async () => {
  const before = count('passkey.find');
  await pageAsks({ allowCredentials: [{ id: 'QUxJQ0U' }] });
  assert.equal(count('passkey.find'), before + 1);
  const ask = sent.filter((m) => m.type === 'passkey.find').at(-1);
  assert.deepEqual(ask.options, { rpId: 'example.com', allowCredentials: [{ id: 'QUxJQ0U' }] }, 'the request, nothing else of the page');
  assert.ok(card(), 'the card is shown');
  assert.equal(doc.querySelector('pass-passkey').shadowRoot, null, 'closed shadow root');
  assert.match(cardText(), /Sign in with your passkey\?/);
  assert.match(cardText(), /example\.com/);
  assert.match(cardText(), /alice@example\.com/);
  assert.ok(button('Sign in'));
  assert.ok(button('Not now'));
  assert.equal(doc.activeElement, doc.body, 'the page keeps the focus');

  // A click the user didn't make, or one right as it appeared, does nothing.
  button('Sign in').click();
  await click(button('Sign in'));
  await tick(10);
  assert.deepEqual(bridge.completed, []);

  await settle();
  await click(button('Sign in'));
  await tick(20);
  assert.deepEqual(bridge.completed, [['ex-alice', 'QUxJQ0U']], 'that passkey completes the page request');
  assert.equal(card(), null, 'signed in: the card goes');
});

test('a failed sign-in keeps the card with what happened; the request stays pending', async () => {
  bridge.completed.length = 0;
  bridge.answer = () => ({ ok: false, error: { code: 'cancelled', message: 'user verification cancelled' } });
  try {
    await pageAsks();
    await settle();
    await click(button('Sign in'));
    await tick(20);
    assert.equal(bridge.completed.length, 1);
    assert.ok(card(), 'still there');
    assert.match(card().querySelector('.status').textContent, /Cancel/i);
    assert.equal(button('Sign in').disabled, false, 'the user can try again');
    assert.ok(bridge.hasConditional());
  } finally {
    bridge.answer = () => ({ ok: true, result: { credentialId: 'x' } });
  }
  // The page gives up on its request (AbortSignal): the card goes with it.
  bridge.request(null);
  await tick(10);
  assert.equal(card(), null);
});

test('several passkeys: the user picks the account', async () => {
  found = { rp_id: 'example.com', items: [ALICE, BOB], locked: false };
  bridge.completed.length = 0;
  try {
    await pageAsks();
    assert.match(cardText(), /Choose a passkey to sign in/);
    const rows = [...card().querySelectorAll('button.acct')];
    assert.equal(rows.length, 2);
    assert.equal(rows[1].getAttribute('aria-label'), 'Sign in as bob');
    assert.equal(button('Sign in'), undefined, 'no single Sign in button');
    await settle();
    await click(rows[1]);
    await tick(20);
    assert.deepEqual(bridge.completed, [['ex-bob', 'Qk9C']]);
    assert.equal(card(), null);
  } finally {
    found = { rp_id: 'example.com', items: [ALICE], locked: false };
  }
});

test('nothing for the site (unlocked): Passyble steps out of the request at once and says so; no card, nothing waits', async () => {
  found = { rp_id: 'example.com', items: [], locked: false };
  bridge.stepped.length = 0;
  await pageAsks();
  assert.equal(card(), null);
  assert.deepEqual(bridge.stepped, [`r${rid}`], 'endConditional: only the browser\'s own conditional request is left');
  assert.equal(bridge.hasConditional(), false);
  assert.equal(noneText(), 'No passkey for example.com in Passyble');
  assert.equal(noneBox().getAttribute('role'), 'status');
  assert.equal(doc.activeElement, doc.body, 'the page keeps the focus');
  // The username field: no Passyble menu opens for a request Passyble is out of.
  const field = doc.querySelector('[name=user]');
  field.focus();
  await tick(30);
  const menuHost = doc.querySelector('pass-menu');
  const menuItems = menuHost ? [...shadowRoots.get(menuHost).querySelectorAll('.item')] : [];
  assert.ok(!menuItems.some((el) => /Sign in with passkey/.test(el.textContent)), 'no passkey entry');
  field.blur();
  await tick(10);
  await click(noneBox().querySelector('.x'));
  assert.equal(noneText(), null, 'dismissed');

  // The page asks again (an SPA re-render): out at once again, the notice only once per site.
  await pageAsks();
  assert.equal(bridge.stepped.length, 2);
  assert.equal(noneText(), null, 'once per site on this page');
  // Locked with the list kept (the same list) and nothing in it for the site: the same, for another site.
  locked = true;
  found = { rp_id: 'other.example', items: [], locked: false };
  await pageAsks({ rpId: 'other.example' });
  assert.equal(card(), null);
  assert.equal(bridge.stepped.length, 3);
  assert.equal(noneText(), 'No passkey for other.example in Passyble');
  assert.equal(count('unlock.options'), 0, 'no unlock asked for');
  await click(noneBox().querySelector('.x'));
  locked = false;
  found = { rp_id: 'example.com', items: [ALICE], locked: false };
});

test('"Offer passkey sign-in" off: Passyble steps out all the same, without the notice', async () => {
  stored = { autoPasskey: false };
  settingsListener({ autoPasskey: { newValue: false } }, 'local');
  await tick(10);
  found = { rp_id: 'quiet.example', items: [], locked: false };
  bridge.stepped.length = 0;
  try {
    await pageAsks({ rpId: 'quiet.example' });
    assert.equal(bridge.stepped.length, 1);
    assert.equal(noneText(), null);
  } finally {
    found = { rp_id: 'example.com', items: [ALICE], locked: false };
    stored = {};
    settingsListener({ autoPasskey: { newValue: true } }, 'local');
    await tick(10);
  }
});

test('a passkey for the site, or Passyble not reachable, or an older desktop app: Passyble stays in the request, no notice', async () => {
  bridge.stepped.length = 0;
  await pageAsks();
  assert.ok(card(), 'the card as before');
  assert.ok(bridge.hasConditional());
  bridge.request(null);
  await tick(10);
  for (const error of [{ code: 'agent_unavailable', message: 'x' }, { code: 'not_supported', message: 'unknown method' }]) {
    findError = error;
    await pageAsks();
    assert.equal(card(), null, error.code);
    assert.ok(bridge.hasConditional(), `${error.code}: the request stays`);
    bridge.request(null);
  }
  findError = null;
  assert.deepEqual(bridge.stepped, []);
  assert.equal(noneText(), null);
});

test('fully locked: the card offers "Unlock" with nothing of the vault; once unlocked it signs in with the one passkey', async () => {
  bridge.completed.length = 0;
  findError = { code: 'locked', message: 'Vault is locked' };
  locked = true;
  await pageAsks();
  assert.ok(card(), 'a card, though Passyble knows nothing of the vault yet');
  assert.match(cardText(), /Sign in with a Passyble passkey\?/);
  assert.match(cardText(), /Passyble is locked\. Unlock it/);
  assert.equal(card().querySelectorAll('.acct').length, 0, 'no account');
  assert.doesNotMatch(cardText(), /alice/);
  assert.ok(button('Unlock'));
  assert.ok(button('Not now'));
  assert.equal(button('Use another device'), undefined, "the browser's own passkey autofill runs alongside already");
  const hellos = count('unlock.hello');
  await tick(30);
  assert.equal(count('unlock.hello'), hellos, 'nothing before a click');
  // The unlock lifts the lock: passkey.find answers.
  findError = null;
  await settle();
  await click(button('Unlock'));
  await tick(50);
  assert.equal(count('unlock.hello'), hellos + 1, 'Windows Hello at once');
  assert.equal(count('unlock'), 0, "never the desktop app's own prompt");
  assert.equal(sent.filter((m) => m.type === 'passkey.find').at(-1).automatic, false);
  assert.deepEqual(bridge.completed, [['ex-alice', 'QUxJQ0U']]);
  assert.equal(card(), null);
});

test('fully locked, several passkeys or none behind it: the pick after the unlock, or Passyble steps out with "No passkey for <site> in Passyble"', async () => {
  bridge.completed.length = 0;
  findError = { code: 'locked', message: 'Vault is locked' };
  locked = true;
  found = { rp_id: 'example.com', items: [ALICE, BOB], locked: false };
  await pageAsks();
  findError = null;
  await settle();
  await click(button('Unlock'));
  await tick(50);
  assert.deepEqual(bridge.completed, []);
  assert.match(cardText(), /Choose a passkey to sign in/);
  const rows = [...card().querySelectorAll('button.acct')];
  assert.equal(rows.length, 2);
  await settle();
  await click(rows[1]);
  await tick(20);
  assert.deepEqual(bridge.completed, [['ex-bob', 'Qk9C']]);

  bridge.completed.length = 0;
  findError = { code: 'locked', message: 'Vault is locked' };
  locked = true;
  found = { rp_id: 'example.com', items: [], locked: false };
  await pageAsks();
  findError = null;
  await settle();
  bridge.stepped.length = 0;
  await click(button('Unlock'));
  await tick(50);
  assert.equal(card(), null, 'unlocked and none: the card goes');
  assert.deepEqual(bridge.stepped, [`r${rid}`], 'Passyble steps out; the browser\'s own passkey autofill stays');
  assert.equal(bridge.hasConditional(), false);
  assert.deepEqual(bridge.completed, []);
  assert.equal(noneText(), 'No passkey for example.com in Passyble', 'shown after the click, though shown on this page before');
  await click(noneBox().querySelector('.x'));
  found = { rp_id: 'example.com', items: [ALICE], locked: false };
});

test('fully locked and "Offer passkey sign-in" off: no card, as before', async () => {
  stored = { autoPasskey: false };
  settingsListener({ autoPasskey: { newValue: false } }, 'local');
  await tick(10);
  findError = { code: 'locked', message: 'Vault is locked' };
  locked = true;
  try {
    await pageAsks();
    assert.equal(card(), null);
  } finally {
    bridge.request(null);
    findError = null;
    locked = false;
    stored = {};
    settingsListener({ autoPasskey: { newValue: true } }, 'local');
    await tick(10);
  }
});

test('the setting turns the card off; the menu still offers the passkey', async () => {
  stored = { autoPasskey: false };
  settingsListener({ autoPasskey: { newValue: false } }, 'local');
  await tick(10);
  try {
    await pageAsks();
    assert.equal(card(), null);
    const field = doc.querySelector('[name=user]');
    field.focus();
    await tick(30);
    const menu = shadowRoots.get(doc.querySelector('pass-menu'));
    const passkeyEntry = [...menu.querySelectorAll('.item')].find((el) => /Sign in with passkey/.test(el.textContent));
    assert.ok(passkeyEntry, 'the passkey from passkey.find in the menu');
    assert.match(passkeyEntry.textContent, /alice@example\.com/);
    field.blur();
  } finally {
    stored = {};
    settingsListener({ autoPasskey: { newValue: true } }, 'local');
    await tick(10);
  }
  // Back on: the card for the request still pending.
  assert.ok(card());
  bridge.request(null);
  await tick(10);
});

test('locked with the list kept: "Unlock and sign in" unlocks for that login (Windows Hello at once), then signs in', async () => {
  locked = true;
  bridge.completed.length = 0;
  await pageAsks();
  assert.ok(button('Unlock and sign in'));
  const hellos = count('unlock.hello');
  await settle();
  await click(button('Unlock and sign in'));
  await tick(40);
  assert.equal(sent.filter((m) => m.type === 'unlock.options').at(-1)?.for, 'ex-alice', 'the unlock is for that login');
  assert.equal(count('unlock.hello'), hellos + 1, 'Windows Hello without another click');
  assert.equal(count('unlock'), 0, "not the desktop app's own prompt");
  assert.deepEqual(bridge.completed, [['ex-alice', 'QUxJQ0U']]);
  assert.equal(card(), null);
  assert.equal(locked, false);
});

test('"Not now": the request stays pending, and the card stays away for the site on this page', async () => {
  bridge.completed.length = 0;
  await pageAsks();
  assert.ok(card());
  await click(button('Not now'));
  await tick(10);
  assert.equal(card(), null);
  assert.ok(bridge.hasConditional(), 'the page request is still pending (passkey autofill)');
  assert.deepEqual(bridge.completed, []);
  // The page asks again (an SPA re-render): no card again on this page.
  bridge.request(null);
  await pageAsks();
  assert.equal(card(), null);
  // Another site (the RP ID of another request) is asked again.
  found = { rp_id: 'login.example.com', items: [ALICE], locked: false };
  await pageAsks({ rpId: 'login.example.com' });
  assert.ok(card());
  found = { rp_id: 'example.com', items: [ALICE], locked: false };
});

test('a lock while the card is up: the accounts go, the card asks to unlock (fully locked: nothing of the vault)', async () => {
  assert.ok(card());
  assert.match(cardText(), /alice@example\.com/);
  findError = { code: 'locked', message: 'Vault is locked' };
  await new Promise((resolve) => runtimeListener({ type: 'lock_state', locked: true }, { id: 'pass-ext' }, resolve));
  await tick(20);
  assert.ok(card());
  assert.doesNotMatch(cardText(), /alice/);
  assert.ok(button('Unlock'));
  findError = null;
  bridge.request(null);
  await tick(10);
  assert.equal(card(), null, 'the request ended: the card goes');
});

test('the menu of the username field lists the passkeys of the request; a pick there signs in with that one', async () => {
  found = { rp_id: 'example.com', items: [ALICE, BOB], locked: false };
  bridge.completed.length = 0;
  try {
    await pageAsks();
    const field = doc.querySelector('[name=user]');
    field.focus();
    await tick(30);
    const menu = shadowRoots.get(doc.querySelector('pass-menu'));
    const passkeys = [...menu.querySelectorAll('.item')].filter((el) => /Sign in with passkey/.test(el.textContent));
    assert.equal(passkeys.length, 2, 'one entry per passkey, not per login');
    assert.match(passkeys[1].textContent, /Sign in with passkey · bob/);
    await settle();
    await click(passkeys[1]);
    await tick(20);
    assert.deepEqual(bridge.completed, [['ex-bob', 'Qk9C']]);
    assert.equal(card(), null, 'the card goes with the request');
    field.blur();
  } finally {
    found = { rp_id: 'example.com', items: [ALICE], locked: false };
  }
});
