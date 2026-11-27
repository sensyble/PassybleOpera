import { test, before, after, afterEach, mock } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { JSDOM } from 'jsdom';
import { dispatchTrusted } from './helpers/dom.js';
import { charRuns, cssEscapedString, REVEAL_TTL_MS, showGeneratedPassword } from '../src/content/reveal.js';
import { MIN_VISIBLE_MS } from '../src/content/ui-common.js';

const PASSWORD = 'Tr0ub4dor&3xyz';
const dom = new JSDOM(`<!doctype html><html><body>
  <form id="login" action="/session"><h1>Sign in</h1>
    <input type="email" name="email" id="email" autocomplete="username">
    <input type="password" name="password" id="pw" style="font-size: 18px" autocomplete="current-password">
    <button type="submit" id="go">Sign in</button></form>
  <form id="signup" action="/register"><h1>Create account</h1>
    <input type="email" name="new-email" id="new-email" autocomplete="email">
    <input type="password" id="new1" autocomplete="new-password" style="font-size: 18px">
    <input type="password" id="new2" autocomplete="new-password" style="font-size: 18px">
    <button type="submit" id="create">Create account</button></form>
  <p id="elsewhere">Forgot your password?</p>
  <iframe id="frame" srcdoc="<input type=password id=fpw>"></iframe>
</body></html>`, { url: 'https://app.example/login', pretendToBeVisual: true });
const w = dom.window;
const doc = w.document;

const IN_VIEW = { left: 10, top: 10, right: 210, bottom: 40, width: 200, height: 30, x: 10, y: 10 };
let fieldRect = IN_VIEW;
w.Element.prototype.getBoundingClientRect = function () {
  return this.id === 'new2' ? fieldRect : IN_VIEW;
};
const shadowRoots = new Map();
const attachShadow = w.Element.prototype.attachShadow;
w.Element.prototype.attachShadow = function (init) {
  const root = attachShadow.call(this, init);
  shadowRoots.set(this, root);
  return root;
};

const sent = [];
const posted = [];
const logged = [];
const clipboard = [];
let store = {};
let settingsListener = null;
let runtimeListener = null;
const creds = { username: 'alice@example.com', password: PASSWORD, totp: null };
let nextPassword = 0;
const ok = (result) => ({ ok: true, result });
const LOGIN = { id: 'a', title: 'App', username: 'alice@example.com', has_totp: false, has_passkey: false };
const findOne = () => ok({ items: [LOGIN], pending_otp: null });
const responses = {
  'otp.context': () => ok({ pending: null, offer: false, autoFillOtp: false, otpFieldElsewhere: false, items: [] }),
  'logins.find': findOne,
  'logins.fill': () => ok(creds),
  'logins.fill_cross': () => ok({ ...creds, cross: true }),
  'save.query': () => ok(null),
  generate: () => { nextPassword += 1; return ok({ password: `Gen-Pass-${nextPassword}-2468-xyz` }); },
  'draft.save': () => ok({ id: 'd1', created: true }),
  'generate.copy': () => ok({ copied: true }),
};

let main;
const consoleMethods = ['log', 'info', 'warn', 'error', 'debug'];
const originalConsole = {};
before(async () => {
  Object.assign(globalThis, {
    window: w, document: doc, location: w.location, history: w.history, Node: w.Node,
    MutationObserver: w.MutationObserver, requestAnimationFrame: w.requestAnimationFrame.bind(w),
    getComputedStyle: w.getComputedStyle.bind(w),
  });
  Object.defineProperty(globalThis.navigator, 'clipboard', {
    configurable: true,
    value: { writeText: async (text) => { clipboard.push(text); } },
  });
  for (const m of consoleMethods) {
    originalConsole[m] = console[m];
    console[m] = (...args) => { logged.push(args.map(String).join(' ')); originalConsole[m](...args); };
  }
  const postMessage = w.postMessage.bind(w);
  w.postMessage = (data, ...rest) => { posted.push(JSON.stringify(data)); return postMessage(data, ...rest); };
  const framePost = doc.getElementById('frame').contentWindow;
  if (framePost) framePost.postMessage = (data) => { posted.push(JSON.stringify(data)); };
  globalThis.chrome = {
    runtime: {
      id: 'pass-ext',
      sendMessage: async (msg) => {
        sent.push(msg);
        const fn = responses[msg.type];
        return fn ? fn(msg) : ok({});
      },
      onMessage: { addListener: (f) => { runtimeListener = f; } },
    },
    storage: {
      local: { get: async () => ({ ...store }) },
      sync: { get: async () => ({}) },
      onChanged: { addListener: (f) => { settingsListener = f; } },
    },
  };
  main = await import('../src/content/main.js');
  await main.start();
});

after(() => {
  for (const m of consoleMethods) console[m] = originalConsole[m];
  main.stop();
  w.close();
});

afterEach(() => {
  doc.activeElement?.blur?.();
  fieldRect = IN_VIEW;
  sent.length = 0;
  clipboard.length = 0;
});

const tick = (ms = 0) => new Promise((r) => setTimeout(r, ms));
const command = (msg) => new Promise((resolve) => runtimeListener(msg, { id: 'pass-ext' }, resolve));
const $ = (id) => doc.getElementById(id);
const revealHost = () => doc.querySelector('pass-reveal');
const revealRoot = () => (revealHost() ? shadowRoots.get(revealHost()) : null);
const copyButton = () => revealRoot()?.querySelector('button.copy');
const press = (el) => dispatchTrusted(el, new w.MouseEvent('mousedown', { bubbles: true, composed: true, cancelable: true, button: 0 }));
const trustedClick = (el) => dispatchTrusted(el, new w.MouseEvent('click', { bubbles: true, composed: true, cancelable: true, button: 0 }));
const lastSent = (type) => sent.filter((m) => m.type === type).at(-1);
const menuItems = () => {
  const host = doc.querySelector('pass-menu');
  return host ? [...shadowRoots.get(host).querySelectorAll('.item')] : [];
};

/** The password the callout shows: its CSS `content` escapes, run after run. */
function shownPassword() {
  const root = revealRoot();
  if (!root) return null;
  const css = [...root.querySelectorAll('style')].map((s) => s.textContent).join('\n');
  const runs = new Map();
  for (const m of css.matchAll(/\.r(\d+)::before \{ content: "((?:\\[0-9a-f]{6})*)"; \}/g)) {
    runs.set(Number(m[1]), m[2].replace(/\\([0-9a-f]{6})/g, (_, hex) => String.fromCodePoint(parseInt(hex, 16))));
  }
  return [...runs.keys()].sort((a, b) => a - b).map((k) => runs.get(k)).join('').replaceAll('␣', ' ');
}

/** Generates and fills in the sign-up form (the context menu's "Generate password"); the password. */
async function generate() {
  $('new1').focus();
  await tick(5);
  assert.deepEqual(await command({ type: 'cmd.generate-here' }), { ok: true });
  await tick(5);
  const password = `Gen-Pass-${nextPassword}-2468-xyz`;
  assert.equal($('new2').value, password);
  assert.equal(doc.activeElement, $('new2'), 'the confirmation was filled last');
  return password;
}

/** A generated password whose callout has been on screen long enough for clicks to count. */
async function generateAndWait() {
  const password = await generate();
  await tick(MIN_VISIBLE_MS + 30);
  return password;
}

/** Everything of the page's own DOM a script could read: markup, text, every attribute, selectors. */
function assertNotInPage(secret) {
  assert.ok(!doc.documentElement.outerHTML.includes(secret), 'not in the markup');
  assert.ok(!doc.documentElement.textContent.includes(secret), 'not in textContent');
  assert.ok(!(doc.body.innerText ?? '').includes(secret), 'not in innerText');
  for (const el of doc.querySelectorAll('*')) {
    for (const attr of el.attributes) assert.ok(!attr.value.includes(secret), `not in ${el.localName}[${attr.name}]`);
  }
  assert.equal(doc.querySelector(`[value*="${secret}"], [title*="${secret}"], [aria-label*="${secret}"], [data-password]`), null);
  assert.equal(revealHost().shadowRoot, null, 'closed shadow root');
  assert.equal(revealHost().attributes.length <= 4, true, 'only the host attributes (style, lang, dir, popover)');
  assert.ok(!logged.some((line) => line.includes(secret)), 'not in the console');
  assert.ok(!posted.some((m) => m.includes(secret)), 'not in a window message');
  // Not even inside Passyble's own shadow root as text (Chromium's window.find() searches there).
  const root = revealRoot();
  const walker = doc.createTreeWalker(root, w.NodeFilter.SHOW_TEXT);
  let text = '';
  for (let n = walker.nextNode(); n; n = walker.nextNode()) text += n.data;
  assert.ok(!text.includes(secret) && !text.includes(secret.slice(0, 4)), 'no text node with the password');
  for (const el of root.querySelectorAll('*')) {
    for (const attr of el.attributes) assert.ok(!attr.value.includes(secret.slice(0, 4)), `not in the shadow ${el.localName}[${attr.name}]`);
  }
}

async function assertLoginFilledWithoutCallout(path, run) {
  $('pw').value = '';
  await run();
  await tick(5);
  assert.equal($('pw').value, PASSWORD, `${path}: filled`);
  assert.equal(revealHost(), null, `${path}: nothing shows`);
  $('pw').value = '';
}

/** Opens the suggestions on the username field and picks the login, once the click would count. */
async function pickInMenu() {
  $('email').value = '';
  $('email').focus();
  await press($('email'));
  await trustedClick($('email'));
  await tick(30);
  assert.equal(menuItems().length, 1, 'the suggestions');
  await tick(MIN_VISIBLE_MS + 30);
  await trustedClick(menuItems()[0]);
  await tick(30);
}

test('a filled login never shows its password: popup, shortcut, context menu, "Fill on this page"', async () => {
  $('pw').focus();
  await tick(5);
  await assertLoginFilledWithoutCallout('popup', () => command({ type: 'cmd.fill-item', id: 'a' }));
  assert.equal(doc.activeElement, $('pw'), 'the fill left the focus in the password field');
  await assertLoginFilledWithoutCallout('shortcut and context menu', () => command({ type: 'cmd.fill-login' }));
  await assertLoginFilledWithoutCallout('"Fill on this page"', () => command({ type: 'cmd.fill-cross', id: 'b' }));
  $('pw').focus();
  await tick(5);
  assert.equal(revealHost(), null, 'nor on coming back');
});

test('a filled login never shows its password: a pick in the inline menu', async () => {
  await assertLoginFilledWithoutCallout('inline menu', pickInMenu);
});

test('a filled login never shows its password: a pick that unlocked first', async () => {
  let locked = true;
  const fill = responses['logins.fill'];
  responses['logins.fill'] = () => (locked ? { ok: false, error: { code: 'locked', message: 'Vault is locked' } } : ok(creds));
  responses['logins.find'] = () => ok({ items: [LOGIN], pending_otp: null, locked });
  responses['unlock.options'] = () => ok({ inline: true, locked, hello: true });
  responses['unlock.hello'] = () => { locked = false; return ok({ locked: false }); };
  try {
    await assertLoginFilledWithoutCallout('one-step unlock', pickInMenu);
    assert.ok(sent.some((m) => m.type === 'unlock.hello'), 'Windows Hello first');
  } finally {
    responses['logins.fill'] = fill;
    responses['logins.find'] = findOne;
    delete responses['unlock.options'];
    delete responses['unlock.hello'];
  }
});

test('the old setting does not matter: logins stay hidden with it stored on, generated passwords show with it stored off', async () => {
  store = { revealFilled: true };
  settingsListener({ revealFilled: { newValue: true } }, 'local');
  await tick(5);
  $('pw').focus();
  await assertLoginFilledWithoutCallout('stored on', () => command({ type: 'cmd.fill-item', id: 'a' }));
  store = { revealFilled: false };
  settingsListener({ revealFilled: { newValue: false } }, 'local');
  await tick(5);
  const password = await generate();
  assert.equal(shownPassword(), password);
  store = {};
});

test('the setting is gone from the extension: no option, default or string', async () => {
  const { DEFAULT_SETTINGS } = await import('../src/shared/settings.js');
  assert.ok(!('revealFilled' in DEFAULT_SETTINGS));
  const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
  assert.ok(!read('src/options/options.html').includes('revealFilled'));
  assert.ok(!read('src/content/main.js').includes('revealFilled'));
  for (const locale of ['de', 'en', 'es', 'fr', 'hi', 'id', 'ja', 'ko', 'zh_CN']) {
    const messages = JSON.parse(read(`_locales/${locale}/messages.json`));
    assert.ok(!('settingRevealFilled' in messages) && !('settingRevealFilledDetails' in messages), locale);
    assert.ok(messages.revealCaption?.message, `${locale} has the caption`);
  }
});

test('a generated password shows once, in a closed shadow root, with Copy, in the field\'s font size', async () => {
  const password = await generate();
  assert.ok(revealHost(), 'callout mounted');
  assert.equal(shownPassword(), password, 'shows exactly the generated password');
  assert.equal($('new2').type, 'password', 'the page\'s field stays a password field');
  assert.equal($('new2').getAttribute('type'), 'password');
  const pwEl = revealRoot().querySelector('.pw');
  assert.equal(pwEl.style.fontSize, '18px', 'in the field\'s font size');
  assert.equal(pwEl.getAttribute('aria-hidden'), 'true', 'not read out by screen readers');
  assert.equal(revealRoot().querySelector('.cap .text').textContent, 'Generated password');
  assert.equal(copyButton().textContent, 'Copy');
  assert.equal(copyButton().getAttribute('type'), 'button');
  assert.equal(revealRoot().querySelectorAll('button').length, 1, 'Copy is the only control');
  assertNotInPage(password);
});

test('only the Copy button takes clicks', () => {
  const source = readFileSync(new URL('../src/content/reveal.js', import.meta.url), 'utf8');
  const css = source.slice(source.indexOf('const CSS = `'), source.indexOf('`;', source.indexOf('const CSS = `')));
  assert.match(css, /\.reveal \{[^}]*pointer-events: none;/);
  assert.match(css, /\.copy \{[^}]*pointer-events: auto;/);
  assert.equal((css.match(/pointer-events: auto/g) || []).length, 1);
});

test('leaving the field hides it and drops the password; coming back shows nothing', async () => {
  await generate();
  const root = revealRoot();
  assert.ok(root);
  $('email').focus();
  assert.equal(revealHost(), null, 'gone');
  assert.ok(![...root.querySelectorAll('style')].some((s) => /\\0000/.test(s.textContent)), 'the escapes are dropped too');
  $('new2').focus();
  await tick(5);
  assert.equal(revealHost(), null, 'focusing the field again shows nothing');
});

test('typing or editing in the field hides it', async () => {
  await generate();
  assert.ok(revealHost());
  await dispatchTrusted($('new2'), new w.KeyboardEvent('keydown', { key: 'Shift', bubbles: true }));
  assert.ok(revealHost(), 'a modifier on its own is no typing');
  await dispatchTrusted($('new2'), new w.KeyboardEvent('keydown', { key: 'a', bubbles: true, cancelable: true }));
  assert.equal(revealHost(), null, 'a key');

  await generate();
  assert.ok(revealHost());
  $('new2').dispatchEvent(new w.Event('paste', { bubbles: true }));
  assert.equal(revealHost(), null, 'a paste');

  await generate();
  $('new2').dispatchEvent(new w.Event('input', { bubbles: true }));
  assert.equal(revealHost(), null, 'an input event');
});

test('a click elsewhere hides it; a click into the field itself does not', async () => {
  await generate();
  await press($('new2'));
  assert.ok(revealHost(), 'placing the caret in the field');
  await press($('elsewhere'));
  assert.equal(revealHost(), null);
});

test('submitting the form hides it (also a script\'s requestSubmit)', async () => {
  await generate();
  assert.ok(revealHost());
  $('signup').addEventListener('submit', (e) => e.preventDefault(), { once: true });
  $('signup').requestSubmit();
  assert.equal(revealHost(), null, 'requestSubmit');
  await generate();
  assert.ok(revealHost());
  await dispatchTrusted($('new2'), new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true }));
  assert.equal(revealHost(), null, 'Enter in the field');
});

test('Passyble locking hides it', async () => {
  await generate();
  assert.ok(revealHost());
  await command({ type: 'lock_state', locked: true });
  assert.equal(revealHost(), null);
});

test('leaving the page, an SPA navigation, the window losing focus, or scrolling the field away hide it', async () => {
  await generate();
  w.dispatchEvent(new w.Event('pagehide'));
  assert.equal(revealHost(), null, 'pagehide');

  await generate();
  w.history.pushState({}, '', '/login?step=2');
  await tick(300);
  assert.equal(revealHost(), null, 'SPA navigation');
  w.history.replaceState({}, '', '/login');

  await generate();
  w.dispatchEvent(new w.Event('blur'));
  assert.equal(revealHost(), null, 'window blur');

  await generate();
  assert.ok(revealHost());
  fieldRect = { left: 10, top: -200, right: 210, bottom: -170, width: 200, height: 30, x: 10, y: -200 };
  doc.dispatchEvent(new w.Event('scroll'));
  assert.equal(revealHost(), null, 'scrolled out of view');
});

test('the page changing the value (or showing it as text) hides it', async () => {
  await generate();
  $('new2').value = 'something else';
  await tick(300);
  assert.equal(revealHost(), null, 'value changed');

  await generate();
  $('new2').type = 'text'; // the site's own "show password" toggle
  await tick(300);
  assert.equal(revealHost(), null, 'field shows its own text');
  $('new2').type = 'password';
});

test(`gone after ${REVEAL_TTL_MS / 1000} s even while the field keeps the focus`, async () => {
  $('new1').focus();
  await tick(5);
  mock.timers.enable({ apis: ['setTimeout', 'setInterval'] });
  try {
    // No tick() here (setTimeout is mocked): the generator and the fill need no timer to end.
    assert.deepEqual(await command({ type: 'cmd.generate-here' }), { ok: true });
    assert.ok(revealHost());
    mock.timers.tick(REVEAL_TTL_MS - 1000);
    assert.ok(revealHost(), 'still there before the timeout');
    assert.equal(doc.activeElement, $('new2'));
    mock.timers.tick(1000);
    assert.equal(revealHost(), null, 'timed out');
  } finally {
    mock.timers.reset();
  }
});

test('nothing shows when the focus is not in the field, or the field holds something else', () => {
  $('new2').value = 'Some-Generated-1';
  $('email').focus();
  assert.equal(showGeneratedPassword($('new2'), 'Some-Generated-1'), null, 'not focused');
  $('new2').focus();
  assert.equal(showGeneratedPassword($('new2'), 'Other-Value-2'), null, 'not what the field holds');
  assert.equal(revealHost(), null);
  $('new2').value = '';
});

test('only in the frame that filled: nothing in another frame, nothing posted to frames', async () => {
  posted.length = 0;
  const password = await generate();
  assert.ok(revealHost());
  const frameDoc = $('frame').contentDocument;
  if (frameDoc) assert.equal(frameDoc.querySelector('pass-reveal'), null);
  assert.equal(posted.length, 0, 'no messages to or from frames');
  const keepers = new Set(['draft.save', 'generate.filled']);
  assert.ok(!sent.some((m) => !keepers.has(m.type) && JSON.stringify(m).includes(password)),
    'until Copy, only the draft save and the background note of a generated password have it');
});

test('never two at once: picking the generator closes the menu, and a menu opening closes the callout', async () => {
  const form = doc.createElement('form');
  form.innerHTML = '<input type="password" id="m1" autocomplete="new-password"><input type="password" id="m2" autocomplete="new-password"><button type="submit">Create account</button>';
  doc.body.append(form);
  try {
    $('m1').focus();
    await press($('m1'));
    await tick(40);
    assert.equal(revealHost(), null, 'only the menu, its preview masked');
    await tick(MIN_VISIBLE_MS + 30);
    const entry = menuItems().find((el) => el.querySelector('.pw'));
    assert.ok(entry, 'the generator entry with its preview');
    assert.ok(entry.querySelector('.pw-val.masked'));
    await trustedClick(entry);
    await tick(20);
    assert.deepEqual(menuItems(), [], 'the menu closed');
    assert.equal(doc.activeElement, $('m2'));
    assert.equal(shownPassword(), $('m2').value, 'the callout shows what the preview masked');

    // The shortcut with several logins opens the menu here: it takes the callout's place.
    responses['logins.find'] = () => ok({ items: [LOGIN, { ...LOGIN, id: 'b', title: 'App 2' }], pending_otp: null });
    await command({ type: 'cmd.fill-login' });
    await tick(30);
    assert.ok(menuItems().length, 'the menu');
    assert.equal(revealHost(), null, 'one at a time');
  } finally {
    responses['logins.find'] = findOne;
    await dispatchTrusted(doc.activeElement, new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true, composed: true, cancelable: true }));
    doc.activeElement?.blur?.();
    form.remove();
  }
});

test('generating again replaces the callout: one at a time', async () => {
  const password = await generate();
  assert.equal(doc.querySelectorAll('pass-reveal').length, 1, 'one callout');
  assert.equal(shownPassword(), password);
  const second = await generate();
  assert.notEqual(second, password);
  assert.equal(doc.querySelectorAll('pass-reveal').length, 1, 'the new one replaces it');
  assert.equal(shownPassword(), second);
});

test('Copy goes through the desktop app, keeps the focus and the callout, and says Copied', async () => {
  const password = await generateAndWait();
  let submitted = 0;
  const onSubmit = (e) => { submitted += 1; e.preventDefault(); };
  $('signup').addEventListener('submit', onSubmit);
  try {
    const btn = copyButton();
    await dispatchTrusted(btn, new w.MouseEvent('pointerdown', { bubbles: true, composed: true, cancelable: true }));
    const down = new w.MouseEvent('mousedown', { bubbles: true, composed: true, cancelable: true, button: 0 });
    await dispatchTrusted(btn, down);
    assert.ok(down.defaultPrevented, 'pressing the button does not take the focus');
    assert.ok(revealHost(), 'a press on Copy is no click elsewhere');
    await trustedClick(btn);
    await tick(5);
    assert.deepEqual(lastSent('generate.copy'), { type: 'generate.copy', password });
    assert.deepEqual(clipboard, [], 'not through the browser\'s clipboard');
    assert.equal(lastSent('clipboard.copied'), undefined, 'the desktop app clears its own copy');
    assert.equal(copyButton().textContent, 'Copied');
    assert.ok(revealHost(), 'still there');
    assert.equal(doc.activeElement, $('new2'), 'the field keeps the focus');
    assert.equal(submitted, 0, 'the form is not submitted');
    assert.equal(shownPassword(), password);
    assertNotInPage(password);
    await tick(1550);
    assert.equal(copyButton().textContent, 'Copy', 'the feedback is brief');
  } finally {
    $('signup').removeEventListener('submit', onSubmit);
  }
});

for (const [why, answer] of [
  ['an older desktop app', { ok: false, error: { code: 'not_supported', message: 'unknown method' } }],
  ['the desktop app not running', { ok: false, error: { code: 'agent_unavailable', message: 'not running' } }],
  ['a password the desktop app did not generate', { ok: false, error: { code: 'not_found', message: 'no' } }],
]) {
  test(`Copy with ${why} uses the browser's clipboard and schedules the 45 s clear`, async () => {
    const real = responses['generate.copy'];
    responses['generate.copy'] = () => answer;
    try {
      const password = await generateAndWait();
      await trustedClick(copyButton());
      await tick(5);
      assert.deepEqual(clipboard, [password]);
      assert.deepEqual(lastSent('clipboard.copied'), { type: 'clipboard.copied', value: password });
      assert.equal(copyButton().textContent, 'Copied');
      assert.equal(doc.activeElement, $('new2'));
    } finally {
      responses['generate.copy'] = real;
    }
  });
}

test('Copy says so when no way of copying worked', async () => {
  const real = responses['generate.copy'];
  const writeText = navigator.clipboard.writeText;
  responses['generate.copy'] = () => ({ ok: false, error: { code: 'not_supported', message: 'unknown method' } });
  navigator.clipboard.writeText = async () => { throw new Error('denied'); };
  try {
    await generateAndWait();
    await trustedClick(copyButton());
    await tick(5);
    assert.equal(copyButton().textContent, 'Copy failed');
    assert.ok(revealHost(), 'the callout stays');
    assert.equal(doc.activeElement, $('new2'), 'the focus is back in the field');
    assert.equal(lastSent('clipboard.copied'), undefined);
    assert.equal(revealRoot().querySelectorAll('textarea').length, 0, 'nothing left behind in the shadow root');
  } finally {
    responses['generate.copy'] = real;
    navigator.clipboard.writeText = writeText;
  }
});

test('the guard: an untrusted click, a click right after it appeared, and a see-through callout copy nothing', async () => {
  const password = await generate();
  await trustedClick(copyButton());
  await tick(5);
  assert.equal(lastSent('generate.copy'), undefined, 'too soon after it appeared');

  await tick(MIN_VISIBLE_MS + 30);
  copyButton().click();
  copyButton().dispatchEvent(new w.MouseEvent('click', { bubbles: true, composed: true }));
  await tick(5);
  assert.equal(lastSent('generate.copy'), undefined, 'a script\'s click');
  assert.deepEqual(clipboard, []);
  assert.equal(copyButton().textContent, 'Copy');

  revealHost().style.setProperty('opacity', '0', 'important');
  await trustedClick(copyButton());
  await tick(5);
  assert.equal(lastSent('generate.copy'), undefined, 'the page made it see-through');
  revealHost().style.setProperty('opacity', '1', 'important');

  doc.documentElement.style.opacity = '0.01';
  await trustedClick(copyButton());
  await tick(5);
  assert.equal(lastSent('generate.copy'), undefined, 'the page made <html> see-through');
  doc.documentElement.style.opacity = '';

  await trustedClick(copyButton());
  await tick(5);
  assert.deepEqual(lastSent('generate.copy'), { type: 'generate.copy', password }, 'a real click on the intact callout');
});

test('Copy events stay inside: the page sees nothing of a press or click on the button', async () => {
  const seen = [];
  const listen = (e) => seen.push(e.type);
  for (const type of ['pointerdown', 'mousedown', 'click']) doc.addEventListener(type, listen);
  try {
    await generateAndWait();
    const btn = copyButton();
    await press(btn);
    await trustedClick(btn);
    await tick(5);
    assert.deepEqual(seen, []);
  } finally {
    for (const type of ['pointerdown', 'mousedown', 'click']) doc.removeEventListener(type, listen);
  }
});

test('leaving the field before the desktop app answered: no second copy through the browser', async () => {
  const real = responses['generate.copy'];
  let answer;
  responses['generate.copy'] = () => new Promise((resolve) => { answer = resolve; });
  try {
    await generateAndWait();
    await trustedClick(copyButton());
    await tick(5);
    $('email').focus();
    assert.equal(revealHost(), null);
    answer({ ok: false, error: { code: 'not_supported', message: 'unknown method' } });
    await tick(5);
    assert.deepEqual(clipboard, []);
  } finally {
    responses['generate.copy'] = real;
  }
});

test('unit: every character is a CSS escape, runs by kind, spaces visible', () => {
  assert.equal(cssEscapedString('a"\\'), '"\\000061\\000022\\00005c"');
  assert.deepEqual(charRuns('ab12 !x'), [
    { kind: 'l', text: 'ab' }, { kind: 'd', text: '12' }, { kind: 's', text: '␣' }, { kind: 'y', text: '!' }, { kind: 'l', text: 'x' },
  ]);
  assert.deepEqual(charRuns('🔑é'), [{ kind: 'y', text: '🔑' }, { kind: 'l', text: 'é' }]);
});
