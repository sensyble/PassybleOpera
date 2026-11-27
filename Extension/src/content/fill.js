// Filling that frameworks notice: React's value tracker only sees a change made through the prototype
// setter, and other sites listen for keydown, input, keyup, change or blur.

const filledByPass = new WeakSet();

function viewOf(el) {
  return el.ownerDocument?.defaultView || globalThis;
}

/** Sets `value` via the native prototype setter so framework trackers see a real change. */
export function setNativeValue(el, value) {
  const view = viewOf(el);
  const proto = el.tagName === 'TEXTAREA' ? view.HTMLTextAreaElement.prototype : view.HTMLInputElement.prototype;
  const desc = Object.getOwnPropertyDescriptor(proto, 'value');
  if (desc?.set) desc.set.call(el, value);
  else el.value = value;
}

function keyEvent(view, type, key) {
  const Ctor = view.KeyboardEvent || view.Event;
  return new Ctor(type, { key, code: '', bubbles: true, cancelable: true, composed: true });
}

function inputEvent(view, type, data) {
  const Ctor = view.InputEvent || view.Event;
  return new Ctor(type, { inputType: 'insertText', data, bubbles: true, cancelable: type === 'beforeinput', composed: true });
}

/** Fills one input. Returns true when the field now holds `value`. */
export function fillInput(el, value, { blur = false, focus = true } = {}) {
  if (!el || !el.isConnected || el.disabled || el.readOnly) return false;
  const view = viewOf(el);
  const str = String(value ?? '');
  if (focus) {
    try { el.focus({ preventScroll: true }); } catch { /* not focusable */ }
  }
  const lastChar = str.slice(-1) || 'Unidentified';
  el.dispatchEvent(keyEvent(view, 'keydown', lastChar));
  el.dispatchEvent(inputEvent(view, 'beforeinput', str));
  setNativeValue(el, str);
  el.dispatchEvent(inputEvent(view, 'input', str));
  el.dispatchEvent(keyEvent(view, 'keyup', lastChar));
  el.dispatchEvent(new view.Event('change', { bubbles: true }));
  if (blur) {
    try { el.blur(); } catch { /* ignore */ }
  }
  filledByPass.add(el);
  watchUserEdits(el);
  return el.value === str;
}

const watched = new WeakSet();
function watchUserEdits(el) {
  if (watched.has(el)) return;
  watched.add(el);
  // Only real keystrokes (isTrusted) clear the marker; our own synthetic events must not.
  el.addEventListener('input', (e) => { if (e.isTrusted) filledByPass.delete(el); }, true);
}

/** True when Passyble filled `el` and the user has not typed into it since. */
export function wasFilledByPass(el) {
  return filledByPass.has(el);
}

function deepActiveElement(doc) {
  let a = doc?.activeElement || null;
  while (a?.shadowRoot?.activeElement) a = a.shadowRoot.activeElement;
  return a;
}

/** The KeyboardEvent `code` of a character a code box takes ("Digit5", "KeyA"), else "". */
function keyCodeOf(ch) {
  if (/^[0-9]$/.test(ch)) return `Digit${ch}`;
  if (/^[a-z]$/i.test(ch)) return `Key${ch.toUpperCase()}`;
  return '';
}

function typedKeyEvent(view, type, ch) {
  const Ctor = view.KeyboardEvent || view.Event;
  const charCode = ch.charCodeAt(0);
  const keyCode = /^[a-z]$/i.test(ch) ? ch.toUpperCase().charCodeAt(0) : charCode;
  return new Ctor(type, {
    key: ch, code: keyCodeOf(ch), bubbles: true, cancelable: true, composed: true,
    keyCode: type === 'keypress' ? charCode : keyCode, charCode: type === 'keypress' ? charCode : 0,
    which: type === 'keypress' ? charCode : keyCode,
  });
}

const splitOk = (els, chars) => els.every((el, i) => el.value === (chars[i] ?? ''));

/**
 * Types `chars` key by key, for code boxes that ignore values set from script and pastes. Inserts the
 * character where no handler cancelled the keystroke and moves focus when the widget doesn't.
 */
function typeSplitOtp(els, chars) {
  const start = els.findIndex((el, i) => el.value !== (chars[i] ?? ''));
  if (start < 0) return;
  for (let i = start; i < els.length && i < chars.length; i++) {
    const el = els[i];
    if (!el.isConnected || el.disabled || el.readOnly) return;
    const doc = el.ownerDocument;
    if (deepActiveElement(doc) !== el) {
      try { el.focus({ preventScroll: true }); } catch { /* not focusable */ }
    }
    const view = viewOf(el);
    const ch = chars[i];
    const down = el.dispatchEvent(typedKeyEvent(view, 'keydown', ch));
    const press = down && el.dispatchEvent(typedKeyEvent(view, 'keypress', ch));
    const before = press && el.dispatchEvent(inputEvent(view, 'beforeinput', ch));
    if (before && el.value !== ch) {
      setNativeValue(el, ch);
      el.dispatchEvent(inputEvent(view, 'input', ch));
    }
    el.dispatchEvent(typedKeyEvent(view, 'keyup', ch));
    filledByPass.add(el);
    watchUserEdits(el);
    if (splitOk(els, chars)) return;
  }
}

/** Fills split OTP boxes without submitting: box by box, then a synthetic paste, then key by key. */
export function fillSplitOtp(els, code) {
  const chars = [...String(code).replace(/\s+/g, '')];
  els.forEach((el, i) => fillInput(el, chars[i] ?? '', { focus: true }));
  if (splitOk(els, chars)) return true;
  try {
    const view = viewOf(els[0]);
    const dt = new view.DataTransfer();
    dt.setData('text/plain', chars.join(''));
    els[0].focus();
    els[0].dispatchEvent(new view.ClipboardEvent('paste', { clipboardData: dt, bubbles: true, cancelable: true, composed: true }));
  } catch { /* DataTransfer / ClipboardEvent unavailable */ }
  if (splitOk(els, chars)) return true;
  typeSplitOtp(els, chars);
  return splitOk(els, chars);
}

export function fillOtpEntry(entry, code) {
  if (!entry || !code) return false;
  if (entry.kind === 'split') return fillSplitOtp(entry.fields, code);
  return fillInput(entry.fields[0], code);
}

/**
 * Fills a login group: username, the stored password (loginPasswordFields) and the OTP when the group
 * has an OTP field and a code is given. Returns what was filled.
 */
export function fillLoginGroup(group, { username, password, totp }, { field = null } = {}) {
  const result = { username: false, password: false, otp: false };
  if (group.username && username) result.username = fillInput(group.username, username);
  if (password) {
    for (const target of loginPasswordFields(group, field)) result.password = fillInput(target, password) || result.password;
  }
  if (group.otp && totp?.code) result.otp = fillOtpEntry(group.otp, totp.code);
  // Leave focus on the last filled field so Enter submits naturally.
  return result;
}

/**
 * Where the stored password goes: the user's picked `field`, else the current-password (or plain
 * sign-in) field, never a lone new-password field. Null when there is none.
 */
export function loginPasswordField(group, field = null) {
  if (field && group?.passwords?.some((p) => p.el === field)) return field;
  return group?.currentPassword || (group?.newPasswords?.length ? null : group?.passwords?.[0]?.el) || null;
}

/**
 * Every field the stored password goes into, the user's own field last (it keeps focus). A picked
 * new-password field on sign-up fills its confirmation too; on change-password the other new field
 * is left to the user.
 */
export function loginPasswordFields(group, field = null) {
  const target = loginPasswordField(group, field);
  if (!target) return [];
  const news = group.newPasswords || [];
  if (!news.includes(target)) return [target];
  if (group.currentPassword) return [group.currentPassword, target];
  if (news.length === 2) return [news.find((el) => el !== target), target];
  return [target];
}

export function fillNewPasswords(group, password) {
  let any = false;
  for (const el of group.newPasswords) any = fillInput(el, password) || any;
  return any;
}
