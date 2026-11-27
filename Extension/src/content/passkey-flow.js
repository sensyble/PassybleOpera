// Handles a page's own passkey get() (not conditional) and create() in an in-page card, after
// bridge.js parks the request. User verification stays with the desktop app.
//
// Apart from "no passkey for this site", which hands off at once, only a visible click on
// "Use another device" sends a request on to the browser's own WebAuthn.
import { ext } from '../shared/api.js';
import { t } from '../shared/i18n.js';
import { friendlyError, isHostMissing } from '../shared/messages.js';
import { showPasskeyNone, showPasskeyNotice, showPasskeyPrompt, showPasskeySave } from './passkey-prompt.js';
import { newLoginVaultChoice } from '../shared/vaults.js';
import { showNotice as showToastNotice } from './toast.js';

const FRAME_PATH = 'src/unlock/frame.html';
const FRAME_READY_MS = 3000;
// End the request with the page's DOMException (final); any other error keeps the card.
const FINAL_CODES = new Set(['invalid_state', 'url_mismatch']);

/** What a card says about an agent error: never its raw text. */
function passkeyErrorText(err) {
  const code = err?.code;
  const older = err?.reason === 'needs_update' || /unknown method/i.test(String(err?.message || ''));
  // userVerification "required" and Windows Hello can't verify now.
  if (code === 'not_supported' && !older) return t('passkeyNeedsVerification');
  if (code === 'not_found') return t('passkeyNoneTitle');
  return friendlyError(err);
}

class FlowError extends Error {
  constructor(code, message) {
    super(message || code);
    this.code = code;
  }
}

function extensionOrigin() {
  try { return String(ext.runtime.getURL('') || '').replace(/\/+$/, ''); } catch { return ''; }
}

/** `bg(type, payload)` throws `{ code }`; `bridge()` returns `__passBridge`. */
export function createPasskeyFlow({ bg, bridge, onCardShown = () => {} }) {
  let current = null;   // { info, card, unlocking }
  let unlocking = null; // { unlocked(), locked() }

  const message = (err) => passkeyErrorText(err);
  const end = (req, outcome) => {
    if (current === req) current = null;
    req.card?.close();
    bridge()?.endModal(req.info.rid, outcome);
  };
  const stillOn = (req) => current === req && !!bridge()?.hasModal(req.info.rid);

  /** Resolves `true` once unlocked, else the card's message ('' when the user cancelled). */
  async function unlockInCard(card, { itemId = null } = {}) {
    let opts;
    try {
      opts = await bg('unlock.options', itemId ? { for: itemId } : {});
    } catch (err) {
      return message(err);
    }
    if (card.closed) return '';
    if (!opts?.locked) return true;
    if (!opts.inline) {
      // An older desktop app can only unlock in its own window.
      card.setStatus(t('menuUnlockingInApp'));
      try {
        await bg('unlock', itemId ? { for: itemId } : {});
        return true;
      } catch (err) {
        return message(err);
      }
    }
    return new Promise((resolve) => {
      let finished = false;
      let helloRun = 0;
      let frame = null; // { el, ready, timer, watch }
      const session = {
        unlocked: () => finish(true),
        locked: () => {},
      };
      unlocking = session;
      const dropFrame = () => {
        if (!frame) return;
        clearTimeout(frame.timer);
        clearInterval(frame.watch);
        frame = null;
      };
      const finish = (ok) => {
        if (finished) return;
        finished = true;
        helloRun++;
        dropFrame();
        window.removeEventListener('message', onFrameMessage);
        if (unlocking === session) unlocking = null;
        if (!card.closed) card.hideUnlock();
        resolve(ok ? true : '');
      };
      const back = () => {
        bg('unlock.cancel').catch(() => {});
        finish(false);
      };
      const inWindow = async () => {
        // The extension's own page takes the password; this page never sees it.
        try {
          await bg('unlock.open-form');
          if (!finished) showPassword({ message: t('commonUnlockInApp'), noFrame: true });
        } catch (err) {
          if (!finished) showPassword({ message: message(err), noFrame: true });
        }
      };
      const makeFrame = () => {
        if (!extensionOrigin()) return null;
        const el = document.createElement('iframe');
        el.className = 'unlock-frame';
        el.title = t('unlockFrameTitle');
        el.src = `${ext.runtime.getURL(FRAME_PATH)}?focus=1`;
        const made = { el, ready: false, timer: 0, watch: 0 };
        // Some pages block extension frames; fall back to a Passyble window.
        made.timer = setTimeout(() => { if (frame === made && !made.ready) frameFailed(); }, FRAME_READY_MS);
        // The page must not draw over the card or make it see-through while a password goes in.
        made.watch = setInterval(() => {
          if (frame !== made) return;
          if (card.closed) { back(); return; }
          if (!card.intact()) frameFailed();
        }, 250);
        return made;
      };
      const frameFailed = () => {
        dropFrame();
        if (!finished) showPassword({ noFrame: true });
      };
      function onFrameMessage(e) {
        if (!frame || e.source !== frame.el.contentWindow || e.origin !== extensionOrigin()) return;
        const what = e.data?.passybleUnlock;
        if (what === 'ready') {
          frame.ready = true;
          clearTimeout(frame.timer);
          const height = Number(e.data.height);
          if (height > 0) frame.el.style.height = `${Math.min(160, Math.max(40, Math.ceil(height)))}px`;
          try { frame.el.focus({ preventScroll: true }); } catch { /* gone */ }
          try { frame.el.contentWindow?.postMessage({ passybleUnlock: 'focus' }, extensionOrigin()); } catch { /* gone */ }
        } else if (what === 'unlocked') {
          finish(true);
        } else if (what === 'escape') {
          back();
        }
      }
      window.addEventListener('message', onFrameMessage);

      function showPassword({ message: text = '', noFrame = false } = {}) {
        helloRun++;
        if (noFrame) dropFrame();
        else if (!frame) frame = makeFrame();
        const choices = [];
        if (opts.hello) choices.push({ label: t('menuUnlockHello'), link: true, onClick: () => startHello() });
        if (!frame) choices.push({ label: t('menuUnlockPassword'), onClick: () => inWindow() });
        choices.push({ label: t('commonCancel'), onClick: back });
        card.showUnlock({ message: text || (frame ? '' : t('commonUnlockInApp')), frame: frame?.el || null, choices, onCancel: back });
      }

      async function startHello() {
        const run = ++helloRun;
        dropFrame();
        card.showUnlock({
          message: t('commonConfirmHello'),
          choices: [
            { label: t('menuUsePassword'), link: true, onClick: () => { bg('unlock.cancel').catch(() => {}); showPassword(); } },
            { label: t('commonCancel'), onClick: back },
          ],
          onCancel: back,
        });
        try {
          await bg('unlock.hello');
        } catch (err) {
          if (finished || run !== helloRun) return; // the user moved on meanwhile
          if (err.code === 'cancelled') showPassword({ message: t('menuHelloCancelledPassword') });
          // Hello turned off, or the master password is due.
          else if (err.code === 'not_supported') { opts = { ...opts, hello: false }; showPassword({ message: friendlyError(err, { context: 'unlock' }) }); }
          else showPassword({ message: message(err) });
          return;
        }
        finish(true);
      }

      if (opts.hello && (opts.hello_auto !== false || opts.hello_pending)) startHello();
      else showPassword();
    });
  }

  async function lookUpPasskeys(info) {
    // Not automatic: the user is waiting, so ask even if Passyble was just found not running.
    const found = await bg('passkey.find', { options: { rpId: info.rpId, allowCredentials: info.allowCredentials }, automatic: false });
    const items = (Array.isArray(found?.items) ? found.items : []).filter((pk) => pk && typeof pk.id === 'string' && pk.id);
    return { items, locked: found?.locked === true, site: typeof found?.rp_id === 'string' && found.rp_id ? found.rp_id : null };
  }

  async function handleGet(req) {
    const { info } = req;
    let found;
    try {
      found = await lookUpPasskeys(info);
    } catch (err) {
      if (!stillOn(req)) return;
      // Fully locked: nothing starts before a click on the card.
      lookupFailed(req, err, () => showSignIn(req, { items: [], locked: true }));
      return;
    }
    if (!stillOn(req)) return;
    if (!found.items.length) { noPasskey(req, found.site); return; }
    showSignIn(req, found);
  }

  function lookupFailed(req, err, showLocked) {
    // The browser vault does not support passkeys yet.
    if (err?.reason === 'passkeys_need_app') {
      showNotice(req, { heading: t('passkeyBrowserVaultTitle') });
      return;
    }
    switch (err?.code) {
      case 'update_required':
        appReadOnly(req, err);
        return;
      case 'locked':
        showLocked();
        return;
      case 'not_supported':
        // An older desktop app asks in its own window.
        current = null;
        bridge()?.passModal(req.info.rid);
        return;
      case 'agent_unavailable':
        showNotRunning(req, err);
        return;
      case 'url_mismatch':
        // Same SecurityError the browser would give.
        end(req, { ok: false, error: { code: 'url_mismatch', message: 'The relying party ID is not valid for this origin' } });
        return;
      case 'not_found':
        // A cross-site frame (the browser checks the permissions policy) or an origin left to the browser.
        showNotice(req, { heading: t('passkeyFrameTitle') });
        return;
      default:
        showError(req, err);
    }
  }

  /** The desktop app is read-only until updated: hand off and show why. */
  function appReadOnly(req, err) {
    end(req, 'fallback');
    try { showToastNotice(friendlyError(err)); } catch { /* no page UI here */ }
  }

  function showNotice(req, opts) {
    req.card?.close();
    const card = showPasskeyNotice({
      site: req.info.rpId || location.hostname,
      ...opts,
      onElsewhere: () => end(req, 'fallback'),
      onDismiss: () => end(req, 'cancel'),
    });
    req.card = card;
    onCardShown();
  }

  /** Passyble knows it has no passkey: no card, the browser's own WebAuthn at once. */
  function noPasskey(req, site = null) {
    end(req, 'fallback');
    showPasskeyNone(site || req.info.rpId || location.hostname);
  }

  /** "Open Passyble" only when the native host is reachable. */
  function showNotRunning(req, err) {
    const unreachable = isHostMissing(err);
    showNotice(req, {
      heading: t('passkeyNotRunningTitle'),
      note: unreachable ? friendlyError(err) : '',
      noteIcon: 'power',
      action: unreachable ? null : { label: t('commonOpenPassyble'), busyText: t('passkeyOpening'), run: () => openApp(req) },
    });
  }

  async function openApp(req) {
    if (!stillOn(req)) return { done: true };
    req.clicked = true;
    try {
      await bg('passkey.start_app');
    } catch (err) {
      return { message: isHostMissing(err) || err?.code !== 'agent_unavailable' ? friendlyError(err) : t('errStartFailed') };
    }
    if (!stillOn(req)) return { done: true };
    await restart(req);
    return { done: true };
  }

  function showError(req, err) {
    showNotice(req, {
      heading: t('passkeyErrorTitle'),
      note: message(err),
      noteIcon: 'alert',
      action: { label: t('passkeyTryAgain'), run: async () => { await restart(req); return { done: true }; } },
    });
  }

  async function restart(req) {
    if (!stillOn(req)) return;
    try {
      await (req.info.kind === 'get' ? handleGet(req) : handleCreate(req));
    } catch (err) {
      failed(req, err);
    }
  }

  // An unexpected error stays in the card; it never hands off to the browser by itself.
  function failed(req, err) {
    console.debug('[Passyble] passkey request:', err);
    if (!stillOn(req)) return;
    try {
      showError(req, { code: 'internal', message: String(err?.message || err) });
    } catch {
      end(req, 'cancel');
    }
  }

  function showSignIn(req, { items, locked, site = null }) {
    req.card?.close();
    const card = showPasskeyPrompt({
      site: site || req.info.rpId || location.hostname,
      passkeys: items,
      locked,
      modal: true,
      onPick: (pk, shown) => signIn(req, pk, { locked, card: shown }),
      onElsewhere: () => end(req, 'fallback'),
      onDismiss: () => end(req, 'cancel'),
    });
    req.card = card;
    onCardShown();
  }

  /** `pk` null: "Unlock and sign in" on a fully locked Passyble. */
  async function signIn(req, pk, { locked, card }) {
    if (!stillOn(req)) return { done: true };
    req.clicked = true;
    if (locked) {
      const unlocked = await unlockInCard(card, { itemId: pk?.id || null });
      if (unlocked !== true) return { message: unlocked };
      if (!stillOn(req)) return { done: true };
    }
    let chosen = pk;
    if (!chosen) {
      let found;
      try {
        found = await lookUpPasskeys(req.info);
      } catch (err) {
        return { message: message(err) };
      }
      if (!stillOn(req)) return { done: true };
      if (!found.items.length) { noPasskey(req, found.site); return { done: true }; }
      // Several: the user picks one with a click of its own.
      if (found.items.length > 1) { showSignIn(req, { ...found, locked: false }); return { done: true }; }
      chosen = found.items[0];
    }
    card.setStatus(t('passkeyPromptSigningIn'));
    const res = await bridge().completeModal(req.info.rid, { id: chosen.id, credentialId: chosen.credential_id });
    return after(req, res, () => { restart(req); });
  }

  /** Outcome of a request sent from the card; `relock` when it got locked meanwhile. */
  function after(req, res, relock) {
    if (res?.ok) {
      if (current === req) current = null;
      return { done: true };
    }
    const code = res?.error?.code || 'internal';
    if (!stillOn(req)) return { done: true };
    if (FINAL_CODES.has(code)) { end(req, { ok: false, error: res.error }); return { done: true }; }
    if (code === 'locked') { relock(); return { done: true }; }
    if (code === 'update_required') { appReadOnly(req, new FlowError(code, res?.error?.message)); return { done: true }; }
    return { message: message(new FlowError(code, res?.error?.message)) };
  }

  async function createOptions(info) {
    return bg('passkey.create_options', {
      options: { rpId: info.rpId, userName: info.user?.name || '', excludeCredentials: info.excludeCredentials },
    });
  }

  async function handleCreate(req) {
    const { info } = req;
    let opts;
    try {
      opts = await createOptions(info);
    } catch (err) {
      if (!stillOn(req)) return;
      lookupFailed(req, err, () => showSave(req, { locked: true, full: true }));
      return;
    }
    if (!stillOn(req)) return;
    if (opts?.excluded) { end(req, excludedError()); return; }
    showSave(req, { locked: opts?.locked === true, options: opts });
  }

  function excludedError() {
    return { ok: false, error: { code: 'invalid_state', message: 'A passkey for this account is already in Passyble' } };
  }

  function showSave(req, { locked, full = false, options = null }) {
    req.card?.close();
    const { info } = req;
    const user = info.user || {};
    const account = user.name || user.displayName || '';
    const card = showPasskeySave({
      site: options?.rp_id || info.rpId || location.hostname,
      account,
      detail: user.displayName || '',
      candidates: Array.isArray(options?.candidates) ? options.candidates.filter((c) => c && typeof c.id === 'string') : [],
      suggested: typeof options?.suggested === 'string' ? options.suggested : null,
      vault: typeof options?.vault === 'string' && options.vault ? options.vault : null,
      vaults: newLoginVaultChoice(options),
      locked,
      onSave: (itemId, shown, vault) => save(req, itemId, { locked, full, card: shown, vault }),
      onElsewhere: () => end(req, 'fallback'),
      onDismiss: () => end(req, 'cancel'),
    });
    req.card = card;
    onCardShown();
  }

  async function save(req, itemId, { locked, full, card, vault = null }) {
    if (!stillOn(req)) return { done: true };
    req.clicked = true;
    if (locked) {
      const unlocked = await unlockInCard(card);
      if (unlocked !== true) return { message: unlocked };
      if (!stillOn(req)) return { done: true };
      if (full) {
        let opts;
        try {
          opts = await createOptions(req.info);
        } catch (err) {
          return { message: message(err) };
        }
        if (!stillOn(req)) return { done: true };
        if (opts?.excluded) { end(req, excludedError()); return { done: true }; }
        // Logins to choose from need a click of their own; none: save a new login now.
        if (Array.isArray(opts?.candidates) && opts.candidates.length) {
          showSave(req, { locked: false, options: opts });
          return { done: true };
        }
      }
    }
    card.setStatus(t('passkeySaveSaving'));
    const res = await bridge().completeModal(req.info.rid, { itemId, ...(vault && !itemId ? { vault } : {}) });
    return after(req, res, () => { restart(req); });
  }

  return {
    /** Returns false to leave the request to the background. */
    handle(info) {
      if (!info || (info.kind !== 'get' && info.kind !== 'create')) return false;
      if (current) current.card?.close();
      const req = { info, card: null };
      current = req;
      (info.kind === 'get' ? handleGet(req) : handleCreate(req)).catch((err) => failed(req, err));
      return true;
    },
    /** For bridge.js onModalChange: an ended request takes its card along. */
    changed() {
      if (current && !bridge()?.hasModal(current.info.rid)) {
        current.card?.close();
        current = null;
      }
    },
    lockChanged(locked) {
      if (!locked) unlocking?.unlocked();
    },
    unlockInCard,
    get active() { return !!current?.card && !current.card.closed; },
    stop() {
      current?.card?.close();
      current = null;
    },
  };
}
