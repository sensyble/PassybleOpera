// Isolated-world end of the WebAuthn channel (classic content script, document_start, all frames).
// Binds to the secret channel name from webauthn-main.js (first hello only) and relays requests to
// the background, which takes the origin from the browser's sender info, never from here. Requests
// are parked until the content script's card answers them. `userActivated` is read here, where the
// page can't fake it.
(() => {
  'use strict';
  const ext = globalThis.browser ?? globalThis.chrome;
  // A bridge left over from before an extension update has a dead runtime; replace it.
  if (globalThis.__passBridge?.alive()) return;
  const alive = () => { try { return !!ext.runtime.id; } catch { return false; } };
  const HELLO = 'pass-webauthn-hello-v1';
  const READY = 'pass-webauthn-ready-v1';
  const CHANNEL_RE = /^pass-[0-9a-f]{32}$/;

  let channel = null;
  const inflight = new Map(); // rid -> { cancelled }
  let conditional = null; // { rid, publicKey }
  const conditionalListeners = new Set();
  let modal = null; // { rid, op, publicKey, mediation, userActivated, timer }: a page's own get() / create()
  let modalHandler = null;
  const modalListeners = new Set();
  // The page's own timeout, clamped.
  const MODAL_MIN_MS = 60_000;
  const MODAL_MAX_MS = 10 * 60_000;
  const MODAL_DEFAULT_MS = 5 * 60_000;
  const HANDLER_WAIT_MS = 15_000;
  const LOADER_GRACE_MS = 300;
  let contentComing = false; // loader.js is starting the content script
  const handlerWaiters = new Set();

  function respond(rid, msg) {
    if (!channel) return;
    window.dispatchEvent(new CustomEvent(channel + ':res', { detail: JSON.stringify({ rid, ...msg }) }));
  }

  function notifyConditional() {
    for (const fn of conditionalListeners) {
      try { fn(!!conditional); } catch (err) { console.error('[Passyble]', err); }
    }
  }

  function notifyModal() {
    for (const fn of modalListeners) {
      try { fn(modal ? modal.rid : null); } catch (err) { console.error('[Passyble]', err); }
    }
  }

  function modalTimeout(timeout) {
    const ms = Number(timeout);
    if (!Number.isFinite(ms) || ms <= 0) return MODAL_DEFAULT_MS;
    return Math.min(MODAL_MAX_MS, Math.max(MODAL_MIN_MS, ms));
  }

  function endModal(rid, msg) {
    const current = modal;
    if (!current || current.rid !== rid) return false;
    clearTimeout(current.timer);
    modal = null;
    respond(rid, msg);
    notifyModal();
    return true;
  }

  // The content script never sees the challenge or the user handle.
  function describeModal(current) {
    const pk = current.publicKey && typeof current.publicKey === 'object' ? current.publicKey : {};
    const ids = (list) => (Array.isArray(list) ? list : []).filter((c) => c && typeof c.id === 'string').map((c) => ({ id: c.id }));
    const text = (v) => (typeof v === 'string' ? v.slice(0, 256) : '');
    const info = { rid: current.rid, kind: current.op, userActivated: current.userActivated };
    if (current.op === 'get') {
      info.rpId = typeof pk.rpId === 'string' && pk.rpId ? pk.rpId : null;
      info.allowCredentials = ids(pk.allowCredentials);
    } else {
      info.rpId = typeof pk.rp?.id === 'string' && pk.rp.id ? pk.rp.id : null;
      info.rpName = text(pk.rp?.name);
      info.user = Object.freeze({ name: text(pk.user?.name), displayName: text(pk.user?.displayName) });
      info.excludeCredentials = ids(pk.excludeCredentials);
    }
    return Object.freeze(info);
  }

  // Starts main.js like loader.js does: document_idle can come after the page's `load`.
  function startContent() {
    if (contentComing || modalHandler) return true;
    try {
      if (globalThis.__passContent?.alive()) return false; // already running and not taking requests
      const url = ext.runtime.getURL('src/content/main.js');
      const flag = { alive };
      globalThis.__passContent = flag;
      contentComing = true;
      const gone = () => {
        contentComing = false;
        if (!modalHandler) for (const done of [...handlerWaiters]) done(false);
      };
      import(url)
        .then((m) => m.start())
        .then(gone, (err) => {
          console.debug('[Passyble] content script not started:', err);
          if (globalThis.__passContent === flag) delete globalThis.__passContent;
          gone();
        });
      return true;
    } catch {
      return false;
    }
  }

  function waitForModalHandler() {
    if (modalHandler) return Promise.resolve(true);
    if (!contentComing && document.readyState === 'complete' && !startContent()) return Promise.resolve(false);
    if (modalHandler) return Promise.resolve(true);
    return new Promise((resolve) => {
      let graceTimer = 0;
      const done = (taken) => {
        if (!handlerWaiters.delete(done)) return;
        clearTimeout(timer);
        clearTimeout(graceTimer);
        document.removeEventListener('readystatechange', onState);
        resolve(taken);
      };
      // Loaded and loader.js hasn't claimed it: start it here.
      const onState = () => {
        if (document.readyState !== 'complete' || contentComing) return;
        graceTimer = setTimeout(() => { if (!contentComing && !startContent()) done(!!modalHandler); }, LOADER_GRACE_MS);
      };
      const timer = setTimeout(() => done(!!modalHandler), HANDLER_WAIT_MS);
      handlerWaiters.add(done);
      document.addEventListener('readystatechange', onState);
      onState();
    });
  }

  async function sendModal(current) {
    const res = await sendBackground({
      type: current.op === 'create' ? 'passkey.create' : 'passkey.get',
      options: current.publicKey,
      mediation: current.mediation,
      userActivated: current.userActivated,
    });
    endModal(current.rid, res);
  }

  /** The background's minimum-version gate blocks exactly this version (src/shared/app-versions.js). */
  function updateRequired(gate) {
    let version = '';
    try { version = String(ext.runtime.getManifest?.()?.version || ''); } catch { /* never blocked */ }
    return !!gate && typeof gate === 'object' && gate.required === true && version !== '' && gate.version === version;
  }

  async function passkeysEnabled() {
    try {
      const got = await ext.storage.local.get({ passkeys: true, appVersionGate: null });
      return got?.passkeys !== false && !updateRequired(got?.appVersionGate);
    } catch {
      return false; // extension context gone: stay out of the way
    }
  }

  // Sandboxed documents: `document.domain` is "" exactly then, and the page can't fake it from here.
  function opaqueOrigin() {
    try { return document.domain === ''; } catch { return true; }
  }

  // Transient or sticky activation. False for a page that asks on its own while loading.
  function userActivated() {
    try {
      const ua = navigator.userActivation;
      return !!ua && (ua.isActive === true || ua.hasBeenActive === true);
    } catch {
      return false;
    }
  }

  // WebAuthn crossOrigin: any ancestor frame has another origin.
  function crossOriginAncestor() {
    try {
      const ancestors = location.ancestorOrigins;
      if (ancestors) {
        for (let i = 0; i < ancestors.length; i++) if (ancestors[i] !== location.origin) return true;
        return false;
      }
    } catch { /* not supported: walk the parents */ }
    try {
      for (let w = window; w !== w.top; w = w.parent) {
        if (w.parent.location.origin !== location.origin) return true;
      }
      return false;
    } catch {
      return true; // a cross-origin parent can't be read
    }
  }

  // Retries only undelivered messages (MV3 service worker still starting; Brave can take ~2 s).
  // Other failures may have reached it, so they are not repeated.
  const RETRY_MS = [250, 500, 1000];
  const NOT_DELIVERED_RE = /receiving end does not exist|could not establish connection/i;

  async function sendBackground(message) {
    message.crossOriginAncestor = crossOriginAncestor();
    for (let attempt = 0; ; attempt++) {
      if (!alive()) return { ok: false, error: { code: 'extension_reloaded', message: 'Extension was reloaded' } };
      try {
        const res = await ext.runtime.sendMessage(message);
        return res && typeof res === 'object' ? res : { ok: false, error: { code: 'agent_unavailable', message: 'No response' } };
      } catch (err) {
        const text = String(err?.message || err);
        if (!alive()) return { ok: false, error: { code: 'extension_reloaded', message: text } };
        if (attempt >= RETRY_MS.length || !NOT_DELIVERED_RE.test(text)) return { ok: false, error: { code: 'agent_unavailable', message: text } };
        await new Promise((resolve) => setTimeout(resolve, RETRY_MS[attempt]));
      }
    }
  }

  async function onRequest(event) {
    if (!alive()) return; // stale instance: stay silent so the live bridge answers
    let msg;
    try { msg = JSON.parse(event.detail); } catch { return; }
    if (!msg || typeof msg.rid !== 'string' || typeof msg.op !== 'string') return;
    const { rid, op } = msg;
    const activated = userActivated(); // read at once, still inside the page's credentials call
    // Synchronous receipt: without one, webauthn-main.js assumes a dead bridge and lets the browser take over.
    window.dispatchEvent(new CustomEvent(channel + ':got', { detail: rid }));
    const payload = msg.payload && typeof msg.payload === 'object' ? msg.payload : {};

    if (op === 'config') {
      respond(rid, { ok: true, result: { enabled: !opaqueOrigin() && await passkeysEnabled() } });
      return;
    }
    if (op === 'cancel') {
      const target = payload.target;
      const entry = inflight.get(target);
      if (entry) entry.cancelled = true;
      if (conditional && conditional.rid === target) {
        conditional = null;
        notifyConditional();
      }
      if (modal && modal.rid === target) {
        clearTimeout(modal.timer);
        modal = null;
        notifyModal();
      }
      return;
    }
    if (op !== 'create' && op !== 'get') return;
    if (opaqueOrigin() || !(await passkeysEnabled())) {
      respond(rid, { fallback: true });
      return;
    }
    if (op === 'get' && payload.mediation === 'conditional') {
      conditional = { rid, publicKey: payload.publicKey };
      notifyConditional();
      return; // answered by completeConditional()
    }
    if (await waitForModalHandler()) {
      // The page gave up on the older one without aborting it.
      if (modal) endModal(modal.rid, { ok: false, final: true, error: { code: 'cancelled', message: 'Replaced by a newer passkey request' } });
      const current = { rid, op, publicKey: payload.publicKey, mediation: payload.mediation, userActivated: activated, timer: 0 };
      modal = current;
      current.timer = setTimeout(() => endModal(rid, { ok: false, final: true, error: { code: 'cancelled', message: 'The passkey request timed out' } }),
        modalTimeout(payload.publicKey?.timeout));
      let taken = false;
      try { taken = modalHandler(describeModal(current)) !== false; } catch (err) { console.error('[Passyble]', err); }
      if (!taken && modal === current) await sendModal(current);
      return; // answered by completeModal() / endModal() / passModal()
    }
    const entry = { cancelled: false };
    inflight.set(rid, entry);
    const res = await sendBackground({
      type: op === 'create' ? 'passkey.create' : 'passkey.get',
      options: payload.publicKey,
      mediation: payload.mediation,
      userActivated: activated,
    });
    inflight.delete(rid);
    if (!entry.cancelled) respond(rid, res);
  }

  function onHello(event) {
    if (channel || !alive()) return;
    const name = event.detail;
    if (typeof name !== 'string' || !CHANNEL_RE.test(name)) return;
    channel = name;
    window.removeEventListener(HELLO, onHello, true);
    window.addEventListener(channel + ':req', onRequest, true);
    window.dispatchEvent(new CustomEvent(channel + ':ack'));
  }

  window.addEventListener(HELLO, onHello, true);
  // In case the MAIN-world script ran first.
  window.dispatchEvent(new CustomEvent(READY));

  // API for the isolated-world content script. Not visible to the page.
  globalThis.__passBridge = Object.freeze({
    alive,
    hasConditional: () => !!conditional,
    /** `{ rid, rpId, allowCredentials: [{ id }] }` or null; never the challenge. */
    conditionalRequest() {
      const current = conditional;
      if (!current) return null;
      const pk = current.publicKey && typeof current.publicKey === 'object' ? current.publicKey : {};
      const allow = Array.isArray(pk.allowCredentials) ? pk.allowCredentials : [];
      return Object.freeze({
        rid: current.rid,
        rpId: typeof pk.rpId === 'string' && pk.rpId ? pk.rpId : null,
        allowCredentials: allow.filter((c) => c && typeof c.id === 'string').map((c) => ({ id: c.id })),
      });
    },
    onConditionalChange(fn) {
      conditionalListeners.add(fn);
      return () => conditionalListeners.delete(fn);
    },
    /** Called after a trusted pick in the Passyble menu or passkey prompt. */
    async completeConditional(itemId, credentialId) {
      const current = conditional;
      if (!current) return { ok: false, error: { code: 'not_found', message: 'No passkey request on this page' } };
      // `inPage`: unlocking happens in the page; a lock meanwhile answers `locked`.
      const message = { type: 'passkey.get', options: current.publicKey, mediation: 'conditional', id: itemId, userActivated: true, inPage: true };
      if (typeof credentialId === 'string' && credentialId) message.credentialId = credentialId;
      const res = await sendBackground(message);
      if (conditional !== current) return { ok: false, error: { code: 'cancelled', message: 'The request was aborted' } };
      if (res.ok) {
        conditional = null;
        notifyConditional();
        respond(current.rid, res);
      }
      return res; // on error the request stays pending so the user can try again
    },
    /** No passkey: the browser's own conditional request, running alongside, is left to answer. */
    endConditional(rid) {
      const current = conditional;
      if (!current || current.rid !== rid) return false;
      conditional = null;
      notifyConditional();
      respond(current.rid, { fallback: true });
      return true;
    },

    /** `fn(describeModal(...))` per page get() / create(); returning false leaves it to the background. */
    onModalRequest(fn) {
      modalHandler = fn;
      for (const done of [...handlerWaiters]) done(true);
      return () => {
        if (modalHandler !== fn) return;
        modalHandler = null;
        contentComing = false;
      };
    },
    contentStarting() {
      contentComing = true;
    },
    onModalChange(fn) {
      modalListeners.add(fn);
      return () => modalListeners.delete(fn);
    },
    hasModal: (rid) => !!modal && modal.rid === rid,
    /** get: `{ id, credentialId }`; create: `{ itemId, vault }`. On error the request stays parked. */
    async completeModal(rid, choice = {}) {
      const current = modal;
      if (!current || current.rid !== rid) return { ok: false, error: { code: 'cancelled', message: 'The request was aborted' } };
      const message = {
        type: current.op === 'create' ? 'passkey.create' : 'passkey.get',
        options: current.publicKey,
        mediation: current.mediation,
        userActivated: true,
        inPage: true,
      };
      if (current.op === 'create') {
        message.consent = { itemId: typeof choice.itemId === 'string' && choice.itemId ? choice.itemId : null };
        if (!message.consent.itemId && typeof choice.vault === 'string' && choice.vault) message.consent.vault = choice.vault;
      } else {
        if (typeof choice.id === 'string' && choice.id) message.id = choice.id;
        if (typeof choice.credentialId === 'string' && choice.credentialId) message.credentialId = choice.credentialId;
      }
      const res = await sendBackground(message);
      if (modal !== current) return { ok: false, error: { code: 'cancelled', message: 'The request was aborted' } };
      if (res.ok) endModal(rid, res);
      return res;
    },
    /** `'fallback'`: the browser's own WebAuthn; `'cancel'` or an error: a `final` DOMException. */
    endModal(rid, outcome) {
      if (outcome === 'fallback') return endModal(rid, { fallback: true });
      if (outcome === 'cancel') return endModal(rid, { ok: false, final: true, error: { code: 'cancelled', message: 'The user cancelled' } });
      if (outcome && typeof outcome === 'object' && outcome.ok === false && outcome.error) {
        const { code, message } = outcome.error;
        return endModal(rid, { ok: false, final: true, error: { code: String(code || 'internal'), message: String(message || '') } });
      }
      return false;
    },
    // For older desktop apps, which show their own prompt.
    passModal(rid) {
      const current = modal;
      if (!current || current.rid !== rid) return false;
      sendModal(current);
      return true;
    },
  });
})();
