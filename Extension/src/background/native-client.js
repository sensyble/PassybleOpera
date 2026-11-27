import { ErrorCode, PassError } from '../shared/errors.js';

export const HOST_NAME = 'com.sensyble.pass';

function portClosed(reason) {
  const err = new PassError(ErrorCode.AGENT_UNAVAILABLE, reason);
  err.portClosed = true;
  return err;
}

// Methods that wait for a human (unlock window, passkey consent) get long timeouts.
const DEFAULT_TIMEOUT_MS = 30_000;
const METHOD_TIMEOUTS_MS = {
  unlock: 10 * 60_000,
  'unlock.hello': 10 * 60_000,
  'unlock.password': 10 * 60_000,
  'passkey.create': 10 * 60_000,
  'passkey.get': 10 * 60_000,
  // Popup editor: may wait for Windows Hello.
  'logins.get_for_edit': 3 * 60_000,
  'logins.update': 3 * 60_000,
  'logins.create': 3 * 60_000,
  'logins.delete': 3 * 60_000,
  'items.move': 3 * 60_000,
  'totp.set': 3 * 60_000,
  'logins.fill': 3 * 60_000,
  'logins.fill_cross': 3 * 60_000,
  'logins.copy': 3 * 60_000,
  'totp.get': 3 * 60_000,
  'totp.popup': 3 * 60_000,
  'cards.fill': 3 * 60_000,
  // The desktop app asks the alias service (up to two requests of 30 s).
  'generate.email': 90_000,
  'server.pair': 10 * 60_000,
};

/**
 * Client for the native messaging host. A port that disconnects rejects everything pending with
 * `agent_unavailable` and `portClosed: true`: unlike the host's own `agent_unavailable` answer, the same
 * request may work on a fresh port.
 */
export class NativeClient {
  constructor({ connect, lastError = () => undefined, hostName = HOST_NAME,
    setTimeout: st = globalThis.setTimeout.bind(globalThis),
    clearTimeout: ct = globalThis.clearTimeout.bind(globalThis) }) {
    this._connect = connect;
    this._lastError = lastError;
    this._hostName = hostName;
    this._setTimeout = st;
    this._clearTimeout = ct;
    this._port = null;
    this._nextId = 1;
    this._pending = new Map();
    this._listeners = new Map();
    this.lastDisconnectReason = null;
  }

  get connected() {
    return this._port !== null;
  }

  get pendingCount() {
    return this._pending.size;
  }

  request(method, params = {}, { timeoutMs } = {}) {
    return new Promise((resolve, reject) => {
      let port;
      try {
        port = this._ensurePort();
      } catch (err) {
        reject(new PassError(ErrorCode.AGENT_UNAVAILABLE, `Cannot reach the Passyble desktop app: ${err?.message || err}`));
        return;
      }
      const id = this._allocId();
      const ms = timeoutMs ?? METHOD_TIMEOUTS_MS[method] ?? DEFAULT_TIMEOUT_MS;
      const timer = this._setTimeout(() => {
        if (!this._pending.has(id)) return;
        this._pending.delete(id);
        reject(new PassError(ErrorCode.TIMEOUT, `Passyble did not answer "${method}" in time`));
      }, ms);
      this._pending.set(id, { resolve, reject, timer, method });
      try {
        port.postMessage({ id, method, params });
      } catch (err) {
        // The port died between _ensurePort() and now.
        const entry = this._pending.get(id);
        this._pending.delete(id);
        this._clearTimeout(timer);
        this._dropPort();
        entry?.reject(portClosed(err?.message || 'Port closed'));
      }
    });
  }

  on(event, fn) {
    if (!this._listeners.has(event)) this._listeners.set(event, new Set());
    this._listeners.get(event).add(fn);
    return () => this._listeners.get(event)?.delete(fn);
  }

  disconnect() {
    const port = this._port;
    this._dropPort();
    try { port?.disconnect(); } catch { /* already closed */ }
    this._rejectAll('Disconnected');
  }

  _allocId() {
    for (;;) {
      const id = this._nextId;
      this._nextId = this._nextId >= 0x7fffffff ? 1 : this._nextId + 1;
      if (!this._pending.has(id)) return id;
    }
  }

  _ensurePort() {
    if (this._port) return this._port;
    const port = this._connect(this._hostName);
    if (!port) throw new Error('connectNative returned no port');
    const onMessage = (msg) => this._onMessage(msg);
    const onDisconnect = (p) => this._onDisconnect(port, p);
    port.onMessage.addListener(onMessage);
    port.onDisconnect.addListener(onDisconnect);
    this._port = port;
    return port;
  }

  _dropPort() {
    this._port = null;
  }

  _onMessage(msg) {
    if (!msg || typeof msg !== 'object') return;
    if (msg.id !== undefined && msg.id !== null) {
      const id = typeof msg.id === 'string' ? Number(msg.id) : msg.id;
      this._settle(id, msg.result, msg.error);
      return;
    }
    if (typeof msg.event === 'string') this._emit(msg.event, msg.data ?? {});
  }

  _settle(id, result, error) {
    const entry = this._pending.get(id);
    if (!entry) return;
    this._pending.delete(id);
    this._clearTimeout(entry.timer);
    if (error) {
      entry.reject(new PassError(typeof error.code === 'string' ? error.code : ErrorCode.INTERNAL,
        typeof error.message === 'string' ? error.message : undefined));
    } else {
      entry.resolve(result ?? {});
    }
  }

  _onDisconnect(port, p) {
    if (this._port !== port) return;
    const reason = p?.error?.message || this._lastError()?.message || 'Native host disconnected';
    this.lastDisconnectReason = reason;
    this._dropPort();
    this._rejectAll(reason);
    this._emit('disconnect', { reason });
  }

  _rejectAll(reason) {
    const entries = [...this._pending.values()];
    this._pending.clear();
    for (const entry of entries) {
      this._clearTimeout(entry.timer);
      entry.reject(portClosed(reason));
    }
  }

  _emit(event, data) {
    for (const fn of this._listeners.get(event) ?? []) {
      try { fn(data); } catch (err) { console.error('[Passyble] event listener failed', err); }
    }
  }
}
