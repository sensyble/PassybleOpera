// Backend for the browser vault. Same surface as NativeClient, backed by the agent's request
// handlers compiled to WebAssembly (BrowserAgent).
//
// After every BrowserAgent call the encrypted file goes to IndexedDB, effects are applied (lock state,
// copy, vault_changed), and the next tick is scheduled with a timer plus a chrome.alarms alarm to wake
// a stopped service worker.
//
// A stopped service worker loses the WebAssembly instance; the next call rebuilds it from IndexedDB and
// the key in storage.session. Pending 2FA codes, grants and rate limits start empty, and a soft lock
// becomes a full lock.
//
// Calls run one at a time because the vault is a single WebAssembly instance and the awaits must not
// interleave. Master passwords are never kept here.
import { ErrorCode, PassError } from '../../shared/errors.js';

export const TICK_ALARM = 'pass-vault-tick';
// Chrome runs alarms at most every 30 s; the timer covers shorter waits while the worker is up.
const MIN_ALARM_MS = 30_000;
// lastUseAt in storage.session is rewritten only when it moved this much (not on every request).
const SESSION_SLACK_MS = 10_000;
const RETRY_FIRST_MS = 1000;
const RETRY_MAX_MS = 30_000;

export class LocalBackend {
  constructor({ wasm, store, session, config, alarms = null, now = () => Date.now(),
    setTimeout: st = globalThis.setTimeout.bind(globalThis), clearTimeout: ct = globalThis.clearTimeout.bind(globalThis),
    log = console }) {
    this._wasm = wasm;
    this._store = store;
    this._session = session;
    this._config = config;
    this._alarms = alarms;
    this._now = now;
    this._setTimeout = st;
    this._clearTimeout = ct;
    this._log = log;
    this._agent = null;
    this._vaultId = null;
    this._meta = null;
    this._locked = true;
    this._unsaved = null;
    this._stashed = null;
    this._retryTimer = null;
    this._retryMs = 0;
    this._sessionUseAt = 0;
    this._timer = null;
    this._alarmAt = 0;
    this._queue = Promise.resolve();
    this._listeners = new Map();
    this._nextId = 1;
    this._generation = 0;
  }

  get connected() { return true; }

  on(event, fn) {
    if (!this._listeners.has(event)) this._listeners.set(event, new Set());
    this._listeners.get(event).add(fn);
    return () => this._listeners.get(event)?.delete(fn);
  }

  disconnect() {}

  /** A protocol request. `grant` and `confirmed` come only from the background, never from a content script. */
  request(method, params = {}, { grant = null, confirmed = false } = {}) {
    return this._serial(async (agent) => {
      agent.tick(); // an overdue auto-lock happens before the request
      const line = { id: this._allocId(), method, params };
      if (typeof grant === 'string' && grant) line.grant = grant;
      if (confirmed === true) line.confirmed = true;
      const out = parse(agent.handle(JSON.stringify(line)));
      await this._after();
      if (out.error) throw toError(out.error);
      return out.result ?? {};
    });
  }

  /**
   * Runs `fn(agent, { generation, locked })` in turn with every other call, then saves and applies effects.
   * `generation` changes when the instance is rebuilt, so shared vaults must be reopened. `fn` must not call
   * request() (it would wait for itself).
   */
  withAgent(fn) {
    return this._serial(async (agent) => {
      try {
        return await fn(agent, { generation: this._generation, locked: this._locked });
      } finally {
        await this._after();
      }
    });
  }

  /** A value the Teams code copies: written and cleared like the agent's `copy` effects. */
  releaseCopy(text) {
    if (typeof text === 'string' && text) this._emit('copy', { text });
  }

  /** `source` is 'drive' for a record of the builds that synced Google Drive, else null. */
  info() {
    return this._serial(async (agent) => ({
      hasVault: agent.hasVault(), locked: this._locked, vaultId: this._vaultId,
      createdAt: this._meta?.createdAt ?? 0, backedUpAt: this._meta?.backedUpAt ?? 0,
      source: this._meta?.source ?? null, name: this._meta?.name ?? '', account: this._meta?.account ?? null,
    }));
  }

  /** The master password rule for a new password. Needs no vault, so it doesn't wait for the queue. */
  async checkMasterPassword(password, names = []) {
    const { checkMasterPassword } = await this._wasm();
    if (typeof checkMasterPassword !== 'function') {
      throw new PassError(ErrorCode.NOT_SUPPORTED, 'This build of the browser vault has no master password check');
    }
    const list = Array.isArray(names) ? names.filter((n) => typeof n === 'string' && n) : [];
    const out = parse(checkMasterPassword(String(password ?? ''), JSON.stringify(list)));
    if (out.error) throw toError(out.error);
    return {
      ok: out.ok === true,
      score: Number.isInteger(out.score) ? out.score : 0,
      label: typeof out.label === 'string' ? out.label : '',
      entropy_bits: Number.isFinite(out.entropy_bits) ? out.entropy_bits : 0,
      issues: Array.isArray(out.issues) ? out.issues.filter((i) => typeof i === 'string') : [],
      name: typeof out.name === 'string' ? out.name : '',
      min_length: Number.isInteger(out.min_length) ? out.min_length : 0,
    };
  }

  create(password, fields = {}) {
    return this._serial(async (agent) => {
      if (agent.hasVault()) throw new PassError(ErrorCode.INVALID_STATE, 'There is a vault in this browser already');
      const res = this._result(agent.create(String(password)));
      this._vaultId = res.vault_id;
      this._meta = { createdAt: this._now(), backedUpAt: 0, ...fields };
      await this._after({ fields });
      return res;
    });
  }

  /** A vault file the user picked, checked with its master password before anything is stored. */
  openFile(file, password, fields = {}) {
    return this._openFile(file, (fresh) => fresh.unlock(String(password)), fields);
  }

  openFileWithAccountKey(file, accountKey, fields = {}) {
    return this._openFile(file, (fresh) => fresh.unlockWithAccountKey(accountKey), fields);
  }

  /** What a vault file opens with, without opening it. WebAssembly from an older core can't tell: "password". */
  async fileAccess(file) {
    const { glue } = await this._wasm();
    if (typeof glue?.vaultFileAccess !== 'function') return { kind: 'password', account: null, ak_id: null, account_recovery: false };
    return this._result(glue.vaultFileAccess(file));
  }

  vaultAccess() {
    return this._serial(async (agent) => {
      if (!agent.hasVault()) return null;
      if (typeof agent.vaultAccess !== 'function') return { kind: 'password', account: null, ak_id: null, account_recovery: false };
      return this._result(agent.vaultAccess());
    });
  }

  /** Opens a linked vault with a pass-wasm `AccountKey` (the caller frees it). */
  unlockWithAccountKey(accountKey) {
    return this._serial(async (agent) => {
      const res = this._result(agent.unlockWithAccountKey(accountKey));
      await this._after();
      return res;
    });
  }

  verifyAccountKey(accountKey) {
    return this._serial(async (agent) => {
      const res = this._result(agent.verifyAccountKey(accountKey));
      await this._after();
      return res;
    });
  }

  _openFile(file, open, fields) {
    return this._serial(async (agent) => {
      if (agent.hasVault()) throw new PassError(ErrorCode.INVALID_STATE, 'There is a vault in this browser already');
      const { BrowserAgent } = await this._wasm();
      const fresh = new BrowserAgent(JSON.stringify(await this._config()));
      let res;
      try {
        res = this._result(fresh.load(file));
        this._result(open(fresh));
      } catch (err) {
        fresh.free();
        throw err;
      }
      agent.free();
      this._agent = fresh;
      this._vaultId = res.vault_id;
      await this._store.save(res.vault_id, file, this._now(), fields);
      this._meta = { createdAt: this._now(), backedUpAt: 0, ...fields };
      await this._after();
      return { vault_id: res.vault_id };
    });
  }

  unlock(password) {
    return this._serial(async (agent) => {
      const res = this._result(agent.unlock(String(password)));
      await this._after();
      return res;
    });
  }

  verifyPassword(password) {
    return this._serial(async (agent) => {
      const res = this._result(agent.verifyPassword(String(password)));
      await this._after();
      return res;
    });
  }

  lock(completely = false) {
    return this._serial(async (agent) => {
      const res = this._result(agent.lock(!!completely));
      await this._after();
      return res;
    });
  }

  setOptions(options) {
    return this._serial(async (agent) => {
      this._result(agent.setOptions(JSON.stringify(options)));
      await this._after();
      return {};
    });
  }

  tick() {
    return this._serial(async (agent) => {
      agent.tick();
      await this._after();
    });
  }

  /** The encrypted vault file now, or null without a vault. `backup`: clears "Not backed up". */
  exportVault({ backup = true } = {}) {
    return this._serial(async (agent) => {
      const file = agent.exportVault();
      await this._after();
      if (!file) return null;
      if (backup && this._vaultId) {
        const at = this._now();
        await this._store.update(this._vaultId, { backedUpAt: at });
        this._meta = { ...(this._meta || {}), backedUpAt: at };
      }
      return file;
    });
  }

  /**
   * The vault file and its key for moving this browser's vault into the Passyble app, checked by opening a
   * second instance with `open(fresh)`. This browser's own instance is left as it is. The caller clears `key`.
   */
  exportForMove(open) {
    return this._serial(async (agent) => {
      if (!agent.hasVault()) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser');
      const file = agent.exportVault();
      await this._after();
      if (!file) throw new PassError(ErrorCode.NO_VAULT, 'There is no vault in this browser');
      const { BrowserAgent } = await this._wasm();
      const fresh = new BrowserAgent(JSON.stringify(await this._config()));
      try {
        this._result(fresh.load(file));
        this._result(open(fresh));
        const key = fresh.vaultKey();
        if (!key?.length) throw new PassError(ErrorCode.INTERNAL, 'The vault in this browser did not open');
        const copy = new Uint8Array(key);
        key.fill?.(0);
        return { file, key: copy, vaultId: this._vaultId };
      } finally {
        try { fresh.lock(true); } catch { /* not open */ }
        try { fresh.takeEffects?.(); fresh.takeSave?.(); } catch { /* nothing kept */ }
        fresh.free?.();
      }
    });
  }

  deleteVault() {
    return this._serial(async (agent) => {
      const id = this._vaultId;
      const wasLocked = this._locked;
      try { agent.lock(true); } catch { /* no vault */ }
      agent.takeEffects();
      agent.takeSave();
      agent.free();
      this._agent = null;
      this._vaultId = null;
      this._meta = null;
      this._unsaved = null;
      this._stashed = null;
      this._clearRetry();
      this._locked = true;
      this._stopTimers();
      await this._session.clear();
      await this._session.clearUnsaved?.().catch(() => {});
      if (id) await this._store.remove(id);
      if (!wasLocked) this._emit('lock_state', { locked: true });
      this._emit('vault_changed', {});
      return { deleted: !!id };
    });
  }

  /** Locks completely and drops the WebAssembly instance (switch to app mode). The vault stays in IndexedDB. */
  reset() {
    return this._serial(async (agent) => {
      try { agent.lock(true); } catch { /* no vault */ }
      await this._after();
      this._agent?.free();
      this._agent = null;
      this._vaultId = null;
      this._meta = null;
      this._locked = true;
      this._stopTimers();
      await this._session.clear();
    }, { load: !!this._agent });
  }

  _serial(fn, { load = true } = {}) {
    const run = this._queue.then(async () => fn(load ? await this._ensure() : this._agent));
    this._queue = run.catch(() => {});
    return run;
  }

  async _ensure() {
    if (this._agent) return this._agent;
    const { BrowserAgent } = await this._wasm();
    const agent = new BrowserAgent(JSON.stringify(await this._config()));
    let record = null;
    try {
      record = await this._store.load();
    } catch (err) {
      this._log.error?.('[Passyble] could not read the browser vault', err);
      agent.free();
      throw new PassError(ErrorCode.INTERNAL, 'Could not read the vault in this browser');
    }
    this._agent = agent;
    this._generation += 1;
    this._locked = true;
    // A file IndexedDB refused is newer than the stored one of the same vault: open that one, or an edit made
    // now would be saved on top of the older copy.
    const pending = this._unsaved ?? (await this._session.loadUnsaved?.().catch(() => null)) ?? null;
    const candidates = [];
    if (pending?.file && (!record?.file || record.id === pending.vaultId)) candidates.push({ file: pending.file, pending });
    if (record?.file) candidates.push({ file: record.file, pending: null });
    for (const c of candidates) {
      const loaded = parse(agent.load(c.file));
      if (loaded.error) {
        this._log.error?.('[Passyble] the stored browser vault does not open', loaded.error.code);
        continue;
      }
      this._vaultId = loaded.result.vault_id;
      this._meta = { ...(record ? metaOf(record) : { createdAt: this._now(), backedUpAt: 0 }), ...(c.pending?.fields || {}) };
      if (c.pending && !this._unsaved) {
        this._unsaved = { vaultId: c.pending.vaultId, file: c.pending.file, fields: { ...(c.pending.fields || {}) } };
        this._stashed = c.pending.file;
      }
      break;
    }
    let restored = false;
    if (this._vaultId) {
      const kept = await this._session.load().catch(() => null);
      if (kept && kept.vaultId === this._vaultId) {
        const idle = Math.max(0, this._now() - kept.lastUseAt);
        const res = parse(agent.unlockWithKey(kept.key, idle));
        if (res.error) {
          await this._session.clear();
        } else {
          restored = true;
          this._sessionUseAt = kept.lastUseAt;
          agent.tick(); // locks if the auto-lock time passed meanwhile
        }
      }
    }
    await this._after({ restored });
    return agent;
  }

  async _after({ restored = false, fields = null } = {}) {
    const agent = this._agent;
    if (!agent) return;
    const file = agent.takeSave();
    if (file) {
      const before = this._unsaved?.vaultId === this._vaultId ? this._unsaved.fields : {};
      this._unsaved = { vaultId: this._vaultId, file, fields: { ...before, ...(fields || {}) } };
    }
    await this._persist();
    let lockChange = null;
    let vaultChanged = false;
    for (const effect of parseEffects(agent.takeEffects())) {
      if (effect?.type === 'lock_state') lockChange = !!effect.locked;
      else if (effect?.type === 'vault_changed') vaultChanged = true;
      else if (effect?.type === 'copy' && typeof effect.text === 'string') this._emit('copy', { text: effect.text });
    }
    const wasLocked = this._locked;
    if (lockChange !== null) this._locked = lockChange;
    if (this._locked) {
      if (lockChange === true || this._sessionUseAt) {
        this._sessionUseAt = 0;
        await this._session.clear().catch(() => {});
      }
    } else {
      await this._keepSession(agent, lockChange === false && !restored);
    }
    this._schedule(agent);
    if (this._locked !== wasLocked && !(restored && !this._locked)) this._emit('lock_state', { locked: this._locked });
    if (vaultChanged) this._emit('vault_changed', {});
  }

  /** Writes the file waiting in _unsaved to IndexedDB; refused, it is kept and retried. Runs inside _serial only. */
  async _persist() {
    const pending = this._unsaved;
    if (!pending?.vaultId) return;
    try {
      await this._store.save(pending.vaultId, pending.file, this._now(), pending.fields);
    } catch (err) {
      this._log.error?.('[Passyble] could not save the browser vault', err);
      if (this._stashed !== pending.file) {
        try {
          await this._session.keepUnsaved?.(pending);
          this._stashed = pending.file;
        } catch (e) {
          this._log.warn?.('[Passyble] could not keep the unsaved vault for this session either', e);
        }
      }
      this._retryLater();
      return;
    }
    if (this._unsaved === pending) this._unsaved = null;
    if (pending.vaultId === this._vaultId) this._meta = { ...(this._meta || {}), ...pending.fields };
    this._clearRetry();
    if (this._stashed) {
      this._stashed = null;
      await this._session.clearUnsaved?.().catch(() => {});
    }
  }

  _retryLater() {
    if (this._retryTimer) return;
    this._retryMs = Math.min(RETRY_MAX_MS, this._retryMs ? this._retryMs * 2 : RETRY_FIRST_MS);
    this._retryTimer = this._setTimeout(() => {
      this._retryTimer = null;
      // No instance is built: the refused file is all it needs (also after reset()).
      this._serial(async () => {
        await this._persist();
        if (this._agent) this._schedule(this._agent);
      }, { load: false }).catch((err) => this._log.warn?.('[Passyble] vault save retry failed', err));
    }, this._retryMs);
    this._retryTimer?.unref?.(); // Node (tests) only
  }

  _clearRetry() {
    if (this._retryTimer) this._clearTimeout(this._retryTimer);
    this._retryTimer = null;
    this._retryMs = 0;
  }

  async _keepSession(agent, fresh) {
    const lastUseAt = this._now() - Math.max(0, Number(agent.idleMs()) || 0);
    if (!fresh && this._sessionUseAt && Math.abs(lastUseAt - this._sessionUseAt) < SESSION_SLACK_MS) return;
    const key = agent.vaultKey();
    if (!key || !this._vaultId) return;
    try {
      await this._session.save({ key, vaultId: this._vaultId, lastUseAt });
      this._sessionUseAt = lastUseAt;
    } catch (err) {
      this._log.warn?.('[Passyble] could not keep the vault key for this session', err);
    } finally {
      key.fill(0);
    }
  }

  _schedule(agent) {
    const ms = agent.nextTickMs();
    if (this._timer) this._clearTimeout(this._timer);
    this._timer = null;
    const due = ms !== undefined && ms !== null && Number.isFinite(ms);
    // A refused save keeps the alarm: it wakes a stopped service worker, which writes the kept copy.
    if (!due && !this._unsaved) {
      if (this._alarmAt) {
        this._alarmAt = 0;
        Promise.resolve(this._alarms?.clear?.(TICK_ALARM)).catch(() => {});
      }
      return;
    }
    const wait = due ? Math.max(0, ms) : 0;
    if (due) {
      this._timer = this._setTimeout(() => {
        this._timer = null;
        this.tick().catch((err) => this._log.warn?.('[Passyble] vault timer failed', err));
      }, wait + 25);
      this._timer?.unref?.(); // Node (tests) only
    }
    const at = this._now() + Math.max(wait, MIN_ALARM_MS) + 1000;
    if (this._alarms?.create && Math.abs(at - this._alarmAt) > 5000) {
      this._alarmAt = at;
      Promise.resolve(this._alarms.create(TICK_ALARM, { when: at })).catch(() => {});
    }
  }

  _stopTimers() {
    if (this._timer) this._clearTimeout(this._timer);
    this._timer = null;
    this._alarmAt = 0;
    Promise.resolve(this._alarms?.clear?.(TICK_ALARM)).catch(() => {});
  }

  _result(text) {
    const out = parse(text);
    if (out.error) throw toError(out.error);
    return out.result ?? {};
  }

  _allocId() {
    const id = this._nextId;
    this._nextId = id >= 0x7fffffff ? 1 : id + 1;
    return id;
  }

  _emit(event, data) {
    for (const fn of this._listeners.get(event) ?? []) {
      try { fn(data); } catch (err) { this._log.error?.('[Passyble] event listener failed', err); }
    }
  }
}

function parse(text) {
  try {
    const out = JSON.parse(text);
    return out && typeof out === 'object' ? out : { error: { code: 'internal', message: 'No answer' } };
  } catch {
    return { error: { code: 'internal', message: 'Unreadable answer' } };
  }
}

function metaOf(record) {
  const { file, prev, id, ...rest } = record || {};
  return { createdAt: 0, backedUpAt: 0, ...rest };
}

function parseEffects(text) {
  try {
    const list = JSON.parse(text || '[]');
    return Array.isArray(list) ? list : [];
  } catch {
    return [];
  }
}

function toError(error) {
  return new PassError(typeof error?.code === 'string' ? error.code : ErrorCode.INTERNAL,
    typeof error?.message === 'string' ? error.message : undefined);
}
