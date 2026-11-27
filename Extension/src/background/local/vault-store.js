// The browser vault's file in the extension's IndexedDB: one record per vault id with the encrypted file as
// the apps write it and `prev`, the copy before the last save. Nothing decrypted is ever stored, and content
// scripts (which run in the page's origin) can't reach this database. A record with `source: 'drive'` comes
// from the builds that synced Google Drive themselves and still opens.

const DB_NAME = 'passyble';
const DB_VERSION = 1;

export function idbVaultStore(idb = globalThis.indexedDB) {
  let opened = null;
  const db = () => {
    opened ??= new Promise((resolve, reject) => {
      const req = idb.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        const d = req.result;
        if (!d.objectStoreNames.contains('vaults')) d.createObjectStore('vaults', { keyPath: 'id' });
        if (!d.objectStoreNames.contains('meta')) d.createObjectStore('meta', { keyPath: 'key' });
      };
      req.onsuccess = () => {
        const d = req.result;
        // A newer version wants the database: let it, and reopen next time.
        d.onversionchange = () => { d.close(); opened = null; };
        resolve(d);
      };
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('IndexedDB is blocked'));
    });
    opened.catch(() => { opened = null; });
    return opened;
  };
  const run = async (stores, mode, fn) => {
    const d = await db();
    return new Promise((resolve, reject) => {
      // A write is answered only once it is on disk: "relaxed" durability could report a save the user was
      // told about before it is flushed. One transaction per write keeps the file, `prev` and the pointer together.
      const tx = mode === 'readwrite' ? d.transaction(stores, mode, { durability: 'strict' }) : d.transaction(stores, mode);
      let out;
      tx.oncomplete = () => resolve(out);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
      const get = (store, key) => new Promise((res, rej) => {
        const r = tx.objectStore(store).get(key);
        r.onsuccess = () => res(r.result);
        r.onerror = () => rej(r.error);
      });
      Promise.resolve(fn({ tx, get, store: (name) => tx.objectStore(name) })).then((v) => { out = v; }, (err) => {
        try { tx.abort(); } catch { /* finished */ }
        reject(err);
      });
    });
  };
  return storeApi({
    async active() {
      return run(['meta', 'vaults'], 'readonly', async ({ get }) => {
        const pointer = await get('meta', 'active');
        return pointer?.id ? normalize(await get('vaults', pointer.id)) : null;
      });
    },
    async write(id, file, now, fields) {
      return run(['meta', 'vaults'], 'readwrite', async ({ get, store }) => {
        const old = await get('vaults', id);
        const rec = old
          ? { ...old, ...fields, id, prev: old.file ?? null, file, updatedAt: now }
          : { createdAt: now, backedUpAt: 0, ...fields, id, file, prev: null, updatedAt: now };
        store('vaults').put(rec);
        store('meta').put({ key: 'active', id });
      });
    },
    async patch(id, fields) {
      return run(['vaults'], 'readwrite', async ({ get, store }) => {
        const old = await get('vaults', id);
        if (old) store('vaults').put({ ...old, ...fields, id });
      });
    },
    async remove(id) {
      return run(['meta', 'vaults'], 'readwrite', async ({ get, store }) => {
        store('vaults').delete(id);
        const pointer = await get('meta', 'active');
        if (pointer?.id === id) store('meta').delete('active');
      });
    },
  });
}

/** The same store in memory (tests, or a browser without IndexedDB). */
export function memoryVaultStore() {
  const vaults = new Map();
  let activeId = null;
  return storeApi({
    async active() { return activeId && vaults.has(activeId) ? normalize(structuredClone(vaults.get(activeId))) : null; },
    async write(id, file, now, fields) {
      const old = vaults.get(id);
      vaults.set(id, old ? { ...old, ...fields, id, prev: old.file, file, updatedAt: now }
        : { createdAt: now, backedUpAt: 0, ...fields, id, file, prev: null, updatedAt: now });
      activeId = id;
    },
    async patch(id, fields) { if (vaults.has(id)) vaults.set(id, { ...vaults.get(id), ...fields, id }); },
    async remove(id) { vaults.delete(id); if (activeId === id) activeId = null; },
  });
}

let sharedMemory = null;

/** IndexedDB, or one shared in-memory store where there is none (tests), so a reloaded background finds it. */
export function defaultVaultStore() {
  if (typeof globalThis.indexedDB?.open === 'function') return idbVaultStore();
  sharedMemory ??= memoryVaultStore();
  return sharedMemory;
}

function plain(fields) {
  const { file, prev, id, ...rest } = fields || {};
  return rest;
}

function normalize(rec) {
  if (!rec) return null;
  const bytes = (v) => (v instanceof Uint8Array ? v : v instanceof ArrayBuffer ? new Uint8Array(v) : v ? new Uint8Array(v) : null);
  return { ...rec, file: bytes(rec.file), prev: bytes(rec.prev) };
}

function storeApi(impl) {
  return {
    load: () => impl.active(),
    save: (id, file, now = Date.now(), fields = {}) => impl.write(id, new Uint8Array(file), now, plain(fields)),
    update: (id, fields) => impl.patch(id, plain(fields)),
    remove: (id) => impl.remove(id),
  };
}
