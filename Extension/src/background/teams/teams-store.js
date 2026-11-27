// The browser's copies of shared vault files in IndexedDB, keyed by server path (`dirty`: not uploaded yet).
// Nothing decrypted is stored, and content scripts can't reach this database.

const DB_NAME = 'passyble-teams';

function idbTeamsStore(idb = globalThis.indexedDB) {
  let opened = null;
  const db = () => {
    opened ??= new Promise((resolve, reject) => {
      const req = idb.open(DB_NAME, 1);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains('shared')) req.result.createObjectStore('shared', { keyPath: 'path' });
      };
      req.onsuccess = () => { req.result.onversionchange = () => { req.result.close(); opened = null; }; resolve(req.result); };
      req.onerror = () => reject(req.error);
      req.onblocked = () => reject(new Error('IndexedDB is blocked'));
    });
    opened.catch(() => { opened = null; });
    return opened;
  };
  const run = async (mode, fn) => {
    const d = await db();
    return new Promise((resolve, reject) => {
      const tx = d.transaction('shared', mode);
      const req = fn(tx.objectStore('shared'));
      tx.oncomplete = () => resolve(req?.result);
      tx.onerror = () => reject(tx.error);
      tx.onabort = () => reject(tx.error || new Error('IndexedDB transaction aborted'));
    });
  };
  return {
    all: () => run('readonly', (s) => s.getAll()).then((v) => v || []),
    put: (rec) => run('readwrite', (s) => s.put(rec)),
    remove: (path) => run('readwrite', (s) => s.delete(path)),
    clear: () => run('readwrite', (s) => s.clear()),
  };
}

export function memoryTeamsStore() {
  const recs = new Map();
  return {
    all: async () => [...recs.values()].map((r) => structuredClone(r)),
    put: async (rec) => { recs.set(rec.path, structuredClone(rec)); },
    remove: async (path) => { recs.delete(path); },
    clear: async () => { recs.clear(); },
  };
}

export function defaultTeamsStore() {
  return globalThis.indexedDB ? idbTeamsStore() : memoryTeamsStore();
}
