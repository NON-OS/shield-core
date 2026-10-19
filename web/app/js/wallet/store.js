// The browser's storage for the wallet: the files the core writes, byte for byte what a phone keeps
// on disk, and a little that is not secret, such as which passkey wraps the key. The vault and the
// note logs are sealed by the core before they reach here.

const NAME = "nox-shield";
const VERSION = 1;

function opened() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(NAME, VERSION);
    req.onupgradeneeded = () => {
      req.result.createObjectStore("files");
      req.result.createObjectStore("meta");
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

function done(tx) {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error);
  });
}

export async function openStore() {
  const db = await opened();
  return {
    async files() {
      const tx = db.transaction("files");
      const store = tx.objectStore("files");
      const [keys, values] = await Promise.all(
        [store.getAllKeys(), store.getAll()].map(
          (r) =>
            new Promise(
              (ok, no) => ((r.onsuccess = () => ok(r.result)), (r.onerror = () => no(r.error))),
            ),
        ),
      );
      return keys.map((k, i) => [k, values[i]]);
    },
    // One transaction for every change of a call, so storage never holds half of one.
    async apply(changes) {
      if (changes.length === 0) return;
      const tx = db.transaction("files", "readwrite");
      const store = tx.objectStore("files");
      for (const { path, bytes } of changes) bytes ? store.put(bytes, path) : store.delete(path);
      await done(tx);
    },
    async meta(key) {
      const r = db.transaction("meta").objectStore("meta").get(key);
      return new Promise(
        (ok, no) => ((r.onsuccess = () => ok(r.result)), (r.onerror = () => no(r.error))),
      );
    },
    async setMeta(key, value) {
      const tx = db.transaction("meta", "readwrite");
      tx.objectStore("meta").put(value, key);
      await done(tx);
    },
    async wipe() {
      const tx = db.transaction(["files", "meta"], "readwrite");
      tx.objectStore("files").clear();
      tx.objectStore("meta").clear();
      await done(tx);
    },
    close() {
      db.close();
    },
  };
}
