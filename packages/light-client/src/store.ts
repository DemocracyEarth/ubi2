/**
 * Verified-state persistence store (spec 07 §3.3).
 *
 * In a browser: uses IndexedDB.
 * In Node.js (tests / SSR): falls back to an in-memory map.
 *
 * The key is `"lightState:<chainId>"`.  The value is the raw bytes from
 * `LightState.serialize()` — a canonical snapshot that can be verified on load
 * (the caller checks `stateRoot()` against the stored `tip.stateRoot`).
 */

const DB_NAME = "ubi2-light-client";
const STORE_NAME = "snapshots";
const DB_VERSION = 1;

/** Minimal async key-value store used by the light client for snapshot persistence. */
export interface SnapshotStore {
  load(key: string): Promise<Uint8Array | null>;
  save(key: string, value: Uint8Array): Promise<void>;
}

/** In-memory fallback for Node.js / environments without IndexedDB. */
export class InMemoryStore implements SnapshotStore {
  private map = new Map<string, Uint8Array>();
  async load(key: string): Promise<Uint8Array | null> {
    return this.map.get(key) ?? null;
  }
  async save(key: string, value: Uint8Array): Promise<void> {
    this.map.set(key, value);
  }
}

/** IndexedDB-backed store (browser).  Opens lazily on first use. */
export class IndexedDbStore implements SnapshotStore {
  private db: IDBDatabase | null = null;

  private open(): Promise<IDBDatabase> {
    if (this.db) return Promise.resolve(this.db);
    return new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = (e) => {
        const db = (e.target as IDBOpenDBRequest).result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME);
        }
      };
      req.onsuccess = (e) => {
        this.db = (e.target as IDBOpenDBRequest).result;
        resolve(this.db!);
      };
      req.onerror = () => reject(req.error);
    });
  }

  async load(key: string): Promise<Uint8Array | null> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).get(key);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error);
    });
  }

  async save(key: string, value: Uint8Array): Promise<void> {
    const db = await this.open();
    return new Promise((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const req = tx.objectStore(STORE_NAME).put(value, key);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    });
  }
}

/** Pick the right store for the current runtime. */
export function defaultStore(): SnapshotStore {
  if (typeof indexedDB !== "undefined") {
    return new IndexedDbStore();
  }
  return new InMemoryStore();
}
