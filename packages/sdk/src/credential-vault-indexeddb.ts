import {
  parseCredentialVault,
  type CredentialVaultBinding,
  type PortableCredentialVault,
} from "./credential-vault";
import { zkHolderCredentialVaultSha256 } from "./zk-holder-private-status-refresh";

const DATABASE_VERSION = 1;
const STORE_NAME = "whole-vault";
const RECORD_KEY = "current";
const RECORD_SCHEMA = "org.proofofhumanity.credential-vault-indexeddb-record/1" as const;
const BACKUP_SCHEMA = "org.proofofhumanity.encrypted-credential-vault-backup/1" as const;
const BACKUP_VERSION = 1 as const;
const BACKUP_CIPHER = "A256GCM" as const;
const BACKUP_KDF = "HKDF-SHA-256" as const;
const BACKUP_KEY_BYTES = 32;
const BACKUP_SALT_BYTES = 32;
const BACKUP_IV_BYTES = 12;
const MAX_BACKUP_CIPHERTEXT_BYTES = 512 * 1024;

interface IndexedDbVaultRecord {
  schema: typeof RECORD_SCHEMA;
  key: typeof RECORD_KEY;
  revision: number;
  vault: PortableCredentialVault;
}

export interface EncryptedCredentialVaultBackup {
  schema: typeof BACKUP_SCHEMA;
  version: typeof BACKUP_VERSION;
  cipher: typeof BACKUP_CIPHER;
  kdf: typeof BACKUP_KDF;
  salt: string;
  iv: string;
  ciphertext: string;
}

export interface IndexedDbCredentialVaultStoreOptions {
  databaseName: string;
  vaultId: string;
  binding: CredentialVaultBinding;
  indexedDB?: IDBFactory;
  BroadcastChannelConstructor?: typeof BroadcastChannel;
  /** Fault injection used only by crash/recovery drills. */
  testHooks?: { beforeCommit?(): void };
}

export interface IndexedDbCredentialVaultMetadata {
  vaultId: string;
  binding: CredentialVaultBinding;
  credentialIds: string[];
}

export type CredentialVaultRestoreResult = "restored" | "occupied" | "stale";

/** Generate an independent 256-bit secret for one encrypted backup. */
export function generateCredentialVaultBackupKey(): Uint8Array {
  return cryptoApi().getRandomValues(new Uint8Array(BACKUP_KEY_BYTES));
}

/**
 * Discover the public locator for an existing encrypted vault database.
 *
 * This returns only WebAuthn/vault routing metadata. It never decrypts the
 * credential, exposes ciphertext, or creates an authorization decision. The
 * caller must still construct a bound store and perform a fresh passkey
 * ceremony before using the vault.
 */
export async function inspectIndexedDbCredentialVaultStore(input: {
  databaseName: string;
  indexedDB?: IDBFactory;
}): Promise<IndexedDbCredentialVaultMetadata | undefined> {
  if (!input || typeof input !== "object") throw new Error("IndexedDB vault inspection input is required");
  assertBoundedString(input.databaseName, "IndexedDB database name", 128);
  const factory = input.indexedDB ?? globalThis.indexedDB;
  if (!factory || typeof factory.open !== "function") throw new Error("IndexedDB is required for vault storage");

  if (typeof factory.databases === "function") {
    try {
      const databases = await factory.databases();
      if (!databases.some(({ name }) => name === input.databaseName)) return undefined;
    } catch {
      // Safari versions that expose but reject `databases()` can still inspect
      // safely by opening the exact account-derived name below.
    }
  }

  const database = await openDatabase(factory, input.databaseName);
  try {
    const transaction = database.transaction(STORE_NAME, "readonly");
    const raw = await requestResult<unknown>(transaction.objectStore(STORE_NAME).get(RECORD_KEY));
    await transactionComplete(transaction);
    if (raw === undefined) return undefined;
    const vault = parseStoredRecord(raw).vault;
    return {
      vaultId: vault.vaultId,
      binding: { ...vault.binding },
      credentialIds: vault.keySlots.map(({ credentialId }) => credentialId),
    };
  } finally {
    database.close();
  }
}

/**
 * Browser persistence for one complete encrypted credential vault.
 *
 * IndexedDB read/write transactions serialize competing tabs. A replacement is
 * committed only after the previously read revision and whole-vault digest both
 * still match. The digest is never persisted, broadcast, logged or returned.
 */
export class IndexedDbCredentialVaultStore {
  readonly #databaseName: string;
  readonly #vaultId: string;
  readonly #binding: CredentialVaultBinding;
  readonly #factory: IDBFactory;
  readonly #hooks?: { beforeCommit?(): void };
  readonly #channel?: BroadcastChannel;
  #database?: Promise<IDBDatabase>;
  readonly #listeners = new Set<() => void>();

  constructor(options: IndexedDbCredentialVaultStoreOptions) {
    if (!options || typeof options !== "object") throw new Error("IndexedDB vault store options are required");
    assertBoundedString(options.databaseName, "IndexedDB database name", 128);
    const vaultId = parseCredentialVaultShape(options.vaultId, options.binding);
    const factory = options.indexedDB ?? globalThis.indexedDB;
    if (!factory || typeof factory.open !== "function") throw new Error("IndexedDB is required for vault storage");
    this.#databaseName = options.databaseName;
    this.#vaultId = vaultId.vaultId;
    this.#binding = vaultId.binding;
    this.#factory = factory;
    this.#hooks = options.testHooks;
    const Channel = options.BroadcastChannelConstructor ?? globalThis.BroadcastChannel;
    if (typeof Channel === "function") {
      this.#channel = new Channel(`${options.databaseName}:whole-vault-change`);
      this.#channel.onmessage = () => {
        for (const listener of this.#listeners) listener();
      };
    }
  }

  /** Subscribe to a content-free cross-tab invalidation signal. */
  subscribe(listener: () => void): () => void {
    if (typeof listener !== "function") throw new Error("vault change listener is required");
    this.#listeners.add(listener);
    return () => this.#listeners.delete(listener);
  }

  /** Initialize an empty database without replacing an existing vault. */
  async initialize(vaultValue: unknown): Promise<boolean> {
    const vault = this.#boundVault(vaultValue);
    const db = await this.#db();
    const result = await this.#write(db, (store, finish) => {
      const read = store.get(RECORD_KEY);
      read.onsuccess = () => {
        if (read.result !== undefined) return finish(false);
        this.#beforeCommit();
        store.add(record(vault, 1));
        finish(true);
      };
    });
    if (result) this.#announce();
    return result;
  }

  /** Return a structured clone of the current complete encrypted vault. */
  async read(): Promise<PortableCredentialVault | undefined> {
    const db = await this.#db();
    const transaction = db.transaction(STORE_NAME, "readonly");
    const raw = await requestResult<unknown>(transaction.objectStore(STORE_NAME).get(RECORD_KEY));
    await transactionComplete(transaction);
    if (raw === undefined) return undefined;
    return structuredClone(this.#boundRecord(raw).vault);
  }

  /**
   * One durable whole-vault CAS. A concurrent passkey/recovery/status update in
   * another tab changes the revision and prevents this transaction from writing.
   */
  async compareAndSwap(expectedVaultSha256: string, replacementValue: PortableCredentialVault): Promise<boolean> {
    assertSha256(expectedVaultSha256);
    const replacement = this.#boundVault(replacementValue);
    const db = await this.#db();
    const observed = await this.#readRecord(db);
    if (!observed) return false;
    if ((await zkHolderCredentialVaultSha256(observed.vault)) !== expectedVaultSha256) return false;

    const result = await this.#write(db, (store, finish) => {
      const read = store.get(RECORD_KEY);
      read.onsuccess = () => {
        const current = read.result === undefined ? undefined : this.#boundRecord(read.result);
        if (!current || current.revision !== observed.revision) return finish(false);
        if (current.revision === Number.MAX_SAFE_INTEGER) throw new Error("credential vault revision is exhausted");
        this.#beforeCommit();
        store.put(record(replacement, current.revision + 1));
        finish(true);
      };
    });
    if (result) this.#announce();
    return result;
  }

  /** Encrypt the complete already-encrypted vault for an independent E2EE backup. */
  async exportEncryptedBackup(recoveryKeyValue: Uint8Array): Promise<EncryptedCredentialVaultBackup> {
    const recoveryKey = backupKey(recoveryKeyValue);
    const vault = await this.read();
    if (!vault) throw new Error("credential vault is not initialized");
    const plaintext = new TextEncoder().encode(JSON.stringify(vault));
    if (plaintext.byteLength > MAX_BACKUP_CIPHERTEXT_BYTES - 16) {
      plaintext.fill(0);
      recoveryKey.fill(0);
      throw new Error("credential vault backup is too large");
    }
    const salt = cryptoApi().getRandomValues(new Uint8Array(BACKUP_SALT_BYTES));
    const iv = cryptoApi().getRandomValues(new Uint8Array(BACKUP_IV_BYTES));
    try {
      const key = await deriveBackupKey(recoveryKey, salt);
      const ciphertext = await cryptoApi().subtle.encrypt(
        { name: "AES-GCM", iv: arrayBuffer(iv), additionalData: backupAad(), tagLength: 128 },
        key,
        arrayBuffer(plaintext),
      );
      return {
        schema: BACKUP_SCHEMA,
        version: BACKUP_VERSION,
        cipher: BACKUP_CIPHER,
        kdf: BACKUP_KDF,
        salt: base64Url(salt),
        iv: base64Url(iv),
        ciphertext: base64Url(new Uint8Array(ciphertext)),
      };
    } finally {
      plaintext.fill(0);
      recoveryKey.fill(0);
      salt.fill(0);
      iv.fill(0);
    }
  }

  /**
   * Restore into an empty database, or use an explicit whole-vault CAS to
   * replace an occupied database. Backup restore never bypasses current status.
   */
  async restoreEncryptedBackup(input: {
    backup: unknown;
    recoveryKey: Uint8Array;
    mode: "empty-only" | "compare-and-swap";
    expectedCurrentVaultSha256?: string;
  }): Promise<CredentialVaultRestoreResult> {
    if (!input || typeof input !== "object") throw new Error("credential vault restore input is required");
    const backup = parseEncryptedCredentialVaultBackup(input.backup);
    const recoveryKey = backupKey(input.recoveryKey);
    const salt = decodeBase64Url(backup.salt, "backup salt", BACKUP_SALT_BYTES);
    const iv = decodeBase64Url(backup.iv, "backup IV", BACKUP_IV_BYTES);
    const ciphertext = decodeBase64Url(backup.ciphertext, "backup ciphertext", MAX_BACKUP_CIPHERTEXT_BYTES);
    let plaintext: Uint8Array | undefined;
    try {
      const key = await deriveBackupKey(recoveryKey, salt);
      let opened: ArrayBuffer;
      try {
        opened = await cryptoApi().subtle.decrypt(
          { name: "AES-GCM", iv: arrayBuffer(iv), additionalData: backupAad(), tagLength: 128 },
          key,
          arrayBuffer(ciphertext),
        );
      } catch {
        throw new Error("credential vault backup authentication failed");
      }
      plaintext = new Uint8Array(opened);
      let parsed: unknown;
      try {
        parsed = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(plaintext));
      } catch {
        throw new Error("credential vault backup payload is invalid");
      }
      const vault = this.#boundVault(parsed);
      if (input.mode === "empty-only") return await this.initialize(vault) ? "restored" : "occupied";
      if (input.mode !== "compare-and-swap" || input.expectedCurrentVaultSha256 === undefined) {
        throw new Error("occupied restore requires an expected current whole-vault digest");
      }
      return await this.compareAndSwap(input.expectedCurrentVaultSha256, vault) ? "restored" : "stale";
    } finally {
      plaintext?.fill(0);
      recoveryKey.fill(0);
      salt.fill(0);
      iv.fill(0);
      ciphertext.fill(0);
    }
  }

  close(): void {
    this.#channel?.close();
    void this.#database?.then((database) => database.close());
    this.#database = undefined;
    this.#listeners.clear();
  }

  async #readRecord(db: IDBDatabase): Promise<IndexedDbVaultRecord | undefined> {
    const transaction = db.transaction(STORE_NAME, "readonly");
    const raw = await requestResult<unknown>(transaction.objectStore(STORE_NAME).get(RECORD_KEY));
    await transactionComplete(transaction);
    return raw === undefined ? undefined : this.#boundRecord(raw);
  }

  #boundRecord(value: unknown): IndexedDbVaultRecord {
    const record = parseStoredRecord(value);
    return { ...record, vault: this.#boundVault(record.vault) };
  }

  #boundVault(value: unknown): PortableCredentialVault {
    const vault = parseCredentialVault(value);
    if (
      vault.vaultId !== this.#vaultId ||
      vault.binding.schema !== this.#binding.schema ||
      vault.binding.rpId !== this.#binding.rpId
    ) {
      throw new Error("credential vault does not match the store binding");
    }
    return vault;
  }

  #beforeCommit(): void {
    this.#hooks?.beforeCommit?.();
  }

  #announce(): void {
    this.#channel?.postMessage({ schema: "org.proofofhumanity.credential-vault-changed/1" });
    for (const listener of this.#listeners) listener();
  }

  #db(): Promise<IDBDatabase> {
    this.#database ??= new Promise((resolve, reject) => {
      const request = this.#factory.open(this.#databaseName, DATABASE_VERSION);
      request.onupgradeneeded = () => {
        const database = request.result;
        if (!database.objectStoreNames.contains(STORE_NAME)) database.createObjectStore(STORE_NAME, { keyPath: "key" });
      };
      request.onerror = () => reject(request.error ?? new Error("could not open credential vault database"));
      request.onblocked = () => reject(new Error("credential vault database upgrade is blocked"));
      request.onsuccess = () => {
        request.result.onversionchange = () => request.result.close();
        resolve(request.result);
      };
    });
    return this.#database;
  }

  #write(
    db: IDBDatabase,
    operation: (store: IDBObjectStore, finish: (result: boolean) => void) => void,
  ): Promise<boolean> {
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, "readwrite", { durability: "strict" });
      let result = false;
      let operationError: unknown;
      const finish = (value: boolean) => { result = value; };
      transaction.oncomplete = () => resolve(result);
      transaction.onerror = () => reject(operationError ?? transaction.error ?? new Error("vault transaction failed"));
      transaction.onabort = () => reject(operationError ?? transaction.error ?? new Error("vault transaction aborted"));
      try {
        operation(transaction.objectStore(STORE_NAME), finish);
      } catch (error) {
        operationError = error;
        transaction.abort();
      }
    });
  }
}

function parseStoredRecord(value: unknown): IndexedDbVaultRecord {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("stored vault record is invalid");
  const candidate = value as Partial<IndexedDbVaultRecord>;
  if (
    Object.keys(candidate).sort().join(",") !== "key,revision,schema,vault" ||
    candidate.schema !== RECORD_SCHEMA ||
    candidate.key !== RECORD_KEY ||
    !Number.isSafeInteger(candidate.revision) ||
    (candidate.revision as number) < 1
  ) {
    throw new Error("stored vault record is invalid");
  }
  return {
    schema: RECORD_SCHEMA,
    key: RECORD_KEY,
    revision: candidate.revision as number,
    vault: parseCredentialVault(candidate.vault),
  };
}

function openDatabase(factory: IDBFactory, databaseName: string): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = factory.open(databaseName, DATABASE_VERSION);
    request.onupgradeneeded = () => {
      if (!request.result.objectStoreNames.contains(STORE_NAME)) {
        request.result.createObjectStore(STORE_NAME, { keyPath: "key" });
      }
    };
    request.onerror = () => reject(request.error ?? new Error("could not open credential vault database"));
    request.onblocked = () => reject(new Error("credential vault database upgrade is blocked"));
    request.onsuccess = () => resolve(request.result);
  });
}

export function parseEncryptedCredentialVaultBackup(value: unknown): EncryptedCredentialVaultBackup {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("encrypted vault backup is invalid");
  const candidate = value as Partial<EncryptedCredentialVaultBackup>;
  if (
    Object.keys(candidate).sort().join(",") !== "cipher,ciphertext,iv,kdf,salt,schema,version" ||
    candidate.schema !== BACKUP_SCHEMA ||
    candidate.version !== BACKUP_VERSION ||
    candidate.cipher !== BACKUP_CIPHER ||
    candidate.kdf !== BACKUP_KDF
  ) {
    throw new Error("encrypted vault backup is invalid");
  }
  decodeBase64Url(candidate.salt, "backup salt", BACKUP_SALT_BYTES);
  decodeBase64Url(candidate.iv, "backup IV", BACKUP_IV_BYTES);
  const ciphertext = decodeBase64Url(candidate.ciphertext, "backup ciphertext", MAX_BACKUP_CIPHERTEXT_BYTES);
  if (ciphertext.byteLength < 17) throw new Error("backup ciphertext is invalid");
  return candidate as EncryptedCredentialVaultBackup;
}

function record(vault: PortableCredentialVault, revision: number): IndexedDbVaultRecord {
  return { schema: RECORD_SCHEMA, key: RECORD_KEY, revision, vault: structuredClone(vault) };
}

function parseCredentialVaultShape(vaultId: string, binding: CredentialVaultBinding): Pick<PortableCredentialVault, "vaultId" | "binding"> {
  assertBoundedString(vaultId, "vault id", 64);
  if (decodeBase64Url(vaultId, "vault id", 16).byteLength !== 16) throw new Error("vault id must be 16 bytes");
  assertBoundedString(binding?.schema, "vault binding schema", 512);
  assertBoundedString(binding?.rpId, "vault binding rpId", 253);
  return { vaultId, binding: { schema: binding.schema, rpId: binding.rpId } };
}

function assertBoundedString(value: unknown, label: string, max: number): asserts value is string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) {
    throw new Error(`${label} must be a non-empty string of at most ${max} characters`);
  }
}

function assertSha256(value: unknown): asserts value is string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) throw new Error("whole-vault digest is invalid");
}

function cryptoApi(): Crypto {
  if (!globalThis.crypto?.subtle || !globalThis.crypto.getRandomValues) throw new Error("Web Crypto is required");
  return globalThis.crypto;
}

function backupKey(value: Uint8Array): Uint8Array {
  if (!(value instanceof Uint8Array) || value.byteLength !== BACKUP_KEY_BYTES) {
    throw new Error(`credential vault backup key must be ${BACKUP_KEY_BYTES} bytes`);
  }
  return new Uint8Array(value);
}

async function deriveBackupKey(secret: Uint8Array, salt: Uint8Array): Promise<CryptoKey> {
  const material = await cryptoApi().subtle.importKey("raw", arrayBuffer(secret), "HKDF", false, ["deriveKey"]);
  return cryptoApi().subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: arrayBuffer(salt), info: backupAad() },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

function backupAad(): ArrayBuffer {
  return arrayBuffer(new TextEncoder().encode(JSON.stringify([BACKUP_SCHEMA, BACKUP_VERSION, BACKUP_CIPHER, BACKUP_KDF])));
}

function arrayBuffer(value: Uint8Array): ArrayBuffer {
  return new Uint8Array(value).buffer as ArrayBuffer;
}

function base64Url(value: Uint8Array): string {
  let binary = "";
  for (const byte of value) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function decodeBase64Url(value: unknown, label: string, maxBytes: number): Uint8Array {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    value.length > Math.ceil((maxBytes * 4) / 3) + 2 ||
    !/^[A-Za-z0-9_-]+$/u.test(value) ||
    value.length % 4 === 1
  ) {
    throw new Error(`${label} must be canonical unpadded base64url`);
  }
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try { binary = atob(padded); } catch { throw new Error(`${label} must be canonical unpadded base64url`); }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.byteLength > maxBytes || base64Url(bytes) !== value) {
    throw new Error(`${label} must be canonical unpadded base64url`);
  }
  return bytes;
}

function requestResult<T>(request: IDBRequest): Promise<T> {
  return new Promise((resolve, reject) => {
    request.onsuccess = () => resolve(request.result as T);
    request.onerror = () => reject(request.error ?? new Error("IndexedDB request failed"));
  });
}

function transactionComplete(transaction: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    transaction.oncomplete = () => resolve();
    transaction.onerror = () => reject(transaction.error ?? new Error("IndexedDB transaction failed"));
    transaction.onabort = () => reject(transaction.error ?? new Error("IndexedDB transaction aborted"));
  });
}
