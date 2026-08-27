/**
 * Browser adapter for the circuit-native ADR-0014 refresh engine.
 *
 * The WASM module is loaded and hash-checked before any vault decryption. The
 * Worker then irreversibly masks ordinary network capabilities before the
 * private payload enters this adapter. Independent audit admission remains a
 * compile-time false constant in this slice.
 */
import { serializeZkIdentityPackedStatusSnapshot } from "./zk-identity-status-snapshot";
import { BN254_SCALAR_FIELD } from "./zk-identity-encoding";
import {
  ZkHolderPrivateStatusRefreshClient,
  serveZkHolderPrivateStatusRefreshWorker,
  ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_MEMORY_BYTES,
  type ZkHolderDerivedStatusPath,
  type ZkHolderPrivateStatusRefreshEngine,
  type ZkHolderPrivateStatusRefreshPolicy,
  type ZkHolderPrivateStatusRefreshWorkerLike,
  type ZkHolderPrivateStatusRefreshWorkerScopeLike,
} from "./zk-holder-private-status-refresh";
import {
  ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
  type ZkHolderProductionVaultPayload,
} from "./zk-holder-production-vault";
import { ZK_HOLDER_PROFILE_ID } from "./zk-holder-profile-prover-worker";

export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256 =
  "42123b2ab76133356e55e1ce15461a9dd662f96968f4eee862c668fd7f011cee" as const;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_BYTES = 326_583 as const;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_BINDINGS_SHA256 =
  "f22864b136562cf7d8a8d2c4ab6a16f9c01bd157feaa27b5129d5b741c399feb" as const;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256 =
  "ae57f9b95b7f53fc20bf77c3a77b103a37815b65232fff408e0458dd10ad008d" as const;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_NAME =
  "ubi2-v2-holder-private-status-refresh" as const;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED = false as const;

const WORKER_BASENAME =
  `holder-private-status-refresh-worker.${ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_SOURCE_SHA256}.js`;

export interface ZkHolderPrivateStatusRefreshWasmBindings {
  validatePackedStatusSnapshot(snapshotJson: string): void;
  verifyProductionVaultPayload(payloadJson: string): void;
  buildPackedStatusPath(snapshotJson: string, statusId: number): string;
  wasmLinearMemoryBytes(): number;
  destroy?(): void;
}

export interface ZkHolderPrivateStatusRefreshWasmPackage {
  wasmSha256: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256;
  bindingsSha256: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_BINDINGS_SHA256;
  bindings: ZkHolderPrivateStatusRefreshWasmBindings;
}

export type ZkHolderPrivateStatusRefreshWasmLoader =
  () => Promise<ZkHolderPrivateStatusRefreshWasmPackage> | ZkHolderPrivateStatusRefreshWasmPackage;

export interface ZkHolderPrivateStatusRefreshBrowserWorkerConstructor {
  new(
    url: URL,
    options: { type: "module"; name: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_NAME },
  ): ZkHolderPrivateStatusRefreshWorkerLike;
}

export interface ZkHolderPrivateStatusRefreshBrowserClientOptions {
  workerUrl: URL;
  WorkerConstructor?: ZkHolderPrivateStatusRefreshBrowserWorkerConstructor;
}

export interface ZkHolderPrivateStatusRefreshBrowserWorkerOptions {
  policy: ZkHolderPrivateStatusRefreshPolicy;
  loadWasm: ZkHolderPrivateStatusRefreshWasmLoader;
  /** Worker global, injectable only for isolation tests. */
  networkTarget?: Record<string, unknown>;
  /** Trusted wall clock, injectable only for deterministic tests. */
  now?: () => number;
}

/** Circuit-native candidate engine. Admission is intentionally always false. */
export class ZkHolderPrivateStatusRefreshBrowserWasmEngine
implements ZkHolderPrivateStatusRefreshEngine {
  readonly #loadWasm: ZkHolderPrivateStatusRefreshWasmLoader;
  readonly #networkTarget: Record<string, unknown>;
  #loading?: Promise<ZkHolderPrivateStatusRefreshWasmBindings>;
  #bindings?: ZkHolderPrivateStatusRefreshWasmBindings;
  #lastMemoryBytes = 0;
  #networkLocked = false;

  constructor(
    loadWasm: ZkHolderPrivateStatusRefreshWasmLoader,
    networkTarget: Record<string, unknown> = globalThis as unknown as Record<string, unknown>,
  ) {
    if (typeof loadWasm !== "function") throw new Error("a holder refresh WASM loader is required");
    this.#loadWasm = loadWasm;
    this.#networkTarget = networkTarget;
  }

  admitsProductionProfile(policy: ZkHolderPrivateStatusRefreshPolicy): boolean {
    return ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED &&
      policy.productionApproved &&
      policy.profileId === ZK_HOLDER_PROFILE_ID &&
      policy.parameterManifestSha256 === ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256;
  }

  async validateSnapshot(snapshot: Parameters<ZkHolderPrivateStatusRefreshEngine["validateSnapshot"]>[0], signal: AbortSignal): Promise<void> {
    abortIfRequested(signal);
    const bindings = await this.#load();
    abortIfRequested(signal);
    bindings.validatePackedStatusSnapshot(serializeZkIdentityPackedStatusSnapshot(snapshot));
    this.#measure(bindings);
    abortIfRequested(signal);
  }

  async verifyPayload(payload: ZkHolderProductionVaultPayload, signal: AbortSignal): Promise<void> {
    abortIfRequested(signal);
    if (!this.#networkLocked) throw new Error("holder refresh network must be locked before payload verification");
    const bindings = await this.#load();
    abortIfRequested(signal);
    bindings.verifyProductionVaultPayload(JSON.stringify(payload));
    this.#measure(bindings);
    abortIfRequested(signal);
  }

  async buildStatusPath(input: {
    snapshot: Parameters<ZkHolderPrivateStatusRefreshEngine["validateSnapshot"]>[0];
    statusId: number;
    signal: AbortSignal;
  }): Promise<ZkHolderDerivedStatusPath> {
    abortIfRequested(input.signal);
    if (!this.#networkLocked) throw new Error("holder refresh network must be locked before path derivation");
    const bindings = await this.#load();
    abortIfRequested(input.signal);
    const result = parseDerivedStatusPath(bindings.buildPackedStatusPath(
      serializeZkIdentityPackedStatusSnapshot(input.snapshot),
      input.statusId,
    ));
    this.#measure(bindings);
    abortIfRequested(input.signal);
    return result;
  }

  lockNetwork(): void {
    if (this.#networkLocked) return;
    lockWorkerNetwork(this.#networkTarget);
    this.#networkLocked = true;
  }

  memoryBytes(): number {
    return this.#lastMemoryBytes;
  }

  destroy(): void {
    try { this.#bindings?.destroy?.(); } finally {
      this.#bindings = undefined;
      this.#loading = undefined;
      this.#lastMemoryBytes = 0;
    }
  }

  async #load(): Promise<ZkHolderPrivateStatusRefreshWasmBindings> {
    if (this.#bindings) return this.#bindings;
    this.#loading ??= Promise.resolve(this.#loadWasm()).then((loaded) => {
      if (
        loaded === null || typeof loaded !== "object" ||
        loaded.wasmSha256 !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_WASM_SHA256 ||
        loaded.bindingsSha256 !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_BINDINGS_SHA256
      ) {
        throw new Error("holder refresh WASM package does not match the pinned content address");
      }
      validateBindings(loaded.bindings);
      this.#measure(loaded.bindings);
      this.#bindings = loaded.bindings;
      return loaded.bindings;
    });
    return this.#loading;
  }

  #measure(bindings: ZkHolderPrivateStatusRefreshWasmBindings): void {
    const bytes = bindings.wasmLinearMemoryBytes();
    if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_MEMORY_BYTES) {
      throw new Error("holder refresh WASM memory is outside the supported range");
    }
    this.#lastMemoryBytes = bytes;
  }
}

export function serveZkHolderPrivateStatusRefreshBrowserWorker(
  scope: ZkHolderPrivateStatusRefreshWorkerScopeLike,
  options: ZkHolderPrivateStatusRefreshBrowserWorkerOptions,
): void {
  if (options === null || typeof options !== "object") throw new Error("holder refresh browser Worker options are required");
  const engine = new ZkHolderPrivateStatusRefreshBrowserWasmEngine(
    options.loadWasm,
    options.networkTarget ?? scope as unknown as Record<string, unknown>,
  );
  serveZkHolderPrivateStatusRefreshWorker(scope, {
    policy: options.policy,
    engine,
    now: options.now,
  });
}

export function createZkHolderPrivateStatusRefreshBrowserClient(
  options: ZkHolderPrivateStatusRefreshBrowserClientOptions,
): ZkHolderPrivateStatusRefreshClient {
  const workerUrl = browserWorkerUrl(options?.workerUrl);
  const WorkerConstructor = options?.WorkerConstructor ??
    (globalThis as { Worker?: ZkHolderPrivateStatusRefreshBrowserWorkerConstructor }).Worker;
  if (typeof WorkerConstructor !== "function") throw new Error("module Workers are unavailable");
  return new ZkHolderPrivateStatusRefreshClient(() => new WorkerConstructor(workerUrl, {
    type: "module",
    name: ZK_HOLDER_PRIVATE_STATUS_REFRESH_WORKER_NAME,
  }));
}

/** Irreversible ordinary-network capability mask installed before decryption. */
export function lockWorkerNetwork(target: Record<string, unknown>): void {
  if (target === null || typeof target !== "object") throw new Error("a Worker network target is required");
  const deny = Object.freeze(function networkDisabled(): never {
    throw new Error("network capability is disabled inside the holder refresh Worker");
  });
  for (const key of ["fetch", "XMLHttpRequest", "WebSocket", "EventSource", "WebTransport", "importScripts"] as const) {
    const descriptor = Object.getOwnPropertyDescriptor(target, key);
    if (descriptor && !descriptor.configurable) {
      throw new Error("holder refresh Worker network capability could not be disabled");
    }
    Object.defineProperty(target, key, {
      value: deny,
      configurable: false,
      enumerable: false,
      writable: false,
    });
  }
}

function parseDerivedStatusPath(value: string): ZkHolderDerivedStatusPath {
  if (typeof value !== "string" || value.length < 64 || value.length > 8 * 1024) {
    throw new Error("holder refresh WASM path output size is invalid");
  }
  let raw: unknown;
  try { raw = JSON.parse(value); } catch { throw new Error("holder refresh WASM path output is invalid JSON"); }
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) throw new Error("holder refresh WASM path output is invalid");
  const candidate = raw as Record<string, unknown>;
  exactKeys(candidate, ["chunkLimbsLittleEndian", "siblingsBottomUp"]);
  if (!Array.isArray(candidate.chunkLimbsLittleEndian) || candidate.chunkLimbsLittleEndian.length !== 2) {
    throw new Error("holder refresh WASM chunk output is invalid");
  }
  const chunk = candidate.chunkLimbsLittleEndian.map((entry) => decimal(entry, (1n << 128n) - 1n)) as [string, string];
  if (!Array.isArray(candidate.siblingsBottomUp) || candidate.siblingsBottomUp.length !== 24) {
    throw new Error("holder refresh WASM path length is invalid");
  }
  const siblings = candidate.siblingsBottomUp.map((entry) => decimal(
    entry,
    BN254_SCALAR_FIELD - 1n,
  ));
  return { chunkLimbsLittleEndian: chunk, siblingsBottomUp: siblings };
}

function validateBindings(value: unknown): asserts value is ZkHolderPrivateStatusRefreshWasmBindings {
  if (value === null || typeof value !== "object" || Array.isArray(value)) throw new Error("holder refresh WASM bindings are invalid");
  const candidate = value as Partial<ZkHolderPrivateStatusRefreshWasmBindings>;
  if (
    typeof candidate.validatePackedStatusSnapshot !== "function" ||
    typeof candidate.verifyProductionVaultPayload !== "function" ||
    typeof candidate.buildPackedStatusPath !== "function" ||
    typeof candidate.wasmLinearMemoryBytes !== "function" ||
    (candidate.destroy !== undefined && typeof candidate.destroy !== "function")
  ) throw new Error("holder refresh WASM bindings are incomplete");
}

function browserWorkerUrl(value: unknown): URL {
  if (!(value instanceof URL)) throw new Error("holder refresh Worker URL must be absolute");
  if (value.protocol !== "https:" && value.protocol !== "http:") throw new Error("holder refresh Worker URL must use HTTP or HTTPS");
  if (value.username || value.password || value.hash || value.search) {
    throw new Error("holder refresh Worker URL must not contain credentials, a query or a fragment");
  }
  if (!value.pathname.endsWith(`/${WORKER_BASENAME}`)) {
    throw new Error("holder refresh Worker URL is not the pinned content-addressed module");
  }
  const location = (globalThis as { location?: Location }).location;
  if (location && value.origin !== location.origin) throw new Error("holder refresh Worker URL must be same-origin");
  return new URL(value.href);
}

function decimal(value: unknown, maximum: bigint): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value) || BigInt(value) > maximum) {
    throw new Error("holder refresh WASM field output is not canonical");
  }
  return value;
}

function exactKeys(candidate: Record<string, unknown>, keys: readonly string[]): void {
  const actual = Object.keys(candidate).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error("holder refresh WASM path output fields are invalid");
  }
}

function abortIfRequested(signal: AbortSignal): void {
  if (signal.aborted) throw new Error("holder refresh WASM operation was cancelled");
}
