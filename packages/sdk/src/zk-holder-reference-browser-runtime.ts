/**
 * Browser/WASM adapter for the deterministic 18-signal reference proof.
 *
 * This is permanently reference-only. It accepts no credential, witness, key,
 * artifact URL or proof bytes from the host. The generated research proof and
 * public-toxic-waste setup stay inside the disposable Worker/WASM instance and
 * are discarded before the existing non-presentable receipt is emitted.
 */
import { decodeZkIdentityPublicSignals, ZK_PUBLIC_SIGNAL_COUNT } from "./zk-identity-encoding";
import {
  serveZkHolderReferenceProverWorker,
  ZkHolderReferenceProverClient,
  ZK_HOLDER_REFERENCE_PROVER_MAX_MEMORY_BYTES,
  type ZkHolderReferenceProvingEngine,
  type ZkHolderReferenceProvingEngineInput,
  type ZkHolderReferenceWorkerLike,
  type ZkHolderReferenceWorkerScopeLike,
} from "./zk-holder-reference-prover-worker";

export const ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID =
  "synthetic:dynamic-status-research-v1" as const;
export const ZK_HOLDER_REFERENCE_BROWSER_REPORT_SCHEMA =
  "org.proofofhumanity.v2-browser-dynamic-status-reference-proof/1" as const;
export const ZK_HOLDER_REFERENCE_BROWSER_REPORT_WARNING =
  "research fixture only; deterministic toxic-waste setup and proof are not deployable" as const;
export const ZK_HOLDER_REFERENCE_BROWSER_WORKER_NAME =
  "ubi2-holder-reference-prover" as const;
export const ZK_HOLDER_REFERENCE_BROWSER_CONSTRAINTS = 28_499 as const;
export const ZK_HOLDER_REFERENCE_BROWSER_WITNESS_VARIABLES = 27_561 as const;

/** Exact public inputs emitted by the deterministic research fixture. */
export const ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS: readonly bigint[] = Object.freeze([
  1n,
  289702399193246464478010289331281785396n,
  48741886182628607789356429954167136159n,
  5684059935654687451218130737850785594n,
  67299010049198418576218540330172003346n,
  37132466444412026084997320841716176201n,
  145816799220352339406472454506834083821n,
  193982682682601763857871921400019234941n,
  144791356043039333640796404275935384537n,
  251146112810056859446043645491032321007n,
  180051849839934735603729905154568835574n,
  217086243769357075757050964729507721374n,
  147556859725270294027880020698272123538n,
  2173426621476070313010179067782747041747347598219631929177813172977412983666n,
  292300327466180583640736966543256603931186508595n,
  1n,
  230n,
  1788480000n,
]);

// Validate the checked-in vector at module initialization so drift fails before proving.
decodeZkIdentityPublicSignals(ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS);

export interface ZkHolderReferenceBrowserWasmBindings {
  /** Generates and verifies the synthetic proof, returning only sanitized JSON. */
  proveDynamicStatusReference(): string;
  /** Current Rust/WASM linear memory high-water value. */
  wasmLinearMemoryBytes(): number;
  /** Optional generated-binding teardown hook. */
  destroy?(): void;
}

export type ZkHolderReferenceBrowserWasmLoader = () =>
  | Promise<ZkHolderReferenceBrowserWasmBindings>
  | ZkHolderReferenceBrowserWasmBindings;

export interface ZkHolderReferenceBrowserWorkerConstructor {
  new (
    scriptUrl: URL,
    options: { type: "module"; name: typeof ZK_HOLDER_REFERENCE_BROWSER_WORKER_NAME },
  ): ZkHolderReferenceWorkerLike;
}

export interface ZkHolderReferenceBrowserClientOptions {
  /** Same-origin, content-addressable module Worker entry chosen by the application bundle. */
  workerUrl: URL;
  /** Test seam. Browsers use the global Worker constructor by default. */
  WorkerConstructor?: ZkHolderReferenceBrowserWorkerConstructor;
}

export interface ZkHolderReferenceBrowserReport {
  schema: typeof ZK_HOLDER_REFERENCE_BROWSER_REPORT_SCHEMA;
  warning: typeof ZK_HOLDER_REFERENCE_BROWSER_REPORT_WARNING;
  constraints: typeof ZK_HOLDER_REFERENCE_BROWSER_CONSTRAINTS;
  witness_variables: typeof ZK_HOLDER_REFERENCE_BROWSER_WITNESS_VARIABLES;
  public_input_count: typeof ZK_PUBLIC_SIGNAL_COUNT;
  public_inputs: readonly bigint[];
  proof_verified: true;
}

/**
 * Worker-private adapter around the generated Rust/WASM bindings.
 *
 * The WASM call is synchronous once started. Cancellation remains safe because
 * the host controller terminates the disposable Worker instead of waiting for
 * cooperative JavaScript execution.
 */
export class ZkHolderReferenceBrowserWasmEngine implements ZkHolderReferenceProvingEngine {
  readonly #loadWasm: ZkHolderReferenceBrowserWasmLoader;
  #bindings: ZkHolderReferenceBrowserWasmBindings | undefined;
  #generation = 0;

  constructor(loadWasm: ZkHolderReferenceBrowserWasmLoader) {
    if (typeof loadWasm !== "function") throw new Error("a reference browser WASM loader is required");
    this.#loadWasm = loadWasm;
  }

  async runReference(input: ZkHolderReferenceProvingEngineInput): Promise<{
    publicSignals: readonly bigint[];
    proofVerified: true;
    retainedMemoryBytes: number;
  }> {
    if (input.fixtureId !== ZK_HOLDER_REFERENCE_BROWSER_FIXTURE_ID) {
      throw new Error("unsupported reference browser fixture");
    }
    if (!sameSignals(input.expectedPublicSignals, ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS)) {
      throw new Error("reference browser public signals do not match the pinned fixture");
    }
    abortIfRequested(input.signal);
    const generation = this.#generation;
    input.reportProgress({ phase: "loading-artifacts", percent: 5, memoryBytes: 0 });

    const bindings = await this.#loadWasm();
    if (generation !== this.#generation) throw new Error("reference browser engine was destroyed during load");
    abortIfRequested(input.signal);
    validateBindings(bindings);
    this.#bindings = bindings;
    const loadedMemoryBytes = readMemory(bindings);
    input.reportProgress({
      phase: "loading-artifacts",
      percent: 20,
      memoryBytes: loadedMemoryBytes,
    });
    input.reportProgress({
      phase: "building-witness",
      percent: 35,
      memoryBytes: loadedMemoryBytes,
    });
    abortIfRequested(input.signal);
    input.reportProgress({ phase: "proving", percent: 55, memoryBytes: loadedMemoryBytes });

    // Synchronous Rust/WASM setup + proof + verification. Proof/key bytes never enter the result schema.
    const rawReport = bindings.proveDynamicStatusReference();
    abortIfRequested(input.signal);
    const report = parseBrowserReferenceReport(rawReport);
    const retainedMemoryBytes = readMemory(bindings);
    input.reportProgress({ phase: "verifying", percent: 95, memoryBytes: retainedMemoryBytes });
    if (!sameSignals(report.public_inputs, input.expectedPublicSignals)) {
      throw new Error("reference browser proof changed the pinned public signals");
    }
    return {
      publicSignals: report.public_inputs,
      proofVerified: true,
      retainedMemoryBytes,
    };
  }

  destroy(): void {
    this.#generation += 1;
    const bindings = this.#bindings;
    this.#bindings = undefined;
    try {
      bindings?.destroy?.();
    } catch {
      // The outer one-shot runtime terminates the Worker even if generated teardown fails.
    }
  }
}

/** Install the reference-only Rust/WASM engine in a dedicated Worker global. */
export function serveZkHolderReferenceBrowserWorker(
  scope: ZkHolderReferenceWorkerScopeLike,
  loadWasm: ZkHolderReferenceBrowserWasmLoader,
): void {
  serveZkHolderReferenceProverWorker(scope, new ZkHolderReferenceBrowserWasmEngine(loadWasm));
}

/** Create a browser client that always launches a same-origin module Worker. */
export function createZkHolderReferenceBrowserClient(
  options: ZkHolderReferenceBrowserClientOptions,
): ZkHolderReferenceProverClient {
  const workerUrl = browserWorkerUrl(options?.workerUrl);
  const WorkerConstructor =
    options?.WorkerConstructor ??
    ((globalThis as { Worker?: ZkHolderReferenceBrowserWorkerConstructor }).Worker as
      | ZkHolderReferenceBrowserWorkerConstructor
      | undefined);
  if (typeof WorkerConstructor !== "function") {
    throw new Error("module Workers are unavailable in this browser runtime");
  }
  return new ZkHolderReferenceProverClient(
    () =>
      new WorkerConstructor(workerUrl, {
        type: "module",
        name: ZK_HOLDER_REFERENCE_BROWSER_WORKER_NAME,
      }),
  );
}

export function parseZkHolderReferenceBrowserReport(value: unknown): ZkHolderReferenceBrowserReport {
  const source = typeof value === "string" ? strictJson(value) : value;
  const candidate = object(source, "reference browser proof report");
  exactKeys(
    candidate,
    [
      "schema",
      "warning",
      "constraints",
      "witness_variables",
      "public_input_count",
      "public_inputs",
      "proof_verified",
    ],
    "reference browser proof report",
  );
  if (
    candidate.schema !== ZK_HOLDER_REFERENCE_BROWSER_REPORT_SCHEMA ||
    candidate.warning !== ZK_HOLDER_REFERENCE_BROWSER_REPORT_WARNING ||
    candidate.constraints !== ZK_HOLDER_REFERENCE_BROWSER_CONSTRAINTS ||
    candidate.witness_variables !== ZK_HOLDER_REFERENCE_BROWSER_WITNESS_VARIABLES ||
    candidate.public_input_count !== ZK_PUBLIC_SIGNAL_COUNT ||
    candidate.proof_verified !== true
  ) {
    throw new Error("unsupported reference browser proof report");
  }
  if (!Array.isArray(candidate.public_inputs) || candidate.public_inputs.length !== ZK_PUBLIC_SIGNAL_COUNT) {
    throw new Error("reference browser proof report must contain exactly 18 public inputs");
  }
  const publicInputs = candidate.public_inputs.map((value, index) => decimalField(value, index));
  decodeZkIdentityPublicSignals(publicInputs);
  if (!sameSignals(publicInputs, ZK_HOLDER_REFERENCE_BROWSER_PUBLIC_SIGNALS)) {
    throw new Error("reference browser proof report does not match the pinned fixture");
  }
  return {
    schema: ZK_HOLDER_REFERENCE_BROWSER_REPORT_SCHEMA,
    warning: ZK_HOLDER_REFERENCE_BROWSER_REPORT_WARNING,
    constraints: ZK_HOLDER_REFERENCE_BROWSER_CONSTRAINTS,
    witness_variables: ZK_HOLDER_REFERENCE_BROWSER_WITNESS_VARIABLES,
    public_input_count: ZK_PUBLIC_SIGNAL_COUNT,
    public_inputs: publicInputs,
    proof_verified: true,
  };
}

function parseBrowserReferenceReport(value: unknown): ZkHolderReferenceBrowserReport {
  return parseZkHolderReferenceBrowserReport(value);
}

function validateBindings(value: unknown): asserts value is ZkHolderReferenceBrowserWasmBindings {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error("reference browser WASM bindings must be an object");
  }
  const candidate = value as Partial<ZkHolderReferenceBrowserWasmBindings>;
  if (
    typeof candidate.proveDynamicStatusReference !== "function" ||
    typeof candidate.wasmLinearMemoryBytes !== "function" ||
    (candidate.destroy !== undefined && typeof candidate.destroy !== "function")
  ) {
    throw new Error("reference browser WASM bindings are incomplete");
  }
}

function readMemory(bindings: ZkHolderReferenceBrowserWasmBindings): number {
  const value = bindings.wasmLinearMemoryBytes();
  if (!Number.isSafeInteger(value) || value < 0 || value > ZK_HOLDER_REFERENCE_PROVER_MAX_MEMORY_BYTES) {
    throw new Error("reference browser WASM memory is outside the supported range");
  }
  return value;
}

function browserWorkerUrl(value: unknown): URL {
  if (!(value instanceof URL)) throw new Error("reference browser Worker URL must be an absolute URL");
  if (value.protocol !== "https:" && value.protocol !== "http:") {
    throw new Error("reference browser Worker URL must use HTTP or HTTPS");
  }
  if (value.username || value.password || value.hash) {
    throw new Error("reference browser Worker URL must not contain credentials or a fragment");
  }
  const browserLocation = (globalThis as { location?: Location }).location;
  if (browserLocation && value.origin !== browserLocation.origin) {
    throw new Error("reference browser Worker URL must be same-origin");
  }
  return new URL(value.href);
}

function abortIfRequested(signal: AbortSignal): void {
  if (signal.aborted) throw new Error("reference browser proving was cancelled");
}

function sameSignals(left: readonly bigint[], right: readonly bigint[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function strictJson(value: string): unknown {
  if (value.length < 2 || value.length > 16 * 1024) {
    throw new Error("reference browser proof report has an invalid size");
  }
  try {
    return JSON.parse(value);
  } catch {
    throw new Error("reference browser proof report is not valid JSON");
  }
}

function decimalField(value: unknown, index: number): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/u.test(value)) {
    throw new Error(`reference browser public input ${index} is not canonical decimal`);
  }
  return BigInt(value);
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(candidate: Record<string, unknown>, keys: readonly string[], label: string): void {
  const expected = [...keys].sort();
  const actual = Object.keys(candidate).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} fields are invalid`);
  }
}
