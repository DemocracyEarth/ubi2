/** Browser/WASM adapter for the ratified V2 holder cryptographic profile. */
import { parseZkHolderReferenceVaultPayload, ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA } from "./zk-holder-reference-handoff";
import {
  serializeZkHolderGroth16Proof,
  serveZkHolderProfileProverWorker,
  ZkHolderProfileProverClient,
  ZK_HOLDER_PROFILE_ID,
  ZK_HOLDER_PROFILE_MAX_MEMORY_BYTES,
  ZK_HOLDER_PROFILE_SANCTIONS_CIRCUIT_ID,
  ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID,
  ZK_HOLDER_PROFILE_SYNTHETIC_WARNING,
  type ZkHolderProfileProvingEngine,
  type ZkHolderProfileEngineInput,
  type ZkHolderProfileWorkerLike,
  type ZkHolderProfileWorkerScopeLike,
} from "./zk-holder-profile-prover-worker";

export const ZK_HOLDER_PROFILE_BROWSER_WORKER_NAME = "ubi2-holder-profile-prover" as const;
export const ZK_HOLDER_PROFILE_BROWSER_REPORT_SCHEMA =
  "org.proofofhumanity.v2-holder-profile-synthetic-proof/1" as const;
export const ZK_HOLDER_PROFILE_BROWSER_CONSTRAINTS = 28_499 as const;
export const ZK_HOLDER_PROFILE_BROWSER_WITNESS_VARIABLES = 27_561 as const;

const BN254_BASE_FIELD =
  21_888_242_871_839_275_222_246_405_745_257_275_088_696_311_157_297_823_662_689_037_894_645_226_208_583n;

/** Exact ratified-profile synthetic vector; all 18 positions remain frozen. */
export const ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS: readonly bigint[] = Object.freeze([
  1n,
  298153432178052702942782841865641982479n,
  323371391837014476834094542362038374866n,
  5684059935654687451218130737850785594n,
  67299010049198418576218540330172003346n,
  55069225046984221918962208138329020160n,
  144683645641168599330677347960429542586n,
  193982682682601763857871921400019234941n,
  144791356043039333640796404275935384537n,
  251146112810056859446043645491032321007n,
  180051849839934735603729905154568835574n,
  217086243769357075757050964729507721374n,
  147556859725270294027880020698272123538n,
  21747405852401584827188266926965114988458708712933309970979850614266557444889n,
  292300327466180583640736966543256603931186508595n,
  1n,
  230n,
  1788480000n,
]);

export interface ZkHolderProfileBrowserWasmBindings {
  /** Consumes the decrypted synthetic credential in WASM memory. */
  proveSyntheticHolderProfile(privateCredentialJson: string): string;
  wasmLinearMemoryBytes(): number;
  destroy?(): void;
}

export type ZkHolderProfileBrowserWasmLoader = (
  verifiedWasmModule: Uint8Array,
) => Promise<ZkHolderProfileBrowserWasmBindings> | ZkHolderProfileBrowserWasmBindings;

export interface ZkHolderProfileBrowserWorkerConstructor {
  new (
    scriptUrl: URL,
    options: { type: "module"; name: typeof ZK_HOLDER_PROFILE_BROWSER_WORKER_NAME },
  ): ZkHolderProfileWorkerLike;
}

export interface ZkHolderProfileBrowserClientOptions {
  workerUrl: URL;
  WorkerConstructor?: ZkHolderProfileBrowserWorkerConstructor;
}

interface EvmG1 { x: bigint; y: bigint }
interface EvmG2 { xImaginary: bigint; xReal: bigint; yImaginary: bigint; yReal: bigint }

export interface ZkHolderProfileBrowserReport {
  schema: typeof ZK_HOLDER_PROFILE_BROWSER_REPORT_SCHEMA;
  profileId: typeof ZK_HOLDER_PROFILE_ID;
  warning: typeof ZK_HOLDER_PROFILE_SYNTHETIC_WARNING;
  constraints: typeof ZK_HOLDER_PROFILE_BROWSER_CONSTRAINTS;
  witnessVariables: typeof ZK_HOLDER_PROFILE_BROWSER_WITNESS_VARIABLES;
  publicInputCount: 18;
  publicInputs: readonly bigint[];
  proof: { a: EvmG1; b: EvmG2; c: EvmG1 };
  proofVerified: true;
}

export class ZkHolderProfileBrowserWasmEngine implements ZkHolderProfileProvingEngine {
  readonly #loadWasm: ZkHolderProfileBrowserWasmLoader;
  #bindings: ZkHolderProfileBrowserWasmBindings | undefined;
  #generation = 0;

  constructor(loadWasm: ZkHolderProfileBrowserWasmLoader) {
    if (typeof loadWasm !== "function") throw new Error("a holder profile WASM loader is required");
    this.#loadWasm = loadWasm;
  }

  admitsProductionProfile(): false {
    // No ceremony artifact or production vault envelope is admitted in this build.
    return false;
  }

  acceptsVaultBinding(mode: "synthetic" | "production", schema: string): boolean {
    return mode === "synthetic" && schema === ZK_HOLDER_REFERENCE_VAULT_PAYLOAD_SCHEMA;
  }

  parseVaultPayload(mode: "synthetic" | "production", value: unknown): unknown {
    if (mode !== "synthetic") throw new Error("production vault schema is not admitted");
    return parseZkHolderReferenceVaultPayload(value);
  }

  async prove(input: ZkHolderProfileEngineInput) {
    if (
      input.context.mode !== "synthetic" ||
      input.context.circuitId !== ZK_HOLDER_PROFILE_SANCTIONS_CIRCUIT_ID ||
      !sameSignals(input.expectedPublicSignals, ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS)
    ) throw new Error("unsupported holder profile browser fixture");
    const payload = parseZkHolderReferenceVaultPayload(input.vaultPayload);
    const wasmModule = input.artifacts.get("wasmModule");
    if (!wasmModule) throw new Error("verified holder profile WASM module is missing");
    abortIfRequested(input.signal);
    const generation = this.#generation;
    const bindings = await this.#loadWasm(wasmModule);
    if (generation !== this.#generation) throw new Error("holder profile engine was destroyed during load");
    abortIfRequested(input.signal);
    validateBindings(bindings);
    this.#bindings = bindings;
    const loadedMemory = readMemory(bindings);
    input.reportProgress({ phase: "building-witness", percent: 45, memoryBytes: loadedMemory });
    input.reportProgress({ phase: "proving", percent: 55, memoryBytes: loadedMemory });

    let privateCredentialJson: string | undefined;
    let rawReport: string;
    try {
      privateCredentialJson = JSON.stringify(payload.credential);
      rawReport = bindings.proveSyntheticHolderProfile(privateCredentialJson);
    } finally {
      privateCredentialJson = undefined;
    }
    abortIfRequested(input.signal);
    const report = parseZkHolderProfileBrowserReport(rawReport);
    const retainedMemoryBytes = readMemory(bindings);
    input.reportProgress({ phase: "verifying", percent: 95, memoryBytes: retainedMemoryBytes });
    if (!sameSignals(report.publicInputs, input.expectedPublicSignals)) {
      throw new Error("holder profile proof changed the frozen public signals");
    }
    return {
      proof: serializeZkHolderGroth16Proof([
        report.proof.a.x,
        report.proof.a.y,
        report.proof.b.xImaginary,
        report.proof.b.xReal,
        report.proof.b.yImaginary,
        report.proof.b.yReal,
        report.proof.c.x,
        report.proof.c.y,
      ]),
      publicSignals: report.publicInputs,
      locallyVerified: true,
      retainedMemoryBytes,
    };
  }

  destroy(): void {
    this.#generation += 1;
    const bindings = this.#bindings;
    this.#bindings = undefined;
    try { bindings?.destroy?.(); } catch { /* The outer Worker is still terminated. */ }
  }
}

export function serveZkHolderProfileBrowserWorker(
  scope: ZkHolderProfileWorkerScopeLike,
  loadWasm: ZkHolderProfileBrowserWasmLoader,
): void {
  serveZkHolderProfileProverWorker(scope, new ZkHolderProfileBrowserWasmEngine(loadWasm));
}

export function createZkHolderProfileBrowserClient(
  options: ZkHolderProfileBrowserClientOptions,
): ZkHolderProfileProverClient {
  const workerUrl = browserWorkerUrl(options?.workerUrl);
  const WorkerConstructor = options?.WorkerConstructor ??
    (globalThis as { Worker?: ZkHolderProfileBrowserWorkerConstructor }).Worker;
  if (typeof WorkerConstructor !== "function") throw new Error("module Workers are unavailable");
  return new ZkHolderProfileProverClient(() => new WorkerConstructor(workerUrl, {
    type: "module",
    name: ZK_HOLDER_PROFILE_BROWSER_WORKER_NAME,
  }));
}

export function parseZkHolderProfileBrowserReport(value: unknown): ZkHolderProfileBrowserReport {
  const source = typeof value === "string" ? strictJson(value) : value;
  const candidate = object(source, "holder profile browser report");
  exactKeys(candidate, [
    "schema", "profileId", "warning", "constraints", "witnessVariables", "publicInputCount",
    "publicInputs", "proof", "proofVerified",
  ], "holder profile browser report");
  if (
    candidate.schema !== ZK_HOLDER_PROFILE_BROWSER_REPORT_SCHEMA ||
    candidate.profileId !== ZK_HOLDER_PROFILE_ID ||
    candidate.warning !== ZK_HOLDER_PROFILE_SYNTHETIC_WARNING ||
    candidate.constraints !== ZK_HOLDER_PROFILE_BROWSER_CONSTRAINTS ||
    candidate.witnessVariables !== ZK_HOLDER_PROFILE_BROWSER_WITNESS_VARIABLES ||
    candidate.publicInputCount !== 18 || candidate.proofVerified !== true
  ) throw new Error("unsupported holder profile browser report");
  if (!Array.isArray(candidate.publicInputs) || candidate.publicInputs.length !== 18) {
    throw new Error("holder profile report must contain exactly 18 public inputs");
  }
  const publicInputs = candidate.publicInputs.map((entry, index) => decimal(entry, `public input ${index}`));
  if (!sameSignals(publicInputs, ZK_HOLDER_PROFILE_SYNTHETIC_PUBLIC_SIGNALS)) {
    throw new Error("holder profile report does not match the synthetic vector");
  }
  const rawProof = object(candidate.proof, "holder profile proof");
  exactKeys(rawProof, ["a", "b", "c"], "holder profile proof");
  const proof = {
    a: g1(rawProof.a, "proof.a"),
    b: g2(rawProof.b, "proof.b"),
    c: g1(rawProof.c, "proof.c"),
  };
  return {
    schema: ZK_HOLDER_PROFILE_BROWSER_REPORT_SCHEMA,
    profileId: ZK_HOLDER_PROFILE_ID,
    warning: ZK_HOLDER_PROFILE_SYNTHETIC_WARNING,
    constraints: ZK_HOLDER_PROFILE_BROWSER_CONSTRAINTS,
    witnessVariables: ZK_HOLDER_PROFILE_BROWSER_WITNESS_VARIABLES,
    publicInputCount: 18,
    publicInputs,
    proof,
    proofVerified: true,
  };
}

function g1(value: unknown, label: string): EvmG1 {
  const candidate = object(value, label);
  exactKeys(candidate, ["x", "y"], label);
  return { x: coordinate(candidate.x, `${label}.x`), y: coordinate(candidate.y, `${label}.y`) };
}

function g2(value: unknown, label: string): EvmG2 {
  const candidate = object(value, label);
  exactKeys(candidate, ["x_imaginary", "x_real", "y_imaginary", "y_real"], label);
  return {
    xImaginary: coordinate(candidate.x_imaginary, `${label}.x_imaginary`),
    xReal: coordinate(candidate.x_real, `${label}.x_real`),
    yImaginary: coordinate(candidate.y_imaginary, `${label}.y_imaginary`),
    yReal: coordinate(candidate.y_real, `${label}.y_real`),
  };
}

function coordinate(value: unknown, label: string): bigint {
  const parsed = decimal(value, label);
  if (parsed >= BN254_BASE_FIELD) throw new Error(`${label} exceeds the BN254 base field`);
  return parsed;
}

function decimal(value: unknown, label: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]{0,77})$/u.test(value)) {
    throw new Error(`${label} is not canonical decimal`);
  }
  return BigInt(value);
}

function validateBindings(value: unknown): asserts value is ZkHolderProfileBrowserWasmBindings {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error("holder profile WASM bindings must be an object");
  const candidate = value as Partial<ZkHolderProfileBrowserWasmBindings>;
  if (
    typeof candidate.proveSyntheticHolderProfile !== "function" ||
    typeof candidate.wasmLinearMemoryBytes !== "function" ||
    (candidate.destroy !== undefined && typeof candidate.destroy !== "function")
  ) throw new Error("holder profile WASM bindings are incomplete");
}

function readMemory(bindings: ZkHolderProfileBrowserWasmBindings): number {
  const value = bindings.wasmLinearMemoryBytes();
  if (!Number.isSafeInteger(value) || value < 0 || value > ZK_HOLDER_PROFILE_MAX_MEMORY_BYTES) {
    throw new Error("holder profile WASM memory is outside the supported range");
  }
  return value;
}

function browserWorkerUrl(value: unknown): URL {
  if (!(value instanceof URL)) throw new Error("holder profile Worker URL must be absolute");
  if (value.protocol !== "https:" && value.protocol !== "http:") throw new Error("holder profile Worker URL must use HTTP or HTTPS");
  if (value.username || value.password || value.hash) throw new Error("holder profile Worker URL must not contain credentials or a fragment");
  const location = (globalThis as { location?: Location }).location;
  if (location && value.origin !== location.origin) throw new Error("holder profile Worker URL must be same-origin");
  return new URL(value.href);
}

function strictJson(value: string): unknown {
  if (value.length < 2 || value.length > 64 * 1024) throw new Error("holder profile report size is invalid");
  try { return JSON.parse(value); } catch { throw new Error("holder profile report is not valid JSON"); }
}
function abortIfRequested(signal: AbortSignal): void { if (signal.aborted) throw new Error("holder profile proving was cancelled"); }
function sameSignals(left: readonly bigint[], right: readonly bigint[]): boolean { return left.length === right.length && left.every((entry, index) => entry === right[index]); }
function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function exactKeys(candidate: Record<string, unknown>, keys: readonly string[], label: string): void {
  const expected = [...keys].sort();
  const actual = Object.keys(candidate).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} fields are invalid`);
}

// Keep these profile selectors close to the adapter so tree-shaking cannot
// silently substitute the old research circuit.
void ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID;
