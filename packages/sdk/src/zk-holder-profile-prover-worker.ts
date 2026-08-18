/**
 * Profile-specific holder proving boundary for a disposable browser Worker.
 *
 * The host transfers only authenticated ciphertext, a one-use PRF result,
 * content-addressed public artifacts and the frozen public inputs. Vault
 * plaintext is created, parsed and consumed inside the Worker. Production mode
 * additionally requires a production-approved profile manifest and the exact
 * admission record emitted for it. The checked-in executable is deliberately
 * synthetic until ceremony artifacts and a production vault envelope exist.
 */
import { concatHex, encodeFunctionData, isHex, parseAbi, size, toHex, type Hex } from "viem";
import {
  parseCredentialVault,
  unlockCredentialVault,
  type PortableCredentialVault,
} from "./credential-vault";
import {
  decodeZkIdentityPublicSignals,
  serializeZkIdentityPublicSignals,
  ZK_PUBLIC_SIGNAL_COUNT,
} from "./zk-identity-encoding";
import {
  parseZkProductionProfileManifest,
  ZK_PRODUCTION_PROFILE_ADMISSION_SCHEMA,
  type ZkProductionProfileAdmission,
  type ZkProductionProfileManifest,
} from "./zk-production-profile";

export const ZK_HOLDER_PROFILE_ID =
  "org.proofofhumanity.v2-crypto.groth16-bn254-poseidon/1" as const;
export const ZK_HOLDER_PROFILE_SANCTIONS_CIRCUIT_ID =
  "0xe04e432671953a25e6aadbb5e59cfa0ff347108e31aac4a5599cb08f5cce11d2" as const;
export const ZK_HOLDER_PROFILE_WORKER_SCHEMA =
  "org.proofofhumanity.zk-holder-profile-prover-worker/1" as const;
export const ZK_HOLDER_PROFILE_RECEIPT_SCHEMA =
  "org.proofofhumanity.zk-holder-profile-proving-receipt/1" as const;
export const ZK_HOLDER_PROFILE_WORKER_VERSION = 1 as const;
export const ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID =
  "synthetic:production-profile-sanctions-v1" as const;
export const ZK_HOLDER_PROFILE_SYNTHETIC_WARNING =
  "synthetic profile fixture only; public toxic-waste setup is not production-admitted" as const;
export const ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256 =
  "0x451d599ba213d44f2b9e56c139e0c889b150ed9bbe57ee1fa3de7a2d91ee72c7" as const;

export const ZK_HOLDER_PROFILE_MIN_TIMEOUT_MS = 1_000;
export const ZK_HOLDER_PROFILE_MAX_TIMEOUT_MS = 10 * 60 * 1_000;
export const ZK_HOLDER_PROFILE_DEFAULT_TIMEOUT_MS = 2 * 60 * 1_000;
export const ZK_HOLDER_PROFILE_MIN_MEMORY_BYTES = 16 * 1024 * 1024;
export const ZK_HOLDER_PROFILE_MAX_MEMORY_BYTES = 1024 * 1024 * 1024;
export const ZK_HOLDER_PROFILE_DEFAULT_MEMORY_BYTES = 256 * 1024 * 1024;
export const ZK_HOLDER_PROFILE_MAX_ARTIFACT_BYTES = 768 * 1024 * 1024;

const JOB_ID_BYTES = 16;
const PUBLIC_SIGNALS_BYTES = ZK_PUBLIC_SIGNAL_COUNT * 32;
const GROTH16_PROOF_BYTES = 8 * 32;
const ARTIFACT_ROLES = [
  "parameterManifest",
  "circuitSource",
  "constraintSystem",
  "compilerLock",
  "proverArtifact",
  "verifierArtifact",
  "verifierSource",
  "publicSignalManifest",
] as const;
const PHASES = [
  "initializing",
  "verifying-artifacts",
  "unlocking-vault",
  "building-witness",
  "proving",
  "verifying",
] as const;
const REGISTRY_ABI = parseAbi([
  "function registerCircuit(bytes32 circuitId,address verifier)",
  "function authorizeIssuer(bytes32 circuitId,bytes32 issuerKeyId)",
]);
const PREDICATE_VERIFIER_ABI = parseAbi(["function setPredicateProver(address newProver)"]);
const RATED_CIRCUIT_IDS = new Set<Hex>([
  ZK_HOLDER_PROFILE_SANCTIONS_CIRCUIT_ID,
  "0xe372a2a117a999d9de9a071f78281a421aaf5562705b34f0e110c7f33f302305",
  "0xcf17502eca9d6173b12a1d6b8149db11a2b3db5e739b336dfbd122b91b21a3a6",
  "0xf0901f3261d5952d6a48fc33f1b8782a064175c6aa96063fa959b2ec41ef806f",
  "0x2ba3a8d0157db6fcd9a82a825cd527347b7629787483f6ff5a3ec900b0999801",
]);

export type ZkHolderProfileMode = "synthetic" | "production";
export type ZkHolderProfileProvingPhase = (typeof PHASES)[number];
export type ZkHolderProfileArtifactRole = (typeof ARTIFACT_ROLES)[number] | "wasmModule";
export type ZkHolderProfileFailureCode =
  | "artifact-hash-mismatch"
  | "cancelled"
  | "deadline-exceeded"
  | "invalid-request"
  | "profile-not-admitted"
  | "proof-verification-failed"
  | "proving-failed"
  | "protocol-error"
  | "resource-limit"
  | "vault-unlock-failed"
  | "worker-failed";

export interface ZkHolderProfileArtifact {
  role: ZkHolderProfileArtifactRole;
  sha256: Hex;
  bytes: Uint8Array;
}

export interface ZkHolderProfileSyntheticSelection {
  mode: "synthetic";
  profileId: typeof ZK_HOLDER_PROFILE_ID;
  fixtureId: typeof ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID;
}

export interface ZkHolderProfileProductionSelection {
  mode: "production";
  profileId: typeof ZK_HOLDER_PROFILE_ID;
  manifest: unknown;
  admission: unknown;
}

export type ZkHolderProfileSelection =
  | ZkHolderProfileSyntheticSelection
  | ZkHolderProfileProductionSelection;

export interface ZkHolderProfileProvingProgress {
  phase: ZkHolderProfileProvingPhase;
  percent: number;
  memoryBytes: number;
}

export interface ZkHolderProfileProvingRequest {
  profile: ZkHolderProfileSelection;
  artifacts: readonly ZkHolderProfileArtifact[];
  vault: PortableCredentialVault;
  unlock: { credentialId: string; prfOutput: Uint8Array };
  expectedPublicSignals: readonly bigint[];
  timeoutMs?: number;
  maxMemoryBytes?: number;
  signal?: AbortSignal;
  onProgress?: (progress: ZkHolderProfileProvingProgress) => void;
}

export interface ZkHolderProfileArtifactDigest {
  role: ZkHolderProfileArtifactRole;
  sha256: Hex;
}

export interface ZkHolderProfileProvingReceipt {
  schema: typeof ZK_HOLDER_PROFILE_RECEIPT_SCHEMA;
  version: typeof ZK_HOLDER_PROFILE_WORKER_VERSION;
  profileId: typeof ZK_HOLDER_PROFILE_ID;
  mode: ZkHolderProfileMode;
  manifestHash: Hex | null;
  circuitId: Hex;
  fixtureId: typeof ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID | null;
  warning: typeof ZK_HOLDER_PROFILE_SYNTHETIC_WARNING | null;
  presentationReady: boolean;
  artifactDigests: readonly ZkHolderProfileArtifactDigest[];
  proofEncoding: "groth16-bn254-eip197-uint256[8]";
  proof: Hex;
  publicSignals: Hex;
  locallyVerified: true;
  peakMemoryBytes: number;
}

export class ZkHolderProfileProverError extends Error {
  readonly code: ZkHolderProfileFailureCode;

  constructor(code: ZkHolderProfileFailureCode) {
    super(`holder profile prover ${code}`);
    this.name = "ZkHolderProfileProverError";
    this.code = code;
  }
}

export interface ZkHolderProfileWorkerLike {
  postMessage(message: unknown, transfer?: readonly Transferable[]): void;
  terminate(): void;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: ((event: { message?: string }) => void) | null;
}

export interface ZkHolderProfileWorkerScopeLike {
  postMessage(message: unknown): void;
  onmessage: ((event: { data: unknown }) => void) | null;
}

export interface ZkHolderProfileEngineContext {
  mode: ZkHolderProfileMode;
  manifest: ZkProductionProfileManifest | null;
  admission: ZkProductionProfileAdmission | null;
  circuitId: Hex;
}

export interface ZkHolderProfileEngineInput {
  context: ZkHolderProfileEngineContext;
  artifacts: ReadonlyMap<ZkHolderProfileArtifactRole, Uint8Array>;
  vaultPayload: unknown;
  expectedPublicSignals: readonly bigint[];
  signal: AbortSignal;
  reportProgress(progress: ZkHolderProfileProvingProgress): void;
}

/** Implementations run only inside the Worker and own plaintext parsing. */
export interface ZkHolderProfileProvingEngine {
  /** Worker-bundled/local admission allowlist; host-provided records are never sufficient alone. */
  admitsProductionProfile(context: ZkHolderProfileEngineContext): Promise<boolean> | boolean;
  acceptsVaultBinding(mode: ZkHolderProfileMode, schema: string): boolean;
  parseVaultPayload(mode: ZkHolderProfileMode, value: unknown): unknown;
  prove(input: ZkHolderProfileEngineInput): Promise<unknown> | unknown;
  destroy?(): void;
}

interface StartCommand {
  schema: typeof ZK_HOLDER_PROFILE_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_PROFILE_WORKER_VERSION;
  kind: "start";
  jobId: string;
  profile: ZkHolderProfileSelection;
  artifacts: ZkHolderProfileArtifact[];
  vault: PortableCredentialVault;
  unlock: { credentialId: string; prfOutput: Uint8Array };
  expectedPublicSignals: Hex;
  deadlineAtMs: number;
  maxMemoryBytes: number;
}

interface CancelCommand {
  schema: typeof ZK_HOLDER_PROFILE_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_PROFILE_WORKER_VERSION;
  kind: "cancel";
  jobId: string;
}

export type ZkHolderProfileCommand = StartCommand | CancelCommand;

interface ProgressEvent extends ZkHolderProfileProvingProgress {
  schema: typeof ZK_HOLDER_PROFILE_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_PROFILE_WORKER_VERSION;
  kind: "progress";
  jobId: string;
}

interface CompleteEvent {
  schema: typeof ZK_HOLDER_PROFILE_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_PROFILE_WORKER_VERSION;
  kind: "complete";
  jobId: string;
  receipt: ZkHolderProfileProvingReceipt;
}

interface FailedEvent {
  schema: typeof ZK_HOLDER_PROFILE_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_PROFILE_WORKER_VERSION;
  kind: "failed";
  jobId: string;
  code: Exclude<ZkHolderProfileFailureCode, "protocol-error" | "worker-failed">;
}

export type ZkHolderProfileEvent = ProgressEvent | CompleteEvent | FailedEvent;

export class ZkHolderProfileProverClient {
  readonly #createWorker: () => ZkHolderProfileWorkerLike;

  constructor(createWorker: () => ZkHolderProfileWorkerLike) {
    if (typeof createWorker !== "function") throw new Error("a holder profile Worker factory is required");
    this.#createWorker = createWorker;
  }

  prove(request: ZkHolderProfileProvingRequest): Promise<ZkHolderProfileProvingReceipt> {
    const parsed = parseHostRequest(request);
    if (request.signal?.aborted) return Promise.reject(new ZkHolderProfileProverError("cancelled"));
    let worker: ZkHolderProfileWorkerLike;
    try {
      worker = this.#createWorker();
    } catch {
      return Promise.reject(new ZkHolderProfileProverError("worker-failed"));
    }
    if (!worker || typeof worker.postMessage !== "function" || typeof worker.terminate !== "function") {
      throw new Error("holder profile Worker factory returned an invalid Worker");
    }
    const jobId = newJobId();
    const command: StartCommand = {
      ...envelope(),
      kind: "start",
      jobId,
      profile: parsed.profile,
      artifacts: parsed.artifacts,
      vault: parsed.vault,
      unlock: parsed.unlock,
      expectedPublicSignals: parsed.expectedPublicSignals,
      deadlineAtMs: checkedDeadline(parsed.timeoutMs),
      maxMemoryBytes: parsed.maxMemoryBytes,
    };
    const transfer = [
      parsed.unlock.prfOutput.buffer,
      ...parsed.artifacts.map(({ bytes }) => bytes.buffer),
    ] as Transferable[];

    return new Promise((resolve, reject) => {
      let settled = false;
      let lastPhase = -1;
      let lastPercent = -1;
      let peakMemoryBytes = 0;
      const finish = (
        result: { receipt: ZkHolderProfileProvingReceipt } | { error: ZkHolderProfileProverError },
      ) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        request.signal?.removeEventListener("abort", abort);
        worker.onmessage = null;
        worker.onerror = null;
        worker.terminate();
        if ("receipt" in result) resolve(result.receipt);
        else reject(result.error);
      };
      const stop = (code: ZkHolderProfileFailureCode) => {
        try {
          worker.postMessage({ ...envelope(), kind: "cancel", jobId } satisfies CancelCommand);
        } catch {
          // Worker termination below is authoritative.
        }
        finish({ error: new ZkHolderProfileProverError(code) });
      };
      const abort = () => stop("cancelled");
      const timer = setTimeout(() => stop("deadline-exceeded"), parsed.timeoutMs);

      worker.onmessage = ({ data }) => {
        if (settled) return;
        let event: ZkHolderProfileEvent;
        try {
          event = parseZkHolderProfileEvent(data);
        } catch {
          stop("protocol-error");
          return;
        }
        if (event.jobId !== jobId) return;
        if (event.kind === "progress") {
          const phase = phaseIndex(event.phase);
          if (phase < lastPhase || event.percent < lastPercent || event.memoryBytes > parsed.maxMemoryBytes) {
            stop(event.memoryBytes > parsed.maxMemoryBytes ? "resource-limit" : "protocol-error");
            return;
          }
          lastPhase = phase;
          lastPercent = event.percent;
          peakMemoryBytes = Math.max(peakMemoryBytes, event.memoryBytes);
          try {
            request.onProgress?.({ phase: event.phase, percent: event.percent, memoryBytes: event.memoryBytes });
          } catch {
            stop("protocol-error");
          }
          return;
        }
        if (event.kind === "failed") {
          finish({ error: new ZkHolderProfileProverError(event.code) });
          return;
        }
        try {
          const receipt = parseZkHolderProfileProvingReceipt(event.receipt);
          if (
            receipt.mode !== parsed.profile.mode ||
            receipt.publicSignals !== parsed.expectedPublicSignals ||
            receipt.peakMemoryBytes < peakMemoryBytes ||
            receipt.peakMemoryBytes > parsed.maxMemoryBytes
          ) throw new Error("profile receipt does not match request");
          finish({ receipt });
        } catch {
          stop("protocol-error");
        }
      };
      worker.onerror = () => finish({ error: new ZkHolderProfileProverError("worker-failed") });
      request.signal?.addEventListener("abort", abort, { once: true });
      if (request.signal?.aborted) return abort();
      try {
        worker.postMessage(command, transfer);
      } catch {
        zeroize(parsed.unlock.prfOutput);
        for (const artifact of parsed.artifacts) zeroize(artifact.bytes);
        finish({ error: new ZkHolderProfileProverError("worker-failed") });
      }
    });
  }
}

export function serveZkHolderProfileProverWorker(
  scope: ZkHolderProfileWorkerScopeLike,
  engine: ZkHolderProfileProvingEngine,
): void {
  if (
    !scope || typeof scope.postMessage !== "function" || !engine ||
    typeof engine.admitsProductionProfile !== "function" ||
    typeof engine.acceptsVaultBinding !== "function" ||
    typeof engine.parseVaultPayload !== "function" || typeof engine.prove !== "function"
  ) throw new Error("a valid holder profile Worker scope and engine are required");
  let started = false;
  let active: { jobId: string; controller: AbortController; failure?: FailedEvent["code"] } | undefined;
  scope.onmessage = ({ data }) => {
    let command: ZkHolderProfileCommand;
    try {
      command = parseZkHolderProfileProverCommand(data);
    } catch {
      const recovered = recoverJobId(data);
      if (recovered) postFailed(scope, recovered, "invalid-request");
      return;
    }
    if (command.kind === "cancel") {
      if (active?.jobId === command.jobId && !active.failure) {
        active.failure = "cancelled";
        active.controller.abort();
      }
      return;
    }
    if (started) return postFailed(scope, command.jobId, "invalid-request");
    started = true;
    void executeJob(scope, engine, command, (value) => (active = value));
  };
}

async function executeJob(
  scope: ZkHolderProfileWorkerScopeLike,
  engine: ZkHolderProfileProvingEngine,
  command: StartCommand,
  setActive: (value: { jobId: string; controller: AbortController; failure?: FailedEvent["code"] } | undefined) => void,
): Promise<void> {
  const controller = new AbortController();
  const state: { jobId: string; controller: AbortController; failure?: FailedEvent["code"] } = {
    jobId: command.jobId,
    controller,
  };
  setActive(state);
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;
  let lastPhase = -1;
  let lastPercent = -1;
  let peakMemoryBytes = 0;
  try {
    const remaining = command.deadlineAtMs - Date.now();
    if (remaining < 1 || remaining > ZK_HOLDER_PROFILE_MAX_TIMEOUT_MS) throw failure("deadline-exceeded");
    deadlineTimer = setTimeout(() => {
      state.failure = "deadline-exceeded";
      controller.abort();
    }, remaining);
    const reportProgress = (raw: ZkHolderProfileProvingProgress) => {
      if (state.failure) throw failure(state.failure);
      const progress = parseProgress(raw);
      const nextPhase = phaseIndex(progress.phase);
      if (nextPhase < lastPhase || progress.percent < lastPercent) throw failure("proving-failed");
      if (progress.memoryBytes > command.maxMemoryBytes) {
        state.failure = "resource-limit";
        controller.abort();
        throw failure("resource-limit");
      }
      lastPhase = nextPhase;
      lastPercent = progress.percent;
      peakMemoryBytes = Math.max(peakMemoryBytes, progress.memoryBytes);
      scope.postMessage({ ...envelope(), kind: "progress", jobId: command.jobId, ...progress } satisfies ProgressEvent);
    };

    reportProgress({ phase: "initializing", percent: 0, memoryBytes: 0 });
    const publicSignals = deserializePublicSignals(command.expectedPublicSignals);
    const context = parseProfileContext(command.profile, publicSignals);
    if (context.mode === "production" && !(await engine.admitsProductionProfile(context))) {
      throw failure("profile-not-admitted");
    }
    reportProgress({ phase: "verifying-artifacts", percent: 5, memoryBytes: 0 });
    const verified = await verifyArtifacts(context, command.artifacts);
    reportProgress({ phase: "verifying-artifacts", percent: 20, memoryBytes: 0 });

    const vault = parseCredentialVault(command.vault);
    if (!engine.acceptsVaultBinding(context.mode, vault.binding.schema)) throw failure("vault-unlock-failed");
    reportProgress({ phase: "unlocking-vault", percent: 25, memoryBytes: 0 });
    let rawPayload: unknown;
    try {
      rawPayload = await unlockCredentialVault(vault, command.unlock);
    } catch {
      throw failure("vault-unlock-failed");
    } finally {
      zeroize(command.unlock.prfOutput);
    }
    let vaultPayload: unknown;
    try {
      vaultPayload = engine.parseVaultPayload(context.mode, rawPayload);
    } catch {
      throw failure("vault-unlock-failed");
    } finally {
      rawPayload = undefined;
    }
    reportProgress({ phase: "building-witness", percent: 35, memoryBytes: 0 });
    const rawResult = await engine.prove({
      context,
      artifacts: verified.bytes,
      vaultPayload,
      expectedPublicSignals: publicSignals,
      signal: controller.signal,
      reportProgress,
    });
    vaultPayload = undefined;
    if (state.failure) throw failure(state.failure);
    const result = parseEngineResult(rawResult);
    const serializedSignals = serializeZkIdentityPublicSignals(result.publicSignals);
    if (!result.locallyVerified || serializedSignals !== command.expectedPublicSignals) {
      throw failure("proof-verification-failed");
    }
    const decoded = decodeZkIdentityPublicSignals(result.publicSignals);
    if (decoded.circuitId !== context.circuitId) throw failure("proof-verification-failed");
    if (context.manifest && !context.manifest.issuerKeyIds.includes(decoded.issuerKeyId)) {
      throw failure("proof-verification-failed");
    }
    if (result.retainedMemoryBytes > command.maxMemoryBytes) throw failure("resource-limit");
    peakMemoryBytes = Math.max(peakMemoryBytes, result.retainedMemoryBytes);
    const receipt = parseZkHolderProfileProvingReceipt({
      schema: ZK_HOLDER_PROFILE_RECEIPT_SCHEMA,
      version: ZK_HOLDER_PROFILE_WORKER_VERSION,
      profileId: ZK_HOLDER_PROFILE_ID,
      mode: context.mode,
      manifestHash: context.manifest?.manifestHash ?? null,
      circuitId: context.circuitId,
      fixtureId: context.mode === "synthetic" ? ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID : null,
      warning: context.mode === "synthetic" ? ZK_HOLDER_PROFILE_SYNTHETIC_WARNING : null,
      presentationReady: context.mode === "production",
      artifactDigests: verified.digests,
      proofEncoding: "groth16-bn254-eip197-uint256[8]",
      proof: result.proof,
      publicSignals: serializedSignals,
      locallyVerified: true,
      peakMemoryBytes,
    });
    scope.postMessage({ ...envelope(), kind: "complete", jobId: command.jobId, receipt } satisfies CompleteEvent);
  } catch (error) {
    postFailed(scope, command.jobId, state.failure ?? failureCode(error) ?? "proving-failed");
  } finally {
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
    controller.abort();
    zeroize(command.unlock.prfOutput);
    for (const artifact of command.artifacts) zeroize(artifact.bytes);
    try { engine.destroy?.(); } catch { /* Worker termination remains authoritative. */ }
    setActive(undefined);
  }
}

export function parseZkHolderProfileProverCommand(value: unknown): ZkHolderProfileCommand {
  const candidate = object(value, "holder profile command");
  protocolHeader(candidate);
  if (candidate.kind === "cancel") {
    exactKeys(candidate, ["schema", "version", "kind", "jobId"], "cancel command");
    return { ...envelope(), kind: "cancel", jobId: jobId(candidate.jobId) };
  }
  if (candidate.kind !== "start") throw new Error("unsupported holder profile command");
  exactKeys(candidate, [
    "schema", "version", "kind", "jobId", "profile", "artifacts", "vault", "unlock",
    "expectedPublicSignals", "deadlineAtMs", "maxMemoryBytes",
  ], "start command");
  const signals = publicSignalsHex(candidate.expectedPublicSignals);
  deserializePublicSignals(signals);
  const unlock = parseUnlock(candidate.unlock);
  return {
    ...envelope(),
    kind: "start",
    jobId: jobId(candidate.jobId),
    profile: parseSelection(candidate.profile),
    artifacts: parseArtifacts(candidate.artifacts, false),
    vault: parseCredentialVault(candidate.vault),
    unlock,
    expectedPublicSignals: signals,
    deadlineAtMs: integer(candidate.deadlineAtMs, "worker deadline", 1, Number.MAX_SAFE_INTEGER),
    maxMemoryBytes: memoryLimit(candidate.maxMemoryBytes),
  };
}

export function parseZkHolderProfileEvent(value: unknown): ZkHolderProfileEvent {
  const candidate = object(value, "holder profile event");
  protocolHeader(candidate);
  if (candidate.kind === "progress") {
    exactKeys(candidate, ["schema", "version", "kind", "jobId", "phase", "percent", "memoryBytes"], "progress event");
    return { ...envelope(), kind: "progress", jobId: jobId(candidate.jobId), ...parseProgress(candidate) };
  }
  if (candidate.kind === "complete") {
    exactKeys(candidate, ["schema", "version", "kind", "jobId", "receipt"], "complete event");
    return { ...envelope(), kind: "complete", jobId: jobId(candidate.jobId), receipt: parseZkHolderProfileProvingReceipt(candidate.receipt) };
  }
  if (candidate.kind === "failed") {
    exactKeys(candidate, ["schema", "version", "kind", "jobId", "code"], "failed event");
    return { ...envelope(), kind: "failed", jobId: jobId(candidate.jobId), code: postedFailureCode(candidate.code) };
  }
  throw new Error("unsupported holder profile event");
}

export function parseZkHolderProfileProvingReceipt(value: unknown): ZkHolderProfileProvingReceipt {
  const candidate = object(value, "holder profile receipt");
  exactKeys(candidate, [
    "schema", "version", "profileId", "mode", "manifestHash", "circuitId", "fixtureId", "warning",
    "presentationReady", "artifactDigests", "proofEncoding", "proof", "publicSignals", "locallyVerified",
    "peakMemoryBytes",
  ], "holder profile receipt");
  if (
    candidate.schema !== ZK_HOLDER_PROFILE_RECEIPT_SCHEMA ||
    candidate.version !== ZK_HOLDER_PROFILE_WORKER_VERSION ||
    candidate.profileId !== ZK_HOLDER_PROFILE_ID ||
    (candidate.mode !== "synthetic" && candidate.mode !== "production") ||
    candidate.proofEncoding !== "groth16-bn254-eip197-uint256[8]" ||
    candidate.locallyVerified !== true
  ) throw new Error("unsupported holder profile receipt");
  const mode = candidate.mode;
  if (mode === "synthetic") {
    if (
      candidate.manifestHash !== null || candidate.fixtureId !== ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID ||
      candidate.warning !== ZK_HOLDER_PROFILE_SYNTHETIC_WARNING || candidate.presentationReady !== false
    ) throw new Error("synthetic profile receipt was relabeled");
  } else if (
    candidate.fixtureId !== null || candidate.warning !== null || candidate.presentationReady !== true
  ) throw new Error("production profile receipt is not admission-bound");
  const manifestHash = candidate.manifestHash === null ? null : bytes32(candidate.manifestHash, "manifest hash");
  if (mode === "production" && manifestHash === null) throw new Error("production receipt requires a manifest hash");
  const publicSignals = publicSignalsHex(candidate.publicSignals);
  const decoded = decodeZkIdentityPublicSignals(deserializePublicSignals(publicSignals));
  const circuitId = bytes32(candidate.circuitId, "receipt circuit id");
  if (decoded.circuitId !== circuitId) throw new Error("receipt circuit id does not match public signals");
  const proof = fixedHex(candidate.proof, GROTH16_PROOF_BYTES, "Groth16 proof");
  if (!Array.isArray(candidate.artifactDigests)) throw new Error("artifact digests must be an array");
  const artifactDigests = candidate.artifactDigests.map(parseArtifactDigest);
  if (new Set(artifactDigests.map(({ role }) => role)).size !== artifactDigests.length) {
    throw new Error("artifact digest roles must be unique");
  }
  return {
    schema: ZK_HOLDER_PROFILE_RECEIPT_SCHEMA,
    version: ZK_HOLDER_PROFILE_WORKER_VERSION,
    profileId: ZK_HOLDER_PROFILE_ID,
    mode,
    manifestHash,
    circuitId,
    fixtureId: mode === "synthetic" ? ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID : null,
    warning: mode === "synthetic" ? ZK_HOLDER_PROFILE_SYNTHETIC_WARNING : null,
    presentationReady: mode === "production",
    artifactDigests,
    proofEncoding: "groth16-bn254-eip197-uint256[8]",
    proof,
    publicSignals,
    locallyVerified: true,
    peakMemoryBytes: integer(candidate.peakMemoryBytes, "peak worker memory", 0, ZK_HOLDER_PROFILE_MAX_MEMORY_BYTES),
  };
}

export function serializeZkHolderGroth16Proof(words: readonly bigint[]): Hex {
  if (words.length !== 8) throw new Error("Groth16 proof requires exactly 8 EIP-197 words");
  return concatHex(words.map((word, index) => {
    if (typeof word !== "bigint" || word < 0n || word >= 1n << 256n) {
      throw new Error(`Groth16 proof word ${index} is not uint256`);
    }
    return toHex(word, { size: 32 });
  }));
}

function parseHostRequest(request: ZkHolderProfileProvingRequest) {
  const candidate = object(request, "holder profile proving request");
  allowedKeys(candidate, ["profile", "artifacts", "vault", "unlock", "expectedPublicSignals", "timeoutMs", "maxMemoryBytes", "signal", "onProgress"], "holder profile proving request");
  if (!Array.isArray(candidate.expectedPublicSignals)) throw new Error("expected public signals must be an array");
  if (candidate.signal !== undefined && !isAbortSignal(candidate.signal)) throw new Error("abort signal is invalid");
  if (candidate.onProgress !== undefined && typeof candidate.onProgress !== "function") throw new Error("progress callback must be a function");
  const unlock = parseUnlock(candidate.unlock, true);
  return {
    profile: structuredClone(parseSelection(candidate.profile)),
    artifacts: parseArtifacts(candidate.artifacts, true),
    vault: structuredClone(parseCredentialVault(candidate.vault)),
    unlock,
    expectedPublicSignals: serializeZkIdentityPublicSignals(candidate.expectedPublicSignals),
    timeoutMs: integer(candidate.timeoutMs ?? ZK_HOLDER_PROFILE_DEFAULT_TIMEOUT_MS, "holder profile timeout", ZK_HOLDER_PROFILE_MIN_TIMEOUT_MS, ZK_HOLDER_PROFILE_MAX_TIMEOUT_MS),
    maxMemoryBytes: memoryLimit(candidate.maxMemoryBytes ?? ZK_HOLDER_PROFILE_DEFAULT_MEMORY_BYTES),
  };
}

function parseSelection(value: unknown): ZkHolderProfileSelection {
  const candidate = object(value, "holder profile selection");
  if (candidate.mode === "synthetic") {
    exactKeys(candidate, ["mode", "profileId", "fixtureId"], "synthetic profile selection");
    if (candidate.profileId !== ZK_HOLDER_PROFILE_ID || candidate.fixtureId !== ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID) {
      throw new Error("unsupported synthetic profile selection");
    }
    return { mode: "synthetic", profileId: ZK_HOLDER_PROFILE_ID, fixtureId: ZK_HOLDER_PROFILE_SYNTHETIC_FIXTURE_ID };
  }
  if (candidate.mode !== "production") throw new Error("unsupported holder profile mode");
  exactKeys(candidate, ["mode", "profileId", "manifest", "admission"], "production profile selection");
  if (candidate.profileId !== ZK_HOLDER_PROFILE_ID) throw new Error("unsupported production profile id");
  return { mode: "production", profileId: ZK_HOLDER_PROFILE_ID, manifest: candidate.manifest, admission: candidate.admission };
}

function parseProfileContext(selection: ZkHolderProfileSelection, signals: readonly bigint[]): ZkHolderProfileEngineContext {
  const decoded = decodeZkIdentityPublicSignals(signals);
  if (selection.mode === "synthetic") {
    if (decoded.circuitId !== ZK_HOLDER_PROFILE_SANCTIONS_CIRCUIT_ID) throw failure("proof-verification-failed");
    return { mode: "synthetic", manifest: null, admission: null, circuitId: decoded.circuitId };
  }
  let manifest: ZkProductionProfileManifest;
  try { manifest = parseZkProductionProfileManifest(selection.manifest); } catch { throw failure("profile-not-admitted"); }
  if (manifest.releaseStatus !== "production-approved" || !RATED_CIRCUIT_IDS.has(manifest.circuit.circuitId)) {
    throw failure("profile-not-admitted");
  }
  if (
    manifest.circuit.publicSignalLayoutVersion !== 1 || manifest.circuit.publicSignalCount !== 18 ||
    manifest.circuit.proofSystem !== "groth16-bn254-circuit-specific-mpc/1" ||
    manifest.circuit.commitmentScheme !== "poseidon-bn254-arkworks-0.5-x5-rate2/1" ||
    manifest.circuit.issuerAuthenticationScheme !== "schnorr-babyjubjub-poseidon-sha512-nonce/1" ||
    manifest.circuit.statusTreeScheme !== "poseidon-bn254-packed-status-depth24/1"
  ) throw failure("profile-not-admitted");
  const admission = parseAdmission(selection.admission, manifest);
  if (decoded.circuitId !== manifest.circuit.circuitId) throw failure("proof-verification-failed");
  return { mode: "production", manifest, admission, circuitId: manifest.circuit.circuitId };
}

async function verifyArtifacts(context: ZkHolderProfileEngineContext, artifacts: ZkHolderProfileArtifact[]) {
  const expected = new Map<ZkHolderProfileArtifactRole, Hex>();
  if (context.mode === "synthetic") expected.set("wasmModule", ZK_HOLDER_PROFILE_SYNTHETIC_WASM_SHA256);
  else {
    for (const role of ARTIFACT_ROLES) expected.set(role, context.manifest!.artifacts[role].sha256);
  }
  if (artifacts.length !== expected.size) throw failure("artifact-hash-mismatch");
  const bytes = new Map<ZkHolderProfileArtifactRole, Uint8Array>();
  const digests: ZkHolderProfileArtifactDigest[] = [];
  for (const artifact of artifacts) {
    const pinned = expected.get(artifact.role);
    if (!pinned || pinned !== artifact.sha256 || bytes.has(artifact.role)) throw failure("artifact-hash-mismatch");
    const actual = await sha256(artifact.bytes);
    if (actual !== pinned) throw failure("artifact-hash-mismatch");
    bytes.set(artifact.role, artifact.bytes);
    digests.push({ role: artifact.role, sha256: pinned });
  }
  digests.sort((left, right) => left.role.localeCompare(right.role));
  return { bytes, digests };
}

function parseAdmission(value: unknown, manifest: ZkProductionProfileManifest): ZkProductionProfileAdmission {
  const candidate = object(value, "production profile admission");
  exactKeys(candidate, ["schema", "manifestHash", "network", "chainId", "observedAtBlock", "governance", "circuitId", "verifierCodehash", "registrationCalls", "proofPathActivation"], "production profile admission");
  if (
    candidate.schema !== ZK_PRODUCTION_PROFILE_ADMISSION_SCHEMA ||
    bytes32(candidate.manifestHash, "admission manifest hash") !== manifest.manifestHash ||
    bytes32(candidate.circuitId, "admission circuit id") !== manifest.circuit.circuitId
  ) throw failure("profile-not-admitted");
  const chainId = integer(candidate.chainId, "admission chain id", 1, Number.MAX_SAFE_INTEGER);
  const target = manifest.targets.find((entry) => entry.chainId === chainId);
  if (
    !target || candidate.network !== target.network || candidate.governance !== target.governance ||
    candidate.verifierCodehash !== target.rawVerifierCodehash ||
    typeof candidate.observedAtBlock !== "string" || !/^[1-9][0-9]*$/u.test(candidate.observedAtBlock)
  ) throw failure("profile-not-admitted");
  if (!Array.isArray(candidate.registrationCalls) || candidate.registrationCalls.length !== manifest.issuerKeyIds.length + 1) {
    throw failure("profile-not-admitted");
  }
  const expectedCalls: Array<{ to: string; data: Hex; operation: string }> = [
    {
      to: target.versionRegistry,
      data: encodeFunctionData({
        abi: REGISTRY_ABI,
        functionName: "registerCircuit",
        args: [manifest.circuit.circuitId, target.rawVerifier],
      }),
      operation: "register-circuit",
    },
    ...manifest.issuerKeyIds.map((issuerKeyId) => ({
      to: target.versionRegistry,
      data: encodeFunctionData({
        abi: REGISTRY_ABI,
        functionName: "authorizeIssuer",
        args: [manifest.circuit.circuitId, issuerKeyId],
      }),
      operation: "authorize-issuer",
    })),
  ];
  for (const [index, rawCall] of candidate.registrationCalls.entries()) {
    const call = object(rawCall, `registration call ${index}`);
    exactKeys(call, ["to", "data", "operation"], `registration call ${index}`);
    const expected = expectedCalls[index]!;
    if (call.to !== expected.to || call.data !== expected.data || call.operation !== expected.operation) {
      throw failure("profile-not-admitted");
    }
  }
  const activation = object(candidate.proofPathActivation, "proof path activation");
  exactKeys(activation, ["to", "data", "operation", "executeOnlyAfterStatusAdmission"], "proof path activation");
  if (
    activation.to !== target.predicateVerifier || activation.operation !== "set-predicate-prover" ||
    activation.executeOnlyAfterStatusAdmission !== true ||
    activation.data !== encodeFunctionData({
      abi: PREDICATE_VERIFIER_ABI,
      functionName: "setPredicateProver",
      args: [target.predicateProver],
    })
  ) throw failure("profile-not-admitted");
  return value as ZkProductionProfileAdmission;
}

function parseArtifacts(value: unknown, clone: boolean): ZkHolderProfileArtifact[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > ARTIFACT_ROLES.length) throw new Error("artifact bundle size is invalid");
  let total = 0;
  const roles = new Set<string>();
  return value.map((raw, index) => {
    const candidate = object(raw, `artifact ${index}`);
    exactKeys(candidate, ["role", "sha256", "bytes"], `artifact ${index}`);
    const role = artifactRole(candidate.role);
    if (roles.has(role)) throw new Error("artifact roles must be unique");
    roles.add(role);
    if (!(candidate.bytes instanceof Uint8Array) || candidate.bytes.byteLength === 0) throw new Error("artifact bytes are required");
    if (!clone && (!(candidate.bytes.buffer instanceof ArrayBuffer) || candidate.bytes.byteOffset !== 0 || candidate.bytes.byteLength !== candidate.bytes.buffer.byteLength)) {
      throw new Error("Worker artifact bytes must own a transferable ArrayBuffer");
    }
    total += candidate.bytes.byteLength;
    if (total > ZK_HOLDER_PROFILE_MAX_ARTIFACT_BYTES) throw new Error("artifact bundle exceeds the worker limit");
    return { role, sha256: bytes32(candidate.sha256, `artifact ${role} SHA-256`), bytes: clone ? new Uint8Array(candidate.bytes) : candidate.bytes };
  });
}

function parseUnlock(value: unknown, clone = false) {
  const candidate = object(value, "vault unlock");
  exactKeys(candidate, ["credentialId", "prfOutput"], "vault unlock");
  if (typeof candidate.credentialId !== "string" || candidate.credentialId.length === 0 || candidate.credentialId.length > 2048) throw new Error("vault unlock credential id is invalid");
  if (!(candidate.prfOutput instanceof Uint8Array) || candidate.prfOutput.byteLength !== 32) throw new Error("vault unlock PRF output must be 32 bytes");
  if (!clone && (!(candidate.prfOutput.buffer instanceof ArrayBuffer) || candidate.prfOutput.byteOffset !== 0 || candidate.prfOutput.byteLength !== candidate.prfOutput.buffer.byteLength)) {
    throw new Error("Worker PRF output must own a transferable ArrayBuffer");
  }
  return { credentialId: candidate.credentialId, prfOutput: clone ? new Uint8Array(candidate.prfOutput) : candidate.prfOutput };
}

function parseEngineResult(value: unknown) {
  const candidate = object(value, "holder profile engine result");
  exactKeys(candidate, ["proof", "publicSignals", "locallyVerified", "retainedMemoryBytes"], "holder profile engine result");
  if (!Array.isArray(candidate.publicSignals)) throw new Error("engine public signals must be an array");
  decodeZkIdentityPublicSignals(candidate.publicSignals);
  if (typeof candidate.locallyVerified !== "boolean") throw new Error("local verification result must be Boolean");
  return {
    proof: fixedHex(candidate.proof, GROTH16_PROOF_BYTES, "Groth16 proof"),
    publicSignals: candidate.publicSignals,
    locallyVerified: candidate.locallyVerified,
    retainedMemoryBytes: integer(candidate.retainedMemoryBytes, "retained worker memory", 0, ZK_HOLDER_PROFILE_MAX_MEMORY_BYTES),
  };
}

function parseArtifactDigest(value: unknown): ZkHolderProfileArtifactDigest {
  const candidate = object(value, "artifact digest");
  exactKeys(candidate, ["role", "sha256"], "artifact digest");
  return { role: artifactRole(candidate.role), sha256: bytes32(candidate.sha256, "artifact digest") };
}

function parseProgress(value: unknown): ZkHolderProfileProvingProgress {
  const candidate = object(value, "holder profile progress");
  return {
    phase: progressPhase(candidate.phase),
    percent: integer(candidate.percent, "worker progress percent", 0, 99),
    memoryBytes: integer(candidate.memoryBytes, "worker progress memory", 0, ZK_HOLDER_PROFILE_MAX_MEMORY_BYTES),
  };
}

function deserializePublicSignals(value: Hex): readonly bigint[] {
  const body = value.slice(2);
  const signals = Array.from({ length: ZK_PUBLIC_SIGNAL_COUNT }, (_, index) => BigInt(`0x${body.slice(index * 64, (index + 1) * 64)}`));
  decodeZkIdentityPublicSignals(signals);
  return signals;
}

async function sha256(bytes: Uint8Array): Promise<Hex> {
  if (!globalThis.crypto?.subtle) throw failure("artifact-hash-mismatch");
  const input = bytes.buffer instanceof ArrayBuffer && bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? bytes.buffer
    : bytes.slice().buffer;
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input));
  return `0x${Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("")}`;
}

function postFailed(scope: ZkHolderProfileWorkerScopeLike, id: string, code: FailedEvent["code"]): void {
  scope.postMessage({ ...envelope(), kind: "failed", jobId: id, code } satisfies FailedEvent);
}

function envelope() {
  return { schema: ZK_HOLDER_PROFILE_WORKER_SCHEMA, version: ZK_HOLDER_PROFILE_WORKER_VERSION } as const;
}

function protocolHeader(candidate: Record<string, unknown>): void {
  if (candidate.schema !== ZK_HOLDER_PROFILE_WORKER_SCHEMA || candidate.version !== ZK_HOLDER_PROFILE_WORKER_VERSION) throw new Error("unsupported holder profile protocol");
}

class WorkerFailure extends Error { constructor(readonly code: FailedEvent["code"]) { super(code); } }
function failure(code: FailedEvent["code"]): WorkerFailure { return new WorkerFailure(code); }
function failureCode(value: unknown): FailedEvent["code"] | undefined { return value instanceof WorkerFailure ? value.code : undefined; }

function postedFailureCode(value: unknown): FailedEvent["code"] {
  const supported: FailedEvent["code"][] = ["artifact-hash-mismatch", "cancelled", "deadline-exceeded", "invalid-request", "profile-not-admitted", "proof-verification-failed", "proving-failed", "resource-limit", "vault-unlock-failed"];
  if (!supported.includes(value as FailedEvent["code"])) throw new Error("unsupported holder profile failure code");
  return value as FailedEvent["code"];
}

function progressPhase(value: unknown): ZkHolderProfileProvingPhase {
  if (!PHASES.includes(value as ZkHolderProfileProvingPhase)) throw new Error("unsupported holder profile progress phase");
  return value as ZkHolderProfileProvingPhase;
}
function phaseIndex(value: ZkHolderProfileProvingPhase): number { return PHASES.indexOf(value); }
function artifactRole(value: unknown): ZkHolderProfileArtifactRole {
  if (value === "wasmModule" || ARTIFACT_ROLES.includes(value as (typeof ARTIFACT_ROLES)[number])) return value as ZkHolderProfileArtifactRole;
  throw new Error("unsupported holder profile artifact role");
}
function publicSignalsHex(value: unknown): Hex { return fixedHex(value, PUBLIC_SIGNALS_BYTES, "public signals"); }
function fixedHex(value: unknown, bytes: number, label: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== bytes) throw new Error(`${label} must be ${bytes} bytes`);
  return value.toLowerCase() as Hex;
}
function bytes32(value: unknown, label: string): Hex { return fixedHex(value, 32, label); }
function memoryLimit(value: unknown): number { return integer(value, "holder profile memory limit", ZK_HOLDER_PROFILE_MIN_MEMORY_BYTES, ZK_HOLDER_PROFILE_MAX_MEMORY_BYTES); }
function integer(value: unknown, label: string, min: number, max: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < min || (value as number) > max) throw new Error(`${label} is outside the supported range`);
  return value as number;
}
function jobId(value: unknown): string {
  if (typeof value !== "string" || !/^[0-9a-f]{32}$/u.test(value)) throw new Error("worker job id is invalid");
  return value;
}
function newJobId(): string {
  if (!globalThis.crypto?.getRandomValues) throw new Error("Web Crypto is required for holder proving");
  return Array.from(globalThis.crypto.getRandomValues(new Uint8Array(JOB_ID_BYTES)), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
function checkedDeadline(timeoutMs: number): number {
  const deadline = Date.now() + timeoutMs;
  if (!Number.isSafeInteger(deadline)) throw new Error("holder profile deadline is outside the safe range");
  return deadline;
}
function zeroize(bytes: Uint8Array): void { try { bytes.fill(0); } catch { /* A transferred buffer is already detached. */ } }
function recoverJobId(value: unknown): string | undefined {
  try { return jobId(object(value, "command").jobId); } catch { return undefined; }
}
function isAbortSignal(value: unknown): value is AbortSignal { return typeof value === "object" && value !== null && "aborted" in value && typeof (value as AbortSignal).addEventListener === "function"; }
function object(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new Error(`${label} must be an object`);
  return value as Record<string, unknown>;
}
function exactKeys(candidate: Record<string, unknown>, keys: readonly string[], label: string): void {
  const expected = [...keys].sort();
  const actual = Object.keys(candidate).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) throw new Error(`${label} fields are invalid`);
}
function allowedKeys(candidate: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  if (Object.keys(candidate).some((key) => !allowed.has(key))) throw new Error(`${label} fields are invalid`);
}
