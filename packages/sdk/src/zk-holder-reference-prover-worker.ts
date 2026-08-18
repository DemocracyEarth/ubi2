/**
 * Reference-only control plane for running a holder prover in a dedicated Worker.
 *
 * This module deliberately contains no credential witness, proving key, circuit id,
 * proof bytes, or production profile. A worker-private engine may run a synthetic
 * fixture and report whether it verified, but the public receipt can never be
 * presented on chain. ADR-0012 requires a new, ratified profile-specific boundary
 * before live holder credentials or proofs use this control plane.
 */
import { isHex, size, type Hex } from "viem";
import {
  decodeZkIdentityPublicSignals,
  serializeZkIdentityPublicSignals,
  ZK_PUBLIC_SIGNAL_COUNT,
} from "./zk-identity-encoding";
import {
  ZK_HOLDER_REFERENCE_PROFILE_STATUS,
  ZK_HOLDER_REFERENCE_WARNING,
} from "./zk-holder-reference-handoff";

export const ZK_HOLDER_REFERENCE_PROVER_WORKER_SCHEMA =
  "org.proofofhumanity.zk-holder-reference-prover-worker/1" as const;
export const ZK_HOLDER_REFERENCE_PROVING_RECEIPT_SCHEMA =
  "org.proofofhumanity.zk-holder-reference-proving-receipt/1" as const;
export const ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION = 1 as const;

export const ZK_HOLDER_REFERENCE_PROVER_MIN_TIMEOUT_MS = 1_000;
export const ZK_HOLDER_REFERENCE_PROVER_MAX_TIMEOUT_MS = 10 * 60 * 1_000;
export const ZK_HOLDER_REFERENCE_PROVER_MIN_MEMORY_BYTES = 16 * 1024 * 1024;
export const ZK_HOLDER_REFERENCE_PROVER_MAX_MEMORY_BYTES = 1024 * 1024 * 1024;
export const ZK_HOLDER_REFERENCE_PROVER_DEFAULT_TIMEOUT_MS = 2 * 60 * 1_000;
export const ZK_HOLDER_REFERENCE_PROVER_DEFAULT_MEMORY_BYTES = 256 * 1024 * 1024;

const JOB_ID_BYTES = 16;
const PUBLIC_SIGNALS_BYTES = ZK_PUBLIC_SIGNAL_COUNT * 32;
const PROGRESS_PHASES = [
  "initializing",
  "loading-artifacts",
  "building-witness",
  "proving",
  "verifying",
] as const;

export type ZkHolderReferenceProvingPhase = (typeof PROGRESS_PHASES)[number];
export type ZkHolderReferenceProverFailureCode =
  | "cancelled"
  | "deadline-exceeded"
  | "invalid-request"
  | "proving-failed"
  | "protocol-error"
  | "resource-limit"
  | "worker-failed";

export interface ZkHolderReferenceProvingRequest {
  /** `synthetic:` tag selecting a fixture compiled into the worker. Never a credential id. */
  fixtureId: string;
  /** Exact frozen 18-signal V1 bytes the fixture must reproduce. */
  expectedPublicSignals: readonly bigint[];
  /** Hard host deadline. Defaults to two minutes; maximum ten minutes. */
  timeoutMs?: number;
  /** Maximum reported WASM linear memory. Defaults to 256 MiB; maximum 1 GiB. */
  maxMemoryBytes?: number;
  signal?: AbortSignal;
  onProgress?: (progress: ZkHolderReferenceProvingProgress) => void;
}

export interface ZkHolderReferenceProvingProgress {
  phase: ZkHolderReferenceProvingPhase;
  percent: number;
  memoryBytes: number;
}

export interface ZkHolderReferenceProvingReceipt {
  schema: typeof ZK_HOLDER_REFERENCE_PROVING_RECEIPT_SCHEMA;
  version: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION;
  profileStatus: typeof ZK_HOLDER_REFERENCE_PROFILE_STATUS;
  warning: typeof ZK_HOLDER_REFERENCE_WARNING;
  presentationReady: false;
  fixtureId: string;
  publicSignals: Hex;
  proofVerified: true;
  peakMemoryBytes: number;
}

export class ZkHolderReferenceProverError extends Error {
  readonly code: ZkHolderReferenceProverFailureCode;

  constructor(code: ZkHolderReferenceProverFailureCode) {
    super(`holder reference prover ${code}`);
    this.name = "ZkHolderReferenceProverError";
    this.code = code;
  }
}

export interface ZkHolderReferenceWorkerLike {
  postMessage(message: unknown): void;
  terminate(): void;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: ((event: { message?: string }) => void) | null;
}

export interface ZkHolderReferenceWorkerScopeLike {
  postMessage(message: unknown): void;
  onmessage: ((event: { data: unknown }) => void) | null;
}

export interface ZkHolderReferenceProvingEngineInput {
  fixtureId: string;
  expectedPublicSignals: readonly bigint[];
  signal: AbortSignal;
  reportProgress(progress: ZkHolderReferenceProvingProgress): void;
}

/**
 * Profile-neutral worker-private seam. The engine output is revalidated and its
 * proof bytes are intentionally discarded/not represented by this protocol.
 */
export interface ZkHolderReferenceProvingEngine {
  runReference(input: ZkHolderReferenceProvingEngineInput): Promise<unknown> | unknown;
  destroy?(): void;
}

interface StartCommand {
  schema: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION;
  profileStatus: typeof ZK_HOLDER_REFERENCE_PROFILE_STATUS;
  kind: "start";
  jobId: string;
  fixtureId: string;
  expectedPublicSignals: Hex;
  deadlineAtMs: number;
  maxMemoryBytes: number;
}

interface CancelCommand {
  schema: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION;
  profileStatus: typeof ZK_HOLDER_REFERENCE_PROFILE_STATUS;
  kind: "cancel";
  jobId: string;
}

export type ZkHolderReferenceProverCommand = StartCommand | CancelCommand;

interface ProgressEvent {
  schema: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION;
  profileStatus: typeof ZK_HOLDER_REFERENCE_PROFILE_STATUS;
  kind: "progress";
  jobId: string;
  phase: ZkHolderReferenceProvingPhase;
  percent: number;
  memoryBytes: number;
}

interface CompleteEvent {
  schema: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION;
  profileStatus: typeof ZK_HOLDER_REFERENCE_PROFILE_STATUS;
  kind: "complete";
  jobId: string;
  receipt: ZkHolderReferenceProvingReceipt;
}

interface FailedEvent {
  schema: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_SCHEMA;
  version: typeof ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION;
  profileStatus: typeof ZK_HOLDER_REFERENCE_PROFILE_STATUS;
  kind: "failed";
  jobId: string;
  code: Exclude<ZkHolderReferenceProverFailureCode, "protocol-error" | "worker-failed">;
}

export type ZkHolderReferenceProverEvent = ProgressEvent | CompleteEvent | FailedEvent;

/**
 * Host-side one-worker-per-run controller. Abort and deadline always terminate
 * the Worker, which is the only reliable way to stop synchronous WASM proving.
 */
export class ZkHolderReferenceProverClient {
  readonly #createWorker: () => ZkHolderReferenceWorkerLike;

  constructor(createWorker: () => ZkHolderReferenceWorkerLike) {
    if (typeof createWorker !== "function") throw new Error("a holder reference Worker factory is required");
    this.#createWorker = createWorker;
  }

  prove(request: ZkHolderReferenceProvingRequest): Promise<ZkHolderReferenceProvingReceipt> {
    const parsed = parseHostRequest(request);
    if (request.signal?.aborted) {
      return Promise.reject(new ZkHolderReferenceProverError("cancelled"));
    }

    let worker: ZkHolderReferenceWorkerLike;
    try {
      worker = this.#createWorker();
    } catch {
      return Promise.reject(new ZkHolderReferenceProverError("worker-failed"));
    }
    if (!worker || typeof worker.postMessage !== "function" || typeof worker.terminate !== "function") {
      throw new Error("holder reference Worker factory returned an invalid Worker");
    }
    const jobId = newJobId();
    const deadlineAtMs = checkedDeadline(parsed.timeoutMs);
    const command: StartCommand = {
      ...protocolEnvelope(),
      kind: "start",
      jobId,
      fixtureId: parsed.fixtureId,
      expectedPublicSignals: parsed.expectedPublicSignals,
      deadlineAtMs,
      maxMemoryBytes: parsed.maxMemoryBytes,
    };

    return new Promise((resolve, reject) => {
      let settled = false;
      let lastPhase = -1;
      let lastPercent = -1;
      let peakMemoryBytes = 0;

      const finish = (
        result: { receipt: ZkHolderReferenceProvingReceipt } | { error: ZkHolderReferenceProverError },
      ) => {
        if (settled) return;
        settled = true;
        clearTimeout(deadlineTimer);
        request.signal?.removeEventListener("abort", abort);
        worker.onmessage = null;
        worker.onerror = null;
        worker.terminate();
        if ("receipt" in result) resolve(result.receipt);
        else reject(result.error);
      };

      const stop = (code: ZkHolderReferenceProverFailureCode) => {
        try {
          worker.postMessage({ ...protocolEnvelope(), kind: "cancel", jobId } satisfies CancelCommand);
        } catch {
          // Hard termination below is authoritative even if best-effort cancellation cannot be posted.
        }
        finish({ error: new ZkHolderReferenceProverError(code) });
      };
      const abort = () => stop("cancelled");
      const deadlineTimer = setTimeout(() => stop("deadline-exceeded"), parsed.timeoutMs);

      worker.onmessage = ({ data }) => {
        if (settled) return;
        let event: ZkHolderReferenceProverEvent;
        try {
          event = parseZkHolderReferenceProverEvent(data);
        } catch {
          stop("protocol-error");
          return;
        }
        if (event.jobId !== jobId) return;

        if (event.kind === "progress") {
          const phase = phaseIndex(event.phase);
          if (
            phase < lastPhase ||
            event.percent < lastPercent ||
            event.memoryBytes > parsed.maxMemoryBytes
          ) {
            stop(event.memoryBytes > parsed.maxMemoryBytes ? "resource-limit" : "protocol-error");
            return;
          }
          lastPhase = phase;
          lastPercent = event.percent;
          peakMemoryBytes = Math.max(peakMemoryBytes, event.memoryBytes);
          try {
            request.onProgress?.({
              phase: event.phase,
              percent: event.percent,
              memoryBytes: event.memoryBytes,
            });
          } catch {
            stop("protocol-error");
          }
          return;
        }

        if (event.kind === "failed") {
          finish({ error: new ZkHolderReferenceProverError(event.code) });
          return;
        }

        try {
          const receipt = parseZkHolderReferenceProvingReceipt(event.receipt);
          if (
            receipt.fixtureId !== parsed.fixtureId ||
            receipt.publicSignals !== parsed.expectedPublicSignals ||
            receipt.peakMemoryBytes < peakMemoryBytes ||
            receipt.peakMemoryBytes > parsed.maxMemoryBytes
          ) {
            throw new Error("reference proving receipt does not match the requested job");
          }
          finish({ receipt });
        } catch {
          stop("protocol-error");
        }
      };
      worker.onerror = () => finish({ error: new ZkHolderReferenceProverError("worker-failed") });
      request.signal?.addEventListener("abort", abort, { once: true });
      if (request.signal?.aborted) {
        abort();
        return;
      }

      try {
        worker.postMessage(command);
      } catch {
        finish({ error: new ZkHolderReferenceProverError("worker-failed") });
      }
    });
  }
}

/**
 * Install the strict worker-side runtime around a synthetic/reference engine.
 * One runtime accepts exactly one start command; the host terminates it afterward.
 */
export function serveZkHolderReferenceProverWorker(
  scope: ZkHolderReferenceWorkerScopeLike,
  engine: ZkHolderReferenceProvingEngine,
): void {
  if (!scope || typeof scope.postMessage !== "function" || !engine || typeof engine.runReference !== "function") {
    throw new Error("a valid holder reference Worker scope and proving engine are required");
  }
  let started = false;
  let active:
    | { jobId: string; controller: AbortController; failure?: FailedEvent["code"] }
    | undefined;

  scope.onmessage = ({ data }) => {
    let command: ZkHolderReferenceProverCommand;
    try {
      command = parseZkHolderReferenceProverCommand(data);
    } catch {
      const jobId = recoverJobId(data);
      if (jobId) postFailed(scope, jobId, "invalid-request");
      return;
    }

    if (command.kind === "cancel") {
      if (active?.jobId === command.jobId && !active.failure) {
        active.failure = "cancelled";
        active.controller.abort();
      }
      return;
    }
    if (started) {
      postFailed(scope, command.jobId, "invalid-request");
      return;
    }
    started = true;
    void executeWorkerJob(scope, engine, command, (value) => {
      active = value;
    });
  };
}

async function executeWorkerJob(
  scope: ZkHolderReferenceWorkerScopeLike,
  engine: ZkHolderReferenceProvingEngine,
  command: StartCommand,
  setActive: (
    active: { jobId: string; controller: AbortController; failure?: FailedEvent["code"] } | undefined,
  ) => void,
): Promise<void> {
  const controller = new AbortController();
  const state: { jobId: string; controller: AbortController; failure?: FailedEvent["code"] } = {
    jobId: command.jobId,
    controller,
  };
  setActive(state);
  let phase = -1;
  let percent = -1;
  let peakMemoryBytes = 0;
  let deadlineTimer: ReturnType<typeof setTimeout> | undefined;

  try {
    const remainingMs = command.deadlineAtMs - Date.now();
    if (remainingMs < 1 || remainingMs > ZK_HOLDER_REFERENCE_PROVER_MAX_TIMEOUT_MS) {
      throw workerFailure("deadline-exceeded");
    }
    deadlineTimer = setTimeout(() => {
      state.failure = "deadline-exceeded";
      controller.abort();
    }, remainingMs);

    const reportProgress = (value: ZkHolderReferenceProvingProgress) => {
      if (state.failure) throw workerFailure(state.failure);
      const progress = parseProgress(value);
      const nextPhase = phaseIndex(progress.phase);
      if (nextPhase < phase || progress.percent < percent) throw workerFailure("proving-failed");
      if (progress.memoryBytes > command.maxMemoryBytes) {
        state.failure = "resource-limit";
        controller.abort();
        throw workerFailure("resource-limit");
      }
      phase = nextPhase;
      percent = progress.percent;
      peakMemoryBytes = Math.max(peakMemoryBytes, progress.memoryBytes);
      scope.postMessage({
        ...protocolEnvelope(),
        kind: "progress",
        jobId: command.jobId,
        ...progress,
      } satisfies ProgressEvent);
    };

    reportProgress({ phase: "initializing", percent: 0, memoryBytes: 0 });
    const expectedPublicSignals = deserializePublicSignals(command.expectedPublicSignals);
    const rawResult = await engine.runReference({
      fixtureId: command.fixtureId,
      expectedPublicSignals,
      signal: controller.signal,
      reportProgress,
    });
    if (state.failure) throw workerFailure(state.failure);
    const result = parseEngineResult(rawResult);
    const publicSignals = serializeZkIdentityPublicSignals(result.publicSignals);
    if (!result.proofVerified || publicSignals !== command.expectedPublicSignals) {
      throw workerFailure("proving-failed");
    }
    if (result.retainedMemoryBytes > command.maxMemoryBytes) throw workerFailure("resource-limit");
    peakMemoryBytes = Math.max(peakMemoryBytes, result.retainedMemoryBytes);
    const receipt = parseZkHolderReferenceProvingReceipt({
      schema: ZK_HOLDER_REFERENCE_PROVING_RECEIPT_SCHEMA,
      version: ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION,
      profileStatus: ZK_HOLDER_REFERENCE_PROFILE_STATUS,
      warning: ZK_HOLDER_REFERENCE_WARNING,
      presentationReady: false,
      fixtureId: command.fixtureId,
      publicSignals,
      proofVerified: true,
      peakMemoryBytes,
    });
    scope.postMessage({
      ...protocolEnvelope(),
      kind: "complete",
      jobId: command.jobId,
      receipt,
    } satisfies CompleteEvent);
  } catch (error) {
    const code = state.failure ?? workerFailureCode(error) ?? "proving-failed";
    postFailed(scope, command.jobId, code);
  } finally {
    if (deadlineTimer !== undefined) clearTimeout(deadlineTimer);
    controller.abort();
    try {
      engine.destroy?.();
    } catch {
      // Teardown errors are intentionally not reflected after a terminal event.
    }
    setActive(undefined);
  }
}

export function parseZkHolderReferenceProverCommand(value: unknown): ZkHolderReferenceProverCommand {
  const candidate = object(value, "holder reference prover command");
  protocolHeader(candidate);
  if (candidate.kind === "cancel") {
    exactKeys(candidate, ["schema", "version", "profileStatus", "kind", "jobId"], "cancel command");
    return { ...protocolEnvelope(), kind: "cancel", jobId: jobId(candidate.jobId) };
  }
  if (candidate.kind !== "start") throw new Error("unsupported holder reference prover command");
  exactKeys(
    candidate,
    [
      "schema",
      "version",
      "profileStatus",
      "kind",
      "jobId",
      "fixtureId",
      "expectedPublicSignals",
      "deadlineAtMs",
      "maxMemoryBytes",
    ],
    "start command",
  );
  const expectedPublicSignals = publicSignalsHex(candidate.expectedPublicSignals);
  deserializePublicSignals(expectedPublicSignals);
  return {
    ...protocolEnvelope(),
    kind: "start",
    jobId: jobId(candidate.jobId),
    fixtureId: syntheticFixtureId(candidate.fixtureId),
    expectedPublicSignals,
    deadlineAtMs: integer(candidate.deadlineAtMs, "worker deadline", 1, Number.MAX_SAFE_INTEGER),
    maxMemoryBytes: memoryLimit(candidate.maxMemoryBytes),
  };
}

export function parseZkHolderReferenceProverEvent(value: unknown): ZkHolderReferenceProverEvent {
  const candidate = object(value, "holder reference prover event");
  protocolHeader(candidate);
  if (candidate.kind === "progress") {
    exactKeys(
      candidate,
      ["schema", "version", "profileStatus", "kind", "jobId", "phase", "percent", "memoryBytes"],
      "progress event",
    );
    return {
      ...protocolEnvelope(),
      kind: "progress",
      jobId: jobId(candidate.jobId),
      ...parseProgress(candidate),
    };
  }
  if (candidate.kind === "complete") {
    exactKeys(candidate, ["schema", "version", "profileStatus", "kind", "jobId", "receipt"], "complete event");
    return {
      ...protocolEnvelope(),
      kind: "complete",
      jobId: jobId(candidate.jobId),
      receipt: parseZkHolderReferenceProvingReceipt(candidate.receipt),
    };
  }
  if (candidate.kind === "failed") {
    exactKeys(candidate, ["schema", "version", "profileStatus", "kind", "jobId", "code"], "failed event");
    return {
      ...protocolEnvelope(),
      kind: "failed",
      jobId: jobId(candidate.jobId),
      code: workerFailureCodeValue(candidate.code),
    };
  }
  throw new Error("unsupported holder reference prover event");
}

export function parseZkHolderReferenceProvingReceipt(value: unknown): ZkHolderReferenceProvingReceipt {
  const candidate = object(value, "holder reference proving receipt");
  exactKeys(
    candidate,
    [
      "schema",
      "version",
      "profileStatus",
      "warning",
      "presentationReady",
      "fixtureId",
      "publicSignals",
      "proofVerified",
      "peakMemoryBytes",
    ],
    "holder reference proving receipt",
  );
  if (
    candidate.schema !== ZK_HOLDER_REFERENCE_PROVING_RECEIPT_SCHEMA ||
    candidate.version !== ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION ||
    candidate.profileStatus !== ZK_HOLDER_REFERENCE_PROFILE_STATUS ||
    candidate.warning !== ZK_HOLDER_REFERENCE_WARNING ||
    candidate.presentationReady !== false ||
    candidate.proofVerified !== true
  ) {
    throw new Error("unsupported or presentation-enabled holder reference proving receipt");
  }
  const publicSignals = publicSignalsHex(candidate.publicSignals);
  deserializePublicSignals(publicSignals);
  return {
    schema: ZK_HOLDER_REFERENCE_PROVING_RECEIPT_SCHEMA,
    version: ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION,
    profileStatus: ZK_HOLDER_REFERENCE_PROFILE_STATUS,
    warning: ZK_HOLDER_REFERENCE_WARNING,
    presentationReady: false,
    fixtureId: syntheticFixtureId(candidate.fixtureId),
    publicSignals,
    proofVerified: true,
    peakMemoryBytes: integer(
      candidate.peakMemoryBytes,
      "peak worker memory",
      0,
      ZK_HOLDER_REFERENCE_PROVER_MAX_MEMORY_BYTES,
    ),
  };
}

function parseHostRequest(request: ZkHolderReferenceProvingRequest): {
  fixtureId: string;
  expectedPublicSignals: Hex;
  timeoutMs: number;
  maxMemoryBytes: number;
} {
  const candidate = object(request, "holder reference proving request");
  allowedKeys(
    candidate,
    ["fixtureId", "expectedPublicSignals", "timeoutMs", "maxMemoryBytes", "signal", "onProgress"],
    "holder reference proving request",
  );
  if (!Array.isArray(candidate.expectedPublicSignals)) {
    throw new Error("expected public signals must be an array");
  }
  const expectedPublicSignals = serializeZkIdentityPublicSignals(candidate.expectedPublicSignals);
  if (candidate.onProgress !== undefined && typeof candidate.onProgress !== "function") {
    throw new Error("holder reference progress callback must be a function");
  }
  if (candidate.signal !== undefined && !isAbortSignal(candidate.signal)) {
    throw new Error("holder reference abort signal is invalid");
  }
  return {
    fixtureId: syntheticFixtureId(candidate.fixtureId),
    expectedPublicSignals,
    timeoutMs: integer(
      candidate.timeoutMs ?? ZK_HOLDER_REFERENCE_PROVER_DEFAULT_TIMEOUT_MS,
      "holder reference prover timeout",
      ZK_HOLDER_REFERENCE_PROVER_MIN_TIMEOUT_MS,
      ZK_HOLDER_REFERENCE_PROVER_MAX_TIMEOUT_MS,
    ),
    maxMemoryBytes: memoryLimit(candidate.maxMemoryBytes ?? ZK_HOLDER_REFERENCE_PROVER_DEFAULT_MEMORY_BYTES),
  };
}

function parseEngineResult(value: unknown): {
  publicSignals: readonly bigint[];
  proofVerified: boolean;
  retainedMemoryBytes: number;
} {
  const candidate = object(value, "holder reference proving engine result");
  exactKeys(candidate, ["publicSignals", "proofVerified", "retainedMemoryBytes"], "proving engine result");
  if (!Array.isArray(candidate.publicSignals)) throw new Error("engine public signals must be an array");
  decodeZkIdentityPublicSignals(candidate.publicSignals);
  if (typeof candidate.proofVerified !== "boolean") throw new Error("engine verification result must be Boolean");
  return {
    publicSignals: candidate.publicSignals,
    proofVerified: candidate.proofVerified,
    retainedMemoryBytes: integer(
      candidate.retainedMemoryBytes,
      "retained worker memory",
      0,
      ZK_HOLDER_REFERENCE_PROVER_MAX_MEMORY_BYTES,
    ),
  };
}

function parseProgress(value: unknown): ZkHolderReferenceProvingProgress {
  const candidate = object(value, "holder reference proving progress");
  const phase = progressPhase(candidate.phase);
  return {
    phase,
    percent: integer(candidate.percent, "worker progress percent", 0, 99),
    memoryBytes: integer(
      candidate.memoryBytes,
      "worker progress memory",
      0,
      ZK_HOLDER_REFERENCE_PROVER_MAX_MEMORY_BYTES,
    ),
  };
}

function deserializePublicSignals(value: Hex): readonly bigint[] {
  const body = value.slice(2);
  const signals = Array.from({ length: ZK_PUBLIC_SIGNAL_COUNT }, (_, index) =>
    BigInt(`0x${body.slice(index * 64, (index + 1) * 64)}`),
  );
  decodeZkIdentityPublicSignals(signals);
  return signals;
}

function postFailed(
  scope: ZkHolderReferenceWorkerScopeLike,
  jobIdValue: string,
  code: FailedEvent["code"],
): void {
  scope.postMessage({
    ...protocolEnvelope(),
    kind: "failed",
    jobId: jobIdValue,
    code,
  } satisfies FailedEvent);
}

function protocolEnvelope() {
  return {
    schema: ZK_HOLDER_REFERENCE_PROVER_WORKER_SCHEMA,
    version: ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION,
    profileStatus: ZK_HOLDER_REFERENCE_PROFILE_STATUS,
  } as const;
}

function protocolHeader(candidate: Record<string, unknown>): void {
  if (
    candidate.schema !== ZK_HOLDER_REFERENCE_PROVER_WORKER_SCHEMA ||
    candidate.version !== ZK_HOLDER_REFERENCE_PROVER_WORKER_VERSION ||
    candidate.profileStatus !== ZK_HOLDER_REFERENCE_PROFILE_STATUS
  ) {
    throw new Error("unsupported holder reference prover protocol");
  }
}

function progressPhase(value: unknown): ZkHolderReferenceProvingPhase {
  if (typeof value !== "string" || !PROGRESS_PHASES.includes(value as ZkHolderReferenceProvingPhase)) {
    throw new Error("unsupported holder reference proving phase");
  }
  return value as ZkHolderReferenceProvingPhase;
}

function phaseIndex(phase: ZkHolderReferenceProvingPhase): number {
  return PROGRESS_PHASES.indexOf(phase);
}

function memoryLimit(value: unknown): number {
  return integer(
    value,
    "holder reference prover memory limit",
    ZK_HOLDER_REFERENCE_PROVER_MIN_MEMORY_BYTES,
    ZK_HOLDER_REFERENCE_PROVER_MAX_MEMORY_BYTES,
  );
}

function checkedDeadline(timeoutMs: number): number {
  const now = Date.now();
  if (!Number.isSafeInteger(now) || now < 0) throw new Error("holder reference prover clock is invalid");
  const deadline = now + timeoutMs;
  if (!Number.isSafeInteger(deadline)) throw new Error("holder reference prover deadline is outside the safe range");
  return deadline;
}

function newJobId(): string {
  const bytes = new Uint8Array(JOB_ID_BYTES);
  crypto.getRandomValues(bytes);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/u, "");
}

function jobId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/u.test(value)) {
    throw new Error("holder reference prover job id is invalid");
  }
  return value;
}

function recoverJobId(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) return undefined;
  try {
    return jobId((value as Record<string, unknown>).jobId);
  } catch {
    return undefined;
  }
}

function publicSignalsHex(value: unknown): Hex {
  if (!isHex(value, { strict: true }) || size(value) !== PUBLIC_SIGNALS_BYTES) {
    throw new Error(`public-signal bytes must contain exactly ${PUBLIC_SIGNALS_BYTES} bytes`);
  }
  return value.toLowerCase() as Hex;
}

function syntheticFixtureId(value: unknown): string {
  if (typeof value !== "string" || !/^synthetic:[a-z0-9][a-z0-9._-]{0,63}$/u.test(value)) {
    throw new Error("fixture id must be a bounded synthetic fixture tag");
  }
  return value;
}

function workerFailureCodeValue(value: unknown): FailedEvent["code"] {
  if (
    value !== "cancelled" &&
    value !== "deadline-exceeded" &&
    value !== "invalid-request" &&
    value !== "proving-failed" &&
    value !== "resource-limit"
  ) {
    throw new Error("unsupported holder reference prover failure code");
  }
  return value;
}

class WorkerFailure extends Error {
  readonly code: FailedEvent["code"];

  constructor(code: FailedEvent["code"]) {
    super(code);
    this.code = code;
  }
}

function workerFailure(code: FailedEvent["code"]): WorkerFailure {
  return new WorkerFailure(code);
}

function workerFailureCode(value: unknown): FailedEvent["code"] | undefined {
  return value instanceof WorkerFailure ? value.code : undefined;
}

function integer(value: unknown, label: string, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`${label} must be an integer between ${minimum} and ${maximum}`);
  }
  return value as number;
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

function allowedKeys(candidate: Record<string, unknown>, keys: readonly string[], label: string): void {
  const allowed = new Set(keys);
  if (Object.keys(candidate).some((key) => !allowed.has(key))) {
    throw new Error(`${label} fields are invalid`);
  }
}

function isAbortSignal(value: unknown): value is AbortSignal {
  if (typeof value !== "object" || value === null) return false;
  const candidate = value as Partial<AbortSignal>;
  return (
    typeof candidate.aborted === "boolean" &&
    typeof candidate.addEventListener === "function" &&
    typeof candidate.removeEventListener === "function"
  );
}
