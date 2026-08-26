/**
 * ADR-0014 private all-cohort packed-status refresh Worker boundary.
 *
 * The host supplies the same authenticated public cohort set for every holder.
 * Only this disposable Worker unlocks the vault and derives the private status
 * selector. No progress or selector-bearing diagnostic crosses the boundary.
 */
import {
  getAddress,
  isAddress,
  isHex,
  recoverTypedDataAddress,
  size,
  type Address,
  type Hex,
} from "viem";
import {
  parseCredentialVault,
  transformCredentialVaultPayload,
  type PortableCredentialVault,
} from "./credential-vault";
import { BN254_SCALAR_FIELD } from "./zk-identity-encoding";
import {
  parseZkIdentityPackedStatusSnapshot,
  serializeZkIdentityPackedStatusSnapshot,
  zkIdentityPackedStatusAttestationTypedData,
  zkIdentityPackedStatusSnapshotHash,
  type ZkIdentityPackedStatusSnapshot,
} from "./zk-identity-status-snapshot";
import {
  parseZkHolderPackedStatusWitness,
  parseZkHolderProductionVaultPayload,
  ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEMA,
  ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEME,
  ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
  ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA,
  type ZkHolderPackedStatusWitness,
  type ZkHolderProductionVaultPayload,
} from "./zk-holder-production-vault";
import { ZK_HOLDER_PROFILE_ID } from "./zk-holder-profile-prover-worker";

export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_SCHEMA =
  "org.proofofhumanity.zk-holder-private-status-refresh/1" as const;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_RESULT_SCHEMA =
  "org.proofofhumanity.zk-holder-private-status-refresh-result/1" as const;
export const ZK_HOLDER_STATUS_REFRESH_TRUST_BUNDLE_SCHEMA =
  "org.proofofhumanity.zk-holder-status-refresh-trust-bundle/1" as const;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION = 1 as const;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_COHORTS = 32;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_SNAPSHOT_BYTES = 64 * 1024 * 1024;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_SNAPSHOT_CHUNKS = 1_000_000;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATION_BYTES = 128 * 1024;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATIONS_PER_KIND = 32;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_JSON_DEPTH = 64;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_MEMORY_BYTES = 256 * 1024 * 1024;
export const ZK_HOLDER_PRIVATE_STATUS_REFRESH_JOB_MS = 60_000;

const UINT32_MAX = 0xffff_ffff;
const UINT64_MAX = (1n << 64n) - 1n;
const SECP256K1_ORDER =
  0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const SECP256K1_HALF_ORDER = SECP256K1_ORDER >> 1n;
const UTF8 = new TextEncoder();
const UTF8_FATAL = new TextDecoder("utf-8", { fatal: true });

export type ZkHolderPrivateStatusRefreshFailureCode =
  | "INVALID_REQUEST"
  | "PROFILE_REJECTED"
  | "VAULT_REJECTED"
  | "SNAPSHOT_REJECTED"
  | "CREDENTIAL_UNUSABLE"
  | "RESOURCE_LIMIT"
  | "CANCELLED"
  | "DEADLINE_EXCEEDED"
  | "INTERNAL_ERROR";

export interface ZkHolderStatusResolution {
  chainId: string;
  issuanceRegistry: Address;
  registryRuntimeCodehash: Hex;
  issuerKeyId: Hex;
  issuerActive: true;
  snapshotId: number;
  snapshotHash: Hex;
  snapshotContentSha256: string;
  attestationSetSha256: string;
  root: Hex;
  activatedThroughStatusId: number;
  publishedAt: number;
  revoked: false;
  accepted: true;
  observationBlockNumber: string;
  observationBlockHash: Hex;
  observationBlockTimestamp: string;
  validUntil: string;
  finalityRuleId: Hex;
  resolverConfigHash: Hex;
  reconcilerConfigHash: Hex;
}

export interface ZkHolderStatusRefreshCohortBundle {
  resolution: ZkHolderStatusResolution;
  snapshotBytes: ArrayBuffer;
  attestationBytes: ArrayBuffer;
}

export interface ZkHolderPrivateStatusRefreshRequest {
  schema: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_SCHEMA;
  version: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION;
  jobId: string;
  priorVaultSha256: string;
  vault: PortableCredentialVault;
  unlock: { credentialId: string; prfOutput: ArrayBuffer };
  cohortBundles: ZkHolderStatusRefreshCohortBundle[];
}

export type ZkHolderPrivateStatusRefreshResult =
  | {
      schema: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_RESULT_SCHEMA;
      version: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION;
      jobId: string;
      status: "updated";
      replacementVault: PortableCredentialVault;
    }
  | {
      schema: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_RESULT_SCHEMA;
      version: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION;
      jobId: string;
      status: "unchanged";
    }
  | {
      schema: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_RESULT_SCHEMA;
      version: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION;
      jobId: string;
      status: "failed";
      code: ZkHolderPrivateStatusRefreshFailureCode;
    };

export interface ZkHolderStatusRefreshCohortPolicy {
  chainId: string;
  issuanceRegistry: Address;
  registryRuntimeCodehash: Hex;
  issuerKeyId: Hex;
  finalityRuleId: Hex;
  resolverConfigHash: Hex;
  reconcilerConfigHash: Hex;
  resolverSigners: readonly Address[];
  resolverThreshold: number;
  reconcilerSigners: readonly Address[];
  reconcilerThreshold: number;
}

export interface ZkHolderPrivateStatusRefreshPolicy {
  profileId: typeof ZK_HOLDER_PROFILE_ID;
  parameterManifestSha256: typeof ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256;
  productionApproved: boolean;
  cohorts: readonly ZkHolderStatusRefreshCohortPolicy[];
}

export interface ZkHolderDerivedStatusPath {
  chunkLimbsLittleEndian: readonly [string, string];
  siblingsBottomUp: readonly string[];
}

/** Cryptographic operations supplied only by the locally bundled Worker binary. */
export interface ZkHolderPrivateStatusRefreshEngine {
  admitsProductionProfile(policy: ZkHolderPrivateStatusRefreshPolicy): Promise<boolean> | boolean;
  validateSnapshot(
    snapshot: ZkIdentityPackedStatusSnapshot,
    signal: AbortSignal,
  ): Promise<void> | void;
  verifyPayload(
    payload: ZkHolderProductionVaultPayload,
    signal: AbortSignal,
  ): Promise<void> | void;
  buildStatusPath(input: {
    snapshot: ZkIdentityPackedStatusSnapshot;
    statusId: number;
    signal: AbortSignal;
  }): Promise<ZkHolderDerivedStatusPath> | ZkHolderDerivedStatusPath;
  /** Irreversibly remove fetch/socket/import capabilities before vault decryption. */
  lockNetwork(): void;
  memoryBytes?(): number;
  destroy?(): void;
}

/** Checked-in safe default: no production profile or payload is admitted. */
export class ZkHolderPrivateStatusRefreshDisabledEngine
implements ZkHolderPrivateStatusRefreshEngine {
  admitsProductionProfile(): false { return false; }
  validateSnapshot(): never { throw new Error("production status refresh is not admitted"); }
  verifyPayload(): never { throw new Error("production status refresh is not admitted"); }
  buildStatusPath(): never { throw new Error("production status refresh is not admitted"); }
  lockNetwork(): void { /* No network was ever enabled for the disabled engine. */ }
}

export interface ZkHolderPrivateStatusRefreshWorkerLike {
  postMessage(message: unknown, transfer?: readonly Transferable[]): void;
  terminate(): void;
  onmessage: ((event: { data: unknown }) => void) | null;
  onerror: ((event: { message?: string }) => void) | null;
}

export interface ZkHolderPrivateStatusRefreshWorkerScopeLike {
  postMessage(message: unknown): void;
  onmessage: ((event: { data: unknown }) => void) | null;
}

export interface ZkHolderPrivateStatusRefreshWorkerOptions {
  policy: ZkHolderPrivateStatusRefreshPolicy;
  engine: ZkHolderPrivateStatusRefreshEngine;
  /** Trusted wall clock, injectable only for deterministic tests. */
  now?: () => number;
}

export class ZkHolderPrivateStatusRefreshClient {
  readonly #createWorker: () => ZkHolderPrivateStatusRefreshWorkerLike;

  constructor(createWorker: () => ZkHolderPrivateStatusRefreshWorkerLike) {
    if (typeof createWorker !== "function") throw new Error("a private status refresh Worker factory is required");
    this.#createWorker = createWorker;
  }

  refresh(
    requestValue: ZkHolderPrivateStatusRefreshRequest,
    options: { signal?: AbortSignal } = {},
  ): Promise<ZkHolderPrivateStatusRefreshResult> {
    let request: ZkHolderPrivateStatusRefreshRequest;
    try {
      request = parseZkHolderPrivateStatusRefreshRequest(requestValue);
    } catch (error) {
      const id = recoverJobId(requestValue);
      const code = failureCode(error);
      if (id && code) return Promise.resolve(failed(id, code));
      throw error;
    }
    const signal = options.signal;
    if (signal !== undefined && !isAbortSignal(signal)) throw new Error("refresh abort signal is invalid");
    if (signal?.aborted) return Promise.resolve(failed(request.jobId, "CANCELLED"));
    let worker: ZkHolderPrivateStatusRefreshWorkerLike;
    try {
      worker = this.#createWorker();
    } catch {
      zeroBuffer(request.unlock.prfOutput);
      return Promise.resolve(failed(request.jobId, "INTERNAL_ERROR"));
    }
    if (!worker || typeof worker.postMessage !== "function" || typeof worker.terminate !== "function") {
      throw new Error("private status refresh Worker factory returned an invalid Worker");
    }
    const transfers: Transferable[] = [
      request.unlock.prfOutput,
      ...request.cohortBundles.flatMap(({ snapshotBytes, attestationBytes }) => [snapshotBytes, attestationBytes]),
    ];

    return new Promise((resolve) => {
      let settled = false;
      const finish = (result: ZkHolderPrivateStatusRefreshResult) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", abort);
        worker.onmessage = null;
        worker.onerror = null;
        worker.terminate();
        resolve(result);
      };
      const abort = () => finish(failed(request.jobId, "CANCELLED"));
      const timer = setTimeout(
        () => finish(failed(request.jobId, "DEADLINE_EXCEEDED")),
        ZK_HOLDER_PRIVATE_STATUS_REFRESH_JOB_MS,
      );
      worker.onmessage = ({ data }) => {
        try {
          const result = parseZkHolderPrivateStatusRefreshResult(data);
          if (result.jobId !== request.jobId) return;
          finish(result);
        } catch {
          finish(failed(request.jobId, "INTERNAL_ERROR"));
        }
      };
      worker.onerror = () => finish(failed(request.jobId, "INTERNAL_ERROR"));
      signal?.addEventListener("abort", abort, { once: true });
      if (signal?.aborted) return abort();
      try {
        worker.postMessage(request, transfers);
      } catch {
        zeroBuffer(request.unlock.prfOutput);
        finish(failed(request.jobId, "INTERNAL_ERROR"));
      }
    });
  }
}

/** Create the exact request and its input-only whole-vault CAS digest. */
export async function createZkHolderPrivateStatusRefreshRequest(input: {
  vault: unknown;
  unlock: { credentialId: string; prfOutput: ArrayBuffer };
  cohortBundles: ZkHolderStatusRefreshCohortBundle[];
}): Promise<ZkHolderPrivateStatusRefreshRequest> {
  const vault = parseCredentialVault(input.vault);
  return parseZkHolderPrivateStatusRefreshRequest({
    schema: ZK_HOLDER_PRIVATE_STATUS_REFRESH_SCHEMA,
    version: ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION,
    jobId: newJobId(),
    priorVaultSha256: await zkHolderCredentialVaultSha256(vault),
    vault,
    unlock: input.unlock,
    cohortBundles: input.cohortBundles,
  });
}

export function serveZkHolderPrivateStatusRefreshWorker(
  scope: ZkHolderPrivateStatusRefreshWorkerScopeLike,
  options: ZkHolderPrivateStatusRefreshWorkerOptions,
): void {
  if (!scope || typeof scope.postMessage !== "function") {
    throw new Error("a private status refresh Worker scope is required");
  }
  if (!options || !validEngine(options.engine)) {
    throw new Error("a private status refresh engine is required");
  }
  const policy = parsePolicy(options.policy);
  const now = options.now ?? Date.now;
  if (typeof now !== "function") throw new Error("a trusted refresh clock is required");
  let started = false;
  scope.onmessage = ({ data }) => {
    if (started) {
      const id = recoverJobId(data);
      if (id) scope.postMessage(failed(id, "INVALID_REQUEST"));
      return;
    }
    started = true;
    let request: ZkHolderPrivateStatusRefreshRequest;
    try {
      request = parseZkHolderPrivateStatusRefreshRequest(data);
    } catch (error) {
      const id = recoverJobId(data);
      if (id) scope.postMessage(failed(id, failureCode(error) ?? "INVALID_REQUEST"));
      return;
    }
    void executeRefresh(scope, request, policy, options.engine, now);
  };
}

async function executeRefresh(
  scope: ZkHolderPrivateStatusRefreshWorkerScopeLike,
  request: ZkHolderPrivateStatusRefreshRequest,
  policy: ZkHolderPrivateStatusRefreshPolicy,
  engine: ZkHolderPrivateStatusRefreshEngine,
  now: () => number,
): Promise<void> {
  const controller = new AbortController();
  let deadline = false;
  const deadlineAtMs = Date.now() + ZK_HOLDER_PRIVATE_STATUS_REFRESH_JOB_MS;
  const checkDeadline = () => {
    if (Date.now() >= deadlineAtMs) {
      deadline = true;
      controller.abort();
    }
    abortIfNeeded(controller.signal, deadline);
  };
  const timer = setTimeout(() => {
    deadline = true;
    controller.abort();
  }, ZK_HOLDER_PRIVATE_STATUS_REFRESH_JOB_MS);
  try {
    if (!policy.productionApproved || !(await engine.admitsProductionProfile(policy))) {
      throw failure("PROFILE_REJECTED");
    }
    assertMemory(engine);
    const workerNow = nowSeconds(now);
    const validated = await validateCohortBundles(
      request.cohortBundles,
      policy,
      engine,
      controller.signal,
      workerNow,
    );
    checkDeadline();
    assertMemory(engine);

    const vault = parseCredentialVault(request.vault);
    try {
      assertStrictProductionVaultEnvelope(vault);
    } catch {
      throw failure("VAULT_REJECTED");
    }
    if (vault.binding.schema !== ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA) {
      throw failure("VAULT_REJECTED");
    }
    if (await zkHolderCredentialVaultSha256(vault) !== request.priorVaultSha256) {
      throw failure("VAULT_REJECTED");
    }
    engine.lockNetwork();

    let decrypted = false;
    let transformed: Awaited<ReturnType<typeof transformCredentialVaultPayload>>;
    try {
      transformed = await transformCredentialVaultPayload(
        vault,
        {
          credentialId: request.unlock.credentialId,
          prfOutput: new Uint8Array(request.unlock.prfOutput),
        },
        async (rawPayload) => {
          decrypted = true;
          checkDeadline();
          const payload = parseZkHolderProductionVaultPayload(rawPayload);
          await engine.verifyPayload(payload, controller.signal);
          checkDeadline();
          assertMemory(engine);
          const selected = validated.find(({ cohort }) =>
            cohort.chainId === payload.statusWitness.snapshot.chainId &&
            cohort.issuanceRegistry === payload.statusWitness.snapshot.issuanceRegistry.toLowerCase() &&
            cohort.issuerKeyId === payload.statusWitness.issuerKeyId
          );
          if (!selected) throw failure("CREDENTIAL_UNUSABLE");
          const previous = payload.statusWitness.snapshot;
          const next = selected.resolution;
          if (
            next.snapshotId < previous.snapshotId ||
            BigInt(next.publishedAt) < BigInt(previous.publishedAt)
          ) {
            throw failure("CREDENTIAL_UNUSABLE");
          }
          if (next.snapshotId === previous.snapshotId) {
            if (
              next.root !== previous.root ||
              next.activatedThroughStatusId !== previous.activatedThroughStatusId ||
              next.publishedAt.toString() !== previous.publishedAt
            ) {
              throw failure("CREDENTIAL_UNUSABLE");
            }
            return { status: "unchanged" } as const;
          }
          if (next.activatedThroughStatusId < payload.credential.statusId) {
            throw failure("CREDENTIAL_UNUSABLE");
          }
          const path = await engine.buildStatusPath({
            snapshot: selected.snapshot,
            statusId: payload.credential.statusId,
            signal: controller.signal,
          });
          checkDeadline();
          assertMemory(engine);
          const statusWitness = parseZkHolderPackedStatusWitness({
            schema: ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEMA,
            scheme: ZK_HOLDER_PACKED_STATUS_WITNESS_SCHEME,
            issuerKeyId: payload.credential.issuerKeyId,
            statusId: payload.credential.statusId,
            snapshot: {
              chainId: next.chainId,
              issuanceRegistry: next.issuanceRegistry,
              snapshotId: next.snapshotId,
              root: next.root,
              activatedThroughStatusId: next.activatedThroughStatusId,
              publishedAt: next.publishedAt.toString(),
            },
            chunkLimbsLittleEndian: path.chunkLimbsLittleEndian,
            siblingsBottomUp: path.siblingsBottomUp,
          });
          const replacement = parseZkHolderProductionVaultPayload({ ...payload, statusWitness });
          return { status: "updated", payload: replacement } as const;
        },
      );
    } catch (error) {
      const code = failureCode(error);
      if (code) throw error;
      throw failure(decrypted ? "CREDENTIAL_UNUSABLE" : "VAULT_REJECTED");
    } finally {
      zeroBuffer(request.unlock.prfOutput);
    }
    checkDeadline();
    if (transformed.status === "unchanged") {
      scope.postMessage(unchanged(request.jobId));
    } else {
      scope.postMessage(updated(request.jobId, transformed.vault));
    }
  } catch (error) {
    scope.postMessage(failed(request.jobId, deadline ? "DEADLINE_EXCEEDED" : failureCode(error) ?? "INTERNAL_ERROR"));
  } finally {
    clearTimeout(timer);
    controller.abort();
    zeroBuffer(request.unlock.prfOutput);
    for (const bundle of request.cohortBundles) {
      zeroBuffer(bundle.snapshotBytes);
      zeroBuffer(bundle.attestationBytes);
    }
    try { engine.destroy?.(); } catch { /* Worker termination remains authoritative. */ }
  }
}

interface ValidatedCohortBundle {
  cohort: ZkHolderStatusRefreshCohortPolicy;
  resolution: ZkHolderStatusResolution;
  snapshot: ZkIdentityPackedStatusSnapshot;
}

async function validateCohortBundles(
  bundles: ZkHolderStatusRefreshCohortBundle[],
  policy: ZkHolderPrivateStatusRefreshPolicy,
  engine: ZkHolderPrivateStatusRefreshEngine,
  signal: AbortSignal,
  workerNow: bigint,
): Promise<ValidatedCohortBundle[]> {
  if (bundles.length !== policy.cohorts.length || bundles.length < 1) {
    throw failure("SNAPSHOT_REJECTED");
  }
  let snapshotBytes = 0;
  let attestationBytes = 0;
  let chunks = 0;
  let snapshotAttestations = 0;
  let resolutionAttestations = 0;
  const output: ValidatedCohortBundle[] = [];

  for (const [index, bundle] of bundles.entries()) {
    abortIfNeeded(signal, false);
    snapshotBytes += bundle.snapshotBytes.byteLength;
    attestationBytes += bundle.attestationBytes.byteLength;
    if (
      snapshotBytes > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_SNAPSHOT_BYTES ||
      attestationBytes > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATION_BYTES
    ) {
      throw failure("RESOURCE_LIMIT");
    }
    try {
      assertJsonDepth(bundle.snapshotBytes);
      assertJsonDepth(bundle.attestationBytes);
      const snapshotText = UTF8_FATAL.decode(bundle.snapshotBytes);
      const snapshotRaw = JSON.parse(snapshotText) as unknown;
      const snapshot = parseZkIdentityPackedStatusSnapshot(snapshotRaw);
      if (snapshotText !== serializeZkIdentityPackedStatusSnapshot(snapshot)) {
        throw new Error("status snapshot bytes are not canonical");
      }
      chunks += snapshot.chunks.length;
      if (chunks > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_SNAPSHOT_CHUNKS) {
        throw failure("RESOURCE_LIMIT");
      }
      const resolution = parseZkHolderStatusResolution(bundle.resolution);
      const cohort = policy.cohorts[index]!;
      requireResolutionMatchesCohort(resolution, cohort);
      if (
        resolution.snapshotContentSha256 !== await sha256Hex(bundle.snapshotBytes) ||
        resolution.snapshotHash !== zkIdentityPackedStatusSnapshotHash(snapshot) ||
        resolution.snapshotHash !== zkIdentityPackedStatusSnapshotHash(snapshotRaw) ||
        resolution.chainId !== snapshot.chainId ||
        resolution.issuanceRegistry !== snapshot.issuanceRegistry ||
        resolution.issuerKeyId !== snapshot.issuerKeyId ||
        resolution.root !== snapshot.root ||
        resolution.activatedThroughStatusId !== snapshot.activatedThroughStatusId
      ) {
        throw new Error("status resolution does not match its canonical snapshot");
      }
      requireFreshResolution(resolution, workerNow);

      const attestationText = UTF8_FATAL.decode(bundle.attestationBytes);
      const attestationRaw = JSON.parse(attestationText) as unknown;
      if (attestationText !== canonicalJson(attestationRaw)) {
        throw new Error("status trust bundle is not RFC 8785 canonical JSON");
      }
      if (resolution.attestationSetSha256 !== await sha256Hex(bundle.attestationBytes)) {
        throw new Error("status trust bundle digest does not match");
      }
      const trust = parseTrustBundle(attestationRaw);
      snapshotAttestations += trust.snapshotAttestations.length;
      resolutionAttestations += trust.resolutionAttestations.length;
      if (
        snapshotAttestations > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATIONS_PER_KIND ||
        resolutionAttestations > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATIONS_PER_KIND
      ) {
        throw failure("RESOURCE_LIMIT");
      }
      await verifyAttestationSet(
        trust.snapshotAttestations,
        cohort.reconcilerSigners,
        cohort.reconcilerThreshold,
        zkIdentityPackedStatusAttestationTypedData(snapshot),
        "snapshot",
      );
      await verifyAttestationSet(
        trust.resolutionAttestations,
        cohort.resolverSigners,
        cohort.resolverThreshold,
        zkHolderStatusResolutionTypedData(resolution),
        "resolution",
      );
      await engine.validateSnapshot(snapshot, signal);
      abortIfNeeded(signal, false);
      assertMemory(engine);
      output.push({ cohort, resolution, snapshot });
    } catch (error) {
      if (failureCode(error)) throw error;
      throw failure("SNAPSHOT_REJECTED");
    }
  }
  return output;
}

export function parseZkHolderPrivateStatusRefreshRequest(
  value: unknown,
): ZkHolderPrivateStatusRefreshRequest {
  const candidate = object(value, "private status refresh request");
  exactKeys(
    candidate,
    ["schema", "version", "jobId", "priorVaultSha256", "vault", "unlock", "cohortBundles"],
    "private status refresh request",
  );
  if (
    candidate.schema !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_SCHEMA ||
    candidate.version !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION
  ) {
    throw new Error("unsupported private status refresh request");
  }
  const unlockCandidate = object(candidate.unlock, "private status refresh unlock");
  exactKeys(unlockCandidate, ["credentialId", "prfOutput"], "private status refresh unlock");
  if (
    typeof unlockCandidate.credentialId !== "string" ||
    unlockCandidate.credentialId.length === 0 ||
    unlockCandidate.credentialId.length > 2048 ||
    !/^[A-Za-z0-9_-]+$/u.test(unlockCandidate.credentialId)
  ) {
    throw new Error("refresh WebAuthn credential id is invalid");
  }
  if (!(unlockCandidate.prfOutput instanceof ArrayBuffer) || unlockCandidate.prfOutput.byteLength !== 32) {
    throw new Error("refresh WebAuthn PRF output must be a transferable 32-byte ArrayBuffer");
  }
  if (!Array.isArray(candidate.cohortBundles)) throw new Error("refresh cohort bundles must be an array");
  if (
    candidate.cohortBundles.length < 1 ||
    candidate.cohortBundles.length > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_COHORTS
  ) {
    throw new Error("refresh cohort bundle count is outside the supported range");
  }
  const cohortBundles = candidate.cohortBundles.map((raw, index) => {
    const bundle = object(raw, `refresh cohort bundle ${index}`);
    exactKeys(bundle, ["resolution", "snapshotBytes", "attestationBytes"], `refresh cohort bundle ${index}`);
    if (!(bundle.snapshotBytes instanceof ArrayBuffer) || !(bundle.attestationBytes instanceof ArrayBuffer)) {
      throw new Error("refresh cohort bytes must be transferable ArrayBuffers");
    }
    return {
      resolution: parseZkHolderStatusResolution(bundle.resolution),
      snapshotBytes: bundle.snapshotBytes,
      attestationBytes: bundle.attestationBytes,
    };
  });
  try {
    assertHostResourceLimits(cohortBundles);
  } catch (error) {
    if (failureCode(error)) throw error;
    throw failure("SNAPSHOT_REJECTED");
  }
  return {
    schema: ZK_HOLDER_PRIVATE_STATUS_REFRESH_SCHEMA,
    version: ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION,
    jobId: jobId(candidate.jobId),
    priorVaultSha256: sha256Digest(candidate.priorVaultSha256, "prior vault SHA-256"),
    vault: parseCredentialVault(candidate.vault),
    unlock: { credentialId: unlockCandidate.credentialId, prfOutput: unlockCandidate.prfOutput },
    cohortBundles,
  };
}

export function parseZkHolderPrivateStatusRefreshResult(
  value: unknown,
): ZkHolderPrivateStatusRefreshResult {
  const candidate = object(value, "private status refresh result");
  if (
    candidate.schema !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_RESULT_SCHEMA ||
    candidate.version !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION
  ) {
    throw new Error("unsupported private status refresh result");
  }
  const id = jobId(candidate.jobId);
  if (candidate.status === "updated") {
    exactKeys(candidate, ["schema", "version", "jobId", "status", "replacementVault"], "updated refresh result");
    const replacementVault = parseCredentialVault(candidate.replacementVault);
    try {
      assertStrictProductionVaultEnvelope(replacementVault);
    } catch {
      throw new Error("updated refresh result contains the wrong vault schema");
    }
    return updated(id, replacementVault);
  }
  if (candidate.status === "unchanged") {
    exactKeys(candidate, ["schema", "version", "jobId", "status"], "unchanged refresh result");
    return unchanged(id);
  }
  if (candidate.status === "failed") {
    exactKeys(candidate, ["schema", "version", "jobId", "status", "code"], "failed refresh result");
    return failed(id, failureCodeValue(candidate.code));
  }
  throw new Error("unsupported private status refresh result status");
}

export function parseZkHolderStatusResolution(value: unknown): ZkHolderStatusResolution {
  const candidate = object(value, "holder status resolution");
  exactKeys(
    candidate,
    [
      "chainId",
      "issuanceRegistry",
      "registryRuntimeCodehash",
      "issuerKeyId",
      "issuerActive",
      "snapshotId",
      "snapshotHash",
      "snapshotContentSha256",
      "attestationSetSha256",
      "root",
      "activatedThroughStatusId",
      "publishedAt",
      "revoked",
      "accepted",
      "observationBlockNumber",
      "observationBlockHash",
      "observationBlockTimestamp",
      "validUntil",
      "finalityRuleId",
      "resolverConfigHash",
      "reconcilerConfigHash",
    ],
    "holder status resolution",
  );
  if (candidate.issuerActive !== true || candidate.revoked !== false || candidate.accepted !== true) {
    throw new Error("holder status resolution is not active and accepted");
  }
  return {
    chainId: canonicalDecimal(candidate.chainId, "resolution chain id", false, (1n << 256n) - 1n),
    issuanceRegistry: address(candidate.issuanceRegistry, "resolution issuance registry"),
    registryRuntimeCodehash: bytes32(candidate.registryRuntimeCodehash, "registry runtime codehash", true),
    issuerKeyId: bytes32(candidate.issuerKeyId, "resolution issuer key id", true),
    issuerActive: true,
    snapshotId: uint32(candidate.snapshotId, "resolution snapshot id", false),
    snapshotHash: bytes32(candidate.snapshotHash, "resolution snapshot hash", true),
    snapshotContentSha256: sha256Digest(candidate.snapshotContentSha256, "snapshot content SHA-256"),
    attestationSetSha256: sha256Digest(candidate.attestationSetSha256, "attestation-set SHA-256"),
    root: fieldBytes32(candidate.root, "resolution status root", true),
    activatedThroughStatusId: uint32(
      candidate.activatedThroughStatusId,
      "resolution allocation watermark",
      true,
    ),
    publishedAt: uint32(candidate.publishedAt, "resolution publication time", false),
    revoked: false,
    accepted: true,
    observationBlockNumber: canonicalDecimal(
      candidate.observationBlockNumber,
      "resolution observation block number",
      true,
      UINT64_MAX,
    ),
    observationBlockHash: bytes32(candidate.observationBlockHash, "resolution observation block hash", true),
    observationBlockTimestamp: canonicalDecimal(
      candidate.observationBlockTimestamp,
      "resolution observation block timestamp",
      true,
      UINT64_MAX,
    ),
    validUntil: canonicalDecimal(candidate.validUntil, "resolution validity deadline", true, UINT64_MAX),
    finalityRuleId: bytes32(candidate.finalityRuleId, "resolution finality rule id", true),
    resolverConfigHash: bytes32(candidate.resolverConfigHash, "resolver configuration hash", true),
    reconcilerConfigHash: bytes32(candidate.reconcilerConfigHash, "reconciler configuration hash", true),
  };
}

export function zkHolderStatusResolutionTypedData(value: unknown) {
  const resolution = parseZkHolderStatusResolution(value);
  const chainId = BigInt(resolution.chainId);
  if (chainId > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("resolution EIP-712 chain id exceeds the SDK safe range");
  }
  return {
    domain: {
      name: "ProofOfHumanityStatusResolution",
      version: "1",
      chainId: Number(chainId),
      verifyingContract: resolution.issuanceRegistry,
    },
    types: {
      StatusResolution: [
        { name: "configHash", type: "bytes32" },
        { name: "registryRuntimeCodehash", type: "bytes32" },
        { name: "issuerKeyId", type: "bytes32" },
        { name: "issuerActive", type: "bool" },
        { name: "snapshotId", type: "uint32" },
        { name: "snapshotHash", type: "bytes32" },
        { name: "root", type: "bytes32" },
        { name: "activatedThroughStatusId", type: "uint32" },
        { name: "publishedAt", type: "uint32" },
        { name: "revoked", type: "bool" },
        { name: "accepted", type: "bool" },
        { name: "observationBlockNumber", type: "uint64" },
        { name: "observationBlockHash", type: "bytes32" },
        { name: "observationBlockTimestamp", type: "uint64" },
        { name: "validUntil", type: "uint64" },
        { name: "finalityRuleId", type: "bytes32" },
      ],
    },
    primaryType: "StatusResolution",
    message: {
      configHash: resolution.resolverConfigHash,
      registryRuntimeCodehash: resolution.registryRuntimeCodehash,
      issuerKeyId: resolution.issuerKeyId,
      issuerActive: true,
      snapshotId: resolution.snapshotId,
      snapshotHash: resolution.snapshotHash,
      root: resolution.root,
      activatedThroughStatusId: resolution.activatedThroughStatusId,
      publishedAt: resolution.publishedAt,
      revoked: false,
      accepted: true,
      observationBlockNumber: BigInt(resolution.observationBlockNumber),
      observationBlockHash: resolution.observationBlockHash,
      observationBlockTimestamp: BigInt(resolution.observationBlockTimestamp),
      validUntil: BigInt(resolution.validUntil),
      finalityRuleId: resolution.finalityRuleId,
    },
  } as const;
}

export function serializeZkHolderStatusRefreshTrustBundle(value: unknown): string {
  return canonicalJson(parseTrustBundle(value));
}

/** RFC-8785/JCS SHA-256 over the entire strictly parsed portable vault. */
export async function zkHolderCredentialVaultSha256(value: unknown): Promise<string> {
  return sha256Hex(UTF8.encode(canonicalJson(parseCredentialVault(value))));
}

export interface ZkHolderPrivateStatusAtomicVaultStore {
  /** One durable transaction: compare the current whole-vault digest and replace the complete vault. */
  compareAndSwap(expectedVaultSha256: string, replacementVault: PortableCredentialVault): Promise<boolean>;
}

export async function commitZkHolderPrivateStatusRefresh(input: {
  store: ZkHolderPrivateStatusAtomicVaultStore;
  priorVaultSha256: string;
  result: unknown;
}): Promise<"committed" | "stale" | "not-updated"> {
  if (!input.store || typeof input.store.compareAndSwap !== "function") {
    throw new Error("an atomic holder vault store is required");
  }
  const priorVaultSha256 = sha256Digest(input.priorVaultSha256, "prior vault SHA-256");
  const result = parseZkHolderPrivateStatusRefreshResult(input.result);
  if (result.status !== "updated") return "not-updated";
  return await input.store.compareAndSwap(priorVaultSha256, result.replacementVault)
    ? "committed"
    : "stale";
}

interface TrustAttestation { signer: Address; signature: Hex }
interface TrustBundle {
  schema: typeof ZK_HOLDER_STATUS_REFRESH_TRUST_BUNDLE_SCHEMA;
  version: typeof ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION;
  snapshotAttestations: TrustAttestation[];
  resolutionAttestations: TrustAttestation[];
}

function parseTrustBundle(value: unknown): TrustBundle {
  const candidate = object(value, "holder status refresh trust bundle");
  exactKeys(
    candidate,
    ["schema", "version", "snapshotAttestations", "resolutionAttestations"],
    "holder status refresh trust bundle",
  );
  if (
    candidate.schema !== ZK_HOLDER_STATUS_REFRESH_TRUST_BUNDLE_SCHEMA ||
    candidate.version !== ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION ||
    !Array.isArray(candidate.snapshotAttestations) ||
    !Array.isArray(candidate.resolutionAttestations)
  ) {
    throw new Error("unsupported holder status refresh trust bundle");
  }
  return {
    schema: ZK_HOLDER_STATUS_REFRESH_TRUST_BUNDLE_SCHEMA,
    version: ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION,
    snapshotAttestations: parseTrustAttestations(candidate.snapshotAttestations, "snapshot"),
    resolutionAttestations: parseTrustAttestations(candidate.resolutionAttestations, "resolution"),
  };
}

function parseTrustAttestations(values: unknown[], label: string): TrustAttestation[] {
  let previous = "";
  return values.map((value, index) => {
    const candidate = object(value, `${label} attestation ${index}`);
    exactKeys(candidate, ["signer", "signature"], `${label} attestation ${index}`);
    const signer = checksumAddress(candidate.signer, `${label} attestation signer`);
    const key = signer.toLowerCase();
    if (key <= previous) throw new Error(`${label} attestation signers must be sorted and unique`);
    previous = key;
    return { signer, signature: compactSignature(candidate.signature, `${label} attestation signature`) };
  });
}

async function verifyAttestationSet(
  attestations: TrustAttestation[],
  expectedSigners: readonly Address[],
  threshold: number,
  typedData: Parameters<typeof recoverTypedDataAddress>[0] extends infer T ? Omit<T, "signature"> : never,
  label: string,
): Promise<void> {
  if (attestations.length < threshold) throw new Error(`${label} attestation threshold is not met`);
  const expected = new Set(expectedSigners.map((signer) => signer.toLowerCase()));
  for (const attestation of attestations) {
    if (!expected.has(attestation.signer.toLowerCase())) {
      throw new Error(`${label} attestation signer is not allowlisted`);
    }
    const recovered = getAddress(await recoverTypedDataAddress({ ...typedData, signature: attestation.signature }));
    if (recovered !== attestation.signer) throw new Error(`${label} attestation signer does not recover`);
  }
}

function requireResolutionMatchesCohort(
  resolution: ZkHolderStatusResolution,
  cohort: ZkHolderStatusRefreshCohortPolicy,
): void {
  if (
    resolution.chainId !== cohort.chainId ||
    resolution.issuanceRegistry !== cohort.issuanceRegistry ||
    resolution.registryRuntimeCodehash !== cohort.registryRuntimeCodehash ||
    resolution.issuerKeyId !== cohort.issuerKeyId ||
    resolution.finalityRuleId !== cohort.finalityRuleId ||
    resolution.resolverConfigHash !== cohort.resolverConfigHash ||
    resolution.reconcilerConfigHash !== cohort.reconcilerConfigHash
  ) {
    throw new Error("status resolution does not match its Worker-pinned cohort");
  }
}

function requireFreshResolution(resolution: ZkHolderStatusResolution, workerNow: bigint): void {
  const publishedAt = BigInt(resolution.publishedAt);
  const observedAt = BigInt(resolution.observationBlockTimestamp);
  const validUntil = BigInt(resolution.validUntil);
  if (
    publishedAt > observedAt ||
    observedAt > workerNow + 120n ||
    observedAt > validUntil ||
    validUntil - observedAt > 900n ||
    workerNow > validUntil
  ) {
    throw new Error("status resolution freshness is invalid");
  }
}

function parsePolicy(value: unknown): ZkHolderPrivateStatusRefreshPolicy {
  const candidate = object(value, "private status refresh policy");
  exactKeys(candidate, ["profileId", "parameterManifestSha256", "productionApproved", "cohorts"], "private status refresh policy");
  if (
    candidate.profileId !== ZK_HOLDER_PROFILE_ID ||
    candidate.parameterManifestSha256 !== ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256 ||
    typeof candidate.productionApproved !== "boolean" ||
    !Array.isArray(candidate.cohorts) ||
    candidate.cohorts.length < 1 ||
    candidate.cohorts.length > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_COHORTS
  ) {
    throw new Error("private status refresh policy is invalid");
  }
  let previous = "";
  const cohorts = candidate.cohorts.map((raw, index) => {
    const cohortCandidate = object(raw, `private status refresh cohort ${index}`);
    exactKeys(
      cohortCandidate,
      [
        "chainId",
        "issuanceRegistry",
        "registryRuntimeCodehash",
        "issuerKeyId",
        "finalityRuleId",
        "resolverConfigHash",
        "reconcilerConfigHash",
        "resolverSigners",
        "resolverThreshold",
        "reconcilerSigners",
        "reconcilerThreshold",
      ],
      `private status refresh cohort ${index}`,
    );
    const cohort: ZkHolderStatusRefreshCohortPolicy = {
      chainId: canonicalDecimal(cohortCandidate.chainId, "cohort chain id", false, (1n << 256n) - 1n),
      issuanceRegistry: address(cohortCandidate.issuanceRegistry, "cohort issuance registry"),
      registryRuntimeCodehash: bytes32(cohortCandidate.registryRuntimeCodehash, "cohort registry codehash", true),
      issuerKeyId: bytes32(cohortCandidate.issuerKeyId, "cohort issuer key id", true),
      finalityRuleId: bytes32(cohortCandidate.finalityRuleId, "cohort finality rule id", true),
      resolverConfigHash: bytes32(cohortCandidate.resolverConfigHash, "cohort resolver config hash", true),
      reconcilerConfigHash: bytes32(cohortCandidate.reconcilerConfigHash, "cohort reconciler config hash", true),
      resolverSigners: policySigners(cohortCandidate.resolverSigners, "cohort resolver signers"),
      resolverThreshold: threshold(cohortCandidate.resolverThreshold, "cohort resolver threshold"),
      reconcilerSigners: policySigners(cohortCandidate.reconcilerSigners, "cohort reconciler signers"),
      reconcilerThreshold: threshold(cohortCandidate.reconcilerThreshold, "cohort reconciler threshold"),
    };
    if (cohort.resolverThreshold > cohort.resolverSigners.length || cohort.reconcilerThreshold > cohort.reconcilerSigners.length) {
      throw new Error("private status refresh cohort threshold exceeds its allowlist");
    }
    const key = cohortKey(cohort);
    if (key <= previous) throw new Error("private status refresh cohorts must be sorted and unique");
    previous = key;
    return cohort;
  });
  return {
    profileId: ZK_HOLDER_PROFILE_ID,
    parameterManifestSha256: ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
    productionApproved: candidate.productionApproved,
    cohorts,
  };
}

function policySigners(value: unknown, label: string): readonly Address[] {
  if (!Array.isArray(value) || value.length < 2 || value.length > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATIONS_PER_KIND) {
    throw new Error(`${label} count is outside the supported range`);
  }
  const signers = value.map((entry) => checksumAddress(entry, label));
  if (new Set(signers.map((entry) => entry.toLowerCase())).size !== signers.length) {
    throw new Error(`${label} must be unique`);
  }
  return signers;
}

function cohortKey(cohort: Pick<ZkHolderStatusRefreshCohortPolicy, "chainId" | "issuanceRegistry" | "issuerKeyId">): string {
  return `${BigInt(cohort.chainId).toString(16).padStart(64, "0")}:${cohort.issuanceRegistry.toLowerCase()}:${cohort.issuerKeyId}`;
}

function threshold(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 2 || (value as number) > 32) {
    throw new Error(`${label} must be between 2 and 32`);
  }
  return value as number;
}

function assertJsonDepth(buffer: ArrayBuffer): void {
  if (buffer.byteLength === 0) throw new Error("canonical JSON bytes must not be empty");
  const bytes = new Uint8Array(buffer);
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (const byte of bytes) {
    if (inString) {
      if (escaped) escaped = false;
      else if (byte === 0x5c) escaped = true;
      else if (byte === 0x22) inString = false;
      continue;
    }
    if (byte === 0x22) inString = true;
    else if (byte === 0x7b || byte === 0x5b) {
      depth += 1;
      if (depth > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_JSON_DEPTH) throw failure("RESOURCE_LIMIT");
    } else if (byte === 0x7d || byte === 0x5d) {
      depth -= 1;
      if (depth < 0) throw new Error("canonical JSON nesting is invalid");
    }
  }
  if (inString || escaped || depth !== 0) throw new Error("canonical JSON nesting is invalid");
}

function canonicalJson(value: unknown, seen = new Set<object>()): string {
  if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonical JSON numbers must be finite");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    if (seen.has(value)) throw new Error("canonical JSON must not be cyclic");
    seen.add(value);
    const encoded = `[${value.map((entry) => canonicalJson(entry, seen)).join(",")}]`;
    seen.delete(value);
    return encoded;
  }
  if (typeof value !== "object") throw new Error("value is not representable in canonical JSON");
  const candidate = value as Record<string, unknown>;
  if (seen.has(candidate)) throw new Error("canonical JSON must not be cyclic");
  seen.add(candidate);
  const encoded = `{${Object.keys(candidate).sort().map((key) =>
    `${JSON.stringify(key)}:${canonicalJson(candidate[key], seen)}`
  ).join(",")}}`;
  seen.delete(candidate);
  return encoded;
}

async function sha256Hex(value: ArrayBuffer | Uint8Array): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto SHA-256 is required");
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  const input = bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength
    ? bytes.buffer as ArrayBuffer
    : bytes.slice().buffer as ArrayBuffer;
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", input));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function compactSignature(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 65 || value !== value.toLowerCase()) {
    throw new Error(`${label} must be canonical lowercase 65-byte hex`);
  }
  const signature = value as Hex;
  const r = BigInt(`0x${signature.slice(2, 66)}`);
  const s = BigInt(`0x${signature.slice(66, 130)}`);
  const v = Number.parseInt(signature.slice(130, 132), 16);
  if (r === 0n || r >= SECP256K1_ORDER || s === 0n || s > SECP256K1_HALF_ORDER || (v !== 27 && v !== 28)) {
    throw new Error(`${label} is not canonical low-s r||s||v`);
  }
  return signature;
}

function updated(job: string, replacementVault: PortableCredentialVault): ZkHolderPrivateStatusRefreshResult {
  return {
    schema: ZK_HOLDER_PRIVATE_STATUS_REFRESH_RESULT_SCHEMA,
    version: ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION,
    jobId: job,
    status: "updated",
    replacementVault,
  };
}

function unchanged(job: string): ZkHolderPrivateStatusRefreshResult {
  return {
    schema: ZK_HOLDER_PRIVATE_STATUS_REFRESH_RESULT_SCHEMA,
    version: ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION,
    jobId: job,
    status: "unchanged",
  };
}

function failed(job: string, code: ZkHolderPrivateStatusRefreshFailureCode): ZkHolderPrivateStatusRefreshResult {
  return {
    schema: ZK_HOLDER_PRIVATE_STATUS_REFRESH_RESULT_SCHEMA,
    version: ZK_HOLDER_PRIVATE_STATUS_REFRESH_VERSION,
    jobId: job,
    status: "failed",
    code,
  };
}

function failureCodeValue(value: unknown): ZkHolderPrivateStatusRefreshFailureCode {
  const values: ZkHolderPrivateStatusRefreshFailureCode[] = [
    "INVALID_REQUEST",
    "PROFILE_REJECTED",
    "VAULT_REJECTED",
    "SNAPSHOT_REJECTED",
    "CREDENTIAL_UNUSABLE",
    "RESOURCE_LIMIT",
    "CANCELLED",
    "DEADLINE_EXCEEDED",
    "INTERNAL_ERROR",
  ];
  if (!values.includes(value as ZkHolderPrivateStatusRefreshFailureCode)) {
    throw new Error("unsupported private status refresh failure code");
  }
  return value as ZkHolderPrivateStatusRefreshFailureCode;
}

class RefreshFailure extends Error {
  constructor(readonly code: ZkHolderPrivateStatusRefreshFailureCode) { super(code); }
}
function failure(code: ZkHolderPrivateStatusRefreshFailureCode): RefreshFailure { return new RefreshFailure(code); }
function failureCode(value: unknown): ZkHolderPrivateStatusRefreshFailureCode | undefined {
  return value instanceof RefreshFailure ? value.code : undefined;
}

function assertMemory(engine: ZkHolderPrivateStatusRefreshEngine): void {
  if (engine.memoryBytes === undefined) return;
  const bytes = engine.memoryBytes();
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_MEMORY_BYTES) {
    throw failure("RESOURCE_LIMIT");
  }
}

function abortIfNeeded(signal: AbortSignal, deadline: boolean): void {
  if (signal.aborted) throw failure(deadline ? "DEADLINE_EXCEEDED" : "CANCELLED");
}

function nowSeconds(now: () => number): bigint {
  const milliseconds = now();
  if (!Number.isSafeInteger(milliseconds) || milliseconds < 0) throw failure("INTERNAL_ERROR");
  return BigInt(Math.floor(milliseconds / 1000));
}

function validEngine(value: unknown): value is ZkHolderPrivateStatusRefreshEngine {
  if (value === null || typeof value !== "object") return false;
  const candidate = value as Partial<ZkHolderPrivateStatusRefreshEngine>;
  return (
    typeof candidate.admitsProductionProfile === "function" &&
    typeof candidate.validateSnapshot === "function" &&
    typeof candidate.verifyPayload === "function" &&
    typeof candidate.buildStatusPath === "function" &&
    typeof candidate.lockNetwork === "function"
  );
}

function assertHostResourceLimits(bundles: readonly ZkHolderStatusRefreshCohortBundle[]): void {
  let snapshotBytes = 0;
  let attestationBytes = 0;
  let chunks = 0;
  for (const bundle of bundles) {
    snapshotBytes += bundle.snapshotBytes.byteLength;
    attestationBytes += bundle.attestationBytes.byteLength;
    if (
      snapshotBytes > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_SNAPSHOT_BYTES ||
      attestationBytes > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_ATTESTATION_BYTES
    ) {
      throw failure("RESOURCE_LIMIT");
    }
    assertJsonDepth(bundle.snapshotBytes);
    assertJsonDepth(bundle.attestationBytes);
    let snapshot: Record<string, unknown>;
    try {
      snapshot = object(JSON.parse(UTF8_FATAL.decode(bundle.snapshotBytes)), "host packed-status snapshot");
    } catch (error) {
      if (failureCode(error)) throw error;
      throw new Error("host packed-status snapshot is invalid JSON");
    }
    if (!Array.isArray(snapshot.chunks)) throw new Error("host packed-status snapshot chunks are invalid");
    chunks += snapshot.chunks.length;
    if (chunks > ZK_HOLDER_PRIVATE_STATUS_REFRESH_MAX_SNAPSHOT_CHUNKS) throw failure("RESOURCE_LIMIT");
  }
}

function assertStrictProductionVaultEnvelope(vault: PortableCredentialVault): void {
  exactKeys(
    vault as unknown as Record<string, unknown>,
    ["format", "version", "vaultId", "binding", "payload", "keySlots"],
    "production credential vault",
  );
  exactKeys(vault.binding as unknown as Record<string, unknown>, ["schema", "rpId"], "vault binding");
  if (vault.binding.schema !== ZK_HOLDER_PRODUCTION_VAULT_PAYLOAD_SCHEMA) {
    throw new Error("production credential vault has the wrong binding schema");
  }
  exactKeys(vault.payload as unknown as Record<string, unknown>, ["cipher", "iv", "ciphertext"], "vault payload envelope");
  for (const [index, slot] of vault.keySlots.entries()) {
    exactKeys(
      slot as unknown as Record<string, unknown>,
      ["version", "type", "credentialId", "prfSalt", "kdf", "wrap", "iv", "wrappedKey"],
      `vault key slot ${index}`,
    );
  }
}

function exactKeys(candidate: Record<string, unknown>, keys: readonly string[], label: string): void {
  const expected = [...keys].sort();
  const actual = Object.keys(candidate).sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    throw new Error(`${label} contains missing or unknown fields`);
  }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function bytes32(value: unknown, label: string, nonZero = false): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32) {
    throw new Error(`${label} must be bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (nonZero && BigInt(normalized) === 0n) throw new Error(`${label} must not be zero`);
  return normalized;
}

function fieldBytes32(value: unknown, label: string, nonZero = false): Hex {
  const normalized = bytes32(value, label, nonZero);
  if (BigInt(normalized) >= BN254_SCALAR_FIELD) throw new Error(`${label} must be a canonical BN254 field`);
  return normalized;
}

function address(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${label} must be a nonzero EVM address`);
  }
  return getAddress(value).toLowerCase() as Address;
}

function checksumAddress(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${label} must be a nonzero EVM address`);
  }
  const normalized = getAddress(value);
  if (value !== normalized) throw new Error(`${label} must use EIP-55 checksum encoding`);
  return normalized;
}

function uint32(value: unknown, label: string, allowZero: boolean): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1) ||
    value > UINT32_MAX
  ) {
    throw new Error(`${label} must be ${allowZero ? "a" : "a nonzero"} uint32`);
  }
  return value;
}

function canonicalDecimal(value: unknown, label: string, allowZero: boolean, maximum: bigint): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed = BigInt(value);
  if ((!allowZero && parsed === 0n) || parsed > maximum) throw new Error(`${label} is outside the supported range`);
  return value;
}

function sha256Digest(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{64}$/u.test(value)) {
    throw new Error(`${label} must be 64 lowercase hex characters`);
  }
  return value;
}

function jobId(value: unknown): string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{22}$/u.test(value)) {
    throw new Error("private status refresh job id is invalid");
  }
  const bytes = fromBase64Url(value);
  if (bytes.length !== 16 || toBase64Url(bytes) !== value) throw new Error("private status refresh job id is invalid");
  return value;
}

function newJobId(): string {
  if (!globalThis.crypto?.getRandomValues) throw new Error("Web Crypto is required for private status refresh");
  return toBase64Url(globalThis.crypto.getRandomValues(new Uint8Array(16)));
}

function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/u, "");
}

function fromBase64Url(value: string): Uint8Array {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(value.length / 4) * 4, "=");
  let binary: string;
  try { binary = atob(padded); } catch { return new Uint8Array(); }
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function recoverJobId(value: unknown): string | undefined {
  try { return jobId(object(value, "private status refresh request").jobId); } catch { return undefined; }
}

function zeroBuffer(buffer: ArrayBuffer): void {
  try { new Uint8Array(buffer).fill(0); } catch { /* A transferred buffer is already detached. */ }
}

function isAbortSignal(value: unknown): value is AbortSignal {
  return typeof value === "object" && value !== null && "aborted" in value && typeof (value as AbortSignal).addEventListener === "function";
}
