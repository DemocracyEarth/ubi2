import {
  reconcileZkIdentityPackedStatusSnapshots,
  reconciledZkIdentityStatusPublication,
  recoverZkIdentityPackedStatusAttestationSigner,
  type ZkIdentityPackedStatusAttestation,
} from "@ubi2/sdk";
import { getAddress, isHex, size, type Address, type Hex } from "viem";
import {
  parseZkIdentityStatusOperatorArtifact,
  parseZkIdentityStatusOperatorHealth,
  serializeZkIdentityStatusOperatorArtifact,
  type ZkIdentityStatusOperatorArtifact,
  type ZkIdentityStatusOperatorHealth,
} from "./artifact";
import type { ZkIdentityStatusFleetConfig } from "./config";

export const ZK_IDENTITY_STATUS_FLEET_REPORT_SCHEMA =
  "org.proofofhumanity.v2-packed-status-fleet-report/1" as const;

export type ZkIdentityStatusFleetAlertCode =
  | "OPERATOR_UNAVAILABLE"
  | "REFERENCE_RPC_UNAVAILABLE"
  | "REFERENCE_RPC_BEHIND"
  | "MALFORMED_OPERATOR_RESPONSE"
  | "OPERATOR_TRUST_MISMATCH"
  | "HEARTBEAT_STALE"
  | "OPERATOR_CLOCK_SKEW"
  | "OPERATOR_DEGRADED"
  | "LATEST_HEALTH_MISMATCH"
  | "IMMUTABLE_ARTIFACT_UNAVAILABLE"
  | "IMMUTABLE_ARTIFACT_MISMATCH"
  | "WITHHOLDING_SUSPECTED"
  | "SNAPSHOT_DIVERGENCE"
  | "QUORUM_UNAVAILABLE"
  | "SIGNATURE_SET_INVALID";

export interface ZkIdentityStatusFleetAlert {
  code: ZkIdentityStatusFleetAlertCode;
  severity: "critical";
  operatorId: string | null;
}

export interface ZkIdentityStatusFleetReport {
  schema: typeof ZK_IDENTITY_STATUS_FLEET_REPORT_SCHEMA;
  observedAt: string;
  ready: boolean;
  alerts: ZkIdentityStatusFleetAlert[];
  candidate: null | {
    sourceBlockNumber: string;
    sourceBlockHash: Hex;
    snapshotHash: Hex;
    signers: Address[];
  };
  publication: null | {
    issuerKeyId: Hex;
    expectedNextStatusId: string;
    root: Hex;
  };
}

export interface FetchedZkIdentityStatusOperator {
  operatorId: string;
  health?: unknown;
  latest?: unknown;
  immutableArtifact?: unknown;
  immutableCacheControl?: string;
}

interface AcceptedOperator {
  operatorId: string;
  health: ZkIdentityStatusOperatorHealth;
  artifact: ZkIdentityStatusOperatorArtifact;
  attestation: ZkIdentityPackedStatusAttestation;
  signer: Address;
  sourceBlock: bigint;
}

function alert(
  code: ZkIdentityStatusFleetAlertCode,
  operatorId: string | null,
): ZkIdentityStatusFleetAlert {
  return { code, severity: "critical", operatorId };
}

function trustMatches(
  config: ZkIdentityStatusFleetConfig,
  health: ZkIdentityStatusOperatorHealth,
  artifact: ZkIdentityStatusOperatorArtifact,
): boolean {
  const snapshot = artifact.attestation.snapshot;
  return (
    health.chainId === String(config.chainId) &&
    health.issuanceRegistry.toLowerCase() === config.issuanceRegistry.toLowerCase() &&
    health.issuerKeyId === config.issuerKeyId &&
    snapshot.chainId === String(config.chainId) &&
    snapshot.issuanceRegistry.toLowerCase() === config.issuanceRegistry.toLowerCase() &&
    snapshot.issuerKeyId === config.issuerKeyId
  );
}

/**
 * Independently validate every configured operator. Any unavailable, stale,
 * lagging, divergent, or malformed operator blocks publication.
 */
export async function evaluateZkIdentityStatusOperatorFleet(input: {
  config: ZkIdentityStatusFleetConfig;
  fetched: readonly FetchedZkIdentityStatusOperator[];
  referenceFinalizedBlock?: { number: bigint; hash: Hex };
  observedAt?: Date;
}): Promise<ZkIdentityStatusFleetReport> {
  const observedAtDate = input.observedAt ?? new Date();
  const observedAt = observedAtDate.toISOString();
  const observedAtMs = observedAtDate.getTime();
  const alerts: ZkIdentityStatusFleetAlert[] = [];
  const accepted: AcceptedOperator[] = [];
  const fetchedById = new Map(input.fetched.map((value) => [value.operatorId, value]));
  if (fetchedById.size !== input.fetched.length) {
    alerts.push(alert("MALFORMED_OPERATOR_RESPONSE", null));
  }

  for (const expected of input.config.operators) {
    const fetched = fetchedById.get(expected.operatorId);
    if (fetched?.health === undefined || fetched.latest === undefined) {
      alerts.push(alert("OPERATOR_UNAVAILABLE", expected.operatorId));
      continue;
    }
    let health: ZkIdentityStatusOperatorHealth;
    let artifact: ZkIdentityStatusOperatorArtifact;
    try {
      health = parseZkIdentityStatusOperatorHealth(fetched.health);
      artifact = parseZkIdentityStatusOperatorArtifact(fetched.latest);
    } catch {
      alerts.push(alert("MALFORMED_OPERATOR_RESPONSE", expected.operatorId));
      continue;
    }
    if (
      fetched.immutableArtifact === undefined ||
      fetched.immutableCacheControl === undefined ||
      !fetched.immutableCacheControl
        .split(",")
        .map((directive) => directive.trim().toLowerCase())
        .includes("immutable")
    ) {
      alerts.push(alert("IMMUTABLE_ARTIFACT_UNAVAILABLE", expected.operatorId));
      continue;
    }
    try {
      const immutable = parseZkIdentityStatusOperatorArtifact(fetched.immutableArtifact);
      if (
        serializeZkIdentityStatusOperatorArtifact(immutable) !==
        serializeZkIdentityStatusOperatorArtifact(artifact)
      ) {
        alerts.push(alert("IMMUTABLE_ARTIFACT_MISMATCH", expected.operatorId));
        continue;
      }
    } catch {
      alerts.push(alert("IMMUTABLE_ARTIFACT_MISMATCH", expected.operatorId));
      continue;
    }
    if (
      health.operatorId !== expected.operatorId ||
      artifact.operatorId !== expected.operatorId ||
      getAddress(health.signerAddress) !== getAddress(expected.signerAddress) ||
      !trustMatches(input.config, health, artifact)
    ) {
      alerts.push(alert("OPERATOR_TRUST_MISMATCH", expected.operatorId));
      continue;
    }
    const heartbeatMs = new Date(health.observedAt).getTime();
    if (heartbeatMs > observedAtMs + 60_000) {
      alerts.push(alert("OPERATOR_CLOCK_SKEW", expected.operatorId));
      continue;
    }
    if (observedAtMs - heartbeatMs > input.config.maxHeartbeatAgeSeconds * 1_000) {
      alerts.push(alert("HEARTBEAT_STALE", expected.operatorId));
      continue;
    }
    if (health.state !== "healthy") {
      alerts.push(alert("OPERATOR_DEGRADED", expected.operatorId));
      continue;
    }
    if (
      health.checkpoint.snapshotHash !== artifact.attestation.snapshotHash ||
      health.checkpoint.sourceBlockNumber !== artifact.attestation.snapshot.sourceBlockNumber ||
      health.checkpoint.sourceBlockHash !== artifact.attestation.snapshot.sourceBlockHash ||
      health.checkpoint.root !== artifact.attestation.snapshot.root ||
      health.checkpoint.nextStatusId !== artifact.attestation.snapshot.nextStatusId
    ) {
      alerts.push(alert("LATEST_HEALTH_MISMATCH", expected.operatorId));
      continue;
    }
    let signer: Address;
    try {
      signer = getAddress(
        await recoverZkIdentityPackedStatusAttestationSigner(artifact.attestation),
      );
    } catch {
      alerts.push(alert("SIGNATURE_SET_INVALID", expected.operatorId));
      continue;
    }
    if (signer !== getAddress(expected.signerAddress)) {
      alerts.push(alert("OPERATOR_TRUST_MISMATCH", expected.operatorId));
      continue;
    }
    accepted.push({
      operatorId: expected.operatorId,
      health,
      artifact,
      attestation: artifact.attestation,
      signer,
      sourceBlock: BigInt(artifact.attestation.snapshot.sourceBlockNumber),
    });
  }

  const highestBlock = accepted.reduce(
    (highest, operator) => (operator.sourceBlock > highest ? operator.sourceBlock : highest),
    0n,
  );
  if (
    input.referenceFinalizedBlock === undefined ||
    typeof input.referenceFinalizedBlock.number !== "bigint" ||
    input.referenceFinalizedBlock.number < 0n ||
    !isHex(input.referenceFinalizedBlock.hash) ||
    size(input.referenceFinalizedBlock.hash) !== 32 ||
    BigInt(input.referenceFinalizedBlock.hash) === 0n
  ) {
    alerts.push(alert("REFERENCE_RPC_UNAVAILABLE", null));
  } else {
    const reference = input.referenceFinalizedBlock;
    if (reference.number < highestBlock) {
      alerts.push(alert("REFERENCE_RPC_BEHIND", null));
    } else if (
      reference.number === highestBlock &&
      accepted.some(
        ({ sourceBlock, attestation }) =>
          sourceBlock === reference.number &&
          attestation.snapshot.sourceBlockHash !== reference.hash,
      )
    ) {
      alerts.push(alert("SNAPSHOT_DIVERGENCE", null));
    } else if (reference.number - highestBlock > BigInt(input.config.maxBlockLag)) {
      alerts.push(alert("WITHHOLDING_SUSPECTED", null));
    }
  }
  for (const operator of accepted) {
    if (highestBlock - operator.sourceBlock > BigInt(input.config.maxBlockLag)) {
      alerts.push(alert("WITHHOLDING_SUSPECTED", operator.operatorId));
    }
  }

  const hashesByBlock = new Map<string, Set<Hex>>();
  for (const operator of accepted) {
    const block = operator.sourceBlock.toString();
    const hashes = hashesByBlock.get(block) ?? new Set<Hex>();
    hashes.add(operator.attestation.snapshotHash);
    hashesByBlock.set(block, hashes);
  }
  for (const hashes of hashesByBlock.values()) {
    if (hashes.size > 1) alerts.push(alert("SNAPSHOT_DIVERGENCE", null));
  }

  const groups = new Map<Hex, AcceptedOperator[]>();
  for (const operator of accepted) {
    const group = groups.get(operator.attestation.snapshotHash) ?? [];
    group.push(operator);
    groups.set(operator.attestation.snapshotHash, group);
  }
  const candidates = [...groups.values()]
    .filter((group) => group.length >= input.config.threshold)
    .sort((left, right) =>
      left[0]!.sourceBlock === right[0]!.sourceBlock
        ? 0
        : left[0]!.sourceBlock > right[0]!.sourceBlock
          ? -1
          : 1,
    );
  const candidateGroup = candidates[0];
  if (candidateGroup === undefined) alerts.push(alert("QUORUM_UNAVAILABLE", null));

  let candidate: ZkIdentityStatusFleetReport["candidate"] = null;
  let publication: ZkIdentityStatusFleetReport["publication"] = null;
  if (candidateGroup !== undefined) {
    try {
      const reconciled = await reconcileZkIdentityPackedStatusSnapshots({
        attestations: candidateGroup.map(({ attestation }) => attestation),
        expectedReconcilers: input.config.operators.map(({ signerAddress }) => signerAddress),
        threshold: input.config.threshold,
      });
      candidate = {
        sourceBlockNumber: reconciled.snapshot.sourceBlockNumber,
        sourceBlockHash: reconciled.snapshot.sourceBlockHash,
        snapshotHash: reconciled.snapshotHash,
        signers: reconciled.signers,
      };
      const normalized = reconciledZkIdentityStatusPublication(reconciled);
      publication = {
        issuerKeyId: normalized.issuerKeyId,
        expectedNextStatusId: normalized.expectedNextStatusId.toString(),
        root: normalized.root,
      };
    } catch {
      alerts.push(alert("SIGNATURE_SET_INVALID", null));
    }
  }

  const ready = alerts.length === 0 && candidate !== null && publication !== null;
  return {
    schema: ZK_IDENTITY_STATUS_FLEET_REPORT_SCHEMA,
    observedAt,
    ready,
    alerts,
    candidate: ready ? candidate : null,
    publication: ready ? publication : null,
  };
}

async function fetchBoundedJson(
  url: string,
  timeoutMs: number,
  acceptedStatuses: readonly number[],
): Promise<{ value: unknown; cacheControl: string }> {
  const response = await fetch(url, {
    method: "GET",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(timeoutMs),
    redirect: "error",
  });
  if (!acceptedStatuses.includes(response.status)) {
    throw new Error("status operator endpoint is unavailable");
  }
  if (!(response.headers.get("content-type") ?? "").toLowerCase().startsWith("application/json")) {
    throw new Error("status operator endpoint returned the wrong content type");
  }
  const declared = response.headers.get("content-length");
  if (declared !== null && Number(declared) > 2 * 1024 * 1024) {
    throw new Error("status operator response is too large");
  }
  if (response.body === null) throw new Error("status operator response body is missing");
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > 2 * 1024 * 1024) {
      await reader.cancel();
      throw new Error("status operator response is too large");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return {
    value: JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(body)),
    cacheControl: response.headers.get("cache-control") ?? "",
  };
}

export async function fetchZkIdentityStatusOperatorFleet(
  config: ZkIdentityStatusFleetConfig,
): Promise<FetchedZkIdentityStatusOperator[]> {
  return Promise.all(
    config.operators.map(async (operator) => {
      try {
        const [healthResponse, latestResponse] = await Promise.all([
          fetchBoundedJson(`${operator.baseUrl}/healthz`, config.requestTimeoutMs, [200, 503]),
          fetchBoundedJson(`${operator.baseUrl}/latest`, config.requestTimeoutMs, [200]),
        ]);
        const result: FetchedZkIdentityStatusOperator = {
          operatorId: operator.operatorId,
          health: healthResponse.value,
          latest: latestResponse.value,
        };
        try {
          const latest = parseZkIdentityStatusOperatorArtifact(latestResponse.value);
          const immutableResponse = await fetchBoundedJson(
            `${operator.baseUrl}/artifacts/${latest.attestation.snapshotHash}`,
            config.requestTimeoutMs,
            [200],
          );
          result.immutableArtifact = immutableResponse.value;
          result.immutableCacheControl = immutableResponse.cacheControl;
        } catch {
          // Preserve health/latest so evaluation emits the specific immutable
          // artifact failure without trusting transport error text.
        }
        return result;
      } catch {
        return { operatorId: operator.operatorId };
      }
    }),
  );
}
