import {
  parseZkIdentityPackedStatusAttestation,
  type ZkIdentityPackedStatusAttestation,
} from "@ubi2/sdk";
import { getAddress, isAddress, isHex, size, type Address, type Hex } from "viem";

export const ZK_IDENTITY_STATUS_OPERATOR_ARTIFACT_SCHEMA =
  "org.proofofhumanity.v2-packed-status-operator-artifact/1" as const;
export const ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA =
  "org.proofofhumanity.v2-packed-status-operator-health/1" as const;

export type ZkIdentityStatusOperatorState = "healthy" | "degraded";

export interface ZkIdentityStatusOperatorArtifact {
  schema: typeof ZK_IDENTITY_STATUS_OPERATOR_ARTIFACT_SCHEMA;
  operatorId: string;
  attestation: ZkIdentityPackedStatusAttestation;
}

export interface ZkIdentityStatusOperatorCheckpointSummary {
  sourceBlockNumber: string;
  sourceBlockHash: Hex;
  snapshotHash: Hex;
  root: Hex;
  nextStatusId: number;
}

export interface ZkIdentityStatusOperatorHealth {
  schema: typeof ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA;
  operatorId: string;
  state: ZkIdentityStatusOperatorState;
  observedAt: string;
  consecutiveFailures: number;
  chainId: string;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  signerAddress: Address;
  checkpoint: ZkIdentityStatusOperatorCheckpointSummary;
  errorCode: string | null;
}

const artifactKeys = ["schema", "operatorId", "attestation"] as const;
const healthKeys = [
  "schema",
  "operatorId",
  "state",
  "observedAt",
  "consecutiveFailures",
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "signerAddress",
  "checkpoint",
  "errorCode",
] as const;
const checkpointKeys = [
  "sourceBlockNumber",
  "sourceBlockHash",
  "snapshotHash",
  "root",
  "nextStatusId",
] as const;

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${label} contains missing or unknown fields`);
  }
}

export function canonicalOperatorId(value: unknown): string {
  if (typeof value !== "string" || !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u.test(value)) {
    throw new Error("status operator id must be a lowercase DNS-style label");
  }
  return value;
}

function canonicalDecimal(value: unknown, label: string, nonZero = false): string {
  if (
    typeof value !== "string" ||
    value.length > 20 ||
    !/^(0|[1-9][0-9]*)$/u.test(value)
  ) {
    throw new Error(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > 0xffff_ffff_ffff_ffffn || (nonZero && parsed === 0n)) {
    throw new Error(`${label} must fit the supported uint64 range`);
  }
  return value;
}

function canonicalBytes32(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32) {
    throw new Error(`${label} must be bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function canonicalAddress(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${label} must be a non-zero EVM address`);
  }
  return getAddress(value);
}

function canonicalTimestamp(value: unknown): string {
  if (typeof value !== "string") throw new Error("status operator timestamp must be a string");
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error("status operator timestamp must be canonical ISO-8601 UTC");
  }
  return value;
}

export function parseZkIdentityStatusOperatorArtifact(
  value: unknown,
): ZkIdentityStatusOperatorArtifact {
  const candidate = object(value, "status operator artifact");
  exactKeys(candidate, artifactKeys, "status operator artifact");
  if (candidate.schema !== ZK_IDENTITY_STATUS_OPERATOR_ARTIFACT_SCHEMA) {
    throw new Error("unsupported status operator artifact schema");
  }
  return {
    schema: ZK_IDENTITY_STATUS_OPERATOR_ARTIFACT_SCHEMA,
    operatorId: canonicalOperatorId(candidate.operatorId),
    attestation: parseZkIdentityPackedStatusAttestation(candidate.attestation),
  };
}

export function serializeZkIdentityStatusOperatorArtifact(value: unknown): string {
  return JSON.stringify(parseZkIdentityStatusOperatorArtifact(value));
}

export function parseZkIdentityStatusOperatorHealth(
  value: unknown,
): ZkIdentityStatusOperatorHealth {
  const candidate = object(value, "status operator health");
  exactKeys(candidate, healthKeys, "status operator health");
  if (candidate.schema !== ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA) {
    throw new Error("unsupported status operator health schema");
  }
  if (candidate.state !== "healthy" && candidate.state !== "degraded") {
    throw new Error("status operator health state is unsupported");
  }
  if (
    typeof candidate.consecutiveFailures !== "number" ||
    !Number.isSafeInteger(candidate.consecutiveFailures) ||
    candidate.consecutiveFailures < 0
  ) {
    throw new Error("status operator failure count must be a non-negative safe integer");
  }
  if (
    candidate.errorCode !== null &&
    (typeof candidate.errorCode !== "string" || !/^[A-Z0-9_]{1,64}$/u.test(candidate.errorCode))
  ) {
    throw new Error("status operator error code is invalid");
  }
  if (
    (candidate.state === "healthy" &&
      (candidate.consecutiveFailures !== 0 || candidate.errorCode !== null)) ||
    (candidate.state === "degraded" &&
      (candidate.consecutiveFailures === 0 || candidate.errorCode === null))
  ) {
    throw new Error("status operator health state and failure metadata do not agree");
  }
  const checkpoint = object(candidate.checkpoint, "status operator checkpoint summary");
  exactKeys(checkpoint, checkpointKeys, "status operator checkpoint summary");
  if (
    typeof checkpoint.nextStatusId !== "number" ||
    !Number.isSafeInteger(checkpoint.nextStatusId) ||
    checkpoint.nextStatusId <= 0
  ) {
    throw new Error("status operator next status id must be a positive safe integer");
  }
  return {
    schema: ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA,
    operatorId: canonicalOperatorId(candidate.operatorId),
    state: candidate.state,
    observedAt: canonicalTimestamp(candidate.observedAt),
    consecutiveFailures: candidate.consecutiveFailures,
    chainId: canonicalDecimal(candidate.chainId, "status operator chain id", true),
    issuanceRegistry: canonicalAddress(candidate.issuanceRegistry, "status operator registry"),
    issuerKeyId: canonicalBytes32(candidate.issuerKeyId, "status operator issuer key id"),
    signerAddress: canonicalAddress(candidate.signerAddress, "status operator signer"),
    checkpoint: {
      sourceBlockNumber: canonicalDecimal(
        checkpoint.sourceBlockNumber,
        "status operator source block number",
      ),
      sourceBlockHash: canonicalBytes32(
        checkpoint.sourceBlockHash,
        "status operator source block hash",
      ),
      snapshotHash: canonicalBytes32(checkpoint.snapshotHash, "status operator snapshot hash"),
      root: canonicalBytes32(checkpoint.root, "status operator root"),
      nextStatusId: checkpoint.nextStatusId,
    },
    errorCode: candidate.errorCode,
  };
}

export function serializeZkIdentityStatusOperatorHealth(value: unknown): string {
  return JSON.stringify(parseZkIdentityStatusOperatorHealth(value));
}
