import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { link, mkdir, open, readFile, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import { isHex, size, type Hex } from "viem";
import {
  parseZkIdentityStatusFleetConfig,
  type ZkIdentityStatusFleetConfig,
} from "./config";
import {
  evaluateZkIdentityStatusOperatorFleet,
  type FetchedZkIdentityStatusOperator,
  type ZkIdentityStatusFleetReport,
} from "./fleet";

export const ZK_IDENTITY_STATUS_TESTNET_EVIDENCE_SCHEMA =
  "org.proofofhumanity.v2-packed-status-testnet-evidence/1" as const;

interface PublicFleetConfig {
  schema: ZkIdentityStatusFleetConfig["schema"];
  chainId: number;
  issuanceRegistry: ZkIdentityStatusFleetConfig["issuanceRegistry"];
  issuerKeyId: Hex;
  threshold: number;
  maxHeartbeatAgeSeconds: number;
  maxBlockLag: number;
  operators: ZkIdentityStatusFleetConfig["operators"];
}

interface EvidenceOperator {
  operatorId: string;
  health: unknown | null;
  latest: unknown | null;
  immutableArtifact: unknown | null;
  immutableCacheControl: string | null;
}

export interface ZkIdentityStatusTestnetEvidence {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_EVIDENCE_SCHEMA;
  fleet: PublicFleetConfig;
  referenceFinalizedBlock: null | { number: string; hash: Hex };
  operators: EvidenceOperator[];
  report: ZkIdentityStatusFleetReport;
  evidenceSha256: Hex;
}

const evidenceKeys = [
  "schema",
  "fleet",
  "referenceFinalizedBlock",
  "operators",
  "report",
  "evidenceSha256",
] as const;
const fleetKeys = [
  "schema",
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "threshold",
  "maxHeartbeatAgeSeconds",
  "maxBlockLag",
  "operators",
] as const;
const evidenceOperatorKeys = [
  "operatorId",
  "health",
  "latest",
  "immutableArtifact",
  "immutableCacheControl",
] as const;
const referenceKeys = ["number", "hash"] as const;

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

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const entries = Object.entries(value as Record<string, unknown>)
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([key, nested]) => `${JSON.stringify(key)}:${canonicalJson(nested)}`);
  return `{${entries.join(",")}}`;
}

function sha256(value: unknown): Hex {
  return `0x${createHash("sha256").update(canonicalJson(value)).digest("hex")}`;
}

function publicFleet(config: ZkIdentityStatusFleetConfig): PublicFleetConfig {
  const parsed = parseZkIdentityStatusFleetConfig(config);
  return {
    schema: parsed.schema,
    chainId: parsed.chainId,
    issuanceRegistry: parsed.issuanceRegistry,
    issuerKeyId: parsed.issuerKeyId,
    threshold: parsed.threshold,
    maxHeartbeatAgeSeconds: parsed.maxHeartbeatAgeSeconds,
    maxBlockLag: parsed.maxBlockLag,
    operators: parsed.operators,
  };
}

function evaluationConfig(value: unknown): ZkIdentityStatusFleetConfig {
  const candidate = object(value, "status evidence fleet trust");
  exactKeys(candidate, fleetKeys, "status evidence fleet trust");
  return parseZkIdentityStatusFleetConfig({
    ...candidate,
    // RPC credentials and project paths are intentionally excluded from the
    // public evidence bundle. The captured finalized header is the evidence.
    referenceRpcUrl: "https://redacted.invalid",
    requestTimeoutMs: 1,
  });
}

function normalizedEvidenceOperators(
  values: readonly FetchedZkIdentityStatusOperator[],
): EvidenceOperator[] {
  return values.map((value) => ({
    operatorId: value.operatorId,
    health: value.health ?? null,
    latest: value.latest ?? null,
    immutableArtifact: value.immutableArtifact ?? null,
    immutableCacheControl: value.immutableCacheControl ?? null,
  }));
}

function fetchedFromEvidence(values: readonly EvidenceOperator[]): FetchedZkIdentityStatusOperator[] {
  return values.map((value) => ({
    operatorId: value.operatorId,
    ...(value.health === null ? {} : { health: value.health }),
    ...(value.latest === null ? {} : { latest: value.latest }),
    ...(value.immutableArtifact === null
      ? {}
      : { immutableArtifact: value.immutableArtifact }),
    ...(value.immutableCacheControl === null
      ? {}
      : { immutableCacheControl: value.immutableCacheControl }),
  }));
}

function evidencePayload(value: Omit<ZkIdentityStatusTestnetEvidence, "evidenceSha256">) {
  return {
    schema: value.schema,
    fleet: value.fleet,
    referenceFinalizedBlock: value.referenceFinalizedBlock,
    operators: value.operators,
    report: value.report,
  };
}

/** Create one self-contained, secretless fleet observation for archival. */
export async function createZkIdentityStatusTestnetEvidence(input: {
  config: ZkIdentityStatusFleetConfig;
  fetched: readonly FetchedZkIdentityStatusOperator[];
  referenceFinalizedBlock?: { number: bigint; hash: Hex };
  observedAt?: Date;
}): Promise<ZkIdentityStatusTestnetEvidence> {
  const fleet = publicFleet(input.config);
  const report = await evaluateZkIdentityStatusOperatorFleet({
    config: input.config,
    fetched: input.fetched,
    referenceFinalizedBlock: input.referenceFinalizedBlock,
    observedAt: input.observedAt,
  });
  const payload = {
    schema: ZK_IDENTITY_STATUS_TESTNET_EVIDENCE_SCHEMA,
    fleet,
    referenceFinalizedBlock:
      input.referenceFinalizedBlock === undefined
        ? null
        : {
            number: input.referenceFinalizedBlock.number.toString(),
            hash: input.referenceFinalizedBlock.hash,
          },
    operators: normalizedEvidenceOperators(input.fetched),
    report,
  } satisfies Omit<ZkIdentityStatusTestnetEvidence, "evidenceSha256">;
  return { ...payload, evidenceSha256: sha256(evidencePayload(payload)) };
}

/** Verify checksum, strict trust metadata, signatures, artifacts, and the reproduced fleet decision. */
export async function verifyZkIdentityStatusTestnetEvidence(
  value: unknown,
): Promise<ZkIdentityStatusTestnetEvidence> {
  const candidate = object(value, "status testnet evidence");
  exactKeys(candidate, evidenceKeys, "status testnet evidence");
  if (candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_EVIDENCE_SCHEMA) {
    throw new Error("unsupported status testnet evidence schema");
  }
  if (
    typeof candidate.evidenceSha256 !== "string" ||
    !isHex(candidate.evidenceSha256) ||
    size(candidate.evidenceSha256) !== 32
  ) {
    throw new Error("status testnet evidence SHA-256 must be bytes32");
  }
  const rawPayload = {
    schema: candidate.schema,
    fleet: candidate.fleet,
    referenceFinalizedBlock: candidate.referenceFinalizedBlock,
    operators: candidate.operators,
    report: candidate.report,
  };
  if (sha256(rawPayload) !== candidate.evidenceSha256.toLowerCase()) {
    throw new Error("status testnet evidence SHA-256 mismatch");
  }

  const config = evaluationConfig(candidate.fleet);
  if (!Array.isArray(candidate.operators)) {
    throw new Error("status testnet evidence operators must be an array");
  }
  const operators = candidate.operators.map((value) => {
    const operator = object(value, "status testnet evidence operator");
    exactKeys(operator, evidenceOperatorKeys, "status testnet evidence operator");
    if (
      typeof operator.operatorId !== "string" ||
      !/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/u.test(operator.operatorId) ||
      (operator.immutableCacheControl !== null &&
        typeof operator.immutableCacheControl !== "string")
    ) {
      throw new Error("status testnet evidence operator metadata is invalid");
    }
    return operator as unknown as EvidenceOperator;
  });

  let referenceFinalizedBlock: { number: bigint; hash: Hex } | undefined;
  if (candidate.referenceFinalizedBlock !== null) {
    const reference = object(
      candidate.referenceFinalizedBlock,
      "status testnet evidence reference block",
    );
    exactKeys(reference, referenceKeys, "status testnet evidence reference block");
    if (
      typeof reference.number !== "string" ||
      !/^(0|[1-9][0-9]*)$/u.test(reference.number) ||
      typeof reference.hash !== "string" ||
      !isHex(reference.hash) ||
      size(reference.hash) !== 32 ||
      BigInt(reference.hash) === 0n
    ) {
      throw new Error("status testnet evidence reference block is invalid");
    }
    referenceFinalizedBlock = {
      number: BigInt(reference.number),
      hash: reference.hash.toLowerCase() as Hex,
    };
  }

  const report = object(candidate.report, "status testnet evidence fleet report");
  if (typeof report.observedAt !== "string") {
    throw new Error("status testnet evidence observation time is invalid");
  }
  const observedAt = new Date(report.observedAt);
  if (!Number.isFinite(observedAt.getTime()) || observedAt.toISOString() !== report.observedAt) {
    throw new Error("status testnet evidence observation time is not canonical");
  }
  const reproduced = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: fetchedFromEvidence(operators),
    referenceFinalizedBlock,
    observedAt,
  });
  if (canonicalJson(reproduced) !== canonicalJson(candidate.report)) {
    throw new Error("status testnet evidence fleet report cannot be reproduced");
  }
  return candidate as unknown as ZkIdentityStatusTestnetEvidence;
}

async function syncDirectory(path: string): Promise<void> {
  const handle = await open(path, constants.O_RDONLY);
  try {
    await handle.sync();
  } catch (error) {
    const code =
      error !== null && typeof error === "object" && "code" in error
        ? (error as { code?: unknown }).code
        : undefined;
    if (code !== "EINVAL" && code !== "ENOTSUP") throw error;
  } finally {
    await handle.close();
  }
}

/** Write a new evidence file atomically and refuse to replace prior evidence. */
export async function writeZkIdentityStatusTestnetEvidence(
  path: string,
  evidence: unknown,
): Promise<void> {
  if (!isAbsolute(path)) throw new Error("status testnet evidence path must be absolute");
  const verified = await verifyZkIdentityStatusTestnetEvidence(evidence);
  const directory = dirname(path);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = join(directory, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(temporary, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    await handle.writeFile(`${JSON.stringify(verified)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    handle = undefined;
    try {
      await link(temporary, path);
    } catch (error) {
      const code =
        error !== null && typeof error === "object" && "code" in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (code !== "EEXIST") throw error;
      throw Object.assign(new Error("status testnet evidence already exists"), {
        code: "EVIDENCE_ALREADY_EXISTS",
      });
    }
    await unlink(temporary);
    await syncDirectory(directory);
  } catch (error) {
    if (handle !== undefined) await handle.close().catch(() => undefined);
    await unlink(temporary).catch(() => undefined);
    throw error;
  }
}

export async function readZkIdentityStatusTestnetEvidence(
  path: string,
): Promise<ZkIdentityStatusTestnetEvidence> {
  if (!isAbsolute(path)) throw new Error("status testnet evidence path must be absolute");
  return verifyZkIdentityStatusTestnetEvidence(JSON.parse(await readFile(path, "utf8")));
}
