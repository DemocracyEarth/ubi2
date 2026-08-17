import { readFile } from "node:fs/promises";
import { isAbsolute } from "node:path";
import { canonicalOperatorId } from "./artifact";
import {
  parseZkIdentityStatusFleetConfig,
  type ZkIdentityStatusFleetConfig,
} from "./config";
import {
  readZkIdentityStatusTestnetEvidenceAgainstFleet,
  type ZkIdentityStatusTestnetEvidence,
} from "./evidence";
import type { ZkIdentityStatusFleetAlertCode } from "./fleet";

export const ZK_IDENTITY_STATUS_TESTNET_DRILL_MANIFEST_SCHEMA =
  "org.proofofhumanity.v2-packed-status-testnet-drill-manifest/1" as const;
export const ZK_IDENTITY_STATUS_TESTNET_DRILL_REPORT_SCHEMA =
  "org.proofofhumanity.v2-packed-status-testnet-drill-report/1" as const;

export interface ZkIdentityStatusTestnetRestartEvidencePaths {
  operatorId: string;
  before: string;
  after: string;
}

export interface ZkIdentityStatusTestnetBlockedEvidencePaths {
  before: string;
  blocked: string;
  after: string;
}

export interface ZkIdentityStatusTestnetDrillManifest {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_DRILL_MANIFEST_SCHEMA;
  restarts: ZkIdentityStatusTestnetRestartEvidencePaths[];
  withholding: ZkIdentityStatusTestnetBlockedEvidencePaths;
  divergence: ZkIdentityStatusTestnetBlockedEvidencePaths;
}

export interface ZkIdentityStatusTestnetDrillReport {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_DRILL_REPORT_SCHEMA;
  intrinsicEvidenceValid: true;
  fleet: {
    chainId: number;
    issuanceRegistry: ZkIdentityStatusFleetConfig["issuanceRegistry"];
    issuerKeyId: ZkIdentityStatusFleetConfig["issuerKeyId"];
  };
  restarts: Array<{
    operatorId: string;
    beforeEvidenceSha256: ZkIdentityStatusTestnetEvidence["evidenceSha256"];
    afterEvidenceSha256: ZkIdentityStatusTestnetEvidence["evidenceSha256"];
  }>;
  withholding: {
    beforeEvidenceSha256: ZkIdentityStatusTestnetEvidence["evidenceSha256"];
    blockedEvidenceSha256: ZkIdentityStatusTestnetEvidence["evidenceSha256"];
    afterEvidenceSha256: ZkIdentityStatusTestnetEvidence["evidenceSha256"];
    observedAlertCodes: ZkIdentityStatusFleetAlertCode[];
  };
  divergence: {
    beforeEvidenceSha256: ZkIdentityStatusTestnetEvidence["evidenceSha256"];
    blockedEvidenceSha256: ZkIdentityStatusTestnetEvidence["evidenceSha256"];
    afterEvidenceSha256: ZkIdentityStatusTestnetEvidence["evidenceSha256"];
    observedAlertCodes: ZkIdentityStatusFleetAlertCode[];
  };
  externalChecksRequired: [
    "EVIDENCE_ARCHIVE_TIMESTAMPS",
    "RESTART_SERVICE_RESULTS_AND_SINGLE_WRITER",
    "WITHHOLDING_FAULT_ACTION",
    "WITHHOLDING_PAGE_ACKNOWLEDGEMENT",
    "DIVERGENCE_FAULT_ISOLATION",
    "DIVERGENCE_PAGE_ACKNOWLEDGEMENT",
  ];
}

const manifestKeys = ["schema", "restarts", "withholding", "divergence"] as const;
const restartKeys = ["operatorId", "before", "after"] as const;
const blockedKeys = ["before", "blocked", "after"] as const;
const withholdingAlerts = new Set<ZkIdentityStatusFleetAlertCode>([
  "WITHHOLDING_SUSPECTED",
  "HEARTBEAT_STALE",
  "OPERATOR_UNAVAILABLE",
]);

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

function evidencePath(value: unknown, label: string): string {
  if (typeof value !== "string" || !isAbsolute(value)) {
    throw new Error(`${label} must be an absolute path`);
  }
  return value;
}

function parseBlockedPaths(
  value: unknown,
  label: string,
): ZkIdentityStatusTestnetBlockedEvidencePaths {
  const candidate = object(value, label);
  exactKeys(candidate, blockedKeys, label);
  const paths = {
    before: evidencePath(candidate.before, `${label} before evidence`),
    blocked: evidencePath(candidate.blocked, `${label} blocked evidence`),
    after: evidencePath(candidate.after, `${label} after evidence`),
  };
  if (new Set(Object.values(paths)).size !== 3) {
    throw new Error(`${label} must reference three distinct evidence files`);
  }
  return paths;
}

export function parseZkIdentityStatusTestnetDrillManifest(
  value: unknown,
): ZkIdentityStatusTestnetDrillManifest {
  const candidate = object(value, "status testnet drill manifest");
  exactKeys(candidate, manifestKeys, "status testnet drill manifest");
  if (candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_DRILL_MANIFEST_SCHEMA) {
    throw new Error("unsupported status testnet drill manifest schema");
  }
  if (!Array.isArray(candidate.restarts) || candidate.restarts.length < 2) {
    throw new Error("status testnet drill manifest requires at least two restart observations");
  }
  const restarts = candidate.restarts.map((value) => {
    const restart = object(value, "status testnet restart evidence");
    exactKeys(restart, restartKeys, "status testnet restart evidence");
    const parsed = {
      operatorId: canonicalOperatorId(restart.operatorId),
      before: evidencePath(restart.before, "status testnet restart before evidence"),
      after: evidencePath(restart.after, "status testnet restart after evidence"),
    };
    if (parsed.before === parsed.after) {
      throw new Error("status testnet restart must reference distinct evidence files");
    }
    return parsed;
  });
  if (new Set(restarts.map(({ operatorId }) => operatorId)).size !== restarts.length) {
    throw new Error("status testnet restart operator ids must be distinct");
  }
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_DRILL_MANIFEST_SCHEMA,
    restarts,
    withholding: parseBlockedPaths(candidate.withholding, "status testnet withholding evidence"),
    divergence: parseBlockedPaths(candidate.divergence, "status testnet divergence evidence"),
  };
}

function observedAt(evidence: ZkIdentityStatusTestnetEvidence): number {
  return new Date(evidence.report.observedAt).getTime();
}

function requireReady(
  evidence: ZkIdentityStatusTestnetEvidence,
  label: string,
): asserts evidence is ZkIdentityStatusTestnetEvidence & {
  report: ZkIdentityStatusTestnetEvidence["report"] & {
    ready: true;
    candidate: NonNullable<ZkIdentityStatusTestnetEvidence["report"]["candidate"]>;
    publication: NonNullable<ZkIdentityStatusTestnetEvidence["report"]["publication"]>;
  };
} {
  if (
    !evidence.report.ready ||
    evidence.report.candidate === null ||
    evidence.report.publication === null
  ) {
    throw new Error(`${label} must be a ready fleet observation`);
  }
}

function requireReadyTransition(
  before: ZkIdentityStatusTestnetEvidence,
  after: ZkIdentityStatusTestnetEvidence,
  label: string,
): void {
  requireReady(before, `${label} before evidence`);
  requireReady(after, `${label} after evidence`);
  if (observedAt(after) <= observedAt(before)) {
    throw new Error(`${label} after evidence must be observed later than before evidence`);
  }
  const beforeBlock = BigInt(before.report.candidate.sourceBlockNumber);
  const afterBlock = BigInt(after.report.candidate.sourceBlockNumber);
  if (afterBlock < beforeBlock) {
    throw new Error(`${label} recovery cannot regress the reconciled source block`);
  }
  if (
    afterBlock === beforeBlock &&
    after.report.candidate.snapshotHash !== before.report.candidate.snapshotHash
  ) {
    throw new Error(`${label} recovery cannot equivocate at the same source block`);
  }
}

function requireBlockedTransition(
  before: ZkIdentityStatusTestnetEvidence,
  blocked: ZkIdentityStatusTestnetEvidence,
  after: ZkIdentityStatusTestnetEvidence,
  expectedAlert: (code: ZkIdentityStatusFleetAlertCode) => boolean,
  label: string,
): ZkIdentityStatusFleetAlertCode[] {
  requireReadyTransition(before, after, label);
  if (
    blocked.report.ready ||
    blocked.report.candidate !== null ||
    blocked.report.publication !== null
  ) {
    throw new Error(`${label} blocked evidence must fail closed with no publication`);
  }
  if (!(observedAt(before) < observedAt(blocked) && observedAt(blocked) < observedAt(after))) {
    throw new Error(`${label} blocked evidence must be observed between ready observations`);
  }
  const codes = [...new Set(blocked.report.alerts.map(({ code }) => code))].sort();
  if (!codes.some(expectedAlert)) {
    throw new Error(`${label} blocked evidence does not contain the required alert`);
  }
  return codes;
}

export async function readZkIdentityStatusTestnetDrillManifest(
  path: string,
): Promise<ZkIdentityStatusTestnetDrillManifest> {
  if (!isAbsolute(path)) throw new Error("status testnet drill manifest path must be absolute");
  return parseZkIdentityStatusTestnetDrillManifest(JSON.parse(await readFile(path, "utf8")));
}

/**
 * Verify only the intrinsic, offline-checkable relationships between captured
 * drill observations. Host actions, fault isolation, and page acknowledgement
 * remain external checks and are always listed in the report.
 */
export async function verifyZkIdentityStatusTestnetDrillEvidence(input: {
  config: ZkIdentityStatusFleetConfig;
  manifest: ZkIdentityStatusTestnetDrillManifest;
}): Promise<ZkIdentityStatusTestnetDrillReport> {
  const config = parseZkIdentityStatusFleetConfig(input.config);
  const manifest = parseZkIdentityStatusTestnetDrillManifest(input.manifest);
  const configuredOperatorIds = config.operators.map(({ operatorId }) => operatorId).sort();
  const restartOperatorIds = manifest.restarts.map(({ operatorId }) => operatorId).sort();
  if (
    configuredOperatorIds.length !== restartOperatorIds.length ||
    configuredOperatorIds.some((operatorId, index) => operatorId !== restartOperatorIds[index])
  ) {
    throw new Error("status testnet drill must contain one restart for every configured operator");
  }

  const evidenceCache = new Map<string, Promise<ZkIdentityStatusTestnetEvidence>>();
  const load = (path: string): Promise<ZkIdentityStatusTestnetEvidence> => {
    const cached = evidenceCache.get(path);
    if (cached !== undefined) return cached;
    const pending = readZkIdentityStatusTestnetEvidenceAgainstFleet(path, config);
    evidenceCache.set(path, pending);
    return pending;
  };

  const restarts = await Promise.all(
    manifest.restarts.map(async ({ operatorId, before, after }) => {
      const [beforeEvidence, afterEvidence] = await Promise.all([load(before), load(after)]);
      requireReadyTransition(beforeEvidence, afterEvidence, `${operatorId} restart`);
      return {
        operatorId,
        beforeEvidenceSha256: beforeEvidence.evidenceSha256,
        afterEvidenceSha256: afterEvidence.evidenceSha256,
      };
    }),
  );

  const verifyBlocked = async (
    paths: ZkIdentityStatusTestnetBlockedEvidencePaths,
    expectedAlert: (code: ZkIdentityStatusFleetAlertCode) => boolean,
    label: string,
  ) => {
    const [before, blocked, after] = await Promise.all([
      load(paths.before),
      load(paths.blocked),
      load(paths.after),
    ]);
    return {
      beforeEvidenceSha256: before.evidenceSha256,
      blockedEvidenceSha256: blocked.evidenceSha256,
      afterEvidenceSha256: after.evidenceSha256,
      observedAlertCodes: requireBlockedTransition(
        before,
        blocked,
        after,
        expectedAlert,
        label,
      ),
    };
  };

  const [withholding, divergence] = await Promise.all([
    verifyBlocked(
      manifest.withholding,
      (code) => withholdingAlerts.has(code),
      "publication withholding",
    ),
    verifyBlocked(
      manifest.divergence,
      (code) => code === "SNAPSHOT_DIVERGENCE",
      "snapshot divergence",
    ),
  ]);

  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_DRILL_REPORT_SCHEMA,
    intrinsicEvidenceValid: true,
    fleet: {
      chainId: config.chainId,
      issuanceRegistry: config.issuanceRegistry,
      issuerKeyId: config.issuerKeyId,
    },
    restarts,
    withholding,
    divergence,
    externalChecksRequired: [
      "EVIDENCE_ARCHIVE_TIMESTAMPS",
      "RESTART_SERVICE_RESULTS_AND_SINGLE_WRITER",
      "WITHHOLDING_FAULT_ACTION",
      "WITHHOLDING_PAGE_ACKNOWLEDGEMENT",
      "DIVERGENCE_FAULT_ISOLATION",
      "DIVERGENCE_PAGE_ACKNOWLEDGEMENT",
    ],
  };
}
