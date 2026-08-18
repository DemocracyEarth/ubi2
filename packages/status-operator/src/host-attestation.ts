import { execFile } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { constants } from "node:fs";
import { access, link, lstat, mkdir, open, readFile, unlink } from "node:fs/promises";
import { basename, dirname, isAbsolute, join } from "node:path";
import { promisify } from "node:util";
import { getAddress, isAddress, isHex, size, type Address, type Hex } from "viem";
import {
  parseZkIdentityStatusOperatorConfig,
  type ZkIdentityStatusOperatorConfig,
} from "./config";
import {
  parseZkIdentityStatusTestnetTrustRecord,
  verifyZkIdentityStatusTestnetPreflightEvidence,
  type ZkIdentityStatusTestnetPreflightEvidence,
  type ZkIdentityStatusTestnetTrustOperator,
  type ZkIdentityStatusTestnetTrustRecord,
} from "./readiness";

export const ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-host-attestation/1" as const;
export const ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_REPORT_SCHEMA =
  "org.proofofhumanity.v2-canonical-testnet-host-attestation-report/1" as const;

const execute = promisify(execFile);
const SUBPROCESS_ENV: NodeJS.ProcessEnv = { LANG: "C", LC_ALL: "C" };

export type ZkIdentityStatusTestnetHostAttestationAlertCode =
  | "SOURCE_INSPECTION_FAILED"
  | "SOURCE_COMMIT_MISMATCH"
  | "SOURCE_TRACKED_CHANGES"
  | "OPERATOR_CONFIG_PERMISSIONS_INVALID"
  | "BUILDER_INTEGRITY_FAILED"
  | "CAST_INTEGRITY_FAILED"
  | "KEYSTORE_PERMISSIONS_INVALID"
  | "PASSWORD_FILE_PERMISSIONS_INVALID"
  | "SECRET_FILES_REUSED"
  | "KEYSTORE_ADDRESS_UNAVAILABLE"
  | "SIGNER_ADDRESS_MISMATCH";

export interface ZkIdentityStatusTestnetHostAttestationIdentity {
  preflightEvidenceSha256: Hex;
  network: string;
  chainId: number;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  operatorId: string;
  hostId: string;
  volumeId: string;
  signerAddress: Address;
  reviewedSourceCommit: string;
  builderSha256: Hex;
  castSha256: Hex;
}

export interface ZkIdentityStatusTestnetHostAttestationObservation {
  sourceCommit: string | null;
  sourceTrackedFilesClean: boolean | null;
  operatorConfigPrivate: boolean;
  builderSha256: Hex | null;
  castSha256: Hex | null;
  keystorePrivate: boolean;
  passwordFilePrivate: boolean;
  secretFilesDistinct: boolean | null;
  keystoreAddress: Address | null;
}

export interface ZkIdentityStatusTestnetHostAttestationReport {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_REPORT_SCHEMA;
  observedAt: string;
  ready: boolean;
  alerts: ZkIdentityStatusTestnetHostAttestationAlertCode[];
  externalChecksRequired: readonly [
    "PHYSICAL_HOST_VOLUME_PROVIDER_INDEPENDENCE",
    "AUTHORITATIVE_EVIDENCE_TIMESTAMP",
  ];
}

export interface ZkIdentityStatusTestnetHostAttestationEvidence {
  schema: typeof ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_SCHEMA;
  identity: ZkIdentityStatusTestnetHostAttestationIdentity;
  observation: ZkIdentityStatusTestnetHostAttestationObservation;
  report: ZkIdentityStatusTestnetHostAttestationReport;
  evidenceSha256: Hex;
}

export interface ZkIdentityStatusTestnetHostPrivateFileIdentity {
  device: string;
  inode: string;
}

export interface ZkIdentityStatusTestnetHostInspector {
  inspectSource(sourceDirectory: string): Promise<{
    commit: string;
    trackedFilesClean: boolean;
  }>;
  inspectExecutable(path: string): Promise<{ sha256: Hex }>;
  inspectPrivateFile(
    path: string,
    maximumBytes: number,
  ): Promise<ZkIdentityStatusTestnetHostPrivateFileIdentity>;
  resolveKeystoreAddress(input: {
    castPath: string;
    keystorePath: string;
    passwordFile: string;
  }): Promise<Address>;
}

const evidenceKeys = ["schema", "identity", "observation", "report", "evidenceSha256"] as const;
const identityKeys = [
  "preflightEvidenceSha256",
  "network",
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "operatorId",
  "hostId",
  "volumeId",
  "signerAddress",
  "reviewedSourceCommit",
  "builderSha256",
  "castSha256",
] as const;
const observationKeys = [
  "sourceCommit",
  "sourceTrackedFilesClean",
  "operatorConfigPrivate",
  "builderSha256",
  "castSha256",
  "keystorePrivate",
  "passwordFilePrivate",
  "secretFilesDistinct",
  "keystoreAddress",
] as const;
const reportKeys = ["schema", "observedAt", "ready", "alerts", "externalChecksRequired"] as const;
const alertCodes: readonly ZkIdentityStatusTestnetHostAttestationAlertCode[] = [
  "SOURCE_INSPECTION_FAILED",
  "SOURCE_COMMIT_MISMATCH",
  "SOURCE_TRACKED_CHANGES",
  "OPERATOR_CONFIG_PERMISSIONS_INVALID",
  "BUILDER_INTEGRITY_FAILED",
  "CAST_INTEGRITY_FAILED",
  "KEYSTORE_PERMISSIONS_INVALID",
  "PASSWORD_FILE_PERMISSIONS_INVALID",
  "SECRET_FILES_REUSED",
  "KEYSTORE_ADDRESS_UNAVAILABLE",
  "SIGNER_ADDRESS_MISMATCH",
];
const externalChecksRequired = [
  "PHYSICAL_HOST_VOLUME_PROVIDER_INDEPENDENCE",
  "AUTHORITATIVE_EVIDENCE_TIMESTAMP",
] as const;

function object(value: unknown, description: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${description} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  description: string,
): void {
  const actual = Object.keys(value).sort();
  const canonical = [...expected].sort();
  if (actual.length !== canonical.length || actual.some((key, index) => key !== canonical[index])) {
    throw new Error(`${description} contains missing or unknown fields`);
  }
}

function label(value: unknown, description: string): string {
  if (typeof value !== "string" || !/^[a-z0-9](?:[a-z0-9._-]{0,126}[a-z0-9])?$/u.test(value)) {
    throw new Error(`${description} must be a canonical public label`);
  }
  return value;
}

function commit(value: unknown, description: string): string {
  if (typeof value !== "string" || !/^[0-9a-f]{40}$/u.test(value)) {
    throw new Error(`${description} must be a full lowercase git SHA-1`);
  }
  return value;
}

function integer(value: unknown, description: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${description} must be a positive integer`);
  }
  return value;
}

function address(value: unknown, description: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${description} must be a non-zero EVM address`);
  }
  return getAddress(value);
}

function bytes32(value: unknown, description: string): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32 || BigInt(value) === 0n) {
    throw new Error(`${description} must be non-zero bytes32`);
  }
  return value.toLowerCase() as Hex;
}

function nullableBoolean(value: unknown, description: string): boolean | null {
  if (value !== null && typeof value !== "boolean") {
    throw new Error(`${description} must be a boolean or null`);
  }
  return value;
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

function findOperator(
  trustRecord: ZkIdentityStatusTestnetTrustRecord,
  operatorId: string,
): ZkIdentityStatusTestnetTrustOperator {
  const operator = trustRecord.operators.find((candidate) => candidate.operatorId === operatorId);
  if (operator === undefined) {
    throw new Error("status operator config is not present in the canonical testnet trust record");
  }
  return operator;
}

function bindHostConfiguration(input: {
  preflightEvidence: unknown;
  operatorConfig: unknown;
}): {
  preflightEvidence: ZkIdentityStatusTestnetPreflightEvidence;
  trustRecord: ZkIdentityStatusTestnetTrustRecord;
  operatorConfig: ZkIdentityStatusOperatorConfig;
  trustOperator: ZkIdentityStatusTestnetTrustOperator;
} {
  const preflightEvidence = verifyZkIdentityStatusTestnetPreflightEvidence(input.preflightEvidence);
  if (!preflightEvidence.report.ready) {
    throw new Error("canonical testnet preflight evidence is not ready");
  }
  const trustRecord = parseZkIdentityStatusTestnetTrustRecord(preflightEvidence.trustRecord);
  const operatorConfig = parseZkIdentityStatusOperatorConfig(input.operatorConfig);
  const trustOperator = findOperator(trustRecord, operatorConfig.operatorId);
  if (
    operatorConfig.chainId !== trustRecord.chainId ||
    operatorConfig.issuanceRegistry !== trustRecord.issuanceRegistry ||
    operatorConfig.issuerKeyId !== trustRecord.issuerKeyId ||
    operatorConfig.signerAddress !== trustOperator.signerAddress ||
    operatorConfig.builderSha256 !== trustRecord.builderSha256 ||
    operatorConfig.castSha256 !== trustRecord.castSha256
  ) {
    throw new Error(
      "status operator host configuration does not match the canonical testnet trust record",
    );
  }
  return { preflightEvidence, trustRecord, operatorConfig, trustOperator };
}

function identity(input: {
  preflightEvidence: ZkIdentityStatusTestnetPreflightEvidence;
  trustRecord: ZkIdentityStatusTestnetTrustRecord;
  trustOperator: ZkIdentityStatusTestnetTrustOperator;
}): ZkIdentityStatusTestnetHostAttestationIdentity {
  return {
    preflightEvidenceSha256: input.preflightEvidence.evidenceSha256,
    network: input.trustRecord.network,
    chainId: input.trustRecord.chainId,
    issuanceRegistry: input.trustRecord.issuanceRegistry,
    issuerKeyId: input.trustRecord.issuerKeyId,
    operatorId: input.trustOperator.operatorId,
    hostId: input.trustOperator.hostId,
    volumeId: input.trustOperator.volumeId,
    signerAddress: input.trustOperator.signerAddress,
    reviewedSourceCommit: input.trustRecord.reviewedSourceCommit,
    builderSha256: input.trustRecord.builderSha256,
    castSha256: input.trustRecord.castSha256,
  };
}

export function evaluateZkIdentityStatusTestnetHostAttestation(input: {
  identity: ZkIdentityStatusTestnetHostAttestationIdentity;
  observation: ZkIdentityStatusTestnetHostAttestationObservation;
  observedAt?: Date;
}): ZkIdentityStatusTestnetHostAttestationReport {
  const alerts: ZkIdentityStatusTestnetHostAttestationAlertCode[] = [];
  const { identity: expected, observation } = input;
  if (observation.sourceCommit === null || observation.sourceTrackedFilesClean === null) {
    alerts.push("SOURCE_INSPECTION_FAILED");
  } else {
    if (observation.sourceCommit !== expected.reviewedSourceCommit) {
      alerts.push("SOURCE_COMMIT_MISMATCH");
    }
    if (!observation.sourceTrackedFilesClean) alerts.push("SOURCE_TRACKED_CHANGES");
  }
  if (!observation.operatorConfigPrivate) alerts.push("OPERATOR_CONFIG_PERMISSIONS_INVALID");
  if (observation.builderSha256 !== expected.builderSha256) {
    alerts.push("BUILDER_INTEGRITY_FAILED");
  }
  if (observation.castSha256 !== expected.castSha256) alerts.push("CAST_INTEGRITY_FAILED");
  if (!observation.keystorePrivate) alerts.push("KEYSTORE_PERMISSIONS_INVALID");
  if (!observation.passwordFilePrivate) alerts.push("PASSWORD_FILE_PERMISSIONS_INVALID");
  if (observation.secretFilesDistinct === false) alerts.push("SECRET_FILES_REUSED");
  const addressPrerequisitesReady =
    observation.castSha256 === expected.castSha256 &&
    observation.keystorePrivate &&
    observation.passwordFilePrivate &&
    observation.secretFilesDistinct === true;
  if (addressPrerequisitesReady) {
    if (observation.keystoreAddress === null) {
      alerts.push("KEYSTORE_ADDRESS_UNAVAILABLE");
    } else if (observation.keystoreAddress !== expected.signerAddress) {
      alerts.push("SIGNER_ADDRESS_MISMATCH");
    }
  }
  const observedAt = input.observedAt ?? new Date();
  if (!Number.isFinite(observedAt.getTime())) {
    throw new Error("status operator host attestation time is invalid");
  }
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_REPORT_SCHEMA,
    observedAt: observedAt.toISOString(),
    ready: alerts.length === 0,
    alerts,
    externalChecksRequired,
  };
}

function evidencePayload(
  value: Omit<ZkIdentityStatusTestnetHostAttestationEvidence, "evidenceSha256">,
): Omit<ZkIdentityStatusTestnetHostAttestationEvidence, "evidenceSha256"> {
  return {
    schema: value.schema,
    identity: value.identity,
    observation: value.observation,
    report: value.report,
  };
}

export function createZkIdentityStatusTestnetHostAttestationEvidence(input: {
  identity: ZkIdentityStatusTestnetHostAttestationIdentity;
  observation: ZkIdentityStatusTestnetHostAttestationObservation;
  observedAt?: Date;
}): ZkIdentityStatusTestnetHostAttestationEvidence {
  const payload = {
    schema: ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_SCHEMA,
    identity: input.identity,
    observation: input.observation,
    report: evaluateZkIdentityStatusTestnetHostAttestation(input),
  } satisfies Omit<ZkIdentityStatusTestnetHostAttestationEvidence, "evidenceSha256">;
  return { ...payload, evidenceSha256: sha256(evidencePayload(payload)) };
}

function parseIdentity(value: unknown): ZkIdentityStatusTestnetHostAttestationIdentity {
  const candidate = object(value, "status operator host attestation identity");
  exactKeys(candidate, identityKeys, "status operator host attestation identity");
  return {
    preflightEvidenceSha256: bytes32(
      candidate.preflightEvidenceSha256,
      "host attestation preflight evidence SHA-256",
    ),
    network: label(candidate.network, "host attestation network"),
    chainId: integer(candidate.chainId, "host attestation chain id"),
    issuanceRegistry: address(candidate.issuanceRegistry, "host attestation issuance registry"),
    issuerKeyId: bytes32(candidate.issuerKeyId, "host attestation issuer key id"),
    operatorId: label(candidate.operatorId, "host attestation operator id"),
    hostId: label(candidate.hostId, "host attestation host id"),
    volumeId: label(candidate.volumeId, "host attestation volume id"),
    signerAddress: address(candidate.signerAddress, "host attestation signer"),
    reviewedSourceCommit: commit(candidate.reviewedSourceCommit, "host attestation source commit"),
    builderSha256: bytes32(candidate.builderSha256, "host attestation builder SHA-256"),
    castSha256: bytes32(candidate.castSha256, "host attestation cast SHA-256"),
  };
}

function parseObservation(value: unknown): ZkIdentityStatusTestnetHostAttestationObservation {
  const candidate = object(value, "status operator host attestation observation");
  exactKeys(candidate, observationKeys, "status operator host attestation observation");
  if (
    typeof candidate.operatorConfigPrivate !== "boolean" ||
    typeof candidate.keystorePrivate !== "boolean" ||
    typeof candidate.passwordFilePrivate !== "boolean"
  ) {
    throw new Error("status operator host attestation observation has invalid file checks");
  }
  return {
    sourceCommit:
      candidate.sourceCommit === null
        ? null
        : commit(candidate.sourceCommit, "host attestation observed source commit"),
    sourceTrackedFilesClean: nullableBoolean(
      candidate.sourceTrackedFilesClean,
      "host attestation source cleanliness",
    ),
    operatorConfigPrivate: candidate.operatorConfigPrivate,
    builderSha256:
      candidate.builderSha256 === null
        ? null
        : bytes32(candidate.builderSha256, "host attestation observed builder SHA-256"),
    castSha256:
      candidate.castSha256 === null
        ? null
        : bytes32(candidate.castSha256, "host attestation observed cast SHA-256"),
    keystorePrivate: candidate.keystorePrivate,
    passwordFilePrivate: candidate.passwordFilePrivate,
    secretFilesDistinct: nullableBoolean(
      candidate.secretFilesDistinct,
      "host attestation secret file separation",
    ),
    keystoreAddress:
      candidate.keystoreAddress === null
        ? null
        : address(candidate.keystoreAddress, "host attestation observed keystore address"),
  };
}

function parseReport(value: unknown): ZkIdentityStatusTestnetHostAttestationReport {
  const candidate = object(value, "status operator host attestation report");
  exactKeys(candidate, reportKeys, "status operator host attestation report");
  if (
    candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_REPORT_SCHEMA ||
    typeof candidate.observedAt !== "string" ||
    typeof candidate.ready !== "boolean" ||
    !Array.isArray(candidate.alerts) ||
    !Array.isArray(candidate.externalChecksRequired)
  ) {
    throw new Error("status operator host attestation report is invalid");
  }
  const observedAt = new Date(candidate.observedAt);
  if (!Number.isFinite(observedAt.getTime()) || observedAt.toISOString() !== candidate.observedAt) {
    throw new Error("status operator host attestation report time is not canonical");
  }
  const alerts = candidate.alerts.map((value) => {
    if (
      typeof value !== "string" ||
      !alertCodes.includes(value as ZkIdentityStatusTestnetHostAttestationAlertCode)
    ) {
      throw new Error("status operator host attestation report contains an invalid alert");
    }
    return value as ZkIdentityStatusTestnetHostAttestationAlertCode;
  });
  if (canonicalJson(candidate.externalChecksRequired) !== canonicalJson(externalChecksRequired)) {
    throw new Error("status operator host attestation external checks are invalid");
  }
  return {
    schema: ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_REPORT_SCHEMA,
    observedAt: candidate.observedAt,
    ready: candidate.ready,
    alerts,
    externalChecksRequired,
  };
}

export function verifyZkIdentityStatusTestnetHostAttestationEvidence(
  value: unknown,
): ZkIdentityStatusTestnetHostAttestationEvidence {
  const candidate = object(value, "status operator host attestation evidence");
  exactKeys(candidate, evidenceKeys, "status operator host attestation evidence");
  if (candidate.schema !== ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_SCHEMA) {
    throw new Error("unsupported status operator host attestation evidence schema");
  }
  const suppliedSha256 = bytes32(candidate.evidenceSha256, "host attestation evidence SHA-256");
  const rawPayload = {
    schema: candidate.schema,
    identity: candidate.identity,
    observation: candidate.observation,
    report: candidate.report,
  };
  if (sha256(rawPayload) !== suppliedSha256) {
    throw new Error("status operator host attestation evidence SHA-256 mismatch");
  }
  const identity = parseIdentity(candidate.identity);
  const observation = parseObservation(candidate.observation);
  const report = parseReport(candidate.report);
  const reproduced = evaluateZkIdentityStatusTestnetHostAttestation({
    identity,
    observation,
    observedAt: new Date(report.observedAt),
  });
  if (canonicalJson(reproduced) !== canonicalJson(report)) {
    throw new Error("status operator host attestation report cannot be reproduced");
  }
  const normalizedPayload = {
    schema: ZK_IDENTITY_STATUS_TESTNET_HOST_ATTESTATION_SCHEMA,
    identity,
    observation,
    report,
  };
  if (canonicalJson(normalizedPayload) !== canonicalJson(rawPayload)) {
    throw new Error("status operator host attestation evidence is not canonically encoded");
  }
  return {
    ...normalizedPayload,
    evidenceSha256: suppliedSha256,
  };
}

export function verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig(input: {
  evidence: unknown;
  preflightEvidence: unknown;
  operatorConfig: unknown;
}): ZkIdentityStatusTestnetHostAttestationEvidence {
  const evidence = verifyZkIdentityStatusTestnetHostAttestationEvidence(input.evidence);
  const bound = bindHostConfiguration(input);
  const expectedIdentity = identity(bound);
  if (canonicalJson(evidence.identity) !== canonicalJson(expectedIdentity)) {
    throw new Error(
      "status operator host attestation evidence does not match the reviewed host configuration",
    );
  }
  return evidence;
}

async function gitClean(sourceDirectory: string, arguments_: string[]): Promise<boolean> {
  try {
    await execute("/usr/bin/git", ["-C", sourceDirectory, ...arguments_], {
      timeout: 30_000,
      maxBuffer: 16 * 1024,
      encoding: "utf8",
      env: SUBPROCESS_ENV,
    });
    return true;
  } catch (error) {
    const code =
      error !== null && typeof error === "object" && "code" in error
        ? (error as { code?: unknown }).code
        : undefined;
    if (code === 1) return false;
    throw error;
  }
}

async function regularDirectory(path: string, description: string): Promise<void> {
  if (!isAbsolute(path)) throw new Error(`${description} must be an absolute path`);
  const metadata = await lstat(path);
  if (!metadata.isDirectory() || metadata.isSymbolicLink()) {
    throw new Error(`${description} must be a non-symlink directory`);
  }
}

async function executableSha256(path: string): Promise<Hex> {
  if (!isAbsolute(path)) throw new Error("host executable path must be absolute");
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink() || metadata.size <= 0) {
    throw new Error("host executable must be a non-empty non-symlink regular file");
  }
  await Promise.all([access(path, constants.R_OK), access(path, constants.X_OK)]);
  return `0x${createHash("sha256").update(await readFile(path)).digest("hex")}`;
}

async function privateFileIdentity(
  path: string,
  maximumBytes: number,
): Promise<ZkIdentityStatusTestnetHostPrivateFileIdentity> {
  if (!isAbsolute(path)) throw new Error("host private file path must be absolute");
  const metadata = await lstat(path);
  if (
    !metadata.isFile() ||
    metadata.isSymbolicLink() ||
    metadata.size <= 0 ||
    metadata.size > maximumBytes ||
    (metadata.mode & 0o077) !== 0
  ) {
    throw new Error(
      "host private file must be a bounded non-symlink regular file with private permissions",
    );
  }
  await access(path, constants.R_OK);
  return { device: metadata.dev.toString(), inode: metadata.ino.toString() };
}

export function createZkIdentityStatusTestnetHostInspector(): ZkIdentityStatusTestnetHostInspector {
  return {
    inspectSource: async (sourceDirectory) => {
      await regularDirectory(sourceDirectory, "status operator source directory");
      const { stdout } = await execute(
        "/usr/bin/git",
        ["-C", sourceDirectory, "rev-parse", "--verify", "HEAD^{commit}"],
        {
          timeout: 30_000,
          maxBuffer: 16 * 1024,
          encoding: "utf8",
          env: SUBPROCESS_ENV,
        },
      );
      const sourceCommit = commit(stdout.trim().toLowerCase(), "observed source commit");
      const [worktreeClean, indexClean] = await Promise.all([
        gitClean(sourceDirectory, ["diff", "--quiet", "--ignore-submodules=none", "HEAD", "--"]),
        gitClean(sourceDirectory, [
          "diff",
          "--cached",
          "--quiet",
          "--ignore-submodules=none",
          "HEAD",
          "--",
        ]),
      ]);
      return { commit: sourceCommit, trackedFilesClean: worktreeClean && indexClean };
    },
    inspectExecutable: async (path) => ({ sha256: await executableSha256(path) }),
    inspectPrivateFile: privateFileIdentity,
    resolveKeystoreAddress: async (input) => {
      const { stdout } = await execute(
        input.castPath,
        [
          "wallet",
          "address",
          "--keystore",
          input.keystorePath,
          "--password-file",
          input.passwordFile,
          "--color",
          "never",
        ],
        {
          timeout: 30_000,
          maxBuffer: 16 * 1024,
          encoding: "utf8",
          env: SUBPROCESS_ENV,
        },
      );
      const output = stdout.trim();
      if (!/^0x[0-9a-fA-F]{40}$/u.test(output)) {
        throw new Error("cast returned an invalid keystore address");
      }
      return getAddress(output);
    },
  };
}

async function settled<T>(operation: () => Promise<T>): Promise<T | null> {
  try {
    return await operation();
  } catch {
    return null;
  }
}

export async function captureZkIdentityStatusTestnetHostAttestation(input: {
  preflightEvidence: unknown;
  operatorConfig: unknown;
  operatorConfigPath: string;
  sourceDirectory: string;
  inspector?: ZkIdentityStatusTestnetHostInspector;
  observedAt?: Date;
}): Promise<ZkIdentityStatusTestnetHostAttestationEvidence> {
  if (!isAbsolute(input.operatorConfigPath) || !isAbsolute(input.sourceDirectory)) {
    throw new Error("status operator host attestation paths must be absolute");
  }
  const bound = bindHostConfiguration(input);
  const inspector = input.inspector ?? createZkIdentityStatusTestnetHostInspector();
  const [source, operatorConfigFile, builder, cast, keystore, passwordFile] = await Promise.all([
    settled(() => inspector.inspectSource(input.sourceDirectory)),
    settled(() => inspector.inspectPrivateFile(input.operatorConfigPath, 1024 * 1024)),
    settled(() => inspector.inspectExecutable(bound.operatorConfig.builderPath)),
    settled(() => inspector.inspectExecutable(bound.operatorConfig.castPath)),
    settled(() => inspector.inspectPrivateFile(bound.operatorConfig.keystorePath, 1024 * 1024)),
    settled(() => inspector.inspectPrivateFile(bound.operatorConfig.passwordFile, 64 * 1024)),
  ]);
  const secretFilesDistinct =
    keystore === null || passwordFile === null
      ? null
      : keystore.device !== passwordFile.device || keystore.inode !== passwordFile.inode;
  const canResolveAddress =
    cast?.sha256 === bound.trustRecord.castSha256 &&
    keystore !== null &&
    passwordFile !== null &&
    secretFilesDistinct;
  const keystoreAddress = canResolveAddress
    ? await settled(() =>
        inspector.resolveKeystoreAddress({
          castPath: bound.operatorConfig.castPath,
          keystorePath: bound.operatorConfig.keystorePath,
          passwordFile: bound.operatorConfig.passwordFile,
        }),
      )
    : null;
  return createZkIdentityStatusTestnetHostAttestationEvidence({
    identity: identity(bound),
    observation: {
      sourceCommit: source?.commit ?? null,
      sourceTrackedFilesClean: source?.trackedFilesClean ?? null,
      operatorConfigPrivate: operatorConfigFile !== null,
      builderSha256: builder?.sha256 ?? null,
      castSha256: cast?.sha256 ?? null,
      keystorePrivate: keystore !== null,
      passwordFilePrivate: passwordFile !== null,
      secretFilesDistinct,
      keystoreAddress,
    },
    observedAt: input.observedAt,
  });
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

export async function writeZkIdentityStatusTestnetHostAttestationEvidence(
  path: string,
  evidence: unknown,
): Promise<void> {
  if (!isAbsolute(path)) {
    throw new Error("status operator host attestation evidence path must be absolute");
  }
  const verified = verifyZkIdentityStatusTestnetHostAttestationEvidence(evidence);
  const directory = dirname(path);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const temporary = join(directory, `.${basename(path)}.${process.pid}.${randomUUID()}.tmp`);
  let handle;
  try {
    handle = await open(
      temporary,
      constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY,
      0o600,
    );
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
      throw Object.assign(new Error("status operator host attestation evidence already exists"), {
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

export async function readZkIdentityStatusTestnetHostAttestationEvidence(
  path: string,
): Promise<ZkIdentityStatusTestnetHostAttestationEvidence> {
  if (!isAbsolute(path)) {
    throw new Error("status operator host attestation evidence path must be absolute");
  }
  return verifyZkIdentityStatusTestnetHostAttestationEvidence(
    JSON.parse(await readFile(path, "utf8")),
  );
}
