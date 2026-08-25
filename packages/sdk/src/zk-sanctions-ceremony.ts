import { sha256 as hashSha256, stringToBytes, type Hex } from "viem";

export const V2_SANCTIONS_CEREMONY_SCHEMA =
  "org.proofofhumanity.v2-sanctions-clear-ceremony/1" as const;
export const V2_SANCTIONS_PROFILE_ID =
  "org.proofofhumanity.v2-crypto.groth16-bn254-poseidon/1" as const;
export const V2_SANCTIONS_CIRCUIT_ID =
  "0xe04e432671953a25e6aadbb5e59cfa0ff347108e31aac4a5599cb08f5cce11d2" as const;
export const V2_SANCTIONS_CONSTRAINTS = 28_499 as const;
export const V2_SANCTIONS_WITNESS_VARIABLES = 27_561 as const;
export const V2_SANCTIONS_PUBLIC_SIGNALS = 18 as const;

export interface V2CeremonyEvidence {
  uri: string;
  sha256: Hex;
  bytes: number;
  mediaType: string;
}

export interface V2SanctionsAuditApproval {
  kind: "circuit" | "cryptography";
  auditorId: string;
  organizationId: string;
  identity: V2CeremonyEvidence;
  approvedAt: string;
  sourceManifestSha256: Hex;
  constraintSystemSha256: Hex;
  criticalOpen: 0;
  highOpen: 0;
  report: V2CeremonyEvidence;
  approvalReceipt: V2CeremonyEvidence;
}

export interface V2SanctionsCeremonyContribution {
  sequence: number;
  contributorId: string;
  organizationId: string;
  contributedAt: string;
  beforeSha256: Hex;
  afterSha256: Hex;
  receipt: V2CeremonyEvidence;
  verification: V2CeremonyEvidence;
}

export interface V2SanctionsCeremonyRecord {
  schema: typeof V2_SANCTIONS_CEREMONY_SCHEMA;
  status: "ceremony-complete-artifacts-inactive";
  profileId: typeof V2_SANCTIONS_PROFILE_ID;
  circuitId: typeof V2_SANCTIONS_CIRCUIT_ID;
  freeze: {
    sourceCommit: string;
    sourceManifest: V2CeremonyEvidence;
    sourceArchive: V2CeremonyEvidence;
    constraintManifest: V2CeremonyEvidence;
    constraintSystem: V2CeremonyEvidence;
    canonicalConstraintSystemSha256: Hex;
    compilerLock: V2CeremonyEvidence;
    parameterManifest: V2CeremonyEvidence;
    publicSignalManifest: V2CeremonyEvidence;
    publicSignalCount: typeof V2_SANCTIONS_PUBLIC_SIGNALS;
    constraints: typeof V2_SANCTIONS_CONSTRAINTS;
    witnessVariables: typeof V2_SANCTIONS_WITNESS_VARIABLES;
  };
  audits: [V2SanctionsAuditApproval, V2SanctionsAuditApproval];
  setup: {
    phase1Transcript: V2CeremonyEvidence;
    initialPhase2Transcript: V2CeremonyEvidence;
    contributions: V2SanctionsCeremonyContribution[];
    finalBeacon: {
      source: V2CeremonyEvidence;
      commitment: V2CeremonyEvidence;
      committedAt: string;
      revealedAt: string;
      appliedAt: string;
      inputSha256: Hex;
      outputSha256: Hex;
      applicationReport: V2CeremonyEvidence;
    };
    finalPhase2Transcript: V2CeremonyEvidence;
    contributionVerificationReport: V2CeremonyEvidence;
  };
  artifacts: {
    provingKey: V2CeremonyEvidence;
    verifyingKey: V2CeremonyEvidence;
    verifierSource: V2CeremonyEvidence;
    verifierRuntime: V2CeremonyEvidence;
  };
  reproduction: {
    reproducerId: string;
    organizationId: string;
    identity: V2CeremonyEvidence;
    reproducedAt: string;
    sourceCommit: string;
    sourceManifestSha256: Hex;
    constraintSystemSha256: Hex;
    provingKeySha256: Hex;
    verifyingKeySha256: Hex;
    verifierSourceSha256: Hex;
    verifierRuntimeSha256: Hex;
    report: V2CeremonyEvidence;
    approvalReceipt: V2CeremonyEvidence;
    verified: true;
  };
  publication: {
    artifactIndex: V2CeremonyEvidence;
    timestampAuthority: V2CeremonyEvidence;
    timestampReceipt: V2CeremonyEvidence;
    subjectSha256: Hex;
    anchoredAt: string;
  };
  safety: {
    authorization: "artifact-publication-only";
    transactionsPerformed: false;
    deployed: false;
    proofPathActivated: false;
  };
  recordSha256: Hex;
}

const recordKeys = [
  "schema",
  "status",
  "profileId",
  "circuitId",
  "freeze",
  "audits",
  "setup",
  "artifacts",
  "reproduction",
  "publication",
  "safety",
  "recordSha256",
] as const;
const freezeKeys = [
  "sourceCommit",
  "sourceManifest",
  "sourceArchive",
  "constraintManifest",
  "constraintSystem",
  "canonicalConstraintSystemSha256",
  "compilerLock",
  "parameterManifest",
  "publicSignalManifest",
  "publicSignalCount",
  "constraints",
  "witnessVariables",
] as const;
const auditKeys = [
  "kind",
  "auditorId",
  "organizationId",
  "identity",
  "approvedAt",
  "sourceManifestSha256",
  "constraintSystemSha256",
  "criticalOpen",
  "highOpen",
  "report",
  "approvalReceipt",
] as const;
const setupKeys = [
  "phase1Transcript",
  "initialPhase2Transcript",
  "contributions",
  "finalBeacon",
  "finalPhase2Transcript",
  "contributionVerificationReport",
] as const;
const contributionKeys = [
  "sequence",
  "contributorId",
  "organizationId",
  "contributedAt",
  "beforeSha256",
  "afterSha256",
  "receipt",
  "verification",
] as const;
const beaconKeys = [
  "source",
  "commitment",
  "committedAt",
  "revealedAt",
  "appliedAt",
  "inputSha256",
  "outputSha256",
  "applicationReport",
] as const;
const artifactKeys = ["provingKey", "verifyingKey", "verifierSource", "verifierRuntime"] as const;
const reproductionKeys = [
  "reproducerId",
  "organizationId",
  "identity",
  "reproducedAt",
  "sourceCommit",
  "sourceManifestSha256",
  "constraintSystemSha256",
  "provingKeySha256",
  "verifyingKeySha256",
  "verifierSourceSha256",
  "verifierRuntimeSha256",
  "report",
  "approvalReceipt",
  "verified",
] as const;
const publicationKeys = [
  "artifactIndex",
  "timestampAuthority",
  "timestampReceipt",
  "subjectSha256",
  "anchoredAt",
] as const;
const safetyKeys = ["authorization", "transactionsPerformed", "deployed", "proofPathActivated"] as const;
const evidenceKeys = ["uri", "sha256", "bytes", "mediaType"] as const;

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`${label} has missing or unknown fields`);
  }
}

function identifier(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^[a-z0-9][a-z0-9._:@/-]{1,127}$/u.test(value)) {
    throw new Error(`${label} is not a canonical public identifier`);
  }
  return value;
}

function sha256(value: unknown, label: string): Hex {
  if (typeof value !== "string" || !/^0x[0-9a-f]{64}$/u.test(value) || /^0x0{64}$/u.test(value)) {
    throw new Error(`${label} must be a nonzero lowercase SHA-256 digest`);
  }
  return value as Hex;
}

function timestamp(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value)) {
    throw new Error(`${label} must be a canonical UTC timestamp`);
  }
  const parsed = new Date(value);
  if (!Number.isFinite(parsed.valueOf()) || parsed.toISOString() !== value) {
    throw new Error(`${label} is invalid`);
  }
  return value;
}

function evidence(value: unknown, label: string): V2CeremonyEvidence {
  const candidate = object(value, label);
  exactKeys(candidate, evidenceKeys, label);
  if (typeof candidate.uri !== "string") throw new Error(`${label} URI is invalid`);
  const uri = new URL(candidate.uri);
  if (uri.protocol !== "https:" || uri.username !== "" || uri.password !== "" || uri.search !== "" || uri.hash !== "") {
    throw new Error(`${label} must use credential-free immutable HTTPS without query or fragment`);
  }
  const host = uri.hostname.toLowerCase();
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".invalid") ||
    host.endsWith(".test") ||
    host === "127.0.0.1" ||
    host === "[::1]" ||
    /^10\./u.test(host) ||
    /^192\.168\./u.test(host) ||
    /^169\.254\./u.test(host) ||
    /^172\.(1[6-9]|2\d|3[01])\./u.test(host)
  ) {
    throw new Error(`${label} must use a public artifact host`);
  }
  if (typeof candidate.bytes !== "number" || !Number.isSafeInteger(candidate.bytes) || candidate.bytes <= 0) {
    throw new Error(`${label} byte length must be a positive safe integer`);
  }
  if (typeof candidate.mediaType !== "string" || !/^[a-z0-9.+-]+\/[a-z0-9.+-]+$/u.test(candidate.mediaType)) {
    throw new Error(`${label} media type is invalid`);
  }
  const contentSha256 = sha256(candidate.sha256, `${label} SHA-256`);
  if (!uri.pathname.toLowerCase().split("/").includes(contentSha256.slice(2))) {
    throw new Error(`${label} URI must contain its SHA-256 as a content-addressed path segment`);
  }
  return {
    uri: uri.toString(),
    sha256: contentSha256,
    bytes: candidate.bytes,
    mediaType: candidate.mediaType,
  };
}

function canonical(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([key, item]) => [key, canonical(item)]),
    );
  }
  return value;
}

function canonicalJson(value: unknown): string {
  return JSON.stringify(canonical(value));
}

function digestRecord(value: Omit<V2SanctionsCeremonyRecord, "recordSha256">): Hex {
  return hashSha256(stringToBytes(canonicalJson(value)));
}

function parseAudit(
  value: unknown,
  index: number,
  sourceManifestSha256: Hex,
  constraintSystemSha256: Hex,
): V2SanctionsAuditApproval {
  const candidate = object(value, `audit approval ${index}`);
  exactKeys(candidate, auditKeys, `audit approval ${index}`);
  if (candidate.kind !== "circuit" && candidate.kind !== "cryptography") {
    throw new Error(`audit approval ${index} kind is unsupported`);
  }
  if (candidate.criticalOpen !== 0 || candidate.highOpen !== 0) {
    throw new Error(`audit approval ${index} has open Critical or High findings`);
  }
  if (candidate.sourceManifestSha256 !== sourceManifestSha256 || candidate.constraintSystemSha256 !== constraintSystemSha256) {
    throw new Error(`audit approval ${index} does not bind the frozen source and constraints`);
  }
  return {
    kind: candidate.kind,
    auditorId: identifier(candidate.auditorId, `audit approval ${index} auditor`),
    organizationId: identifier(candidate.organizationId, `audit approval ${index} organization`),
    identity: evidence(candidate.identity, `audit approval ${index} identity`),
    approvedAt: timestamp(candidate.approvedAt, `audit approval ${index} timestamp`),
    sourceManifestSha256,
    constraintSystemSha256,
    criticalOpen: 0,
    highOpen: 0,
    report: evidence(candidate.report, `audit approval ${index} report`),
    approvalReceipt: evidence(candidate.approvalReceipt, `audit approval ${index} receipt`),
  };
}

/**
 * Fail-closed parser for evidence from a completed external audit and real
 * circuit-specific MPC. It does not run a ceremony, generate keys, deploy, or
 * authorize activation.
 */
export function parseV2SanctionsCeremonyRecord(value: unknown): V2SanctionsCeremonyRecord {
  const candidate = object(value, "sanctions ceremony record");
  exactKeys(candidate, recordKeys, "sanctions ceremony record");
  if (
    candidate.schema !== V2_SANCTIONS_CEREMONY_SCHEMA ||
    candidate.status !== "ceremony-complete-artifacts-inactive" ||
    candidate.profileId !== V2_SANCTIONS_PROFILE_ID ||
    candidate.circuitId !== V2_SANCTIONS_CIRCUIT_ID
  ) {
    throw new Error("sanctions ceremony record identity or inactive status is invalid");
  }

  const rawFreeze = object(candidate.freeze, "sanctions source freeze");
  exactKeys(rawFreeze, freezeKeys, "sanctions source freeze");
  if (typeof rawFreeze.sourceCommit !== "string" || !/^[0-9a-f]{40}$/u.test(rawFreeze.sourceCommit)) {
    throw new Error("sanctions source freeze requires a full lowercase Git commit");
  }
  if (
    rawFreeze.publicSignalCount !== V2_SANCTIONS_PUBLIC_SIGNALS ||
    rawFreeze.constraints !== V2_SANCTIONS_CONSTRAINTS ||
    rawFreeze.witnessVariables !== V2_SANCTIONS_WITNESS_VARIABLES
  ) {
    throw new Error("sanctions source freeze constraint metadata drifted");
  }
  const freeze = {
    sourceCommit: rawFreeze.sourceCommit,
    sourceManifest: evidence(rawFreeze.sourceManifest, "source manifest"),
    sourceArchive: evidence(rawFreeze.sourceArchive, "source archive"),
    constraintManifest: evidence(rawFreeze.constraintManifest, "constraint manifest"),
    constraintSystem: evidence(rawFreeze.constraintSystem, "constraint system"),
    canonicalConstraintSystemSha256: sha256(
      rawFreeze.canonicalConstraintSystemSha256,
      "canonical constraint system SHA-256",
    ),
    compilerLock: evidence(rawFreeze.compilerLock, "compiler lock"),
    parameterManifest: evidence(rawFreeze.parameterManifest, "parameter manifest"),
    publicSignalManifest: evidence(rawFreeze.publicSignalManifest, "public signal manifest"),
    publicSignalCount: V2_SANCTIONS_PUBLIC_SIGNALS,
    constraints: V2_SANCTIONS_CONSTRAINTS,
    witnessVariables: V2_SANCTIONS_WITNESS_VARIABLES,
  };

  if (!Array.isArray(candidate.audits) || candidate.audits.length !== 2) {
    throw new Error("sanctions ceremony requires exactly circuit and cryptography audit approvals");
  }
  const audits = candidate.audits.map((item, index) =>
    parseAudit(item, index, freeze.sourceManifest.sha256, freeze.canonicalConstraintSystemSha256),
  ) as [V2SanctionsAuditApproval, V2SanctionsAuditApproval];
  if (audits[0].kind !== "circuit" || audits[1].kind !== "cryptography") {
    throw new Error("audit approvals must be canonically ordered circuit then cryptography");
  }
  if (audits[0].auditorId === audits[1].auditorId || audits[0].organizationId === audits[1].organizationId) {
    throw new Error("circuit and cryptography approvals must be independently issued");
  }

  const rawSetup = object(candidate.setup, "sanctions Phase 2 setup");
  exactKeys(rawSetup, setupKeys, "sanctions Phase 2 setup");
  const phase1Transcript = evidence(rawSetup.phase1Transcript, "Phase 1 transcript");
  const initialPhase2Transcript = evidence(rawSetup.initialPhase2Transcript, "initial Phase 2 transcript");
  if (!Array.isArray(rawSetup.contributions) || rawSetup.contributions.length < 3) {
    throw new Error("sanctions Phase 2 requires at least three real contributions");
  }
  const contributors = new Set<string>();
  let previous = initialPhase2Transcript.sha256;
  const firstAuditApproval = Math.max(...audits.map(({ approvedAt }) => Date.parse(approvedAt)));
  let previousContributionAt = firstAuditApproval;
  const contributions = rawSetup.contributions.map((value, index) => {
    const row = object(value, `Phase 2 contribution ${index + 1}`);
    exactKeys(row, contributionKeys, `Phase 2 contribution ${index + 1}`);
    if (row.sequence !== index + 1) throw new Error("Phase 2 contributions must be sequentially ordered");
    const contributorId = identifier(row.contributorId, `Phase 2 contributor ${index + 1}`);
    if (contributors.has(contributorId)) throw new Error("Phase 2 contributors must be unique");
    contributors.add(contributorId);
    const contributedAt = timestamp(row.contributedAt, `Phase 2 contribution ${index + 1} timestamp`);
    if (Date.parse(contributedAt) <= previousContributionAt) {
      throw new Error("Phase 2 contributions must occur after both audits and in sequence");
    }
    previousContributionAt = Date.parse(contributedAt);
    const beforeSha256 = sha256(row.beforeSha256, `Phase 2 contribution ${index + 1} input`);
    const afterSha256 = sha256(row.afterSha256, `Phase 2 contribution ${index + 1} output`);
    if (beforeSha256 !== previous || afterSha256 === beforeSha256) {
      throw new Error("Phase 2 transcript contribution chain is broken");
    }
    previous = afterSha256;
    return {
      sequence: index + 1,
      contributorId,
      organizationId: identifier(row.organizationId, `Phase 2 contributor ${index + 1} organization`),
      contributedAt,
      beforeSha256,
      afterSha256,
      receipt: evidence(row.receipt, `Phase 2 contribution ${index + 1} receipt`),
      verification: evidence(row.verification, `Phase 2 contribution ${index + 1} verification`),
    };
  });

  const rawBeacon = object(rawSetup.finalBeacon, "final beacon");
  exactKeys(rawBeacon, beaconKeys, "final beacon");
  const beacon = {
    source: evidence(rawBeacon.source, "final beacon source"),
    commitment: evidence(rawBeacon.commitment, "final beacon commitment"),
    committedAt: timestamp(rawBeacon.committedAt, "final beacon commitment timestamp"),
    revealedAt: timestamp(rawBeacon.revealedAt, "final beacon reveal"),
    appliedAt: timestamp(rawBeacon.appliedAt, "final beacon application"),
    inputSha256: sha256(rawBeacon.inputSha256, "final beacon input"),
    outputSha256: sha256(rawBeacon.outputSha256, "final beacon output"),
    applicationReport: evidence(rawBeacon.applicationReport, "final beacon application report"),
  };
  const lastContribution = contributions.at(-1)!;
  if (
    beacon.inputSha256 !== lastContribution.afterSha256 ||
    beacon.outputSha256 === beacon.inputSha256 ||
    Date.parse(beacon.committedAt) >= Date.parse(contributions[0]!.contributedAt) ||
    Date.parse(beacon.revealedAt) <= Date.parse(lastContribution.contributedAt) ||
    Date.parse(beacon.appliedAt) < Date.parse(beacon.revealedAt)
  ) {
    throw new Error("final beacon is not correctly ordered after the contribution chain");
  }
  const finalPhase2Transcript = evidence(rawSetup.finalPhase2Transcript, "final Phase 2 transcript");
  if (finalPhase2Transcript.sha256 !== beacon.outputSha256) {
    throw new Error("final Phase 2 transcript does not match the beacon output");
  }
  const setup = {
    phase1Transcript,
    initialPhase2Transcript,
    contributions,
    finalBeacon: beacon,
    finalPhase2Transcript,
    contributionVerificationReport: evidence(
      rawSetup.contributionVerificationReport,
      "contribution verification report",
    ),
  };

  const rawArtifacts = object(candidate.artifacts, "ceremony artifacts");
  exactKeys(rawArtifacts, artifactKeys, "ceremony artifacts");
  const artifacts = {
    provingKey: evidence(rawArtifacts.provingKey, "proving key"),
    verifyingKey: evidence(rawArtifacts.verifyingKey, "verifying key"),
    verifierSource: evidence(rawArtifacts.verifierSource, "verifier source"),
    verifierRuntime: evidence(rawArtifacts.verifierRuntime, "verifier runtime"),
  };
  if (artifacts.provingKey.sha256 === artifacts.verifyingKey.sha256) {
    throw new Error("proving and verifying key identities must be distinct");
  }

  const rawReproduction = object(candidate.reproduction, "independent reproduction");
  exactKeys(rawReproduction, reproductionKeys, "independent reproduction");
  if (rawReproduction.verified !== true || rawReproduction.sourceCommit !== freeze.sourceCommit) {
    throw new Error("independent reproduction is unverified or uses another source commit");
  }
  const reproduction = {
    reproducerId: identifier(rawReproduction.reproducerId, "independent reproducer"),
    organizationId: identifier(rawReproduction.organizationId, "independent reproducer organization"),
    identity: evidence(rawReproduction.identity, "independent reproducer identity"),
    reproducedAt: timestamp(rawReproduction.reproducedAt, "independent reproduction timestamp"),
    sourceCommit: freeze.sourceCommit,
    sourceManifestSha256: sha256(rawReproduction.sourceManifestSha256, "reproduced source manifest"),
    constraintSystemSha256: sha256(rawReproduction.constraintSystemSha256, "reproduced constraints"),
    provingKeySha256: sha256(rawReproduction.provingKeySha256, "reproduced proving key"),
    verifyingKeySha256: sha256(rawReproduction.verifyingKeySha256, "reproduced verifying key"),
    verifierSourceSha256: sha256(rawReproduction.verifierSourceSha256, "reproduced verifier source"),
    verifierRuntimeSha256: sha256(rawReproduction.verifierRuntimeSha256, "reproduced verifier runtime"),
    report: evidence(rawReproduction.report, "independent reproduction report"),
    approvalReceipt: evidence(rawReproduction.approvalReceipt, "independent reproduction receipt"),
    verified: true as const,
  };
  if (
    reproduction.sourceManifestSha256 !== freeze.sourceManifest.sha256 ||
    reproduction.constraintSystemSha256 !== freeze.canonicalConstraintSystemSha256 ||
    reproduction.provingKeySha256 !== artifacts.provingKey.sha256 ||
    reproduction.verifyingKeySha256 !== artifacts.verifyingKey.sha256 ||
    reproduction.verifierSourceSha256 !== artifacts.verifierSource.sha256 ||
    reproduction.verifierRuntimeSha256 !== artifacts.verifierRuntime.sha256
  ) {
    throw new Error("independent reproduction does not bind every frozen and ceremony artifact");
  }
  const externalOrganizations = new Set([
    ...audits.map(({ organizationId }) => organizationId),
    ...contributions.map(({ organizationId }) => organizationId),
  ]);
  if (externalOrganizations.has(reproduction.organizationId)) {
    throw new Error("source-to-verifier reproduction must be organizationally independent");
  }
  if (Date.parse(reproduction.reproducedAt) <= Date.parse(beacon.appliedAt)) {
    throw new Error("source-to-verifier reproduction must occur after final beacon application");
  }

  const rawPublication = object(candidate.publication, "ceremony publication");
  exactKeys(rawPublication, publicationKeys, "ceremony publication");
  const publication = {
    artifactIndex: evidence(rawPublication.artifactIndex, "ceremony artifact index"),
    timestampAuthority: evidence(rawPublication.timestampAuthority, "timestamp authority"),
    timestampReceipt: evidence(rawPublication.timestampReceipt, "timestamp receipt"),
    subjectSha256: sha256(rawPublication.subjectSha256, "timestamp subject"),
    anchoredAt: timestamp(rawPublication.anchoredAt, "publication anchor timestamp"),
  };
  if (publication.subjectSha256 !== publication.artifactIndex.sha256) {
    throw new Error("public timestamp receipt does not bind the ceremony artifact index");
  }
  if (Date.parse(publication.anchoredAt) < Date.parse(reproduction.reproducedAt)) {
    throw new Error("public timestamp anchor predates independent reproduction");
  }

  const rawSafety = object(candidate.safety, "ceremony safety boundary");
  exactKeys(rawSafety, safetyKeys, "ceremony safety boundary");
  if (
    rawSafety.authorization !== "artifact-publication-only" ||
    rawSafety.transactionsPerformed !== false ||
    rawSafety.deployed !== false ||
    rawSafety.proofPathActivated !== false
  ) {
    throw new Error("ceremony record cannot authorize transactions, deployment, or proof-path activation");
  }
  const safety = {
    authorization: "artifact-publication-only" as const,
    transactionsPerformed: false as const,
    deployed: false as const,
    proofPathActivated: false as const,
  };

  const payload = {
    schema: V2_SANCTIONS_CEREMONY_SCHEMA,
    status: "ceremony-complete-artifacts-inactive" as const,
    profileId: V2_SANCTIONS_PROFILE_ID,
    circuitId: V2_SANCTIONS_CIRCUIT_ID,
    freeze,
    audits,
    setup,
    artifacts,
    reproduction,
    publication,
    safety,
  };
  const recordSha256 = sha256(candidate.recordSha256, "ceremony record SHA-256");
  if (recordSha256 !== digestRecord(payload)) throw new Error("ceremony record SHA-256 mismatch");
  return { ...payload, recordSha256 };
}

export function createV2SanctionsCeremonyRecord(
  input: Omit<V2SanctionsCeremonyRecord, "recordSha256">,
): V2SanctionsCeremonyRecord {
  return parseV2SanctionsCeremonyRecord({ ...input, recordSha256: digestRecord(input) });
}

export function serializeV2SanctionsCeremonyRecord(record: V2SanctionsCeremonyRecord): string {
  const parsed = parseV2SanctionsCeremonyRecord(record);
  return `${JSON.stringify(canonical(parsed), null, 2)}\n`;
}
