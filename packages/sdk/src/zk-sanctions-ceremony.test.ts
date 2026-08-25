import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import type { Hex } from "viem";
import {
  createV2SanctionsCeremonyRecord,
  parseV2SanctionsCeremonyRecord,
  serializeV2SanctionsCeremonyRecord,
  V2_SANCTIONS_CEREMONY_SCHEMA,
  V2_SANCTIONS_CIRCUIT_ID,
  V2_SANCTIONS_CONSTRAINTS,
  V2_SANCTIONS_PROFILE_ID,
  V2_SANCTIONS_PUBLIC_SIGNALS,
  V2_SANCTIONS_WITNESS_VARIABLES,
  type V2CeremonyEvidence,
  type V2SanctionsCeremonyRecord,
} from "./zk-sanctions-ceremony";

const digest = (label: string): Hex => `0x${createHash("sha256").update(label).digest("hex")}`;
const evidence = (label: string, mediaType = "application/json"): V2CeremonyEvidence => {
  const sha256 = digest(label);
  return {
    uri: `https://artifacts.proofofhumanity.org/v2/${sha256.slice(2)}/${label}.json`,
    sha256,
    bytes: 100 + label.length,
    mediaType,
  };
};

function input(): Omit<V2SanctionsCeremonyRecord, "recordSha256"> {
  const sourceManifest = evidence("source-manifest");
  const canonicalConstraints = digest("canonical-uncompressed-constraints");
  const initialPhase2Transcript = evidence("initial-phase2", "application/octet-stream");
  const contributionOne = digest("contribution-one");
  const contributionTwo = digest("contribution-two");
  const contributionThree = digest("contribution-three");
  const beaconOutput = digest("final-beacon-output");
  const provingKey = evidence("proving-key", "application/octet-stream");
  const verifyingKey = evidence("verifying-key", "application/octet-stream");
  const verifierSource = evidence("verifier-source", "text/plain");
  const verifierRuntime = evidence("verifier-runtime", "application/octet-stream");
  return {
    schema: V2_SANCTIONS_CEREMONY_SCHEMA,
    status: "ceremony-complete-artifacts-inactive",
    profileId: V2_SANCTIONS_PROFILE_ID,
    circuitId: V2_SANCTIONS_CIRCUIT_ID,
    freeze: {
      sourceCommit: "12".repeat(20),
      sourceManifest,
      sourceArchive: evidence("source-archive", "application/gzip"),
      constraintManifest: evidence("constraint-manifest"),
      constraintSystem: evidence("constraint-system", "application/gzip"),
      canonicalConstraintSystemSha256: canonicalConstraints,
      compilerLock: evidence("compiler-lock"),
      parameterManifest: evidence("parameter-manifest"),
      publicSignalManifest: evidence("public-signal-manifest"),
      publicSignalCount: V2_SANCTIONS_PUBLIC_SIGNALS,
      constraints: V2_SANCTIONS_CONSTRAINTS,
      witnessVariables: V2_SANCTIONS_WITNESS_VARIABLES,
    },
    audits: [
      {
        kind: "circuit",
        auditorId: "auditor.circuit",
        organizationId: "audit-lab.alpha",
        identity: evidence("circuit-auditor-identity"),
        approvedAt: "2026-08-25T10:00:00.000Z",
        sourceManifestSha256: sourceManifest.sha256,
        constraintSystemSha256: canonicalConstraints,
        criticalOpen: 0,
        highOpen: 0,
        report: evidence("circuit-audit-report"),
        approvalReceipt: evidence("circuit-audit-approval"),
      },
      {
        kind: "cryptography",
        auditorId: "auditor.crypto",
        organizationId: "audit-lab.beta",
        identity: evidence("crypto-auditor-identity"),
        approvedAt: "2026-08-25T11:00:00.000Z",
        sourceManifestSha256: sourceManifest.sha256,
        constraintSystemSha256: canonicalConstraints,
        criticalOpen: 0,
        highOpen: 0,
        report: evidence("crypto-audit-report"),
        approvalReceipt: evidence("crypto-audit-approval"),
      },
    ],
    setup: {
      phase1Transcript: evidence("phase1-transcript", "application/octet-stream"),
      initialPhase2Transcript,
      contributions: [
        {
          sequence: 1,
          contributorId: "contributor.one",
          organizationId: "contributor-org.one",
          contributedAt: "2026-08-25T12:00:00.000Z",
          beforeSha256: initialPhase2Transcript.sha256,
          afterSha256: contributionOne,
          receipt: evidence("contribution-one-receipt"),
          verification: evidence("contribution-one-verification"),
        },
        {
          sequence: 2,
          contributorId: "contributor.two",
          organizationId: "contributor-org.two",
          contributedAt: "2026-08-25T13:00:00.000Z",
          beforeSha256: contributionOne,
          afterSha256: contributionTwo,
          receipt: evidence("contribution-two-receipt"),
          verification: evidence("contribution-two-verification"),
        },
        {
          sequence: 3,
          contributorId: "contributor.three",
          organizationId: "contributor-org.three",
          contributedAt: "2026-08-25T14:00:00.000Z",
          beforeSha256: contributionTwo,
          afterSha256: contributionThree,
          receipt: evidence("contribution-three-receipt"),
          verification: evidence("contribution-three-verification"),
        },
      ],
      finalBeacon: {
        source: evidence("beacon-source"),
        commitment: evidence("beacon-commitment"),
        committedAt: "2026-08-25T11:30:00.000Z",
        revealedAt: "2026-08-25T15:00:00.000Z",
        appliedAt: "2026-08-25T15:05:00.000Z",
        inputSha256: contributionThree,
        outputSha256: beaconOutput,
        applicationReport: evidence("beacon-application"),
      },
      finalPhase2Transcript: {
        uri: `https://artifacts.proofofhumanity.org/v2/${beaconOutput.slice(2)}/final-phase2.bin`,
        sha256: beaconOutput,
        bytes: 256,
        mediaType: "application/octet-stream",
      },
      contributionVerificationReport: evidence("all-contributions-verification"),
    },
    artifacts: { provingKey, verifyingKey, verifierSource, verifierRuntime },
    reproduction: {
      reproducerId: "reproducer.independent",
      organizationId: "reproduction-lab.gamma",
      identity: evidence("reproducer-identity"),
      reproducedAt: "2026-08-25T16:00:00.000Z",
      sourceCommit: "12".repeat(20),
      sourceManifestSha256: sourceManifest.sha256,
      constraintSystemSha256: canonicalConstraints,
      provingKeySha256: provingKey.sha256,
      verifyingKeySha256: verifyingKey.sha256,
      verifierSourceSha256: verifierSource.sha256,
      verifierRuntimeSha256: verifierRuntime.sha256,
      report: evidence("independent-reproduction-report"),
      approvalReceipt: evidence("independent-reproduction-approval"),
      verified: true,
    },
    publication: {
      artifactIndex: evidence("public-artifact-index"),
      timestampAuthority: evidence("timestamp-authority"),
      timestampReceipt: evidence("timestamp-receipt"),
      subjectSha256: digest("public-artifact-index"),
      anchoredAt: "2026-08-25T17:00:00.000Z",
    },
    safety: {
      authorization: "artifact-publication-only",
      transactionsPerformed: false,
      deployed: false,
      proofPathActivated: false,
    },
  };
}

const record = createV2SanctionsCeremonyRecord(input());
assert.deepEqual(parseV2SanctionsCeremonyRecord(JSON.parse(serializeV2SanctionsCeremonyRecord(record))), record);

function rejects(mutate: (candidate: V2SanctionsCeremonyRecord) => void, expected: RegExp): void {
  const candidate = structuredClone(record);
  mutate(candidate);
  assert.throws(() => parseV2SanctionsCeremonyRecord(candidate), expected);
}

rejects((candidate) => candidate.setup.contributions.pop(), /at least three real contributions/u);
rejects((candidate) => {
  candidate.setup.contributions[1]!.contributorId = candidate.setup.contributions[0]!.contributorId;
}, /contributors must be unique/u);
rejects((candidate) => {
  candidate.setup.contributions[1]!.beforeSha256 = digest("wrong predecessor");
}, /contribution chain is broken/u);
rejects((candidate) => {
  candidate.audits[1].organizationId = candidate.audits[0].organizationId;
}, /independently issued/u);
rejects((candidate) => {
  candidate.audits[0].constraintSystemSha256 = digest("other constraints");
}, /does not bind the frozen source and constraints/u);
rejects((candidate) => {
  candidate.setup.contributions[0]!.contributedAt = "2026-08-25T10:30:00.000Z";
}, /must occur after both audits and in sequence/u);
rejects((candidate) => {
  candidate.setup.contributions[1]!.contributedAt = "2026-08-25T11:45:00.000Z";
}, /must occur after both audits and in sequence/u);
rejects((candidate) => {
  candidate.setup.finalBeacon.committedAt = "2026-08-25T12:30:00.000Z";
}, /not correctly ordered/u);
rejects((candidate) => {
  candidate.setup.finalBeacon.inputSha256 = digest("wrong beacon input");
}, /not correctly ordered/u);
rejects((candidate) => {
  candidate.reproduction.verifyingKeySha256 = digest("wrong verifying key");
}, /does not bind every frozen and ceremony artifact/u);
rejects((candidate) => {
  candidate.reproduction.organizationId = candidate.setup.contributions[0]!.organizationId;
}, /organizationally independent/u);
rejects((candidate) => {
  candidate.reproduction.reproducedAt = "2026-08-25T15:01:00.000Z";
}, /must occur after final beacon application/u);
rejects((candidate) => {
  candidate.publication.subjectSha256 = digest("another artifact index");
}, /does not bind the ceremony artifact index/u);
rejects((candidate) => {
  (candidate.safety.deployed as boolean) = true;
}, /cannot authorize transactions, deployment, or proof-path activation/u);
rejects((candidate) => {
  candidate.artifacts.provingKey.uri = "https://user:password@artifacts.example/key";
}, /credential-free immutable HTTPS/u);
rejects((candidate) => {
  const key = candidate.artifacts.provingKey;
  key.uri = `https://localhost/${key.sha256.slice(2)}/key`;
}, /public artifact host/u);
rejects((candidate) => {
  (candidate as unknown as Record<string, unknown>).unexpected = true;
}, /missing or unknown fields/u);
rejects((candidate) => {
  candidate.recordSha256 = digest("tampered record hash");
}, /record SHA-256 mismatch/u);

console.log("v2 sanctions ceremony: strict external evidence gate PASS");
