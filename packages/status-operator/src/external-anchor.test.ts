import assert from "node:assert/strict";
import { mkdtemp, readFile, rm, stat, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zkIssuanceDomainHash } from "@ubi2/sdk";
import { type Address, type Hex } from "viem";
import {
  ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REFERENCES_SCHEMA,
  createZkIdentityStatusTestnetExternalAnchorManifest,
  createZkIdentityStatusTestnetProviderIndependenceSubject,
  parseZkIdentityStatusTestnetExternalAnchorReferences,
  readZkIdentityStatusTestnetExternalAnchorManifest,
  verifyZkIdentityStatusTestnetExternalAnchorManifest,
  verifyZkIdentityStatusTestnetExternalAnchorManifestAgainstEvidence,
  writeZkIdentityStatusTestnetExternalAnchorManifest,
  zkIdentityStatusTestnetProviderIndependenceSubjectSha256,
} from "./external-anchor";
import {
  createZkIdentityStatusTestnetHostAttestationEvidence,
  type ZkIdentityStatusTestnetHostAttestationEvidence,
} from "./host-attestation";
import {
  createZkIdentityStatusTestnetPreflightEvidence,
  parseZkIdentityStatusTestnetTrustRecord,
  validateZkIdentityStatusTestnetTopology,
  type ZkIdentityStatusTestnetProviderObservation,
} from "./readiness";

const [trustValue, operatorA, fleetValue, exampleReferences] = await Promise.all([
  readFile(
    new URL("../../../ops/status-operator/trust-record.example.json", import.meta.url),
    "utf8",
  ).then(JSON.parse),
  readFile(
    new URL("../../../ops/status-operator/operator.example.json", import.meta.url),
    "utf8",
  ).then(JSON.parse),
  readFile(
    new URL("../../../ops/status-operator/fleet.example.json", import.meta.url),
    "utf8",
  ).then(JSON.parse),
  readFile(
    new URL(
      "../../../ops/status-operator/external-anchor-references.example.json",
      import.meta.url,
    ),
    "utf8",
  ).then(JSON.parse),
]);
assert.equal(
  parseZkIdentityStatusTestnetExternalAnchorReferences(exampleReferences)
    .authoritativeTimestamps.length,
  2,
);
const trustRecord = parseZkIdentityStatusTestnetTrustRecord(trustValue);
const operatorB = {
  ...operatorA,
  operatorId: "reconciler-b",
  rpcUrl: "https://rpc-provider-b.example/v1/project-id",
  signerAddress: fleetValue.operators[1].signerAddress,
  initialCheckpointPath: "/etc/ubi2/status-operator/initial-checkpoint-b.json",
  stateDirectory: "/var/lib/ubi2-status-operator-reconciler-b",
  keystorePath: "/etc/ubi2/status-operator/keystores/reconciler-b",
  passwordFile: "/etc/ubi2/status-operator/secrets/reconciler-b.password",
  listenPort: 8788,
};
const topology = validateZkIdentityStatusTestnetTopology({
  trustRecord,
  operatorConfigs: [operatorA, operatorB],
  fleetConfig: fleetValue,
}).publicTopology;
const rpcObservation = {
  chainId: trustRecord.chainId,
  finalizedBlockNumber: "100",
  finalizedBlockHash: `0x${"aa".repeat(32)}` as Hex,
  registryRuntimeCodeHash: trustRecord.registryRuntimeCodeHash,
  issuanceDomain: zkIssuanceDomainHash({
    chainId: trustRecord.chainId,
    registry: trustRecord.issuanceRegistry,
  }),
  ownerAddress: trustRecord.ownerAddress,
  pendingOwnerAddress: "0x0000000000000000000000000000000000000000" as Address,
  issuerKey: { registered: true, active: true, nextStatusId: "1" },
  statusPublisher: {
    configuredCodeHash: `0x${"77".repeat(32)}` as Hex,
    runtimeCodeHash: `0x${"77".repeat(32)}` as Hex,
    registered: true,
    active: true,
  },
  registryDeployment: {
    transactionHash: trustRecord.registryDeploymentTransaction,
    blockNumber: "50",
    blockHash: `0x${"bb".repeat(32)}` as Hex,
    from: trustRecord.deployerAddress,
    contractAddress: trustRecord.issuanceRegistry,
    status: "success" as const,
  },
};
const providers: ZkIdentityStatusTestnetProviderObservation[] = [
  ...trustRecord.operators.map(({ rpcProviderId }) => ({
    providerId: rpcProviderId,
    observation: rpcObservation,
  })),
  { providerId: trustRecord.referenceRpcProviderId, observation: rpcObservation },
];
const preflightEvidence = createZkIdentityStatusTestnetPreflightEvidence({
  trustRecord,
  publicTopology: topology,
  providers,
  observedAt: new Date("2026-08-18T17:00:00.000Z"),
});
assert.equal(preflightEvidence.report.ready, true);

function hostEvidence(
  operatorId: "reconciler-a" | "reconciler-b",
  observedAt: string,
  overrides: {
    preflightEvidenceSha256?: Hex;
    sourceTrackedFilesClean?: boolean;
  } = {},
): ZkIdentityStatusTestnetHostAttestationEvidence {
  const operator = trustRecord.operators.find((candidate) => candidate.operatorId === operatorId)!;
  return createZkIdentityStatusTestnetHostAttestationEvidence({
    identity: {
      preflightEvidenceSha256:
        overrides.preflightEvidenceSha256 ?? preflightEvidence.evidenceSha256,
      network: trustRecord.network,
      chainId: trustRecord.chainId,
      issuanceRegistry: trustRecord.issuanceRegistry,
      issuerKeyId: trustRecord.issuerKeyId,
      operatorId: operator.operatorId,
      hostId: operator.hostId,
      volumeId: operator.volumeId,
      signerAddress: operator.signerAddress,
      reviewedSourceCommit: trustRecord.reviewedSourceCommit,
      builderSha256: trustRecord.builderSha256,
      castSha256: trustRecord.castSha256,
    },
    observation: {
      sourceCommit: trustRecord.reviewedSourceCommit,
      sourceTrackedFilesClean: overrides.sourceTrackedFilesClean ?? true,
      operatorConfigPrivate: true,
      builderSha256: trustRecord.builderSha256,
      castSha256: trustRecord.castSha256,
      keystorePrivate: true,
      passwordFilePrivate: true,
      secretFilesDistinct: true,
      keystoreAddress: operator.signerAddress,
    },
    observedAt: new Date(observedAt),
  });
}

const hostA = hostEvidence("reconciler-a", "2026-08-18T18:00:00.000Z");
const hostB = hostEvidence("reconciler-b", "2026-08-18T18:05:00.000Z");
const providerSubjectSha256 =
  zkIdentityStatusTestnetProviderIndependenceSubjectSha256(preflightEvidence);
const providerSubject =
  createZkIdentityStatusTestnetProviderIndependenceSubject(preflightEvidence);
assert.equal(providerSubject.preflightEvidenceSha256, preflightEvidence.evidenceSha256);
assert.deepEqual(
  providerSubject.operators.map(({ operatorId }) => operatorId),
  ["reconciler-a", "reconciler-b"],
);
const references = {
  schema: ZK_IDENTITY_STATUS_TESTNET_EXTERNAL_ANCHOR_REFERENCES_SCHEMA,
  authoritativeTimestamps: [
    {
      kind: "authoritative-timestamp",
      authorityId: "public-timestamp-service",
      subjectSha256: hostA.evidenceSha256,
      receiptIssuedAt: "2026-08-18T19:00:00.000Z",
      receiptUrl: "https://evidence.example/timestamps/reconciler-a-20260818",
      receiptSha256: `0x${"91".repeat(32)}`,
    },
    {
      kind: "authoritative-timestamp",
      authorityId: "public-timestamp-service",
      subjectSha256: hostB.evidenceSha256,
      receiptIssuedAt: "2026-08-18T19:05:00.000Z",
      receiptUrl: "https://evidence.example/timestamps/reconciler-b-20260818",
      receiptSha256: `0x${"92".repeat(32)}`,
    },
  ],
  providerIndependence: {
    kind: "provider-independence",
    authorityId: "public-provider-inventory",
    subjectSha256: providerSubjectSha256,
    receiptIssuedAt: "2026-08-18T16:00:00.000Z",
    receiptUrl: "https://inventory.example/receipts/canonical-testnet-topology-20260818",
    receiptSha256: `0x${"93".repeat(32)}`,
  },
};

function create(input: {
  preflightEvidence?: unknown;
  hostAttestations?: readonly unknown[];
  operatorConfigs?: readonly unknown[];
  references?: unknown;
} = {}) {
  return createZkIdentityStatusTestnetExternalAnchorManifest({
    preflightEvidence: input.preflightEvidence ?? preflightEvidence,
    hostAttestations: input.hostAttestations ?? [hostA, hostB],
    operatorConfigs: input.operatorConfigs ?? [operatorA, operatorB],
    references: input.references ?? references,
  });
}

const manifest = create({
  hostAttestations: [hostB, hostA],
  operatorConfigs: [operatorB, operatorA],
});
assert.equal(manifest.hosts.length, 2);
assert.deepEqual(
  manifest.hosts.map(({ operatorId }) => operatorId),
  ["reconciler-a", "reconciler-b"],
);
assert.equal(manifest.identity.preflightEvidenceSha256, preflightEvidence.evidenceSha256);
assert.equal(manifest.identity.providerIndependenceSubjectSha256, providerSubjectSha256);
assert.equal(manifest.providerIndependence.subjectSha256, providerSubjectSha256);
assert.equal(manifest.report.intrinsicEvidenceValid, true);
assert.equal(manifest.report.liveReadinessClaimed, false);
assert.deepEqual(manifest.report.externalChecksRequired, [
  "AUTHORITATIVE_TIMESTAMP_RECEIPT_AUTHENTICITY",
  "PROVIDER_INDEPENDENCE_RECEIPT_AUTHENTICITY",
]);
assert.equal(
  verifyZkIdentityStatusTestnetExternalAnchorManifest(manifest).manifestSha256,
  manifest.manifestSha256,
);
assert.equal(
  verifyZkIdentityStatusTestnetExternalAnchorManifestAgainstEvidence({
    manifest,
    preflightEvidence,
    hostAttestations: [hostA, hostB],
    operatorConfigs: [operatorA, operatorB],
  }).manifestSha256,
  manifest.manifestSha256,
);

const serialized = JSON.stringify(manifest);
for (const forbidden of [
  operatorA.rpcUrl,
  operatorB.rpcUrl,
  fleetValue.referenceRpcUrl,
  operatorA.initialCheckpointPath,
  operatorA.stateDirectory,
  operatorA.builderPath,
  operatorA.castPath,
  operatorA.keystorePath,
  operatorA.passwordFile,
  "project-id",
  "sensitive",
]) {
  assert.equal(serialized.includes(forbidden), false);
}

assert.throws(
  () => create({ hostAttestations: [hostA] }),
  /requires exactly two host attestations and configs/u,
);
assert.throws(
  () => create({ operatorConfigs: [operatorA] }),
  /requires exactly two host attestations and configs/u,
);
assert.throws(
  () =>
    create({
      hostAttestations: [
        hostEvidence("reconciler-a", "2026-08-18T18:00:00.000Z", {
          sourceTrackedFilesClean: false,
        }),
        hostB,
      ],
    }),
  /requires two ready hosts/u,
);
assert.throws(
  () =>
    create({
      hostAttestations: [
        hostEvidence("reconciler-a", "2026-08-18T18:00:00.000Z", {
          preflightEvidenceSha256: `0x${"ab".repeat(32)}` as Hex,
        }),
        hostB,
      ],
    }),
  /same preflight/u,
);
assert.throws(
  () => create({ operatorConfigs: [operatorA, operatorA] }),
  /operator configs must be distinct/u,
);
assert.throws(
  () => create({ hostAttestations: [hostA, hostA] }),
  /host attestations must be independent and distinct/u,
);
assert.throws(
  () => create({ operatorConfigs: [operatorA, { ...operatorB, signerAddress: operatorA.signerAddress }] }),
  /does not match the canonical testnet trust record/u,
);

const wrongTimestampSubject = structuredClone(references);
wrongTimestampSubject.authoritativeTimestamps[0]!.subjectSha256 = `0x${"94".repeat(32)}`;
assert.throws(
  () => create({ references: wrongTimestampSubject }),
  /exactly one authoritative timestamp receipt/u,
);
const earlyTimestamp = structuredClone(references);
earlyTimestamp.authoritativeTimestamps[0]!.receiptIssuedAt = "2026-08-18T17:59:59.999Z";
assert.throws(() => create({ references: earlyTimestamp }), /cannot predate/u);
const wrongProviderSubject = structuredClone(references);
wrongProviderSubject.providerIndependence.subjectSha256 = `0x${"95".repeat(32)}`;
assert.throws(
  () => create({ references: wrongProviderSubject }),
  /does not bind the reviewed preflight topology/u,
);
const reusedReceipt = structuredClone(references);
reusedReceipt.providerIndependence.receiptSha256 =
  reusedReceipt.authoritativeTimestamps[0]!.receiptSha256;
assert.throws(
  () => create({ references: reusedReceipt }),
  /receipt SHA-256 values must be distinct/u,
);

for (const receiptUrl of [
  "http://evidence.example/receipt/a",
  "https://user:password@evidence.example/receipt/a",
  "https://evidence.example/receipt/a?token=secret",
  "https://evidence.example/receipt/a#fragment",
  "https://localhost/receipt/a",
  "https://127.0.0.1/receipt/a",
  "https://[::1]/receipt/a",
  "https://evidence.example/",
  "https://evidence.example:8443/receipt/a",
]) {
  const invalidUrl = structuredClone(references);
  invalidUrl.authoritativeTimestamps[0]!.receiptUrl = receiptUrl;
  assert.throws(
    () => parseZkIdentityStatusTestnetExternalAnchorReferences(invalidUrl),
    /public HTTPS/u,
  );
}
assert.throws(
  () =>
    parseZkIdentityStatusTestnetExternalAnchorReferences({
      ...references,
      privateKey: "must-not-be-accepted",
    }),
  /missing or unknown fields/u,
);
assert.throws(
  () =>
    parseZkIdentityStatusTestnetExternalAnchorReferences({
      ...references,
      authoritativeTimestamps: [references.authoritativeTimestamps[0]],
    }),
  /exactly two timestamps/u,
);

const tamperedManifest = structuredClone(manifest);
tamperedManifest.identity.chainId += 1;
assert.throws(
  () => verifyZkIdentityStatusTestnetExternalAnchorManifest(tamperedManifest),
  /manifest SHA-256 mismatch/u,
);
const liveClaim = structuredClone(manifest);
liveClaim.report.liveReadinessClaimed = true as false;
assert.throws(
  () => verifyZkIdentityStatusTestnetExternalAnchorManifest(liveClaim),
  /manifest SHA-256 mismatch/u,
);
const otherPreflight = createZkIdentityStatusTestnetPreflightEvidence({
  trustRecord,
  publicTopology: topology,
  providers,
  observedAt: new Date("2026-08-18T17:01:00.000Z"),
});
assert.throws(
  () =>
    verifyZkIdentityStatusTestnetExternalAnchorManifestAgainstEvidence({
      manifest,
      preflightEvidence: otherPreflight,
      hostAttestations: [hostA, hostB],
      operatorConfigs: [operatorA, operatorB],
    }),
  /same preflight/u,
);

const directory = await mkdtemp(join(tmpdir(), "ubi2-external-anchor-"));
try {
  const path = join(directory, "anchor-manifest.json");
  await writeZkIdentityStatusTestnetExternalAnchorManifest(path, manifest);
  assert.equal((await stat(path)).mode & 0o777, 0o600);
  assert.equal(
    (await readZkIdentityStatusTestnetExternalAnchorManifest(path)).manifestSha256,
    manifest.manifestSha256,
  );
  await assert.rejects(
    writeZkIdentityStatusTestnetExternalAnchorManifest(path, manifest),
    (error: unknown) =>
      error instanceof Error &&
      "code" in error &&
      (error as Error & { code: unknown }).code === "EVIDENCE_ALREADY_EXISTS",
  );
  const referencesPath = join(directory, "references.json");
  await writeFile(referencesPath, `${JSON.stringify(references)}\n`, "utf8");
  assert.equal(
    parseZkIdentityStatusTestnetExternalAnchorReferences(
      JSON.parse(await readFile(referencesPath, "utf8")),
    ).authoritativeTimestamps.length,
    2,
  );
} finally {
  await rm(directory, { recursive: true, force: true });
}

process.stdout.write("external anchor manifest tests passed\n");
