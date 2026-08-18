import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { zkIssuanceDomainHash } from "@ubi2/sdk";
import { keccak256, type Address, type Hex } from "viem";
import {
  collectZkIdentityStatusTestnetRpcObservation,
  createZkIdentityStatusTestnetPreflightEvidence,
  evaluateZkIdentityStatusTestnetPreflight,
  parseZkIdentityStatusTestnetTrustRecord,
  readZkIdentityStatusTestnetPreflightEvidence,
  validateZkIdentityStatusTestnetTopology,
  verifyZkIdentityStatusTestnetPreflightEvidence,
  verifyZkIdentityStatusTestnetPreflightEvidenceAgainstTopology,
  writeZkIdentityStatusTestnetPreflightEvidence,
  type ZkIdentityStatusTestnetProviderObservation,
  type ZkIdentityStatusTestnetRpcReader,
} from "./readiness";

const [trustValue, operatorAValue, fleetValue] = await Promise.all([
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
]);

const runtimeCode = "0x60006000" as Hex;
const runtimeCodeHash = keccak256(runtimeCode);
const trustRecord = parseZkIdentityStatusTestnetTrustRecord({
  ...trustValue,
  registryRuntimeCodeHash: runtimeCodeHash,
});
const operatorBValue = {
  ...operatorAValue,
  operatorId: "reconciler-b",
  rpcUrl: "https://rpc-provider-b.example/v1/project-id",
  signerAddress: fleetValue.operators[1].signerAddress,
  initialCheckpointPath: "/etc/ubi2/status-operator/initial-checkpoint-b.json",
  stateDirectory: "/var/lib/ubi2-status-operator-reconciler-b",
  keystorePath: "/etc/ubi2/status-operator/keystores/reconciler-b",
  passwordFile: "/etc/ubi2/status-operator/secrets/reconciler-b.password",
  listenPort: 8788,
};
const topologyInput = {
  trustRecord,
  operatorConfigs: [operatorAValue, operatorBValue],
  fleetConfig: fleetValue,
} as const;
const topology = validateZkIdentityStatusTestnetTopology(topologyInput);
assert.deepEqual(
  topology.operatorConfigs.map(({ operatorId }) => operatorId),
  ["reconciler-a", "reconciler-b"],
);

assert.throws(
  () => parseZkIdentityStatusTestnetTrustRecord({ ...trustValue, chainId: 1 }),
  /network and chain id/u,
);
assert.throws(
  () => parseZkIdentityStatusTestnetTrustRecord({ ...trustValue, privateKey: "forbidden" }),
  /unknown fields/u,
);
assert.throws(
  () =>
    parseZkIdentityStatusTestnetTrustRecord({
      ...trustValue,
      statusPublisherAddress: trustValue.operators[0].signerAddress,
    }),
  /signing roles/u,
);
assert.throws(
  () =>
    validateZkIdentityStatusTestnetTopology({
      ...topologyInput,
      operatorConfigs: [
        operatorAValue,
        { ...operatorBValue, rpcUrl: operatorAValue.rpcUrl },
      ],
    }),
  /RPC URLs/u,
);
assert.throws(
  () =>
    validateZkIdentityStatusTestnetTopology({
      ...topologyInput,
      operatorConfigs: [operatorAValue, { ...operatorBValue, builderSha256: `0x${"99".repeat(32)}` }],
    }),
  /does not match the trust record/u,
);
assert.throws(
  () =>
    validateZkIdentityStatusTestnetTopology({
      ...topologyInput,
      fleetConfig: {
        ...fleetValue,
        operators: [
          fleetValue.operators[0],
          { ...fleetValue.operators[1], signerAddress: "0x7777777777777777777777777777777777777777" },
        ],
      },
    }),
  /does not match the trust record/u,
);

const issuanceDomain = zkIssuanceDomainHash({
  chainId: trustRecord.chainId,
  registry: trustRecord.issuanceRegistry,
});
const finalizedHash = `0x${"aa".repeat(32)}` as Hex;
const deploymentBlockHash = `0x${"bb".repeat(32)}` as Hex;

class FixtureReader implements ZkIdentityStatusTestnetRpcReader {
  getChainId = async () => trustRecord.chainId;
  getFinalizedBlock = async () => ({ number: 100n, hash: finalizedHash });
  getCode = async (target: Address) =>
    target === trustRecord.issuanceRegistry ? runtimeCode : undefined;
  getOwner = async () => trustRecord.ownerAddress;
  getPendingOwner = async () => "0x0000000000000000000000000000000000000000" as Address;
  getIssuanceDomain = async () => issuanceDomain;
  getIssuerKey = async () => [true, true, 1n] as const;
  getStatusPublisher = async () => [`0x${"00".repeat(32)}` as Hex, true, true] as const;
  getDeploymentReceipt = async () => ({
    transactionHash: trustRecord.registryDeploymentTransaction,
    blockNumber: 50n,
    blockHash: deploymentBlockHash,
    from: trustRecord.deployerAddress,
    contractAddress: trustRecord.issuanceRegistry,
    status: "success" as const,
  });
}

const observation = await collectZkIdentityStatusTestnetRpcObservation({
  trustRecord,
  reader: new FixtureReader(),
});
assert.equal(observation.registryRuntimeCodeHash, runtimeCodeHash);
assert.equal(observation.statusPublisher.runtimeCodeHash, `0x${"00".repeat(32)}`);

const providers: ZkIdentityStatusTestnetProviderObservation[] = [
  ...trustRecord.operators.map(({ rpcProviderId }) => ({
    providerId: rpcProviderId,
    observation,
  })),
  { providerId: trustRecord.referenceRpcProviderId, observation },
];
const observedAt = new Date("2026-08-17T20:00:00.000Z");
const evidence = createZkIdentityStatusTestnetPreflightEvidence({
  trustRecord,
  publicTopology: topology.publicTopology,
  providers,
  observedAt,
});
assert.equal(evidence.report.ready, true);
assert.deepEqual(evidence.report.alerts, []);
assert.equal(verifyZkIdentityStatusTestnetPreflightEvidence(evidence).evidenceSha256, evidence.evidenceSha256);
assert.equal(
  verifyZkIdentityStatusTestnetPreflightEvidenceAgainstTopology({
    ...topologyInput,
    evidence,
  }).report.ready,
  true,
);
assert.throws(
  () =>
    verifyZkIdentityStatusTestnetPreflightEvidence(
      createZkIdentityStatusTestnetPreflightEvidence({
        trustRecord,
        publicTopology: {
          ...topology.publicTopology,
          operators: topology.publicTopology.operators.map((operator, index) =>
            index === 0
              ? { ...operator, builderSha256: `0x${"99".repeat(32)}` as Hex }
              : operator,
          ),
        },
        providers,
        observedAt,
      }),
    ),
  /public operator does not match/u,
);

assert.throws(
  () =>
    verifyZkIdentityStatusTestnetPreflightEvidence({
      ...evidence,
      trustRecord: { ...evidence.trustRecord, ownerAddress: "0x8888888888888888888888888888888888888888" },
    }),
  /SHA-256 mismatch/u,
);

const unavailable = evaluateZkIdentityStatusTestnetPreflight({
  trustRecord,
  providers: providers.map((provider, index) =>
    index === 0 ? { ...provider, observation: null } : provider,
  ),
  observedAt,
});
assert.equal(unavailable.ready, false);
assert.ok(unavailable.alerts.some(({ code }) => code === "RPC_UNAVAILABLE"));

const disagreement = evaluateZkIdentityStatusTestnetPreflight({
  trustRecord,
  providers: providers.map((provider, index) =>
    index === 2
      ? {
          ...provider,
          observation: {
            ...observation,
            issuerKey: { ...observation.issuerKey, nextStatusId: "2" },
          },
        }
      : provider,
  ),
  observedAt,
});
assert.equal(disagreement.ready, false);
assert.ok(disagreement.alerts.some(({ code }) => code === "PROVIDER_STATE_DISAGREEMENT"));

const unsafeState = evaluateZkIdentityStatusTestnetPreflight({
  trustRecord,
  providers: providers.map((provider) => ({
    ...provider,
    observation: {
      ...observation,
      finalizedBlockNumber: "49",
      pendingOwnerAddress: "0x9999999999999999999999999999999999999999",
      statusPublisher: {
        ...observation.statusPublisher,
        configuredCodeHash: `0x${"11".repeat(32)}` as Hex,
        active: false,
      },
    },
  })),
  observedAt,
});
assert.equal(unsafeState.ready, false);
assert.ok(unsafeState.alerts.some(({ code }) => code === "REGISTRY_DEPLOYMENT_NOT_FINALIZED"));
assert.ok(unsafeState.alerts.some(({ code }) => code === "OWNERSHIP_TRANSFER_PENDING"));
assert.ok(unsafeState.alerts.some(({ code }) => code === "STATUS_PUBLISHER_INACTIVE"));
assert.ok(unsafeState.alerts.some(({ code }) => code === "STATUS_PUBLISHER_CODEHASH_MISMATCH"));

const temporary = await mkdtemp(join(tmpdir(), "ubi2-status-readiness-"));
try {
  const evidencePath = join(temporary, "preflight.json");
  await writeZkIdentityStatusTestnetPreflightEvidence(evidencePath, evidence);
  assert.equal(
    (await readZkIdentityStatusTestnetPreflightEvidence(evidencePath)).evidenceSha256,
    evidence.evidenceSha256,
  );
  await assert.rejects(
    writeZkIdentityStatusTestnetPreflightEvidence(evidencePath, evidence),
    /already exists/u,
  );
} finally {
  await rm(temporary, { recursive: true, force: true });
}

console.log("v2 status testnet readiness: trust topology + finalized three-RPC evidence PASS");
