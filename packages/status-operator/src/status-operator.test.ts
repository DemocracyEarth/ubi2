import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  collectZkIdentityFinalizedStatusTranscript,
  createZkIdentityPackedStatusAttestation,
  parseZkIdentityPackedStatusSnapshot,
  zkIdentityPackedStatusAttestationDigest,
  zkIdentityPackedStatusSnapshotHash,
  type ZkIdentityCredentialAllocatedLog,
  type ZkIdentityFinalizedBlockHeader,
  type ZkIdentityFinalizedRpcReader,
  type ZkIdentityPackedStatusSnapshot,
} from "@ubi2/sdk";
import { privateKeyToAccount } from "viem/accounts";
import type { Address, Hex, LocalAccount } from "viem";
import {
  ZK_IDENTITY_STATUS_OPERATOR_ARTIFACT_SCHEMA,
  ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA,
} from "./artifact";
import {
  parseZkIdentityStatusFleetConfig,
  parseZkIdentityStatusOperatorConfig,
  ZK_IDENTITY_STATUS_FLEET_CONFIG_SCHEMA,
} from "./config";
import {
  createZkIdentityStatusTestnetEvidence,
  readZkIdentityStatusTestnetEvidence,
  verifyZkIdentityStatusTestnetEvidence,
  writeZkIdentityStatusTestnetEvidence,
} from "./evidence";
import {
  evaluateZkIdentityStatusOperatorFleet,
  fetchZkIdentityStatusOperatorFleet,
  type FetchedZkIdentityStatusOperator,
} from "./fleet";
import {
  runZkIdentityStatusOperatorCycle,
  type ZkIdentityPackedStatusBuilder,
  type ZkIdentityStatusDigestSigner,
  type ZkIdentityStatusOperatorIdentity,
} from "./operator";
import { startZkIdentityStatusOperatorServer } from "./server";
import { ZkIdentityStatusOperatorStore } from "./storage";

const hash = (byte: string) => `0x${byte.repeat(32)}` as Hex;
const issuanceRegistry = "0x1111111111111111111111111111111111111111" as const;
const issuerKeyId = hash("22");
// Public local test vectors reused by the SDK suite. Never fund these accounts.
const reconcilerA = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8411ddca14bb03ea63",
);
const reconcilerB = privateKeyToAccount(
  "0x8b3a350cf5c34c9194ca3a545d4f80aa3102b4c3b8d1b5e1d4f6f7c8d9e0a123",
);
const initialJson = (
  await readFile(
    new URL(
      "../../../tools/v2-crypto-bench/fixtures/packed-status-snapshot.json",
      import.meta.url,
    ),
    "utf8",
  )
).trim();
const initial = parseZkIdentityPackedStatusSnapshot(JSON.parse(initialJson));
const operatorExample = parseZkIdentityStatusOperatorConfig(
  JSON.parse(
    await readFile(
      new URL("../../../ops/status-operator/operator.example.json", import.meta.url),
      "utf8",
    ),
  ),
);
const fleetExample = parseZkIdentityStatusFleetConfig(
  JSON.parse(
    await readFile(
      new URL("../../../ops/status-operator/fleet.example.json", import.meta.url),
      "utf8",
    ),
  ),
);
assert.equal(operatorExample.operatorId, "reconciler-a");
assert.equal(fleetExample.operators.length, 2);
assert.throws(
  () => parseZkIdentityStatusOperatorConfig({ ...operatorExample, privateKey: "forbidden" }),
  /unknown fields/u,
);
assert.throws(
  () =>
    parseZkIdentityStatusOperatorConfig({
      ...operatorExample,
      rpcUrl: "http://localhost:8545",
    }),
  /must use HTTPS/u,
);
const field = (lastNibble: string) => `${"0x"}${"0".repeat(63)}${lastNibble}` as Hex;
const advanced = parseZkIdentityPackedStatusSnapshot({
  ...initial,
  sourceBlockNumber: "103",
  sourceBlockHash: hash("04"),
  sourceBlockParentHash: hash("03"),
  nextStatusId: 4,
  activatedThroughStatusId: 3,
  root: field("1"),
  chunks: [
    {
      index: 0,
      value: "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3",
    },
  ],
});
const block103: ZkIdentityFinalizedBlockHeader = {
  number: 103n,
  hash: hash("04"),
  parentHash: hash("03"),
};
const allocation: ZkIdentityCredentialAllocatedLog = {
  blockNumber: 103n,
  blockHash: hash("04"),
  logIndex: 1,
  issuerKeyId,
  statusId: 3,
};
const reader = (chainId = 84_532): ZkIdentityFinalizedRpcReader => ({
  getChainId: async () => chainId,
  getFinalizedBlock: async () => block103,
  getBlock: async () => block103,
  getCredentialAllocatedLogs: async () => [allocation],
});
const builder: ZkIdentityPackedStatusBuilder = {
  advance: async (_checkpoint, source) => {
    const parsed = JSON.parse(source) as { blocks?: Array<{ number?: string }> };
    assert.equal(parsed.blocks?.at(-1)?.number, "103");
    return JSON.stringify(advanced);
  },
};
const digestSigner = (account: LocalAccount): ZkIdentityStatusDigestSigner => ({
  signDigest: (digest) => account.sign!({ hash: digest }),
});
const identity = (
  operatorId: string,
  signerAddress: Address,
): ZkIdentityStatusOperatorIdentity => ({
  operatorId,
  chainId: 84_532,
  issuanceRegistry,
  issuerKeyId,
  signerAddress,
});
const signedArtifact = async (
  snapshot: ZkIdentityPackedStatusSnapshot,
  operatorId: string,
  account: LocalAccount,
) => ({
  schema: ZK_IDENTITY_STATUS_OPERATOR_ARTIFACT_SCHEMA,
  operatorId,
  attestation: createZkIdentityPackedStatusAttestation(
    snapshot,
    await account.sign!({ hash: zkIdentityPackedStatusAttestationDigest(snapshot) }),
  ),
});
const operatorFetch = (
  operatorId: string,
  health: unknown,
  latest: unknown,
): FetchedZkIdentityStatusOperator => ({
  operatorId,
  health,
  latest,
  immutableArtifact: latest,
  immutableCacheControl: "public, max-age=31536000, immutable",
});

const root = await mkdtemp(join(tmpdir(), "ubi2-status-operator-test-"));
try {
  const storeA = new ZkIdentityStatusOperatorStore(join(root, "operator-a"));
  const storeB = new ZkIdentityStatusOperatorStore(join(root, "operator-b"));
  await Promise.all([storeA.initialize(initialJson), storeB.initialize(initialJson)]);

  const directTranscript = await collectZkIdentityFinalizedStatusTranscript({
    reader: reader(),
    chainId: 84_532,
    issuanceRegistry,
    issuerKeyId,
    anchor: {
      number: 102n,
      hash: initial.sourceBlockHash,
      parentHash: initial.sourceBlockParentHash,
    },
    expectedNextStatusId: 3n,
  });
  assert.equal(directTranscript.blocks.length, 1);

  const release = await storeA.acquireLock();
  await assert.rejects(storeA.acquireLock(), /EEXIST/u);
  await release();

  const now = () => new Date("2026-08-16T12:00:00.000Z");
  const bootstrapStore = new ZkIdentityStatusOperatorStore(join(root, "operator-bootstrap"));
  await bootstrapStore.initialize(initialJson);
  let bootstrapRestores = 0;
  const bootstrapBuilder: ZkIdentityPackedStatusBuilder = {
    advance: async (_checkpoint, source) => {
      bootstrapRestores += 1;
      assert.deepEqual((JSON.parse(source) as { blocks: unknown[] }).blocks, []);
      return initialJson;
    },
  };
  const idleReader: ZkIdentityFinalizedRpcReader = {
    getChainId: async () => 84_532,
    getFinalizedBlock: async () => ({
      number: 102n,
      hash: initial.sourceBlockHash,
      parentHash: initial.sourceBlockParentHash,
    }),
    getBlock: async () => {
      throw new Error("idle checkpoint must not fetch a block");
    },
    getCredentialAllocatedLogs: async () => [],
  };
  const bootstrapInput = {
    identity: identity("reconciler-bootstrap", reconcilerA.address),
    reader: idleReader,
    builder: bootstrapBuilder,
    signer: digestSigner(reconcilerA),
    store: bootstrapStore,
    now,
  };
  const bootstrapped = await runZkIdentityStatusOperatorCycle(bootstrapInput);
  assert.equal(bootstrapped.ok, true, JSON.stringify(bootstrapped));
  assert.equal(bootstrapped.ok && bootstrapped.advanced, false);
  assert.equal(bootstrapRestores, 1, "the initial root is recomputed before its first signature");
  const idleAgain = await runZkIdentityStatusOperatorCycle(bootstrapInput);
  assert.equal(idleAgain.ok, true, JSON.stringify(idleAgain));
  assert.equal(idleAgain.ok && idleAgain.advanced, false);
  assert.equal(bootstrapRestores, 1, "an authenticated durable checkpoint skips redundant restore");

  const tamperedStore = new ZkIdentityStatusOperatorStore(join(root, "operator-tampered"));
  await tamperedStore.initialize(initialJson);
  await tamperedStore.commit(
    await signedArtifact(initial, "reconciler-tampered", reconcilerB),
  );
  const tampered = await runZkIdentityStatusOperatorCycle({
    ...bootstrapInput,
    identity: identity("reconciler-tampered", reconcilerA.address),
    store: tamperedStore,
  });
  assert.equal(tampered.ok, false);
  assert.equal(!tampered.ok && tampered.errorCode, "SIGNER_MISMATCH");

  const [resultA, resultB] = await Promise.all([
    runZkIdentityStatusOperatorCycle({
      identity: identity("reconciler-a", reconcilerA.address),
      reader: reader(),
      builder,
      signer: digestSigner(reconcilerA),
      store: storeA,
      now,
    }),
    runZkIdentityStatusOperatorCycle({
      identity: identity("reconciler-b", reconcilerB.address),
      reader: reader(),
      builder,
      signer: digestSigner(reconcilerB),
      store: storeB,
      now,
    }),
  ]);
  assert.equal(resultA.ok && resultA.advanced, true, JSON.stringify(resultA));
  assert.equal(resultB.ok && resultB.advanced, true, JSON.stringify(resultB));
  assert.equal(
    JSON.parse(await storeA.readCheckpointJson()).sourceBlockNumber,
    "103",
    "the durable checkpoint advances only after the signed artifact is stored",
  );

  const healthA = await storeA.readHealth();
  const healthB = await storeB.readHealth();
  const latestA = await storeA.readLatest();
  const latestB = await storeB.readLatest();
  assert.ok(healthA && healthB && latestA && latestB);
  const config = parseZkIdentityStatusFleetConfig({
    schema: ZK_IDENTITY_STATUS_FLEET_CONFIG_SCHEMA,
    referenceRpcUrl: "https://reference-rpc.example",
    chainId: 84_532,
    issuanceRegistry,
    issuerKeyId,
    threshold: 2,
    maxHeartbeatAgeSeconds: 120,
    maxBlockLag: 0,
    requestTimeoutMs: 5_000,
    operators: [
      {
        operatorId: "reconciler-a",
        signerAddress: reconcilerA.address,
        baseUrl: "https://reconciler-a.example",
      },
      {
        operatorId: "reconciler-b",
        signerAddress: reconcilerB.address,
        baseUrl: "https://reconciler-b.example",
      },
    ],
  });
  const fleet = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: [
      operatorFetch("reconciler-a", healthA, latestA),
      operatorFetch("reconciler-b", healthB, latestB),
    ],
    referenceFinalizedBlock: block103,
    observedAt: now(),
  });
  assert.equal(fleet.ready, true);
  assert.deepEqual(fleet.alerts, []);
  assert.equal(fleet.publication?.expectedNextStatusId, "4");

  const immutableMismatch = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: [
      {
        ...operatorFetch("reconciler-a", healthA, latestA),
        immutableArtifact: latestB,
      },
      operatorFetch("reconciler-b", healthB, latestB),
    ],
    referenceFinalizedBlock: block103,
    observedAt: now(),
  });
  assert.equal(immutableMismatch.ready, false);
  assert.ok(
    immutableMismatch.alerts.some(
      ({ code, operatorId }) =>
        code === "IMMUTABLE_ARTIFACT_MISMATCH" && operatorId === "reconciler-a",
    ),
  );
  assert.equal(immutableMismatch.publication, null);

  const evidencePath = join(root, "evidence", "ready.json");
  const evidence = await createZkIdentityStatusTestnetEvidence({
    config,
    fetched: [
      operatorFetch("reconciler-a", healthA, latestA),
      operatorFetch("reconciler-b", healthB, latestB),
    ],
    referenceFinalizedBlock: block103,
    observedAt: now(),
  });
  assert.equal(evidence.report.ready, true);
  await writeZkIdentityStatusTestnetEvidence(evidencePath, evidence);
  assert.equal((await readZkIdentityStatusTestnetEvidence(evidencePath)).report.ready, true);
  await assert.rejects(
    writeZkIdentityStatusTestnetEvidence(evidencePath, evidence),
    { message: /already exists/u, code: "EVIDENCE_ALREADY_EXISTS" },
  );
  const tamperedEvidence = structuredClone(evidence) as unknown as {
    report: { ready: boolean };
  };
  tamperedEvidence.report.ready = false;
  await assert.rejects(
    verifyZkIdentityStatusTestnetEvidence(tamperedEvidence),
    /SHA-256 mismatch/u,
  );

  const missingReference = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: [
      operatorFetch("reconciler-a", healthA, latestA),
      operatorFetch("reconciler-b", healthB, latestB),
    ],
    observedAt: now(),
  });
  assert.equal(missingReference.ready, false);
  assert.ok(
    missingReference.alerts.some(({ code }) => code === "REFERENCE_RPC_UNAVAILABLE"),
  );

  const [serverA, serverB] = await Promise.all([
    startZkIdentityStatusOperatorServer({ store: storeA, host: "127.0.0.1", port: 0 }),
    startZkIdentityStatusOperatorServer({ store: storeB, host: "127.0.0.1", port: 0 }),
  ]);
  try {
    const addressA = serverA.address();
    const addressB = serverB.address();
    assert.ok(addressA !== null && typeof addressA === "object");
    assert.ok(addressB !== null && typeof addressB === "object");
    const baseUrl = `http://127.0.0.1:${addressA.port}`;
    const [healthResponse, latestResponse, artifactResponse] = await Promise.all([
      fetch(`${baseUrl}/healthz`),
      fetch(`${baseUrl}/latest`),
      fetch(`${baseUrl}/artifacts/${latestA.attestation.snapshotHash}`),
    ]);
    assert.equal(healthResponse.status, 200);
    assert.equal(latestResponse.status, 200);
    assert.match(artifactResponse.headers.get("cache-control") ?? "", /immutable/u);
    const networkConfig = parseZkIdentityStatusFleetConfig({
      ...config,
      operators: [
        { ...config.operators[0]!, baseUrl },
        { ...config.operators[1]!, baseUrl: `http://127.0.0.1:${addressB.port}` },
      ],
    });
    const networkFleet = await evaluateZkIdentityStatusOperatorFleet({
      config: networkConfig,
      fetched: await fetchZkIdentityStatusOperatorFleet(networkConfig),
      referenceFinalizedBlock: block103,
      observedAt: now(),
    });
    assert.equal(networkFleet.ready, true);
  } finally {
    await Promise.all(
      [serverA, serverB].map(
        (server) => new Promise<void>((resolve) => server.close(() => resolve())),
      ),
    );
  }

  const stale = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: [
      operatorFetch("reconciler-a", healthA, latestA),
      operatorFetch("reconciler-b", healthB, latestB),
    ],
    referenceFinalizedBlock: block103,
    observedAt: new Date("2026-08-16T12:03:00.000Z"),
  });
  assert.equal(stale.ready, false);
  assert.equal(stale.alerts.filter(({ code }) => code === "HEARTBEAT_STALE").length, 2);
  assert.equal(stale.publication, null);

  const storeBehind = new ZkIdentityStatusOperatorStore(join(root, "operator-behind"));
  await storeBehind.initialize(initialJson);
  const behindArtifact = await storeBehind.commit(
    await signedArtifact(initial, "reconciler-b", reconcilerB),
  );
  const behindHealth = await storeBehind.writeHealth({
    schema: ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA,
    operatorId: "reconciler-b",
    state: "healthy",
    observedAt: now().toISOString(),
    consecutiveFailures: 0,
    chainId: initial.chainId,
    issuanceRegistry,
    issuerKeyId,
    signerAddress: reconcilerB.address,
    checkpoint: {
      sourceBlockNumber: initial.sourceBlockNumber,
      sourceBlockHash: initial.sourceBlockHash,
      snapshotHash: behindArtifact.attestation.snapshotHash,
      root: initial.root,
      nextStatusId: initial.nextStatusId,
    },
    errorCode: null,
  });
  const withholding = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: [
      operatorFetch("reconciler-a", healthA, latestA),
      operatorFetch("reconciler-b", behindHealth, behindArtifact),
    ],
    referenceFinalizedBlock: block103,
    observedAt: now(),
  });
  assert.equal(withholding.ready, false);
  assert.ok(withholding.alerts.some(({ code }) => code === "WITHHOLDING_SUSPECTED"));
  assert.equal(withholding.publication, null);
  const withholdingEvidence = await createZkIdentityStatusTestnetEvidence({
    config,
    fetched: [
      operatorFetch("reconciler-a", healthA, latestA),
      operatorFetch("reconciler-b", behindHealth, behindArtifact),
    ],
    referenceFinalizedBlock: block103,
    observedAt: now(),
  });
  assert.equal(
    (await verifyZkIdentityStatusTestnetEvidence(withholdingEvidence)).report.ready,
    false,
  );

  const behindAArtifact = await signedArtifact(initial, "reconciler-a", reconcilerA);
  const allBehind = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: [
      operatorFetch(
        "reconciler-a",
        {
          ...behindHealth,
          operatorId: "reconciler-a",
          signerAddress: reconcilerA.address,
          checkpoint: {
            ...behindHealth.checkpoint,
            snapshotHash: behindAArtifact.attestation.snapshotHash,
          },
        },
        behindAArtifact,
      ),
      operatorFetch("reconciler-b", behindHealth, behindArtifact),
    ],
    referenceFinalizedBlock: block103,
    observedAt: now(),
  });
  assert.equal(allBehind.ready, false);
  assert.ok(
    allBehind.alerts.some(
      ({ code, operatorId }) => code === "WITHHOLDING_SUSPECTED" && operatorId === null,
    ),
  );

  const wrongChain = await runZkIdentityStatusOperatorCycle({
    identity: identity("reconciler-a", reconcilerA.address),
    reader: reader(1),
    builder,
    signer: digestSigner(reconcilerA),
    store: storeA,
    now: () => new Date("2026-08-16T12:00:30.000Z"),
  });
  assert.equal(wrongChain.ok, false);
  assert.equal(!wrongChain.ok && wrongChain.errorCode, "INGESTION_FAILED");
  assert.equal((await storeA.readHealth())?.state, "degraded");
  assert.equal((await storeA.readLatest())?.attestation.snapshotHash, latestA.attestation.snapshotHash);

  await assert.rejects(
    storeA.commit(await signedArtifact({ ...advanced, root: field("2") }, "reconciler-a", reconcilerA)),
    /cannot regress or equivocate/u,
  );
  const splitSnapshot = parseZkIdentityPackedStatusSnapshot({ ...advanced, root: field("2") });
  const splitStore = new ZkIdentityStatusOperatorStore(join(root, "operator-split"));
  await splitStore.initialize(initialJson);
  const splitArtifact = await splitStore.commit(
    await signedArtifact(splitSnapshot, "reconciler-b", reconcilerB),
  );
  const splitHash = zkIdentityPackedStatusSnapshotHash(splitSnapshot);
  await splitStore.writeHealth({
    schema: ZK_IDENTITY_STATUS_OPERATOR_HEALTH_SCHEMA,
    operatorId: "reconciler-b",
    state: "healthy",
    observedAt: now().toISOString(),
    consecutiveFailures: 0,
    chainId: "84532",
    issuanceRegistry,
    issuerKeyId,
    signerAddress: reconcilerB.address,
    checkpoint: {
      sourceBlockNumber: "103",
      sourceBlockHash: hash("04"),
      snapshotHash: splitHash,
      root: splitSnapshot.root,
      nextStatusId: 4,
    },
    errorCode: null,
  });
  const divergence = await evaluateZkIdentityStatusOperatorFleet({
    config,
    fetched: [
      operatorFetch("reconciler-a", healthA, latestA),
      operatorFetch("reconciler-b", await splitStore.readHealth(), splitArtifact),
    ],
    referenceFinalizedBlock: block103,
    observedAt: now(),
  });
  assert.equal(divergence.ready, false);
  assert.ok(divergence.alerts.some(({ code }) => code === "SNAPSHOT_DIVERGENCE"));
  assert.equal(divergence.publication, null);

  console.log("v2 status operators: atomic checkpoints + strict fleet reconciliation PASS");
} finally {
  await rm(root, { recursive: true, force: true });
}
