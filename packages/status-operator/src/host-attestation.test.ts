import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { zkIssuanceDomainHash } from "@ubi2/sdk";
import { getAddress, type Address, type Hex } from "viem";
import { parseZkIdentityStatusOperatorConfig } from "./config";
import {
  captureZkIdentityStatusTestnetHostAttestation,
  readZkIdentityStatusTestnetHostAttestationEvidence,
  verifyZkIdentityStatusTestnetHostAttestationEvidence,
  verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig,
  writeZkIdentityStatusTestnetHostAttestationEvidence,
  type ZkIdentityStatusTestnetHostInspector,
} from "./host-attestation";
import {
  createZkIdentityStatusTestnetPreflightEvidence,
  parseZkIdentityStatusTestnetTrustRecord,
  validateZkIdentityStatusTestnetTopology,
  type ZkIdentityStatusTestnetProviderObservation,
} from "./readiness";

const execute = promisify(execFile);
const [trustValue, operatorValue, fleetValue] = await Promise.all([
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
const trustRecord = parseZkIdentityStatusTestnetTrustRecord(trustValue);
const operatorConfig = parseZkIdentityStatusOperatorConfig(operatorValue);
const operatorBValue = {
  ...operatorValue,
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
  operatorConfigs: [operatorValue, operatorBValue],
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
const operatorConfigPath = "/etc/ubi2/status-operator/reconciler-a.json";
const sourceDirectory = "/opt/ubi2";
const otherSigner = getAddress("0x7777777777777777777777777777777777777777");

interface InspectorOptions {
  sourceCommit?: string;
  sourceTrackedFilesClean?: boolean;
  sourceFailure?: boolean;
  operatorConfigFailure?: boolean;
  builderSha256?: Hex;
  builderFailure?: boolean;
  castSha256?: Hex;
  castFailure?: boolean;
  keystoreFailure?: boolean;
  passwordFailure?: boolean;
  reuseSecrets?: boolean;
  keystoreAddress?: Address;
  addressFailure?: boolean;
}

function fixtureInspector(options: InspectorOptions = {}): {
  inspector: ZkIdentityStatusTestnetHostInspector;
  addressCalls: () => number;
} {
  let calls = 0;
  return {
    inspector: {
      inspectSource: async () => {
        if (options.sourceFailure) throw new Error("sensitive source inspection detail");
        return {
          commit: options.sourceCommit ?? trustRecord.reviewedSourceCommit,
          trackedFilesClean: options.sourceTrackedFilesClean ?? true,
        };
      },
      inspectExecutable: async (path) => {
        if (path === operatorConfig.builderPath) {
          if (options.builderFailure) throw new Error("sensitive builder inspection detail");
          return { sha256: options.builderSha256 ?? trustRecord.builderSha256 };
        }
        if (options.castFailure) throw new Error("sensitive cast inspection detail");
        return { sha256: options.castSha256 ?? trustRecord.castSha256 };
      },
      inspectPrivateFile: async (path) => {
        if (path === operatorConfigPath) {
          if (options.operatorConfigFailure) throw new Error("sensitive config inspection detail");
          return { device: "1", inode: "1" };
        }
        if (path === operatorConfig.keystorePath) {
          if (options.keystoreFailure) throw new Error("sensitive keystore inspection detail");
          return { device: "2", inode: "2" };
        }
        if (options.passwordFailure) throw new Error("sensitive password inspection detail");
        return { device: "2", inode: options.reuseSecrets ? "2" : "3" };
      },
      resolveKeystoreAddress: async () => {
        calls += 1;
        if (options.addressFailure) throw new Error("sensitive cast failure detail");
        return options.keystoreAddress ?? operatorConfig.signerAddress;
      },
    },
    addressCalls: () => calls,
  };
}

async function capture(options: InspectorOptions = {}) {
  const fixture = fixtureInspector(options);
  const evidence = await captureZkIdentityStatusTestnetHostAttestation({
    preflightEvidence,
    operatorConfig,
    operatorConfigPath,
    sourceDirectory,
    inspector: fixture.inspector,
    observedAt: new Date("2026-08-18T18:00:00.000Z"),
  });
  return { evidence, addressCalls: fixture.addressCalls() };
}

const ready = await capture();
assert.equal(ready.evidence.report.ready, true);
assert.deepEqual(ready.evidence.report.alerts, []);
assert.equal(ready.addressCalls, 1);
assert.equal(
  verifyZkIdentityStatusTestnetHostAttestationEvidence(ready.evidence).evidenceSha256,
  ready.evidence.evidenceSha256,
);
assert.equal(
  verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig({
    evidence: ready.evidence,
    preflightEvidence,
    operatorConfig,
  }).report.ready,
  true,
);
const serialized = JSON.stringify(ready.evidence);
for (const forbidden of [
  operatorConfig.rpcUrl,
  operatorConfigPath,
  sourceDirectory,
  operatorConfig.builderPath,
  operatorConfig.castPath,
  operatorConfig.keystorePath,
  operatorConfig.passwordFile,
  "sensitive",
]) {
  assert.equal(serialized.includes(forbidden), false);
}

const failureCases: Array<{
  options: InspectorOptions;
  alert: string;
  addressCalls?: number;
}> = [
  {
    options: { sourceFailure: true },
    alert: "SOURCE_INSPECTION_FAILED",
  },
  {
    options: { sourceCommit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" },
    alert: "SOURCE_COMMIT_MISMATCH",
  },
  {
    options: { sourceTrackedFilesClean: false },
    alert: "SOURCE_TRACKED_CHANGES",
  },
  {
    options: { operatorConfigFailure: true },
    alert: "OPERATOR_CONFIG_PERMISSIONS_INVALID",
  },
  {
    options: { builderSha256: `0x${"99".repeat(32)}` as Hex },
    alert: "BUILDER_INTEGRITY_FAILED",
  },
  {
    options: { castSha256: `0x${"99".repeat(32)}` as Hex },
    alert: "CAST_INTEGRITY_FAILED",
    addressCalls: 0,
  },
  {
    options: { keystoreFailure: true },
    alert: "KEYSTORE_PERMISSIONS_INVALID",
    addressCalls: 0,
  },
  {
    options: { passwordFailure: true },
    alert: "PASSWORD_FILE_PERMISSIONS_INVALID",
    addressCalls: 0,
  },
  {
    options: { reuseSecrets: true },
    alert: "SECRET_FILES_REUSED",
    addressCalls: 0,
  },
  {
    options: { addressFailure: true },
    alert: "KEYSTORE_ADDRESS_UNAVAILABLE",
    addressCalls: 1,
  },
  {
    options: { keystoreAddress: otherSigner },
    alert: "SIGNER_ADDRESS_MISMATCH",
    addressCalls: 1,
  },
];
for (const testCase of failureCases) {
  const result = await capture(testCase.options);
  assert.equal(result.evidence.report.ready, false);
  assert.ok(result.evidence.report.alerts.includes(testCase.alert as never), testCase.alert);
  if (testCase.addressCalls !== undefined) assert.equal(result.addressCalls, testCase.addressCalls);
  assert.equal(JSON.stringify(result.evidence).includes("sensitive"), false);
}

assert.throws(
  () =>
    verifyZkIdentityStatusTestnetHostAttestationEvidence({
      ...ready.evidence,
      identity: { ...ready.evidence.identity, hostId: "tampered-host" },
    }),
  /SHA-256 mismatch/u,
);
assert.throws(
  () =>
    verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig({
      evidence: ready.evidence,
      preflightEvidence: createZkIdentityStatusTestnetPreflightEvidence({
        trustRecord: parseZkIdentityStatusTestnetTrustRecord({
          ...trustRecord,
          reviewedSourceCommit: "cccccccccccccccccccccccccccccccccccccccc",
        }),
        publicTopology: topology,
        providers,
        observedAt: new Date("2026-08-18T17:00:00.000Z"),
      }),
      operatorConfig,
    }),
  /does not match the reviewed host configuration/u,
);
assert.throws(
  () =>
    verifyZkIdentityStatusTestnetHostAttestationEvidenceAgainstConfig({
      evidence: ready.evidence,
      preflightEvidence,
      operatorConfig: { ...operatorValue, signerAddress: otherSigner },
    }),
  /does not match the canonical testnet trust record/u,
);
await assert.rejects(
  captureZkIdentityStatusTestnetHostAttestation({
    preflightEvidence: createZkIdentityStatusTestnetPreflightEvidence({
      trustRecord,
      publicTopology: topology,
      providers: providers.map((provider, index) =>
        index === 0 ? { ...provider, observation: null } : provider,
      ),
      observedAt: new Date("2026-08-18T17:00:00.000Z"),
    }),
    operatorConfig,
    operatorConfigPath,
    sourceDirectory,
    inspector: fixtureInspector().inspector,
  }),
  /preflight evidence is not ready/u,
);

const temporary = await mkdtemp(join(tmpdir(), "ubi2-host-attestation-"));
try {
  const evidencePath = join(temporary, "host-attestation.json");
  await writeZkIdentityStatusTestnetHostAttestationEvidence(evidencePath, ready.evidence);
  assert.equal(
    (await readZkIdentityStatusTestnetHostAttestationEvidence(evidencePath)).evidenceSha256,
    ready.evidence.evidenceSha256,
  );
  await assert.rejects(
    writeZkIdentityStatusTestnetHostAttestationEvidence(evidencePath, ready.evidence),
    /already exists/u,
  );

  const repository = join(temporary, "source");
  await mkdir(repository);
  await execute("/usr/bin/git", ["-C", repository, "init", "--quiet"]);
  await execute("/usr/bin/git", ["-C", repository, "config", "user.name", "ubi2 test"]);
  await execute("/usr/bin/git", ["-C", repository, "config", "user.email", "test@example.invalid"]);
  const trackedPath = join(repository, "tracked.txt");
  await writeFile(trackedPath, "reviewed\n", { mode: 0o600 });
  await execute("/usr/bin/git", ["-C", repository, "add", "tracked.txt"]);
  await execute("/usr/bin/git", ["-C", repository, "commit", "--quiet", "-m", "fixture"]);
  const { stdout: commitOutput } = await execute("/usr/bin/git", [
    "-C",
    repository,
    "rev-parse",
    "HEAD",
  ]);

  const builderPath = join(temporary, "builder");
  const castPath = join(temporary, "cast");
  const keystorePath = join(temporary, "keystore.json");
  const passwordFile = join(temporary, "password");
  const configPath = join(temporary, "operator.json");
  await writeFile(builderPath, "#!/bin/sh\nexit 0\n", { mode: 0o700 });
  await writeFile(
    castPath,
    `#!/bin/sh\nprintf '%s\\n' '${operatorConfig.signerAddress}'\n`,
    { mode: 0o700 },
  );
  await Promise.all([chmod(builderPath, 0o700), chmod(castPath, 0o700)]);
  await writeFile(keystorePath, '{"crypto":"encrypted-fixture"}\n', { mode: 0o600 });
  await writeFile(passwordFile, "fixture-only\n", { mode: 0o600 });
  const hash = async (path: string) =>
    `0x${createHash("sha256").update(await readFile(path)).digest("hex")}` as Hex;
  const [builderSha256, castSha256] = await Promise.all([hash(builderPath), hash(castPath)]);
  const liveOperator = {
    ...operatorValue,
    builderPath,
    builderSha256,
    castPath,
    castSha256,
    keystorePath,
    passwordFile,
  };
  await writeFile(configPath, `${JSON.stringify(liveOperator)}\n`, { mode: 0o600 });
  const liveTrust = parseZkIdentityStatusTestnetTrustRecord({
    ...trustValue,
    reviewedSourceCommit: commitOutput.trim(),
    builderSha256,
    castSha256,
  });
  const livePreflightEvidence = createZkIdentityStatusTestnetPreflightEvidence({
    trustRecord: liveTrust,
    publicTopology: {
      ...preflightEvidence.topology,
      operators: preflightEvidence.topology.operators.map((operator) => ({
        ...operator,
        builderSha256,
        castSha256,
      })),
    },
    providers: preflightEvidence.providers,
    observedAt: new Date("2026-08-18T17:00:00.000Z"),
  });
  const liveEvidence = await captureZkIdentityStatusTestnetHostAttestation({
    preflightEvidence: livePreflightEvidence,
    operatorConfig: liveOperator,
    operatorConfigPath: configPath,
    sourceDirectory: repository,
    observedAt: new Date("2026-08-18T19:00:00.000Z"),
  });
  assert.equal(liveEvidence.report.ready, true);
  assert.equal(liveEvidence.observation.keystoreAddress, operatorConfig.signerAddress);

  await writeFile(trackedPath, "locally modified\n", { mode: 0o600 });
  const dirtyEvidence = await captureZkIdentityStatusTestnetHostAttestation({
    preflightEvidence: livePreflightEvidence,
    operatorConfig: liveOperator,
    operatorConfigPath: configPath,
    sourceDirectory: repository,
    observedAt: new Date("2026-08-18T19:01:00.000Z"),
  });
  assert.equal(dirtyEvidence.report.ready, false);
  assert.ok(dirtyEvidence.report.alerts.includes("SOURCE_TRACKED_CHANGES"));
} finally {
  await rm(temporary, { recursive: true, force: true });
}

console.log("v2 status testnet host attestation: source + executables + keystore checks PASS");
