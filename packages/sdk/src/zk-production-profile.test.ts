import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  decodeFunctionData,
  getAddress,
  keccak256,
  parseAbi,
  stringToHex,
  type Address,
  type Hex,
} from "viem";
import {
  admitZkProductionProfile,
  createZkProductionProfileManifest,
  parseZkProductionProfileManifest,
  serializeZkProductionProfileManifest,
  type ZkProductionDeploymentSnapshot,
  type ZkProductionEvidence,
  type ZkProductionProfileInput,
} from "./zk-production-profile";

const address = (digit: string): Address => getAddress(`0x${digit.repeat(40)}`);
const digest = (label: string): Hex => keccak256(stringToHex(label));
const sha256 = (label: string): Hex => `0x${createHash("sha256").update(label).digest("hex")}`;
const evidence = (label: string): ZkProductionEvidence => ({
  uri: `https://artifacts.proofofhumanity.org/v2/${label}.json`,
  sha256: sha256(label),
});
const code = {
  governance: "0x600160005560016000f3" as Hex,
  versionRegistry: "0x600260005560026000f3" as Hex,
  rawVerifier: "0x600360005560036000f3" as Hex,
  predicateProver: "0x600460005560046000f3" as Hex,
  predicateVerifier: "0x600560005560056000f3" as Hex,
};
const addresses = {
  governance: address("1"),
  versionRegistry: address("2"),
  rawVerifier: address("3"),
  predicateProver: address("4"),
  predicateVerifier: address("5"),
};

function input(
  releaseStatus: ZkProductionProfileInput["releaseStatus"] = "production-approved",
): ZkProductionProfileInput {
  return {
    releaseStatus,
    approvedAt: releaseStatus === "production-approved" ? "2026-08-17T20:30:00.000Z" : null,
    sourceCommit: "12".repeat(20),
    circuit: {
      name: "v2.dynamic-status.production-1",
      circuitId: digest("v2 production circuit 1"),
      publicSignalLayoutVersion: 1,
      publicSignalCount: 18,
      proofSystem: "groth16-bn254/1",
      commitmentScheme: "poseidon-bn254-production/1",
      issuerAuthenticationScheme: "eddsa-babyjubjub-production/1",
      statusTreeScheme: "poseidon-packed-depth24-production/1",
      compiler: "arkworks-r1cs",
      compilerVersion: "0.5.1",
    },
    issuerKeyIds: [digest("issuer two"), digest("issuer one")],
    artifacts: {
      parameterManifest: evidence("parameter-manifest"),
      circuitSource: evidence("circuit-source"),
      constraintSystem: evidence("constraint-system"),
      compilerLock: evidence("compiler-lock"),
      proverArtifact: evidence("prover-artifact"),
      verifierArtifact: evidence("verifier-artifact"),
      verifierSource: evidence("verifier-source"),
      publicSignalManifest: evidence("public-signal-manifest"),
    },
    setup: {
      kind: "circuit-specific-mpc",
      contributionCount: 12,
      artifacts: [
        { kind: "phase1-transcript", ...evidence("phase1-transcript") },
        { kind: "phase2-transcript", ...evidence("phase2-transcript") },
        { kind: "final-beacon", ...evidence("final-beacon") },
        { kind: "contribution-verification", ...evidence("contribution-verification") },
        { kind: "independent-reproduction", ...evidence("independent-reproduction") },
      ],
    },
    audits: {
      criticalOpen: 0,
      highOpen: 0,
      reports: {
        circuit: evidence("circuit-audit"),
        cryptography: evidence("cryptography-audit"),
        solidity: evidence("solidity-audit"),
        privacy: evidence("privacy-review"),
        qa: evidence("qa-report"),
        reliability: evidence("reliability-report"),
        security: evidence("security-report"),
        acceptedRiskRegister: evidence("accepted-risk-register"),
      },
    },
    deviceBenchmarks: [
      {
        deviceClass: "mid-range-mobile",
        platform: "android-15",
        browser: "chromium-140",
        sampleSize: 30,
        proofP95Ms: 18_500,
        peakMemoryBytes: 384 * 1024 * 1024,
        report: evidence("mobile-performance-report"),
      },
    ],
    targets: [
      {
        network: "base",
        chainId: 8453,
        deployedAtBlock: "34567890",
        governance: addresses.governance,
        governanceCodehash: keccak256(code.governance),
        versionRegistry: addresses.versionRegistry,
        versionRegistryCodehash: keccak256(code.versionRegistry),
        rawVerifier: addresses.rawVerifier,
        rawVerifierCodehash: keccak256(code.rawVerifier),
        predicateProver: addresses.predicateProver,
        predicateProverCodehash: keccak256(code.predicateProver),
        predicateVerifier: addresses.predicateVerifier,
        predicateVerifierCodehash: keccak256(code.predicateVerifier),
        rawVerifierGas: 340_000,
        fullPathGas: 440_000,
        blockGasLimit: 30_000_000,
        gasReport: evidence("base-gas-report"),
        integrationReport: evidence("base-integration-report"),
      },
    ],
  };
}

function snapshot(): ZkProductionDeploymentSnapshot {
  return {
    chainId: 8453,
    observedAtBlock: "34567900",
    registryOwner: addresses.governance,
    predicateVerifierOwner: addresses.governance,
    predicateVerifierProver: address("0"),
    circuitRegistration: {
      verifier: address("0"),
      verifierCodehash: `0x${"00".repeat(32)}`,
      active: false,
    },
    runtimeBytecode: code,
  };
}

const manifest = createZkProductionProfileManifest(input());
assert.deepEqual(
  parseZkProductionProfileManifest(JSON.parse(serializeZkProductionProfileManifest(manifest))),
  manifest,
);
assert.deepEqual(manifest.issuerKeyIds, [...manifest.issuerKeyIds].sort());
const normalizedBenchmarks = createZkProductionProfileManifest({
  ...input(),
  deviceBenchmarks: [
    input().deviceBenchmarks[0]!,
    {
      ...input().deviceBenchmarks[0]!,
      deviceClass: "flagship-mobile",
      report: evidence("flagship-performance-report"),
    },
  ],
});
assert.deepEqual(
  normalizedBenchmarks.deviceBenchmarks.map(({ deviceClass }) => deviceClass),
  ["flagship-mobile", "mid-range-mobile"],
);

const admission = admitZkProductionProfile({ manifest, snapshot: snapshot() });
assert.equal(admission.chainId, 8453);
assert.equal(admission.registrationCalls.length, 3);
assert.equal(admission.proofPathActivation.executeOnlyAfterStatusAdmission, true);
const registryAbi = parseAbi([
  "function registerCircuit(bytes32 circuitId,address verifier)",
  "function authorizeIssuer(bytes32 circuitId,bytes32 issuerKeyId)",
]);
assert.deepEqual(decodeFunctionData({ abi: registryAbi, data: admission.registrationCalls[0]!.data }), {
  functionName: "registerCircuit",
  args: [manifest.circuit.circuitId, addresses.rawVerifier],
});

const candidate = createZkProductionProfileManifest(input("candidate"));
assert.deepEqual(parseZkProductionProfileManifest(candidate), candidate);
assert.throws(
  () => admitZkProductionProfile({ manifest: candidate, snapshot: snapshot() }),
  /has not been approved/u,
);

assert.throws(
  () => parseZkProductionProfileManifest({ ...manifest, sourceCommit: "34".repeat(20) }),
  /manifest hash mismatch/u,
);
assert.throws(
  () => parseZkProductionProfileManifest({ ...manifest, injected: true }),
  /missing or unknown fields/u,
);

const unsafeName = createZkProductionProfileManifest({
  ...input(),
  circuit: { ...input().circuit, name: "v2.dynamic-status.research-1" },
});
assert.throws(
  () => admitZkProductionProfile({ manifest: unsafeName, snapshot: snapshot() }),
  /non-production evidence or identifiers/u,
);
for (const circuitId of [
  digest("ubi2.zk-identity.v2.packed-status.research-1"),
  digest("ubi2.zk-identity.v2.dynamic-status-packed-research-1"),
]) {
  const renamedResearchCircuit = createZkProductionProfileManifest({
    ...input(),
    circuit: { ...input().circuit, circuitId },
  });
  assert.throws(
    () => admitZkProductionProfile({ manifest: renamedResearchCircuit, snapshot: snapshot() }),
    /prohibited research circuit id/u,
  );
}
for (const rawVerifierCodehash of [
  "0x51391a6337e1723e8ebc4a6a284e7f0a996d41b6ec476cdba56ddd1da7d964fa",
  "0x4bd30512624c62747d8a6e1b34405550f09939d798bb7f6c22dcb910b0352a7c",
] as const) {
  const renamedResearchVerifier = createZkProductionProfileManifest({
    ...input(),
    targets: [{ ...input().targets[0]!, rawVerifierCodehash }],
  });
  assert.throws(
    () => admitZkProductionProfile({ manifest: renamedResearchVerifier, snapshot: snapshot() }),
    /prohibited research verifier codehash/u,
  );
}
const openHigh = createZkProductionProfileManifest({
  ...input(),
  audits: { ...input().audits, highOpen: 1 },
});
assert.throws(
  () => admitZkProductionProfile({ manifest: openHigh, snapshot: snapshot() }),
  /open Critical or High/u,
);
const undersampled = createZkProductionProfileManifest({
  ...input(),
  deviceBenchmarks: [{ ...input().deviceBenchmarks[0]!, sampleSize: 19 }],
});
assert.throws(
  () => admitZkProductionProfile({ manifest: undersampled, snapshot: snapshot() }),
  /representative mid-range-mobile/u,
);

assert.throws(
  () =>
    admitZkProductionProfile({
      manifest,
      snapshot: { ...snapshot(), chainId: 1 },
    }),
  /absent from the production profile/u,
);
assert.throws(
  () =>
    admitZkProductionProfile({
      manifest,
      snapshot: { ...snapshot(), observedAtBlock: "34567889" },
    }),
  /observation predates the approved deployment/u,
);
assert.throws(
  () =>
    admitZkProductionProfile({
      manifest,
      snapshot: { ...snapshot(), registryOwner: address("9") },
    }),
  /version registry is not owned/u,
);
assert.throws(
  () =>
    admitZkProductionProfile({
      manifest,
      snapshot: { ...snapshot(), predicateVerifierProver: addresses.predicateProver },
    }),
  /proof path must remain unset/u,
);
assert.throws(
  () =>
    admitZkProductionProfile({
      manifest,
      snapshot: {
        ...snapshot(),
        circuitRegistration: {
          verifier: addresses.rawVerifier,
          verifierCodehash: keccak256(code.rawVerifier),
          active: true,
        },
      },
    }),
  /already registered/u,
);
assert.throws(
  () =>
    admitZkProductionProfile({
      manifest,
      snapshot: {
        ...snapshot(),
        runtimeBytecode: { ...snapshot().runtimeBytecode, rawVerifier: "0x6000" },
      },
    }),
  /raw verifier runtime codehash mismatch/u,
);
assert.throws(
  () =>
    createZkProductionProfileManifest({
      ...input(),
      setup: { ...input().setup, artifacts: input().setup.artifacts.slice(1) },
    }),
  /setup evidence does not match/u,
);
assert.throws(
  () =>
    createZkProductionProfileManifest({
      ...input(),
      targets: [{ ...input().targets[0]!, fullPathGas: 30_000_000 }],
    }),
  /do not fit the target block budget/u,
);
assert.throws(
  () =>
    createZkProductionProfileManifest({
      ...input(),
      targets: [{ ...input().targets[0]!, deployedAtBlock: "0" }],
    }),
  /deployment block must be greater than zero/u,
);
assert.throws(
  () =>
    createZkProductionProfileManifest({
      ...input(),
      deviceBenchmarks: [input().deviceBenchmarks[0]!, input().deviceBenchmarks[0]!],
    }),
  /device benchmark environments must be unique/u,
);
assert.throws(
  () =>
    createZkProductionProfileManifest({
      ...input(),
      artifacts: {
        ...input().artifacts,
        parameterManifest: {
          ...input().artifacts.parameterManifest,
          uri: "https://artifacts.proofofhumanity.org/v2/parameters.json?mutable=true",
        },
      },
    }),
  /must not contain credentials, a query or a fragment/u,
);

console.log("v2 production profile: manifest + live admission gate PASS");
