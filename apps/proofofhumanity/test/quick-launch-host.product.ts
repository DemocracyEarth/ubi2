import assert from "node:assert/strict";
import { getAddress, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  assessQuickLaunchHostProbe,
  type QuickLaunchHostPublicProbe,
} from "../app/quick-launch-host";
import { quickLaunchHostReadiness } from "../app/lib/server/quick-launch-host-readiness";
import { QUICK_LAUNCH_RELEASE } from "../app/quick-launch";
import blockedHostEvidence from "../../../ops/proofofhumanity/evidence/quick-launch-host-preflight-2026-08-30.json";

const ISSUER_KEY = `0x${"0".repeat(63)}1` as Hex;
const SPONSOR_KEY = `0x${"0".repeat(63)}2` as Hex;
const OWNER_KEY = `0x${"0".repeat(63)}3` as Hex;
const issuer = getAddress(privateKeyToAccount(ISSUER_KEY).address);
const sponsor = getAddress(privateKeyToAccount(SPONSOR_KEY).address);
const owner = getAddress(privateKeyToAccount(OWNER_KEY).address);
const digest = (character: string) => character.repeat(64);

const validProbe: QuickLaunchHostPublicProbe = {
  sourceRevision: "d".repeat(40),
  selfEndpoint: QUICK_LAUNCH_RELEASE.canonicalSelfEndpoint,
  selfEnvironment: "staging",
  singleStickyNodeDeclared: true,
  topologyAttestationSha256: digest("a"),
  issuerSecretAttestationSha256: digest("b"),
  issuerAddress: issuer,
  sponsorSecretAttestationSha256: digest("c"),
  sponsorAddress: sponsor,
  sponsorEnabledChainIds: [84_532],
  sponsorPolicyValid: true,
};
const expected = { issuer, owner, selfEndpoint: QUICK_LAUNCH_RELEASE.canonicalSelfEndpoint };
assert.deepEqual(assessQuickLaunchHostProbe(validProbe, expected), { ready: true, blockers: [] });

function rejects(
  overrides: Partial<QuickLaunchHostPublicProbe>,
  blocker: ReturnType<typeof assessQuickLaunchHostProbe>["blockers"][number],
  customExpected = expected,
): void {
  const result = assessQuickLaunchHostProbe({ ...validProbe, ...overrides }, customExpected);
  assert.equal(result.ready, false);
  assert.ok(result.blockers.includes(blocker), `${blocker} was not reported: ${result.blockers.join(", ")}`);
}

rejects({ sourceRevision: null }, "source-revision-unavailable");
rejects({ sourceRevision: "d".repeat(39) }, "source-revision-unavailable");
rejects({ selfEndpoint: "https://preview.example/api/self-verify" }, "self-endpoint-mismatch");
rejects({ selfEnvironment: "production" }, "self-environment-not-staging");
rejects({ singleStickyNodeDeclared: false }, "single-sticky-node-not-declared");
rejects({ topologyAttestationSha256: null }, "topology-attestation-missing");
rejects({ issuerSecretAttestationSha256: null }, "issuer-secret-attestation-missing");
rejects({ issuerAddress: null }, "issuer-key-unavailable");
rejects({ issuerAddress: sponsor }, "issuer-address-mismatch");
rejects({ sponsorSecretAttestationSha256: null }, "sponsor-secret-attestation-missing");
rejects({ sponsorAddress: null }, "sponsor-key-unavailable");
rejects({ sponsorPolicyValid: false }, "sponsor-policy-invalid");
rejects({ sponsorEnabledChainIds: [] }, "sponsor-policy-invalid");
rejects({ sponsorEnabledChainIds: [84_532, 11_155_111] }, "sponsor-policy-invalid");
rejects({ sponsorAddress: issuer }, "sponsor-role-overlap");
rejects({ sponsorAddress: owner }, "sponsor-role-overlap");

const env: NodeJS.ProcessEnv = {
  NODE_ENV: "production",
  POH_SOURCE_REVISION: "d".repeat(40),
  NEXT_PUBLIC_SELF_ENDPOINT: QUICK_LAUNCH_RELEASE.canonicalSelfEndpoint,
  NEXT_PUBLIC_SELF_ENV: "staging",
  POH_RUNTIME_TOPOLOGY: "single-sticky-node",
  POH_TOPOLOGY_ATTESTATION_SHA256: digest("a"),
  POH_ISSUER_SECRET_ATTESTATION_SHA256: digest("b"),
  ISSUER_PRIVATE_KEY: ISSUER_KEY,
  POH_SPONSOR_SECRET_ATTESTATION_SHA256: digest("c"),
  POH_SPONSOR_PRIVATE_KEY: SPONSOR_KEY,
  POH_SPONSOR_TESTNET_CHAIN_IDS: "84532",
};
const readiness = quickLaunchHostReadiness(env, expected);
assert.equal(readiness.ready, true);
assert.equal(readiness.issuerAddress, issuer);
assert.equal(readiness.sponsorAddress, sponsor);
assert.deepEqual(readiness.sponsorEnabledChainIds, [84_532]);
const serialized = JSON.stringify(readiness);
assert.equal(serialized.includes(ISSUER_KEY), false);
assert.equal(serialized.includes(SPONSOR_KEY), false);

const noSecrets = quickLaunchHostReadiness(
  {
    ...env,
    ISSUER_PRIVATE_KEY: undefined,
    POH_SPONSOR_PRIVATE_KEY: undefined,
    POH_SPONSOR_TESTNET_CHAIN_IDS: undefined,
  },
  expected,
);
assert.equal(noSecrets.ready, false);
assert.ok(noSecrets.blockers.includes("issuer-key-unavailable"));
assert.ok(noSecrets.blockers.includes("sponsor-key-unavailable"));

const malformedSponsor = quickLaunchHostReadiness(
  { ...env, POH_SPONSOR_MAX_GAS: "unbounded" },
  expected,
);
assert.equal(malformedSponsor.ready, false);
assert.ok(malformedSponsor.blockers.includes("sponsor-policy-invalid"));
assert.equal(JSON.stringify(malformedSponsor).includes("unbounded"), false);

const malformedPublicValues = quickLaunchHostReadiness(
  {
    ...env,
    NEXT_PUBLIC_SELF_ENDPOINT: "https://user:password@invalid.example/api/self-verify",
    NEXT_PUBLIC_SELF_ENV: "password",
    POH_SOURCE_REVISION: "password",
    POH_TOPOLOGY_ATTESTATION_SHA256: "password",
  },
  expected,
);
assert.equal(malformedPublicValues.ready, false);
assert.equal(JSON.stringify(malformedPublicValues).includes("password"), false);

assert.equal(blockedHostEvidence.transactionFree, true);
assert.equal(blockedHostEvidence.publicChainPreflight.ready, true);
assert.equal(blockedHostEvidence.publicSurface.originTopologyVerified, false);
assert.equal(blockedHostEvidence.externalAttestations.issuerSecretPathVerified, false);
assert.equal(blockedHostEvidence.externalAttestations.sponsorSecretPathVerified, false);
assert.equal(blockedHostEvidence.ready, false);
const evidenceJson = JSON.stringify(blockedHostEvidence);
for (const forbidden of ["privateKey", "password", "mnemonic", "seedPhrase", "rawSecret", ".env"]) {
  assert.equal(evidenceJson.includes(forbidden), false, `blocked evidence contains forbidden field ${forbidden}`);
}

console.log("Quick Launch host readiness, role separation, and secret-redaction failures: PASS");
