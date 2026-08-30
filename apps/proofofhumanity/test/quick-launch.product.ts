import assert from "node:assert/strict";
import { getAddress, type Address, type Hex } from "viem";
import type { ChainConfig } from "../app/config";
import { decodeDisclosureRequest, encodeDisclosureRequest, encodeV2IssuanceRequest } from "../app/lib/disclosure-profile";
import {
  QUICK_LAUNCH_CHAIN,
  QUICK_LAUNCH_CHAINS,
  QUICK_LAUNCH_RELEASE,
  assessQuickLaunchPublicProbe,
  isQuickLaunchDisclosureRequest,
  selectQuickLaunchChain,
  type QuickLaunchPublicProbe,
} from "../app/quick-launch";

assert.equal(QUICK_LAUNCH_CHAINS.length, 1);
assert.equal(QUICK_LAUNCH_CHAIN.chainId, 84_532);
assert.equal(QUICK_LAUNCH_CHAIN.name, "Base Sepolia");
assert.equal(QUICK_LAUNCH_CHAIN.network, "testnet");
assert.equal(QUICK_LAUNCH_RELEASE.features.mainnet, false);
assert.equal(QUICK_LAUNCH_RELEASE.features.demoCredentials, false);
assert.equal(QUICK_LAUNCH_RELEASE.features.holderVault, false);
assert.equal(QUICK_LAUNCH_RELEASE.features.v2Issuance, false);
assert.equal(QUICK_LAUNCH_RELEASE.features.v2PredicateProver, false);

assert.throws(() => selectQuickLaunchChain([]), /exactly one chain 84532; found 0/u);
assert.throws(
  () => selectQuickLaunchChain([QUICK_LAUNCH_CHAIN, { ...QUICK_LAUNCH_CHAIN }]),
  /exactly one chain 84532; found 2/u,
);
assert.throws(
  () => selectQuickLaunchChain([{ ...QUICK_LAUNCH_CHAIN, network: "mainnet" }]),
  /must remain classified as a public testnet/u,
);

const session = "0123456789abcdef0123456789abcdef";
const v1Request = decodeDisclosureRequest(encodeDisclosureRequest({ age: 21, nationality: true }, session));
assert.ok(v1Request && isQuickLaunchDisclosureRequest(v1Request));
const v2Request = decodeDisclosureRequest(
  encodeV2IssuanceRequest(
    { age: 21, nationality: true },
    session,
    "0x00000000000000000000000000000000000000000000000000000000075bcd15",
  ),
);
assert.ok(v2Request && !isQuickLaunchDisclosureRequest(v2Request));

const validProbe: QuickLaunchPublicProbe = {
  chainId: QUICK_LAUNCH_RELEASE.chainId,
  pohAddress: QUICK_LAUNCH_RELEASE.proofOfHumanity,
  predicateAddress: QUICK_LAUNCH_RELEASE.predicateVerifier,
  pohCode: "0x6000" as Hex,
  predicateCode: "0x6001" as Hex,
  pohOwner: QUICK_LAUNCH_RELEASE.expectedOwner,
  pohIssuer: QUICK_LAUNCH_RELEASE.expectedIssuer,
  predicateOwner: QUICK_LAUNCH_RELEASE.expectedOwner,
  predicateIssuer: QUICK_LAUNCH_RELEASE.expectedIssuer,
  predicateProver: getAddress("0x0000000000000000000000000000000000000000"),
  selfEndpoint: "https://poh.example/api/self-verify",
  selfEnvironment: "staging",
};
assert.deepEqual(assessQuickLaunchPublicProbe(validProbe), { ready: true, errors: [] });

function rejects(overrides: Partial<QuickLaunchPublicProbe>, pattern: RegExp): void {
  const result = assessQuickLaunchPublicProbe({ ...validProbe, ...overrides });
  assert.equal(result.ready, false);
  assert.match(result.errors.join("\n"), pattern);
}

rejects({ chainId: 1 }, /RPC chain id/u);
rejects({ pohAddress: getAddress("0x1111111111111111111111111111111111111111") }, /Configured ProofOfHumanity/u);
rejects({ predicateAddress: getAddress("0x1111111111111111111111111111111111111111") }, /Configured PredicateVerifier/u);
rejects({ pohCode: "0x" }, /ProofOfHumanity has no deployed bytecode/u);
rejects({ predicateCode: "0x" }, /PredicateVerifier has no deployed bytecode/u);
rejects({ pohOwner: getAddress("0x1111111111111111111111111111111111111111") }, /ProofOfHumanity owner/u);
rejects({ predicateOwner: getAddress("0x1111111111111111111111111111111111111111") }, /PredicateVerifier owner/u);
rejects({ pohIssuer: getAddress("0x2222222222222222222222222222222222222222") }, /ProofOfHumanity issuer/u);
rejects({ predicateIssuer: getAddress("0x2222222222222222222222222222222222222222") }, /PredicateVerifier issuer/u);
rejects({ predicateProver: getAddress("0x3333333333333333333333333333333333333333") }, /prover must remain zero/u);
rejects({ selfEnvironment: "preview" }, /must be exactly staging or production/u);
rejects({ selfEndpoint: "" }, /absolute public HTTPS URL/u);
rejects({ selfEndpoint: "http://poh.example/api/self-verify" }, /must use HTTPS/u);
rejects({ selfEndpoint: "https://localhost/api/self-verify" }, /must not use a loopback host/u);
rejects({ selfEndpoint: "https://user:pass@poh.example/api/self-verify" }, /must not contain credentials/u);
rejects({ selfEndpoint: "https://poh.example/not-the-callback" }, /point exactly to \/api\/self-verify/u);

const foreignTestnet: ChainConfig = {
  ...QUICK_LAUNCH_CHAIN,
  chainId: 11_155_111,
  name: "Ethereum Sepolia",
  pohAddress: getAddress("0x1111111111111111111111111111111111111111") as Address,
};
assert.throws(() => selectQuickLaunchChain([foreignTestnet]), /found 0/u);

console.log("Quick Launch product boundary and transaction-free preflight failures: PASS");
