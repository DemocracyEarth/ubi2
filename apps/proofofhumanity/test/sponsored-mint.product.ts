import assert from "node:assert/strict";
import { getAddress, type Address, type Hex } from "viem";
import type { ChainConfig } from "../app/config";
import { FixedWindowRateLimiter } from "../app/lib/fixed-window-rate-limit";
import {
  parseSponsoredTestnetAllowlist,
  sponsoredMintAttemptEvidence,
  validateSponsoredMintBinding,
  type SponsoredMintAttempt,
} from "../app/lib/sponsored-mint";
import type { SignedForChain } from "../app/lib/verification-record";

const recipient = getAddress("0x1111111111111111111111111111111111111111");
const other = getAddress("0x2222222222222222222222222222222222222222");
const poh = getAddress("0x3333333333333333333333333333333333333333");
const signature = `0x${"11".repeat(65)}` as Hex;

function chain(overrides: Partial<ChainConfig> = {}): ChainConfig {
  return {
    chainId: 11_155_111,
    name: "Testnet",
    network: "testnet",
    rpcUrl: "https://rpc.invalid",
    pohAddress: poh,
    predicateAddress: "0x0000000000000000000000000000000000000000",
    explorer: "https://explorer.invalid",
    ...overrides,
  };
}

function signed(overrides: Partial<SignedForChain> = {}): SignedForChain {
  return {
    chainId: 11_155_111,
    name: "Testnet",
    pohAddress: poh,
    voucher: { to: recipient, nullifier: "123456789", epoch: 42 },
    signature,
    ...overrides,
  };
}

const proof = { nullifier: "123456789", epoch: 42 };
const bound = validateSponsoredMintBinding({ capabilityAddress: recipient, chain: chain(), signed: signed(), proof });
assert.deepEqual(bound, { to: recipient, nullifier: 123456789n, epoch: 42 });

assert.throws(
  () => validateSponsoredMintBinding({ capabilityAddress: other, chain: chain(), signed: signed(), proof }),
  /recipient does not match/u,
);
assert.throws(
  () =>
    validateSponsoredMintBinding({
      capabilityAddress: recipient,
      chain: chain(),
      signed: signed({ chainId: 84_532 }),
      proof,
    }),
  /different chain/u,
);
assert.throws(
  () =>
    validateSponsoredMintBinding({
      capabilityAddress: recipient,
      chain: chain(),
      signed: signed({ pohAddress: other }),
      proof,
    }),
  /different contract/u,
);
assert.throws(
  () =>
    validateSponsoredMintBinding({
      capabilityAddress: recipient,
      chain: chain(),
      signed: signed(),
      proof: { ...proof, nullifier: "987654321" },
    }),
  /proof-derived record/u,
);
assert.throws(
  () =>
    validateSponsoredMintBinding({
      capabilityAddress: recipient,
      chain: chain({ network: "mainnet" }),
      signed: signed(),
      proof,
    }),
  /restricted to explicit testnets/u,
);
assert.throws(
  () =>
    validateSponsoredMintBinding({
      capabilityAddress: recipient,
      chain: chain(),
      signed: signed({ signature: "0x1234" }),
      proof,
    }),
  /signature is malformed/u,
);

const configuredChains = [
  chain(),
  chain({ chainId: 84_532, name: "Other testnet", pohAddress: other }),
  chain({ chainId: 1, name: "Mainnet", network: "mainnet" }),
  chain({ chainId: 31_337, name: "Local", network: "local" }),
];
assert.deepEqual(parseSponsoredTestnetAllowlist("11155111, 84532,11155111", configuredChains), [
  11_155_111,
  84_532,
]);
assert.throws(() => parseSponsoredTestnetAllowlist("1", configuredChains), /not a configured, deployed testnet/u);
assert.throws(() => parseSponsoredTestnetAllowlist("31337", configuredChains), /not a configured, deployed testnet/u);
assert.throws(() => parseSponsoredTestnetAllowlist("11155111,nope", configuredChains), /positive integers/u);
assert.throws(
  () =>
    parseSponsoredTestnetAllowlist(
      "84532",
      configuredChains.map((candidate) =>
        candidate.chainId === 84_532
          ? { ...candidate, pohAddress: "0x0000000000000000000000000000000000000000" as Address }
          : candidate,
      ),
    ),
  /not a configured, deployed testnet/u,
);

let now = 1_000;
const limiter = new FixedWindowRateLimiter(10, () => now);
assert.deepEqual(limiter.take("sponsor", recipient, 2, 60), { allowed: true, retryAfter: 59 });
assert.equal(limiter.take("sponsor", recipient, 2, 60).allowed, true);
const limited = limiter.take("sponsor", recipient, 2, 60);
assert.equal(limited.allowed, false);
assert.equal(limited.retryAfter, 59);
assert.equal(limiter.take("sponsor", other, 2, 60).allowed, true, "a separate account has a separate quota");
now = 60_000;
assert.equal(limiter.take("sponsor", recipient, 2, 60).allowed, true, "quota resets in the next window");

now = 1_000;
const boundedLimiter = new FixedWindowRateLimiter(2, () => now);
assert.equal(boundedLimiter.take("source", "one", 2, 60).allowed, true);
assert.equal(boundedLimiter.take("budget", "11155111", 2, 60).allowed, true);
assert.equal(
  boundedLimiter.take("source", "flood", 2, 60).allowed,
  false,
  "capacity exhaustion fails closed instead of evicting a live spend budget",
);
assert.equal(
  boundedLimiter.take("budget", "11155111", 2, 60).allowed,
  true,
  "an existing spend budget remains enforced at capacity",
);
assert.equal(boundedLimiter.take("budget", "11155111", 2, 60).allowed, false);
now = 60_000;
assert.equal(boundedLimiter.take("source", "flood", 2, 60).allowed, true, "expired capacity is reclaimed");

const attempt = {
  status: "submitted",
  attempts: 1,
  startedAt: 1_000,
  submittedAt: 2_000,
  transactionHash: `0x${"ab".repeat(32)}`,
} satisfies SponsoredMintAttempt;
const evidence = sponsoredMintAttemptEvidence(attempt, chain(), recipient);
assert.deepEqual(evidence, {
  schema: "poh-sponsored-mint-receipt",
  version: 1,
  status: "submitted",
  chainId: 11_155_111,
  chainName: "Testnet",
  contract: poh,
  recipient,
  transactionHash: attempt.transactionHash,
  submittedAt: new Date(2_000).toISOString(),
});
assert.equal(JSON.stringify(evidence).includes("PRIVATE_KEY"), false);

console.log("sponsored mint policy: binding, testnet gating, quotas, and public evidence passed");
