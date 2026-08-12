import assert from "node:assert/strict";
import { keccak256, stringToBytes } from "viem";
import {
  countrySetCommitment,
  normalizeZkIdentityPolicy,
  serializeZkIdentityPolicy,
  zkIdentityPolicyHash,
  zkPresentationBindingHash,
} from "./zk-identity-policy";

const age = normalizeZkIdentityPolicy({
  kind: "age-range",
  minimumInclusive: 18,
  maximumExclusive: 65,
  referenceDate: "2026-08-12",
});
assert.deepEqual(age, {
  schema: "org.proofofhumanity.zk-policy",
  version: 1,
  kind: "age-range",
  minimumInclusive: 18,
  maximumExclusive: 65,
  referenceDate: "2026-08-12",
});
assert.equal(JSON.parse(serializeZkIdentityPolicy(age)).kind, "age-range");
assert.equal(
  zkIdentityPolicyHash(age),
  "0x3f71ddd64fc1edef180756674529dd32b2c90f7288d2f0ced062e781a0cda3a2",
  "age policy vector is pinned for circuit/contract parity",
);

const euRoot = countrySetCommitment({ setId: "eu-eea:2026-08", members: ["NOR", "ARG", "DEU", "ARG"] });
assert.equal(euRoot, "0x8c534f5e9d271d455fc8a3f21a6e2faf3a2584dc8a1e1b6ade25c61de71df245");
assert.equal(
  euRoot,
  countrySetCommitment({ setId: "eu-eea:2026-08", members: ["DEU", "NOR", "ARG"] }),
  "country commitments sort and deduplicate members",
);
const countryPolicy = normalizeZkIdentityPolicy({
  kind: "country-set",
  attribute: "nationality",
  operator: "in",
  setId: "eu-eea:2026-08",
  setRoot: euRoot,
});
assert.equal(
  zkIdentityPolicyHash(countryPolicy),
  "0xace19152a22fb55223bb3931b2fa4a96b7df79bf75f5dcad2468d2c82dfda734",
  "country-set policy vector is pinned for circuit/contract parity",
);
assert.notEqual(zkIdentityPolicyHash(countryPolicy), zkIdentityPolicyHash(age));

const status = normalizeZkIdentityPolicy({
  kind: "dynamic-status",
  status: "sanctions-clear",
  providerId: "self:ofac",
  listVersion: "2026-08-12",
  statusRoot: keccak256(stringToBytes("demo status root")),
  maximumAgeSeconds: 86_400,
});
assert.equal(status.maximumAgeSeconds, 86_400);

const policyHash = zkIdentityPolicyHash(age);
const bindingHash = zkPresentationBindingHash({
  policyHash,
  chainId: 84532,
  verifier: "0x1111111111111111111111111111111111111111",
  consumer: "0x2222222222222222222222222222222222222222",
  subject: "0x3333333333333333333333333333333333333333",
  context: keccak256(stringToBytes("membership:season-1")),
  challenge: keccak256(stringToBytes("challenge-1")),
  epoch: 230,
});
assert.equal(
  bindingHash,
  "0xfcbaa318d3aba026a8827d332ec45ae24e9dbdd9ca6029b6fd3741b4e670e7a0",
  "presentation binding vector is pinned for circuit/contract parity",
);
assert.notEqual(
  bindingHash,
  zkPresentationBindingHash({
    policyHash,
    chainId: 84532,
    verifier: "0x1111111111111111111111111111111111111111",
    consumer: "0x2222222222222222222222222222222222222222",
    subject: "0x3333333333333333333333333333333333333333",
    context: keccak256(stringToBytes("membership:season-2")),
    challenge: keccak256(stringToBytes("challenge-1")),
    epoch: 230,
  }),
  "context changes the EVM binding",
);

assert.throws(
  () => normalizeZkIdentityPolicy({ kind: "age-range", minimumInclusive: 21, maximumExclusive: 18, referenceDate: "2026-08-12" }),
  /maximum age/,
);
assert.throws(
  () => normalizeZkIdentityPolicy({ kind: "document-validity", referenceDate: "2026-02-29", minimumRemainingDays: 90 }),
  /valid civil date/,
);
assert.throws(
  () => countrySetCommitment({ setId: "empty:v1", members: [] }),
  /1 to 256/,
);
assert.throws(
  () => normalizeZkIdentityPolicy({ kind: "private-field-match", field: "name", expectedCommitment: keccak256(stringToBytes("name")), consentRequired: false as true }),
  /explicit consent/,
);
assert.throws(
  () => zkIdentityPolicyHash({ ...age, version: 2 as 1 }),
  /unsupported ZK identity policy version/,
);
assert.throws(
  () => normalizeZkIdentityPolicy({ ...countryPolicy, operator: "equals" as "in" }),
  /unsupported country-set operator/,
);
assert.throws(
  () => normalizeZkIdentityPolicy({ kind: "unknown" } as never),
  /unsupported ZK identity policy kind/,
);

console.log("zk identity policy: normalization + policy hashes + EVM presentation binding PASS");
