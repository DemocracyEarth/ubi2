import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import {
  createZkIdentityPackedStatusAttestation,
  parseZkIdentityPackedStatusAttestation,
  parseZkIdentityPackedStatusSnapshot,
  reconcileZkIdentityPackedStatusSnapshots,
  reconciledZkIdentityStatusPublication,
  recoverZkIdentityPackedStatusAttestationSigner,
  serializeZkIdentityPackedStatusAttestation,
  serializeZkIdentityPackedStatusSnapshot,
  zkIdentityPackedStatusAttestationDigest,
  zkIdentityPackedStatusAttestationTypedData,
  zkIdentityPackedStatusSnapshotHash,
} from "./zk-identity-status-snapshot";

const reconcilerA = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8411ddca14bb03ea63",
);
const reconcilerB = privateKeyToAccount(
  "0x8b3a350cf5c34c9194ca3a545d4f80aa3102b4c3b8d1b5e1d4f6f7c8d9e0a123",
);
const outsider = privateKeyToAccount(
  "0x0dbbe8e4e4a29549cb4fd469f5914c9fc6f34b1d4595d07a1f39c643f550a112",
);
const fixtureJson = readFileSync(
  new URL("../../../tools/v2-crypto-bench/fixtures/packed-status-snapshot.json", import.meta.url),
  "utf8",
).trim();
const snapshot = parseZkIdentityPackedStatusSnapshot(JSON.parse(fixtureJson));

assert.equal(serializeZkIdentityPackedStatusSnapshot(snapshot), fixtureJson);
assert.equal(snapshot.nextStatusId, 3);
assert.equal(snapshot.activatedThroughStatusId, 2);
assert.equal(snapshot.chunks[0]?.value.endsWith("fb"), true);

const snapshotHash = zkIdentityPackedStatusSnapshotHash(snapshot);
const attestationDigest = zkIdentityPackedStatusAttestationDigest(snapshot);
assert.equal(
  snapshotHash,
  "0x8ba6ee710cadc5c2019c6c2fa8920f7376212abc86610b8964435982ad912635",
  "canonical builder content hash drift requires explicit distribution review",
);
assert.equal(
  attestationDigest,
  "0x5223432137ea4b34be7ec38ded39daf6e1a75be4dcfc5f4f84f9c815625eeae3",
  "EIP-712 attestation drift requires explicit reconciler review",
);

const signatureA = await reconcilerA.signTypedData(
  zkIdentityPackedStatusAttestationTypedData(snapshot),
);
const signatureB = await reconcilerB.signTypedData(
  zkIdentityPackedStatusAttestationTypedData(snapshot),
);
const attestationA = createZkIdentityPackedStatusAttestation(snapshot, signatureA);
const attestationB = createZkIdentityPackedStatusAttestation(snapshot, signatureB);
assert.deepEqual(parseZkIdentityPackedStatusAttestation(attestationA), attestationA);
assert.deepEqual(
  parseZkIdentityPackedStatusAttestation(
    JSON.parse(serializeZkIdentityPackedStatusAttestation(attestationA)),
  ),
  attestationA,
);
assert.equal(
  await recoverZkIdentityPackedStatusAttestationSigner(attestationA),
  reconcilerA.address,
);

const reconciled = await reconcileZkIdentityPackedStatusSnapshots({
  attestations: [attestationA, attestationB],
  expectedReconcilers: [reconcilerA.address, reconcilerB.address],
});
assert.equal(reconciled.snapshotHash, snapshotHash);
assert.deepEqual(reconciled.signers, [reconcilerA.address, reconcilerB.address].sort());
assert.deepEqual(reconciledZkIdentityStatusPublication(reconciled), {
  issuerKeyId: snapshot.issuerKeyId,
  expectedNextStatusId: 3n,
  root: snapshot.root,
});

await assert.rejects(
  reconcileZkIdentityPackedStatusSnapshots({
    attestations: [attestationA],
    expectedReconcilers: [reconcilerA.address, reconcilerB.address],
  }),
  /threshold/u,
);
await assert.rejects(
  reconcileZkIdentityPackedStatusSnapshots({
    attestations: [attestationA, attestationA],
    expectedReconcilers: [reconcilerA.address, reconcilerB.address],
  }),
  /duplicate signer/u,
);

const outsiderSignature = await outsider.signTypedData(
  zkIdentityPackedStatusAttestationTypedData(snapshot),
);
await assert.rejects(
  reconcileZkIdentityPackedStatusSnapshots({
    attestations: [attestationA, createZkIdentityPackedStatusAttestation(snapshot, outsiderSignature)],
    expectedReconcilers: [reconcilerA.address, reconcilerB.address],
  }),
  /not an expected reconciler/u,
);

const splitSnapshot = parseZkIdentityPackedStatusSnapshot({
  ...snapshot,
  root: "0x2e3cff981778afb5fdfa099bcc7f6c0b291f969667837d16da914895f2f4becb",
});
const splitSignature = await reconcilerB.signTypedData(
  zkIdentityPackedStatusAttestationTypedData(splitSnapshot),
);
await assert.rejects(
  reconcileZkIdentityPackedStatusSnapshots({
    attestations: [
      attestationA,
      createZkIdentityPackedStatusAttestation(splitSnapshot, splitSignature),
    ],
    expectedReconcilers: [reconcilerA.address, reconcilerB.address],
  }),
  /split snapshot/u,
);

const otherChainSnapshot = parseZkIdentityPackedStatusSnapshot({ ...snapshot, chainId: "1" });
const replayedSignature = createZkIdentityPackedStatusAttestation(
  otherChainSnapshot,
  signatureA,
);
assert.notEqual(
  await recoverZkIdentityPackedStatusAttestationSigner(replayedSignature),
  reconcilerA.address,
  "an attestation signature cannot replay onto another source chain",
);

assert.throws(
  () => parseZkIdentityPackedStatusSnapshot({ ...snapshot, injected: true }),
  /missing or unknown/u,
);
assert.throws(
  () =>
    parseZkIdentityPackedStatusSnapshot({
      ...snapshot,
      chunks: [
        {
          index: 0,
          value: "0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3",
        },
      ],
    }),
  /unallocated tail/u,
);
assert.throws(
  () =>
    parseZkIdentityPackedStatusAttestation({
      ...attestationA,
      snapshotHash: `0x${"11".repeat(32)}`,
    }),
  /does not match/u,
);

console.log(
  `zk packed-status snapshot: hash ${snapshotHash}, attestation ${attestationDigest}, 2-of-2 reconciliation PASS`,
);
