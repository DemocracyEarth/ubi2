import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { privateKeyToAccount } from "viem/accounts";
import { encodeAbiParameters, keccak256, stringToBytes, toHex, type Hex } from "viem";
import {
  buildZkHolderIssuanceTranscript,
  parseZkHolderCredentialCommitment,
  parseZkHolderIssuanceTranscript,
  zkHolderAllocationEvidenceFromReceipt,
  zkHolderCredentialFieldElements,
  zkHolderStatusSnapshotEvidenceFromReceipt,
  type ZkHolderCredentialCommitment,
} from "./zk-holder-credential";
import {
  serializeZkSelfIssuanceAuthorization,
  zkSelfIssuanceTypedData,
  type ZkSelfIssuanceArtifact,
  type ZkSelfIssuanceAuthorization,
} from "./zk-self-issuance";

const fixture = JSON.parse(
  readFileSync(
    new URL("../../../tools/v2-crypto-bench/fixtures/holder-credential-commitment.json", import.meta.url),
    "utf8",
  ),
) as { commitment: unknown; fieldElements: string[] };
const commitment = parseZkHolderCredentialCommitment(fixture.commitment);

const privateCredential = {
  issuerKeyId: commitment.issuerKeyId,
  statusId: "0x0000000000000000000000000000000000000000000000000000000000000007" as Hex,
  holderSecret: 123_456_789n,
  credentialBlinding: 987_654_321n,
  dateOfBirth: "2000-01-01",
  nationality: "XAA",
  issuingState: "XAB",
  expiryDate: "2030-01-01",
  documentClass: "epassport" as const,
  assurance: "chip-auth" as const,
  issuedAtEpoch: 230,
};
assert.deepEqual(
  zkHolderCredentialFieldElements(privateCredential).map(String),
  fixture.fieldElements,
  "TypeScript and the circuit reference pin the exact 16-field commitment preimage",
);
assert.throws(
  () =>
    zkHolderCredentialFieldElements({
      ...privateCredential,
      statusId: "0x0000000000000000000000000000000000000000000000010000000000000007",
    }),
  /uint32 packed-status slot/u,
);

const authority = privateKeyToAccount(
  "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d",
);
const chainId = 84_532;
const bridge = "0x1111111111111111111111111111111111111111" as const;
const registry = "0x2222222222222222222222222222222222222222" as const;
const authorization: ZkSelfIssuanceAuthorization = {
  subject: "0x3333333333333333333333333333333333333333",
  duplicateKey: `0x${"44".repeat(32)}`,
  credentialCommitment: BigInt(commitment.commitment),
  issuerKeyId: commitment.issuerKeyId,
  expectedStatusId: commitment.statusId,
  expectedEpoch: commitment.issuedAtEpoch,
  deadline: 1_800_000_600n,
  selfConfigId: `0x${"55".repeat(32)}`,
};
const signature = await authority.signTypedData(
  zkSelfIssuanceTypedData({ chainId, bridge, authorization }),
);
const artifact: ZkSelfIssuanceArtifact = {
  chainId,
  bridge,
  registry,
  authorization: serializeZkSelfIssuanceAuthorization(authorization),
  signature,
};
const allocationReceipt = {
  transactionHash: `0x${"66".repeat(32)}` as Hex,
  blockNumber: 12_345n,
  blockHash: `0x${"77".repeat(32)}` as Hex,
  from: authorization.subject,
  to: bridge,
  status: "success" as const,
  logs: [
    {
      address: registry,
      topics: [
        keccak256(stringToBytes("CredentialAllocated(bytes32,uint32,uint256,uint32)")),
        commitment.issuerKeyId,
        toHex(commitment.statusId, { size: 32 }),
        toHex(BigInt(commitment.commitment), { size: 32 }),
      ],
      data: encodeAbiParameters([{ type: "uint32" }], [commitment.issuedAtEpoch]),
      logIndex: 4,
    },
  ],
};
const allocation = zkHolderAllocationEvidenceFromReceipt({ artifact, receipt: allocationReceipt });
const statusRoot = "0x0a113b98ce937446f2736264862473af1f0222ef413291a6869847d432bb0d05" as Hex;
const snapshotReceipt = {
  transactionHash: `0x${"88".repeat(32)}` as Hex,
  blockNumber: 12_350n,
  blockHash: `0x${"99".repeat(32)}` as Hex,
  from: "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" as const,
  to: registry,
  status: "success" as const,
  logs: [
    {
      address: registry,
      topics: [
        keccak256(
          stringToBytes("StatusSnapshotPublished(bytes32,uint32,bytes32,uint32,uint64,address)"),
        ),
        commitment.issuerKeyId,
        toHex(3, { size: 32 }),
        statusRoot,
      ],
      data: encodeAbiParameters(
        [{ type: "uint32" }, { type: "uint64" }, { type: "address" }],
        [commitment.statusId, 1_800_000_100n, "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      ),
      logIndex: 2,
    },
  ],
};
const statusSnapshot = zkHolderStatusSnapshotEvidenceFromReceipt({
  issuerKeyId: commitment.issuerKeyId,
  statusId: commitment.statusId,
  issuanceRegistry: registry,
  receipt: snapshotReceipt,
});

const transcript = await buildZkHolderIssuanceTranscript({
  commitment,
  artifact,
  verificationAuthority: authority.address,
  allocation,
  statusSnapshot,
});
assert.equal(transcript.state, "snapshot-covered");
assert.equal(transcript.commitment.commitment, commitment.commitment);
assert.equal(transcript.authorization.verificationAuthority, authority.address);
assert.equal(transcript.statusSnapshot?.root, statusSnapshot.root);
assert.equal(
  transcript.transcriptHash,
  "0x1306ecc277b40d2f14ae5906d511825c4b1147876f920c720f25c2300ca9b491",
  "the synthetic live issuance transcript is pinned",
);
assert.deepEqual(
  parseZkHolderIssuanceTranscript(JSON.parse(JSON.stringify(transcript))),
  transcript,
  "the sanitized transcript round-trips through the strict parser",
);
const serialized = JSON.stringify(transcript);
for (const forbidden of [
  "dateOfBirth",
  "nationality",
  "holderSecret",
  "credentialBlinding",
  "duplicateKey",
  "signature",
  "2000-01-01",
  "XAA",
  "XAB",
  "123456789",
  "987654321",
  authorization.duplicateKey.slice(2),
  signature.slice(2),
]) {
  assert(!serialized.includes(forbidden), `transcript must omit ${forbidden}`);
}

const refreshedAuthorization = {
  ...authorization,
  expectedStatusId: commitment.statusId + 1,
};
const refreshedSignature = await authority.signTypedData(
  zkSelfIssuanceTypedData({ chainId, bridge, authorization: refreshedAuthorization }),
);
await assert.rejects(
  buildZkHolderIssuanceTranscript({
    commitment,
    artifact: {
      ...artifact,
      authorization: serializeZkSelfIssuanceAuthorization(refreshedAuthorization),
      signature: refreshedSignature,
    },
    verificationAuthority: authority.address,
    allocation,
  }),
  /does not match the circuit-native commitment/u,
  "a refreshed slot cannot silently reuse a slot-bound commitment",
);
await assert.rejects(
  buildZkHolderIssuanceTranscript({
    commitment,
    artifact,
    verificationAuthority: authority.address,
    allocation: { ...allocation, credentialCommitment: allocation.credentialCommitment + 1n },
  }),
  /allocation evidence does not match/u,
);
await assert.rejects(
  buildZkHolderIssuanceTranscript({
    commitment,
    artifact,
    verificationAuthority: authority.address,
    allocation,
    statusSnapshot: { ...statusSnapshot, activatedThroughStatusId: commitment.statusId - 1 },
  }),
  /does not cover/u,
);
await assert.rejects(
  buildZkHolderIssuanceTranscript({
    commitment,
    artifact,
    verificationAuthority: "0x9999999999999999999999999999999999999999",
    allocation,
  }),
  /signer does not match/u,
);
assert.throws(
  () =>
    zkHolderAllocationEvidenceFromReceipt({
      artifact,
      receipt: { ...allocationReceipt, status: "reverted" },
    }),
  /not a successful/u,
);
assert.throws(
  () =>
    zkHolderStatusSnapshotEvidenceFromReceipt({
      issuerKeyId: commitment.issuerKeyId,
      statusId: commitment.statusId,
      issuanceRegistry: registry,
      receipt: { ...snapshotReceipt, from: authorization.subject },
    }),
  /publisher does not match/u,
);

const tampered = JSON.parse(JSON.stringify(transcript)) as Record<string, unknown>;
(tampered.allocation as Record<string, unknown>).blockNumber = "12346";
assert.throws(() => parseZkHolderIssuanceTranscript(tampered), /hash mismatch/u);
const tamperedLogIndex = JSON.parse(JSON.stringify(transcript)) as Record<string, unknown>;
(tamperedLogIndex.allocation as Record<string, unknown>).logIndex = 5;
assert.throws(() => parseZkHolderIssuanceTranscript(tamperedLogIndex), /hash mismatch/u);
assert.throws(
  () =>
    zkHolderAllocationEvidenceFromReceipt({
      artifact,
      receipt: {
        ...allocationReceipt,
        logs: [
          {
            ...allocationReceipt.logs[0]!,
            topics: [
              allocationReceipt.logs[0]!.topics[0]!,
              allocationReceipt.logs[0]!.topics[1]!,
              `${allocationReceipt.logs[0]!.topics[2]}00` as Hex,
              allocationReceipt.logs[0]!.topics[3]!,
            ],
          },
        ],
      },
    }),
  /must be bytes32/u,
);
assert.throws(
  () => parseZkHolderCredentialCommitment({ ...commitment, extra: "field" }),
  /unknown fields/u,
);

console.log("zk holder credential: circuit commitment + live issuance transcript PASS");
