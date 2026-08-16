import assert from "node:assert/strict";
import { keccak256, stringToBytes, toFunctionSelector } from "viem";
import { BN254_SCALAR_FIELD } from "./zk-identity-encoding";
import {
  encodeZkIdentityStatusSnapshotPublication,
  normalizeZkIdentityStatusSnapshotPublication,
  ZK_IDENTITY_MAX_NEXT_STATUS_ID,
} from "./zk-identity-packed-status";

const publication = {
  issuerKeyId: keccak256(stringToBytes("issuer-key:self:testnet:v1")),
  expectedNextStatusId: 43n,
  root: `0x${123_456_789n.toString(16).padStart(64, "0")}` as const,
};

assert.deepEqual(normalizeZkIdentityStatusSnapshotPublication(publication), publication);
assert.equal(
  encodeZkIdentityStatusSnapshotPublication(publication).slice(0, 10),
  toFunctionSelector("publishStatusSnapshot(bytes32,uint64,bytes32)"),
  "the SDK emits calldata for the exact allocation-bound publication transition",
);
assert.equal(ZK_IDENTITY_MAX_NEXT_STATUS_ID, 4_294_967_296n);

assert.throws(
  () => normalizeZkIdentityStatusSnapshotPublication({ ...publication, expectedNextStatusId: 1n }),
  /at least one allocated/u,
);
assert.throws(
  () =>
    normalizeZkIdentityStatusSnapshotPublication({
      ...publication,
      expectedNextStatusId: ZK_IDENTITY_MAX_NEXT_STATUS_ID + 1n,
    }),
  /allocated uint32 slot/u,
);
assert.throws(
  () =>
    normalizeZkIdentityStatusSnapshotPublication({
      ...publication,
      root: `0x${BN254_SCALAR_FIELD.toString(16).padStart(64, "0")}`,
    }),
  /canonical BN254/u,
);
assert.throws(
  () =>
    normalizeZkIdentityStatusSnapshotPublication({
      ...publication,
      issuerKeyId: `0x${"00".repeat(32)}`,
    }),
  /issuer key id must not be zero/u,
);
