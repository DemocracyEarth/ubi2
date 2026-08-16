/**
 * Canonical-chain packed-status checkpoint helpers.
 *
 * A status publisher builds the Poseidon tree off chain, reconciles it through
 * the issuance registry's current allocation counter, then submits the root.
 * This module deliberately does not construct roots: that requires the frozen
 * production circuit parameters and an independently reviewable event indexer.
 */
import { encodeFunctionData, isHex, size, type Hex } from "viem";
import { BN254_SCALAR_FIELD } from "./zk-identity-encoding";

export const ZK_IDENTITY_MAX_STATUS_ID = 0xffff_ffffn;
export const ZK_IDENTITY_MAX_NEXT_STATUS_ID = ZK_IDENTITY_MAX_STATUS_ID + 1n;

export interface ZkIdentityStatusSnapshotPublication {
  issuerKeyId: Hex;
  /** Exact `nextStatusId` observed after processing every allocation event. */
  expectedNextStatusId: bigint;
  /** Nonzero canonical BN254 Poseidon root. */
  root: Hex;
}

export const zkIdentityIssuanceStatusAbi = [
  {
    type: "error",
    name: "UnexpectedNextStatusId",
    inputs: [
      { name: "expected", type: "uint64" },
      { name: "provided", type: "uint64" },
    ],
  },
  {
    type: "error",
    name: "StatusPublisherInactive",
    inputs: [
      { name: "issuerKeyId", type: "bytes32" },
      { name: "publisher", type: "address" },
    ],
  },
  {
    type: "function",
    name: "publishStatusSnapshot",
    stateMutability: "nonpayable",
    inputs: [
      { name: "issuerKeyId", type: "bytes32" },
      { name: "expectedNextStatusId", type: "uint64" },
      { name: "root", type: "bytes32" },
    ],
    outputs: [{ name: "snapshotId", type: "uint32" }],
  },
  {
    type: "function",
    name: "statusSnapshots",
    stateMutability: "view",
    inputs: [
      { name: "issuerKeyId", type: "bytes32" },
      { name: "snapshotId", type: "uint32" },
    ],
    outputs: [
      { name: "root", type: "bytes32" },
      { name: "activatedThroughStatusId", type: "uint32" },
      { name: "publishedAt", type: "uint64" },
      { name: "revoked", type: "bool" },
    ],
  },
  {
    type: "function",
    name: "isStatusSnapshotAccepted",
    stateMutability: "view",
    inputs: [
      { name: "issuerKeyId", type: "bytes32" },
      { name: "snapshotId", type: "uint32" },
      { name: "root", type: "bytes32" },
    ],
    outputs: [{ name: "accepted", type: "bool" }],
  },
] as const;

function nonZeroBytes32(value: Hex, label: string): Hex {
  if (!isHex(value) || size(value) !== 32) throw new Error(`${label} must be bytes32`);
  const normalized = value.toLowerCase() as Hex;
  if (BigInt(normalized) === 0n) throw new Error(`${label} must not be zero`);
  return normalized;
}

export function normalizeZkIdentityStatusSnapshotPublication(
  input: ZkIdentityStatusSnapshotPublication,
): ZkIdentityStatusSnapshotPublication {
  const issuerKeyId = nonZeroBytes32(input.issuerKeyId, "issuer key id");
  const root = nonZeroBytes32(input.root, "packed status root");
  if (BigInt(root) >= BN254_SCALAR_FIELD) {
    throw new Error("packed status root must be a canonical BN254 field element");
  }
  if (
    typeof input.expectedNextStatusId !== "bigint" ||
    input.expectedNextStatusId < 2n ||
    input.expectedNextStatusId > ZK_IDENTITY_MAX_NEXT_STATUS_ID
  ) {
    throw new Error("expected next status id must identify at least one allocated uint32 slot");
  }
  return { issuerKeyId, expectedNextStatusId: input.expectedNextStatusId, root };
}

/** Encode the publisher transaction after an exact event-stream reconciliation. */
export function encodeZkIdentityStatusSnapshotPublication(
  input: ZkIdentityStatusSnapshotPublication,
): Hex {
  const publication = normalizeZkIdentityStatusSnapshotPublication(input);
  return encodeFunctionData({
    abi: zkIdentityIssuanceStatusAbi,
    functionName: "publishStatusSnapshot",
    args: [publication.issuerKeyId, publication.expectedNextStatusId, publication.root],
  });
}
