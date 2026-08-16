/**
 * Strict public artifacts and authenticated reconciliation for packed status.
 *
 * Snapshot JSON contains no holder or passport data. Its content hash commits
 * to the exact deterministic builder output; EIP-712 attestations bind that
 * content to the canonical issuance chain and registry. Applications must
 * configure reconciler addresses independently of downloaded artifacts.
 */
import {
  getAddress,
  hashTypedData,
  isAddress,
  isHex,
  keccak256,
  recoverTypedDataAddress,
  size,
  stringToBytes,
  type Address,
  type Hex,
} from "viem";
import { BN254_SCALAR_FIELD } from "./zk-identity-encoding";
import {
  normalizeZkIdentityStatusSnapshotPublication,
  ZK_IDENTITY_MAX_NEXT_STATUS_ID,
  type ZkIdentityStatusSnapshotPublication,
} from "./zk-identity-packed-status";

export { ZK_IDENTITY_MAX_NEXT_STATUS_ID } from "./zk-identity-packed-status";

export const ZK_IDENTITY_STATUS_SOURCE_SCHEMA =
  "org.proofofhumanity.v2-packed-status-source/1" as const;
export const ZK_IDENTITY_STATUS_SNAPSHOT_SCHEMA =
  "org.proofofhumanity.v2-packed-status-snapshot/1" as const;
export const ZK_IDENTITY_STATUS_ATTESTATION_SCHEMA =
  "org.proofofhumanity.v2-packed-status-attestation" as const;
export const ZK_IDENTITY_STATUS_ATTESTATION_VERSION = 1 as const;
export const ZK_IDENTITY_STATUS_ATTESTATION_DOMAIN_NAME =
  "ProofOfHumanityPackedStatusSnapshot" as const;
export const ZK_IDENTITY_STATUS_ATTESTATION_DOMAIN_VERSION = "1" as const;
export const ZK_IDENTITY_STATUS_ATTESTATION_PRIMARY_TYPE =
  "PackedStatusSnapshotAttestation" as const;

const FAIL_CLOSED_CHUNK = `0x${"ff".repeat(32)}` as Hex;
const MAX_CHUNK_INDEX = 0xff_ffff;

export interface ZkIdentityStatusSourceAllocationEvent {
  kind: "credential-allocated";
  logIndex: number;
  issuerKeyId: Hex;
  statusId: number;
}

export interface ZkIdentityStatusSourceRevocationEvent {
  kind: "credential-revoked";
  logIndex: number;
  issuerKeyId: Hex;
  statusId: number;
  authorizationReference: Hex;
}

export interface ZkIdentityStatusSourceTranscript {
  schema: typeof ZK_IDENTITY_STATUS_SOURCE_SCHEMA;
  chainId: string;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  anchor: ZkIdentityStatusSourceBlockRef;
  blocks: Array<
    ZkIdentityStatusSourceBlockRef & {
      events: Array<
        ZkIdentityStatusSourceAllocationEvent | ZkIdentityStatusSourceRevocationEvent
      >;
    }
  >;
}

export interface ZkIdentityStatusSourceBlockRef {
  number: string;
  hash: Hex;
  parentHash: Hex;
}

export interface ZkIdentityPackedStatusSnapshotChunk {
  index: number;
  value: Hex;
}

export interface ZkIdentityPackedStatusSnapshot {
  schema: typeof ZK_IDENTITY_STATUS_SNAPSHOT_SCHEMA;
  chainId: string;
  issuanceRegistry: Address;
  issuerKeyId: Hex;
  sourceBlockNumber: string;
  sourceBlockHash: Hex;
  sourceBlockParentHash: Hex;
  nextStatusId: number;
  activatedThroughStatusId: number;
  root: Hex;
  chunks: ZkIdentityPackedStatusSnapshotChunk[];
}

export interface ZkIdentityPackedStatusAttestation {
  schema: typeof ZK_IDENTITY_STATUS_ATTESTATION_SCHEMA;
  version: typeof ZK_IDENTITY_STATUS_ATTESTATION_VERSION;
  snapshot: ZkIdentityPackedStatusSnapshot;
  snapshotHash: Hex;
  signature: Hex;
}

export interface ReconciledZkIdentityPackedStatusSnapshot {
  snapshot: ZkIdentityPackedStatusSnapshot;
  snapshotHash: Hex;
  signers: Address[];
}

export const zkIdentityPackedStatusAttestationTypes = {
  PackedStatusSnapshotAttestation: [
    { name: "snapshotHash", type: "bytes32" },
    { name: "issuerKeyId", type: "bytes32" },
    { name: "sourceBlockNumber", type: "uint64" },
    { name: "sourceBlockHash", type: "bytes32" },
    { name: "expectedNextStatusId", type: "uint64" },
    { name: "root", type: "bytes32" },
  ],
} as const;

const snapshotKeys = [
  "schema",
  "chainId",
  "issuanceRegistry",
  "issuerKeyId",
  "sourceBlockNumber",
  "sourceBlockHash",
  "sourceBlockParentHash",
  "nextStatusId",
  "activatedThroughStatusId",
  "root",
  "chunks",
] as const;
const chunkKeys = ["index", "value"] as const;
const attestationKeys = ["schema", "version", "snapshot", "snapshotHash", "signature"] as const;

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  label: string,
): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    actual.length !== sortedExpected.length ||
    actual.some((key, index) => key !== sortedExpected[index])
  ) {
    throw new Error(`${label} contains missing or unknown fields`);
  }
}

function object(value: unknown, label: string): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value as Record<string, unknown>;
}

function canonicalDecimal(value: unknown, label: string): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical unsigned decimal string`);
  }
  const parsed = BigInt(value);
  if (parsed > 0xffff_ffff_ffff_ffffn) throw new Error(`${label} exceeds uint64`);
  return value;
}

function canonicalAddress(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${label} must be a non-zero EVM address`);
  }
  return getAddress(value).toLowerCase() as Address;
}

function canonicalSignerAddress(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${label} must be a non-zero EVM address`);
  }
  return getAddress(value);
}

function canonicalBytes32(value: unknown, label: string, nonZero = false): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32) {
    throw new Error(`${label} must be bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (nonZero && BigInt(normalized) === 0n) throw new Error(`${label} must not be zero`);
  return normalized;
}

function positiveSafeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

/** Strict structural parser for untrusted deterministic-builder output. */
export function parseZkIdentityPackedStatusSnapshot(
  value: unknown,
): ZkIdentityPackedStatusSnapshot {
  const candidate = object(value, "packed-status snapshot");
  exactKeys(candidate, snapshotKeys, "packed-status snapshot");
  if (candidate.schema !== ZK_IDENTITY_STATUS_SNAPSHOT_SCHEMA) {
    throw new Error("unsupported packed-status snapshot schema");
  }
  const chainId = canonicalDecimal(candidate.chainId, "packed-status chain id");
  if (BigInt(chainId) === 0n) throw new Error("packed-status chain id must not be zero");
  const issuanceRegistry = canonicalAddress(
    candidate.issuanceRegistry,
    "packed-status issuance registry",
  );
  const issuerKeyId = canonicalBytes32(candidate.issuerKeyId, "packed-status issuer key id", true);
  const sourceBlockNumber = canonicalDecimal(
    candidate.sourceBlockNumber,
    "packed-status source block number",
  );
  const sourceBlockHash = canonicalBytes32(
    candidate.sourceBlockHash,
    "packed-status source block hash",
    true,
  );
  const sourceBlockParentHash = canonicalBytes32(
    candidate.sourceBlockParentHash,
    "packed-status source parent hash",
  );
  const nextStatusId = positiveSafeInteger(candidate.nextStatusId, "packed-status next status id");
  if (BigInt(nextStatusId) > ZK_IDENTITY_MAX_NEXT_STATUS_ID) {
    throw new Error("packed-status next status id exceeds the uint32 allocation range");
  }
  if (
    typeof candidate.activatedThroughStatusId !== "number" ||
    !Number.isSafeInteger(candidate.activatedThroughStatusId) ||
    candidate.activatedThroughStatusId !== nextStatusId - 1
  ) {
    throw new Error("packed-status activated watermark does not match next status id");
  }
  const root = canonicalBytes32(candidate.root, "packed-status root", true);
  if (BigInt(root) >= BN254_SCALAR_FIELD) {
    throw new Error("packed-status root must be a canonical BN254 field element");
  }
  if (!Array.isArray(candidate.chunks)) throw new Error("packed-status chunks must be an array");
  const lastAllocated = BigInt(nextStatusId - 1);
  const lastChunk = Number(lastAllocated >> 8n);
  const lastBit = Number(lastAllocated & 0xffn);
  let previousIndex = -1;
  const chunks = candidate.chunks.map((untrusted) => {
    const chunk = object(untrusted, "packed-status chunk");
    exactKeys(chunk, chunkKeys, "packed-status chunk");
    if (
      typeof chunk.index !== "number" ||
      !Number.isSafeInteger(chunk.index) ||
      chunk.index < 0 ||
      chunk.index > MAX_CHUNK_INDEX ||
      chunk.index <= previousIndex ||
      chunk.index > lastChunk
    ) {
      throw new Error("packed-status chunk indices must be sorted and allocation-bounded");
    }
    const normalized = {
      index: chunk.index,
      value: canonicalBytes32(chunk.value, "packed-status chunk value"),
    };
    if (normalized.value === FAIL_CLOSED_CHUNK) {
      throw new Error("packed-status default chunks must be omitted");
    }
    const bits = BigInt(normalized.value);
    if (normalized.index === 0 && (bits & 1n) === 0n) {
      throw new Error("packed-status slot zero must remain fail closed");
    }
    if (normalized.index === lastChunk) {
      const allocatedMask = (1n << BigInt(lastBit + 1)) - 1n;
      const requiredFailClosed = BigInt(FAIL_CLOSED_CHUNK) ^ allocatedMask;
      if ((bits & requiredFailClosed) !== requiredFailClosed) {
        throw new Error("packed-status unallocated tail must remain fail closed");
      }
    }
    previousIndex = normalized.index;
    return normalized;
  });
  if (nextStatusId === 1 && chunks.length !== 0) {
    throw new Error("packed-status empty allocation state must omit every chunk");
  }
  return {
    schema: ZK_IDENTITY_STATUS_SNAPSHOT_SCHEMA,
    chainId,
    issuanceRegistry,
    issuerKeyId,
    sourceBlockNumber,
    sourceBlockHash,
    sourceBlockParentHash,
    nextStatusId,
    activatedThroughStatusId: nextStatusId - 1,
    root,
    chunks,
  };
}

/** Canonical compact JSON; identical builder output has one content hash. */
export function serializeZkIdentityPackedStatusSnapshot(value: unknown): string {
  return JSON.stringify(parseZkIdentityPackedStatusSnapshot(value));
}

export function zkIdentityPackedStatusSnapshotHash(value: unknown): Hex {
  return keccak256(stringToBytes(serializeZkIdentityPackedStatusSnapshot(value)));
}

function snapshotTypedData(snapshot: ZkIdentityPackedStatusSnapshot, snapshotHash: Hex) {
  const chainId = BigInt(snapshot.chainId);
  if (chainId > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("packed-status EIP-712 chain id exceeds the SDK safe range");
  }
  return {
    domain: {
      name: ZK_IDENTITY_STATUS_ATTESTATION_DOMAIN_NAME,
      version: ZK_IDENTITY_STATUS_ATTESTATION_DOMAIN_VERSION,
      chainId: Number(chainId),
      verifyingContract: snapshot.issuanceRegistry,
    },
    types: zkIdentityPackedStatusAttestationTypes,
    primaryType: ZK_IDENTITY_STATUS_ATTESTATION_PRIMARY_TYPE,
    message: {
      snapshotHash,
      issuerKeyId: snapshot.issuerKeyId,
      sourceBlockNumber: BigInt(snapshot.sourceBlockNumber),
      sourceBlockHash: snapshot.sourceBlockHash,
      expectedNextStatusId: BigInt(snapshot.nextStatusId),
      root: snapshot.root,
    },
  } as const;
}

export function zkIdentityPackedStatusAttestationTypedData(snapshotValue: unknown) {
  const snapshot = parseZkIdentityPackedStatusSnapshot(snapshotValue);
  return snapshotTypedData(snapshot, zkIdentityPackedStatusSnapshotHash(snapshot));
}

export function zkIdentityPackedStatusAttestationDigest(snapshotValue: unknown): Hex {
  return hashTypedData(zkIdentityPackedStatusAttestationTypedData(snapshotValue));
}

export function createZkIdentityPackedStatusAttestation(
  snapshotValue: unknown,
  signature: Hex,
): ZkIdentityPackedStatusAttestation {
  const snapshot = parseZkIdentityPackedStatusSnapshot(snapshotValue);
  if (!isHex(signature) || size(signature) !== 65) {
    throw new Error("packed-status attestation signature must be 65 bytes");
  }
  return {
    schema: ZK_IDENTITY_STATUS_ATTESTATION_SCHEMA,
    version: ZK_IDENTITY_STATUS_ATTESTATION_VERSION,
    snapshot,
    snapshotHash: zkIdentityPackedStatusSnapshotHash(snapshot),
    signature: signature.toLowerCase() as Hex,
  };
}

export function parseZkIdentityPackedStatusAttestation(
  value: unknown,
): ZkIdentityPackedStatusAttestation {
  const candidate = object(value, "packed-status attestation");
  exactKeys(candidate, attestationKeys, "packed-status attestation");
  if (
    candidate.schema !== ZK_IDENTITY_STATUS_ATTESTATION_SCHEMA ||
    candidate.version !== ZK_IDENTITY_STATUS_ATTESTATION_VERSION
  ) {
    throw new Error("unsupported packed-status attestation schema or version");
  }
  const snapshot = parseZkIdentityPackedStatusSnapshot(candidate.snapshot);
  const snapshotHash = canonicalBytes32(
    candidate.snapshotHash,
    "packed-status attestation snapshot hash",
    true,
  );
  if (snapshotHash !== zkIdentityPackedStatusSnapshotHash(snapshot)) {
    throw new Error("packed-status attestation hash does not match its snapshot content");
  }
  if (typeof candidate.signature !== "string" || !isHex(candidate.signature) || size(candidate.signature) !== 65) {
    throw new Error("packed-status attestation signature must be 65 bytes");
  }
  return {
    schema: ZK_IDENTITY_STATUS_ATTESTATION_SCHEMA,
    version: ZK_IDENTITY_STATUS_ATTESTATION_VERSION,
    snapshot,
    snapshotHash,
    signature: candidate.signature.toLowerCase() as Hex,
  };
}

export function serializeZkIdentityPackedStatusAttestation(value: unknown): string {
  return JSON.stringify(parseZkIdentityPackedStatusAttestation(value));
}

export function recoverZkIdentityPackedStatusAttestationSigner(
  value: unknown,
): Promise<Address> {
  const attestation = parseZkIdentityPackedStatusAttestation(value);
  return recoverTypedDataAddress({
    ...snapshotTypedData(attestation.snapshot, attestation.snapshotHash),
    signature: attestation.signature,
  });
}

/**
 * Require threshold distinct, application-configured reconcilers to attest to
 * one byte-identical snapshot. Any split view or invalid signature rejects the
 * complete reconciliation set.
 */
export async function reconcileZkIdentityPackedStatusSnapshots(input: {
  attestations: readonly unknown[];
  expectedReconcilers: readonly Address[];
  threshold?: number;
}): Promise<ReconciledZkIdentityPackedStatusSnapshot> {
  const expected = new Set(
    input.expectedReconcilers.map((address) =>
      canonicalSignerAddress(address, "packed-status expected reconciler"),
    ),
  );
  if (expected.size !== input.expectedReconcilers.length) {
    throw new Error("packed-status expected reconcilers must be distinct");
  }
  const threshold = input.threshold ?? 2;
  if (!Number.isSafeInteger(threshold) || threshold < 2 || threshold > expected.size) {
    throw new Error("packed-status reconciliation threshold requires at least two configured keys");
  }
  if (input.attestations.length < threshold) {
    throw new Error("packed-status reconciliation does not meet its signature threshold");
  }

  let accepted: ZkIdentityPackedStatusAttestation | undefined;
  const signers = new Set<Address>();
  for (const untrusted of input.attestations) {
    const attestation = parseZkIdentityPackedStatusAttestation(untrusted);
    if (accepted !== undefined && attestation.snapshotHash !== accepted.snapshotHash) {
      throw new Error("packed-status reconcilers reported split snapshot content");
    }
    const signer = canonicalSignerAddress(
      await recoverZkIdentityPackedStatusAttestationSigner(attestation),
      "packed-status recovered reconciler",
    );
    if (!expected.has(signer)) {
      throw new Error("packed-status attestation signer is not an expected reconciler");
    }
    if (signers.has(signer)) {
      throw new Error("packed-status reconciliation contains a duplicate signer");
    }
    signers.add(signer);
    accepted ??= attestation;
  }
  if (accepted === undefined || signers.size < threshold) {
    throw new Error("packed-status reconciliation does not meet its signature threshold");
  }
  return {
    snapshot: accepted.snapshot,
    snapshotHash: accepted.snapshotHash,
    signers: [...signers].sort(),
  };
}

export function reconciledZkIdentityStatusPublication(
  reconciled: ReconciledZkIdentityPackedStatusSnapshot,
): ZkIdentityStatusSnapshotPublication {
  return normalizeZkIdentityStatusSnapshotPublication({
    issuerKeyId: reconciled.snapshot.issuerKeyId,
    expectedNextStatusId: BigInt(reconciled.snapshot.nextStatusId),
    root: reconciled.snapshot.root,
  });
}
