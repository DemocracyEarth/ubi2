/**
 * Circuit-native v2 holder-credential preimage and sanitized issuance evidence.
 *
 * Private claims and secrets handled by this module are ephemeral prover input.
 * Persist only inside the encrypted credential vault. The finalized transcript
 * deliberately omits passport claims, holder secrets, the raw Self nullifier,
 * the registry-scoped duplicate key, and the bridge signature.
 */
import {
  encodeAbiParameters,
  getAddress,
  isAddress,
  isHex,
  keccak256,
  size,
  stringToBytes,
  stringToHex,
  type Address,
  type Hex,
} from "viem";
import {
  BN254_SCALAR_FIELD,
  encodeZkPrivateCredential,
  splitBytes32,
  zkIssuanceDomainHash,
  ZK_PRIVATE_CREDENTIAL_SCHEMA,
  ZK_PRIVATE_CREDENTIAL_VERSION,
  type ZkPrivateCredentialInput,
} from "./zk-identity-encoding";
import {
  deserializeZkSelfIssuanceAuthorization,
  recoverZkSelfIssuanceAuthority,
  zkSelfIssuanceAuthorizationDigest,
  type ZkSelfIssuanceArtifact,
} from "./zk-self-issuance";

export const ZK_HOLDER_CREDENTIAL_INPUT_SCHEMA =
  "org.proofofhumanity.zk-holder-credential-input/1" as const;
export const ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEMA =
  "org.proofofhumanity.zk-holder-credential-commitment/1" as const;
export const ZK_HOLDER_CREDENTIAL_PRIVATE_SCHEMA =
  "org.proofofhumanity.zk-private-credential/1" as const;
export const ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEME =
  "poseidon-bn254-arkworks-0.5-x5-rate2/1" as const;
export const ZK_HOLDER_ISSUANCE_TRANSCRIPT_SCHEMA =
  "org.proofofhumanity.zk-holder-issuance-transcript/1" as const;
export const ZK_HOLDER_ISSUANCE_TRANSCRIPT_VERSION = 1 as const;

const transcriptDomain = keccak256(stringToBytes("org.proofofhumanity.zk-holder-issuance-transcript"));
const credentialAllocatedTopic = keccak256(
  stringToBytes("CredentialAllocated(bytes32,uint32,uint256,uint32)"),
);
const statusSnapshotPublishedTopic = keccak256(
  stringToBytes("StatusSnapshotPublished(bytes32,uint32,bytes32,uint32,uint64,address)"),
);
const UINT32_MAX = 0xffff_ffff;
const UINT64_MAX = (1n << 64n) - 1n;

export interface ZkHolderCredentialCommitment {
  schema: typeof ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEMA;
  credentialSchema: typeof ZK_HOLDER_CREDENTIAL_PRIVATE_SCHEMA;
  commitmentScheme: typeof ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEME;
  issuerKeyId: Hex;
  statusId: number;
  issuedAtEpoch: number;
  commitment: Hex;
}

export interface ZkHolderAllocationEvidenceInput {
  transactionHash: Hex;
  blockNumber: bigint;
  blockHash: Hex;
  logIndex: number;
  issuerKeyId: Hex;
  statusId: number;
  credentialCommitment: bigint;
  issuedAtEpoch: number;
}

export interface ZkHolderStatusSnapshotEvidenceInput {
  transactionHash: Hex;
  blockNumber: bigint;
  blockHash: Hex;
  logIndex: number;
  snapshotId: number;
  root: Hex;
  activatedThroughStatusId: number;
  publishedAt: bigint;
}

export interface ZkHolderIssuanceReceiptInput {
  transactionHash: Hex;
  blockNumber: bigint;
  blockHash: Hex;
  from: Address;
  to: Address | null;
  status: "success" | "reverted";
  logs: readonly {
    address: Address;
    topics: readonly Hex[];
    data: Hex;
    logIndex: number;
  }[];
}

export interface ZkHolderIssuanceTranscript {
  schema: typeof ZK_HOLDER_ISSUANCE_TRANSCRIPT_SCHEMA;
  version: typeof ZK_HOLDER_ISSUANCE_TRANSCRIPT_VERSION;
  state: "allocated" | "snapshot-covered";
  commitment: ZkHolderCredentialCommitment;
  authorization: {
    chainId: string;
    issuanceRegistry: Address;
    issuanceBridge: Address;
    issuanceDomain: Hex;
    subject: Address;
    verificationAuthority: Address;
    selfConfigId: Hex;
    authorizationDigest: Hex;
  };
  allocation: {
    transactionHash: Hex;
    blockNumber: string;
    blockHash: Hex;
    logIndex: number;
    statusId: number;
    issuedAtEpoch: number;
  };
  statusSnapshot: null | {
    transactionHash: Hex;
    blockNumber: string;
    blockHash: Hex;
    logIndex: number;
    snapshotId: number;
    root: Hex;
    activatedThroughStatusId: number;
    publishedAt: string;
  };
  /** Device-private integrity fingerprint. Never use as a presentation identifier. */
  transcriptHash: Hex;
}

/**
 * The exact 16 field elements absorbed by the v1 holder commitment.
 *
 * The Poseidon sponge prepends its separate field domain `1`; this function
 * returns only the ordered private-credential payload. Calling it must not be
 * followed by logging or plaintext persistence.
 */
export function zkHolderCredentialFieldElements(
  input: ZkPrivateCredentialInput,
): readonly bigint[] {
  // Reuse the canonical ABI validator before applying the narrower packed-slot rule.
  encodeZkPrivateCredential(input);
  const status = BigInt(nonZeroBytes32(input.statusId, "credential status id"));
  if (status > BigInt(UINT32_MAX)) {
    throw new Error("credential status id must encode a nonzero uint32 packed-status slot");
  }
  const [domainHigh, domainLow] = splitBytes32(
    keccak256(stringToBytes(ZK_PRIVATE_CREDENTIAL_SCHEMA)),
  );
  const [issuerHigh, issuerLow] = splitBytes32(nonZeroBytes32(input.issuerKeyId, "issuer key id"));
  const dateOfBirth = packedDate(input.dateOfBirth);
  const expiryDate = packedDate(input.expiryDate);
  const nationality = countryField(input.nationality, "nationality");
  const issuingState = countryField(input.issuingState, "issuing state");

  return [
    domainHigh,
    domainLow,
    BigInt(ZK_PRIVATE_CREDENTIAL_VERSION),
    issuerHigh,
    issuerLow,
    0n,
    status,
    input.holderSecret,
    input.credentialBlinding,
    BigInt(dateOfBirth),
    nationality,
    issuingState,
    BigInt(expiryDate),
    1n,
    input.assurance === "passive-auth" ? 1n : 2n,
    BigInt(input.issuedAtEpoch),
  ] as const;
}

export function parseZkHolderCredentialCommitment(value: unknown): ZkHolderCredentialCommitment {
  const candidate = object(value, "holder credential commitment");
  exactKeys(
    candidate,
    [
      "schema",
      "credentialSchema",
      "commitmentScheme",
      "issuerKeyId",
      "statusId",
      "issuedAtEpoch",
      "commitment",
    ],
    "holder credential commitment",
  );
  if (candidate.schema !== ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEMA) {
    throw new Error("unsupported holder credential commitment schema");
  }
  if (candidate.credentialSchema !== ZK_HOLDER_CREDENTIAL_PRIVATE_SCHEMA) {
    throw new Error("unsupported private credential schema");
  }
  if (candidate.commitmentScheme !== ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEME) {
    throw new Error("unsupported holder credential commitment scheme");
  }
  return {
    schema: ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEMA,
    credentialSchema: ZK_HOLDER_CREDENTIAL_PRIVATE_SCHEMA,
    commitmentScheme: ZK_HOLDER_CREDENTIAL_COMMITMENT_SCHEME,
    issuerKeyId: nonZeroBytes32(candidate.issuerKeyId, "issuer key id"),
    statusId: uint32(candidate.statusId, "credential status id", false),
    issuedAtEpoch: uint32(candidate.issuedAtEpoch, "credential issuance epoch", true),
    commitment: canonicalCommitment(candidate.commitment),
  };
}

/** Decode the one exact registry allocation event from a mined issuance receipt. */
export function zkHolderAllocationEvidenceFromReceipt(input: {
  artifact: ZkSelfIssuanceArtifact;
  receipt: ZkHolderIssuanceReceiptInput;
}): ZkHolderAllocationEvidenceInput {
  const registry = address(input.artifact.registry, "issuance registry");
  const bridge = address(input.artifact.bridge, "issuance bridge");
  const authorization = deserializeZkSelfIssuanceAuthorization(input.artifact.authorization);
  if (
    input.receipt.status !== "success" ||
    address(input.receipt.from, "issuance transaction sender") !== authorization.subject ||
    input.receipt.to === null ||
    address(input.receipt.to, "issuance transaction recipient") !== bridge
  ) {
    throw new Error("issuance receipt is not a successful subject-to-bridge transaction");
  }
  const matches = input.receipt.logs.filter(
    (log) =>
      getAddress(log.address) === registry &&
      log.topics.length === 4 &&
      log.topics[0]?.toLowerCase() === credentialAllocatedTopic,
  );
  if (matches.length !== 1) throw new Error("issuance receipt must contain exactly one credential allocation");
  const log = matches[0]!;
  if (!isHex(log.data) || size(log.data) !== 32) {
    throw new Error("credential allocation event data must contain exactly one word");
  }
  const issuerKeyId = nonZeroBytes32(log.topics[1], "allocation issuer key id");
  const statusId = uint32(topicWord(log.topics[2]!, "allocation status id"), "allocation status id", false);
  const credentialCommitment = commitmentBigInt(
    topicWord(log.topics[3]!, "allocation credential commitment"),
  );
  const issuedAtEpoch = uint32(word(log.data, 0), "allocation issuance epoch", true);
  if (
    issuerKeyId !== authorization.issuerKeyId.toLowerCase() ||
    statusId !== authorization.expectedStatusId ||
    credentialCommitment !== authorization.credentialCommitment ||
    issuedAtEpoch !== authorization.expectedEpoch
  ) {
    throw new Error("credential allocation event does not match the signed authorization");
  }
  return {
    transactionHash: bytes32(input.receipt.transactionHash, "allocation transaction hash", true),
    blockNumber: uint64BigInt(input.receipt.blockNumber, "allocation block number"),
    blockHash: bytes32(input.receipt.blockHash, "allocation block hash", true),
    logIndex: uint32(log.logIndex, "allocation log index", true),
    issuerKeyId,
    statusId,
    credentialCommitment,
    issuedAtEpoch,
  };
}

/** Decode a packed-status publication receipt that covers one allocated slot. */
export function zkHolderStatusSnapshotEvidenceFromReceipt(input: {
  issuerKeyId: Hex;
  statusId: number;
  issuanceRegistry: Address;
  receipt: ZkHolderIssuanceReceiptInput;
}): ZkHolderStatusSnapshotEvidenceInput {
  const issuerKeyId = nonZeroBytes32(input.issuerKeyId, "issuer key id");
  const registry = address(input.issuanceRegistry, "issuance registry");
  const statusId = uint32(input.statusId, "credential status id", false);
  if (
    input.receipt.status !== "success" ||
    input.receipt.to === null ||
    address(input.receipt.to, "snapshot transaction recipient") !== registry
  ) {
    throw new Error("snapshot receipt is not a successful registry transaction");
  }
  const matches = input.receipt.logs.filter(
    (log) =>
      getAddress(log.address) === registry &&
      log.topics.length === 4 &&
      log.topics[0]?.toLowerCase() === statusSnapshotPublishedTopic &&
      log.topics[1]?.toLowerCase() === issuerKeyId,
  );
  if (matches.length !== 1) throw new Error("snapshot receipt must contain exactly one matching publication");
  const log = matches[0]!;
  if (!isHex(log.data) || size(log.data) !== 96) {
    throw new Error("status snapshot event data must contain exactly three words");
  }
  const snapshotId = uint32(topicWord(log.topics[2]!, "snapshot id"), "snapshot id", false);
  const root = canonicalRoot(log.topics[3]);
  const activatedThroughStatusId = uint32(
    word(log.data, 0),
    "snapshot allocation watermark",
    false,
  );
  const publishedAt = uint64BigInt(word(log.data, 1), "snapshot publication time");
  const publisher = word(log.data, 2);
  if (publisher === 0n || publisher >= 1n << 160n) {
    throw new Error("status snapshot publisher must be a nonzero EVM address");
  }
  if (BigInt(address(input.receipt.from, "snapshot publisher")) !== publisher) {
    throw new Error("status snapshot publisher does not match the transaction sender");
  }
  if (activatedThroughStatusId < statusId) {
    throw new Error("status snapshot does not cover the credential slot");
  }
  return {
    transactionHash: bytes32(input.receipt.transactionHash, "snapshot transaction hash", true),
    blockNumber: uint64BigInt(input.receipt.blockNumber, "snapshot block number"),
    blockHash: bytes32(input.receipt.blockHash, "snapshot block hash", true),
    logIndex: uint32(log.logIndex, "snapshot log index", true),
    snapshotId,
    root,
    activatedThroughStatusId,
    publishedAt,
  };
}

/**
 * Verify live Self authorization plus allocation evidence and return a sanitized,
 * tamper-evident transcript suitable for encrypted holder-vault persistence.
 */
export async function buildZkHolderIssuanceTranscript(input: {
  commitment: ZkHolderCredentialCommitment;
  artifact: ZkSelfIssuanceArtifact;
  verificationAuthority: Address;
  allocation: ZkHolderAllocationEvidenceInput;
  statusSnapshot?: ZkHolderStatusSnapshotEvidenceInput;
}): Promise<ZkHolderIssuanceTranscript> {
  const commitment = parseZkHolderCredentialCommitment(input.commitment);
  const chainId = positiveSafeInteger(input.artifact.chainId, "issuance chain id");
  const issuanceRegistry = address(input.artifact.registry, "issuance registry");
  const issuanceBridge = address(input.artifact.bridge, "issuance bridge");
  const verificationAuthority = address(input.verificationAuthority, "verification authority");
  const authorization = deserializeZkSelfIssuanceAuthorization(input.artifact.authorization);
  const recovered = await recoverZkSelfIssuanceAuthority({
    chainId,
    bridge: issuanceBridge,
    authorization,
    signature: input.artifact.signature,
  });
  if (recovered !== verificationAuthority) {
    throw new Error("Self issuance authorization signer does not match the configured authority");
  }
  const commitmentValue = BigInt(commitment.commitment);
  if (
    authorization.issuerKeyId.toLowerCase() !== commitment.issuerKeyId ||
    authorization.credentialCommitment !== commitmentValue ||
    authorization.expectedStatusId !== commitment.statusId ||
    authorization.expectedEpoch !== commitment.issuedAtEpoch
  ) {
    throw new Error("Self issuance authorization does not match the circuit-native commitment");
  }

  const allocation = normalizeAllocation(input.allocation);
  if (
    allocation.issuerKeyId !== commitment.issuerKeyId ||
    allocation.credentialCommitment !== commitmentValue ||
    allocation.statusId !== commitment.statusId ||
    allocation.issuedAtEpoch !== commitment.issuedAtEpoch
  ) {
    throw new Error("allocation evidence does not match the circuit-native commitment");
  }

  const statusSnapshot = input.statusSnapshot
    ? normalizeStatusSnapshot(input.statusSnapshot, commitment.statusId)
    : null;
  const transcriptWithoutHash = {
    schema: ZK_HOLDER_ISSUANCE_TRANSCRIPT_SCHEMA,
    version: ZK_HOLDER_ISSUANCE_TRANSCRIPT_VERSION,
    state: statusSnapshot ? "snapshot-covered" : "allocated",
    commitment,
    authorization: {
      chainId: chainId.toString(),
      issuanceRegistry,
      issuanceBridge,
      issuanceDomain: zkIssuanceDomainHash({ chainId, registry: issuanceRegistry }),
      subject: authorization.subject,
      verificationAuthority,
      selfConfigId: authorization.selfConfigId,
      authorizationDigest: zkSelfIssuanceAuthorizationDigest({
        chainId,
        bridge: issuanceBridge,
        authorization,
      }),
    },
    allocation: {
      transactionHash: allocation.transactionHash,
      blockNumber: allocation.blockNumber.toString(),
      blockHash: allocation.blockHash,
      logIndex: allocation.logIndex,
      statusId: allocation.statusId,
      issuedAtEpoch: allocation.issuedAtEpoch,
    },
    statusSnapshot: statusSnapshot
      ? {
          ...statusSnapshot,
          blockNumber: statusSnapshot.blockNumber.toString(),
          publishedAt: statusSnapshot.publishedAt.toString(),
        }
      : null,
  } as const;
  return {
    ...transcriptWithoutHash,
    transcriptHash: zkHolderIssuanceTranscriptHash(transcriptWithoutHash),
  };
}

export function parseZkHolderIssuanceTranscript(value: unknown): ZkHolderIssuanceTranscript {
  const candidate = object(value, "holder issuance transcript");
  exactKeys(
    candidate,
    [
      "schema",
      "version",
      "state",
      "commitment",
      "authorization",
      "allocation",
      "statusSnapshot",
      "transcriptHash",
    ],
    "holder issuance transcript",
  );
  if (
    candidate.schema !== ZK_HOLDER_ISSUANCE_TRANSCRIPT_SCHEMA ||
    candidate.version !== ZK_HOLDER_ISSUANCE_TRANSCRIPT_VERSION
  ) {
    throw new Error("unsupported holder issuance transcript schema");
  }
  const commitment = parseZkHolderCredentialCommitment(candidate.commitment);
  const authorization = parseAuthorization(candidate.authorization);
  if (authorization.issuanceDomain !== zkIssuanceDomainHash({
    chainId: Number(authorization.chainId),
    registry: authorization.issuanceRegistry,
  })) {
    throw new Error("holder issuance transcript has the wrong issuance domain");
  }
  const allocation = parseAllocation(candidate.allocation);
  if (allocation.statusId !== commitment.statusId || allocation.issuedAtEpoch !== commitment.issuedAtEpoch) {
    throw new Error("holder issuance transcript allocation does not match the commitment");
  }
  const statusSnapshot = candidate.statusSnapshot === null
    ? null
    : parseStatusSnapshot(candidate.statusSnapshot, commitment.statusId);
  const state = statusSnapshot ? "snapshot-covered" : "allocated";
  if (candidate.state !== state) throw new Error("holder issuance transcript state is inconsistent");

  const transcriptWithoutHash = {
    schema: ZK_HOLDER_ISSUANCE_TRANSCRIPT_SCHEMA,
    version: ZK_HOLDER_ISSUANCE_TRANSCRIPT_VERSION,
    state,
    commitment,
    authorization,
    allocation,
    statusSnapshot,
  } as const;
  const transcriptHash = bytes32(candidate.transcriptHash, "holder issuance transcript hash", true);
  if (transcriptHash !== zkHolderIssuanceTranscriptHash(transcriptWithoutHash)) {
    throw new Error("holder issuance transcript hash mismatch");
  }
  return { ...transcriptWithoutHash, transcriptHash };
}

type TranscriptWithoutHash = Omit<ZkHolderIssuanceTranscript, "transcriptHash">;

export function zkHolderIssuanceTranscriptHash(input: TranscriptWithoutHash): Hex {
  const snapshot = input.statusSnapshot;
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint16" },
        { type: "uint256" },
        { type: "uint256" },
        { type: "address" },
        { type: "address" },
        { type: "address" },
        { type: "address" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint32" },
        { type: "uint32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint64" },
        { type: "uint32" },
        { type: "bytes32" },
        { type: "uint32" },
        { type: "uint32" },
        { type: "bytes32" },
        { type: "uint64" },
        { type: "bytes32" },
        { type: "uint32" },
        { type: "uint64" },
      ],
      [
        transcriptDomain,
        ZK_HOLDER_ISSUANCE_TRANSCRIPT_VERSION,
        BigInt(input.commitment.commitment),
        BigInt(input.authorization.chainId),
        input.authorization.issuanceRegistry,
        input.authorization.issuanceBridge,
        input.authorization.subject,
        input.authorization.verificationAuthority,
        input.commitment.issuerKeyId,
        input.authorization.authorizationDigest,
        input.allocation.statusId,
        input.allocation.issuedAtEpoch,
        input.allocation.transactionHash,
        input.allocation.blockHash,
        BigInt(input.allocation.blockNumber),
        input.allocation.logIndex,
        snapshot?.root ?? zeroBytes32(),
        snapshot?.snapshotId ?? 0,
        snapshot?.activatedThroughStatusId ?? 0,
        snapshot?.transactionHash ?? zeroBytes32(),
        BigInt(snapshot?.blockNumber ?? "0"),
        snapshot?.blockHash ?? zeroBytes32(),
        snapshot?.logIndex ?? 0,
        BigInt(snapshot?.publishedAt ?? "0"),
      ],
    ),
  );
}

function normalizeAllocation(input: ZkHolderAllocationEvidenceInput) {
  return {
    transactionHash: bytes32(input.transactionHash, "allocation transaction hash", true),
    blockNumber: uint64BigInt(input.blockNumber, "allocation block number"),
    blockHash: bytes32(input.blockHash, "allocation block hash", true),
    logIndex: uint32(input.logIndex, "allocation log index", true),
    issuerKeyId: nonZeroBytes32(input.issuerKeyId, "allocation issuer key id"),
    statusId: uint32(input.statusId, "allocation status id", false),
    credentialCommitment: commitmentBigInt(input.credentialCommitment),
    issuedAtEpoch: uint32(input.issuedAtEpoch, "allocation issuance epoch", true),
  };
}

function normalizeStatusSnapshot(input: ZkHolderStatusSnapshotEvidenceInput, statusId: number) {
  const snapshot = {
    transactionHash: bytes32(input.transactionHash, "snapshot transaction hash", true),
    blockNumber: uint64BigInt(input.blockNumber, "snapshot block number"),
    blockHash: bytes32(input.blockHash, "snapshot block hash", true),
    logIndex: uint32(input.logIndex, "snapshot log index", true),
    snapshotId: uint32(input.snapshotId, "snapshot id", false),
    root: canonicalRoot(input.root),
    activatedThroughStatusId: uint32(
      input.activatedThroughStatusId,
      "snapshot allocation watermark",
      false,
    ),
    publishedAt: uint64BigInt(input.publishedAt, "snapshot publication time"),
  };
  if (snapshot.activatedThroughStatusId < statusId) {
    throw new Error("status snapshot does not cover the credential slot");
  }
  return snapshot;
}

function parseAuthorization(value: unknown): ZkHolderIssuanceTranscript["authorization"] {
  const candidate = object(value, "holder issuance authorization");
  exactKeys(
    candidate,
    [
      "chainId",
      "issuanceRegistry",
      "issuanceBridge",
      "issuanceDomain",
      "subject",
      "verificationAuthority",
      "selfConfigId",
      "authorizationDigest",
    ],
    "holder issuance authorization",
  );
  const chainId = canonicalDecimal(candidate.chainId, "issuance chain id", false);
  if (BigInt(chainId) > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("issuance chain id exceeds the JavaScript safe-integer range");
  }
  return {
    chainId,
    issuanceRegistry: address(candidate.issuanceRegistry, "issuance registry"),
    issuanceBridge: address(candidate.issuanceBridge, "issuance bridge"),
    issuanceDomain: bytes32(candidate.issuanceDomain, "issuance domain", true),
    subject: address(candidate.subject, "issuance subject"),
    verificationAuthority: address(candidate.verificationAuthority, "verification authority"),
    selfConfigId: bytes32(candidate.selfConfigId, "Self verifier configuration id", true),
    authorizationDigest: bytes32(candidate.authorizationDigest, "authorization digest", true),
  };
}

function parseAllocation(value: unknown): ZkHolderIssuanceTranscript["allocation"] {
  const candidate = object(value, "holder issuance allocation");
  exactKeys(
    candidate,
    ["transactionHash", "blockNumber", "blockHash", "logIndex", "statusId", "issuedAtEpoch"],
    "holder issuance allocation",
  );
  return {
    transactionHash: bytes32(candidate.transactionHash, "allocation transaction hash", true),
    blockNumber: canonicalDecimal(candidate.blockNumber, "allocation block number", true),
    blockHash: bytes32(candidate.blockHash, "allocation block hash", true),
    logIndex: uint32(candidate.logIndex, "allocation log index", true),
    statusId: uint32(candidate.statusId, "allocation status id", false),
    issuedAtEpoch: uint32(candidate.issuedAtEpoch, "allocation issuance epoch", true),
  };
}

function parseStatusSnapshot(
  value: unknown,
  statusId: number,
): NonNullable<ZkHolderIssuanceTranscript["statusSnapshot"]> {
  const candidate = object(value, "holder status snapshot");
  exactKeys(
    candidate,
    [
      "transactionHash",
      "blockNumber",
      "blockHash",
      "logIndex",
      "snapshotId",
      "root",
      "activatedThroughStatusId",
      "publishedAt",
    ],
    "holder status snapshot",
  );
  const snapshot = {
    transactionHash: bytes32(candidate.transactionHash, "snapshot transaction hash", true),
    blockNumber: canonicalDecimal(candidate.blockNumber, "snapshot block number", true),
    blockHash: bytes32(candidate.blockHash, "snapshot block hash", true),
    logIndex: uint32(candidate.logIndex, "snapshot log index", true),
    snapshotId: uint32(candidate.snapshotId, "snapshot id", false),
    root: canonicalRoot(candidate.root),
    activatedThroughStatusId: uint32(
      candidate.activatedThroughStatusId,
      "snapshot allocation watermark",
      false,
    ),
    publishedAt: canonicalDecimal(candidate.publishedAt, "snapshot publication time", false),
  };
  if (snapshot.activatedThroughStatusId < statusId) {
    throw new Error("status snapshot does not cover the credential slot");
  }
  return snapshot;
}

function exactKeys(value: Record<string, unknown>, expected: readonly string[], label: string): void {
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

function bytes32(value: unknown, label: string, nonZero = false): Hex {
  if (typeof value !== "string" || !isHex(value) || size(value) !== 32) {
    throw new Error(`${label} must be bytes32`);
  }
  const normalized = value.toLowerCase() as Hex;
  if (nonZero && BigInt(normalized) === 0n) throw new Error(`${label} must not be zero`);
  return normalized;
}

function nonZeroBytes32(value: unknown, label: string): Hex {
  return bytes32(value, label, true);
}

function address(value: unknown, label: string): Address {
  if (typeof value !== "string" || !isAddress(value) || BigInt(value) === 0n) {
    throw new Error(`${label} must be a nonzero EVM address`);
  }
  return getAddress(value);
}

function uint32(value: unknown, label: string, allowZero: boolean): number {
  if (typeof value === "bigint") {
    if (value < BigInt(allowZero ? 0 : 1) || value > BigInt(UINT32_MAX)) {
      throw new Error(`${label} must be ${allowZero ? "a" : "a nonzero"} uint32`);
    }
    return Number(value);
  }
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < (allowZero ? 0 : 1) ||
    value > UINT32_MAX
  ) {
    throw new Error(`${label} must be ${allowZero ? "a" : "a nonzero"} uint32`);
  }
  return value;
}

function positiveSafeInteger(value: unknown, label: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive safe integer`);
  }
  return value;
}

function uint64BigInt(value: unknown, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > UINT64_MAX) {
    throw new Error(`${label} must be a uint64 bigint`);
  }
  return value;
}

function canonicalDecimal(value: unknown, label: string, allowZero: boolean): string {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/u.test(value)) {
    throw new Error(`${label} must be a canonical decimal string`);
  }
  const parsed = BigInt(value);
  if ((!allowZero && parsed === 0n) || parsed > UINT64_MAX) {
    throw new Error(`${label} is outside the uint64 range`);
  }
  return value;
}

function word(value: Hex, index: number): bigint {
  const start = 2 + index * 64;
  const end = start + 64;
  if (!isHex(value) || value.length < end) throw new Error("event word is truncated");
  return BigInt(`0x${value.slice(start, end)}`);
}

function topicWord(value: Hex, label: string): bigint {
  return BigInt(bytes32(value, label));
}

function commitmentBigInt(value: unknown): bigint {
  if (typeof value !== "bigint" || value <= 0n || value >= BN254_SCALAR_FIELD) {
    throw new Error("credential commitment must be a nonzero canonical BN254 field element");
  }
  return value;
}

function canonicalCommitment(value: unknown): Hex {
  const normalized = bytes32(value, "credential commitment", true);
  commitmentBigInt(BigInt(normalized));
  return normalized;
}

function canonicalRoot(value: unknown): Hex {
  const normalized = bytes32(value, "packed status root", true);
  if (BigInt(normalized) >= BN254_SCALAR_FIELD) {
    throw new Error("packed status root must be a canonical BN254 field element");
  }
  return normalized;
}

function packedDate(value: string): number {
  return Number(value.replaceAll("-", ""));
}

function countryField(value: string, label: string): bigint {
  const normalized = value.trim().toUpperCase();
  if (!/^[A-Z]{3}$/u.test(normalized)) throw new Error(`${label} must be an ISO alpha-3 code`);
  return BigInt(stringToHex(normalized, { size: 3 }));
}

function zeroBytes32(): Hex {
  return `0x${"00".repeat(32)}` as Hex;
}
