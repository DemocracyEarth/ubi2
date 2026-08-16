/**
 * Transitional Self-passport issuance bridge helpers.
 *
 * The raw Self nullifier is accepted only by `zkSelfIssuanceDuplicateKey` and
 * must stay inside the trusted verification service. Applications receive only
 * the registry-scoped derivative and the signed EIP-712 authorization.
 */
import {
  encodeAbiParameters,
  encodeFunctionData,
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

export const ZK_SELF_ISSUANCE_DOMAIN_NAME = "ProofOfHumanitySelfIssuance" as const;
export const ZK_SELF_ISSUANCE_DOMAIN_VERSION = "1" as const;
export const ZK_SELF_ISSUANCE_MAX_AUTHORIZATION_LIFETIME_SECONDS = 600n;
export const ZK_SELF_VERIFIER_CONFIG_SCHEMA =
  "org.proofofhumanity.zk-issuance:self-verifier-config" as const;
export const ZK_SELF_VERIFIER_CONFIG_VERSION = 1 as const;
export const ZK_SELF_DUPLICATE_KEY_SCHEMA =
  "org.proofofhumanity.zk-issuance:self-nullifier" as const;
export const ZK_SELF_DUPLICATE_KEY_VERSION = 1 as const;

export type SelfVerifierEnvironment = "staging" | "production";

export interface ZkSelfVerifierConfigInput {
  /** Exact Self application scope accepted by SelfBackendVerifier. */
  scope: string;
  /** Exact public callback endpoint accepted by SelfBackendVerifier. */
  endpoint: string;
  environment: SelfVerifierEnvironment;
  /** Self attestation identifier. The v1 bridge supports e-passports (`1`). */
  attestationId: 1;
  /** Pinned package/protocol identifier, for example `@selfxyz/core@1.0.8`. */
  verifierPackage: string;
}

export interface ZkSelfIssuanceAuthorization {
  subject: Address;
  duplicateKey: Hex;
  credentialCommitment: bigint;
  issuerKeyId: Hex;
  expectedStatusId: number;
  expectedEpoch: number;
  deadline: bigint;
  selfConfigId: Hex;
}

export interface SerializedZkSelfIssuanceAuthorization {
  subject: Address;
  duplicateKey: Hex;
  credentialCommitment: string;
  issuerKeyId: Hex;
  expectedStatusId: number;
  expectedEpoch: number;
  deadline: string;
  selfConfigId: Hex;
}

export interface ZkSelfIssuanceArtifact {
  chainId: number;
  bridge: Address;
  registry: Address;
  authorization: SerializedZkSelfIssuanceAuthorization;
  signature: Hex;
}

export const zkSelfIssuanceTypes = {
  SelfIssuanceAuthorization: [
    { name: "subject", type: "address" },
    { name: "duplicateKey", type: "bytes32" },
    { name: "credentialCommitment", type: "uint256" },
    { name: "issuerKeyId", type: "bytes32" },
    { name: "expectedStatusId", type: "uint32" },
    { name: "expectedEpoch", type: "uint32" },
    { name: "deadline", type: "uint64" },
    { name: "selfConfigId", type: "bytes32" },
  ],
} as const;

export const zkIdentitySelfIssuanceBridgeAbi = [
  {
    type: "error",
    name: "AuthorizationExpired",
    inputs: [
      { name: "deadline", type: "uint64" },
      { name: "currentTimestamp", type: "uint256" },
    ],
  },
  {
    type: "error",
    name: "UnexpectedStatusId",
    inputs: [
      { name: "expected", type: "uint32" },
      { name: "provided", type: "uint32" },
    ],
  },
  {
    type: "error",
    name: "UnexpectedIssuanceEpoch",
    inputs: [
      { name: "expected", type: "uint32" },
      { name: "provided", type: "uint32" },
    ],
  },
  {
    type: "function",
    name: "issue",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "authorization",
        type: "tuple",
        components: [
          { name: "subject", type: "address" },
          { name: "duplicateKey", type: "bytes32" },
          { name: "credentialCommitment", type: "uint256" },
          { name: "issuerKeyId", type: "bytes32" },
          { name: "expectedStatusId", type: "uint32" },
          { name: "expectedEpoch", type: "uint32" },
          { name: "deadline", type: "uint64" },
          { name: "selfConfigId", type: "bytes32" },
        ],
      },
      { name: "signature", type: "bytes" },
    ],
    outputs: [
      { name: "statusId", type: "uint32" },
      { name: "issuedAtEpoch", type: "uint32" },
    ],
  },
] as const;

const refreshableIssuanceErrors = new Set([
  "AuthorizationExpired",
  "UnexpectedStatusId",
  "UnexpectedIssuanceEpoch",
]);

/** True only for bridge/registry failures that a grant-preserving API refresh can repair. */
export function isZkSelfIssuanceRefreshableErrorName(errorName: unknown): boolean {
  return typeof errorName === "string" && refreshableIssuanceErrors.has(errorName);
}

/** Walk a viem-style `cause` chain without accepting error-message substring guesses. */
export function zkSelfIssuanceRefreshableErrorName(error: unknown): string | null {
  const seen = new Set<object>();
  let current = error;
  for (let depth = 0; depth < 12 && current && typeof current === "object"; depth++) {
    if (seen.has(current)) return null;
    seen.add(current);
    const candidate = current as { errorName?: unknown; data?: unknown; cause?: unknown };
    if (isZkSelfIssuanceRefreshableErrorName(candidate.errorName)) {
      return candidate.errorName as string;
    }
    if (candidate.data && typeof candidate.data === "object") {
      const dataErrorName = (candidate.data as { errorName?: unknown }).errorName;
      if (isZkSelfIssuanceRefreshableErrorName(dataErrorName)) return dataErrorName as string;
    }
    current = candidate.cause;
  }
  return null;
}

const verifierConfigDomainHash = keccak256(stringToBytes(ZK_SELF_VERIFIER_CONFIG_SCHEMA));
const duplicateKeyDomainHash = keccak256(stringToBytes(ZK_SELF_DUPLICATE_KEY_SCHEMA));
const UINT32_MAX = 0xffff_ffff;
const UINT64_MAX = (1n << 64n) - 1n;

function nonEmpty(value: string, label: string): string {
  if (!value || value.trim() !== value) throw new Error(`${label} must be non-empty and unpadded`);
  return value;
}

function uint32(value: number, label: string): number {
  if (!Number.isSafeInteger(value) || value < 0 || value > UINT32_MAX) {
    throw new Error(`${label} must be a uint32`);
  }
  return value;
}

function uint64(value: bigint, label: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > UINT64_MAX) {
    throw new Error(`${label} must be a uint64`);
  }
  return value;
}

function bytes32(value: Hex, label: string, nonZero = true): Hex {
  if (!isHex(value) || size(value) !== 32) throw new Error(`${label} must be bytes32`);
  const normalized = value.toLowerCase() as Hex;
  if (nonZero && BigInt(normalized) === 0n) throw new Error(`${label} must not be zero`);
  return normalized;
}

function address(value: Address, label: string): Address {
  if (!isAddress(value)) throw new Error(`${label} must be an EVM address`);
  const normalized = getAddress(value);
  if (BigInt(normalized) === 0n) throw new Error(`${label} must not be the zero address`);
  return normalized;
}

function chainId(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) throw new Error("issuance chain id must be positive");
  return value;
}

/** Hash the exact Self verifier trust configuration pinned by a bridge deployment. */
export function zkSelfVerifierConfigId(input: ZkSelfVerifierConfigInput): Hex {
  if (input.environment !== "staging" && input.environment !== "production") {
    throw new Error("Self verifier environment must be staging or production");
  }
  if (input.attestationId !== 1) throw new Error("Self verifier attestation id must be 1");

  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint16" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "bytes32" },
        { type: "uint8" },
        { type: "bytes32" },
      ],
      [
        verifierConfigDomainHash,
        ZK_SELF_VERIFIER_CONFIG_VERSION,
        keccak256(stringToBytes(nonEmpty(input.scope, "Self scope"))),
        keccak256(stringToBytes(nonEmpty(input.endpoint, "Self endpoint"))),
        keccak256(stringToBytes(input.environment)),
        input.attestationId,
        keccak256(stringToBytes(nonEmpty(input.verifierPackage, "Self verifier package"))),
      ],
    ),
  );
}

/**
 * Derive the opaque registry-scoped key consumed by the issuance registry.
 * Call this only inside the verifier service; never log or return `selfNullifier`.
 */
export function zkSelfIssuanceDuplicateKey(input: {
  issuanceDomain: Hex;
  selfNullifier: bigint;
}): Hex {
  if (
    typeof input.selfNullifier !== "bigint" ||
    input.selfNullifier <= 0n ||
    input.selfNullifier >= BN254_SCALAR_FIELD
  ) {
    throw new Error("Self nullifier must be a non-zero canonical BN254 field element");
  }
  return keccak256(
    encodeAbiParameters(
      [
        { type: "bytes32" },
        { type: "uint16" },
        { type: "bytes32" },
        { type: "uint256" },
      ],
      [
        duplicateKeyDomainHash,
        ZK_SELF_DUPLICATE_KEY_VERSION,
        bytes32(input.issuanceDomain, "issuance domain"),
        input.selfNullifier,
      ],
    ),
  );
}

export function normalizeZkSelfIssuanceAuthorization(
  input: ZkSelfIssuanceAuthorization,
): ZkSelfIssuanceAuthorization {
  if (
    typeof input.credentialCommitment !== "bigint" ||
    input.credentialCommitment <= 0n ||
    input.credentialCommitment >= BN254_SCALAR_FIELD
  ) {
    throw new Error("credential commitment must be a non-zero canonical BN254 field element");
  }
  return {
    subject: address(input.subject, "issuance subject"),
    duplicateKey: bytes32(input.duplicateKey, "duplicate key"),
    credentialCommitment: input.credentialCommitment,
    issuerKeyId: bytes32(input.issuerKeyId, "issuer key id"),
    expectedStatusId: uint32(input.expectedStatusId, "expected status id"),
    expectedEpoch: uint32(input.expectedEpoch, "expected issuance epoch"),
    deadline: uint64(input.deadline, "authorization deadline"),
    selfConfigId: bytes32(input.selfConfigId, "Self verifier configuration id"),
  };
}

/** EIP-712 payload for the isolated Self verification authority. */
export function zkSelfIssuanceTypedData(input: {
  chainId: number;
  bridge: Address;
  authorization: ZkSelfIssuanceAuthorization;
}) {
  return {
    domain: {
      name: ZK_SELF_ISSUANCE_DOMAIN_NAME,
      version: ZK_SELF_ISSUANCE_DOMAIN_VERSION,
      chainId: chainId(input.chainId),
      verifyingContract: address(input.bridge, "Self issuance bridge"),
    },
    types: zkSelfIssuanceTypes,
    primaryType: "SelfIssuanceAuthorization",
    message: normalizeZkSelfIssuanceAuthorization(input.authorization),
  } as const;
}

export function zkSelfIssuanceAuthorizationDigest(input: {
  chainId: number;
  bridge: Address;
  authorization: ZkSelfIssuanceAuthorization;
}): Hex {
  return hashTypedData(zkSelfIssuanceTypedData(input));
}

export function recoverZkSelfIssuanceAuthority(input: {
  chainId: number;
  bridge: Address;
  authorization: ZkSelfIssuanceAuthorization;
  signature: Hex;
}): Promise<Address> {
  if (!isHex(input.signature)) throw new Error("Self issuance signature must be hex");
  return recoverTypedDataAddress({
    ...zkSelfIssuanceTypedData(input),
    signature: input.signature,
  });
}

export function serializeZkSelfIssuanceAuthorization(
  input: ZkSelfIssuanceAuthorization,
): SerializedZkSelfIssuanceAuthorization {
  const normalized = normalizeZkSelfIssuanceAuthorization(input);
  return {
    ...normalized,
    credentialCommitment: normalized.credentialCommitment.toString(),
    deadline: normalized.deadline.toString(),
  };
}

export function deserializeZkSelfIssuanceAuthorization(
  input: SerializedZkSelfIssuanceAuthorization,
): ZkSelfIssuanceAuthorization {
  if (!/^\d+$/u.test(input.credentialCommitment) || !/^\d+$/u.test(input.deadline)) {
    throw new Error("serialized Self issuance integers must be unsigned decimal strings");
  }
  return normalizeZkSelfIssuanceAuthorization({
    ...input,
    credentialCommitment: BigInt(input.credentialCommitment),
    deadline: BigInt(input.deadline),
  });
}

/** Encode the subject-submitted bridge transaction. */
export function encodeZkSelfIssuance(input: {
  authorization: ZkSelfIssuanceAuthorization | SerializedZkSelfIssuanceAuthorization;
  signature: Hex;
}): Hex {
  const authorization =
    typeof input.authorization.credentialCommitment === "string"
      ? deserializeZkSelfIssuanceAuthorization(input.authorization as SerializedZkSelfIssuanceAuthorization)
      : normalizeZkSelfIssuanceAuthorization(input.authorization as ZkSelfIssuanceAuthorization);
  if (!isHex(input.signature)) throw new Error("Self issuance signature must be hex");
  return encodeFunctionData({
    abi: zkIdentitySelfIssuanceBridgeAbi,
    functionName: "issue",
    args: [authorization, input.signature],
  });
}
