import "server-only";

import {
  createPublicClient,
  getAddress,
  http,
  isAddress,
  isHex,
  keccak256,
  size,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  BN254_SCALAR_FIELD,
  normalizeZkSelfIssuanceAuthorization,
  serializeZkSelfIssuanceAuthorization,
  ZK_SELF_ISSUANCE_MAX_AUTHORIZATION_LIFETIME_SECONDS,
  zkIssuanceDomainHash,
  zkSelfIssuanceDuplicateKey,
  zkSelfIssuanceTypedData,
  zkSelfVerifierConfigId,
  type ZkSelfIssuanceArtifact,
  type ZkSelfIssuanceAuthorization,
} from "@ubi2/sdk";
import { SELF_ENDPOINT, SELF_ENV, SELF_SCOPE } from "../../config";
import {
  getZkSelfIssuanceServerConfig,
  type ZkSelfIssuanceServerConfig,
} from "../../server-config";

const SELF_ATTESTATION_ID = 1 as const;
const SELF_VERIFIER_PACKAGE = "@selfxyz/core@1.0.8" as const;

const registryAbi = [
  {
    type: "function",
    name: "issuanceDomain",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "issuerKeys",
    stateMutability: "view",
    inputs: [{ name: "issuerKeyId", type: "bytes32" }],
    outputs: [
      { name: "registered", type: "bool" },
      { name: "active", type: "bool" },
      { name: "nextStatusId", type: "uint64" },
    ],
  },
  {
    type: "function",
    name: "issuanceAuthorities",
    stateMutability: "view",
    inputs: [
      { name: "issuerKeyId", type: "bytes32" },
      { name: "authority", type: "address" },
    ],
    outputs: [
      { name: "codehash", type: "bytes32" },
      { name: "registered", type: "bool" },
      { name: "active", type: "bool" },
    ],
  },
  {
    type: "function",
    name: "currentEpoch",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "epoch", type: "uint32" }],
  },
  {
    type: "function",
    name: "isDuplicateKeyUsed",
    stateMutability: "view",
    inputs: [{ name: "duplicateKey", type: "bytes32" }],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "credentialCommitmentUsed",
    stateMutability: "view",
    inputs: [{ name: "credentialCommitment", type: "uint256" }],
    outputs: [{ name: "", type: "bool" }],
  },
] as const;

const bridgeAbi = [
  {
    type: "function",
    name: "registry",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "issuerKeyId",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
  {
    type: "function",
    name: "verificationAuthority",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "address" }],
  },
  {
    type: "function",
    name: "selfConfigId",
    stateMutability: "view",
    inputs: [],
    outputs: [{ name: "", type: "bytes32" }],
  },
] as const;

export function configuredSelfVerifierConfigId(): Hex {
  if (!SELF_ENDPOINT) {
    throw new Error("NEXT_PUBLIC_SELF_ENDPOINT is required for v2 Self issuance.");
  }
  return zkSelfVerifierConfigId({
    scope: SELF_SCOPE,
    endpoint: SELF_ENDPOINT,
    environment: SELF_ENV,
    attestationId: SELF_ATTESTATION_ID,
    verifierPackage: SELF_VERIFIER_PACKAGE,
  });
}

/**
 * Private, proof-derived capability retained only in the bounded server handoff.
 * It deliberately omits the raw Self nullifier and fixes every field that a
 * refresh is forbidden to change.
 */
export interface ZkSelfIssuanceGrant {
  readonly subject: Address;
  readonly duplicateKey: Hex;
  readonly credentialCommitment: bigint;
  readonly chainId: number;
  readonly registry: Address;
  readonly bridge: Address;
  readonly issuerKeyId: Hex;
  readonly selfConfigId: Hex;
  readonly expiresAtMs: number;
}

export class ZkSelfIssuanceGrantExpiredError extends Error {
  constructor() {
    super("The verified issuance grant expired; scan the passport again.");
    this.name = "ZkSelfIssuanceGrantExpiredError";
  }
}

export class ZkSelfIssuanceAlreadyConsumedError extends Error {
  constructor() {
    super("This passport or credential commitment has already received an issuance slot.");
    this.name = "ZkSelfIssuanceAlreadyConsumedError";
  }
}

function normalizeGrant(input: ZkSelfIssuanceGrant): ZkSelfIssuanceGrant {
  if (!Number.isSafeInteger(input.expiresAtMs) || input.expiresAtMs <= Date.now()) {
    throw new ZkSelfIssuanceGrantExpiredError();
  }
  if (!Number.isSafeInteger(input.chainId) || input.chainId <= 0) {
    throw new Error("V2 issuance grant chain id must be a positive integer.");
  }
  if (!isAddress(input.registry) || BigInt(input.registry) === 0n) {
    throw new Error("V2 issuance grant registry must be a non-zero EVM address.");
  }
  if (!isAddress(input.bridge) || BigInt(input.bridge) === 0n) {
    throw new Error("V2 issuance grant bridge must be a non-zero EVM address.");
  }
  if (!isHex(input.duplicateKey) || size(input.duplicateKey) !== 32 || BigInt(input.duplicateKey) === 0n) {
    throw new Error("V2 issuance grant duplicate key must be non-zero bytes32.");
  }
  if (
    typeof input.credentialCommitment !== "bigint" ||
    input.credentialCommitment <= 0n ||
    input.credentialCommitment >= BN254_SCALAR_FIELD
  ) {
    throw new Error("V2 issuance grant commitment must be a canonical BN254 field element.");
  }

  const normalized = normalizeZkSelfIssuanceAuthorization({
    subject: input.subject,
    duplicateKey: input.duplicateKey,
    credentialCommitment: input.credentialCommitment,
    issuerKeyId: input.issuerKeyId,
    expectedStatusId: 1,
    expectedEpoch: 0,
    deadline: 1n,
    selfConfigId: input.selfConfigId,
  });
  return Object.freeze({
    subject: normalized.subject,
    duplicateKey: normalized.duplicateKey,
    credentialCommitment: normalized.credentialCommitment,
    chainId: input.chainId,
    registry: getAddress(input.registry),
    bridge: getAddress(input.bridge),
    issuerKeyId: normalized.issuerKeyId,
    selfConfigId: normalized.selfConfigId,
    expiresAtMs: input.expiresAtMs,
  });
}

function assertGrantMatchesServerConfig(
  grant: ZkSelfIssuanceGrant,
  config: ZkSelfIssuanceServerConfig,
): void {
  if (
    grant.chainId !== config.chainId ||
    grant.registry !== config.registry ||
    grant.bridge !== config.bridge ||
    grant.issuerKeyId !== config.issuerKeyId
  ) {
    throw new Error("V2 issuance server configuration changed after passport verification.");
  }
  if (grant.selfConfigId !== configuredSelfVerifierConfigId()) {
    throw new Error("The Self verifier configuration changed after passport verification.");
  }
}

/**
 * Re-check every configured and on-chain trust input at one block, then sign
 * only the next slot/epoch for the immutable proof-derived grant.
 */
async function authorizeZkSelfIssuanceGrant(
  untrustedGrant: ZkSelfIssuanceGrant,
  config: ZkSelfIssuanceServerConfig,
): Promise<ZkSelfIssuanceArtifact> {
  const grant = normalizeGrant(untrustedGrant);
  assertGrantMatchesServerConfig(grant, config);
  const client = createPublicClient({ transport: http(config.rpcUrl) });
  const actualChainId = await client.getChainId();
  if (actualChainId !== config.chainId) {
    throw new Error(
      `V2 issuance RPC chain mismatch: configured ${config.chainId}, received ${actualChainId}.`,
    );
  }
  const blockNumber = await client.getBlockNumber();
  const expectedIssuanceDomain = zkIssuanceDomainHash({
    chainId: config.chainId,
    registry: config.registry,
  });
  const authority = privateKeyToAccount(config.authorityPrivateKey);

  const [
    issuanceDomain,
    issuer,
    registryAuthorization,
    currentEpoch,
    duplicateKeyUsed,
    credentialCommitmentUsed,
    bridgeRegistry,
    bridgeIssuerKeyId,
    bridgeAuthority,
    bridgeSelfConfigId,
    bridgeBytecode,
    issuanceBlock,
  ] = await Promise.all([
    client.readContract({
      address: config.registry,
      abi: registryAbi,
      functionName: "issuanceDomain",
      blockNumber,
    }),
    client.readContract({
      address: config.registry,
      abi: registryAbi,
      functionName: "issuerKeys",
      args: [config.issuerKeyId],
      blockNumber,
    }),
    client.readContract({
      address: config.registry,
      abi: registryAbi,
      functionName: "issuanceAuthorities",
      args: [config.issuerKeyId, config.bridge],
      blockNumber,
    }),
    client.readContract({
      address: config.registry,
      abi: registryAbi,
      functionName: "currentEpoch",
      blockNumber,
    }),
    client.readContract({
      address: config.registry,
      abi: registryAbi,
      functionName: "isDuplicateKeyUsed",
      args: [grant.duplicateKey],
      blockNumber,
    }),
    client.readContract({
      address: config.registry,
      abi: registryAbi,
      functionName: "credentialCommitmentUsed",
      args: [grant.credentialCommitment],
      blockNumber,
    }),
    client.readContract({
      address: config.bridge,
      abi: bridgeAbi,
      functionName: "registry",
      blockNumber,
    }),
    client.readContract({
      address: config.bridge,
      abi: bridgeAbi,
      functionName: "issuerKeyId",
      blockNumber,
    }),
    client.readContract({
      address: config.bridge,
      abi: bridgeAbi,
      functionName: "verificationAuthority",
      blockNumber,
    }),
    client.readContract({
      address: config.bridge,
      abi: bridgeAbi,
      functionName: "selfConfigId",
      blockNumber,
    }),
    client.getBytecode({ address: config.bridge, blockNumber }),
    client.getBlock({ blockNumber }),
  ]);

  if (issuanceDomain.toLowerCase() !== expectedIssuanceDomain) {
    throw new Error("V2 issuance registry domain does not match the configured chain and address.");
  }
  if (!issuer[0] || !issuer[1] || issuer[2] === 0n || issuer[2] > 0xffff_ffffn) {
    throw new Error("V2 issuer key is inactive or has no allocatable uint32 status slot.");
  }
  if (duplicateKeyUsed || credentialCommitmentUsed) {
    throw new ZkSelfIssuanceAlreadyConsumedError();
  }
  if (!registryAuthorization[1] || !registryAuthorization[2]) {
    throw new Error("V2 Self bridge is not an active registry issuance authority.");
  }
  if (!bridgeBytecode || keccak256(bridgeBytecode) !== registryAuthorization[0]) {
    throw new Error("V2 Self bridge bytecode does not match the registry-pinned codehash.");
  }
  if (getAddress(bridgeRegistry) !== config.registry) {
    throw new Error("V2 Self bridge points to a different issuance registry.");
  }
  if (bridgeIssuerKeyId.toLowerCase() !== config.issuerKeyId) {
    throw new Error("V2 Self bridge points to a different issuer key.");
  }
  if (getAddress(bridgeAuthority) !== authority.address) {
    throw new Error("V2 Self bridge verification authority does not match the configured signing key.");
  }
  if (bridgeSelfConfigId.toLowerCase() !== grant.selfConfigId) {
    throw new Error("V2 Self bridge pins a different Self verifier configuration.");
  }

  if (Date.now() >= grant.expiresAtMs) throw new ZkSelfIssuanceGrantExpiredError();
  const grantDeadline = BigInt(Math.floor(grant.expiresAtMs / 1_000));
  const bridgeMaximumDeadline =
    issuanceBlock.timestamp + ZK_SELF_ISSUANCE_MAX_AUTHORIZATION_LIFETIME_SECONDS;
  const deadline = grantDeadline < bridgeMaximumDeadline ? grantDeadline : bridgeMaximumDeadline;
  if (deadline <= issuanceBlock.timestamp) throw new ZkSelfIssuanceGrantExpiredError();

  const authorization: ZkSelfIssuanceAuthorization = {
    subject: grant.subject,
    duplicateKey: grant.duplicateKey,
    credentialCommitment: grant.credentialCommitment,
    issuerKeyId: grant.issuerKeyId,
    expectedStatusId: Number(issuer[2]),
    expectedEpoch: currentEpoch,
    deadline,
    selfConfigId: grant.selfConfigId,
  };
  const signature = await authority.signTypedData(
    zkSelfIssuanceTypedData({
      chainId: config.chainId,
      bridge: config.bridge,
      authorization,
    }),
  );

  return {
    chainId: grant.chainId,
    bridge: grant.bridge,
    registry: grant.registry,
    authorization: serializeZkSelfIssuanceAuthorization(authorization),
    signature,
  };
}

/**
 * Derive the private refresh grant exactly once while the verified Self
 * nullifier is in memory, then discard the raw nullifier.
 */
export async function buildZkSelfIssuanceGrant(input: {
  subject: Address;
  rawSelfNullifier: bigint;
  credentialCommitment: bigint;
  expiresAtMs: number;
}): Promise<{ grant: ZkSelfIssuanceGrant; artifact: ZkSelfIssuanceArtifact }> {
  const config = getZkSelfIssuanceServerConfig();
  if (!config) throw new Error("The v2 Self issuance bridge is not configured on this server.");
  const issuanceDomain = zkIssuanceDomainHash({ chainId: config.chainId, registry: config.registry });
  const grant = normalizeGrant({
    subject: input.subject,
    duplicateKey: zkSelfIssuanceDuplicateKey({
      issuanceDomain,
      selfNullifier: input.rawSelfNullifier,
    }),
    credentialCommitment: input.credentialCommitment,
    chainId: config.chainId,
    registry: config.registry,
    bridge: config.bridge,
    issuerKeyId: config.issuerKeyId,
    selfConfigId: configuredSelfVerifierConfigId(),
    expiresAtMs: input.expiresAtMs,
  });
  const artifact = await authorizeZkSelfIssuanceGrant(grant, config);
  return { grant, artifact };
}

/** Refresh only race-prone fields; all proof-derived fields remain fixed. */
export async function refreshZkSelfIssuanceArtifact(
  grant: ZkSelfIssuanceGrant,
): Promise<ZkSelfIssuanceArtifact> {
  const config = getZkSelfIssuanceServerConfig();
  if (!config) throw new Error("The v2 Self issuance bridge is not configured on this server.");
  return authorizeZkSelfIssuanceGrant(grant, config);
}
