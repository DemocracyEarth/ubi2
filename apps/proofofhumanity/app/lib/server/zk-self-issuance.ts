import "server-only";

import {
  createPublicClient,
  getAddress,
  http,
  keccak256,
  type Address,
  type Hex,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
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
import { getZkSelfIssuanceServerConfig } from "../../server-config";

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
 * Build the only artifact accepted by the immutable bridge after re-checking
 * every configured and on-chain trust input at one block.
 */
export async function buildZkSelfIssuanceArtifact(input: {
  subject: Address;
  rawSelfNullifier: bigint;
  credentialCommitment: bigint;
}): Promise<ZkSelfIssuanceArtifact> {
  const config = getZkSelfIssuanceServerConfig();
  if (!config) throw new Error("The v2 Self issuance bridge is not configured on this server.");

  const client = createPublicClient({ transport: http(config.rpcUrl) });
  const actualChainId = await client.getChainId();
  if (actualChainId !== config.chainId) {
    throw new Error(
      `V2 issuance RPC chain mismatch: configured ${config.chainId}, received ${actualChainId}.`,
    );
  }
  const blockNumber = await client.getBlockNumber();
  const selfConfigId = configuredSelfVerifierConfigId();
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
  if (bridgeSelfConfigId.toLowerCase() !== selfConfigId) {
    throw new Error("V2 Self bridge pins a different Self verifier configuration.");
  }

  const authorization: ZkSelfIssuanceAuthorization = {
    subject: getAddress(input.subject),
    duplicateKey: zkSelfIssuanceDuplicateKey({
      issuanceDomain,
      selfNullifier: input.rawSelfNullifier,
    }),
    credentialCommitment: input.credentialCommitment,
    issuerKeyId: config.issuerKeyId,
    expectedStatusId: Number(issuer[2]),
    expectedEpoch: currentEpoch,
    deadline:
      issuanceBlock.timestamp + ZK_SELF_ISSUANCE_MAX_AUTHORIZATION_LIFETIME_SECONDS,
    selfConfigId,
  };
  const signature = await authority.signTypedData(
    zkSelfIssuanceTypedData({
      chainId: config.chainId,
      bridge: config.bridge,
      authorization,
    }),
  );

  return {
    chainId: config.chainId,
    bridge: config.bridge,
    registry: config.registry,
    authorization: serializeZkSelfIssuanceAuthorization(authorization),
    signature,
  };
}
