/** Public EVM integration helpers for Proof-of-Humanity predicate attestations (issuer path v1). */
import {
  createPublicClient,
  hashTypedData,
  http,
  keccak256,
  recoverTypedDataAddress,
  stringToBytes,
  type Address,
  type Hex,
} from "viem";

export const PREDICATE_DOMAIN_NAME = "ProofOfHumanityPredicate" as const;
export const PREDICATE_DOMAIN_VERSION = "1" as const;

export const predicateTypes = {
  PredicateAttestation: [
    { name: "consumer", type: "address" },
    { name: "context", type: "bytes32" },
    { name: "predicate", type: "bytes32" },
    { name: "result", type: "bool" },
    { name: "subject", type: "address" },
    { name: "epoch", type: "uint32" },
    { name: "nonce", type: "uint256" },
  ],
} as const;

export interface SerializedPredicateAttestation {
  consumer: Address;
  context: Hex;
  predicate: Hex;
  result: boolean;
  subject: Address;
  epoch: number;
  nonce: string;
}

export interface PredicateArtifact {
  chainId: number;
  verifier: Address;
  attestation: SerializedPredicateAttestation;
  signature: Hex;
}

export const predicateVerifierAbi = [
  { type: "function", name: "issuer", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  { type: "function", name: "prover", stateMutability: "view", inputs: [], outputs: [{ name: "", type: "address" }] },
  {
    type: "function",
    name: "check",
    stateMutability: "view",
    inputs: [
      {
        name: "att",
        type: "tuple",
        components: [
          { name: "consumer", type: "address" },
          { name: "context", type: "bytes32" },
          { name: "predicate", type: "bytes32" },
          { name: "result", type: "bool" },
          { name: "subject", type: "address" },
          { name: "epoch", type: "uint32" },
          { name: "nonce", type: "uint256" },
        ],
      },
      { name: "signature", type: "bytes" },
      { name: "presenter", type: "address" },
      { name: "consumer", type: "address" },
    ],
    outputs: [{ name: "", type: "bool" }],
  },
  {
    type: "function",
    name: "consume",
    stateMutability: "nonpayable",
    inputs: [
      {
        name: "att",
        type: "tuple",
        components: [
          { name: "consumer", type: "address" },
          { name: "context", type: "bytes32" },
          { name: "predicate", type: "bytes32" },
          { name: "result", type: "bool" },
          { name: "subject", type: "address" },
          { name: "epoch", type: "uint32" },
          { name: "nonce", type: "uint256" },
        ],
      },
      { name: "signature", type: "bytes" },
      { name: "presenter", type: "address" },
    ],
    outputs: [{ name: "result", type: "bool" }],
  },
] as const;

export function predicateDescriptor(input: { kind: "age"; minimum: 18 | 21 } | { kind: "nationality"; country: string } | { kind: "sanctions" }): string {
  if (input.kind === "age") return `age>=${input.minimum}`;
  if (input.kind === "sanctions") return "sanctions-clear";
  const country = input.country.toUpperCase();
  if (!/^[A-Z]{3}$/.test(country)) throw new Error("country must be an ISO 3166-1 alpha-3 code");
  return `nationality=${country}`;
}

export function predicateDescriptorHash(descriptor: string): Hex {
  if (!/^age>=(18|21)$/.test(descriptor) && !/^nationality=[A-Z]{3}$/.test(descriptor) && descriptor !== "sanctions-clear") {
    throw new Error(`unsupported canonical predicate descriptor: ${descriptor}`);
  }
  return keccak256(stringToBytes(descriptor));
}

export function predicateContext(label: string): Hex {
  if (!label) throw new Error("context label must not be empty");
  return keccak256(stringToBytes(label));
}

export function deserializePredicateAttestation(attestation: SerializedPredicateAttestation) {
  return { ...attestation, nonce: BigInt(attestation.nonce) };
}

export function predicateAttestationDigest(artifact: PredicateArtifact): Hex {
  return hashTypedData({
    domain: {
      name: PREDICATE_DOMAIN_NAME,
      version: PREDICATE_DOMAIN_VERSION,
      chainId: artifact.chainId,
      verifyingContract: artifact.verifier,
    },
    types: predicateTypes,
    primaryType: "PredicateAttestation",
    message: deserializePredicateAttestation(artifact.attestation),
  });
}

export async function recoverPredicateIssuer(artifact: PredicateArtifact): Promise<Address> {
  return recoverTypedDataAddress({
    domain: {
      name: PREDICATE_DOMAIN_NAME,
      version: PREDICATE_DOMAIN_VERSION,
      chainId: artifact.chainId,
      verifyingContract: artifact.verifier,
    },
    types: predicateTypes,
    primaryType: "PredicateAttestation",
    message: deserializePredicateAttestation(artifact.attestation),
    signature: artifact.signature,
  });
}

/** Stateless on-chain verification. Use `consume` from your contract when replay must be prevented. */
export async function checkPredicateArtifact(options: {
  artifact: PredicateArtifact;
  rpcUrl: string;
  presenter: Address;
  consumer: Address;
}): Promise<boolean> {
  const client = createPublicClient({ transport: http(options.rpcUrl) });
  return client.readContract({
    address: options.artifact.verifier,
    abi: predicateVerifierAbi,
    functionName: "check",
    args: [
      deserializePredicateAttestation(options.artifact.attestation),
      options.artifact.signature,
      options.presenter,
      options.consumer,
    ],
  });
}
