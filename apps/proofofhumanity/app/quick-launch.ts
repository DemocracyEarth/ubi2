import { getAddress, type Address } from "viem";
import {
  CHAINS,
  ZERO_ADDRESS,
  isDeployed,
  isPredicateDeployed,
  type ChainConfig,
} from "./config";
import type { DisclosureRequest } from "./lib/disclosure-profile";

/**
 * PoH Quick Launch v1 is deliberately one product on one public testnet.
 * Keeping this boundary in executable configuration prevents a future chain,
 * mainnet address, or research feature from silently joining the release path.
 */
export const QUICK_LAUNCH_RELEASE = {
  id: "poh-quick-launch-v1",
  chainId: 84_532,
  network: "testnet",
  proofOfHumanity: getAddress("0x06BD253009F74ad934A4DaEac133b153d9Fe8029"),
  predicateVerifier: getAddress("0x2051D33c2F10CDd3739324afc4C6fD957564a9D6"),
  expectedOwner: getAddress("0x26250e47500943464290A77ae3508a3001d9B69d"),
  expectedIssuer: getAddress("0x1D6cB99ff20223d730Ae5D4680EC5154B7FdAefe"),
  features: {
    selfVoucherMint: true,
    issuerAttestedPredicates: true,
    sponsoredTestnetMint: true,
    demoCredentials: false,
    holderVault: false,
    v2Issuance: false,
    v2PredicateProver: false,
    mainnet: false,
  },
} as const;

export function selectQuickLaunchChain(chains: readonly ChainConfig[]): ChainConfig {
  const matches = chains.filter((chain) => chain.chainId === QUICK_LAUNCH_RELEASE.chainId);
  if (matches.length !== 1) {
    throw new Error(
      `Quick Launch requires exactly one chain ${QUICK_LAUNCH_RELEASE.chainId}; found ${matches.length}.`,
    );
  }
  const chain = matches[0];
  if (chain.network !== QUICK_LAUNCH_RELEASE.network) {
    throw new Error("Quick Launch chain must remain classified as a public testnet.");
  }
  return chain;
}

export const QUICK_LAUNCH_CHAIN = selectQuickLaunchChain(CHAINS);
export const QUICK_LAUNCH_CHAINS = [QUICK_LAUNCH_CHAIN] as const;

export function isQuickLaunchChainId(chainId: number): boolean {
  return chainId === QUICK_LAUNCH_RELEASE.chainId;
}

/** V1 disclosure requests are accepted; proof-bound v2 commitments fail closed. */
export function isQuickLaunchDisclosureRequest(request: DisclosureRequest): boolean {
  return request.credentialCommitment === undefined;
}

export interface QuickLaunchPublicProbe {
  chainId: number;
  pohAddress: Address;
  predicateAddress: Address;
  pohCode: `0x${string}`;
  predicateCode: `0x${string}`;
  pohOwner: Address;
  pohIssuer: Address;
  predicateOwner: Address;
  predicateIssuer: Address;
  predicateProver: Address;
  selfEndpoint: string;
  selfEnvironment: string;
}

export interface QuickLaunchPreflightResult {
  ready: boolean;
  errors: string[];
}

function validateSelfEndpoint(value: string, errors: string[]): void {
  let endpoint: URL;
  try {
    endpoint = new URL(value);
  } catch {
    errors.push("NEXT_PUBLIC_SELF_ENDPOINT must be an absolute public HTTPS URL.");
    return;
  }
  if (endpoint.protocol !== "https:") errors.push("NEXT_PUBLIC_SELF_ENDPOINT must use HTTPS.");
  if (endpoint.username || endpoint.password) errors.push("NEXT_PUBLIC_SELF_ENDPOINT must not contain credentials.");
  if (["localhost", "127.0.0.1", "::1"].includes(endpoint.hostname.toLowerCase())) {
    errors.push("NEXT_PUBLIC_SELF_ENDPOINT must not use a loopback host.");
  }
  if (endpoint.pathname !== "/api/self-verify" || endpoint.search || endpoint.hash) {
    errors.push("NEXT_PUBLIC_SELF_ENDPOINT must point exactly to /api/self-verify with no query or fragment.");
  }
}

/** Pure, transaction-free assessment used by the operator preflight and failure-path tests. */
export function assessQuickLaunchPublicProbe(probe: QuickLaunchPublicProbe): QuickLaunchPreflightResult {
  const errors: string[] = [];
  if (probe.chainId !== QUICK_LAUNCH_RELEASE.chainId) {
    errors.push(`RPC chain id must be ${QUICK_LAUNCH_RELEASE.chainId}; received ${probe.chainId}.`);
  }
  if (!isDeployed(QUICK_LAUNCH_CHAIN) || !isPredicateDeployed(QUICK_LAUNCH_CHAIN)) {
    errors.push("The checked-in Base Sepolia PoH and PredicateVerifier pair must both be non-zero.");
  }
  if (getAddress(probe.pohAddress) !== QUICK_LAUNCH_RELEASE.proofOfHumanity) {
    errors.push("Configured ProofOfHumanity address does not match the reviewed Base Sepolia deployment.");
  }
  if (getAddress(probe.predicateAddress) !== QUICK_LAUNCH_RELEASE.predicateVerifier) {
    errors.push("Configured PredicateVerifier address does not match the reviewed Base Sepolia deployment.");
  }
  if (probe.pohCode === "0x") errors.push("ProofOfHumanity has no deployed bytecode.");
  if (probe.predicateCode === "0x") errors.push("PredicateVerifier has no deployed bytecode.");
  if (getAddress(probe.pohOwner) !== QUICK_LAUNCH_RELEASE.expectedOwner) {
    errors.push("ProofOfHumanity owner does not match the reviewed Base Sepolia deployment.");
  }
  if (getAddress(probe.predicateOwner) !== QUICK_LAUNCH_RELEASE.expectedOwner) {
    errors.push("PredicateVerifier owner does not match the reviewed Base Sepolia deployment.");
  }
  if (getAddress(probe.pohIssuer) !== QUICK_LAUNCH_RELEASE.expectedIssuer) {
    errors.push("ProofOfHumanity issuer does not match the reviewed Base Sepolia deployment.");
  }
  if (getAddress(probe.predicateIssuer) !== QUICK_LAUNCH_RELEASE.expectedIssuer) {
    errors.push("PredicateVerifier issuer does not match the reviewed Base Sepolia deployment.");
  }
  if (getAddress(probe.pohIssuer) !== getAddress(probe.predicateIssuer)) {
    errors.push("ProofOfHumanity and PredicateVerifier do not share the same issuer.");
  }
  if (getAddress(probe.predicateProver) !== ZERO_ADDRESS) {
    errors.push("PredicateVerifier prover must remain zero for the v1 Quick Launch.");
  }
  if (probe.selfEnvironment !== "staging" && probe.selfEnvironment !== "production") {
    errors.push("NEXT_PUBLIC_SELF_ENV must be exactly staging or production.");
  }
  validateSelfEndpoint(probe.selfEndpoint, errors);
  return { ready: errors.length === 0, errors };
}
