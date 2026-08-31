import { getAddress, isAddress, zeroAddress, type Address } from "viem";
import { QUICK_LAUNCH_RELEASE } from "./quick-launch";

export const QUICK_LAUNCH_HOST_READINESS_SCHEMA =
  "org.proofofhumanity.quick-launch.host-readiness/1" as const;

export const QUICK_LAUNCH_HOST_BLOCKERS = [
  "source-revision-unavailable",
  "self-endpoint-mismatch",
  "self-environment-not-staging",
  "single-sticky-node-not-declared",
  "topology-attestation-missing",
  "issuer-secret-attestation-missing",
  "issuer-key-unavailable",
  "issuer-address-mismatch",
  "sponsor-secret-attestation-missing",
  "sponsor-key-unavailable",
  "sponsor-policy-invalid",
  "sponsor-role-overlap",
] as const;

export type QuickLaunchHostBlocker = (typeof QUICK_LAUNCH_HOST_BLOCKERS)[number];

export interface QuickLaunchHostPublicProbe {
  sourceRevision: string | null;
  selfEndpoint: string | null;
  selfEnvironment: string | null;
  singleStickyNodeDeclared: boolean;
  topologyAttestationSha256: string | null;
  issuerSecretAttestationSha256: string | null;
  issuerAddress: Address | null;
  sponsorSecretAttestationSha256: string | null;
  sponsorAddress: Address | null;
  sponsorEnabledChainIds: readonly number[];
  sponsorPolicyValid: boolean;
}

export interface QuickLaunchHostAssessment {
  ready: boolean;
  blockers: QuickLaunchHostBlocker[];
}

const SHA256 = /^[0-9a-f]{64}$/u;
const REVISION = /^[0-9a-f]{40}$/u;

export function isSha256(value: string | null): value is string {
  return value !== null && SHA256.test(value);
}

export function isSourceRevision(value: string | null): value is string {
  return value !== null && REVISION.test(value);
}

/**
 * Assess only public, transaction-free host facts. Private keys and secret-manager references must
 * be reduced to public addresses and immutable evidence digests before reaching this boundary.
 */
export function assessQuickLaunchHostProbe(
  probe: QuickLaunchHostPublicProbe,
  expected: {
    issuer: Address;
    owner: Address;
    selfEndpoint: string;
  } = {
    issuer: QUICK_LAUNCH_RELEASE.expectedIssuer,
    owner: QUICK_LAUNCH_RELEASE.expectedOwner,
    selfEndpoint: QUICK_LAUNCH_RELEASE.canonicalSelfEndpoint,
  },
): QuickLaunchHostAssessment {
  const blockers: QuickLaunchHostBlocker[] = [];

  if (!isSourceRevision(probe.sourceRevision)) blockers.push("source-revision-unavailable");
  if (probe.selfEndpoint !== expected.selfEndpoint) blockers.push("self-endpoint-mismatch");
  if (probe.selfEnvironment !== "staging") blockers.push("self-environment-not-staging");
  if (!probe.singleStickyNodeDeclared) blockers.push("single-sticky-node-not-declared");
  if (!isSha256(probe.topologyAttestationSha256)) blockers.push("topology-attestation-missing");
  if (!isSha256(probe.issuerSecretAttestationSha256)) blockers.push("issuer-secret-attestation-missing");

  if (!probe.issuerAddress || !isAddress(probe.issuerAddress)) {
    blockers.push("issuer-key-unavailable");
  } else if (getAddress(probe.issuerAddress) !== getAddress(expected.issuer)) {
    blockers.push("issuer-address-mismatch");
  }

  if (!isSha256(probe.sponsorSecretAttestationSha256)) blockers.push("sponsor-secret-attestation-missing");
  if (!probe.sponsorAddress || !isAddress(probe.sponsorAddress)) {
    blockers.push("sponsor-key-unavailable");
  }
  if (
    !probe.sponsorPolicyValid ||
    probe.sponsorEnabledChainIds.length !== 1 ||
    probe.sponsorEnabledChainIds[0] !== QUICK_LAUNCH_RELEASE.chainId
  ) {
    blockers.push("sponsor-policy-invalid");
  }
  if (
    probe.sponsorAddress &&
    isAddress(probe.sponsorAddress) &&
    ([zeroAddress, expected.issuer, expected.owner] as Address[]).some(
      (address) => getAddress(address) === getAddress(probe.sponsorAddress!),
    )
  ) {
    blockers.push("sponsor-role-overlap");
  }

  return { ready: blockers.length === 0, blockers };
}
