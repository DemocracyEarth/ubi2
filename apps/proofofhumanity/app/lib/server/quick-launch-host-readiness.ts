import "server-only";

import { getAddress, type Address, type Hex } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import {
  QUICK_LAUNCH_HOST_READINESS_SCHEMA,
  assessQuickLaunchHostProbe,
  isSha256,
  isSourceRevision,
  type QuickLaunchHostPublicProbe,
} from "../../quick-launch-host";
import { QUICK_LAUNCH_RELEASE } from "../../quick-launch";
import { getSponsoredMintServerConfig } from "../../server-config";

function digest(value: string | undefined): string | null {
  const normalized = value?.trim().toLowerCase() ?? null;
  return isSha256(normalized) ? normalized : null;
}

function revision(env: NodeJS.ProcessEnv): string | null {
  const candidate = (
    env.POH_SOURCE_REVISION ??
    env.AWS_COMMIT_ID ??
    env.VERCEL_GIT_COMMIT_SHA ??
    env.GITHUB_SHA ??
    ""
  )
    .trim()
    .toLowerCase();
  return isSourceRevision(candidate) ? candidate : null;
}

function publicAddress(privateKey: string | undefined): Address | null {
  const candidate = privateKey?.trim();
  if (!candidate || !/^0x[0-9a-fA-F]{64}$/u.test(candidate) || BigInt(candidate) === 0n) return null;
  try {
    return getAddress(privateKeyToAccount(candidate as Hex).address);
  } catch {
    return null;
  }
}

export function quickLaunchHostReadiness(
  env: NodeJS.ProcessEnv = process.env,
  expected: {
    issuer: Address;
    owner: Address;
    selfEndpoint: string;
  } = {
    issuer: QUICK_LAUNCH_RELEASE.expectedIssuer,
    owner: QUICK_LAUNCH_RELEASE.expectedOwner,
    selfEndpoint: QUICK_LAUNCH_RELEASE.canonicalSelfEndpoint,
  },
) {
  let sponsorAddress: Address | null = null;
  let sponsorEnabledChainIds: readonly number[] = [];
  let sponsorPolicyValid = false;
  try {
    const sponsor = getSponsoredMintServerConfig(env);
    if (sponsor) {
      sponsorAddress = publicAddress(sponsor.privateKey);
      sponsorEnabledChainIds = sponsor.enabledChainIds;
      sponsorPolicyValid = true;
    }
  } catch {
    // The public record reports only a fail-closed policy bit, never raw configuration errors.
  }

  const endpoint = env.NEXT_PUBLIC_SELF_ENDPOINT?.trim();
  const selfEnvironment = env.NEXT_PUBLIC_SELF_ENV?.trim();
  const probe: QuickLaunchHostPublicProbe = {
    sourceRevision: revision(env),
    selfEndpoint: endpoint === expected.selfEndpoint ? endpoint : null,
    selfEnvironment:
      selfEnvironment === "staging" || selfEnvironment === "production" ? selfEnvironment : null,
    singleStickyNodeDeclared: env.POH_RUNTIME_TOPOLOGY?.trim() === "single-sticky-node",
    topologyAttestationSha256: digest(env.POH_TOPOLOGY_ATTESTATION_SHA256),
    issuerSecretAttestationSha256: digest(env.POH_ISSUER_SECRET_ATTESTATION_SHA256),
    issuerAddress: publicAddress(env.ISSUER_PRIVATE_KEY),
    sponsorSecretAttestationSha256: digest(env.POH_SPONSOR_SECRET_ATTESTATION_SHA256),
    sponsorAddress,
    sponsorEnabledChainIds,
    sponsorPolicyValid,
  };
  const assessment = assessQuickLaunchHostProbe(probe, expected);

  return {
    schema: QUICK_LAUNCH_HOST_READINESS_SCHEMA,
    release: QUICK_LAUNCH_RELEASE.id,
    transactionFree: true as const,
    chainId: QUICK_LAUNCH_RELEASE.chainId,
    canonicalOrigin: QUICK_LAUNCH_RELEASE.canonicalOrigin,
    ...probe,
    ...assessment,
  };
}
