import {
  ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
  ZK_HOLDER_PROFILE_ID,
  type ZkHolderPrivateStatusRefreshPolicy,
  type ZkHolderStatusResolution,
} from "@ubi2/sdk";

const cohort = {
  chainId: "84532",
  issuanceRegistry: "0x1111111111111111111111111111111111111111",
  registryRuntimeCodehash: `0x${"22".repeat(32)}`,
  issuerKeyId: `0x${"33".repeat(32)}`,
  finalityRuleId: `0x${"44".repeat(32)}`,
  resolverConfigHash: `0x${"55".repeat(32)}`,
  reconcilerConfigHash: `0x${"66".repeat(32)}`,
  resolverSigners: [
    "0x7777777777777777777777777777777777777777",
    "0x8888888888888888888888888888888888888888",
  ],
  resolverThreshold: 2,
  reconcilerSigners: [
    "0x9999999999999999999999999999999999999999",
    "0xaAaAaAaaAaAaAaaAaAAAAAAAAaaaAaAaAaaAaaAa",
  ],
  reconcilerThreshold: 2,
} as const;

export const HARNESS_POLICY_PRODUCTION_APPROVED = false as const;

export const HARNESS_POLICY: ZkHolderPrivateStatusRefreshPolicy = {
  profileId: ZK_HOLDER_PROFILE_ID,
  parameterManifestSha256: ZK_HOLDER_PRODUCTION_PARAMETER_MANIFEST_SHA256,
  productionApproved: HARNESS_POLICY_PRODUCTION_APPROVED,
  cohorts: [cohort],
};

export const HARNESS_RESOLUTION: ZkHolderStatusResolution = {
  chainId: cohort.chainId,
  issuanceRegistry: cohort.issuanceRegistry,
  registryRuntimeCodehash: cohort.registryRuntimeCodehash,
  issuerKeyId: cohort.issuerKeyId,
  issuerActive: true,
  snapshotId: 1,
  snapshotHash: `0x${"ab".repeat(32)}`,
  snapshotContentSha256: "bc".repeat(32),
  attestationSetSha256: "cd".repeat(32),
  root: `0x${"01".repeat(32)}`,
  activatedThroughStatusId: 7,
  publishedAt: 1_700_000_000,
  revoked: false,
  accepted: true,
  observationBlockNumber: "1",
  observationBlockHash: `0x${"de".repeat(32)}`,
  observationBlockTimestamp: "1700000001",
  validUntil: "2000000000",
  finalityRuleId: cohort.finalityRuleId,
  resolverConfigHash: cohort.resolverConfigHash,
  reconcilerConfigHash: cohort.reconcilerConfigHash,
};
