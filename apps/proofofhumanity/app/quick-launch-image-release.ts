import { createHash } from "node:crypto";

export const QUICK_LAUNCH_IMAGE_SCHEMA =
  "org.proofofhumanity.quick-launch.image-provenance/1" as const;
export const QUICK_LAUNCH_SOURCE_BINDING_SCHEMA =
  "org.proofofhumanity.quick-launch.source-image-binding/1" as const;
export const QUICK_LAUNCH_PUBLISHER_ROLE_SCHEMA =
  "org.proofofhumanity.quick-launch.image-publisher-role/1" as const;
export const QUICK_LAUNCH_SOURCE_REPOSITORY = "https://github.com/DemocracyEarth/ubi2" as const;
export const QUICK_LAUNCH_AWS_REGION = "us-east-1" as const;
export const QUICK_LAUNCH_ECR_REPOSITORY = "proof-of-humanity" as const;
export const QUICK_LAUNCH_IMAGE_PLATFORM = "linux/amd64" as const;
export const QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE =
  "PoHQuickLaunchImagePublisherRole" as const;
export const QUICK_LAUNCH_IMAGE_PUBLISHER_POLICY =
  "PoHQuickLaunchImagePublisher" as const;
export const QUICK_LAUNCH_NODE_BUILDER_IMAGE =
  "docker.io/library/node:22-bookworm-slim@sha256:4d676821dff059fd00d277ee4261ef34ea712317fed0737c03941481b5760c96" as const;
export const QUICK_LAUNCH_NODE_RUNTIME_IMAGE =
  "gcr.io/distroless/nodejs22-debian13:nonroot@sha256:9a052c12c6501f1248b682bf6d022276220cb2a65416d215e0973527394d1552" as const;

export const QUICK_LAUNCH_RUNTIME_ENV_KEYS = [
  "HOSTNAME",
  "NEXT_TELEMETRY_DISABLED",
  "NODE_ENV",
  "PATH",
  "PORT",
  "SSL_CERT_FILE",
] as const;

export const QUICK_LAUNCH_IMAGE_BLOCKERS = [
  "source-revision-invalid",
  "source-archive-sha256-invalid",
  "dockerfile-sha256-invalid",
  "dockerignore-sha256-invalid",
  "pnpmfile-sha256-invalid",
  "lockfile-sha256-invalid",
  "builder-image-not-pinned",
  "runtime-image-not-pinned",
  "platform-not-linux-amd64",
  "first-image-digest-invalid",
  "second-image-digest-invalid",
  "image-build-not-reproducible",
  "sbom-sha256-invalid",
  "scan-summary-sha256-invalid",
  "scanner-version-invalid",
  "critical-findings-invalid",
  "high-findings-invalid",
  "critical-findings-present",
  "high-findings-present",
  "runtime-environment-not-allowlisted",
  "image-publication-observed",
] as const;

export type QuickLaunchImageBlocker = (typeof QUICK_LAUNCH_IMAGE_BLOCKERS)[number];

export interface QuickLaunchImageProvenanceInput {
  sourceRevision?: string;
  sourceArchiveSha256?: string;
  dockerfileSha256?: string;
  dockerignoreSha256?: string;
  pnpmfileSha256?: string;
  lockfileSha256?: string;
  builderImage?: string;
  runtimeImage?: string;
  platform?: string;
  firstImageDigest?: string;
  secondImageDigest?: string;
  sbomSha256?: string;
  scanSummarySha256?: string;
  scannerVersion?: string;
  criticalFindings?: number;
  highFindings?: number;
  runtimeEnvironmentKeys?: string[];
  imagePublished?: boolean;
}

type CanonicalJson =
  | null
  | boolean
  | number
  | string
  | CanonicalJson[]
  | { [key: string]: CanonicalJson };

const ACCOUNT_ID = /^[0-9]{12}$/u;
const SOURCE_REVISION = /^[0-9a-f]{40}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const OCI_DIGEST = /^sha256:[0-9a-f]{64}$/u;
const SCANNER_VERSION = /^[0-9A-Za-z][0-9A-Za-z.+_-]{0,63}$/u;

function canonicalize(value: CanonicalJson): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalize(value[key]!)}`)
    .join(",")}}`;
}

export function canonicalJson(value: CanonicalJson): string {
  return canonicalize(value);
}

export function canonicalSha256(value: CanonicalJson): string {
  return createHash("sha256").update(canonicalJson(value)).digest("hex");
}

export function buildQuickLaunchImagePublisherRoleDocuments(accountId: string) {
  if (!ACCOUNT_ID.test(accountId)) throw new Error("Quick Launch deployment account must be 12 digits.");

  const repositoryArn =
    `arn:aws:ecr:${QUICK_LAUNCH_AWS_REGION}:${accountId}:repository/${QUICK_LAUNCH_ECR_REPOSITORY}`;
  const publisherRoleArn =
    `arn:aws:iam::${accountId}:role/${QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE}`;
  const trustPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AllowQuickLaunchDeployer",
        Effect: "Allow",
        Principal: { AWS: `arn:aws:iam::${accountId}:root` },
        Action: "sts:AssumeRole",
        Condition: {
          ArnLike: {
            "aws:PrincipalArn":
              `arn:aws:iam::${accountId}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PoHQuickLaunchDeployer_*`,
          },
        },
      },
    ],
  } as const;
  const permissionsPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AuthorizeEcrInApprovedRegion",
        Effect: "Allow",
        Action: "ecr:GetAuthorizationToken",
        Resource: "*",
        Condition: { StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_AWS_REGION } },
      },
      {
        Sid: "PublishOnlyQuickLaunchImage",
        Effect: "Allow",
        Action: [
          "ecr:BatchCheckLayerAvailability",
          "ecr:CompleteLayerUpload",
          "ecr:InitiateLayerUpload",
          "ecr:PutImage",
          "ecr:UploadLayerPart",
        ],
        Resource: repositoryArn,
        Condition: { StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_AWS_REGION } },
      },
      {
        Sid: "VerifyOnlyQuickLaunchImage",
        Effect: "Allow",
        Action: [
          "ecr:BatchGetImage",
          "ecr:DescribeImageScanFindings",
          "ecr:DescribeImages",
          "ecr:DescribeRepositories",
          "ecr:ListImages",
          "ecr:ListTagsForResource",
        ],
        Resource: repositoryArn,
        Condition: { StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_AWS_REGION } },
      },
    ],
  } as const;
  const deployerAssumeRoleGrant = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AssumeQuickLaunchImagePublisher",
        Effect: "Allow",
        Action: "sts:AssumeRole",
        Resource: publisherRoleArn,
      },
    ],
  } as const;

  return {
    schema: QUICK_LAUNCH_PUBLISHER_ROLE_SCHEMA,
    roleName: QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE,
    inlinePolicyName: QUICK_LAUNCH_IMAGE_PUBLISHER_POLICY,
    maximumSessionDurationSeconds: 3600,
    trustPolicy,
    permissionsPolicy,
    deployerAssumeRoleGrant,
    trustPolicySha256: canonicalSha256(trustPolicy as unknown as CanonicalJson),
    permissionsPolicySha256: canonicalSha256(permissionsPolicy as unknown as CanonicalJson),
    deployerAssumeRoleGrantSha256: canonicalSha256(
      deployerAssumeRoleGrant as unknown as CanonicalJson,
    ),
  };
}

function validCount(value: number | undefined): value is number {
  return Number.isSafeInteger(value) && value !== undefined && value >= 0;
}

function sortedUnique(values: string[] | undefined): string[] {
  return [...new Set(values ?? [])].sort();
}

export function assessQuickLaunchImageProvenance(input: QuickLaunchImageProvenanceInput) {
  const blockers: QuickLaunchImageBlocker[] = [];
  const validHash = (value: string | undefined, blocker: QuickLaunchImageBlocker): string | null => {
    if (!value || !SHA256.test(value)) {
      blockers.push(blocker);
      return null;
    }
    return value;
  };
  const validDigest = (value: string | undefined, blocker: QuickLaunchImageBlocker): string | null => {
    if (!value || !OCI_DIGEST.test(value)) {
      blockers.push(blocker);
      return null;
    }
    return value;
  };

  const sourceRevision = SOURCE_REVISION.test(input.sourceRevision ?? "")
    ? input.sourceRevision!
    : null;
  if (!sourceRevision) blockers.push("source-revision-invalid");
  const sourceArchiveSha256 = validHash(
    input.sourceArchiveSha256,
    "source-archive-sha256-invalid",
  );
  const dockerfileSha256 = validHash(input.dockerfileSha256, "dockerfile-sha256-invalid");
  const dockerignoreSha256 = validHash(input.dockerignoreSha256, "dockerignore-sha256-invalid");
  const pnpmfileSha256 = validHash(input.pnpmfileSha256, "pnpmfile-sha256-invalid");
  const lockfileSha256 = validHash(input.lockfileSha256, "lockfile-sha256-invalid");
  const sbomSha256 = validHash(input.sbomSha256, "sbom-sha256-invalid");
  const scanSummarySha256 = validHash(input.scanSummarySha256, "scan-summary-sha256-invalid");
  const firstImageDigest = validDigest(input.firstImageDigest, "first-image-digest-invalid");
  const secondImageDigest = validDigest(input.secondImageDigest, "second-image-digest-invalid");

  const builderImagePinned = input.builderImage === QUICK_LAUNCH_NODE_BUILDER_IMAGE;
  if (!builderImagePinned) blockers.push("builder-image-not-pinned");
  const runtimeImagePinned = input.runtimeImage === QUICK_LAUNCH_NODE_RUNTIME_IMAGE;
  if (!runtimeImagePinned) blockers.push("runtime-image-not-pinned");
  const platformValid = input.platform === QUICK_LAUNCH_IMAGE_PLATFORM;
  if (!platformValid) blockers.push("platform-not-linux-amd64");
  const reproducible = Boolean(
    firstImageDigest && secondImageDigest && firstImageDigest === secondImageDigest,
  );
  if (!reproducible) blockers.push("image-build-not-reproducible");

  const scannerVersion = SCANNER_VERSION.test(input.scannerVersion ?? "")
    ? input.scannerVersion!
    : null;
  if (!scannerVersion) blockers.push("scanner-version-invalid");
  const criticalFindings = validCount(input.criticalFindings) ? input.criticalFindings : null;
  const highFindings = validCount(input.highFindings) ? input.highFindings : null;
  if (criticalFindings === null) blockers.push("critical-findings-invalid");
  else if (criticalFindings > 0) blockers.push("critical-findings-present");
  if (highFindings === null) blockers.push("high-findings-invalid");
  else if (highFindings > 0) blockers.push("high-findings-present");

  const runtimeEnvironmentKeys = sortedUnique(input.runtimeEnvironmentKeys);
  const runtimeEnvironmentAllowlisted =
    JSON.stringify(runtimeEnvironmentKeys) === JSON.stringify(QUICK_LAUNCH_RUNTIME_ENV_KEYS);
  if (!runtimeEnvironmentAllowlisted) blockers.push("runtime-environment-not-allowlisted");
  const unpublished = input.imagePublished === false;
  if (!unpublished) blockers.push("image-publication-observed");

  const sourceToImageBinding =
    sourceRevision &&
    sourceArchiveSha256 &&
    dockerfileSha256 &&
    dockerignoreSha256 &&
    pnpmfileSha256 &&
    lockfileSha256 &&
    firstImageDigest &&
    sbomSha256 &&
    scanSummarySha256
      ? {
          schema: QUICK_LAUNCH_SOURCE_BINDING_SCHEMA,
          source: {
            repository: QUICK_LAUNCH_SOURCE_REPOSITORY,
            revision: sourceRevision,
            archiveSha256: sourceArchiveSha256,
          },
          recipe: {
            dockerfileSha256,
            dockerignoreSha256,
            pnpmfileSha256,
            lockfileSha256,
            builderImage: builderImagePinned ? QUICK_LAUNCH_NODE_BUILDER_IMAGE : null,
            runtimeImage: runtimeImagePinned ? QUICK_LAUNCH_NODE_RUNTIME_IMAGE : null,
          },
          image: { platform: platformValid ? QUICK_LAUNCH_IMAGE_PLATFORM : null, digest: firstImageDigest },
          sbomSha256,
          scanSummarySha256,
        }
      : null;

  const uniqueBlockers = [...new Set(blockers)].sort();
  return {
    schema: QUICK_LAUNCH_IMAGE_SCHEMA,
    transactionFree: true,
    sourceToImageBinding,
    sourceToImageBindingSha256: sourceToImageBinding
      ? canonicalSha256(sourceToImageBinding as unknown as CanonicalJson)
      : null,
    reproducibility: {
      platform: platformValid ? QUICK_LAUNCH_IMAGE_PLATFORM : null,
      firstImageDigest,
      secondImageDigest,
      matched: reproducible,
      builderImagePinned,
      runtimeImagePinned,
    },
    scan: {
      scanner: "docker-scout",
      scannerVersion,
      criticalFindings,
      highFindings,
      passed: criticalFindings === 0 && highFindings === 0,
    },
    runtimeEnvironmentAllowlisted,
    imagePublished: input.imagePublished === true,
    readyForPublicationApproval: uniqueBlockers.length === 0,
    blockers: uniqueBlockers,
  };
}
