export const QUICK_LAUNCH_AWS_REGION = "us-east-1" as const;
export const QUICK_LAUNCH_TASK_EXECUTION_ROLE_SCHEMA =
  "org.proofofhumanity.quick-launch.task-execution-role-preflight/1" as const;

export const QUICK_LAUNCH_TASK_EXECUTION_ROLE_BLOCKERS = [
  "deployment-account-invalid",
  "deployment-region-not-us-east-1",
  "task-execution-role-arn-invalid",
  "task-execution-role-not-regionless",
  "task-execution-role-account-mismatch",
  "container-image-uri-invalid",
  "container-image-account-mismatch",
  "container-image-region-mismatch",
  "issuer-secret-arn-invalid",
  "issuer-secret-account-mismatch",
  "issuer-secret-region-mismatch",
  "sponsor-secret-arn-invalid",
  "sponsor-secret-account-mismatch",
  "sponsor-secret-region-mismatch",
  "issuer-and-sponsor-secret-not-distinct",
  "issuer-kms-key-arn-invalid",
  "issuer-kms-key-account-mismatch",
  "issuer-kms-key-region-mismatch",
  "sponsor-kms-key-arn-invalid",
  "sponsor-kms-key-account-mismatch",
  "sponsor-kms-key-region-mismatch",
] as const;

export type QuickLaunchTaskExecutionRoleBlocker =
  (typeof QUICK_LAUNCH_TASK_EXECUTION_ROLE_BLOCKERS)[number];

export interface QuickLaunchTaskExecutionRoleInput {
  deploymentAccountId?: string;
  deploymentRegion?: string;
  taskExecutionRoleArn?: string;
  containerImageUri?: string;
  issuerSecretArn?: string;
  sponsorSecretArn?: string;
  issuerKmsKeyArn?: string;
  sponsorKmsKeyArn?: string;
}

interface RegionalArn {
  accountId: string;
  region: string;
}

interface RoleArn extends RegionalArn {
  regionless: boolean;
}

const ACCOUNT_ID = /^[0-9]{12}$/u;
const ROLE_ARN =
  /^arn:aws:iam:([^:]*):([0-9]{12}):role\/(?:[A-Za-z0-9+=,.@_-]+\/)*PoHQuickLaunchTaskExecutionRole$/u;
const IMAGE_URI =
  /^([0-9]{12})\.dkr\.ecr\.([a-z0-9-]+)\.amazonaws\.com\/[a-z0-9._/-]+@sha256:[0-9a-f]{64}$/u;
const SECRET_ARN = /^arn:aws:secretsmanager:([a-z0-9-]+):([0-9]{12}):secret:.+$/u;
const KMS_KEY_ARN =
  /^arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key\/[0-9a-f]{8}-[0-9a-f-]{27}$/u;

function parseRoleArn(value: string | undefined): RoleArn | null {
  const match = value?.trim().match(ROLE_ARN);
  return match
    ? {
        region: match[1] ?? "",
        accountId: match[2] ?? "",
        regionless: match[1] === "",
      }
    : null;
}

function parseImageUri(value: string | undefined): RegionalArn | null {
  const match = value?.trim().match(IMAGE_URI);
  return match ? { accountId: match[1] ?? "", region: match[2] ?? "" } : null;
}

function parseRegionalArn(value: string | undefined, pattern: RegExp): RegionalArn | null {
  const match = value?.trim().match(pattern);
  return match ? { region: match[1] ?? "", accountId: match[2] ?? "" } : null;
}

function assessRegionalBinding(
  parsed: RegionalArn | null,
  accountId: string | null,
  region: string | null,
  invalid: QuickLaunchTaskExecutionRoleBlocker,
  accountMismatch: QuickLaunchTaskExecutionRoleBlocker,
  regionMismatch: QuickLaunchTaskExecutionRoleBlocker,
  blockers: QuickLaunchTaskExecutionRoleBlocker[],
): { valid: boolean; accountMatches: boolean; regionMatches: boolean } {
  const valid = parsed !== null;
  const accountMatches = Boolean(parsed && accountId && parsed.accountId === accountId);
  const regionMatches = Boolean(parsed && region && parsed.region === region);
  if (!valid) blockers.push(invalid);
  else {
    if (!accountMatches) blockers.push(accountMismatch);
    if (!regionMatches) blockers.push(regionMismatch);
  }
  return { valid, accountMatches, regionMatches };
}

export function assessQuickLaunchTaskExecutionRole(
  input: QuickLaunchTaskExecutionRoleInput,
) {
  const blockers: QuickLaunchTaskExecutionRoleBlocker[] = [];
  const deploymentAccountId = input.deploymentAccountId?.trim() ?? "";
  const accountValid = ACCOUNT_ID.test(deploymentAccountId);
  const accountId = accountValid ? deploymentAccountId : null;
  if (!accountValid) blockers.push("deployment-account-invalid");

  const deploymentRegion = input.deploymentRegion?.trim() ?? "";
  const regionValid = deploymentRegion === QUICK_LAUNCH_AWS_REGION;
  const region = regionValid ? deploymentRegion : null;
  if (!regionValid) blockers.push("deployment-region-not-us-east-1");

  const role = parseRoleArn(input.taskExecutionRoleArn);
  const roleValid = role !== null;
  const roleRegionless = role?.regionless === true;
  const roleAccountMatches = Boolean(role && accountId && role.accountId === accountId);
  if (!roleValid) blockers.push("task-execution-role-arn-invalid");
  else {
    if (!roleRegionless) blockers.push("task-execution-role-not-regionless");
    if (!roleAccountMatches) blockers.push("task-execution-role-account-mismatch");
  }

  const containerImage = assessRegionalBinding(
    parseImageUri(input.containerImageUri),
    accountId,
    region,
    "container-image-uri-invalid",
    "container-image-account-mismatch",
    "container-image-region-mismatch",
    blockers,
  );
  const issuerSecret = assessRegionalBinding(
    parseRegionalArn(input.issuerSecretArn, SECRET_ARN),
    accountId,
    region,
    "issuer-secret-arn-invalid",
    "issuer-secret-account-mismatch",
    "issuer-secret-region-mismatch",
    blockers,
  );
  const sponsorSecret = assessRegionalBinding(
    parseRegionalArn(input.sponsorSecretArn, SECRET_ARN),
    accountId,
    region,
    "sponsor-secret-arn-invalid",
    "sponsor-secret-account-mismatch",
    "sponsor-secret-region-mismatch",
    blockers,
  );
  const secretsDistinct =
    Boolean(input.issuerSecretArn?.trim()) &&
    Boolean(input.sponsorSecretArn?.trim()) &&
    input.issuerSecretArn?.trim() !== input.sponsorSecretArn?.trim();
  if (!secretsDistinct) blockers.push("issuer-and-sponsor-secret-not-distinct");

  const assessOptionalKmsKey = (
    value: string | undefined,
    prefix: "issuer" | "sponsor",
  ) => {
    if (!value?.trim()) return { supplied: false, valid: true, accountMatches: true, regionMatches: true };
    const assessed = assessRegionalBinding(
      parseRegionalArn(value, KMS_KEY_ARN),
      accountId,
      region,
      `${prefix}-kms-key-arn-invalid`,
      `${prefix}-kms-key-account-mismatch`,
      `${prefix}-kms-key-region-mismatch`,
      blockers,
    );
    return { supplied: true, ...assessed };
  };
  const issuerKmsKey = assessOptionalKmsKey(input.issuerKmsKeyArn, "issuer");
  const sponsorKmsKey = assessOptionalKmsKey(input.sponsorKmsKeyArn, "sponsor");

  const uniqueBlockers = [...new Set(blockers)].sort();
  return {
    schema: QUICK_LAUNCH_TASK_EXECUTION_ROLE_SCHEMA,
    transactionFree: true,
    deploymentRegion: region,
    accountValid,
    role: {
      arnValid: roleValid,
      accountMatches: roleAccountMatches,
      regionless: roleRegionless,
    },
    resourceBindings: {
      containerImage,
      issuerSecret,
      sponsorSecret,
      secretsDistinct,
      issuerKmsKey,
      sponsorKmsKey,
    },
    ready: uniqueBlockers.length === 0,
    blockers: uniqueBlockers,
  };
}
