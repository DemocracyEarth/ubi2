import { canonicalSha256 } from "./quick-launch-image-release";

export const QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_SCHEMA =
  "org.proofofhumanity.quick-launch.infrastructure-administrator-package/1" as const;
export const QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_PERMISSION_SET =
  "PoHQuickLaunchInfrastructureAdministrator" as const;
export const QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_SESSION = "PT1H" as const;
export const QUICK_LAUNCH_TASK_EXECUTION_ROLE = "PoHQuickLaunchTaskExecutionRole" as const;
export const QUICK_LAUNCH_TASK_EXECUTION_POLICY = "PoHQuickLaunchTaskExecution" as const;
export const QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE =
  "PoHQuickLaunchCloudFormationDeploymentRole" as const;
export const QUICK_LAUNCH_ACCOUNT_ID = "368426158592" as const;
export const QUICK_LAUNCH_REGION = "us-east-1" as const;
export const QUICK_LAUNCH_API_HOSTNAME = "quick-launch-api.proofofhumanity.org" as const;
export const QUICK_LAUNCH_SOURCE_REVISION =
  "d7ec0cc57d6b004ba270b18cb54536a2556bdbc5" as const;
export const QUICK_LAUNCH_IMAGE_DIGEST =
  "sha256:c2179f20c8888c2fd9bd1fc771f7183bc12d358c379523f2036f2a034856d205" as const;

export const QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_TAGS = [
  { Key: "network", Value: "base-sepolia" },
  { Key: "purpose", Value: "infrastructure-administrator" },
  { Key: "release", Value: "poh-quick-launch-v1" },
] as const;

export const QUICK_LAUNCH_TASK_EXECUTION_ROLE_TAGS = [
  { Key: "network", Value: "base-sepolia" },
  { Key: "purpose", Value: "task-execution" },
  { Key: "release", Value: "poh-quick-launch-v1" },
] as const;

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface QuickLaunchInfrastructureAdministratorPackageInput {
  accountId?: string;
  identityCenterRegion?: string;
  instanceArn?: string;
  administratorPrincipalId?: string;
  issuerSecretArn?: string;
  sponsorSecretArn?: string;
  issuerKmsKeyArn?: string;
  sponsorKmsKeyArn?: string;
  vpcId?: string;
  subnetIds?: string[];
  subnetAvailabilityZones?: string[];
  hostedZoneId?: string;
  cloudFormationDeploymentRoleArn?: string;
}

const INSTANCE_ARN = /^arn:aws:sso:::instance\/(ssoins-[A-Za-z0-9.-]{16})$/u;
const PRINCIPAL_ID =
  /^(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$/u;
const SECRET_ARN = /^arn:aws:secretsmanager:([a-z0-9-]+):([0-9]{12}):secret:.+$/u;
const KMS_KEY_ARN =
  /^arn:aws:kms:([a-z0-9-]+):([0-9]{12}):key\/[0-9a-f]{8}-[0-9a-f-]{27}$/u;
const VPC_ID = /^vpc-[0-9a-f]{8,17}$/u;
const SUBNET_ID = /^subnet-[0-9a-f]{8,17}$/u;
const AVAILABILITY_ZONE = /^us-east-1[a-z]$/u;
const HOSTED_ZONE_ID = /^Z[A-Z0-9]{8,32}$/u;
const CLOUDFORMATION_ROLE_ARN =
  /^arn:aws:iam::([0-9]{12}):role\/(?:[A-Za-z0-9+=,.@_-]+\/)*PoHQuickLaunchCloudFormationDeploymentRole$/u;

function required(value: string | undefined, name: string): string {
  const normalized = value?.trim() ?? "";
  if (!normalized) throw new Error(`${name} is required.`);
  return normalized;
}

function rejectFobalNamedResource(value: string, name: string): string {
  if (/fobal/iu.test(value)) throw new Error(`${name} must not reference a Fobal resource.`);
  return value;
}

function requireRegionalArn(value: string, pattern: RegExp, name: string): string {
  const match = value.match(pattern);
  if (!match) throw new Error(`${name} ARN is invalid.`);
  if (match[1] !== QUICK_LAUNCH_REGION) throw new Error(`${name} must be in us-east-1.`);
  if (match[2] !== QUICK_LAUNCH_ACCOUNT_ID) {
    throw new Error(`${name} must belong to account ${QUICK_LAUNCH_ACCOUNT_ID}.`);
  }
  return value;
}

function tagsAsMap(tags: readonly { Key: string; Value: string }[]) {
  return Object.fromEntries(tags.map(({ Key, Value }) => [`aws:RequestTag/${Key}`, Value]));
}

function canonicalHash(value: unknown): string {
  return canonicalSha256(value as JsonValue);
}

export function buildQuickLaunchInfrastructureAdministratorPackage(
  input: QuickLaunchInfrastructureAdministratorPackageInput,
) {
  if (input.accountId !== QUICK_LAUNCH_ACCOUNT_ID) {
    throw new Error(`Quick Launch account must be exactly ${QUICK_LAUNCH_ACCOUNT_ID}.`);
  }
  if (input.identityCenterRegion !== QUICK_LAUNCH_REGION) {
    throw new Error(`IAM Identity Center region must be exactly ${QUICK_LAUNCH_REGION}.`);
  }

  const instanceArn = required(input.instanceArn, "IAM Identity Center instance ARN");
  if (!INSTANCE_ARN.test(instanceArn)) throw new Error("IAM Identity Center instance ARN is invalid.");
  const administratorPrincipalId = required(
    input.administratorPrincipalId,
    "Infrastructure administrator principal ID",
  );
  if (!PRINCIPAL_ID.test(administratorPrincipalId)) {
    throw new Error("Infrastructure administrator principal ID is invalid.");
  }

  const issuerSecretArn = rejectFobalNamedResource(
    requireRegionalArn(
      required(input.issuerSecretArn, "Issuer secret"),
      SECRET_ARN,
      "Issuer secret",
    ),
    "Issuer secret",
  );
  const sponsorSecretArn = rejectFobalNamedResource(
    requireRegionalArn(
      required(input.sponsorSecretArn, "Sponsor secret"),
      SECRET_ARN,
      "Sponsor secret",
    ),
    "Sponsor secret",
  );
  if (issuerSecretArn === sponsorSecretArn) {
    throw new Error("Issuer and sponsor secret references must be distinct.");
  }

  const issuerKmsKeyArn = input.issuerKmsKeyArn?.trim()
    ? requireRegionalArn(input.issuerKmsKeyArn.trim(), KMS_KEY_ARN, "Issuer KMS key")
    : null;
  const sponsorKmsKeyArn = input.sponsorKmsKeyArn?.trim()
    ? requireRegionalArn(input.sponsorKmsKeyArn.trim(), KMS_KEY_ARN, "Sponsor KMS key")
    : null;
  const kmsKeyArns = [...new Set([issuerKmsKeyArn, sponsorKmsKeyArn].filter(Boolean))] as string[];

  const vpcId = required(input.vpcId, "VPC ID");
  if (!VPC_ID.test(vpcId)) throw new Error("VPC ID is invalid.");
  const subnetIds = input.subnetIds?.map((value) => value.trim()) ?? [];
  if (subnetIds.length !== 2 || subnetIds.some((value) => !SUBNET_ID.test(value))) {
    throw new Error("Exactly two valid subnet IDs are required.");
  }
  if (new Set(subnetIds).size !== 2) throw new Error("Approved subnet IDs must be distinct.");
  const subnetAvailabilityZones = input.subnetAvailabilityZones?.map((value) => value.trim()) ?? [];
  if (
    subnetAvailabilityZones.length !== 2 ||
    subnetAvailabilityZones.some((value) => !AVAILABILITY_ZONE.test(value))
  ) {
    throw new Error("Exactly two us-east-1 subnet Availability Zones are required.");
  }
  if (new Set(subnetAvailabilityZones).size !== 2) {
    throw new Error("Approved subnets must be in distinct Availability Zones.");
  }

  const hostedZoneId = required(input.hostedZoneId, "Hosted zone ID");
  if (!HOSTED_ZONE_ID.test(hostedZoneId)) throw new Error("Hosted zone ID is invalid.");
  const cloudFormationDeploymentRoleArn = required(
    input.cloudFormationDeploymentRoleArn,
    "CloudFormation deployment role ARN",
  );
  const cloudFormationRoleMatch = cloudFormationDeploymentRoleArn.match(CLOUDFORMATION_ROLE_ARN);
  if (!cloudFormationRoleMatch) throw new Error("CloudFormation deployment role ARN is invalid.");
  if (cloudFormationRoleMatch[1] !== QUICK_LAUNCH_ACCOUNT_ID) {
    throw new Error("CloudFormation deployment role must belong to the Quick Launch account.");
  }

  const taskExecutionRoleArn =
    `arn:aws:iam::${QUICK_LAUNCH_ACCOUNT_ID}:role/${QUICK_LAUNCH_TASK_EXECUTION_ROLE}`;
  const ecrRepositoryArn =
    `arn:aws:ecr:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:repository/proof-of-humanity`;
  const containerImageUri =
    `${QUICK_LAUNCH_ACCOUNT_ID}.dkr.ecr.${QUICK_LAUNCH_REGION}.amazonaws.com/` +
    `proof-of-humanity@${QUICK_LAUNCH_IMAGE_DIGEST}`;
  const logStreamArn =
    `arn:aws:logs:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    "log-group:/ubi2/poh-quick-launch-api:log-stream:*";
  const hostedZoneArn = `arn:aws:route53:::hostedzone/${hostedZoneId}`;
  const certificateArnPattern =
    `arn:aws:acm:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:certificate/*`;
  const subnetArns = subnetIds.map(
    (subnetId) =>
      `arn:aws:ec2:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:subnet/${subnetId}`,
  );
  const regionCondition = { StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_REGION } };

  const issuerTags = [
    { Key: "purpose", Value: "issuer" },
    { Key: "release", Value: "poh-quick-launch-v1" },
  ] as const;
  const sponsorTags = [
    { Key: "purpose", Value: "sponsor" },
    { Key: "release", Value: "poh-quick-launch-v1" },
  ] as const;
  const subnetTags = [
    { Key: "network", Value: "base-sepolia" },
    { Key: "purpose", Value: "api-origin" },
    { Key: "release", Value: "poh-quick-launch-v1" },
  ] as const;
  const certificateTags = [
    { Key: "network", Value: "base-sepolia" },
    { Key: "purpose", Value: "api-origin-tls" },
    { Key: "release", Value: "poh-quick-launch-v1" },
  ] as const;

  const taskExecutionTrustPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AllowQuickLaunchEcsTasks",
        Effect: "Allow",
        Principal: { Service: "ecs-tasks.amazonaws.com" },
        Action: "sts:AssumeRole",
        Condition: {
          StringEquals: { "aws:SourceAccount": QUICK_LAUNCH_ACCOUNT_ID },
          ArnLike: {
            "aws:SourceArn":
              `arn:aws:ecs:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:*`,
          },
        },
      },
    ],
  } as const;

  const taskExecutionStatements: JsonValue[] = [
    {
      Sid: "AuthorizeOnlyUsEast1Ecr",
      Effect: "Allow",
      Action: "ecr:GetAuthorizationToken",
      Resource: "*",
      Condition: regionCondition,
    },
    {
      Sid: "PullOnlyApprovedQuickLaunchImage",
      Effect: "Allow",
      Action: [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
      ],
      Resource: ecrRepositoryArn,
      Condition: regionCondition,
    },
    {
      Sid: "WriteOnlyQuickLaunchTaskLogs",
      Effect: "Allow",
      Action: ["logs:CreateLogStream", "logs:PutLogEvents"],
      Resource: logStreamArn,
      Condition: regionCondition,
    },
    {
      Sid: "ReadOnlyApprovedQuickLaunchSigners",
      Effect: "Allow",
      Action: "secretsmanager:GetSecretValue",
      Resource: [issuerSecretArn, sponsorSecretArn],
      Condition: regionCondition,
    },
  ];
  if (kmsKeyArns.length > 0) {
    taskExecutionStatements.push({
      Sid: "DecryptOnlyApprovedQuickLaunchSignerKeys",
      Effect: "Allow",
      Action: "kms:Decrypt",
      Resource: kmsKeyArns,
      Condition: {
        StringEquals: {
          "aws:RequestedRegion": QUICK_LAUNCH_REGION,
          "kms:ViaService": `secretsmanager.${QUICK_LAUNCH_REGION}.amazonaws.com`,
        },
      },
    });
  }
  const taskExecutionPermissionsPolicy = {
    Version: "2012-10-17",
    Statement: taskExecutionStatements,
  } as const;

  const secretTagCondition = (tags: readonly { Key: string; Value: string }[]) => ({
    StringEquals: {
      ...tagsAsMap(tags),
      "aws:RequestedRegion": QUICK_LAUNCH_REGION,
    },
    "ForAllValues:StringEquals": { "aws:TagKeys": tags.map(({ Key }) => Key) },
  });
  const exactTagCondition = (tags: readonly { Key: string; Value: string }[]) => ({
    StringEquals: tagsAsMap(tags),
    "ForAllValues:StringEquals": { "aws:TagKeys": tags.map(({ Key }) => Key) },
  });

  const administratorStatements: JsonValue[] = [
    {
      Sid: "DiscoverOnlySecretMetadataInUsEast1",
      Effect: "Allow",
      Action: "secretsmanager:ListSecrets",
      Resource: "*",
      Condition: regionCondition,
    },
    {
      Sid: "InspectOnlyApprovedSignerSecretMetadata",
      Effect: "Allow",
      Action: ["secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds"],
      Resource: [issuerSecretArn, sponsorSecretArn],
      Condition: regionCondition,
    },
    {
      Sid: "TagOnlyApprovedIssuerSecret",
      Effect: "Allow",
      Action: "secretsmanager:TagResource",
      Resource: issuerSecretArn,
      Condition: secretTagCondition(issuerTags),
    },
    {
      Sid: "TagOnlyApprovedSponsorSecret",
      Effect: "Allow",
      Action: "secretsmanager:TagResource",
      Resource: sponsorSecretArn,
      Condition: secretTagCondition(sponsorTags),
    },
    {
      Sid: "DiscoverOnlyUsEast1NetworkMetadata",
      Effect: "Allow",
      Action: [
        "ec2:DescribeAvailabilityZones",
        "ec2:DescribeInternetGateways",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSubnets",
        "ec2:DescribeVpcs",
      ],
      Resource: "*",
      Condition: regionCondition,
    },
    {
      Sid: "TagOnlyTwoApprovedQuickLaunchSubnets",
      Effect: "Allow",
      Action: "ec2:CreateTags",
      Resource: subnetArns,
      Condition: {
        ...exactTagCondition(subnetTags),
        StringEquals: {
          ...exactTagCondition(subnetTags).StringEquals,
          "aws:RequestedRegion": QUICK_LAUNCH_REGION,
        },
      },
    },
    {
      Sid: "DiscoverOnlyUsEast1CertificateMetadata",
      Effect: "Allow",
      Action: "acm:ListCertificates",
      Resource: "*",
      Condition: regionCondition,
    },
    {
      Sid: "RequestOnlyTaggedQuickLaunchApiCertificate",
      Effect: "Allow",
      Action: "acm:RequestCertificate",
      Resource: "*",
      Condition: {
        StringEquals: {
          "aws:RequestedRegion": QUICK_LAUNCH_REGION,
          "aws:RequestTag/network": "base-sepolia",
          "aws:RequestTag/purpose": "api-origin-tls",
          "aws:RequestTag/release": "poh-quick-launch-v1",
          "acm:KeyAlgorithm": "RSA_2048",
          "acm:ValidationMethod": "DNS",
        },
        "ForAllValues:StringEquals": {
          "aws:TagKeys": ["network", "purpose", "release"],
          "acm:DomainNames": [QUICK_LAUNCH_API_HOSTNAME],
        },
      },
    },
    {
      Sid: "InspectOnlyTaggedQuickLaunchApiCertificate",
      Effect: "Allow",
      Action: ["acm:DescribeCertificate", "acm:ListTagsForCertificate"],
      Resource: certificateArnPattern,
      Condition: {
        StringEquals: {
          "aws:RequestedRegion": QUICK_LAUNCH_REGION,
          "aws:ResourceTag/network": "base-sepolia",
          "aws:ResourceTag/purpose": "api-origin-tls",
          "aws:ResourceTag/release": "poh-quick-launch-v1",
        },
      },
    },
    {
      Sid: "InspectOnlyQuickLaunchPublicHostedZone",
      Effect: "Allow",
      Action: ["route53:GetHostedZone", "route53:ListResourceRecordSets"],
      Resource: hostedZoneArn,
    },
    {
      Sid: "UpsertOnlyQuickLaunchCertificateValidationCname",
      Effect: "Allow",
      Action: "route53:ChangeResourceRecordSets",
      Resource: hostedZoneArn,
      Condition: {
        "ForAllValues:StringLike": {
          "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
            `_*.${QUICK_LAUNCH_API_HOSTNAME}`,
          ],
        },
        "ForAllValues:StringEquals": {
          "route53:ChangeResourceRecordSetsRecordTypes": ["CNAME"],
          "route53:ChangeResourceRecordSetsActions": ["UPSERT"],
        },
      },
    },
    {
      Sid: "CreateOnlyTaggedQuickLaunchTaskExecutionRole",
      Effect: "Allow",
      Action: ["iam:CreateRole", "iam:TagRole"],
      Resource: taskExecutionRoleArn,
      Condition: {
        ...exactTagCondition(QUICK_LAUNCH_TASK_EXECUTION_ROLE_TAGS),
        Null: { "iam:PermissionsBoundary": "true" },
      },
    },
    {
      Sid: "InspectOnlyQuickLaunchInfrastructureRoles",
      Effect: "Allow",
      Action: [
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListAttachedRolePolicies",
        "iam:ListRolePolicies",
        "iam:ListRoleTags",
      ],
      Resource: [taskExecutionRoleArn, cloudFormationDeploymentRoleArn],
    },
    {
      Sid: "ConfigureOnlyTaggedQuickLaunchTaskExecutionRole",
      Effect: "Allow",
      Action: "iam:PutRolePolicy",
      Resource: taskExecutionRoleArn,
      Condition: {
        StringEquals: {
          "aws:ResourceTag/network": "base-sepolia",
          "aws:ResourceTag/purpose": "task-execution",
          "aws:ResourceTag/release": "poh-quick-launch-v1",
        },
      },
    },
  ];
  if (kmsKeyArns.length > 0) {
    administratorStatements.splice(6, 0, {
      Sid: "InspectOnlyApprovedSignerKmsKeys",
      Effect: "Allow",
      Action: "kms:DescribeKey",
      Resource: kmsKeyArns,
      Condition: regionCondition,
    });
  }
  const administratorPermissionsPolicy = {
    Version: "2012-10-17",
    Statement: administratorStatements,
  } as const;

  const permissionSetConfiguration = {
    Name: QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_PERMISSION_SET,
    Description:
      "One-hour preparation of only the PoH Quick Launch Base Sepolia infrastructure prerequisites.",
    SessionDuration: QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_SESSION,
    Tags: QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_TAGS,
  } as const;
  const assignment = {
    InstanceArn: instanceArn,
    TargetId: QUICK_LAUNCH_ACCOUNT_ID,
    TargetType: "AWS_ACCOUNT",
    PermissionSetArnFrom: "CreatePermissionSet.PermissionSet.PermissionSetArn",
    PrincipalType: "USER",
    PrincipalId: administratorPrincipalId,
  } as const;

  const taskExecutionRoleCreationRequest = {
    RoleName: QUICK_LAUNCH_TASK_EXECUTION_ROLE,
    AssumeRolePolicyDocument: taskExecutionTrustPolicy,
    Description: "ECS agent execution role for the transaction-disabled Quick Launch API origin.",
    MaxSessionDuration: 3600,
    Tags: QUICK_LAUNCH_TASK_EXECUTION_ROLE_TAGS,
  } as const;
  const certificateRequest = {
    DomainName: QUICK_LAUNCH_API_HOSTNAME,
    ValidationMethod: "DNS",
    KeyAlgorithm: "RSA_2048",
    IdempotencyToken: QUICK_LAUNCH_SOURCE_REVISION.slice(0, 32),
    Options: { CertificateTransparencyLoggingPreference: "ENABLED" },
    Tags: certificateTags,
  } as const;
  const requestPlan = {
    bootstrapWithExistingAdministrator: [
      {
        order: 1,
        api: "sso-admin:CreatePermissionSet",
        input: { InstanceArn: instanceArn, ...permissionSetConfiguration },
      },
      {
        order: 2,
        api: "sso-admin:PutInlinePolicyToPermissionSet",
        input: {
          InstanceArn: instanceArn,
          PermissionSetArnFrom: "step-1",
          InlinePolicy: administratorPermissionsPolicy,
        },
      },
      { order: 3, api: "sso-admin:CreateAccountAssignment", input: assignment },
      {
        order: 4,
        api: "sso-admin:DescribeAccountAssignmentCreationStatus",
        input: { InstanceArn: instanceArn, AccountAssignmentCreationRequestIdFrom: "step-3" },
        requiredStatus: "SUCCEEDED",
      },
    ],
    afterFreshAdministratorLogin: [
      {
        order: 1,
        api: "secretsmanager:ListSecrets/DescribeSecret",
        requiredAssertions: [
          "exactly one supplied issuer ARN and one distinct supplied sponsor ARN exist",
          "neither secret value is requested",
        ],
      },
      {
        order: 2,
        api: "secretsmanager:TagResource",
        inputs: [
          { SecretId: issuerSecretArn, Tags: issuerTags },
          { SecretId: sponsorSecretArn, Tags: sponsorTags },
        ],
      },
      {
        order: 3,
        api: "ec2:DescribeVpcs/DescribeSubnets/DescribeRouteTables/DescribeInternetGateways",
        requiredAssertions: [
          `both subnets belong to ${vpcId}`,
          "both subnets are public and in the supplied distinct Availability Zones",
        ],
      },
      {
        order: 4,
        api: "ec2:CreateTags",
        inputs: subnetIds.map((subnetId) => ({ Resources: [subnetId], Tags: subnetTags })),
      },
      {
        order: 5,
        api: "acm:ListCertificates/DescribeCertificate",
        requiredAssertions: [
          `use only a tagged issued certificate covering ${QUICK_LAUNCH_API_HOSTNAME}`,
          "otherwise continue to step 6",
        ],
      },
      { order: 6, api: "acm:RequestCertificate", input: certificateRequest, conditional: true },
      {
        order: 7,
        api: "route53:ChangeResourceRecordSets",
        input: {
          HostedZoneId: hostedZoneId,
          ChangeBatchFrom: "ACM.DomainValidationOptions[0].ResourceRecord",
          RequiredAction: "UPSERT",
          RequiredType: "CNAME",
          RequiredNormalizedNamePattern: `_*.${QUICK_LAUNCH_API_HOSTNAME}`,
        },
        conditional: true,
      },
      {
        order: 8,
        api: "iam:CreateRole",
        input: taskExecutionRoleCreationRequest,
      },
      {
        order: 9,
        api: "iam:PutRolePolicy",
        input: {
          RoleName: QUICK_LAUNCH_TASK_EXECUTION_ROLE,
          PolicyName: QUICK_LAUNCH_TASK_EXECUTION_POLICY,
          PolicyDocument: taskExecutionPermissionsPolicy,
        },
      },
      {
        order: 10,
        api: "iam:GetRole/GetRolePolicy/ListRolePolicies/ListAttachedRolePolicies/ListRoleTags",
        resources: [taskExecutionRoleArn, cloudFormationDeploymentRoleArn],
        requiredAssertions: [
          "task execution role matches the reviewed trust, policy, tags and hashes",
          "CloudFormation deployment role is inspected only and is not changed",
        ],
      },
    ],
  } as const;

  const issuerAttestation = {
    schema: "org.proofofhumanity.quick-launch.signer-metadata-attestation/1",
    purpose: "issuer",
    release: "poh-quick-launch-v1",
    secretReferenceSha256: canonicalHash(issuerSecretArn),
    kmsBinding: issuerKmsKeyArn
      ? { customerManaged: true, keyReferenceSha256: canonicalHash(issuerKmsKeyArn) }
      : { customerManaged: false, keyReferenceSha256: null },
  } as const;
  const sponsorAttestation = {
    schema: "org.proofofhumanity.quick-launch.signer-metadata-attestation/1",
    purpose: "sponsor",
    release: "poh-quick-launch-v1",
    secretReferenceSha256: canonicalHash(sponsorSecretArn),
    kmsBinding: sponsorKmsKeyArn
      ? { customerManaged: true, keyReferenceSha256: canonicalHash(sponsorKmsKeyArn) }
      : { customerManaged: false, keyReferenceSha256: null },
  } as const;
  const topologyAttestation = {
    schema: "org.proofofhumanity.quick-launch.infrastructure-topology-attestation/1",
    accountId: QUICK_LAUNCH_ACCOUNT_ID,
    region: QUICK_LAUNCH_REGION,
    network: "base-sepolia",
    sourceRevision: QUICK_LAUNCH_SOURCE_REVISION,
    imageDigest: QUICK_LAUNCH_IMAGE_DIGEST,
    apiHostname: QUICK_LAUNCH_API_HOSTNAME,
    vpcIdSha256: canonicalHash(vpcId),
    subnets: subnetIds.map((subnetId, index) => ({
      subnetIdSha256: canonicalHash(subnetId),
      availabilityZone: subnetAvailabilityZones[index]!,
    })),
    hostedZoneIdSha256: canonicalHash(hostedZoneId),
    taskExecutionRoleArnSha256: canonicalHash(taskExecutionRoleArn),
    cloudFormationDeploymentRoleArnSha256: canonicalHash(cloudFormationDeploymentRoleArn),
    desiredCount: 1,
    maximumPercent: 100,
    minimumHealthyPercent: 0,
    transactionsEnabled: false,
  } as const;

  const packageBinding = {
    schema: QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_SCHEMA,
    accountId: QUICK_LAUNCH_ACCOUNT_ID,
    region: QUICK_LAUNCH_REGION,
    instanceArn,
    administratorPrincipalId,
    sourceRevision: QUICK_LAUNCH_SOURCE_REVISION,
    imageDigest: QUICK_LAUNCH_IMAGE_DIGEST,
    permissionSetConfigurationSha256: canonicalHash(permissionSetConfiguration),
    administratorPermissionsPolicySha256: canonicalHash(administratorPermissionsPolicy),
    assignmentSha256: canonicalHash(assignment),
    taskExecutionTrustPolicySha256: canonicalHash(taskExecutionTrustPolicy),
    taskExecutionPermissionsPolicySha256: canonicalHash(taskExecutionPermissionsPolicy),
    issuerAttestationSha256: canonicalHash(issuerAttestation),
    sponsorAttestationSha256: canonicalHash(sponsorAttestation),
    topologyAttestationSha256: canonicalHash(topologyAttestation),
    requestPlanSha256: canonicalHash(requestPlan),
  } as const;

  return {
    ...packageBinding,
    packageBindingSha256: canonicalHash(packageBinding),
    transactionFree: true,
    mutatesAws: false,
    applyAuthorized: false,
    pauseBeforeApply: true,
    residualAuthorizationLimits: [
      "secretsmanager:ListSecrets and EC2 Describe APIs require wildcard resources; they remain metadata-only and region-bound.",
      "IAM cannot bind iam:CreateRole or iam:PutRolePolicy to trust/policy bytes; action-time hash approval and canonical read-back are mandatory.",
      "ACM certificate ARNs are generated server-side; inspection is limited to account/region certificates carrying all three fixed resource tags.",
      "Route 53 exposes no condition for the DNS record value; action-time comparison to ACM's returned CNAME and read-back are mandatory.",
    ],
    permissionSetConfiguration,
    administratorPermissionsPolicy,
    assignment,
    approvedBindings: {
      vpcId,
      subnetIds,
      subnetAvailabilityZones,
      hostedZoneId,
      issuerSecretArn,
      sponsorSecretArn,
      issuerKmsKeyArn,
      sponsorKmsKeyArn,
      containerImageUri,
      cloudFormationDeploymentRoleArn,
    },
    taskExecutionRole: {
      arn: taskExecutionRoleArn,
      creationRequest: taskExecutionRoleCreationRequest,
      inlinePolicyName: QUICK_LAUNCH_TASK_EXECUTION_POLICY,
      trustPolicy: taskExecutionTrustPolicy,
      permissionsPolicy: taskExecutionPermissionsPolicy,
    },
    attestations: {
      issuer: issuerAttestation,
      sponsor: sponsorAttestation,
      topology: topologyAttestation,
    },
    certificateRequest,
    requestPlan,
  };
}
