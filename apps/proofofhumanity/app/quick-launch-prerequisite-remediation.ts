import { canonicalSha256 } from "./quick-launch-image-release";

export const QUICK_LAUNCH_PREREQUISITE_REMEDIATION_SCHEMA =
  "org.proofofhumanity.quick-launch.prerequisite-remediation-package/1" as const;
export const QUICK_LAUNCH_PREREQUISITE_PERMISSION_SET =
  "PoHQuickLaunchPrerequisiteAdministrator" as const;
export const QUICK_LAUNCH_PREREQUISITE_SESSION = "PT1H" as const;
export const QUICK_LAUNCH_ACCOUNT_ID = "368426158592" as const;
export const QUICK_LAUNCH_REGION = "us-east-1" as const;
export const QUICK_LAUNCH_STACK_NAME = "poh-quick-launch-api" as const;
export const QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE =
  "PoHQuickLaunchCloudFormationDeploymentRole" as const;
export const QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_POLICY =
  "PoHQuickLaunchCloudFormationDeployment" as const;
export const QUICK_LAUNCH_TASK_EXECUTION_ROLE = "PoHQuickLaunchTaskExecutionRole" as const;
export const QUICK_LAUNCH_ISSUER_SECRET_NAME =
  "/ubi2/poh-quick-launch-v1/issuer-private-key" as const;
export const QUICK_LAUNCH_SPONSOR_SECRET_NAME =
  "/ubi2/poh-quick-launch-v1/sponsor-private-key" as const;

const RELEASE_TAGS = [
  { Key: "network", Value: "base-sepolia" },
  { Key: "release", Value: "poh-quick-launch-v1" },
] as const;

export const QUICK_LAUNCH_PREREQUISITE_ADMINISTRATOR_TAGS = [
  ...RELEASE_TAGS,
  { Key: "purpose", Value: "prerequisite-administrator" },
] as const;

export const QUICK_LAUNCH_CLOUDFORMATION_ROLE_TAGS = [
  ...RELEASE_TAGS,
  { Key: "purpose", Value: "cloudformation-deployment" },
] as const;

export const QUICK_LAUNCH_SUBNET_TAGS = [
  ...RELEASE_TAGS,
  { Key: "purpose", Value: "api-origin" },
] as const;

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface QuickLaunchPublicSubnetEvidence {
  subnetId?: string;
  availabilityZone?: string;
  vpcId?: string;
  routeTableId?: string;
  internetGatewayId?: string;
  mapPublicIpOnLaunch?: boolean;
  activeIpv4DefaultRoute?: boolean;
  fobalTagged?: boolean;
}

export interface QuickLaunchPrerequisiteRemediationInput {
  accountId?: string;
  identityCenterRegion?: string;
  instanceArn?: string;
  administratorPrincipalId?: string;
  vpcId?: string;
  hostedZoneId?: string;
  publicSubnets?: QuickLaunchPublicSubnetEvidence[];
}

const INSTANCE_ARN = /^arn:aws:sso:::instance\/(ssoins-[A-Za-z0-9.-]{16})$/u;
const PRINCIPAL_ID =
  /^(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$/u;
const VPC_ID = /^vpc-[0-9a-f]{8,17}$/u;
const SUBNET_ID = /^subnet-[0-9a-f]{8,17}$/u;
const ROUTE_TABLE_ID = /^rtb-[0-9a-f]{8,17}$/u;
const INTERNET_GATEWAY_ID = /^igw-[0-9a-f]{8,17}$/u;
const AVAILABILITY_ZONE = /^us-east-1[a-z]$/u;
const HOSTED_ZONE_ID = /^Z[A-Z0-9]{8,32}$/u;

function canonicalHash(value: unknown): string {
  return canonicalSha256(value as JsonValue);
}

function required(value: string | undefined, name: string): string {
  const normalized = value?.trim() ?? "";
  if (!normalized) throw new Error(`${name} is required.`);
  return normalized;
}

function requirePattern(value: string | undefined, pattern: RegExp, name: string): string {
  const normalized = required(value, name);
  if (!pattern.test(normalized)) throw new Error(`${name} is invalid.`);
  return normalized;
}

function rejectFobal(value: string, name: string): string {
  if (/fobal/iu.test(value)) throw new Error(`${name} must not reference a Fobal resource.`);
  return value;
}

function requestTagCondition(tags: readonly { Key: string; Value: string }[]) {
  return {
    StringEquals: Object.fromEntries(
      tags.map(({ Key, Value }) => [`aws:RequestTag/${Key}`, Value]),
    ),
    "ForAllValues:StringEquals": { "aws:TagKeys": tags.map(({ Key }) => Key) },
  };
}

function resourceTagCondition(tags: readonly { Key: string; Value: string }[]) {
  return {
    StringEquals: Object.fromEntries(
      tags.map(({ Key, Value }) => [`aws:ResourceTag/${Key}`, Value]),
    ),
  };
}

export function buildQuickLaunchPrerequisiteRemediationPackage(
  input: QuickLaunchPrerequisiteRemediationInput,
) {
  if (input.accountId !== QUICK_LAUNCH_ACCOUNT_ID) {
    throw new Error(`Quick Launch account must be exactly ${QUICK_LAUNCH_ACCOUNT_ID}.`);
  }
  if (input.identityCenterRegion !== QUICK_LAUNCH_REGION) {
    throw new Error(`IAM Identity Center region must be exactly ${QUICK_LAUNCH_REGION}.`);
  }

  const instanceArn = requirePattern(
    input.instanceArn,
    INSTANCE_ARN,
    "IAM Identity Center instance ARN",
  );
  const administratorPrincipalId = requirePattern(
    input.administratorPrincipalId,
    PRINCIPAL_ID,
    "Prerequisite administrator principal ID",
  );
  const vpcId = rejectFobal(requirePattern(input.vpcId, VPC_ID, "VPC ID"), "VPC ID");
  const hostedZoneId = rejectFobal(
    requirePattern(input.hostedZoneId, HOSTED_ZONE_ID, "Hosted zone ID"),
    "Hosted zone ID",
  );

  const suppliedSubnets = input.publicSubnets ?? [];
  if (suppliedSubnets.length !== 2) {
    throw new Error("Exactly two public subnet evidence records are required.");
  }
  const publicSubnets = suppliedSubnets.map((subnet, index) => {
    const label = `Public subnet ${index + 1}`;
    const subnetId = rejectFobal(
      requirePattern(subnet.subnetId, SUBNET_ID, `${label} ID`),
      `${label} ID`,
    );
    const availabilityZone = requirePattern(
      subnet.availabilityZone,
      AVAILABILITY_ZONE,
      `${label} Availability Zone`,
    );
    const subnetVpcId = requirePattern(subnet.vpcId, VPC_ID, `${label} VPC ID`);
    if (subnetVpcId !== vpcId) throw new Error(`${label} must belong to the approved VPC.`);
    const routeTableId = rejectFobal(
      requirePattern(subnet.routeTableId, ROUTE_TABLE_ID, `${label} route table ID`),
      `${label} route table ID`,
    );
    const internetGatewayId = rejectFobal(
      requirePattern(
        subnet.internetGatewayId,
        INTERNET_GATEWAY_ID,
        `${label} internet gateway ID`,
      ),
      `${label} internet gateway ID`,
    );
    if (subnet.mapPublicIpOnLaunch !== true) {
      throw new Error(`${label} must enable MapPublicIpOnLaunch.`);
    }
    if (subnet.activeIpv4DefaultRoute !== true) {
      throw new Error(`${label} must have an active 0.0.0.0/0 route to its internet gateway.`);
    }
    if (subnet.fobalTagged !== false) {
      throw new Error(`${label} must be explicitly verified as not Fobal-tagged.`);
    }
    return {
      subnetId,
      availabilityZone,
      vpcId: subnetVpcId,
      routeTableId,
      internetGatewayId,
      mapPublicIpOnLaunch: true,
      activeIpv4DefaultRoute: true,
      fobalTagged: false,
    } as const;
  });
  if (new Set(publicSubnets.map(({ subnetId }) => subnetId)).size !== 2) {
    throw new Error("Approved public subnet IDs must be distinct.");
  }
  if (new Set(publicSubnets.map(({ availabilityZone }) => availabilityZone)).size !== 2) {
    throw new Error("Approved public subnets must occupy distinct Availability Zones.");
  }

  const issuerSecretArnPattern =
    `arn:aws:secretsmanager:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    `secret:${QUICK_LAUNCH_ISSUER_SECRET_NAME}-*`;
  const sponsorSecretArnPattern =
    `arn:aws:secretsmanager:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    `secret:${QUICK_LAUNCH_SPONSOR_SECRET_NAME}-*`;
  const deploymentRoleArn =
    `arn:aws:iam::${QUICK_LAUNCH_ACCOUNT_ID}:role/${QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE}`;
  const taskExecutionRoleArn =
    `arn:aws:iam::${QUICK_LAUNCH_ACCOUNT_ID}:role/${QUICK_LAUNCH_TASK_EXECUTION_ROLE}`;
  const vpcArn =
    `arn:aws:ec2:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:vpc/${vpcId}`;
  const subnetArns = publicSubnets.map(
    ({ subnetId }) =>
      `arn:aws:ec2:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:subnet/${subnetId}`,
  );
  const hostedZoneArn = `arn:aws:route53:::hostedzone/${hostedZoneId}`;
  const regionCondition = { StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_REGION } };

  const secretTags = (purpose: "issuer" | "sponsor") => [
    ...RELEASE_TAGS,
    { Key: "purpose", Value: purpose },
  ] as const;
  const secretCreationRequest = (purpose: "issuer" | "sponsor") => ({
    Name:
      purpose === "issuer"
        ? QUICK_LAUNCH_ISSUER_SECRET_NAME
        : QUICK_LAUNCH_SPONSOR_SECRET_NAME,
    Description:
      purpose === "issuer"
        ? "Empty Quick Launch issuer signing-key container; value is entered separately through an AWS protected interface."
        : "Empty Quick Launch sponsor signing-key container; value is entered separately through an AWS protected interface.",
    Tags: secretTags(purpose),
  });
  const issuerSecretCreationRequest = secretCreationRequest("issuer");
  const sponsorSecretCreationRequest = secretCreationRequest("sponsor");

  const createSecretCondition = (purpose: "issuer" | "sponsor") => ({
    StringEquals: {
      ...requestTagCondition(secretTags(purpose)).StringEquals,
      "aws:RequestedRegion": QUICK_LAUNCH_REGION,
      "secretsmanager:Name":
        purpose === "issuer"
          ? QUICK_LAUNCH_ISSUER_SECRET_NAME
          : QUICK_LAUNCH_SPONSOR_SECRET_NAME,
    },
    "ForAllValues:StringEquals": requestTagCondition(secretTags(purpose))[
      "ForAllValues:StringEquals"
    ],
    Null: { "secretsmanager:KmsKeyArn": "true" },
  });

  const administratorPermissionsPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "CreateOnlyEmptyIssuerSecretContainer",
        Effect: "Allow",
        Action: "secretsmanager:CreateSecret",
        Resource: issuerSecretArnPattern,
        Condition: createSecretCondition("issuer"),
      },
      {
        Sid: "CreateOnlyEmptySponsorSecretContainer",
        Effect: "Allow",
        Action: "secretsmanager:CreateSecret",
        Resource: sponsorSecretArnPattern,
        Condition: createSecretCondition("sponsor"),
      },
      {
        Sid: "TagOnlyIssuerSecretContainer",
        Effect: "Allow",
        Action: "secretsmanager:TagResource",
        Resource: issuerSecretArnPattern,
        Condition: {
          StringEquals: {
            ...requestTagCondition(secretTags("issuer")).StringEquals,
            "aws:RequestedRegion": QUICK_LAUNCH_REGION,
          },
          "ForAllValues:StringEquals": requestTagCondition(secretTags("issuer"))[
            "ForAllValues:StringEquals"
          ],
        },
      },
      {
        Sid: "TagOnlySponsorSecretContainer",
        Effect: "Allow",
        Action: "secretsmanager:TagResource",
        Resource: sponsorSecretArnPattern,
        Condition: {
          StringEquals: {
            ...requestTagCondition(secretTags("sponsor")).StringEquals,
            "aws:RequestedRegion": QUICK_LAUNCH_REGION,
          },
          "ForAllValues:StringEquals": requestTagCondition(secretTags("sponsor"))[
            "ForAllValues:StringEquals"
          ],
        },
      },
      {
        Sid: "InspectOnlyQuickLaunchSecretContainers",
        Effect: "Allow",
        Action: ["secretsmanager:DescribeSecret", "secretsmanager:ListSecretVersionIds"],
        Resource: [issuerSecretArnPattern, sponsorSecretArnPattern],
        Condition: regionCondition,
      },
      {
        Sid: "InspectOnlyUsEast1PublicSubnetEvidence",
        Effect: "Allow",
        Action: [
          "ec2:DescribeInternetGateways",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
        ],
        Resource: "*",
        Condition: regionCondition,
      },
      {
        Sid: "ApproveOnlyTwoExactQuickLaunchSubnets",
        Effect: "Allow",
        Action: "ec2:CreateTags",
        Resource: subnetArns,
        Condition: {
          StringEquals: {
            ...requestTagCondition(QUICK_LAUNCH_SUBNET_TAGS).StringEquals,
            "aws:RequestedRegion": QUICK_LAUNCH_REGION,
          },
          "ForAllValues:StringEquals": requestTagCondition(QUICK_LAUNCH_SUBNET_TAGS)[
            "ForAllValues:StringEquals"
          ],
        },
      },
      {
        Sid: "CreateOnlyTaggedQuickLaunchCloudFormationDeploymentRole",
        Effect: "Allow",
        Action: ["iam:CreateRole", "iam:TagRole"],
        Resource: deploymentRoleArn,
        Condition: {
          ...requestTagCondition(QUICK_LAUNCH_CLOUDFORMATION_ROLE_TAGS),
          Null: { "iam:PermissionsBoundary": "true" },
        },
      },
      {
        Sid: "ConfigureOnlyTaggedQuickLaunchCloudFormationDeploymentRole",
        Effect: "Allow",
        Action: "iam:PutRolePolicy",
        Resource: deploymentRoleArn,
        Condition: resourceTagCondition(QUICK_LAUNCH_CLOUDFORMATION_ROLE_TAGS),
      },
      {
        Sid: "InspectOnlyQuickLaunchCloudFormationDeploymentRole",
        Effect: "Allow",
        Action: [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:ListRoleTags",
        ],
        Resource: deploymentRoleArn,
      },
    ],
  } as const;

  const deploymentRoleTrustPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "AllowOnlyQuickLaunchCloudFormationStack",
        Effect: "Allow",
        Principal: { Service: "cloudformation.amazonaws.com" },
        Action: "sts:AssumeRole",
        Condition: {
          StringEquals: { "aws:SourceAccount": QUICK_LAUNCH_ACCOUNT_ID },
          ArnLike: {
            "aws:SourceArn":
              `arn:aws:cloudformation:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
              `stack/${QUICK_LAUNCH_STACK_NAME}/*`,
          },
        },
      },
    ],
  } as const;

  const clusterArn =
    `arn:aws:ecs:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:cluster/poh-quick-launch-api`;
  const serviceArn =
    `arn:aws:ecs:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    "service/poh-quick-launch-api/poh-quick-launch-api";
  const taskDefinitionArn =
    `arn:aws:ecs:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    "task-definition/poh-quick-launch-api:*";
  const logGroupArn =
    `arn:aws:logs:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    "log-group:/ubi2/poh-quick-launch-api:*";
  const securityGroupArnPattern =
    `arn:aws:ec2:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:security-group/*`;
  const loadBalancerArn =
    `arn:aws:elasticloadbalancing:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    "loadbalancer/app/poh-quick-launch-api/*";
  const targetGroupArn =
    `arn:aws:elasticloadbalancing:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    "targetgroup/poh-quick-launch-api/*";
  const listenerArn =
    `arn:aws:elasticloadbalancing:${QUICK_LAUNCH_REGION}:${QUICK_LAUNCH_ACCOUNT_ID}:` +
    "listener/app/poh-quick-launch-api/*/*";
  const releaseRequestTag = {
    StringEquals: {
      "aws:RequestedRegion": QUICK_LAUNCH_REGION,
      "aws:RequestTag/release": "poh-quick-launch-v1",
    },
    "ForAllValues:StringEquals": { "aws:TagKeys": ["release"] },
  };
  const releaseResourceTag = {
    StringEquals: {
      "aws:RequestedRegion": QUICK_LAUNCH_REGION,
      "aws:ResourceTag/release": "poh-quick-launch-v1",
    },
  };

  const deploymentRolePermissionsPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "PassOnlyQuickLaunchTaskExecutionRoleToEcsTasks",
        Effect: "Allow",
        Action: "iam:PassRole",
        Resource: taskExecutionRoleArn,
        Condition: { StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" } },
      },
      {
        Sid: "InspectOnlyApprovedQuickLaunchNetwork",
        Effect: "Allow",
        Action: [
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcs",
        ],
        Resource: "*",
        Condition: regionCondition,
      },
      {
        Sid: "CreateOnlyQuickLaunchSecurityGroupsInApprovedVpc",
        Effect: "Allow",
        Action: "ec2:CreateSecurityGroup",
        Resource: [vpcArn, securityGroupArnPattern],
        Condition: regionCondition,
      },
      {
        Sid: "ManageOnlyTaggedQuickLaunchSecurityGroups",
        Effect: "Allow",
        Action: [
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:DeleteSecurityGroup",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
        ],
        Resource: securityGroupArnPattern,
        Condition: releaseResourceTag,
      },
      {
        Sid: "ManageOnlyQuickLaunchSecurityGroupTags",
        Effect: "Allow",
        Action: ["ec2:CreateTags", "ec2:DeleteTags"],
        Resource: securityGroupArnPattern,
        Condition: {
          StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_REGION },
          "ForAllValues:StringEquals": { "aws:TagKeys": ["release"] },
        },
      },
      {
        Sid: "InspectOnlyQuickLaunchLogGroup",
        Effect: "Allow",
        Action: "logs:DescribeLogGroups",
        Resource: "*",
        Condition: regionCondition,
      },
      {
        Sid: "ManageOnlyQuickLaunchLogGroup",
        Effect: "Allow",
        Action: [
          "logs:CreateLogGroup",
          "logs:DeleteLogGroup",
          "logs:DeleteRetentionPolicy",
          "logs:ListTagsForResource",
          "logs:PutRetentionPolicy",
          "logs:TagResource",
          "logs:UntagResource",
        ],
        Resource: logGroupArn,
        Condition: regionCondition,
      },
      {
        Sid: "ManageOnlyQuickLaunchEcsCluster",
        Effect: "Allow",
        Action: [
          "ecs:CreateCluster",
          "ecs:DeleteCluster",
          "ecs:DescribeClusters",
          "ecs:ListTagsForResource",
          "ecs:TagResource",
          "ecs:UntagResource",
          "ecs:UpdateClusterSettings",
        ],
        Resource: clusterArn,
        Condition: regionCondition,
      },
      {
        Sid: "RegisterOnlyTaggedQuickLaunchTaskDefinitionFamily",
        Effect: "Allow",
        Action: "ecs:RegisterTaskDefinition",
        Resource: taskDefinitionArn,
        Condition: {
          StringEquals: {
            "aws:RequestedRegion": QUICK_LAUNCH_REGION,
            "aws:RequestTag/release": "poh-quick-launch-v1",
            "aws:RequestTag/network": "base-sepolia",
          },
          "ForAllValues:StringEquals": { "aws:TagKeys": ["network", "release"] },
        },
      },
      {
        Sid: "ManageOnlyQuickLaunchTaskDefinitionFamily",
        Effect: "Allow",
        Action: [
          "ecs:DeregisterTaskDefinition",
          "ecs:ListTagsForResource",
          "ecs:TagResource",
          "ecs:UntagResource",
        ],
        Resource: taskDefinitionArn,
        Condition: regionCondition,
      },
      {
        Sid: "InspectOnlyQuickLaunchTaskDefinitionFamily",
        Effect: "Allow",
        Action: "ecs:DescribeTaskDefinition",
        Resource: "*",
        Condition: regionCondition,
      },
      {
        Sid: "ManageOnlyQuickLaunchEcsService",
        Effect: "Allow",
        Action: [
          "ecs:CreateService",
          "ecs:DeleteService",
          "ecs:DescribeServices",
          "ecs:ListTagsForResource",
          "ecs:TagResource",
          "ecs:UntagResource",
          "ecs:UpdateService",
        ],
        Resource: serviceArn,
        Condition: regionCondition,
      },
      {
        Sid: "InspectOnlyUsEast1ElasticLoadBalancingResources",
        Effect: "Allow",
        Action: [
          "elasticloadbalancing:DescribeListenerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeTags",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetHealth",
        ],
        Resource: "*",
        Condition: regionCondition,
      },
      {
        Sid: "CreateOnlyNamedQuickLaunchLoadBalancer",
        Effect: "Allow",
        Action: "elasticloadbalancing:CreateLoadBalancer",
        Resource: loadBalancerArn,
        Condition: {
          StringEquals: {
            "aws:RequestedRegion": QUICK_LAUNCH_REGION,
            "aws:RequestTag/release": "poh-quick-launch-v1",
            "elasticloadbalancing:Scheme": "internet-facing",
          },
          "ForAllValues:StringEquals": {
            "aws:TagKeys": ["release"],
            "elasticloadbalancing:Subnet": publicSubnets.map(({ subnetId }) => subnetId),
          },
        },
      },
      {
        Sid: "ManageOnlyNamedQuickLaunchLoadBalancer",
        Effect: "Allow",
        Action: [
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
        ],
        Resource: loadBalancerArn,
        Condition: regionCondition,
      },
      {
        Sid: "CreateOnlyNamedQuickLaunchTargetGroup",
        Effect: "Allow",
        Action: "elasticloadbalancing:CreateTargetGroup",
        Resource: targetGroupArn,
        Condition: releaseRequestTag,
      },
      {
        Sid: "ManageOnlyNamedQuickLaunchTargetGroup",
        Effect: "Allow",
        Action: [
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:RegisterTargets",
        ],
        Resource: targetGroupArn,
        Condition: regionCondition,
      },
      {
        Sid: "CreateOnlyQuickLaunchListeners",
        Effect: "Allow",
        Action: "elasticloadbalancing:CreateListener",
        Resource: listenerArn,
        Condition: {
          StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_REGION },
          "ForAllValues:StringEquals": {
            "elasticloadbalancing:ListenerProtocol": ["HTTP", "HTTPS"],
          },
        },
      },
      {
        Sid: "ManageOnlyQuickLaunchListeners",
        Effect: "Allow",
        Action: [
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:ModifyListenerAttributes",
        ],
        Resource: listenerArn,
        Condition: regionCondition,
      },
      {
        Sid: "TagOnlyQuickLaunchLoadBalancerResources",
        Effect: "Allow",
        Action: "elasticloadbalancing:AddTags",
        Resource: [loadBalancerArn, targetGroupArn],
        Condition: releaseRequestTag,
      },
      {
        Sid: "RemoveOnlyQuickLaunchReleaseTag",
        Effect: "Allow",
        Action: "elasticloadbalancing:RemoveTags",
        Resource: [loadBalancerArn, targetGroupArn],
        Condition: {
          StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_REGION },
          "ForAllValues:StringEquals": { "aws:TagKeys": ["release"] },
        },
      },
      {
        Sid: "ChangeOnlyQuickLaunchApiDnsRecord",
        Effect: "Allow",
        Action: "route53:ChangeResourceRecordSets",
        Resource: hostedZoneArn,
        Condition: {
          "ForAllValues:StringEquals": {
            "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
              "quick-launch-api.proofofhumanity.org",
            ],
            "route53:ChangeResourceRecordSetsRecordTypes": ["A"],
            "route53:ChangeResourceRecordSetsActions": ["CREATE", "UPSERT", "DELETE"],
          },
        },
      },
      {
        Sid: "InspectOnlyQuickLaunchApiDnsAndChanges",
        Effect: "Allow",
        Action: ["route53:GetChange", "route53:GetHostedZone", "route53:ListResourceRecordSets"],
        Resource: [hostedZoneArn, "arn:aws:route53:::change/*"],
      },
    ],
  } as const;

  const deploymentRoleCreationRequest = {
    RoleName: QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE,
    AssumeRolePolicyDocument: deploymentRoleTrustPolicy,
    Description:
      "CloudFormation service role for only the transaction-disabled PoH Quick Launch API origin.",
    MaxSessionDuration: 3600,
    Tags: QUICK_LAUNCH_CLOUDFORMATION_ROLE_TAGS,
  } as const;

  const permissionSetConfiguration = {
    Name: QUICK_LAUNCH_PREREQUISITE_PERMISSION_SET,
    Description:
      "One-hour, transaction-free remediation of only missing PoH Quick Launch AWS prerequisites.",
    SessionDuration: QUICK_LAUNCH_PREREQUISITE_SESSION,
    Tags: QUICK_LAUNCH_PREREQUISITE_ADMINISTRATOR_TAGS,
  } as const;
  const assignment = {
    InstanceArn: instanceArn,
    TargetId: QUICK_LAUNCH_ACCOUNT_ID,
    TargetType: "AWS_ACCOUNT",
    PermissionSetArnFrom: "CreatePermissionSet.PermissionSet.PermissionSetArn",
    PrincipalType: "USER",
    PrincipalId: administratorPrincipalId,
  } as const;

  const subnetApproval = {
    schema: "org.proofofhumanity.quick-launch.public-subnet-approval/1",
    accountId: QUICK_LAUNCH_ACCOUNT_ID,
    region: QUICK_LAUNCH_REGION,
    network: "base-sepolia",
    vpcIdSha256: canonicalHash(vpcId),
    subnets: publicSubnets.map((subnet) => ({
      subnetIdSha256: canonicalHash(subnet.subnetId),
      availabilityZone: subnet.availabilityZone,
      routeTableIdSha256: canonicalHash(subnet.routeTableId),
      internetGatewayIdSha256: canonicalHash(subnet.internetGatewayId),
      mapPublicIpOnLaunch: true,
      activeIpv4DefaultRoute: true,
      fobalTagged: false,
    })),
  } as const;

  const requestPlan = {
    bootstrap: [
      {
        order: 1,
        mutating: true,
        actionAuthorized: false,
        pauseImmediatelyBefore: "sso-admin:CreatePermissionSet",
        input: { InstanceArn: instanceArn, ...permissionSetConfiguration },
      },
      {
        order: 2,
        mutating: true,
        actionAuthorized: false,
        pauseImmediatelyBefore: "sso-admin:PutInlinePolicyToPermissionSet",
        input: {
          InstanceArn: instanceArn,
          PermissionSetArnFrom: "step-1",
          InlinePolicy: administratorPermissionsPolicy,
        },
      },
      {
        order: 3,
        mutating: true,
        actionAuthorized: false,
        pauseImmediatelyBefore: "sso-admin:CreateAccountAssignment",
        input: assignment,
      },
    ],
    remediation: [
      {
        order: 1,
        mutating: false,
        api: "ec2:DescribeVpcs/DescribeSubnets/DescribeRouteTables/DescribeInternetGateways",
        requiredEvidenceSha256: canonicalHash(subnetApproval),
      },
      {
        order: 2,
        mutating: true,
        actionAuthorized: false,
        pauseImmediatelyBefore: "secretsmanager:CreateSecret",
        purpose: "issuer",
        input: issuerSecretCreationRequest,
      },
      {
        order: 3,
        mutating: false,
        api: "secretsmanager:DescribeSecret/ListSecretVersionIds",
        requiredAssertions: [
          "exact name and tags match",
          "VersionIdsToStages is empty before manual value entry",
        ],
      },
      {
        order: 4,
        mutating: true,
        actionAuthorized: false,
        pauseImmediatelyBefore: "secretsmanager:CreateSecret",
        purpose: "sponsor",
        input: sponsorSecretCreationRequest,
      },
      {
        order: 5,
        mutating: false,
        api: "secretsmanager:DescribeSecret/ListSecretVersionIds",
        requiredAssertions: [
          "exact name and tags match",
          "VersionIdsToStages is empty before manual value entry",
          "issuer and sponsor ARNs are distinct",
        ],
      },
      {
        order: 6,
        mutating: true,
        actionAuthorized: false,
        pauseImmediatelyBefore: "ec2:CreateTags",
        input: {
          Resources: publicSubnets.map(({ subnetId }) => subnetId),
          Tags: QUICK_LAUNCH_SUBNET_TAGS,
        },
      },
      {
        order: 7,
        mutating: true,
        actionAuthorized: false,
        pauseImmediatelyBefore: "iam:CreateRole",
        input: deploymentRoleCreationRequest,
      },
      {
        order: 8,
        mutating: true,
        actionAuthorized: false,
        pauseImmediatelyBefore: "iam:PutRolePolicy",
        input: {
          RoleName: QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE,
          PolicyName: QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_POLICY,
          PolicyDocument: deploymentRolePermissionsPolicy,
        },
      },
      {
        order: 9,
        mutating: false,
        api: "iam:GetRole/GetRolePolicy/ListRolePolicies/ListAttachedRolePolicies/ListRoleTags",
        requiredAssertions: [
          "trust, policy, tags and hashes match",
          "maximum session duration is 3600",
          "no managed policy is attached",
        ],
      },
    ],
  } as const;

  const packageBinding = {
    schema: QUICK_LAUNCH_PREREQUISITE_REMEDIATION_SCHEMA,
    accountId: QUICK_LAUNCH_ACCOUNT_ID,
    region: QUICK_LAUNCH_REGION,
    instanceArn,
    administratorPrincipalId,
    permissionSetConfigurationSha256: canonicalHash(permissionSetConfiguration),
    administratorPermissionsPolicySha256: canonicalHash(administratorPermissionsPolicy),
    assignmentSha256: canonicalHash(assignment),
    issuerSecretCreationRequestSha256: canonicalHash(issuerSecretCreationRequest),
    sponsorSecretCreationRequestSha256: canonicalHash(sponsorSecretCreationRequest),
    subnetApprovalSha256: canonicalHash(subnetApproval),
    deploymentRoleCreationRequestSha256: canonicalHash(deploymentRoleCreationRequest),
    deploymentRoleTrustPolicySha256: canonicalHash(deploymentRoleTrustPolicy),
    deploymentRolePermissionsPolicySha256: canonicalHash(deploymentRolePermissionsPolicy),
    requestPlanSha256: canonicalHash(requestPlan),
  } as const;

  return {
    ...packageBinding,
    packageBindingSha256: canonicalHash(packageBinding),
    transactionFree: true,
    mutatesAws: false,
    applyAuthorized: false,
    pauseBeforeEveryMutation: true,
    liveReadinessClaimed: false,
    permissionSetConfiguration,
    administratorPermissionsPolicy,
    assignment,
    secretContainers: {
      issuer: {
        arnPattern: issuerSecretArnPattern,
        creationRequest: issuerSecretCreationRequest,
      },
      sponsor: {
        arnPattern: sponsorSecretArnPattern,
        creationRequest: sponsorSecretCreationRequest,
      },
      valuesIncluded: false,
      manualValueEntryRequired: true,
    },
    approvedTopology: {
      vpcId,
      publicSubnets,
      hostedZoneId,
      subnetApproval,
    },
    cloudFormationDeploymentRole: {
      arn: deploymentRoleArn,
      creationRequest: deploymentRoleCreationRequest,
      inlinePolicyName: QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_POLICY,
      trustPolicy: deploymentRoleTrustPolicy,
      permissionsPolicy: deploymentRolePermissionsPolicy,
    },
    requestPlan,
    residualAuthorizationLimits: [
      "Secrets Manager cannot express an IAM condition proving SecretString and SecretBinary are absent; compare each CreateSecret request byte-for-byte and verify zero versions immediately afterward.",
      "IAM cannot bind CreateRole or PutRolePolicy to trust/policy document bytes; require action-time hash approval and canonical read-back.",
      "CloudFormation service-role permissions cannot constrain every task-definition, ECS-service, listener or Route 53 alias payload field; a reviewed change-set hash and exact parameter checks remain mandatory before later deployment.",
      "Generated security-group, load-balancer, target-group and listener suffixes require name/tag-scoped ARN wildcards; no wildcard grants secret access, image publication, CloudFormation control-plane access or role assumption.",
    ],
  };
}
