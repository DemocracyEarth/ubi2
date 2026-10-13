import assert from "node:assert/strict";
import {
  AWS_IDENTITY_CENTER_PERMISSION_SET_NAME_MAX_LENGTH,
  QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_POLICY,
  QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE,
  QUICK_LAUNCH_ISSUER_SECRET_NAME,
  QUICK_LAUNCH_PREREQUISITE_PERMISSION_SET,
  QUICK_LAUNCH_SPONSOR_SECRET_NAME,
  assertAwsIdentityCenterPermissionSetNameLength,
  buildQuickLaunchPrerequisiteRemediationPackage,
} from "../app/quick-launch-prerequisite-remediation";

const accountId = "368426158592";
const region = "us-east-1";
const instanceArn = "arn:aws:sso:::instance/ssoins-7223e85b4df333bb";
const administratorPrincipalId = "12345678-1234-1234-1234-123456789abc";
const vpcId = "vpc-0123456789abcdef0";
const hostedZoneId = "Z0123456789ABCDEF";
const publicSubnets = [
  {
    subnetId: "subnet-0123456789abcdef0",
    availabilityZone: "us-east-1a",
    vpcId,
    routeTableId: "rtb-0123456789abcdef0",
    internetGatewayId: "igw-0123456789abcdef0",
    mapPublicIpOnLaunch: true,
    activeIpv4DefaultRoute: true,
    fobalTagged: false,
  },
  {
    subnetId: "subnet-0fedcba9876543210",
    availabilityZone: "us-east-1b",
    vpcId,
    routeTableId: "rtb-0fedcba9876543210",
    internetGatewayId: "igw-0fedcba9876543210",
    mapPublicIpOnLaunch: true,
    activeIpv4DefaultRoute: true,
    fobalTagged: false,
  },
];

const build = (patch = {}) =>
  buildQuickLaunchPrerequisiteRemediationPackage({
    accountId,
    identityCenterRegion: region,
    instanceArn,
    administratorPrincipalId,
    vpcId,
    hostedZoneId,
    publicSubnets,
    ...patch,
  });

const result = build();
assert.equal(result.transactionFree, true);
assert.equal(result.mutatesAws, false);
assert.equal(result.applyAuthorized, false);
assert.equal(result.pauseBeforeEveryMutation, true);
assert.equal(result.liveReadinessClaimed, false);
assert.equal(result.permissionSetConfiguration.Name, QUICK_LAUNCH_PREREQUISITE_PERMISSION_SET);
assert.equal(QUICK_LAUNCH_PREREQUISITE_PERMISSION_SET, "PoHQuickLaunchPrereqAdmin");
assert.ok(
  QUICK_LAUNCH_PREREQUISITE_PERMISSION_SET.length <=
    AWS_IDENTITY_CENTER_PERMISSION_SET_NAME_MAX_LENGTH,
);
assert.equal("PoHQuickLaunchPrerequisiteAdministrator".length, 39);
assert.throws(
  () => assertAwsIdentityCenterPermissionSetNameLength(""),
  /must contain 1-32 characters/u,
);
assert.throws(
  () => assertAwsIdentityCenterPermissionSetNameLength("PoHQuickLaunchPrerequisiteAdministrator"),
  /must contain 1-32 characters/u,
  "the rejected 39-character permission-set name must fail closed",
);
assert.equal(result.permissionSetConfiguration.SessionDuration, "PT1H");
assert.equal(result.assignment.PrincipalType, "USER");
assert.equal(result.assignment.PrincipalId, administratorPrincipalId);
assert.equal(result.assignment.TargetId, accountId);

const hashes = {
  permissionSetConfigurationSha256: result.permissionSetConfigurationSha256,
  administratorPermissionsPolicySha256: result.administratorPermissionsPolicySha256,
  assignmentSha256: result.assignmentSha256,
  issuerSecretCreationRequestSha256: result.issuerSecretCreationRequestSha256,
  sponsorSecretCreationRequestSha256: result.sponsorSecretCreationRequestSha256,
  subnetApprovalSha256: result.subnetApprovalSha256,
  deploymentRoleCreationRequestSha256: result.deploymentRoleCreationRequestSha256,
  deploymentRoleTrustPolicySha256: result.deploymentRoleTrustPolicySha256,
  deploymentRolePermissionsPolicySha256: result.deploymentRolePermissionsPolicySha256,
  requestPlanSha256: result.requestPlanSha256,
  packageBindingSha256: result.packageBindingSha256,
};
for (const hash of Object.values(hashes)) assert.match(hash, /^[0-9a-f]{64}$/u);
assert.deepEqual(
  hashes,
  {
    permissionSetConfigurationSha256:
      "3b8c17fb6de7e92ed5d98ec1fcafa3f040bc1ffa005ae21bb4f439c92c586719",
    administratorPermissionsPolicySha256:
      "78ae3d699a8c017ff3183bde937c903a1ee025c65bf4979ef54c7bf37e938eb5",
    assignmentSha256: "e312ced830226b58adf654c61a9beee81ba96f95c03dee94872542d72577f132",
    issuerSecretCreationRequestSha256:
      "e46df92a3df0809950af66e24404d41e086c4bb92922f3e3009a3abab188156f",
    sponsorSecretCreationRequestSha256:
      "ee6447efd85459f10201ff26ec0495736e2fd7d0349ca70a485c60fe6c3506ea",
    subnetApprovalSha256:
      "983b2671ff407bf239922af50ed40c99d8de34c5ee1816edc9126b9c5f430797",
    deploymentRoleCreationRequestSha256:
      "d58f240e02f4df858f9a8d5dda7c3277603ef57d18530de52a624b2101b398b5",
    deploymentRoleTrustPolicySha256:
      "1a5a246a03b411974f3ff8dd3ca795a60dede809b40313397f1955c949758f74",
    deploymentRolePermissionsPolicySha256:
      "f149216e5e8030a39c8619d30cdbfbef0efb82e670129b33eae30c604a999227",
    requestPlanSha256:
      "9607331294115c3ff339c0f0ebc7b03b0f42fee4c8f97007df9de1e807952816",
    packageBindingSha256:
      "bbf4f9a3b422b2c35535e2cc5caeecf0ada7c2d7e44dd049c0a6f81b6e108aae",
  },
  "fixture hashes changed without explicit review",
);

type Statement = {
  Sid: string;
  Effect: string;
  Action: string | string[];
  Resource: string | string[];
  Condition?: Record<string, Record<string, string | string[]>>;
};
const values = (value: string | string[]) => (Array.isArray(value) ? value : [value]);
const adminStatements = result.administratorPermissionsPolicy.Statement as unknown as Statement[];
const adminActions = [
  ...new Set(adminStatements.flatMap((candidate) => values(candidate.Action))),
].sort();
assert.deepEqual(
  adminActions,
  [
    "ec2:CreateTags",
    "ec2:DescribeInternetGateways",
    "ec2:DescribeRouteTables",
    "ec2:DescribeSubnets",
    "ec2:DescribeVpcs",
    "iam:CreateRole",
    "iam:GetRole",
    "iam:GetRolePolicy",
    "iam:ListAttachedRolePolicies",
    "iam:ListRolePolicies",
    "iam:ListRoleTags",
    "iam:PutRolePolicy",
    "iam:TagRole",
    "secretsmanager:CreateSecret",
    "secretsmanager:DescribeSecret",
    "secretsmanager:ListSecretVersionIds",
    "secretsmanager:TagResource",
  ].sort(),
  "prerequisite administrator action allowlist changed",
);
assert.deepEqual(
  adminStatements
    .filter((statement) => values(statement.Resource).includes("*"))
    .map(({ Sid }) => Sid),
  ["InspectOnlyUsEast1PublicSubnetEvidence"],
  "only unavoidable EC2 metadata discovery may use Resource=*",
);

const adminJson = JSON.stringify(result.administratorPermissionsPolicy);
assert.ok(adminJson.length <= 32_768, "Identity Center inline policy exceeds its size limit");
for (const forbidden of [
  "secretsmanager:GetSecretValue",
  "secretsmanager:BatchGetSecretValue",
  "secretsmanager:PutSecretValue",
  "secretsmanager:UpdateSecret",
  "secretsmanager:DeleteSecret",
  "secretsmanager:RestoreSecret",
  "secretsmanager:UntagResource",
  "ec2:DeleteTags",
  "ec2:CreateVpc",
  "ec2:CreateSubnet",
  "iam:PassRole",
  "iam:AttachRolePolicy",
  "iam:DeleteRole",
  "iam:DeleteRolePolicy",
  "iam:DetachRolePolicy",
  "iam:UpdateAssumeRolePolicy",
  "iam:UntagRole",
  "sts:AssumeRole",
  "cloudformation:",
  "ecs:",
  "ecr:",
  "kms:",
  "ssm:",
]) {
  assert.equal(adminJson.includes(forbidden), false, `administrator contains ${forbidden}`);
}

const statement = (sid: string) => {
  const found = adminStatements.find((candidate) => candidate.Sid === sid);
  assert.ok(found, `missing statement ${sid}`);
  return found;
};
const exactRequestTags = (
  condition: Statement["Condition"],
  tags: Record<string, string>,
) => {
  const keys = condition?.["ForAllValues:StringEquals"]?.["aws:TagKeys"];
  if (!Array.isArray(keys) || keys.length !== Object.keys(tags).length) return false;
  return (
    Object.keys(tags).every((key) => keys.includes(key)) &&
    Object.entries(tags).every(
      ([key, value]) => condition?.StringEquals?.[`aws:RequestTag/${key}`] === value,
    )
  );
};

const issuerCreate = statement("CreateOnlyEmptyIssuerSecretContainer");
const sponsorCreate = statement("CreateOnlyEmptySponsorSecretContainer");
const issuerTag = statement("TagOnlyIssuerSecretContainer");
const sponsorTag = statement("TagOnlySponsorSecretContainer");
const issuerTags = {
  network: "base-sepolia",
  release: "poh-quick-launch-v1",
  purpose: "issuer",
};
const sponsorTags = { ...issuerTags, purpose: "sponsor" };
assert.equal(exactRequestTags(issuerCreate.Condition, issuerTags), true);
assert.equal(exactRequestTags(issuerCreate.Condition, sponsorTags), false);
assert.equal(exactRequestTags(issuerCreate.Condition, { ...issuerTags, extra: "no" }), false);
assert.equal(
  issuerCreate.Condition?.StringEquals?.["secretsmanager:Name"],
  QUICK_LAUNCH_ISSUER_SECRET_NAME,
);
assert.equal(
  sponsorCreate.Condition?.StringEquals?.["secretsmanager:Name"],
  QUICK_LAUNCH_SPONSOR_SECRET_NAME,
);
assert.equal(issuerCreate.Condition?.Null?.["secretsmanager:KmsKeyArn"], "true");
assert.equal(sponsorCreate.Condition?.Null?.["secretsmanager:KmsKeyArn"], "true");
assert.notDeepEqual(issuerCreate.Resource, sponsorCreate.Resource);
assert.equal(exactRequestTags(issuerTag.Condition, issuerTags), true);
assert.equal(exactRequestTags(issuerTag.Condition, sponsorTags), false);
assert.equal(exactRequestTags(sponsorTag.Condition, sponsorTags), true);
assert.equal(exactRequestTags(sponsorTag.Condition, issuerTags), false);
assert.equal(issuerTag.Resource, issuerCreate.Resource);
assert.equal(sponsorTag.Resource, sponsorCreate.Resource);

for (const request of [
  result.secretContainers.issuer.creationRequest,
  result.secretContainers.sponsor.creationRequest,
]) {
  const requestJson = JSON.stringify(request);
  assert.equal(requestJson.includes("SecretString"), false);
  assert.equal(requestJson.includes("SecretBinary"), false);
  assert.equal(requestJson.includes("KmsKeyId"), false);
}
assert.equal(result.secretContainers.valuesIncluded, false);
assert.equal(result.secretContainers.manualValueEntryRequired, true);

const subnetApproval = statement("ApproveOnlyTwoExactQuickLaunchSubnets");
assert.deepEqual(
  [...values(subnetApproval.Resource)].sort(),
  publicSubnets
    .map(
      ({ subnetId }) => `arn:aws:ec2:${region}:${accountId}:subnet/${subnetId}`,
    )
    .sort(),
);
const subnetTags = {
  network: "base-sepolia",
  release: "poh-quick-launch-v1",
  purpose: "api-origin",
};
assert.equal(exactRequestTags(subnetApproval.Condition, subnetTags), true);
assert.equal(
  exactRequestTags(subnetApproval.Condition, { ...subnetTags, network: "mainnet" }),
  false,
);

const roleCreate = statement("CreateOnlyTaggedQuickLaunchCloudFormationDeploymentRole");
assert.equal(
  roleCreate.Resource,
  `arn:aws:iam::${accountId}:role/${QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE}`,
);
assert.equal(
  exactRequestTags(roleCreate.Condition, {
    network: "base-sepolia",
    release: "poh-quick-launch-v1",
    purpose: "cloudformation-deployment",
  }),
  true,
);

assert.deepEqual(result.cloudFormationDeploymentRole.trustPolicy, {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "AllowOnlyQuickLaunchCloudFormationStack",
      Effect: "Allow",
      Principal: { Service: "cloudformation.amazonaws.com" },
      Action: "sts:AssumeRole",
      Condition: {
        StringEquals: { "aws:SourceAccount": accountId },
        ArnLike: {
          "aws:SourceArn":
            `arn:aws:cloudformation:${region}:${accountId}:stack/poh-quick-launch-api/*`,
        },
      },
    },
  ],
});
assert.equal(
  result.cloudFormationDeploymentRole.creationRequest.MaxSessionDuration,
  3600,
);
assert.equal(
  result.cloudFormationDeploymentRole.inlinePolicyName,
  QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_POLICY,
);

const deploymentStatements = result.cloudFormationDeploymentRole.permissionsPolicy
  .Statement as unknown as Statement[];
const deploymentJson = JSON.stringify(result.cloudFormationDeploymentRole.permissionsPolicy);
assert.ok(deploymentJson.length <= 10_240, "role inline policy exceeds its size limit");
const deploymentActions = [
  ...new Set(deploymentStatements.flatMap((candidate) => values(candidate.Action))),
];
for (const required of [
  "iam:PassRole",
  "ecs:CreateCluster",
  "ecs:RegisterTaskDefinition",
  "ecs:CreateService",
  "logs:CreateLogGroup",
  "ec2:CreateSecurityGroup",
  "elasticloadbalancing:CreateLoadBalancer",
  "elasticloadbalancing:CreateTargetGroup",
  "elasticloadbalancing:CreateListener",
  "route53:ChangeResourceRecordSets",
]) {
  assert.equal(deploymentActions.includes(required), true, `deployment role missing ${required}`);
}
for (const forbidden of [
  "secretsmanager:",
  "kms:",
  "ecr:",
  "sso:",
  "sso-admin:",
  "cloudformation:",
  "iam:CreateRole",
  "iam:PutRolePolicy",
  "iam:AttachRolePolicy",
  "iam:DeleteRole",
  "iam:UpdateAssumeRolePolicy",
  "sts:AssumeRole",
  "ec2:CreateVpc",
  "ec2:CreateSubnet",
  "ec2:RunInstances",
  "route53:CreateHostedZone",
  "route53:DeleteHostedZone",
  "lambda:",
]) {
  assert.equal(deploymentJson.includes(forbidden), false, `deployment role contains ${forbidden}`);
}
const passRole = deploymentStatements.find(
  ({ Sid }) => Sid === "PassOnlyQuickLaunchTaskExecutionRoleToEcsTasks",
);
assert.ok(passRole);
assert.equal(
  passRole.Resource,
  `arn:aws:iam::${accountId}:role/PoHQuickLaunchTaskExecutionRole`,
);
assert.deepEqual(passRole.Condition, {
  StringEquals: { "iam:PassedToService": "ecs-tasks.amazonaws.com" },
});
assert.equal(deploymentJson.includes("AWSServiceRoleForECS"), false);
assert.equal(deploymentJson.includes("AWSServiceRoleForElasticLoadBalancing"), false);
assert.equal(deploymentJson.toLowerCase().includes("mainnet"), false);
assert.equal(deploymentJson.toLowerCase().includes("fobal"), false);

const allSteps = [...result.requestPlan.bootstrap, ...result.requestPlan.remediation];
const mutations = allSteps.filter((step) => step.mutating);
assert.equal(mutations.length, 8);
for (const mutation of mutations) {
  assert.equal(mutation.actionAuthorized, false);
  assert.match(mutation.pauseImmediatelyBefore, /^[a-z0-9-]+:[A-Za-z]+/u);
}
assert.equal(JSON.stringify(result.requestPlan).includes("SecretString"), false);
assert.equal(JSON.stringify(result.requestPlan).includes("SecretBinary"), false);
assert.equal(JSON.stringify(result.requestPlan).includes("cloudformation:Create"), false);

const redactedApproval = JSON.stringify(result.approvedTopology.subnetApproval);
for (const protectedValue of [
  vpcId,
  hostedZoneId,
  ...publicSubnets.flatMap(({ subnetId, routeTableId, internetGatewayId }) => [
    subnetId,
    routeTableId,
    internetGatewayId,
  ]),
]) {
  assert.equal(redactedApproval.includes(protectedValue), false, "approval leaked protected metadata");
}

for (const [patch, message] of [
  [{ accountId: "000000000000" }, /account must be exactly/u],
  [{ identityCenterRegion: "us-west-2" }, /region must be exactly/u],
  [{ instanceArn: "invalid" }, /instance ARN is invalid/u],
  [{ administratorPrincipalId: "invalid" }, /principal ID is invalid/u],
  [{ publicSubnets: [publicSubnets[0]] }, /Exactly two/u],
  [
    { publicSubnets: [publicSubnets[0], { ...publicSubnets[1], subnetId: publicSubnets[0].subnetId }] },
    /IDs must be distinct/u,
  ],
  [
    {
      publicSubnets: [
        publicSubnets[0],
        { ...publicSubnets[1], availabilityZone: publicSubnets[0].availabilityZone },
      ],
    },
    /distinct Availability Zones/u,
  ],
  [
    { publicSubnets: [publicSubnets[0], { ...publicSubnets[1], vpcId: "vpc-aaaaaaaaaaaaaaaaa" }] },
    /approved VPC/u,
  ],
  [
    { publicSubnets: [publicSubnets[0], { ...publicSubnets[1], mapPublicIpOnLaunch: false }] },
    /MapPublicIpOnLaunch/u,
  ],
  [
    { publicSubnets: [publicSubnets[0], { ...publicSubnets[1], activeIpv4DefaultRoute: false }] },
    /active 0.0.0.0\/0/u,
  ],
  [
    { publicSubnets: [publicSubnets[0], { ...publicSubnets[1], fobalTagged: true }] },
    /not Fobal-tagged/u,
  ],
  [{ hostedZoneId: "invalid" }, /Hosted zone ID is invalid/u],
] as const) {
  assert.throws(() => build(patch), message);
}

console.log("quick-launch prerequisite remediation product tests: ok");
console.log(JSON.stringify(hashes, null, 2));
