import assert from "node:assert/strict";
import {
  QUICK_LAUNCH_API_HOSTNAME,
  QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE,
  QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_PERMISSION_SET,
  QUICK_LAUNCH_TASK_EXECUTION_ROLE,
  buildQuickLaunchInfrastructureAdministratorPackage,
} from "../app/quick-launch-infrastructure-administrator";

const accountId = "368426158592";
const region = "us-east-1";
const instanceArn = "arn:aws:sso:::instance/ssoins-7223e85b4df333bb";
const administratorPrincipalId = "12345678-1234-1234-1234-123456789abc";
const issuerSecretArn =
  `arn:aws:secretsmanager:${region}:${accountId}:secret:poh-quick-launch-issuer-AbCdEf`;
const sponsorSecretArn =
  `arn:aws:secretsmanager:${region}:${accountId}:secret:poh-quick-launch-sponsor-GhIjKl`;
const issuerKmsKeyArn =
  `arn:aws:kms:${region}:${accountId}:key/11111111-1111-1111-1111-111111111111`;
const sponsorKmsKeyArn =
  `arn:aws:kms:${region}:${accountId}:key/22222222-2222-2222-2222-222222222222`;
const vpcId = "vpc-0123456789abcdef0";
const subnetIds = ["subnet-0123456789abcdef0", "subnet-0fedcba9876543210"];
const subnetAvailabilityZones = ["us-east-1a", "us-east-1b"];
const hostedZoneId = "Z0123456789ABCDEF";
const cloudFormationDeploymentRoleArn =
  `arn:aws:iam::${accountId}:role/${QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE}`;

const build = (patch = {}) =>
  buildQuickLaunchInfrastructureAdministratorPackage({
    accountId,
    identityCenterRegion: region,
    instanceArn,
    administratorPrincipalId,
    issuerSecretArn,
    sponsorSecretArn,
    issuerKmsKeyArn,
    sponsorKmsKeyArn,
    vpcId,
    subnetIds,
    subnetAvailabilityZones,
    hostedZoneId,
    cloudFormationDeploymentRoleArn,
    ...patch,
  });

const result = build();
assert.equal(result.transactionFree, true);
assert.equal(result.mutatesAws, false);
assert.equal(result.applyAuthorized, false);
assert.equal(result.pauseBeforeApply, true);
assert.equal(
  result.permissionSetConfiguration.Name,
  QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_PERMISSION_SET,
);
assert.equal(result.permissionSetConfiguration.SessionDuration, "PT1H");
assert.equal(result.assignment.TargetId, accountId);
assert.equal(result.assignment.PrincipalType, "USER");
assert.equal(result.assignment.PrincipalId, administratorPrincipalId);

for (const hash of [
  result.permissionSetConfigurationSha256,
  result.administratorPermissionsPolicySha256,
  result.assignmentSha256,
  result.taskExecutionTrustPolicySha256,
  result.taskExecutionPermissionsPolicySha256,
  result.issuerAttestationSha256,
  result.sponsorAttestationSha256,
  result.topologyAttestationSha256,
  result.requestPlanSha256,
  result.packageBindingSha256,
]) {
  assert.match(hash, /^[0-9a-f]{64}$/u);
}
assert.deepEqual(
  {
    permissionSetConfigurationSha256: result.permissionSetConfigurationSha256,
    administratorPermissionsPolicySha256: result.administratorPermissionsPolicySha256,
    assignmentSha256: result.assignmentSha256,
    taskExecutionTrustPolicySha256: result.taskExecutionTrustPolicySha256,
    taskExecutionPermissionsPolicySha256: result.taskExecutionPermissionsPolicySha256,
    issuerAttestationSha256: result.issuerAttestationSha256,
    sponsorAttestationSha256: result.sponsorAttestationSha256,
    topologyAttestationSha256: result.topologyAttestationSha256,
    requestPlanSha256: result.requestPlanSha256,
    packageBindingSha256: result.packageBindingSha256,
  },
  {
    permissionSetConfigurationSha256:
      "6557d54acded7a33ac58644564f72ef00b9e34e0842ceaa0bb02d5a007d5aaf2",
    administratorPermissionsPolicySha256:
      "0fb0fdca37bda6df2896f40b094ba7184518f08df68e5ad529d032ea9495adb9",
    assignmentSha256: "e312ced830226b58adf654c61a9beee81ba96f95c03dee94872542d72577f132",
    taskExecutionTrustPolicySha256:
      "4ae85e6ac6805330260b864794cabdedf5061f5a2cc701b17444f4399c8f8bee",
    taskExecutionPermissionsPolicySha256:
      "cccd8806988f15b1b000e2e79ea963e319a4d863dc2018390982d8d6a3286adc",
    issuerAttestationSha256:
      "36db49819a4f483a421c0eed41b96c0d320166aaccf808b9b144a9f40fab4b40",
    sponsorAttestationSha256:
      "b6b44feee303467c8bb5f5819be1595f9bfbaa580459fd87d1518c4aca973b5c",
    topologyAttestationSha256:
      "6b7f14a41beed670c240baca607f7c7e5493150f004fc815a397a222ebd2d009",
    requestPlanSha256: "1a9c0306d33f65fd48b54e550b1ee836fe1ccd94e4571dea6a40a6b4902dee01",
    packageBindingSha256:
      "1dace18c0cd7e8539fe36ec14f1b646046abd06cb06a452f702902a04b7b7216",
  },
  "fixture hashes changed without explicit review",
);

type RenderedPolicyStatement = {
  Sid: string;
  Effect: string;
  Action: string | string[];
  Resource: string | string[];
  Condition?: Record<string, Record<string, string | string[]>>;
};
const statements = result.administratorPermissionsPolicy
  .Statement as unknown as RenderedPolicyStatement[];
const values = (value: string | string[]) => (Array.isArray(value) ? value : [value]);
const statement = (sid: string) => {
  const found = statements.find((candidate) => candidate.Sid === sid);
  assert.ok(found, `missing statement ${sid}`);
  return found;
};
const allows = (action: string, resource: string) =>
  statements.some(
    (candidate) =>
      candidate.Effect === "Allow" &&
      values(candidate.Action).includes(action) &&
      values(candidate.Resource).includes(resource),
  );
const actions = [...new Set(statements.flatMap((candidate) => values(candidate.Action)))].sort();
const expectedActions = [
  "acm:DescribeCertificate",
  "acm:ListCertificates",
  "acm:ListTagsForCertificate",
  "acm:RequestCertificate",
  "ec2:CreateTags",
  "ec2:DescribeAvailabilityZones",
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
  "kms:DescribeKey",
  "route53:ChangeResourceRecordSets",
  "route53:GetHostedZone",
  "route53:ListResourceRecordSets",
  "secretsmanager:DescribeSecret",
  "secretsmanager:ListSecretVersionIds",
  "secretsmanager:ListSecrets",
  "secretsmanager:TagResource",
].sort();
assert.deepEqual(actions, expectedActions, "administrator action allowlist changed");

const wildcardStatements = statements.filter((candidate) => values(candidate.Resource).includes("*"));
assert.deepEqual(
  wildcardStatements.map((candidate) => candidate.Sid),
  [
    "DiscoverOnlySecretMetadataInUsEast1",
    "DiscoverOnlyUsEast1NetworkMetadata",
    "DiscoverOnlyUsEast1CertificateMetadata",
    "RequestOnlyTaggedQuickLaunchApiCertificate",
  ],
  "only unavoidable metadata discovery and server-generated certificate creation may use Resource=*",
);

const policyJson = JSON.stringify(result.administratorPermissionsPolicy);
for (const forbidden of [
  "secretsmanager:GetSecretValue",
  "secretsmanager:BatchGetSecretValue",
  "secretsmanager:PutSecretValue",
  "secretsmanager:UpdateSecret",
  "secretsmanager:UntagResource",
  "ec2:DeleteTags",
  "ec2:CreateVpc",
  "ec2:CreateSubnet",
  "ec2:RunInstances",
  "acm:AddTagsToCertificate",
  "acm:DeleteCertificate",
  "acm:ExportCertificate",
  "route53:CreateHostedZone",
  "route53:DeleteHostedZone",
  "ecr:",
  "iam:AttachRolePolicy",
  "iam:DeleteRole",
  "iam:DeleteRolePolicy",
  "iam:DetachRolePolicy",
  "iam:PassRole",
  "iam:UntagRole",
  "iam:UpdateAssumeRolePolicy",
  "iam:UpdateRole",
  "cloudformation:",
  "ecs:",
  "ssm:",
  "sts:AssumeRole",
]) {
  assert.equal(policyJson.includes(forbidden), false, `contains forbidden authority ${forbidden}`);
}

const taskExecutionRoleArn =
  `arn:aws:iam::${accountId}:role/${QUICK_LAUNCH_TASK_EXECUTION_ROLE}`;
assert.equal(allows("iam:CreateRole", taskExecutionRoleArn), true);
assert.equal(allows("iam:TagRole", taskExecutionRoleArn), true);
assert.equal(allows("iam:PutRolePolicy", taskExecutionRoleArn), true);
assert.equal(allows("iam:GetRole", cloudFormationDeploymentRoleArn), true);
assert.equal(allows("iam:GetRolePolicy", cloudFormationDeploymentRoleArn), true);
for (const unrelatedRole of [
  `arn:aws:iam::${accountId}:role/PoHQuickLaunchImagePublisherRole`,
  `arn:aws:iam::${accountId}:role/PoHQuickLaunchBootstrapRole`,
  `arn:aws:iam::${accountId}:role/FobalAdministrator`,
  `arn:aws:iam::000000000000:role/${QUICK_LAUNCH_TASK_EXECUTION_ROLE}`,
]) {
  for (const action of ["iam:CreateRole", "iam:TagRole", "iam:PutRolePolicy", "iam:GetRole"]) {
    assert.equal(allows(action, unrelatedRole), false, `unrelated role allows ${action}`);
  }
}

const exactTagCondition = (
  condition: Record<string, Record<string, string | string[]>> | undefined,
  tags: Record<string, string>,
) => {
  if (!condition) return false;
  const expectedKeys = condition["ForAllValues:StringEquals"]?.["aws:TagKeys"];
  if (!Array.isArray(expectedKeys)) return false;
  if (Object.keys(tags).length !== expectedKeys.length) return false;
  if (!Object.keys(tags).every((key) => expectedKeys.includes(key))) return false;
  return Object.entries(tags).every(
    ([key, value]) => condition.StringEquals?.[`aws:RequestTag/${key}`] === value,
  );
};
const taskRoleCreate = statement("CreateOnlyTaggedQuickLaunchTaskExecutionRole");
const validTaskTags = {
  network: "base-sepolia",
  purpose: "task-execution",
  release: "poh-quick-launch-v1",
};
assert.equal(exactTagCondition(taskRoleCreate.Condition, validTaskTags), true);
assert.equal(exactTagCondition(taskRoleCreate.Condition, { ...validTaskTags, purpose: "fobal" }), false);
assert.equal(
  exactTagCondition(taskRoleCreate.Condition, {
    ...validTaskTags,
    unrelated: "not-approved",
  }),
  false,
);
assert.equal(
  exactTagCondition(taskRoleCreate.Condition, {
    network: "base-sepolia",
    purpose: "task-execution",
  }),
  false,
);

const issuerTag = statement("TagOnlyApprovedIssuerSecret");
const sponsorTag = statement("TagOnlyApprovedSponsorSecret");
assert.deepEqual(values(issuerTag.Resource), [issuerSecretArn]);
assert.deepEqual(values(sponsorTag.Resource), [sponsorSecretArn]);
assert.equal(
  exactTagCondition(issuerTag.Condition, { purpose: "issuer", release: "poh-quick-launch-v1" }),
  true,
);
assert.equal(
  exactTagCondition(issuerTag.Condition, { purpose: "sponsor", release: "poh-quick-launch-v1" }),
  false,
);
assert.equal(
  exactTagCondition(issuerTag.Condition, { purpose: "issuer" }),
  false,
);
assert.equal(
  exactTagCondition(issuerTag.Condition, {
    purpose: "issuer",
    release: "poh-quick-launch-v1",
    project: "fobal",
  }),
  false,
);

const subnetTag = statement("TagOnlyTwoApprovedQuickLaunchSubnets");
assert.deepEqual(
  [...values(subnetTag.Resource)].sort(),
  subnetIds
    .map((id) => `arn:aws:ec2:${region}:${accountId}:subnet/${id}`)
    .sort(),
);
const validSubnetTags = {
  network: "base-sepolia",
  purpose: "api-origin",
  release: "poh-quick-launch-v1",
};
assert.equal(exactTagCondition(subnetTag.Condition, validSubnetTags), true);
assert.equal(
  exactTagCondition(subnetTag.Condition, { ...validSubnetTags, network: "mainnet" }),
  false,
);

const certificateRequest = statement("RequestOnlyTaggedQuickLaunchApiCertificate");
assert.equal(
  certificateRequest.Condition?.["ForAllValues:StringEquals"]?.["acm:DomainNames"]?.[0],
  QUICK_LAUNCH_API_HOSTNAME,
);
assert.equal(
  exactTagCondition(certificateRequest.Condition, {
    network: "base-sepolia",
    purpose: "api-origin-tls",
    release: "poh-quick-launch-v1",
  }),
  true,
);
const dnsUpdate = statement("UpsertOnlyQuickLaunchCertificateValidationCname");
assert.deepEqual(dnsUpdate.Condition, {
  "ForAllValues:StringLike": {
    "route53:ChangeResourceRecordSetsNormalizedRecordNames": [
      `_*.${QUICK_LAUNCH_API_HOSTNAME}`,
    ],
  },
  "ForAllValues:StringEquals": {
    "route53:ChangeResourceRecordSetsRecordTypes": ["CNAME"],
    "route53:ChangeResourceRecordSetsActions": ["UPSERT"],
  },
});

assert.deepEqual(result.taskExecutionRole.trustPolicy, {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "AllowQuickLaunchEcsTasks",
      Effect: "Allow",
      Principal: { Service: "ecs-tasks.amazonaws.com" },
      Action: "sts:AssumeRole",
      Condition: {
        StringEquals: { "aws:SourceAccount": accountId },
        ArnLike: { "aws:SourceArn": `arn:aws:ecs:${region}:${accountId}:*` },
      },
    },
  ],
});
const taskPolicyJson = JSON.stringify(result.taskExecutionRole.permissionsPolicy);
for (const required of [
  "ecr:GetAuthorizationToken",
  "ecr:BatchCheckLayerAvailability",
  "ecr:GetDownloadUrlForLayer",
  "ecr:BatchGetImage",
  "logs:CreateLogStream",
  "logs:PutLogEvents",
  "secretsmanager:GetSecretValue",
  "kms:Decrypt",
]) {
  assert.equal(taskPolicyJson.includes(required), true, `task role missing ${required}`);
}
for (const forbidden of [
  "secretsmanager:ListSecrets",
  "secretsmanager:PutSecretValue",
  "kms:Encrypt",
  "iam:",
  "cloudformation:",
  "ssm:",
]) {
  assert.equal(taskPolicyJson.includes(forbidden), false, `task role contains ${forbidden}`);
}
assert.equal(taskPolicyJson.includes(issuerSecretArn), true);
assert.equal(taskPolicyJson.includes(sponsorSecretArn), true);
assert.equal(taskPolicyJson.includes(issuerKmsKeyArn), true);
assert.equal(taskPolicyJson.includes(sponsorKmsKeyArn), true);

const withoutKms = build({ issuerKmsKeyArn: undefined, sponsorKmsKeyArn: undefined });
assert.equal(
  JSON.stringify(withoutKms.administratorPermissionsPolicy).includes("kms:DescribeKey"),
  false,
);
assert.equal(
  JSON.stringify(withoutKms.taskExecutionRole.permissionsPolicy).includes("kms:Decrypt"),
  false,
);

const requestPlanJson = JSON.stringify(result.requestPlan);
assert.equal(requestPlanJson.includes("cloudformation:"), false);
assert.equal(
  result.requestPlan.afterFreshAdministratorLogin.some((step) => step.api.startsWith("ecs:")),
  false,
);
assert.equal(requestPlanJson.includes('"api":"secretsmanager:GetSecretValue"'), false);
assert.equal(requestPlanJson.includes("sso-admin:CreatePermissionSet"), true);
assert.equal(requestPlanJson.includes("iam:CreateRole"), true);
assert.equal(requestPlanJson.includes("acm:RequestCertificate"), true);

const attestationJson = JSON.stringify(result.attestations);
for (const protectedValue of [
  issuerSecretArn,
  sponsorSecretArn,
  issuerKmsKeyArn,
  sponsorKmsKeyArn,
  vpcId,
  ...subnetIds,
  hostedZoneId,
  cloudFormationDeploymentRoleArn,
]) {
  assert.equal(attestationJson.includes(protectedValue), false, "attestation leaked protected metadata");
}

for (const [patch, message] of [
  [{ accountId: "000000000000" }, /account must be exactly/u],
  [{ identityCenterRegion: "us-west-2" }, /region must be exactly/u],
  [{ instanceArn: "invalid" }, /instance ARN is invalid/u],
  [{ administratorPrincipalId: "invalid" }, /principal ID is invalid/u],
  [{ sponsorSecretArn: issuerSecretArn }, /must be distinct/u],
  [
    { issuerSecretArn: issuerSecretArn.replace(region, "us-west-2") },
    /Issuer secret must be in us-east-1/u,
  ],
  [
    { sponsorSecretArn: sponsorSecretArn.replace(accountId, "000000000000") },
    /Sponsor secret must belong/u,
  ],
  [
    { issuerSecretArn: issuerSecretArn.replace("poh-quick-launch-issuer", "fobal-issuer") },
    /must not reference a Fobal resource/u,
  ],
  [{ subnetIds: [subnetIds[0], subnetIds[0]] }, /subnet IDs must be distinct/u],
  [{ subnetAvailabilityZones: ["us-east-1a", "us-east-1a"] }, /distinct Availability Zones/u],
  [{ hostedZoneId: "not-a-zone" }, /Hosted zone ID is invalid/u],
  [
    {
      cloudFormationDeploymentRoleArn:
        `arn:aws:iam::${accountId}:role/FobalCloudFormationDeploymentRole`,
    },
    /deployment role ARN is invalid/u,
  ],
  [
    {
      cloudFormationDeploymentRoleArn: cloudFormationDeploymentRoleArn.replace(
        accountId,
        "000000000000",
      ),
    },
    /must belong to the Quick Launch account/u,
  ],
] as const) {
  assert.throws(() => build(patch), message);
}

console.log("quick-launch infrastructure administrator product tests: ok");
console.log(JSON.stringify({
  permissionSetConfigurationSha256: result.permissionSetConfigurationSha256,
  administratorPermissionsPolicySha256: result.administratorPermissionsPolicySha256,
  assignmentSha256: result.assignmentSha256,
  taskExecutionTrustPolicySha256: result.taskExecutionTrustPolicySha256,
  taskExecutionPermissionsPolicySha256: result.taskExecutionPermissionsPolicySha256,
  issuerAttestationSha256: result.issuerAttestationSha256,
  sponsorAttestationSha256: result.sponsorAttestationSha256,
  topologyAttestationSha256: result.topologyAttestationSha256,
  requestPlanSha256: result.requestPlanSha256,
  packageBindingSha256: result.packageBindingSha256,
}, null, 2));
