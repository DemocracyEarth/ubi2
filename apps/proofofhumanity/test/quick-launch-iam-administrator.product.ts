import assert from "node:assert/strict";
import {
  QUICK_LAUNCH_IAM_ADMINISTRATOR_PERMISSION_SET,
  buildQuickLaunchIamAdministratorPackage,
} from "../app/quick-launch-iam-administrator";
import { canonicalSha256 } from "../app/quick-launch-image-release";

const accountId = "368426158592";
const instanceArn = "arn:aws:sso:::instance/ssoins-7223e85b4df333bb";
const deployerPermissionSetArn =
  "arn:aws:sso:::permissionSet/ssoins-7223e85b4df333bb/ps-722353e98b48ca5a";
const administratorPrincipalId = "12345678-1234-1234-1234-123456789abc";
const currentDeployerPolicy = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "ExistingQuickLaunchGrant",
      Effect: "Allow",
      Action: "sts:AssumeRole",
      Resource: `arn:aws:iam::${accountId}:role/PoHQuickLaunchBootstrapRole`,
    },
  ],
};
const expectedCurrentDeployerPolicySha256 = canonicalSha256(currentDeployerPolicy);

const build = (patch = {}) =>
  buildQuickLaunchIamAdministratorPackage({
    accountId,
    identityCenterRegion: "us-east-1",
    instanceArn,
    deployerPermissionSetArn,
    administratorPrincipalId,
    currentDeployerPolicy,
    expectedCurrentDeployerPolicySha256,
    ...patch,
  });

const result = build();
assert.equal(result.transactionFree, true);
assert.equal(result.mutatesAws, false);
assert.equal(result.applyAuthorized, false);
assert.equal(result.pauseBeforeApply, true);
assert.equal(result.permissionSetConfiguration.Name, QUICK_LAUNCH_IAM_ADMINISTRATOR_PERMISSION_SET);
assert.equal(result.permissionSetConfiguration.SessionDuration, "PT1H");
assert.equal(result.assignment.TargetId, accountId);
assert.equal(result.assignment.PrincipalType, "USER");
assert.equal(result.assignment.PrincipalId, administratorPrincipalId);
assert.match(result.administratorPermissionsPolicySha256, /^[0-9a-f]{64}$/u);
assert.equal(
  result.administratorPermissionsPolicySha256,
  "9d02054700747aa01528b0a2b24a0973d143b42571676ccac575338eabb00d77",
);
assert.match(result.permissionSetConfigurationSha256, /^[0-9a-f]{64}$/u);
assert.match(result.assignmentSha256, /^[0-9a-f]{64}$/u);
assert.match(result.requestPlanSha256, /^[0-9a-f]{64}$/u);
assert.match(result.packageBindingSha256, /^[0-9a-f]{64}$/u);

assert.equal(
  result.publisherRole.trustPolicySha256,
  "7c5f24c10eb2e6b0f05320bdee16bd361c170840572123761305f00ef27f0351",
);
assert.equal(
  result.publisherRole.permissionsPolicySha256,
  "dc5e57830fde57c4f34adf8517639eedcf69bb076be0bd1e4cce657d6026a433",
);
assert.equal(
  result.deployerPolicyUpdate.exactGrantSha256,
  "bb1672c248223c31799ca5596b9fa6b0a03e67bcabfa467a54920137a220fbdc",
);
assert.equal(result.deployerPolicyUpdate.grantAlreadyPresent, false);
assert.equal(result.deployerPolicyUpdate.updatedPolicy.Statement.length, 2);
assert.deepEqual(result.deployerPolicyUpdate.updatedPolicy.Statement[0], currentDeployerPolicy.Statement[0]);
assert.equal(result.deployerPolicyUpdate.updatedPolicy.Statement[1]?.Sid, "AssumeQuickLaunchImagePublisher");

const policyJson = JSON.stringify(result.administratorPermissionsPolicy);
for (const required of [
  "iam:CreateRole",
  "iam:GetRole",
  "iam:GetRolePolicy",
  "iam:ListAttachedRolePolicies",
  "iam:ListRolePolicies",
  "iam:ListRoleTags",
  "iam:PutRolePolicy",
  "sso:DescribePermissionSet",
  "sso:GetInlinePolicyForPermissionSet",
  "sso:PutInlinePolicyToPermissionSet",
  "sso:ProvisionPermissionSet",
  "sso:DescribePermissionSetProvisioningStatus",
]) {
  assert.ok(policyJson.includes(`\"${required}\"`), `missing exact action ${required}`);
}
for (const forbidden of [
  "iam:*",
  "iam:AttachRolePolicy",
  "iam:CreatePolicy",
  "iam:DeleteRole",
  "iam:PassRole",
  "iam:TagRole",
  "iam:UpdateAssumeRolePolicy",
  "iam:UpdateRole",
  "sso:CreateAccountAssignment",
  "sso:CreatePermissionSet",
  "sso:DeletePermissionSet",
  "sso:ListPermissionSets",
  "identitystore:",
  "ecr:",
  "secretsmanager:",
  "kms:",
  "cloudformation:",
]) {
  assert.equal(policyJson.includes(forbidden), false, `contains forbidden authority ${forbidden}`);
}
assert.equal(policyJson.includes('"Resource":"*"'), false);
assert.equal(policyJson.includes(`arn:aws:iam::${accountId}:role/PoHQuickLaunchImagePublisherRole`), true);
assert.equal(policyJson.includes(instanceArn), true);
assert.equal(policyJson.includes(deployerPermissionSetArn), true);
assert.equal(policyJson.includes(`arn:aws:sso:::account/${accountId}`), true);

assert.deepEqual(result.requestPlan.bootstrapWithExistingAdministrator.map(({ api }) => api), [
  "sso-admin:CreatePermissionSet",
  "sso-admin:PutInlinePolicyToPermissionSet",
  "sso-admin:CreateAccountAssignment",
  "sso-admin:DescribeAccountAssignmentCreationStatus",
]);
assert.deepEqual(result.requestPlan.afterFreshAdministratorLogin.map(({ api }) => api), [
  "iam:CreateRole",
  "iam:PutRolePolicy",
  "sso-admin:PutInlinePolicyToPermissionSet",
  "sso-admin:ProvisionPermissionSet",
  "sso-admin:DescribePermissionSetProvisioningStatus",
]);

const alreadyMergedPolicy = result.deployerPolicyUpdate.updatedPolicy;
const idempotent = build({
  currentDeployerPolicy: alreadyMergedPolicy,
  expectedCurrentDeployerPolicySha256: canonicalSha256(alreadyMergedPolicy),
});
assert.equal(idempotent.deployerPolicyUpdate.grantAlreadyPresent, true);
assert.equal(
  idempotent.deployerPolicyUpdate.currentPolicySha256,
  idempotent.deployerPolicyUpdate.updatedPolicySha256,
);

assert.throws(() => build({ accountId: "not-an-account" }), /12 digits/u);
assert.throws(() => build({ identityCenterRegion: "us-west-2" }), /exactly us-east-1/u);
assert.throws(() => build({ instanceArn: "arn:aws:sso:::instance/not-valid" }), /instance ARN/u);
assert.throws(
  () =>
    build({
      deployerPermissionSetArn:
        "arn:aws:sso:::permissionSet/ssoins-1111111111111111/ps-722353e98b48ca5a",
    }),
  /do not match/u,
);
assert.throws(() => build({ administratorPrincipalId: "sairi-fobal" }), /principal ID/u);
assert.throws(
  () => build({ expectedCurrentDeployerPolicySha256: "0".repeat(64) }),
  /approved SHA-256/u,
);
assert.throws(
  () =>
    build({
      currentDeployerPolicy: {
        Version: "2012-10-17",
        Statement: [
          { Sid: "Duplicate", Effect: "Allow", Action: "iam:GetRole", Resource: "x" },
          { Sid: "Duplicate", Effect: "Allow", Action: "iam:GetRole", Resource: "y" },
        ],
      },
      expectedCurrentDeployerPolicySha256: canonicalSha256({
        Version: "2012-10-17",
        Statement: [
          { Sid: "Duplicate", Effect: "Allow", Action: "iam:GetRole", Resource: "x" },
          { Sid: "Duplicate", Effect: "Allow", Action: "iam:GetRole", Resource: "y" },
        ],
      }),
    }),
  /duplicate Sid/u,
);

const wildcardAssume = {
  Version: "2012-10-17",
  Statement: [
    { Sid: "TooBroad", Effect: "Allow", Action: "sts:AssumeRole", Resource: "*" },
  ],
};
assert.throws(
  () =>
    build({
      currentDeployerPolicy: wildcardAssume,
      expectedCurrentDeployerPolicySha256: canonicalSha256(wildcardAssume),
    }),
  /wildcard sts:AssumeRole/u,
);

const conflictingGrant = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "AssumeQuickLaunchImagePublisher",
      Effect: "Allow",
      Action: "sts:AssumeRole",
      Resource: "arn:aws:iam::368426158592:role/SomeOtherRole",
    },
  ],
};
assert.throws(
  () =>
    build({
      currentDeployerPolicy: conflictingGrant,
      expectedCurrentDeployerPolicySha256: canonicalSha256(conflictingGrant),
    }),
  /conflicting image-publisher grant/u,
);

const missingSid = {
  Version: "2012-10-17",
  Statement: [{ Effect: "Allow", Action: "iam:GetRole", Resource: "x" }],
};
assert.throws(
  () =>
    build({
      currentDeployerPolicy: missingSid,
      expectedCurrentDeployerPolicySha256: canonicalSha256(missingSid),
    }),
  /non-empty Sid/u,
);

const oversizedPolicy = {
  Version: "2012-10-17",
  Statement: [
    {
      Sid: "ExistingLargePolicy",
      Effect: "Allow",
      Action: "iam:GetRole",
      Resource: `arn:aws:iam::${accountId}:role/${"a".repeat(33_000)}`,
    },
  ],
};
assert.throws(
  () =>
    build({
      currentDeployerPolicy: oversizedPolicy,
      expectedCurrentDeployerPolicySha256: canonicalSha256(oversizedPolicy),
    }),
  /32,768-byte limit/u,
);

console.log("Quick Launch IAM administrator least-privilege package and failures: PASS");
