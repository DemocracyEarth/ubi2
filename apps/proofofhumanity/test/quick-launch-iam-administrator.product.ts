import assert from "node:assert/strict";
import {
  QUICK_LAUNCH_DEPLOYER_GENERATED_ROLE,
  QUICK_LAUNCH_IAM_ADMINISTRATOR_PERMISSION_SET,
  buildQuickLaunchIamAdministratorPackage,
} from "../app/quick-launch-iam-administrator";
import { canonicalSha256 } from "../app/quick-launch-image-release";

const accountId = "368426158592";
const instanceArn = "arn:aws:sso:::instance/ssoins-7223e85b4df333bb";
const deployerPermissionSetArn =
  "arn:aws:sso:::permissionSet/ssoins-7223e85b4df333bb/ps-722353e98b48ca5a";
const deployerGeneratedRoleArn =
  `arn:aws:iam::${accountId}:role/aws-reserved/sso.amazonaws.com/` +
  QUICK_LAUNCH_DEPLOYER_GENERATED_ROLE;
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
  "3765bd2e455abb91024dd74ee6ed7172203334f7215712683cbf91a000f51bc6",
);
assert.match(result.permissionSetConfigurationSha256, /^[0-9a-f]{64}$/u);
assert.match(result.assignmentSha256, /^[0-9a-f]{64}$/u);
assert.match(result.requestPlanSha256, /^[0-9a-f]{64}$/u);
assert.match(result.packageBindingSha256, /^[0-9a-f]{64}$/u);
assert.equal(
  result.requestPlanSha256,
  "13f85ccbeb1b89ec68611450ae57062b06097cad071cecb05966b9b6e9c0d93d",
);
assert.equal(
  result.packageBindingSha256,
  "00b4752c247699f4585b39d2aa18e0ed2d416b392aef31e5d423e7c88cde7f14",
);
assert.equal(result.deployerGeneratedRoleArn, deployerGeneratedRoleArn);

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
  "iam:TagRole",
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
  "iam:UntagRole",
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
assert.equal(policyJson.includes(deployerGeneratedRoleArn), true);
assert.equal(policyJson.includes(instanceArn), true);
assert.equal(policyJson.includes(deployerPermissionSetArn), true);
assert.equal(policyJson.includes(`arn:aws:sso:::account/${accountId}`), true);

const createAndTagStatement = result.administratorPermissionsPolicy.Statement[0];
assert.equal(createAndTagStatement.Sid, "CreateOnlyTaggedQuickLaunchImagePublisherRole");
assert.deepEqual(createAndTagStatement.Action, ["iam:CreateRole", "iam:TagRole"]);
assert.equal(
  createAndTagStatement.Resource,
  `arn:aws:iam::${accountId}:role/PoHQuickLaunchImagePublisherRole`,
);
assert.deepEqual(createAndTagStatement.Condition, {
  StringEquals: {
    "aws:RequestTag/network": "base-sepolia",
    "aws:RequestTag/purpose": "image-publisher",
    "aws:RequestTag/release": "poh-quick-launch-v1",
  },
  "ForAllValues:StringEquals": {
    "aws:TagKeys": ["network", "purpose", "release"],
  },
  Null: { "iam:PermissionsBoundary": "true" },
});

type RenderedPolicyStatement = {
  Effect: string;
  Action: string | string[];
  Resource: string | string[];
};
const renderedPolicy = JSON.parse(policyJson) as { Statement: RenderedPolicyStatement[] };
const values = (value: string | string[]) => (Array.isArray(value) ? value : [value]);
const allowsActionOnResource = (action: string, resource: string) =>
  renderedPolicy.Statement.some(
    (statement) =>
      statement.Effect === "Allow" &&
      values(statement.Action).includes(action) &&
      values(statement.Resource).includes(resource),
  );

assert.equal(allowsActionOnResource("iam:GetRole", deployerGeneratedRoleArn), true);
for (const unrelatedRoleArn of [
  `arn:aws:iam::${accountId}:role/PoHQuickLaunchBootstrapRole`,
  `arn:aws:iam::${accountId}:role/${QUICK_LAUNCH_DEPLOYER_GENERATED_ROLE}`,
  `arn:aws:iam::${accountId}:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PoHQuickLaunchDeployer_other`,
  `arn:aws:iam::000000000000:role/aws-reserved/sso.amazonaws.com/${QUICK_LAUNCH_DEPLOYER_GENERATED_ROLE}`,
]) {
  assert.equal(
    allowsActionOnResource("iam:GetRole", unrelatedRoleArn),
    false,
    `unrelated role must fail closed: ${unrelatedRoleArn}`,
  );
}
for (const mutatingAction of [
  "iam:AttachRolePolicy",
  "iam:DeleteRole",
  "iam:PutRolePermissionsBoundary",
  "iam:PutRolePolicy",
  "iam:TagRole",
  "iam:UntagRole",
  "iam:UpdateAssumeRolePolicy",
  "iam:UpdateRole",
]) {
  assert.equal(
    allowsActionOnResource(mutatingAction, deployerGeneratedRoleArn),
    false,
    `generated deployer role must deny ${mutatingAction}`,
  );
}

type RequestTags = Record<string, string>;
const requestTagsSatisfyCreateAndTagContract = (requestTags: RequestTags) => {
  const requiredTags = {
    network: createAndTagStatement.Condition.StringEquals["aws:RequestTag/network"],
    purpose: createAndTagStatement.Condition.StringEquals["aws:RequestTag/purpose"],
    release: createAndTagStatement.Condition.StringEquals["aws:RequestTag/release"],
  };
  const allowedTagKeys = createAndTagStatement.Condition["ForAllValues:StringEquals"]["aws:TagKeys"];
  const requestedTagKeys = Object.keys(requestTags);
  return (
    requestedTagKeys.length === allowedTagKeys.length &&
    requestedTagKeys.every((key) => allowedTagKeys.includes(key as (typeof allowedTagKeys)[number])) &&
    Object.entries(requiredTags).every(([key, value]) => requestTags[key] === value)
  );
};

const exactPublisherTags = {
  network: "base-sepolia",
  purpose: "image-publisher",
  release: "poh-quick-launch-v1",
};
assert.equal(requestTagsSatisfyCreateAndTagContract(exactPublisherTags), true);
for (const missingTag of Object.keys(exactPublisherTags)) {
  assert.equal(
    requestTagsSatisfyCreateAndTagContract(
      Object.fromEntries(
        Object.entries(exactPublisherTags).filter(([key]) => key !== missingTag),
      ),
    ),
    false,
    `missing ${missingTag} tag must fail closed`,
  );
}
for (const alteredTag of Object.keys(exactPublisherTags)) {
  assert.equal(
    requestTagsSatisfyCreateAndTagContract({ ...exactPublisherTags, [alteredTag]: "altered" }),
    false,
    `altered ${alteredTag} tag must fail closed`,
  );
}
assert.equal(
  requestTagsSatisfyCreateAndTagContract({ ...exactPublisherTags, extra: "forbidden" }),
  false,
  "an extra tag must fail closed",
);

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
