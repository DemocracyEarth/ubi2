import {
  QUICK_LAUNCH_AWS_REGION,
  QUICK_LAUNCH_IMAGE_PUBLISHER_POLICY,
  QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE,
  buildQuickLaunchImagePublisherRoleDocuments,
  canonicalJson,
  canonicalSha256,
} from "./quick-launch-image-release";

export const QUICK_LAUNCH_IAM_ADMINISTRATOR_SCHEMA =
  "org.proofofhumanity.quick-launch.iam-administrator-package/1" as const;
export const QUICK_LAUNCH_IAM_ADMINISTRATOR_PERMISSION_SET =
  "PoHQuickLaunchIamAdministrator" as const;
export const QUICK_LAUNCH_IAM_ADMINISTRATOR_SESSION = "PT1H" as const;
export const QUICK_LAUNCH_DEPLOYER_PERMISSION_SET = "PoHQuickLaunchDeployer" as const;

export const QUICK_LAUNCH_IAM_ADMINISTRATOR_TAGS = [
  { Key: "network", Value: "base-sepolia" },
  { Key: "purpose", Value: "iam-administrator" },
  { Key: "release", Value: "poh-quick-launch-v1" },
] as const;

export const QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE_TAGS = [
  { Key: "network", Value: "base-sepolia" },
  { Key: "purpose", Value: "image-publisher" },
  { Key: "release", Value: "poh-quick-launch-v1" },
] as const;

type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

type JsonObject = { [key: string]: JsonValue };

interface PolicyObject extends JsonObject {
  Version: "2012-10-17";
  Statement: JsonObject[];
}

export interface QuickLaunchIamAdministratorPackageInput {
  accountId?: string;
  identityCenterRegion?: string;
  instanceArn?: string;
  deployerPermissionSetArn?: string;
  administratorPrincipalId?: string;
  currentDeployerPolicy?: unknown;
  expectedCurrentDeployerPolicySha256?: string;
}

const ACCOUNT_ID = /^[0-9]{12}$/u;
const SHA256 = /^[0-9a-f]{64}$/u;
const INSTANCE_ARN = /^arn:aws:sso:::instance\/(ssoins-[A-Za-z0-9.-]{16})$/u;
const PERMISSION_SET_ARN =
  /^arn:aws:sso:::permissionSet\/(ssoins-[A-Za-z0-9.-]{16})\/(ps-[A-Za-z0-9./-]{16})$/u;
const PRINCIPAL_ID =
  /^(?:[0-9a-f]{10}-)?[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$/u;

function cloneJson<T extends JsonValue>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

function policyObject(value: unknown): PolicyObject {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("Current deployer inline policy must be one JSON object.");
  }
  const policy = cloneJson(value as JsonObject);
  if (policy.Version !== "2012-10-17" || !Array.isArray(policy.Statement)) {
    throw new Error(
      'Current deployer inline policy must use Version "2012-10-17" and a Statement array.',
    );
  }
  for (const statement of policy.Statement) {
    if (!statement || typeof statement !== "object" || Array.isArray(statement)) {
      throw new Error("Every current deployer policy statement must be one JSON object.");
    }
  }
  return policy as PolicyObject;
}

function stringValues(value: JsonValue | undefined): string[] {
  if (typeof value === "string") return [value];
  if (!Array.isArray(value)) return [];
  return value.filter((entry): entry is string => typeof entry === "string");
}

function includesValue(value: JsonValue, expected: string): boolean {
  if (value === expected) return true;
  if (Array.isArray(value)) return value.some((entry) => includesValue(entry, expected));
  if (value && typeof value === "object") {
    return Object.values(value).some((entry) => includesValue(entry, expected));
  }
  return false;
}

function mergePublisherGrant(
  currentPolicyInput: unknown,
  expectedCurrentPolicySha256: string,
  publisherRoleArn: string,
  grant: JsonObject,
) {
  const currentPolicy = policyObject(currentPolicyInput);
  if (!SHA256.test(expectedCurrentPolicySha256)) {
    throw new Error("Expected current deployer policy SHA-256 must be 64 lowercase hex characters.");
  }
  const currentPolicySha256 = canonicalSha256(currentPolicy);
  if (currentPolicySha256 !== expectedCurrentPolicySha256) {
    throw new Error("Current deployer policy does not match its independently approved SHA-256.");
  }

  const statements = currentPolicy.Statement;
  const seenSids = new Set<string>();
  for (const statement of statements) {
    const sid = statement.Sid;
    if (typeof sid !== "string" || sid.length === 0) {
      throw new Error("Every current deployer policy statement must have a non-empty Sid.");
    }
    if (seenSids.has(sid)) throw new Error(`Current deployer policy contains duplicate Sid ${sid}.`);
    seenSids.add(sid);

    const actions = stringValues(statement.Action);
    const resources = stringValues(statement.Resource);
    if (actions.includes("sts:AssumeRole") && resources.includes("*")) {
      throw new Error("Current deployer policy contains wildcard sts:AssumeRole authority.");
    }
  }

  const expectedGrant = cloneJson(grant);
  const existingTarget = statements.find(
    (statement) =>
      statement.Sid === "AssumeQuickLaunchImagePublisher" ||
      includesValue(statement, publisherRoleArn),
  );
  let grantAlreadyPresent = false;
  if (existingTarget) {
    if (canonicalJson(existingTarget) !== canonicalJson(expectedGrant)) {
      throw new Error("Current deployer policy contains a conflicting image-publisher grant.");
    }
    grantAlreadyPresent = true;
  }

  const updatedPolicy = cloneJson(currentPolicy);
  if (!grantAlreadyPresent) {
    updatedPolicy.Statement.push(expectedGrant);
  }
  const updatedPolicyBytes = Buffer.byteLength(canonicalJson(updatedPolicy), "utf8");
  if (updatedPolicyBytes > 32_768) {
    throw new Error("Merged deployer inline policy exceeds the IAM Identity Center 32,768-byte limit.");
  }

  return {
    currentPolicy,
    currentPolicySha256,
    updatedPolicy,
    updatedPolicySha256: canonicalSha256(updatedPolicy),
    updatedPolicyBytes,
    grantAlreadyPresent,
  };
}

export function buildQuickLaunchIamAdministratorPackage(
  input: QuickLaunchIamAdministratorPackageInput,
) {
  const accountId = input.accountId?.trim() ?? "";
  if (!ACCOUNT_ID.test(accountId)) throw new Error("Quick Launch AWS account must be 12 digits.");
  if (input.identityCenterRegion !== QUICK_LAUNCH_AWS_REGION) {
    throw new Error(`IAM Identity Center region must be exactly ${QUICK_LAUNCH_AWS_REGION}.`);
  }

  const instanceArn = input.instanceArn?.trim() ?? "";
  const instanceMatch = instanceArn.match(INSTANCE_ARN);
  if (!instanceMatch) throw new Error("IAM Identity Center instance ARN is invalid.");

  const deployerPermissionSetArn = input.deployerPermissionSetArn?.trim() ?? "";
  const permissionSetMatch = deployerPermissionSetArn.match(PERMISSION_SET_ARN);
  if (!permissionSetMatch) throw new Error("PoHQuickLaunchDeployer permission-set ARN is invalid.");
  if (permissionSetMatch[1] !== instanceMatch[1]) {
    throw new Error("Permission set and IAM Identity Center instance identifiers do not match.");
  }

  const administratorPrincipalId = input.administratorPrincipalId?.trim() ?? "";
  if (!PRINCIPAL_ID.test(administratorPrincipalId)) {
    throw new Error("Administrator assignment principal ID is invalid.");
  }

  const publisher = buildQuickLaunchImagePublisherRoleDocuments(accountId);
  const publisherRoleArn = `arn:aws:iam::${accountId}:role/${QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE}`;
  const accountResourceArn = `arn:aws:sso:::account/${accountId}`;
  const regionCondition = {
    StringEquals: { "aws:RequestedRegion": QUICK_LAUNCH_AWS_REGION },
  } as const;

  const administratorPermissionsPolicy = {
    Version: "2012-10-17",
    Statement: [
      {
        Sid: "CreateOnlyTaggedQuickLaunchImagePublisherRole",
        Effect: "Allow",
        // IAM authorizes tags supplied to CreateRole through iam:TagRole as well. Keep both actions
        // behind the same exact role, request-tag and tag-key constraints.
        Action: ["iam:CreateRole", "iam:TagRole"],
        Resource: publisherRoleArn,
        Condition: {
          StringEquals: {
            "aws:RequestTag/network": "base-sepolia",
            "aws:RequestTag/purpose": "image-publisher",
            "aws:RequestTag/release": "poh-quick-launch-v1",
          },
          "ForAllValues:StringEquals": {
            "aws:TagKeys": ["network", "purpose", "release"],
          },
          Null: { "iam:PermissionsBoundary": "true" },
        },
      },
      {
        Sid: "InspectOnlyQuickLaunchImagePublisherRole",
        Effect: "Allow",
        Action: [
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:ListRoleTags",
        ],
        Resource: publisherRoleArn,
      },
      {
        Sid: "ConfigureOnlyTaggedQuickLaunchImagePublisherRole",
        Effect: "Allow",
        Action: "iam:PutRolePolicy",
        Resource: publisherRoleArn,
        Condition: {
          StringEquals: {
            "aws:ResourceTag/network": "base-sepolia",
            "aws:ResourceTag/purpose": "image-publisher",
            "aws:ResourceTag/release": "poh-quick-launch-v1",
          },
        },
      },
      {
        Sid: "InspectOnlyQuickLaunchDeployerPermissionSet",
        Effect: "Allow",
        Action: ["sso:DescribePermissionSet", "sso:GetInlinePolicyForPermissionSet"],
        Resource: [instanceArn, deployerPermissionSetArn],
        Condition: regionCondition,
      },
      {
        Sid: "ReplaceOnlyQuickLaunchDeployerInlinePolicy",
        Effect: "Allow",
        Action: "sso:PutInlinePolicyToPermissionSet",
        Resource: [instanceArn, deployerPermissionSetArn],
        Condition: regionCondition,
      },
      {
        Sid: "ProvisionOnlyQuickLaunchDeployerToApprovedAccount",
        Effect: "Allow",
        Action: "sso:ProvisionPermissionSet",
        Resource: [accountResourceArn, instanceArn, deployerPermissionSetArn],
        Condition: regionCondition,
      },
      {
        Sid: "ObserveOnlyIdentityCenterProvisioningStatus",
        Effect: "Allow",
        Action: "sso:DescribePermissionSetProvisioningStatus",
        Resource: instanceArn,
        Condition: regionCondition,
      },
    ],
  } as const;

  const merged = mergePublisherGrant(
    input.currentDeployerPolicy,
    input.expectedCurrentDeployerPolicySha256?.trim() ?? "",
    publisherRoleArn,
    publisher.deployerAssumeRoleGrant.Statement[0] as unknown as JsonObject,
  );

  const permissionSetConfiguration = {
    Name: QUICK_LAUNCH_IAM_ADMINISTRATOR_PERMISSION_SET,
    Description:
      "One-hour Quick Launch publisher-role creation and exact deployer permission-set update only.",
    SessionDuration: QUICK_LAUNCH_IAM_ADMINISTRATOR_SESSION,
    Tags: QUICK_LAUNCH_IAM_ADMINISTRATOR_TAGS,
  } as const;
  const assignment = {
    InstanceArn: instanceArn,
    TargetId: accountId,
    TargetType: "AWS_ACCOUNT",
    PermissionSetArnFrom: "CreatePermissionSet.PermissionSet.PermissionSetArn",
    PrincipalType: "USER",
    PrincipalId: administratorPrincipalId,
  } as const;
  const roleCreationRequest = {
    RoleName: QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE,
    AssumeRolePolicyDocument: publisher.trustPolicy,
    Description: "One-hour publisher for the PoH Quick Launch Base Sepolia API image.",
    MaxSessionDuration: 3600,
    Tags: QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE_TAGS,
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
      {
        order: 3,
        api: "sso-admin:CreateAccountAssignment",
        input: assignment,
      },
      {
        order: 4,
        api: "sso-admin:DescribeAccountAssignmentCreationStatus",
        input: { InstanceArn: instanceArn, AccountAssignmentCreationRequestIdFrom: "step-3" },
        requiredStatus: "SUCCEEDED",
      },
    ],
    afterFreshAdministratorLogin: [
      { order: 1, api: "iam:CreateRole", input: roleCreationRequest },
      {
        order: 2,
        api: "iam:PutRolePolicy",
        input: {
          RoleName: QUICK_LAUNCH_IMAGE_PUBLISHER_ROLE,
          PolicyName: QUICK_LAUNCH_IMAGE_PUBLISHER_POLICY,
          PolicyDocument: publisher.permissionsPolicy,
        },
      },
      {
        order: 3,
        api: "sso-admin:PutInlinePolicyToPermissionSet",
        input: {
          InstanceArn: instanceArn,
          PermissionSetArn: deployerPermissionSetArn,
          InlinePolicy: merged.updatedPolicy,
        },
      },
      {
        order: 4,
        api: "sso-admin:ProvisionPermissionSet",
        input: {
          InstanceArn: instanceArn,
          PermissionSetArn: deployerPermissionSetArn,
          TargetId: accountId,
          TargetType: "AWS_ACCOUNT",
        },
      },
      {
        order: 5,
        api: "sso-admin:DescribePermissionSetProvisioningStatus",
        input: {
          InstanceArn: instanceArn,
          ProvisionPermissionSetRequestIdFrom: "step-4",
        },
        requiredStatus: "SUCCEEDED",
      },
    ],
  } as const;

  const packageBinding = {
    schema: QUICK_LAUNCH_IAM_ADMINISTRATOR_SCHEMA,
    accountId,
    region: QUICK_LAUNCH_AWS_REGION,
    instanceArn,
    deployerPermissionSetArn,
    administratorPrincipalId,
    permissionSetConfiguration,
    permissionSetConfigurationSha256: canonicalSha256(
      permissionSetConfiguration as unknown as JsonValue,
    ),
    administratorPermissionsPolicySha256: canonicalSha256(
      administratorPermissionsPolicy as unknown as JsonValue,
    ),
    assignmentSha256: canonicalSha256(assignment),
    publisherTrustPolicySha256: publisher.trustPolicySha256,
    publisherPermissionsPolicySha256: publisher.permissionsPolicySha256,
    deployerAssumeRoleGrantSha256: publisher.deployerAssumeRoleGrantSha256,
    currentDeployerPolicySha256: merged.currentPolicySha256,
    updatedDeployerPolicySha256: merged.updatedPolicySha256,
    requestPlanSha256: canonicalSha256(requestPlan as unknown as JsonValue),
  } as const;

  return {
    ...packageBinding,
    packageBindingSha256: canonicalSha256(packageBinding as unknown as JsonValue),
    transactionFree: true,
    mutatesAws: false,
    applyAuthorized: false,
    pauseBeforeApply: true,
    residualAuthorizationLimits: [
      "IAM cannot authorize iam:CreateRole by trust-policy bytes.",
      "IAM cannot authorize iam:PutRolePolicy by policy name or policy-document bytes.",
      "IAM Identity Center cannot authorize sso:PutInlinePolicyToPermissionSet by replacement-policy bytes.",
    ],
    permissionSetConfiguration,
    administratorPermissionsPolicy,
    assignment,
    publisherRole: {
      roleCreationRequest,
      inlinePolicyName: publisher.inlinePolicyName,
      permissionsPolicy: publisher.permissionsPolicy,
      trustPolicySha256: publisher.trustPolicySha256,
      permissionsPolicySha256: publisher.permissionsPolicySha256,
    },
    deployerPolicyUpdate: {
      expectedPermissionSetName: QUICK_LAUNCH_DEPLOYER_PERMISSION_SET,
      currentPolicy: merged.currentPolicy,
      currentPolicySha256: merged.currentPolicySha256,
      exactGrant: publisher.deployerAssumeRoleGrant.Statement[0],
      exactGrantSha256: publisher.deployerAssumeRoleGrantSha256,
      grantAlreadyPresent: merged.grantAlreadyPresent,
      updatedPolicy: merged.updatedPolicy,
      updatedPolicySha256: merged.updatedPolicySha256,
      updatedPolicyBytes: merged.updatedPolicyBytes,
    },
    requestPlan,
  };
}
