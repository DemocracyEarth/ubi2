import { readFileSync } from "node:fs";
import { buildQuickLaunchIamAdministratorPackage } from "../app/quick-launch-iam-administrator";

const currentPolicyPath = process.env.QUICK_LAUNCH_CURRENT_DEPLOYER_POLICY_PATH?.trim() ?? "";
if (!currentPolicyPath) {
  throw new Error("QUICK_LAUNCH_CURRENT_DEPLOYER_POLICY_PATH is required.");
}

const currentDeployerPolicy = JSON.parse(readFileSync(currentPolicyPath, "utf8")) as unknown;
const result = buildQuickLaunchIamAdministratorPackage({
  accountId: process.env.QUICK_LAUNCH_AWS_ACCOUNT_ID,
  identityCenterRegion: process.env.QUICK_LAUNCH_IDENTITY_CENTER_REGION,
  instanceArn: process.env.QUICK_LAUNCH_IDENTITY_CENTER_INSTANCE_ARN,
  deployerPermissionSetArn: process.env.QUICK_LAUNCH_DEPLOYER_PERMISSION_SET_ARN,
  administratorPrincipalId: process.env.QUICK_LAUNCH_IAM_ADMINISTRATOR_PRINCIPAL_ID,
  currentDeployerPolicy,
  expectedCurrentDeployerPolicySha256:
    process.env.QUICK_LAUNCH_EXPECTED_CURRENT_DEPLOYER_POLICY_SHA256,
});

// This local renderer never invokes AWS. Its output contains policy documents and an Identity Center
// principal identifier, so write it only to a protected, non-version-controlled path.
console.log(JSON.stringify(result, null, 2));
