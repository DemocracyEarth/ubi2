import {
  buildQuickLaunchPrerequisiteRemediationPackage,
  type QuickLaunchPublicSubnetEvidence,
} from "../app/quick-launch-prerequisite-remediation";

function subnetEvidence(): QuickLaunchPublicSubnetEvidence[] | undefined {
  const raw = process.env.QUICK_LAUNCH_PUBLIC_SUBNET_EVIDENCE_JSON?.trim();
  if (!raw) return undefined;
  const parsed: unknown = JSON.parse(raw);
  if (!Array.isArray(parsed)) throw new Error("Subnet evidence JSON must be an array.");
  return parsed as QuickLaunchPublicSubnetEvidence[];
}

const result = buildQuickLaunchPrerequisiteRemediationPackage({
  accountId: process.env.QUICK_LAUNCH_AWS_ACCOUNT_ID,
  identityCenterRegion: process.env.QUICK_LAUNCH_IDENTITY_CENTER_REGION,
  instanceArn: process.env.QUICK_LAUNCH_IDENTITY_CENTER_INSTANCE_ARN,
  administratorPrincipalId: process.env.QUICK_LAUNCH_PREREQUISITE_ADMINISTRATOR_PRINCIPAL_ID,
  vpcId: process.env.QUICK_LAUNCH_VPC_ID,
  hostedZoneId: process.env.QUICK_LAUNCH_HOSTED_ZONE_ID,
  publicSubnets: subnetEvidence(),
});

// This renderer invokes no AWS API and never accepts secret values. Its output contains protected
// identifiers, so write it only to a new mode-0600, non-version-controlled path.
console.log(JSON.stringify(result, null, 2));
