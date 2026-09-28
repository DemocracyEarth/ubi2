import { buildQuickLaunchInfrastructureAdministratorPackage } from "../app/quick-launch-infrastructure-administrator";

function csv(name: string): string[] | undefined {
  const value = process.env[name]?.trim();
  return value ? value.split(",").map((entry) => entry.trim()) : undefined;
}

const result = buildQuickLaunchInfrastructureAdministratorPackage({
  accountId: process.env.QUICK_LAUNCH_AWS_ACCOUNT_ID,
  identityCenterRegion: process.env.QUICK_LAUNCH_IDENTITY_CENTER_REGION,
  instanceArn: process.env.QUICK_LAUNCH_IDENTITY_CENTER_INSTANCE_ARN,
  administratorPrincipalId:
    process.env.QUICK_LAUNCH_INFRASTRUCTURE_ADMINISTRATOR_PRINCIPAL_ID,
  issuerSecretArn: process.env.QUICK_LAUNCH_ISSUER_SECRET_ARN,
  sponsorSecretArn: process.env.QUICK_LAUNCH_SPONSOR_SECRET_ARN,
  issuerKmsKeyArn: process.env.QUICK_LAUNCH_ISSUER_KMS_KEY_ARN,
  sponsorKmsKeyArn: process.env.QUICK_LAUNCH_SPONSOR_KMS_KEY_ARN,
  vpcId: process.env.QUICK_LAUNCH_VPC_ID,
  subnetIds: csv("QUICK_LAUNCH_PUBLIC_SUBNET_IDS"),
  subnetAvailabilityZones: csv("QUICK_LAUNCH_PUBLIC_SUBNET_AVAILABILITY_ZONES"),
  hostedZoneId: process.env.QUICK_LAUNCH_HOSTED_ZONE_ID,
  cloudFormationDeploymentRoleArn:
    process.env.QUICK_LAUNCH_CLOUDFORMATION_DEPLOYMENT_ROLE_ARN,
});

// This renderer never invokes AWS. The rendered package contains protected resource identifiers and
// a workforce principal ID, so write it only to a protected, non-version-controlled path.
console.log(JSON.stringify(result, null, 2));
