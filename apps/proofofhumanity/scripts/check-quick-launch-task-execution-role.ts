import { assessQuickLaunchTaskExecutionRole } from "../app/quick-launch-task-execution-role";

const evidence = assessQuickLaunchTaskExecutionRole({
  deploymentAccountId: process.env.QUICK_LAUNCH_AWS_ACCOUNT_ID,
  deploymentRegion: process.env.QUICK_LAUNCH_AWS_REGION,
  taskExecutionRoleArn: process.env.QUICK_LAUNCH_TASK_EXECUTION_ROLE_ARN,
  containerImageUri: process.env.QUICK_LAUNCH_CONTAINER_IMAGE_URI,
  issuerSecretArn: process.env.QUICK_LAUNCH_ISSUER_SECRET_ARN,
  sponsorSecretArn: process.env.QUICK_LAUNCH_SPONSOR_SECRET_ARN,
  issuerKmsKeyArn: process.env.QUICK_LAUNCH_ISSUER_KMS_KEY_ARN,
  sponsorKmsKeyArn: process.env.QUICK_LAUNCH_SPONSOR_KMS_KEY_ARN,
});

// This record deliberately contains only booleans, blocker codes and the fixed staging region.
// Never add input ARNs, environment values or AWS API responses to this output.
console.log(JSON.stringify(evidence, null, 2));
if (!evidence.ready) process.exitCode = 1;
