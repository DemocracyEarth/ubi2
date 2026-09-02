# Quick Launch ECS task execution role contract

This runbook defines the only IAM role that the transaction-disabled Base Sepolia API stack may use.
The role is provisioned and approved separately. The application stack accepts its ARN through
`TaskExecutionRoleArn`; it contains no `AWS::IAM::*` resource and cannot create, update, attach or
delete IAM policy.

This is not the CloudFormation deployment role and never belongs in Amplify. Its fixed role name is
`PoHQuickLaunchTaskExecutionRole` (an approved IAM path may precede the name). It is an ECS **task
execution role** used by the ECS agent before the container starts. The application has no task role
and receives no AWS API credentials.

## Account and region invariant

An IAM role ARN is global and therefore has an empty region field:

```text
arn:aws:iam::<ACCOUNT_ID>:role/[APPROVED_PATH/]PoHQuickLaunchTaskExecutionRole
```

An ARN such as `arn:aws:iam:us-east-1:...` is invalid and must be rejected. Regional binding comes
from every resource the role may use: the ECR repository, CloudWatch log stream, issuer and sponsor
secrets, and optional customer-managed KMS keys must all be in the same account and `us-east-1`.
The checked-in preflight validates those bindings without calling AWS or emitting any supplied ARN:

```shell
pnpm --silent --filter @ubi2/proofofhumanity quick-launch:execution-role-preflight \
  > <approved-redacted-evidence-path>
```

Load these inputs only through the protected deployment environment; do not type values into the
command, enable shell tracing, print the environment, or commit a dotenv file:

| Variable | Required contract |
|---|---|
| `QUICK_LAUNCH_AWS_ACCOUNT_ID` | exact 12-digit staging account reported by the approved deployment session |
| `QUICK_LAUNCH_AWS_REGION` | exactly `us-east-1` |
| `QUICK_LAUNCH_TASK_EXECUTION_ROLE_ARN` | same-account, regionless ARN ending in `PoHQuickLaunchTaskExecutionRole` |
| `QUICK_LAUNCH_CONTAINER_IMAGE_URI` | same-account/us-east-1 ECR URI pinned by `@sha256:` |
| `QUICK_LAUNCH_ISSUER_SECRET_ARN` | same-account/us-east-1 approved issuer secret reference |
| `QUICK_LAUNCH_SPONSOR_SECRET_ARN` | distinct same-account/us-east-1 approved sponsor secret reference |
| `QUICK_LAUNCH_ISSUER_KMS_KEY_ARN` | optional same-account/us-east-1 customer-managed key ARN |
| `QUICK_LAUNCH_SPONSOR_KMS_KEY_ARN` | optional same-account/us-east-1 customer-managed key ARN |

The output is an allowlisted record containing only Boolean checks, blocker codes and the fixed public
region. A `ready: true` record proves ARN structure and resource binding only. It does not prove the
role exists or that its live trust/permissions documents match the contract below; those are separate
metadata-only approval gates.

## Exact trust policy

The trust document has exactly one allow statement. Replace placeholders through the protected IAM
provisioning workflow; do not broaden the source account, source region, principal or action.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowQuickLaunchEcsTasks",
      "Effect": "Allow",
      "Principal": { "Service": "ecs-tasks.amazonaws.com" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "aws:SourceAccount": "<ACCOUNT_ID>" },
        "ArnLike": { "aws:SourceArn": "arn:aws:ecs:us-east-1:<ACCOUNT_ID>:*" }
      }
    }
  ]
}
```

No user, workforce role, CloudFormation role, Lambda service or other AWS principal may assume it.

## Exact permissions policy

Attach no AWS-managed or customer-managed policy. The role has exactly one inline policy named
`PoHQuickLaunchTaskExecution`, containing only:

| Purpose | Allowed actions | Exact resource scope |
|---|---|---|
| ECR authorization | `ecr:GetAuthorizationToken` | `*` (the only permitted wildcard resource) |
| Pull reviewed image | `ecr:BatchCheckLayerAvailability`, `ecr:GetDownloadUrlForLayer`, `ecr:BatchGetImage` | the one approved us-east-1 ECR repository ARN |
| Write task logs | `logs:CreateLogStream`, `logs:PutLogEvents` | `arn:aws:logs:us-east-1:<ACCOUNT_ID>:log-group:/ubi2/poh-quick-launch-api:log-stream:*` |
| Inject signers | `secretsmanager:GetSecretValue` | exactly the distinct issuer and sponsor secret ARNs |
| Decrypt signers | `kms:Decrypt`, only when a secret uses a customer-managed key | exactly those one or two key ARNs, with `kms:ViaService` equal to `secretsmanager.us-east-1.amazonaws.com` |

The log-stream suffix is the only other required resource wildcard. There is no `ecr:*`, `logs:*`,
`secretsmanager:*`, unscoped `kms:Decrypt`, `iam:*`, `sts:*`, `ssm:*`, write permission, secret-listing
permission, task-role permission, ECS Exec permission or permission to create a log group. If either
secret uses the default AWS-managed Secrets Manager key, omit the KMS statement entirely.

The protected policy review must compare decoded policy JSON—not a policy name or console summary—to
this action/resource/condition allowlist. It must also prove:

- zero attached managed policies;
- exactly the one inline policy named above;
- any permissions boundary is independently hash-bound and is not used to excuse an overbroad inline policy;
- the trust policy matches the exact account and us-east-1 ECS source ARN;
- every regional ARN matches the account used by the approved deployment principal;
- CloudTrail and IAM metadata review did not require `secretsmanager:GetSecretValue` or `kms:Decrypt`
  by the human/deployment role.

Record only Boolean results plus hashes of the canonical trust and permissions documents in public
evidence. Keep documents containing raw secret references in the approved protected location.

## Failure and change handling

Any preflight blocker, extra statement, attached managed policy, wrong account, cross-region resource,
wildcard secret/key/repository, missing source condition or policy-document retrieval failure blocks the
change set. Do not substitute the AWS-managed `AmazonECSTaskExecutionRolePolicy`: its repository/log
scope is broader than this contract.

Changes to the role are an independent reviewed change. First remove the canonical API proxy or keep
the transaction-disabled stack at zero desired tasks, then approve the new immutable policy hashes,
rerun this preflight, inspect a CloudFormation change set and perform the restart/redaction drill. A
green local test is never evidence that the live role or service is ready.
