# Quick Launch prerequisite remediation package

This package prepares—without applying—three missing AWS prerequisites for the transaction-disabled
Base Sepolia Quick Launch API origin:

1. two distinct, **empty** Secrets Manager containers whose values the release owner enters later through
   separate AWS protected interfaces;
2. a hash-bound approval of exactly two existing, non-Fobal public subnets in distinct Availability
   Zones; and
3. one fixed-name `PoHQuickLaunchCloudFormationDeploymentRole` that can service only the existing
   `poh-quick-launch-api` stack contract.

The renderer invokes no AWS API. It never accepts a secret value. Every mutating request in its plan has
`actionAuthorized=false` and names the API immediately before which the operator must pause. Rendering,
testing or merging this package does not authorize any AWS mutation and is not live-readiness evidence.

## Frozen boundary

| Field | Exact value |
|---|---|
| Account | `368426158592` |
| Region | `us-east-1` |
| Network | Base Sepolia only |
| Temporary permission set | `PoHQuickLaunchPrerequisiteAdministrator` |
| Session | `PT1H` |
| Issuer container name | `/ubi2/poh-quick-launch-v1/issuer-private-key` |
| Sponsor container name | `/ubi2/poh-quick-launch-v1/sponsor-private-key` |
| CloudFormation service role | `PoHQuickLaunchCloudFormationDeploymentRole` |
| CloudFormation inline policy | `PoHQuickLaunchCloudFormationDeployment` |
| Future stack name | `poh-quick-launch-api` |
| Future task execution role | `PoHQuickLaunchTaskExecutionRole` |
| Public API record | `quick-launch-api.proofofhumanity.org` |

The temporary administrator is not allowed to assume or pass the deployment role. It has no
CloudFormation control-plane, ECS, ELB, log, ECR, KMS, SSM, funding, blockchain, mainnet or secret-value
authority. It can prepare only the exact containers, subnet tags and role described below.

## Policy 1 — temporary prerequisite administrator

The full canonical JSON is the `administratorPermissionsPolicy` field rendered by
[`quick-launch-prerequisite-remediation.ts`](../../apps/proofofhumanity/app/quick-launch-prerequisite-remediation.ts).
Its complete allowlist is:

| Sid | Actions | Resource / condition boundary |
|---|---|---|
| `CreateOnlyEmptyIssuerSecretContainer` | `secretsmanager:CreateSecret` | exact issuer name/ARN prefix, `us-east-1`, exact `network`, `release`, `purpose=issuer` tags, no supplied KMS key |
| `CreateOnlyEmptySponsorSecretContainer` | `secretsmanager:CreateSecret` | distinct exact sponsor name/ARN prefix, same boundary with `purpose=sponsor` |
| `TagOnlyIssuerSecretContainer` | `secretsmanager:TagResource` | dependent create-time tag action on only the issuer name prefix and exact full issuer tag set |
| `TagOnlySponsorSecretContainer` | `secretsmanager:TagResource` | dependent create-time tag action on only the sponsor name prefix and exact full sponsor tag set |
| `InspectOnlyQuickLaunchSecretContainers` | `DescribeSecret`, `ListSecretVersionIds` | only the two exact name prefixes; no value read |
| `InspectOnlyUsEast1PublicSubnetEvidence` | four EC2 `Describe*` actions | unavoidable metadata-only `Resource=*`, region-bound |
| `ApproveOnlyTwoExactQuickLaunchSubnets` | `ec2:CreateTags` | exactly two protected subnet ARNs and exactly three Quick Launch tags |
| `CreateOnlyTaggedQuickLaunchCloudFormationDeploymentRole` | `iam:CreateRole`, `iam:TagRole` | exact role ARN, exact tags, no permissions boundary in request |
| `ConfigureOnlyTaggedQuickLaunchCloudFormationDeploymentRole` | `iam:PutRolePolicy` | exact already-tagged role only |
| `InspectOnlyQuickLaunchCloudFormationDeploymentRole` | five IAM read actions | exact role only |

No allow statement contains `GetSecretValue`, `PutSecretValue`, `UpdateSecret`, `DeleteSecret`,
unconstrained tagging, `UntagResource`, `DeleteTags`, `PassRole`, `AssumeRole`, managed-policy attachment, trust
updates, role/policy deletion or unrelated resources. EC2 metadata discovery is the policy's only
`Resource=*` statement.

### Empty-container contract

Each rendered `CreateSecret` request contains only `Name`, `Description`, and the exact tags:

```json
{
  "network": "base-sepolia",
  "release": "poh-quick-launch-v1",
  "purpose": "issuer | sponsor"
}
```

It contains no `SecretString`, `SecretBinary`, or `KmsKeyId`. Omitting `KmsKeyId` selects the
Secrets Manager AWS-managed key, so the later task execution role does not require a customer-managed
KMS grant for these containers. Immediately after each separately authorized creation, call only
`DescribeSecret` and `ListSecretVersionIds`: exact metadata must match and the version list must be empty.
Only then may the release owner enter that one value manually using an approved protected AWS interface.
Never paste or print it in a terminal, ticket, renderer input, evidence record or chat.

AWS IAM has no condition key that proves `SecretString` and `SecretBinary` were omitted. The compensating
control is byte-for-byte action-time request comparison plus the immediate zero-version read-back. Any
payload field or existing version blocks the lane.

## Exactly-two-subnet approval

The renderer accepts exactly two evidence records. Both must:

- belong to the one approved VPC;
- have distinct `us-east-1` Availability Zones and distinct subnet IDs;
- have `MapPublicIpOnLaunch=true`;
- have an active `0.0.0.0/0` route through a recorded internet gateway; and
- be explicitly verified as not tagged for, named for, or shared with Fobal.

The redacted approval record hashes the VPC, subnet, route-table and internet-gateway IDs, but leaves the
two Availability Zones and boolean checks public. The only planned subnet mutation is applying exactly
`network=base-sepolia`, `release=poh-quick-launch-v1`, and `purpose=api-origin` to those two ARN-bound
subnets. Pause immediately before that single `ec2:CreateTags` request. A fixture pair is never live
approval; the live protected pair must produce a new reviewed `subnetApprovalSha256`.

## Policy 2 — CloudFormation deployment-role trust

The complete trust document is:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowOnlyQuickLaunchCloudFormationStack",
    "Effect": "Allow",
    "Principal": { "Service": "cloudformation.amazonaws.com" },
    "Action": "sts:AssumeRole",
    "Condition": {
      "StringEquals": { "aws:SourceAccount": "368426158592" },
      "ArnLike": {
        "aws:SourceArn": "arn:aws:cloudformation:us-east-1:368426158592:stack/poh-quick-launch-api/*"
      }
    }
  }]
}
```

The role has a 3,600-second maximum session and exact tags
`network=base-sepolia`, `release=poh-quick-launch-v1`, and
`purpose=cloudformation-deployment`. It trusts no workforce, root, Fobal, ECS task or external account
principal.

## Policy 3 — CloudFormation deployment-role permissions

The full canonical JSON is rendered as
`cloudFormationDeploymentRole.permissionsPolicy`. Its complete capability groups are:

| Purpose | Exact capability boundary |
|---|---|
| Pass execution role | `iam:PassRole` only for `PoHQuickLaunchTaskExecutionRole`, only to `ecs-tasks.amazonaws.com` |
| Read network metadata | four EC2 `Describe*` actions, `us-east-1` only |
| Security groups | create only in the approved VPC; manage/tag only generated same-account security groups carrying the Quick Launch release tag |
| Logs | describe plus create/update/tag/delete only `/ubi2/poh-quick-launch-api` |
| ECS cluster | create/describe/update/tag/delete only `poh-quick-launch-api` |
| ECS task definition | register/manage only family `poh-quick-launch-api`; exact Base Sepolia/release tags |
| ECS service | create/describe/update/tag/delete only service `poh-quick-launch-api` in that cluster |
| Application load balancer | create/manage only name `poh-quick-launch-api`; internet-facing and exactly the two approved subnet IDs |
| Target group | create/manage only name `poh-quick-launch-api` |
| Listeners | create/manage only the named load balancer's HTTP/HTTPS listeners |
| ELB tags | only the `release=poh-quick-launch-v1` tag on the exact load-balancer/target-group ARN patterns |
| DNS | only `A` record `quick-launch-api.proofofhumanity.org` in the one approved hosted zone; create/upsert/delete for rollback |
| Route 53 reads | only the approved hosted zone and change-status ARNs |

Delete actions exist only where CloudFormation needs rollback/removal of the named stack resources. The
role has no Secrets Manager, KMS, ECR, SSO, CloudFormation control-plane, SSM, Lambda, access-key,
managed-IAM, VPC/subnet creation, instance, funding, blockchain or mainnet authority. It cannot create a
service-linked role; the standard ECS and ELB service-linked roles must already exist and pass read-only
preflight.

Generated security-group, load-balancer, target-group and listener suffixes require narrowly named/tagged
ARN wildcards. Current AWS authorization rules also require wildcard resources for several metadata-only
`Describe*` calls. The package keeps these read-only and region-bound. The policy's canonical compact JSON
is 8,451 bytes in the regression fixture, below IAM's 10,240-byte role-inline-policy limit.

The service role cannot make IAM inspect every ECS task-definition field, listener certificate, service
network parameter or Route 53 alias value. Before any later change-set execution, independently hash and
review the complete change set and every parameter: the exact two subnets, task role, issuer/sponsor ARNs,
certificate, image digest, public credential-free Base Sepolia RPC, transaction-disabled flag and
attestation hashes. This package grants no change-set creation or execution.

## Protected inputs and transaction-free rendering

Provide only metadata through a protected, non-version-controlled environment:

| Variable | Contract |
|---|---|
| `QUICK_LAUNCH_AWS_ACCOUNT_ID` | exactly `368426158592` |
| `QUICK_LAUNCH_IDENTITY_CENTER_REGION` | exactly `us-east-1` |
| `QUICK_LAUNCH_IDENTITY_CENTER_INSTANCE_ARN` | exact live organization instance ARN |
| `QUICK_LAUNCH_PREREQUISITE_ADMINISTRATOR_PRINCIPAL_ID` | approved workforce USER ID |
| `QUICK_LAUNCH_VPC_ID` | one approved, non-Fobal VPC ID |
| `QUICK_LAUNCH_HOSTED_ZONE_ID` | public `proofofhumanity.org` hosted-zone ID |
| `QUICK_LAUNCH_PUBLIC_SUBNET_EVIDENCE_JSON` | exactly two protected evidence objects matching the checks above |

The JSON evidence object fields are `subnetId`, `availabilityZone`, `vpcId`, `routeTableId`,
`internetGatewayId`, `mapPublicIpOnLaunch`, `activeIpv4DefaultRoute`, and `fobalTagged`. Use a newly created
mode-0600 file or environment supplied by the protected executor. Do not enable shell tracing or print the
environment.

```sh
umask 077
pnpm --silent --filter @ubi2/proofofhumanity \
  quick-launch:prerequisite-remediation-package \
  > <NEW_PROTECTED_PATH>/quick-launch-prerequisite-remediation.json
```

The protected output shows every policy and request in full. Publish only the reviewed hashes and redacted
subnet approval. The deterministic regression fixture pins:

| Object | Fixture SHA-256 |
|---|---|
| Permission-set configuration | `5b321aff065afe25eb0ab969f19ba77aaa3955536ce68f0c634767b7fd1e68a2` |
| Administrator permissions | `78ae3d699a8c017ff3183bde937c903a1ee025c65bf4979ef54c7bf37e938eb5` |
| Assignment | `e312ced830226b58adf654c61a9beee81ba96f95c03dee94872542d72577f132` |
| Issuer empty-container request | `e46df92a3df0809950af66e24404d41e086c4bb92922f3e3009a3abab188156f` |
| Sponsor empty-container request | `ee6447efd85459f10201ff26ec0495736e2fd7d0349ca70a485c60fe6c3506ea` |
| Two-subnet approval | `983b2671ff407bf239922af50ed40c99d8de34c5ee1816edc9126b9c5f430797` |
| Deployment-role creation request | `d58f240e02f4df858f9a8d5dda7c3277603ef57d18530de52a624b2101b398b5` |
| Deployment-role trust | `1a5a246a03b411974f3ff8dd3ca795a60dede809b40313397f1955c949758f74` |
| Deployment-role permissions | `f149216e5e8030a39c8619d30cdbfbef0efb82e670129b33eae30c604a999227` |
| Paused request plan | `165570ab4b291794f1008b90d7d7053b1e1b0a496985cd4e09a809955e17f325` |
| Package binding | `eef9f0295ab679289849f46a43c23cb36753b6484cf22bccd6ca6888181e13f6` |

These are fixture hashes, not live AWS approval. Protected live identifiers necessarily change the
assignment, subnet approval, request plan and package binding.

## Administrator handoff and mutation pauses

Use an existing authorized non-root Identity Center administrator. Break-glass root requires separate,
explicit authorization and must be limited to the one confirmed call. At each numbered mutation below,
first re-read live state, compare the exact canonical request and hash, ask for action-time confirmation,
call that API exactly once, canonically read it back, then stop again:

1. `CreatePermissionSet` — then stop;
2. `PutInlinePolicyToPermissionSet` — then stop;
3. `CreateAccountAssignment` — observe only that request to terminal, then stop;
4. issuer `CreateSecret` with no value fields — verify zero versions, then stop;
5. sponsor `CreateSecret` with no value fields — verify zero versions and distinct ARN, then stop;
6. one `CreateTags` request for exactly the two approved subnets — read back, then stop;
7. `CreateRole` for only `PoHQuickLaunchCloudFormationDeploymentRole` — read trust/tags, then stop;
8. `PutRolePolicy` for only `PoHQuickLaunchCloudFormationDeployment` — read back canonical hash, verify
   no managed policies, then stop.

Do not combine calls or infer confirmation from approval of another step. Do not enter either secret value
until both empty containers have passed metadata/zero-version verification. Afterwards, use protected AWS
interfaces only and report solely version-stage and timestamp metadata—never bytes or raw references.

The next lane may render a transaction-disabled CloudFormation change set only after all prerequisites,
the task execution role, ACM certificate, service-linked roles, image scan and protected attestations pass.
It must still pause before change-set creation and again before execution.

## Failure-path gate

```sh
pnpm --filter @ubi2/proofofhumanity \
  test:quick-launch-prerequisite-remediation
```

The test pins every fixture hash and administrator action, proves missing/extra/altered tags fail closed,
rejects wrong accounts/regions, malformed metadata, duplicate/same-AZ/non-public/Fobal-tagged subnets, and
proves secret-value access, unrelated IAM, application deployment, image publication, mainnet and
transactions remain absent. A passing test is not evidence that a live prerequisite exists.
