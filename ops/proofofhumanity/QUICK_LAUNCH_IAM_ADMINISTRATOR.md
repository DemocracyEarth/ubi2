# Quick Launch IAM administrator permission set and assignment

This runbook prepares a one-hour IAM Identity Center permission set named
`PoHQuickLaunchIamAdministrator`. It is a narrow, temporary control-plane identity for creating and
inspecting only `PoHQuickLaunchImagePublisherRole`, and for merging the already frozen one-role
`sts:AssumeRole` grant into only the existing `PoHQuickLaunchDeployer` permission set. It cannot create
its own permission set or assignment.

The checked-in renderer is local and transaction-free. It never invokes AWS, retrieves a secret,
obtains an ECR token, pushes an image, creates an application resource, funds an account or submits a
blockchain transaction. **Stop before the first AWS write until an existing authorized administrator
or an explicitly authorized break-glass root session receives action-time confirmation.**

## Frozen staging boundary

The reviewed package is bound to:

| Field | Required value |
|---|---|
| AWS account | `368426158592` |
| IAM Identity Center region | `us-east-1` |
| Permission-set name | `PoHQuickLaunchIamAdministrator` |
| Session duration | `PT1H` (one hour) |
| Target role | `arn:aws:iam::368426158592:role/PoHQuickLaunchImagePublisherRole` |
| Target deployer permission set | existing `PoHQuickLaunchDeployer` only |
| Assignment | one existing workforce `USER` already assigned to `PoHQuickLaunchDeployer` in account `368426158592` |

For the currently reviewed Identity Center instance and deployer permission-set identifiers, the
canonical administrator inline-policy SHA-256 is:

```text
0fa2aa3bddfc22d7b4485888b7b5bb0550129e2ffe7d12c2f4e6e5fc84c70513
```

The earlier `9d02054700747aa01528b0a2b24a0973d143b42571676ccac575338eabb00d77`
policy and every package binding that includes it are superseded. That policy allowed `CreateRole` but
not the separate `TagRole` authorization AWS evaluates for tags supplied in the create request, so the
reviewed tagged request failed atomically and no publisher role was created.

In particular, the pre-correction live package binding
`724a8410121703cbac883adcb1e4d7830cdfed4ae25dd7e86789c968b90b871e` must not be reused. The
renderer and regression fixture now bind the corrected policy to request-plan SHA-256
`da29a85f10eb4c6beb697e0fb2ff5eb5c21b92af04b6336734346264bd21aa8f` and fixture package-binding
SHA-256 `2c9d6ee504e07d2cecb24e88f0e58c3ebd20990127e3f34db3683bf834473994`.
The latter is test-fixture evidence, not a live authorization value. Re-render the operational package
against the hash-verified protected current deployer policy and separately approve its new
`packageBindingSha256` before any AWS write.

If the live instance ARN or `PoHQuickLaunchDeployer` permission-set ARN differs from the reviewed
identifiers, the rendered hash differs. Stop and review the new identifiers and hash; do not substitute
another account, permission set or workforce principal.

## Exact effective permissions

The new permission set has no AWS-managed or customer-managed policies and no permissions boundary. It
contains exactly one inline policy rendered by
[`quick-launch-iam-administrator.ts`](../../apps/proofofhumanity/app/quick-launch-iam-administrator.ts).

| Purpose | Actions | Exact resource or condition |
|---|---|---|
| Create and tag the publisher role | `iam:CreateRole`, `iam:TagRole` | only the exact role ARN; both actions require exactly `network=base-sepolia`, `purpose=image-publisher`, and `release=poh-quick-launch-v1`; forbids a permissions boundary in the create request |
| Inspect the publisher role | `iam:GetRole`, `iam:GetRolePolicy`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:ListRoleTags` | only the exact role ARN |
| Install the publisher inline policy | `iam:PutRolePolicy` | only the exact role ARN and only while all three fixed resource tags match |
| Inspect the deployer policy | `sso:DescribePermissionSet`, `sso:GetInlinePolicyForPermissionSet` | only the exact Identity Center instance and existing deployer permission-set ARNs, requested in `us-east-1` |
| Replace and provision the reviewed deployer policy | `sso:PutInlinePolicyToPermissionSet`, `sso:ProvisionPermissionSet` | only the same instance/deployer permission set and account `368426158592`, requested in `us-east-1` |
| Observe asynchronous provisioning | `sso:DescribePermissionSetProvisioningStatus` | only the exact Identity Center instance, requested in `us-east-1` |

There is no wildcard resource. `iam:UntagRole` is not granted, and `iam:TagRole` cannot target another
role or submit missing, altered or additional tags. The permission set excludes `iam:PassRole`, trust-
policy updates, role updates/deletion, managed-policy creation/attachment, access-key operations,
Identity Center permission-set creation/deletion/assignment, Identity Store enumeration, ECR, Secrets
Manager, KMS, CloudFormation, ECS and every non-IAM resource service.

AWS documents Identity Center delegated administration using exact `PermissionSet`, `Instance`, and
`Account` resource ARNs. `PutInlinePolicyToPermissionSet` requires the instance and permission-set ARNs,
and a changed assigned permission set must be provisioned before its generated account role receives the
change. The package includes only those required resources and operations.

## Protected metadata inputs

An existing administrator performs read-only discovery. Do not grant `ListUsers` or create a new
workforce user. Obtain the assignment `PrincipalId` from the existing `PoHQuickLaunchDeployer` account
assignment, require `PrincipalType=USER`, and verify that it is the intended workforce identity. Treat
the principal ID and policy documents as protected metadata even though they are not credentials.

Required renderer inputs are:

| Variable | Contract |
|---|---|
| `QUICK_LAUNCH_AWS_ACCOUNT_ID` | exactly `368426158592` |
| `QUICK_LAUNCH_IDENTITY_CENTER_REGION` | exactly `us-east-1` |
| `QUICK_LAUNCH_IDENTITY_CENTER_INSTANCE_ARN` | exact live organization-instance ARN |
| `QUICK_LAUNCH_DEPLOYER_PERMISSION_SET_ARN` | exact live ARN whose described name is `PoHQuickLaunchDeployer`, in the same instance |
| `QUICK_LAUNCH_IAM_ADMINISTRATOR_PRINCIPAL_ID` | exact existing workforce USER principal ID |
| `QUICK_LAUNCH_CURRENT_DEPLOYER_POLICY_PATH` | protected path containing only the decoded current deployer inline-policy JSON object |
| `QUICK_LAUNCH_EXPECTED_CURRENT_DEPLOYER_POLICY_SHA256` | independently reviewed canonical SHA-256 of that current policy |

Retrieve only metadata and the deployer permissions document. Never enable shell tracing, print the
environment, list unrelated principals or retrieve a secret. Canonicalize the decoded current policy
with `jq -cS .` and have a second reviewer record its SHA-256 before rendering. The renderer independently
canonicalizes and rejects any mismatch.

Run locally and write only to a new protected, non-version-controlled path:

```sh
umask 077
pnpm --silent --filter @ubi2/proofofhumanity quick-launch:iam-administrator-package \
  > <NEW_PROTECTED_PATH>/iam-administrator-package.json
```

The renderer fails closed for a malformed account, region, instance ARN, permission-set ARN, mismatched
instance identifiers, malformed principal ID, malformed/mismatched current-policy hash, missing or
duplicate statement `Sid`, wildcard `sts:AssumeRole`, conflicting publisher grant, or merged policy over
the Identity Center 32,768-byte limit. It preserves every current statement byte-semantically, appends
only `AssumeQuickLaunchImagePublisher`, and is idempotent when the exact grant is already present.

Review and record these output hashes:

- `permissionSetConfigurationSha256`
- `administratorPermissionsPolicySha256` (must equal the frozen value above for the reviewed live IDs)
- `assignmentSha256`
- `publisherTrustPolicySha256` (must remain `7c5f24c10eb2e6b0f05320bdee16bd361c170840572123761305f00ef27f0351`)
- `publisherPermissionsPolicySha256` (must remain `dc5e57830fde57c4f34adf8517639eedcf69bb076be0bd1e4cce657d6026a433`)
- `deployerAssumeRoleGrantSha256` (must remain `bb1672c248223c31799ca5596b9fa6b0a03e67bcabfa467a54920137a220fbdc`)
- current and updated deployer policy hashes
- `requestPlanSha256`
- `packageBindingSha256`

The package must say `transactionFree=true`, `mutatesAws=false`, `applyAuthorized=false`, and
`pauseBeforeApply=true`. Those fields describe rendering only and cannot authorize an AWS write.

## Administrator handoff — do not run without action-time confirmation

Prefer an existing authorized non-root IAM Identity Center administrator. Break-glass root is acceptable
only when the user explicitly authorizes that one IAM change at action time; verify account `368426158592`,
perform no other action, and sign root out immediately afterward. Never forward credentials or create
long-lived keys.

Before applying, the administrator must verify all of the following:

1. sanitized STS identity is in account `368426158592` and is the approved administrator, or the
   specifically authorized break-glass root identity;
2. the Identity Center instance and deployer permission-set metadata match the rendered package;
3. the deployer permission-set name is exactly `PoHQuickLaunchDeployer`;
4. the provided USER principal is already the approved deployer assignee in this account;
5. the decoded current deployer policy still matches `currentDeployerPolicySha256` immediately before
   the write;
6. the administrator policy, assignment, updated deployer policy, publisher trust and publisher policy
   match all reviewed hashes;
7. no permission set named `PoHQuickLaunchIamAdministrator` already exists, or its live configuration,
   inline policy and assignment match exactly;
8. CloudTrail management events are enabled for the control-plane changes.

Then pause immediately before `CreatePermissionSet`. After separate confirmation, execute only the four
dependency-ordered `bootstrapWithExistingAdministrator` requests in `requestPlan`:

1. create `PoHQuickLaunchIamAdministrator` with `SessionDuration=PT1H` and the three exact tags;
2. attach only the rendered administrator inline policy to the returned permission-set ARN;
3. create the one USER assignment to account `368426158592`;
4. poll that request ID until `SUCCEEDED` and capture redacted metadata plus the reviewed hashes.

Do not reuse a same-named permission set without byte-for-byte verification. Do not add managed policies,
permissions boundaries, other users/groups/accounts, or another assignment. A fresh access-portal login
must produce an STS ARN containing `AWSReservedSSO_PoHQuickLaunchIamAdministrator_` and a session no longer
than one hour. Stop again before any `iam:CreateRole` or `sso:PutInlinePolicyToPermissionSet` call; those
are a second action-time approval using `afterFreshAdministratorLogin`.

## Payload-level limitation and compensating gate

This is the narrowest resource/action policy AWS exposes, but it is not a cryptographic transaction
firewall. IAM cannot condition `CreateRole` on the trust-policy bytes, cannot condition `PutRolePolicy`
on the inline policy name or bytes, and IAM Identity Center cannot condition
`PutInlinePolicyToPermissionSet` on the replacement document bytes. Consequently, an operator holding
this one-hour permission set could technically write different policy bytes to the two exact targets.

The mandatory compensating controls are the non-editable request plan, independently reviewed hashes,
action-time confirmation, one-hour session, immediate metadata readback, canonical byte comparison,
CloudTrail evidence, and removal of the temporary administrator assignment by the existing administrator
after the publisher role and deployer grant are verified. Any mismatch blocks the release; never broaden
the permission set to work around it.

Run the failure-path test locally:

```sh
pnpm --filter @ubi2/proofofhumanity test:quick-launch-iam-administrator
```

The test proves that omitting any mandatory tag, changing any mandatory value or adding another tag
fails the rendered create/tag contract. It also proves that `iam:UntagRole`, unrelated role ARNs, secret
access, ECR publication and application-deployment authority remain absent.

No successful render or local test proves that the permission set, assignment, publisher role or deployer
grant exists in AWS. It authorizes no image push, application deployment, funding, transaction, mainnet
change or custom-circuit Phase 2 work.
