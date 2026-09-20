# Quick Launch IAM administrator permission set and assignment

This runbook prepares a one-hour IAM Identity Center permission set named
`PoHQuickLaunchIamAdministrator`. It is a narrow, temporary control-plane identity for creating and
inspecting only `PoHQuickLaunchImagePublisherRole`, and for merging the already frozen one-role
`sts:AssumeRole` grant into only the existing `PoHQuickLaunchDeployer` permission set. It may also read
only the exact IAM Identity Center-generated deployer role that AWS must inspect while provisioning that
permission set. It cannot mutate that generated role or create its own permission set or assignment.

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
| Provisioning read target | `arn:aws:iam::368426158592:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PoHQuickLaunchDeployer_77f051e3d9faf765` |
| Target deployer permission set | existing `PoHQuickLaunchDeployer` only |
| Assignment | one existing workforce `USER` already assigned to `PoHQuickLaunchDeployer` in account `368426158592` |

For the currently reviewed Identity Center instance and deployer permission-set identifiers, the
canonical administrator inline-policy SHA-256 is:

```text
3765bd2e455abb91024dd74ee6ed7172203334f7215712683cbf91a000f51bc6
```

The earlier `0fa2aa3bddfc22d7b4485888b7b5bb0550129e2ffe7d12c2f4e6e5fc84c70513`
policy and every package binding that includes it are superseded. It successfully limited publisher-role
creation and configuration, but the live deployer provisioning request failed with `AccessDenied` because
AWS also evaluated `iam:GetRole` on the existing Identity Center-generated deployer role. The replacement
adds only that read action on the byte-exact generated-role ARN above. It adds no generated-role mutation,
wildcard suffix or alternate account/path.

The still earlier `9d02054700747aa01528b0a2b24a0973d143b42571676ccac575338eabb00d77`
policy is also revoked. That policy allowed `CreateRole` but not the separate `TagRole` authorization AWS
evaluates for tags supplied in the create request, so the reviewed tagged request failed atomically.

In particular, the pre-correction live package binding
`724a8410121703cbac883adcb1e4d7830cdfed4ae25dd7e86789c968b90b871e` must not be reused. The
later live package binding `039b3e4696d65c7941bb7b9fdc1636c6400e1a631a42555448e26e89d0136324`
must not be reused either. The renderer and regression fixture now bind the corrected policy to
request-plan SHA-256 `13f85ccbeb1b89ec68611450ae57062b06097cad071cecb05966b9b6e9c0d93d`
and fixture package-binding SHA-256
`00b4752c247699f4585b39d2aa18e0ed2d416b392aef31e5d423e7c88cde7f14`.
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
| Inspect the generated deployer role during provisioning | `iam:GetRole` | only `arn:aws:iam::368426158592:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PoHQuickLaunchDeployer_77f051e3d9faf765` |
| Install the publisher inline policy | `iam:PutRolePolicy` | only the exact role ARN and only while all three fixed resource tags match |
| Inspect the deployer policy | `sso:DescribePermissionSet`, `sso:GetInlinePolicyForPermissionSet` | only the exact Identity Center instance and existing deployer permission-set ARNs, requested in `us-east-1` |
| Replace and provision the reviewed deployer policy | `sso:PutInlinePolicyToPermissionSet`, `sso:ProvisionPermissionSet` | only the same instance/deployer permission set and account `368426158592`, requested in `us-east-1` |
| Observe asynchronous provisioning | `sso:DescribePermissionSetProvisioningStatus` | only the exact Identity Center instance, requested in `us-east-1` |

There is no wildcard resource. `iam:UntagRole` is not granted, and `iam:TagRole` cannot target another
role or submit missing, altered or additional tags. The generated deployer role allows only `GetRole`;
the same role name without its reserved path, a different suffix/account/path and every unrelated role
fail closed. The permission set excludes `iam:PassRole`, trust-policy updates, role updates/deletion,
tagging/untagging or inline/managed-policy mutation of the generated role, access-key operations,
Identity Center permission-set creation/deletion/assignment, Identity Store enumeration, ECR, Secrets
Manager, KMS, CloudFormation, ECS and every non-IAM resource service.

AWS documents Identity Center delegated administration using exact `PermissionSet`, `Instance`, and
`Account` resource ARNs. `PutInlinePolicyToPermissionSet` requires the instance and permission-set ARNs,
and a changed assigned permission set must be provisioned before its generated account role receives the
change. AWS's
[generated-role ARN format](https://docs.aws.amazon.com/singlesignon/latest/userguide/referencingpermissionsets.html)
also confirms that the reserved path omits a region segment for an Identity Center instance hosted in
`us-east-1`. The package includes only those required resources and operations.

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

## Existing-live-permission-set corrective resume

The reviewed account already has the administrator permission set, publisher role, publisher inline
policy and deployer publisher grant. Do not replay `CreatePermissionSet`, `CreateAccountAssignment`,
`CreateRole`, `PutRolePolicy` or the deployer policy replacement merely to correct provisioning. After
this change is merged, the narrow recovery sequence is:

1. use an existing authorized administrator, with separately authorized break-glass root only if none
   exists, to read the existing administrator permission-set metadata and inline policy;
2. require its current canonical policy hash to be the superseded
   `0fa2aa3bddfc22d7b4485888b7b5bb0550129e2ffe7d12c2f4e6e5fc84c70513` and re-render the protected live
   package against the unchanged current deployer policy;
3. obtain action-time approval for one `PutInlinePolicyToPermissionSet` that installs only policy hash
   `3765bd2e455abb91024dd74ee6ed7172203334f7215712683cbf91a000f51bc6`, then read it back canonically;
4. obtain separate confirmation to provision only that administrator permission set to account
   `368426158592`, observe the single request read-only until terminal, and require `SUCCEEDED`;
5. sign out the applying identity, start a fresh one-hour `PoHQuickLaunchIamAdministrator` session and
   verify `iam:GetRole` succeeds only for the exact generated deployer role while an unrelated role and
   mutating IAM action remain denied;
6. pause again. Retrying the failed `PoHQuickLaunchDeployer` provisioning request is a separate action and
   requires fresh authorization after the corrected live administrator policy and session are proven.

Never reuse the failed request ID, hide a nonterminal status, broaden the generated-role resource, or
interpret successful administrator reprovisioning as successful deployer reprovisioning.

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
access, ECR publication and application-deployment authority remain absent. For the generated deployer
role specifically, only `iam:GetRole` succeeds; alternate accounts, reserved-role paths or suffixes and
all mutating IAM actions fail closed.

No successful render or local test proves that the permission set, assignment, publisher role or deployer
grant exists in AWS. It authorizes no image push, application deployment, funding, transaction, mainnet
change or custom-circuit Phase 2 work.
