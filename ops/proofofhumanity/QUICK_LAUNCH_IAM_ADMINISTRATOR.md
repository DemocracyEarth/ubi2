# Quick Launch IAM administrator permission set and assignment

This runbook prepares a one-hour IAM Identity Center permission set named
`PoHQuickLaunchIamAdministrator`. It is a narrow, temporary control-plane identity for creating and
inspecting only `PoHQuickLaunchImagePublisherRole`, and for merging the already frozen one-role
`sts:AssumeRole` grant into only the existing `PoHQuickLaunchDeployer` permission set. It may also read
and enumerate attached managed-policy metadata only on the exact IAM Identity Center-generated deployer
role that AWS must inspect while provisioning that permission set, and replace an inline policy only on
that byte-exact generated role as required by Identity Center provisioning. It cannot delete or attach a
managed policy, change trust, tag, delete or otherwise mutate that generated role, or create its own
permission set or assignment.

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
| Provisioning role target | `arn:aws:iam::368426158592:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PoHQuickLaunchDeployer_77f051e3d9faf765` |
| Target deployer permission set | existing `PoHQuickLaunchDeployer` only |
| Assignment | one existing workforce `USER` already assigned to `PoHQuickLaunchDeployer` in account `368426158592` |

For the currently reviewed Identity Center instance and deployer permission-set identifiers, the
canonical administrator inline-policy SHA-256 is:

```text
ca8356db96cd07b9247e8c0b12090441c8cffc9549f349f4cb52b85150e98515
```

The immediately preceding
`b64dd063ef1240ea4a9b080d64050b97fe0a95591053297c083eb0d6c4a60874` policy and every package binding
that includes it are superseded. After it was provisioned and its two exact-role inspection actions were
verified, the single authorized deployer provisioning retry—whose opaque request identifier is recorded
only as sanitized SHA-256
`1511906cda3d75a6d46b34e17ede7a3e71e5d1f0b3662d3b961fb12e2b2b81e7`—failed atomically with
`AccessDenied` for `iam:PutRolePolicy` on the same generated role. It was not retried. This replacement
preserves only `iam:GetRole` and `iam:ListAttachedRolePolicies` for inspection and adds only
`iam:PutRolePolicy` on the byte-exact ARN above. It grants no other generated-role read or mutation,
wildcard suffix or alternate account/path.

The earlier `3765bd2e455abb91024dd74ee6ed7172203334f7215712683cbf91a000f51bc6`
policy is also superseded. It added the exact generated-role `iam:GetRole` read required by the first
failed live deployer provisioning attempt. The next authorized retry identified the separate
`iam:ListAttachedRolePolicies` requirement.

The still earlier `0fa2aa3bddfc22d7b4485888b7b5bb0550129e2ffe7d12c2f4e6e5fc84c70513`
policy is also revoked. It successfully limited publisher-role creation and configuration, but did not
allow AWS to inspect the generated deployer role during provisioning.

The original `9d02054700747aa01528b0a2b24a0973d143b42571676ccac575338eabb00d77`
policy is also revoked. That policy allowed `CreateRole` but not the separate `TagRole` authorization AWS
evaluates for tags supplied in the create request, so the reviewed tagged request failed atomically.

In particular, the pre-correction live package binding
`724a8410121703cbac883adcb1e4d7830cdfed4ae25dd7e86789c968b90b871e` must not be reused. The
later live package binding `039b3e4696d65c7941bb7b9fdc1636c6400e1a631a42555448e26e89d0136324`
must not be reused either. The post-PR-#119 live package binding
`f99d18040a9b5cde23aa605cef8472a8ec1e94a61422e04a62d7d7f5d4e732bf` is also revoked because it binds
the incomplete `3765bd2e...f51bc6` administrator policy. The protected live re-render against unchanged
deployer policy hash `fa3b2e3a165123bb396c37d86cd91c9f7e3e623c0c2b9a6ebb0c5afac75dc869`
produced package binding `c66c0f70f25fb9bc2607b6d476136f1b5886f8fa487e964f098c58503e3773a8`,
which is now revoked because it binds the incomplete `b64dd063...a60874` policy. A new protected live
binding must be rendered after merge from the same hash-verified deployer policy; this PR does not read
AWS or claim a live replacement binding.
The renderer and regression fixture bind the corrected policy to request-plan SHA-256
`0d1f367455469434248775b1f5a796cb7851c6252d6bbe3d9a6c75aff3279f5c`
and fixture package-binding SHA-256
`3218b85d7acc103a36eea10beaeb20ff246ee40ba32d30a609f14632a3644578`.
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
| Inspect the generated deployer role during provisioning | `iam:GetRole`, `iam:ListAttachedRolePolicies` | only `arn:aws:iam::368426158592:role/aws-reserved/sso.amazonaws.com/AWSReservedSSO_PoHQuickLaunchDeployer_77f051e3d9faf765` |
| Replace the generated deployer inline policy during provisioning | `iam:PutRolePolicy` | only the same byte-exact generated-role ARN; payload constraints are enforced by the action-time controls below because IAM exposes no policy-name/document condition key |
| Install the publisher inline policy | `iam:PutRolePolicy` | only the exact role ARN and only while all three fixed resource tags match |
| Inspect the deployer policy | `sso:DescribePermissionSet`, `sso:GetInlinePolicyForPermissionSet` | only the exact Identity Center instance and existing deployer permission-set ARNs, requested in `us-east-1` |
| Replace and provision the reviewed deployer policy | `sso:PutInlinePolicyToPermissionSet`, `sso:ProvisionPermissionSet` | only the same instance/deployer permission set and account `368426158592`, requested in `us-east-1` |
| Observe asynchronous provisioning | `sso:DescribePermissionSetProvisioningStatus` | only the exact Identity Center instance, requested in `us-east-1` |

There is no wildcard resource. `iam:UntagRole` is not granted, and `iam:TagRole` cannot target another
role or submit missing, altered or additional tags. The generated deployer role allows only `GetRole`,
`ListAttachedRolePolicies` and the required `PutRolePolicy`; `GetRolePolicy`, `ListRolePolicies`,
`ListRoleTags` and every unobserved read remain absent. The same role name without its reserved path, a
different suffix/account/path and every unrelated role fail closed. The permission set excludes
`iam:DeleteRolePolicy`, `iam:AttachRolePolicy`, `iam:DetachRolePolicy`, `iam:PassRole`, trust-policy
updates, role updates/deletion, tagging/untagging and every other generated-role mutation, access-key
operations, Identity Center permission-set creation/deletion/assignment, Identity Store enumeration,
ECR, Secrets Manager, KMS, CloudFormation, ECS and every non-IAM resource service.

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
   `b64dd063ef1240ea4a9b080d64050b97fe0a95591053297c083eb0d6c4a60874` and re-render the protected live
   package against the unchanged current deployer policy;
3. obtain action-time approval for one `PutInlinePolicyToPermissionSet` that installs only policy hash
   `ca8356db96cd07b9247e8c0b12090441c8cffc9549f349f4cb52b85150e98515`, then read it back canonically;
4. obtain separate confirmation to provision only that administrator permission set to account
   `368426158592`, observe the single request read-only until terminal, and require `SUCCEEDED`;
5. sign out the applying identity, start a fresh one-hour `PoHQuickLaunchIamAdministrator` session and
   verify the live policy canonically grants `iam:GetRole`, `iam:ListAttachedRolePolicies` and
   `iam:PutRolePolicy` only on the exact generated deployer role. Exercise only the two reads; verify
   unrelated-role and mutation denials from the live policy or an authorized simulator without invoking
   a mutating API;
6. pause again. Retrying the failed `PoHQuickLaunchDeployer` provisioning request is a separate action.
   Immediately before that one call, re-read the Identity Center deployer inline policy and require
   canonical SHA-256 `fa3b2e3a165123bb396c37d86cd91c9f7e3e623c0c2b9a6ebb0c5afac75dc869`,
   re-render and approve the new live package binding, and record the action-time request-plan hash;
7. call `ProvisionPermissionSet` exactly once, hash its returned opaque request ID, observe only that
   request until terminal and require `SUCCEEDED`. Do not issue a direct `iam:PutRolePolicy` call;
8. after success, have a separately authorized read-only verifier retrieve the generated role's inline
   policy name/document, canonicalize it, and compare it with the approved Identity Center source policy.
   This temporary permission set intentionally lacks `iam:GetRolePolicy` and `iam:ListRolePolicies`, so a
   missing independent read-back is a blocker, not a reason to broaden it.

Never reuse the failed request ID, hide a nonterminal status, broaden the generated-role resource, or
interpret successful administrator reprovisioning as successful deployer reprovisioning.

## Payload-level limitation and compensating gate

This is the narrowest resource/action policy AWS exposes, but it is not a cryptographic transaction
firewall. IAM cannot condition `CreateRole` on the trust-policy bytes, cannot condition either exact-role
`PutRolePolicy` grant on the inline policy name or document bytes, and IAM Identity Center cannot condition
`PutInlinePolicyToPermissionSet` on the replacement document bytes. Consequently, an operator holding
this one-hour permission set could technically write different policy bytes to either exact IAM role.
The AWS [`PutRolePolicy` API](https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html)
accepts `RoleName`, `PolicyName`, and `PolicyDocument` as request parameters, but IAM supplies no
authorization condition key that binds the latter two values for this action.

The mandatory compensating controls are the non-editable request plan, independently reviewed hashes,
action-time confirmation, one-hour session, no direct generated-role `PutRolePolicy` call, exactly one
hash-bound `ProvisionPermissionSet` request, immediate Identity Center source-policy read-back, independent
generated-role inline-policy read-back, canonical byte comparison, CloudTrail evidence, and removal of the
temporary administrator assignment by the existing administrator after the publisher role and deployer
grant are verified. Any mismatch blocks the release; never broaden the permission set to work around it.

Run the failure-path test locally:

```sh
pnpm --filter @ubi2/proofofhumanity test:quick-launch-iam-administrator
```

The test proves that omitting any mandatory tag, changing any mandatory value or adding another tag
fails the rendered create/tag contract. It also proves that `iam:UntagRole`, unrelated role ARNs, secret
access, ECR publication and application-deployment authority remain absent. For the generated deployer
role specifically, only `iam:GetRole`, `iam:ListAttachedRolePolicies` and the required
`iam:PutRolePolicy` target the exact ARN; alternate accounts, reserved-role paths or suffixes, unobserved
reads, inline-policy deletion, managed-policy attachment/detachment, trust updates, tagging, deletion and
all other tested mutations fail closed.

No successful render or local test proves that the permission set, assignment, publisher role or deployer
grant exists in AWS. It authorizes no image push, application deployment, funding, transaction, mainnet
change or custom-circuit Phase 2 work.
