# Security gate — PoH Quick Launch IAM administrator boundary

- **Gate:** least-authority actions/resources, secret exclusion and payload-integrity controls
- **Reviewer:** Codex security review
- **Date:** 2026-09-27
- **Verdict:** **PASS WITH EXPLICIT RESIDUAL — no AWS mutation authorized**

## Controls verified

- The administrator policy contains no wildcard resource. IAM authority is limited to creating, reading
  and installing an inline policy on the exact `PoHQuickLaunchImagePublisherRole`; creation requires the
  three fixed release tags and no permissions boundary.
- `iam:TagRole` is authorized only on that exact role and only when the request contains exactly the
  three fixed tags. Missing, altered and extra tags fail closed, while `iam:UntagRole` remains absent.
- The corrected administrator policy is pinned to SHA-256
  `ca8356db96cd07b9247e8c0b12090441c8cffc9549f349f4cb52b85150e98515`; the earlier policy hashes and
  package bindings are explicitly revoked in the runbook.
- The generated-role authority is exactly `iam:GetRole`, `iam:ListAttachedRolePolicies` and the newly
  observed `iam:PutRolePolicy` on the exact Identity Center-generated deployer-role ARN. There is no
  wildcard suffix. Another account/path/suffix and the same name outside the reserved Identity Center
  path fail closed; unobserved reads, `DeleteRolePolicy`, managed-policy attachment/detachment, tagging,
  trust changes, role deletion and every other mutation remain absent.
- Identity Center authority targets only the exact instance, existing `PoHQuickLaunchDeployer` permission
  set and account `368426158592` in `us-east-1`. The principal cannot create/delete permission sets, create
  assignments, enumerate the identity store or mutate another permission set.
- There is no `iam:PassRole`, managed-policy attachment/creation, trust update, role deletion, access-key,
  ECR, secret, KMS, CloudFormation, ECS, funding, blockchain or mainnet permission.
- Current deployer policy bytes must match an independently approved hash; wildcard role assumption,
  conflicting target grants and duplicate statement identifiers fail closed.
- Renderer output contains no credential or secret reference. Principal IDs and IAM documents are marked
  protected metadata and are excluded from public evidence except by canonical hash.

## Explicit residual authorization risk

AWS IAM does not expose condition keys for the requested trust-policy bytes on `CreateRole`, the inline
policy name/document bytes on either exact-role `PutRolePolicy` grant, or the replacement bytes on
Identity Center `PutInlinePolicyToPermissionSet`. The one-hour principal therefore has payload
discretion on only those two exact IAM roles. This cannot be removed without introducing a pre-created
permissions boundary or a separate tightly controlled deployment service, both outside this slice.

The required mitigation is an immutable hash-bound request plan, independent review, separate action-time
confirmation, no direct generated-role `PutRolePolicy` invocation, exactly one hash-bound Identity Center
provisioning request, immediate source-policy readback, independent generated-role policy readback and
canonical comparison, CloudTrail evidence and prompt de-assignment by the existing administrator. Any
byte mismatch or unavailable independent read-back is a release blocker.

**Security approval:** merge the scoped, non-applying package. Do not provision it, create the role or
replace the deployer policy without the documented live checks and fresh confirmation.
