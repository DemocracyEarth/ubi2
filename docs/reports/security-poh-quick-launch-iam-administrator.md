# Security gate — PoH Quick Launch IAM administrator boundary

- **Gate:** least-authority actions/resources, secret exclusion and payload-integrity controls
- **Reviewer:** Codex security review
- **Date:** 2026-09-20
- **Verdict:** **PASS WITH EXPLICIT RESIDUAL — no AWS mutation authorized**

## Controls verified

- The administrator policy contains no wildcard resource. IAM authority is limited to creating, reading
  and installing an inline policy on the exact `PoHQuickLaunchImagePublisherRole`; creation requires the
  three fixed release tags and no permissions boundary.
- `iam:TagRole` is authorized only on that exact role and only when the request contains exactly the
  three fixed tags. Missing, altered and extra tags fail closed, while `iam:UntagRole` remains absent.
- The corrected administrator policy is pinned to SHA-256
  `3765bd2e455abb91024dd74ee6ed7172203334f7215712683cbf91a000f51bc6`; the earlier policy hashes and
  package bindings are explicitly revoked in the runbook.
- The only new authority is `iam:GetRole` on the exact observed Identity Center-generated deployer-role
  ARN. There is no wildcard suffix. Another account/path/suffix and the same name outside the reserved
  Identity Center path fail closed, and no tagging, trust, inline-policy, managed-policy or lifecycle
  mutation is granted on that role.
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

AWS IAM does not expose condition keys for the requested trust-policy bytes on `CreateRole`, the policy
name/document bytes on `PutRolePolicy`, or the replacement bytes on Identity Center
`PutInlinePolicyToPermissionSet`. The one-hour principal therefore has payload discretion on only those
two exact resources. This cannot be removed without introducing a pre-created permissions boundary or a
separate tightly controlled deployment service, both outside this slice.

The required mitigation is an immutable hash-bound request plan, independent review, separate action-time
confirmation, immediate live readback/canonical comparison, CloudTrail evidence and prompt de-assignment
by the existing administrator. Any byte mismatch is a release blocker.

**Security approval:** merge the scoped, non-applying package. Do not provision it, create the role or
replace the deployer policy without the documented live checks and fresh confirmation.
