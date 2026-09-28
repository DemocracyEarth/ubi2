# Reliability gate — Quick Launch infrastructure administrator handoff

- **Gate:** deterministic bindings, dependency order, concurrency/read-back controls
- **Reviewer:** Codex reliability review
- **Date:** 2026-09-28
- **Verdict:** **PASS — reproducible package only; no prerequisite is claimed live**

## Properties verified

- Canonical JSON hashes bind the permission set, administrator policy, assignment, exact task trust and
  permissions, redacted issuer/sponsor/topology attestations and full request plan into one package hash.
- Every real resource reference is supplied before rendering. A changed secret, key, subnet, zone,
  principal or deployment role changes the binding rather than silently following mutable discovery.
- The plan separates existing-administrator bootstrap from a fresh one-hour infrastructure-
  administrator session. Successful assignment must be observed before any prerequisite mutation.
- The topology requires two distinct subnet IDs in two distinct `us-east-1` Availability Zones and
  records their ordered bindings in the redacted topology attestation.
- Certificate request idempotency is source-revision bound; DNS writes are limited to the returned
  validation name's exact hostname pattern, CNAME type and UPSERT action.
- Optional KMS statements disappear deterministically when AWS-managed keys are used and deduplicate
  when both secrets use one customer-managed key.

## Residual gates

- IAM cannot authorize trust or inline-policy bytes, and Route 53 cannot authorize the CNAME value.
  Action-time hash comparison, one-call execution, immediate read-back, CloudTrail evidence and
  ACM-returned value comparison are mandatory.
- EC2 and secret metadata discovery cannot be resource-scoped. Their results are not approval: the
  operator must independently bind the exact VPC, two public subnets and two tagged signer references.
- A passing renderer does not prove that a certificate issued, DNS propagated, the role exists, its
  live policy matches, or the deployment role is sufficiently scoped.
- No application stack or change set may be created until all prerequisite read-backs and redacted
  attestations are independently accepted.

**Reliability approval:** merge the local package and retain the explicit stop before
`CreatePermissionSet`.
