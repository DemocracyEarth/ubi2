# Reliability gate — PoH Quick Launch IAM administrator handoff

- **Gate:** deterministic policy/assignment binding and fail-closed update sequence
- **Reviewer:** Codex reliability review
- **Date:** 2026-09-20
- **Verdict:** **PASS — reproducible handoff only; live provisioning unobserved**

## Properties verified

- Recursive canonical JSON hashing removes formatting/key-order ambiguity from permission-set, assignment,
  publisher-role and deployer-policy comparisons.
- The package binds account, region, instance, deployer permission set, USER principal, current/updated
  policy hashes and the existing publisher hashes into one deterministic `packageBindingSha256`.
- The current deployer policy must be hash-approved before the exact grant is appended. A concurrent or
  unreviewed change causes the renderer/read-before-write gate to fail rather than overwrite it.
- The request plan separates bootstrap administration from a fresh one-hour administrator login and
  requires successful asynchronous assignment/provisioning evidence before proceeding.
- Re-running the merger after the exact grant exists yields the same updated policy hash without a
  duplicate statement.
- The failed live `CreateRole` attempt was atomic: AWS required `iam:TagRole` for the supplied tags and
  no publisher role remained afterward. The corrected package rebinding prevents reuse of the earlier
  incomplete administrator policy or package hash.
- The corrected canonical administrator policy hash is
  `0fa2aa3bddfc22d7b4485888b7b5bb0550129e2ffe7d12c2f4e6e5fc84c70513`; the regression fixture pins
  request-plan hash `da29a85f10eb4c6beb697e0fb2ff5eb5c21b92af04b6336734346264bd21aa8f` and package binding
  `2c9d6ee504e07d2cecb24e88f0e58c3ebd20990127e3f34db3683bf834473994`.

## Residual gates

- No live STS identity, permission set, assignment, IAM role, CloudTrail event or provisioning status was
  observed. A green local package is not operational evidence.
- The apply operator must re-read and hash the deployer policy immediately before replacement, wait for
  assignment/provisioning `SUCCEEDED`, sign in afresh, read back every live document and capture redacted
  immutable evidence.
- Publisher-role creation and deployer-policy replacement remain a second approval after this permission
  set is provisioned.
- The old live binding `724a8410121703cbac883adcb1e4d7830cdfed4ae25dd7e86789c968b90b871e`
  is invalid. A new live binding remains blocked on a fresh read-only render against the protected current
  deployer policy after this correction is merged.

**Reliability approval:** merge the transaction-free package and runbook; pause before every AWS mutation.
