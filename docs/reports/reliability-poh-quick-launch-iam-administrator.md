# Reliability gate — PoH Quick Launch IAM administrator handoff

- **Gate:** deterministic policy/assignment binding and fail-closed update sequence
- **Reviewer:** Codex reliability review
- **Date:** 2026-09-13
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

## Residual gates

- No live STS identity, permission set, assignment, IAM role, CloudTrail event or provisioning status was
  observed. A green local package is not operational evidence.
- The apply operator must re-read and hash the deployer policy immediately before replacement, wait for
  assignment/provisioning `SUCCEEDED`, sign in afresh, read back every live document and capture redacted
  immutable evidence.
- Publisher-role creation and deployer-policy replacement remain a second approval after this permission
  set is provisioned.

**Reliability approval:** merge the transaction-free package and runbook; pause before every AWS mutation.
