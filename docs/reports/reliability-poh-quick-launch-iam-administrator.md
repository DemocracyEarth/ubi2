# Reliability gate — PoH Quick Launch IAM administrator handoff

- **Gate:** deterministic policy/assignment binding and fail-closed update sequence
- **Reviewer:** Codex reliability review
- **Date:** 2026-09-20
- **Verdict:** **PASS — reproducible correction only; failed live provisioning diagnosed, not retried**

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
- The later deployer provisioning request was matched by its approved request-ID digest and failed
  atomically with `AccessDenied` for `iam:GetRole` on the existing generated deployer role. It was not
  retried. The package now pins that exact account/path/name and cannot follow role recreation or suffix
  drift silently.
- The corrected canonical administrator policy hash is
  `3765bd2e455abb91024dd74ee6ed7172203334f7215712683cbf91a000f51bc6`; the regression fixture pins
  request-plan hash `13f85ccbeb1b89ec68611450ae57062b06097cad071cecb05966b9b6e9c0d93d` and package binding
  `00b4752c247699f4585b39d2aa18e0ed2d416b392aef31e5d423e7c88cde7f14`.

## Residual gates

- The failed provisioning status is diagnostic evidence only. No successful deployer reprovisioning or
  refreshed generated-role policy was observed, so a green local package is not operational readiness.
- The apply operator must re-read and hash the deployer policy immediately before replacement, wait for
  assignment/provisioning `SUCCEEDED`, sign in afresh, read back every live document and capture redacted
  immutable evidence.
- Publisher-role creation and deployer-policy replacement remain a second approval after this permission
  set is provisioned.
- The old live binding `724a8410121703cbac883adcb1e4d7830cdfed4ae25dd7e86789c968b90b871e`
  and the later binding `039b3e4696d65c7941bb7b9fdc1636c6400e1a631a42555448e26e89d0136324`
  are invalid. A new live binding remains blocked on a fresh read-only render against the protected
  current deployer policy after this correction is merged.

**Reliability approval:** merge the transaction-free package and runbook; pause before every AWS mutation.
