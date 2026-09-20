# Reliability gate — PoH Quick Launch IAM administrator handoff

- **Gate:** deterministic policy/assignment binding and fail-closed update sequence
- **Reviewer:** Codex reliability review
- **Date:** 2026-09-20
- **Verdict:** **PASS — reproducible correction only; second failed live provisioning diagnosed, not retried**

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
- After that correction was provisioned, a fresh exact-role `GetRole` preflight passed and the one
  separately authorized deployer reprovisioning retry failed atomically with `AccessDenied` for
  `iam:ListAttachedRolePolicies` on the same generated role. It was not retried. The new package adds
  only that observed read alongside `GetRole` on the already pinned ARN.
- The corrected canonical administrator policy hash is
  `b64dd063ef1240ea4a9b080d64050b97fe0a95591053297c083eb0d6c4a60874`; the regression fixture pins
  request-plan hash `992c0f68bce2b5ae965ec3877d6468e89eeb858629c7427cb01eb05c72924df9` and package binding
  `19346afc59d2bfc4bf79df375f24b79fff9433e4223e51170ce1fe629abec370`.

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
  and post-PR-#119 binding `f99d18040a9b5cde23aa605cef8472a8ec1e94a61422e04a62d7d7f5d4e732bf`
  are invalid. The protected transaction-free re-render produces candidate live binding
  `c66c0f70f25fb9bc2607b6d476136f1b5886f8fa487e964f098c58503e3773a8`; it must be regenerated from a
  fresh live policy read after merge before authorization.

**Reliability approval:** merge the transaction-free package and runbook; pause before every AWS mutation.
