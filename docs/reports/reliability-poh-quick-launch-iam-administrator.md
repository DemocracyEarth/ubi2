# Reliability gate — PoH Quick Launch IAM administrator handoff

- **Gate:** deterministic policy/assignment binding and fail-closed update sequence
- **Reviewer:** Codex reliability review
- **Date:** 2026-09-27
- **Verdict:** **PASS — reproducible correction only; latest failed live provisioning diagnosed, not retried**

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
- After the inspection correction was provisioned and verified, the next one authorized deployer
  provisioning retry failed atomically with `AccessDenied` for `iam:PutRolePolicy` on that same generated
  role. The opaque request is retained only as sanitized SHA-256
  `1511906cda3d75a6d46b34e17ede7a3e71e5d1f0b3662d3b961fb12e2b2b81e7`; it was not retried. The
  package adds only that observed action on the already pinned ARN.
- The corrected canonical administrator policy hash is
  `ca8356db96cd07b9247e8c0b12090441c8cffc9549f349f4cb52b85150e98515`; the regression fixture pins
  request-plan hash `0d1f367455469434248775b1f5a796cb7851c6252d6bbe3d9a6c75aff3279f5c` and package binding
  `3218b85d7acc103a36eea10beaeb20ff246ee40ba32d30a609f14632a3644578`.

## Residual gates

- The failed provisioning status is diagnostic evidence only. No successful deployer reprovisioning or
  refreshed generated-role policy was observed, so a green local package is not operational readiness.
- IAM cannot restrict `PutRolePolicy` by inline-policy name or document bytes. Before the one approved
  provisioning retry, the operator must hash/read back the Identity Center source policy, approve the
  freshly rendered live binding and call only `ProvisionPermissionSet`; a direct generated-role
  `PutRolePolicy` call is forbidden. After success, a separate read-only verifier must retrieve and hash
  the generated-role inline policy. Missing or mismatched read-back blocks release progress.
- The apply operator must re-read and hash the deployer policy immediately before replacement, wait for
  assignment/provisioning `SUCCEEDED`, sign in afresh, read back every live document and capture redacted
  immutable evidence.
- Publisher-role creation and deployer-policy replacement remain a second approval after this permission
  set is provisioned.
- The old live binding `724a8410121703cbac883adcb1e4d7830cdfed4ae25dd7e86789c968b90b871e`
  and the later binding `039b3e4696d65c7941bb7b9fdc1636c6400e1a631a42555448e26e89d0136324`,
  post-PR-#119 binding `f99d18040a9b5cde23aa605cef8472a8ec1e94a61422e04a62d7d7f5d4e732bf`,
  and later binding `c66c0f70f25fb9bc2607b6d476136f1b5886f8fa487e964f098c58503e3773a8`
  are invalid. A fresh protected live package must be rendered from a new live policy read after merge;
  this PR makes no live-binding claim.

**Reliability approval:** merge the transaction-free package and runbook; pause before every AWS mutation.
