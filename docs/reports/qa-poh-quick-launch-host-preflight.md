# QA gate — PoH Quick Launch host preflight

- **Gate:** transaction-free host-readiness tooling
- **Reviewer:** Codex QA review
- **Date:** 2026-08-30
- **Scope:** Base Sepolia automatic-host readiness record, external verifier and blocked operational evidence
- **Verdict:** **PASS — tooling only; live host remains blocked**

No blocking correctness finding remains in the repository slice. This verdict does not attest that the deployed
host is sticky, that either secret-manager reference is approved, or that the host is ready.

## Acceptance evidence

- The readiness assessment requires the exact deployed source revision, canonical HTTPS callback, Self staging
  mode, one externally hash-bound sticky Node topology, the approved issuer address, a distinct non-zero sponsor
  address and the exact Base Sepolia sponsor allowlist.
- Missing, malformed, mismatched and role-overlapping inputs fail closed with enumerated public blockers.
- The runtime route returns HTTP 503 until every requirement passes and sets `Cache-Control: no-store`.
- The external checker binds the response to caller-supplied revision and attestation hashes, verifies that removed
  demo/network surfaces stay absent, emits only allowlisted public fields and exits non-zero on any blocker.
- Product tests inject synthetic keys and prove that keys, passwords, raw secret references and malformed response
  strings are not serialized.
- The production-build PWA test accepts only a schema-valid transaction-free 200/503 readiness response and checks
  the response for prohibited secret fields.

## Validation

- `pnpm --filter @ubi2/proofofhumanity test:quick-launch` — PASS
- `pnpm --filter @ubi2/proofofhumanity test:pwa` — PASS (1 Chromium test)
- `pnpm -r typecheck` — PASS
- `pnpm -r build` — PASS
- Repository Rust, Foundry, SDK, holder-browser, status-operator and V2 regression gates — PASS

**QA approval:** merge the fail-closed readiness boundary. Keep the live readiness record false until T2B supplies
and independently verifies the deployment-owner attestations.
