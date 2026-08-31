# QA gate — PoH Quick Launch dedicated API origin

- **Gate:** exact-path API routing, runtime isolation and transaction-free deployment contract
- **Reviewer:** Codex QA review
- **Date:** 2026-08-30
- **Scope:** Base Sepolia frontend proxy, standalone Node image, one-task ECS template and evidence tooling
- **Verdict:** **PASS — implementation only; no live deployment/readiness claim**

## Acceptance evidence

- Amplify rewrites exactly four canonical paths to one validated public HTTPS origin. HTTP, credentials,
  path/query/fragment, loopback and self-proxy loops fail the build-time configuration.
- Self verification, predicate, sponsored-mint and readiness handlers return a constant HTTP 503 unless the
  dedicated single-replica runtime role is declared. Amplify therefore cannot execute their signer/state paths.
- Sponsored POST has a separate transaction flag and returns `blockchain-transactions-disabled` before body
  validation, capability/store work, signer configuration, RPC, rate limits or state mutation.
- Host-readiness schema v2 requires the dedicated role and disabled transaction flag. `/api/healthz` exposes only
  an allowlisted revision/boot record and remains unhealthy without the role, kill switch or reviewed revision.
- The infrastructure product test pins desired count one, stop-before-start deployment percentages, disabled ECS
  Exec, IP targets, health path, digest-only image input and Secrets Manager injection names.
- The evidence checker rejects extra response fields, stale revisions, enabled transactions, a missing pre-restart
  record, unchanged boot identity or non-monotonic restart time without printing a raw response.

## Validation

- `pnpm --filter @ubi2/proofofhumanity test:quick-launch-api-origin` — PASS
- `pnpm --filter @ubi2/proofofhumanity test:quick-launch-host` — PASS
- `pnpm --filter @ubi2/proofofhumanity typecheck` — PASS
- normal Amplify-mode build and `test:pwa` — PASS (1/1); Docker-only standalone build — PASS; generated server
  returned transaction-free health and rejected sponsored POST before RPC/config/body work.
- repository Rust format, clippy, locked build/tests and four-process `m5_stage_a` — PASS.
- interfaces recursive build/typecheck, SDK tests and status-operator tests — PASS (existing wallet lint warnings only).
- Solidity format/build, 202 tests, 100% target coverage, gas snapshot, cross-stack/product tests and local Anvil
  tooling rehearsal — PASS; no public transaction was sent.
- isolated V2 regression gate — PASS: format/clippy/WASM compile, content-addressed bindings, 62+4 relation tests,
  one ignored all-candidate proof test and all deterministic artifact reproductions. This was regression validation,
  not ceremony or Phase 2 work.
- CloudFormation YAML parse — PASS. AWS `validate-template` was unavailable because this worktree has no AWS
  credentials; Docker is not installed, so the Dockerfile itself was not built as a container image.

**QA approval:** merge the fail-closed deployment slice. Provisioning, DNS/certificate correctness, restart and
canonical-routing evidence remain external acceptance gates.
