# QA gate — PoH Quick Launch pre-created task execution role

- **Gate:** fail-closed template input, account/region binding and regression coverage
- **Reviewer:** Codex QA review
- **Date:** 2026-09-02
- **Scope:** transaction-disabled Base Sepolia API-origin IAM boundary only
- **Verdict:** **PASS — implementation only; no AWS/live-readiness claim**

## Acceptance evidence

- `quick-launch-api-origin.yaml` now requires `TaskExecutionRoleArn` and references it directly from the
  task definition.
- The template contains no `AWS::IAM::Role`, attached managed policy, inline secret-read policy, KMS policy
  parameter or `GetAtt` of a template-owned role.
- The parameter accepts only a regionless IAM ARN for `PoHQuickLaunchTaskExecutionRole` in a 12-digit account.
- The new transaction-free checker validates the declared deployment account, exact `us-east-1` region,
  regionless/same-account role, same-account/us-east-1 digest-pinned ECR image, distinct secret references and
  optional KMS keys.
- Failure tests cover a wrong role account, impossible regional IAM role ARN, cross-region secret and reused
  issuer/sponsor reference. The serialized assessment is proven not to contain any supplied ARN.

## Validation

- Quick Launch product, contract, typecheck, production build and Chromium PWA gates — PASS (PWA 1/1).
- Recursive interface build/typecheck, SDK tests and status-operator tests (including cast adapter) — PASS.
- Rust format, clippy with warnings denied, locked build and serial workspace tests — PASS; required four-process
  `m5_stage_a` acceptance — PASS (1/1).
- Solidity format/build, 202 tests, target coverage 100% lines/branches, gas snapshot, cross-stack tests and
  local-only tooling rehearsal — PASS. The first verbose Forge attempt hit a macOS proxy-discovery process crash;
  the complete lane passed when rerun with Forge offline mode.
- Isolated V2 regression: 62 tests passed/1 intentional ignore plus holder-refresh 4/4; all-candidate proof 1/1;
  content-addressed WASM/bindings and deterministic artifacts reproduced; browser 4/4 and PWA 1/1 — PASS.
- CloudFormation YAML syntax parse, `git diff --check`, and valid/failure redaction CLI checks — PASS.

**QA approval:** merge this code-only IAM boundary. A live role, its policy bytes and any AWS service remain
external evidence gates.
