# QA gate — PoH Quick Launch IAM administrator package

- **Gate:** exact permission-set rendering, deployer-policy merge and failure paths
- **Reviewer:** Codex QA review
- **Date:** 2026-09-13
- **Scope:** local, transaction-free IAM Identity Center handoff only
- **Verdict:** **PASS — no AWS mutation or live identity claim**

## Acceptance evidence

- The renderer requires an exact account, `us-east-1`, matching Identity Center instance/permission-set
  ARNs, one workforce USER principal ID, decoded current deployer policy and independently supplied
  canonical current-policy hash.
- The new permission set is fixed to `PoHQuickLaunchIamAdministrator`, `PT1H`, three release tags and one
  inline policy. Its policy has no wildcard resource and targets only the one publisher-role ARN, one
  Identity Center instance, existing deployer permission set and approved account.
- The deployer merger preserves existing statements, appends only the frozen publisher-role grant, and is
  idempotent when that exact grant already exists.
- The publisher trust, permissions and deployer-grant hashes remain identical to the PR #117 contract.
- The rendered assignment is fixed to `PrincipalType=USER`, one principal ID and account `368426158592`.

## Failure coverage

- Invalid account/region/ARN/principal inputs, cross-instance permission sets, malformed or mismatched
  hashes, duplicate statement identifiers, wildcard `sts:AssumeRole`, conflicting publisher grants and an
  oversized merged policy fail closed.
- Static allowlist tests reject IAM wildcard authority, role deletion/pass-role/trust updates, permission-
  set creation/assignment authority, Identity Store access, ECR, secrets, KMS, CloudFormation and other
  resource services.
- The output remains explicitly non-mutating and paused before apply.

## Repository validation

Executed from the PR worktree on 2026-09-13:

- `pnpm install --frozen-lockfile`: PASS.
- remote-font rejection check: PASS (no `next/font/google` imports).
- `pnpm -r build` and `pnpm -r typecheck`: PASS; the build emitted only the pre-existing wallet
  lint warnings.
- SDK, status-operator, status-operator cast-signing and Proof of Humanity contract/product suites:
  PASS, including the new IAM administrator failure-path test.
- Rust workspace format, clippy with warnings denied, locked build, serial tests and ignored
  `m5_stage_a` multi-node acceptance test: PASS.
- V2 Rust/WASM formatting, release clippy, browser builds, pinned hashes, binding byte comparison,
  relation tests and holder-refresh tests: PASS.
- Solidity format, optimized size build and 202 unit/fuzz/invariant/integration tests: PASS.
- Release-contract coverage: PASS offline at 100% lines and branches for both `ProofOfHumanity.sol`
  and `PredicateVerifier.sol` (minimum 95%).
- Deterministic gas snapshot: PASS offline, 12/12 tests. The first online coverage/snapshot attempts
  hit Foundry 1.5.1's macOS system-proxy `SCDynamicStore` panic before test execution; `--offline`
  avoided that environment-specific path without changing test inputs.
- Full-worktree `git diff --check`: PASS.

The ignored Groth16 candidate-proof job and the Anvil Phase 2 ceremony rehearsal were not run locally:
they belong to the explicitly excluded custom-circuit/Phase-2 lane. The ordinary cryptographic relation
and reproducibility checks above remain green; required hosted CI still owns its unchanged complete gate.

**QA approval:** merge the deterministic package; keep all AWS writes blocked pending a separately
authorized administrator session, live metadata verification and action-time confirmation.
