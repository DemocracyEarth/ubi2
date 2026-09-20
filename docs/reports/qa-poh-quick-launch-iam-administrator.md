# QA gate — PoH Quick Launch IAM administrator package

- **Gate:** exact permission-set rendering, deployer-policy merge, provisioning dependency and failure paths
- **Reviewer:** Codex QA review
- **Date:** 2026-09-20
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
- Corrective coverage authorizes AWS's separate `iam:TagRole` evaluation only on the exact publisher
  role and only with the same exact three request tags required by `iam:CreateRole`.
- Provisioning corrective coverage adds only `iam:GetRole` on the observed generated role
  `AWSReservedSSO_PoHQuickLaunchDeployer_77f051e3d9faf765`, under its exact account and reserved-role
  path. The canonical administrator policy hash is
  `3765bd2e455abb91024dd74ee6ed7172203334f7215712683cbf91a000f51bc6`.

## Failure coverage

- Invalid account/region/ARN/principal inputs, cross-instance permission sets, malformed or mismatched
  hashes, duplicate statement identifiers, wildcard `sts:AssumeRole`, conflicting publisher grants and an
  oversized merged policy fail closed.
- Static allowlist tests reject IAM wildcard authority, role deletion/pass-role/trust updates, permission-
  set creation/assignment authority, Identity Store access, ECR, secrets, KMS, CloudFormation and other
  resource services.
- The output remains explicitly non-mutating and paused before apply.
- Missing, altered and additional create-time tags fail closed; `iam:UntagRole` and unrelated role ARNs
  remain unavailable.
- Generated deployer-role tests reject another account, path or suffix, the same name outside the
  Identity Center reserved path, unrelated roles and every tested mutating IAM action.

## Repository validation

Executed from the PR worktree on 2026-09-20:

- `pnpm install --frozen-lockfile`: PASS.
- remote-font rejection check: PASS (no `next/font/google` imports).
- `pnpm -r build` and `pnpm -r typecheck`: PASS; the build emitted only the pre-existing wallet
  lint warnings.
- SDK, status-operator, status-operator cast-signing, V2 vault/refresh and Proof of Humanity
  contract/product suites: PASS, including the corrected IAM administrator missing/altered/extra-tag
  failure paths.
- Holder browser hardening: PASS, 4 Chromium tests. Quick Launch holder PWA: PASS, 1 Chromium test.
- Rust workspace format, clippy with warnings denied, locked build, serial tests and ignored
  `m5_stage_a` multi-node acceptance test: PASS.
- V2 Rust/WASM formatting, release clippy, browser builds, pinned hashes, binding byte comparison,
  relation tests, holder-refresh tests, deterministic artifact reproductions and the ignored candidate
  Groth16 proof-generation gate: PASS.
- Solidity format, optimized size build and 202 unit/fuzz/invariant/integration tests: PASS.
- Release-contract coverage: PASS offline at 100% lines and branches for both `ProofOfHumanity.sol`
  and `PredicateVerifier.sol` (minimum 95%).
- Deterministic gas snapshot: PASS offline, 12/12 tests. The first online coverage/snapshot attempts
  hit Foundry 1.5.1's macOS system-proxy `SCDynamicStore` panic before test execution; `--offline`
  avoided that environment-specific path without changing test inputs.
- Local Anvil deployment-tooling rehearsal: PASS on disposable chain ID `31337`; no external network,
  funded account or persistent deployment was used.
- Full-worktree `git diff --check`: PASS.

The first sandboxed Rust test attempt could not bind ephemeral loopback listeners; the identical suite
passed after granting local-process/localhost access. An initial typecheck started concurrently with the
Next build observed transient `.next/types` regeneration; the CI-ordered rerun passed. Neither was a
source failure.

**QA approval:** merge the deterministic package; keep all AWS writes blocked pending a separately
authorized administrator session, live metadata verification and action-time confirmation.
