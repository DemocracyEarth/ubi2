# QA gate — PoH Quick Launch IAM administrator package

- **Gate:** exact permission-set rendering, deployer-policy merge, provisioning dependency and failure paths
- **Reviewer:** Codex QA review
- **Date:** 2026-09-27
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
- Provisioning corrective coverage retains `iam:GetRole` and `iam:ListAttachedRolePolicies` and adds only
  `iam:PutRolePolicy` after the next single sanitized provisioning failure identified that required write.
  All three target only the observed generated role
  `AWSReservedSSO_PoHQuickLaunchDeployer_77f051e3d9faf765`, under its exact account and reserved-role
  path. The canonical administrator policy hash is
  `ca8356db96cd07b9247e8c0b12090441c8cffc9549f349f4cb52b85150e98515`.
- The failed opaque provisioning request is recorded only by sanitized request-ID SHA-256
  `1511906cda3d75a6d46b34e17ede7a3e71e5d1f0b3662d3b961fb12e2b2b81e7`; no request identifier or
  protected policy bytes enter the repository.

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
- Generated deployer-role tests require the two approved reads plus `iam:PutRolePolicy` on the exact ARN
  and reject another account, path or suffix, the same name outside the Identity Center reserved path,
  unrelated roles and unobserved reads. They separately prove `DeleteRolePolicy`, `AttachRolePolicy`,
  `DetachRolePolicy`, trust changes, tagging, deletion and every other tested mutation remain denied.
- The fixture pins request-plan SHA-256
  `0d1f367455469434248775b1f5a796cb7851c6252d6bbe3d9a6c75aff3279f5c` and package binding
  `3218b85d7acc103a36eea10beaeb20ff246ee40ba32d30a609f14632a3644578`.

## Repository validation

Executed from the PR worktree on 2026-09-27:

- `pnpm install --frozen-lockfile`: PASS.
- remote-font rejection check: PASS (no `next/font/google` imports).
- `pnpm -r build` and `pnpm -r typecheck`: PASS; the build emitted only the pre-existing wallet
  lint warnings.
- SDK, status-operator, status-operator cast-signing, V2 vault/refresh and Proof of Humanity
  contract/product suites: PASS, including the corrected IAM administrator exact-role and forbidden-
  mutation failure paths.
- Holder browser hardening: PASS, 4 Chromium tests. Quick Launch holder PWA: PASS, 1 Chromium test.
- Rust workspace format, clippy with warnings denied, locked build, serial tests and ignored
  `m5_stage_a` multi-node acceptance test: PASS.
- V2 Rust/WASM formatting, release clippy, browser builds, pinned hashes, binding byte comparison,
  relation tests, holder-refresh tests, deterministic artifact reproductions and the ignored candidate
  Groth16 proof-generation gate: PASS.
- Solidity format, optimized size build and 202 unit/fuzz/invariant/integration tests: PASS.
- Release-contract coverage: PASS at 100% lines and branches for both `ProofOfHumanity.sol`
  and `PredicateVerifier.sol` (minimum 95%).
- Deterministic gas snapshot: PASS, 12/12 tests.
- Local Anvil deployment-tooling rehearsal: PASS on disposable chain ID `31337`; no external network,
  funded account or persistent deployment was used.
- Full-worktree `git diff --check`: PASS.

The first network-restricted dependency check could not resolve the npm registry; the lockfile-pinned
install passed with approved network access. Initial SDK/operator runs could not create their temporary
`tsx` IPC sockets inside the restricted sandbox; the identical suites passed with local-process access.
Neither was a source failure.

**QA approval:** merge the deterministic package; keep all AWS writes blocked pending a separately
authorized administrator session, live metadata verification and action-time confirmation.
