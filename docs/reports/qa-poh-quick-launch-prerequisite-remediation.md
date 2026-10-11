# QA gate — Quick Launch prerequisite remediation

- **Gate:** deterministic empty-secret, two-subnet and deployment-role package
- **Reviewer:** Codex QA review
- **Date:** 2026-10-11
- **Scope:** local, transaction-free package only
- **Verdict:** **PASS — no AWS mutation and no live-readiness claim**

## Acceptance evidence

- The renderer accepts no secret-value field and emits two different fixed-name `CreateSecret` requests
  containing only names, descriptions and exact Base Sepolia/release/purpose tags.
- Exactly two subnet evidence records are required. Duplicate IDs, same-AZ pairs, mismatched VPCs,
  disabled public-IP mapping, absent active internet-gateway route and any Fobal-tagged input fail closed.
- The temporary administrator action allowlist is exhaustively pinned. Its only wildcard resource is
  region-bound EC2 metadata discovery; all mutations target exact secret prefixes, two subnet ARNs or the
  one CloudFormation deployment role.
- The deployment role trusts only CloudFormation for account `368426158592`, region `us-east-1` and stack
  name `poh-quick-launch-api`. It passes only the exact task execution role to ECS tasks.
- Every rendered mutation is independently marked unauthorized and names its mandatory pause point.

## Failure coverage

- Wrong account, region, Identity Center instance, principal, VPC, hosted zone and malformed topology fail.
- Missing, altered and extra secret/subnet/role tags fail the policy-contract tests.
- Secret value read/write/delete, tag removal, KMS, ECR publication, SSO mutation from the temporary principal, role
  assumption, unrelated IAM, CloudFormation control plane, VPC/subnet creation, EC2 instances, Lambda,
  Fobal, mainnet, funding and blockchain transactions are absent.
- The administrator and role inline policies are pinned below their respective AWS size limits.

## Canonical fixture evidence

- Administrator policy: `78ae3d699a8c017ff3183bde937c903a1ee025c65bf4979ef54c7bf37e938eb5`
- Issuer request: `e46df92a3df0809950af66e24404d41e086c4bb92922f3e3009a3abab188156f`
- Sponsor request: `ee6447efd85459f10201ff26ec0495736e2fd7d0349ca70a485c60fe6c3506ea`
- Two-subnet approval: `983b2671ff407bf239922af50ed40c99d8de34c5ee1816edc9126b9c5f430797`
- Deployment trust: `1a5a246a03b411974f3ff8dd3ca795a60dede809b40313397f1955c949758f74`
- Deployment permissions: `f149216e5e8030a39c8619d30cdbfbef0efb82e670129b33eae30c604a999227`
- Request plan: `165570ab4b291794f1008b90d7d7053b1e1b0a496985cd4e09a809955e17f325`
- Package binding: `eef9f0295ab679289849f46a43c23cb36753b6484cf22bccd6ca6888181e13f6`

These hashes prove deterministic fixture rendering only. No live subnet, secret, role or permission set is
approved by this report.

## Validation results

The complete repository gate applicable to this transaction-free slice passed on 2026-10-11:

- `pnpm install --frozen-lockfile`
- remote-font import gate
- `pnpm -r build` (existing wallet lint warnings only) and `pnpm -r typecheck`
- Proof of Humanity product, contract, PWA and focused prerequisite-remediation suites
- SDK, status-operator, status-operator cast, holder-browser, holder-refresh, holder-refresh-wasm and
  holder-vault suites
- `cargo fmt --all --check`, workspace clippy/build/test and the ignored M5 Stage A suite
- Solidity format, size, 202-test, coverage and gas-snapshot gates; `ProofOfHumanity` and
  `PredicateVerifier` each retained 100% line and branch coverage
- V2 Rust/WASM format, clippy, release build/test, deterministic proof-candidate, generated-binding,
  fixture, constraint, status, parameter, vector, sanctions-constraint and source-freeze gates

The Rust workspace test and Foundry test suite were repeated outside the filesystem sandbox after their
first runs hit sandbox-only localhost/proxy restrictions; the repeated gates passed. The local Phase 2
ceremony rehearsal was intentionally not run because it performs local chain transactions and is outside
this slice's explicit no-transaction boundary. No AWS command or external blockchain transaction ran.
