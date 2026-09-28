# QA gate — Quick Launch infrastructure administrator package

- **Gate:** deterministic permission-set, assignment, prerequisite policy and failure paths
- **Reviewer:** Codex QA review
- **Date:** 2026-09-28
- **Scope:** local, transaction-free package only
- **Verdict:** **PASS — no AWS mutation or live-readiness claim**

## Acceptance evidence

- The renderer accepts only account `368426158592`, `us-east-1`, one valid Identity Center instance,
  one workforce USER, two distinct same-account/region secrets, optional same-account/region KMS keys,
  one VPC, exactly two distinct subnets/AZs, one hosted zone and the exact fixed-name CloudFormation role.
- The permission set is fixed to `PoHQuickLaunchInfrastructureAdministrator`, `PT1H` and the three
  Quick Launch/Base Sepolia tags.
- The administrator action allowlist is exhaustively pinned. Only unavoidable metadata discovery and
  server-generated certificate requests have wildcard resources; every mutable existing resource uses
  exact ARNs and exact tags.
- The task execution trust and inline policy reproduce the frozen contract. Secret values are available
  only to the ECS agent on the exact runtime role, never to the administrator.
- The dependency-ordered request plan stops before application stack/change-set creation, and all render
  outputs state `mutatesAws=false`, `applyAuthorized=false`, and `pauseBeforeApply=true`.

## Failure coverage

- Wrong account/region/instance/principal/resource ARNs, duplicate signer references, cross-account or
  cross-region signer/KMS inputs, duplicate subnets, same-AZ topology, invalid hosted zone, wrong
  CloudFormation role and Fobal-named secrets fail closed.
- Missing, changed and additional secret/subnet/task-role tags fail the exact rendered contracts.
- Tests prove there is no secret-value authority, secret write/delete, tag removal, subnet/VPC creation,
  certificate deletion/export, hosted-zone creation/deletion, role pass/delete/trust mutation, ECR
  publication, CloudFormation, ECS, SSM, unrelated role, mainnet or Fobal authority.
- Redacted attestations contain only hashes of protected identifiers; raw references remain in the
  protected package required by the administrator handoff.

## Canonical fixture evidence

- Administrator policy: `0fb0fdca37bda6df2896f40b094ba7184518f08df68e5ad529d032ea9495adb9`
- Task trust: `4ae85e6ac6805330260b864794cabdedf5061f5a2cc701b17444f4399c8f8bee`
- Task permissions: `cccd8806988f15b1b000e2e79ea963e319a4d863dc2018390982d8d6a3286adc`
- Request plan: `1a9c0306d33f65fd48b54e550b1ee836fe1ccd94e4571dea6a40a6b4902dee01`
- Package binding: `1dace18c0cd7e8539fe36ec14f1b646046abd06cb06a452f702902a04b7b7216`

These are regression-fixture hashes, not live AWS authorization values. Real protected identifiers must
produce a separately reviewed live binding.

## Validation

- `pnpm install --frozen-lockfile`, remote-font rejection, workspace build and workspace typecheck: PASS.
- Quick Launch, cross-stack Proof of Humanity, SDK, status-operator and encrypted cast-signing suites:
  PASS, including the new exact action/resource/tag and forbidden-path coverage.
- Holder browser and Quick Launch PWA Chromium gates: PASS (4 + 1 tests).
- Rust workspace format, warnings-denied clippy, locked build, serial tests and ignored multi-node M5
  acceptance: PASS.
- V2 Rust/WASM format, clippy, browser builds, binding/hash comparisons, release tests, all-candidate
  Groth16 proof generation and deterministic artifact reproductions: PASS.
- Repository-owned Solidity format (`src`, `test`, `script`), optimized build, 202 Forge tests, 100%
  target-contract line/branch coverage and 12 deterministic gas checks: PASS. The raw recursive local
  formatter also inspected ignored pre-existing `contracts/lib` dependencies and found two vendor-only
  style differences; no dependency bytes were changed. A clean PR checkout remains the authoritative
  recursive-format check.
- The local Phase 2 Anvil deployment rehearsal was deliberately not run because this slice explicitly
  prohibits transactions; no external network, AWS API or blockchain transaction was used.

**QA approval:** merge the deterministic package; keep AWS apply blocked pending live metadata review
and separate action-time confirmation.
