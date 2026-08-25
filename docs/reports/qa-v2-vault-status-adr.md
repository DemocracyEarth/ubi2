# QA gate — V2 production vault and private status refresh ADR

- **Gate:** contract/vector validation before implementation
- **Reviewer:** qa-engineer
- **Date:** 2026-08-25
- **Scope:** ADR-0014, contract vector/test, CI wiring, related project-state docs and immutable-profile integrity
- **Verdict:** **PASS — approved for implementation only**

No blocking finding remains.

## Acceptance evidence

- The fixture carries exactly the verifier-required Schnorr issuer fields and omits issuer secret, nonce,
  auxiliary randomness, stored challenge, raw nullifier and duplicate key.
- The packed-status fixture selects an active bit, carries two little-endian limbs and exactly 24 bottom-up siblings;
  directions are derived rather than stored.
- Signal names match both canonical V1 manifests in exact order and count 18.
- The refresh contract pins exact request/cohort/resolution/trust/result field sets, EIP-712 resolution types,
  aggregate resource limits, whole-vault CAS and bounded privacy-preserving errors.
- Migration cases distinguish pre-allocation retry from blocked post-allocation supersession/reissuance.
- Security, privacy and reliability reports are green and explicitly limited to implementation.
- ADR-0013 and every file in its immutable artifact index remain byte-identical.
- No runtime parser, live persistence path, presentation authorization, verifier activation or allocated-credential
  reissuance was introduced.

## Commands and results

- `pnpm test:v2-vault-contract` — PASS
- `pnpm --filter @ubi2/sdk typecheck` — PASS
- `pnpm --filter @ubi2/sdk test` — PASS
- `cargo test --manifest-path tools/v2-crypto-bench/Cargo.toml --release artifact_index_matches_every_published_byte` — PASS
- `git diff --check` — PASS
- dedicated `v2-vault-contract` workflow — invokes the focused test and SDK typecheck

**QA approval:** implement the strict payload parser, private refresh worker, authenticated resolver contract and
atomic vault storage flow. Do not infer approval for live credential persistence, presentation, production
activation, verifier deployment or allocated reissuance.
