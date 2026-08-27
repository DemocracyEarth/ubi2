# QA gate — V2 circuit-native holder refresh WASM engine

- **Gate:** implementation acceptance
- **Reviewer:** Codex QA review
- **Date:** 2026-08-27
- **Scope:** Rust native relations, WASM exports/artifacts, SDK adapter, Worker package and focused tests
- **Verdict:** **PASS — production-disabled engine candidate only**

No blocking correctness finding remains in this slice.

## Acceptance evidence

- The Rust engine reuses the circuit's exact Poseidon configuration/domains, holder-credential field order,
  Baby-Jubjub challenge/scalar conversion and depth-24 Merkle relation.
- The ratified ADR-0014 vector verifies through the committed WASM. Credential, Schnorr response and sibling
  mutations reject.
- The holder engine builds from its own crate; the sanctions circuit source-freeze digest remains byte-exact.
- Issuer and nonce points require canonical coordinates, on-curve, nonzero and prime-subgroup membership. The
  nonzero Baby-Jubjub order-two point rejects.
- Full sparse snapshots enforce exact canonical parsing, sorted unique chunks, fail-closed omitted chunks and tail
  bits, declared-root reconstruction, active-slot selection and exactly 24 bottom-up siblings.
- The SDK adapter strictly parses the bounded WASM path result, pins WASM/binding hashes and sizes, reports real
  linear memory, and observes aborts before and after loading/calls.
- Focused tests cover real WASM execution, substitution, resource, same-origin URL, network-lock and cancellation
  behavior. The existing all-cohort privacy/CAS suite remains green.

## Required validation

- `cargo test --release --locked --manifest-path tools/v2-holder-refresh-engine/Cargo.toml` — PASS
- `cargo clippy --release --locked --manifest-path tools/v2-holder-refresh-engine/Cargo.toml --all-targets -- -D warnings` — PASS
- `pnpm test:v2-holder-refresh` — PASS
- `pnpm test:v2-holder-refresh-wasm` — PASS
- `pnpm --filter @ubi2/sdk typecheck` — PASS
- Worker-entry standalone TypeScript check — PASS

**QA approval:** merge the circuit-native candidate and its packaging. Do not change either production/audit bit or
claim browser/mobile readiness.
