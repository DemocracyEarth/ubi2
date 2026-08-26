# QA gate — V2 holder production vault parser and private status refresh boundary

- **Gate:** implementation acceptance
- **Reviewer:** Codex QA review
- **Date:** 2026-08-26
- **Scope:** SDK parser, vault transform, all-cohort Worker/client protocol, atomic-CAS boundary, tests and CI
- **Verdict:** **PASS — boundary implementation only**

No blocking correctness finding remains in this slice.

## Acceptance evidence

- The production plaintext parser rejects unknown/missing fields and pins the exact profile id, parameter digest,
  issuer artifact, issuance transcript and depth-24 witness shape from ADR-0014.
- Every public cohort, canonical snapshot, content digest, trust-bundle digest, threshold signature, finalized
  resolution and resource limit is validated before the vault is decrypted.
- The Worker transfers the PRF buffer, locks its network seam before decrypt, emits no progress, replaces only the
  status witness semantically and returns only the bounded result union.
- Identical snapshot ids are idempotent only for exact root/watermark/time; rollback and same-id divergence fail.
- The vault transform keeps vault id/binding/key slots, uses a fresh AES-GCM IV and zeroes the unwrapped vault key.
- Whole-envelope JCS SHA-256 CAS prevents a stale refresh from overwriting concurrent passkey enrollment.
- The default checked-in engine and existing browser prover remain production-disabled.

## Validation

- `pnpm test:v2-vault-contract` — PASS
- `pnpm test:v2-holder-refresh` — PASS
- `pnpm --filter @ubi2/sdk test` — PASS
- `pnpm -r typecheck` — PASS
- `pnpm -r build` — PASS; existing wallet lint warnings only
- workflow YAML parse — PASS
- `git diff --check` — PASS

**QA approval:** merge the parser/protocol/CAS boundary. Do not treat the mock cryptographic test engine as
Poseidon/Schnorr/path evidence or enable live persistence/presentation.
