# Security gate — V2 holder production vault parser and private status refresh boundary

- **Gate:** defensive implementation review
- **Reviewer:** Codex security review
- **Date:** 2026-08-26
- **Scope:** private selectors, trust roots, signatures, parser strictness, key lifetime, errors and admission
- **Verdict:** **PASS — boundary implementation only; production remains blocked**

No Critical/High finding remains in the implemented boundary.

## Controls verified

- Unknown fields fail closed throughout the production payload, issuer artifact, witness, refresh request,
  resolution, trust bundle and result union. Vault binding is exactly `{schema,rpId}`.
- Snapshot and resolver attestations require sorted unique EIP-55 signers, canonical lowercase 65-byte signatures,
  low `s`, `v` 27/28, recovery to Worker-pinned quorum keys and exact configuration/domain equality.
- SHA-256 and Keccak bind the same canonical full snapshot bytes; the Worker never requests a status id, chunk,
  subject, commitment or path from a remote service.
- All cohorts validate before decrypt; network locking precedes decryption; the PRF buffer is transferred and
  zeroed; no progress, digest, plaintext, detailed error or selector crosses the Worker boundary.
- Decrypted parse/issuer/slot/witness/rollback/activity failures collapse to `CREDENTIAL_UNUSABLE`.
- Whole-envelope CAS includes key slots and ciphertext, closing passkey-enrollment/recovery overwrite races.
- The exported disabled engine rejects production, and the existing browser runtime still rejects the production
  vault schema. Tests use only the synthetic contract vector and test-only signing keys.

## Residual production blockers

- Poseidon credential/root/path computation, Baby-Jubjub on-curve/subgroup/key-id/Schnorr verification and real
  memory accounting are an injected cryptographic-engine responsibility and are not implemented by this slice.
- `lockNetwork()` is an explicit engine/packaging contract, not proof against a hostile origin. CSP, Trusted Types,
  content-addressed same-origin Worker loading and adversarial exfiltration tests remain mandatory.
- The first-party origin can clone a PRF before transfer; ADR-0014's hostile-origin residual remains unchanged.
- Independent circuit, browser/vault and production audits are still required.

**Security approval:** merge the fail-closed boundary. Do not enable live credential persistence, proving,
presentation or production admission.
