# Security gate — V2 holder refresh WASM engine

- **Gate:** defensive cryptographic and browser-boundary review
- **Reviewer:** Codex security review
- **Date:** 2026-08-27
- **Scope:** commitment/signature/path verification, subgroup attacks, artifact integrity, exfiltration surfaces and admission
- **Verdict:** **PASS — production remains blocked**

No open Critical/High finding remains in this implementation slice.

## Controls verified

- Credential commitment, issuer key id and status root are recomputed with circuit-native Poseidon constants and
  domains; the host cannot supply an alternate hash implementation.
- Baby-Jubjub public and nonce points require canonical field coordinates, on-curve/nonidentity checks and prime-
  subgroup membership before key-id or Schnorr verification. Response mutation and the order-two torsion point
  reject.
- Packed status requires an active selected bit, exact depth-24 directions/siblings and equality to both the
  canonical snapshot reconstruction and stored root.
- The same-origin Worker fetches the immutable WASM without credentials/referrer, checks length and SHA-256 before
  compilation, and locks ordinary network capabilities before private payload verification/path derivation.
- The holder engine is isolated from the frozen sanctions ceremony crate, preventing this package from silently
  rewriting that circuit's source provenance.
- Worker source contains no logging/progress path. The existing boundary continues to collapse every decrypted
  cryptographic/status failure to `CREDENTIAL_UNUSABLE` and terminates the Worker.
- Defense in depth keeps admission closed twice: the SDK's compile-time independent-audit constant is false and
  the packaged Worker forcibly rewrites `productionApproved` to false.

## Residual production blockers

- A first-party origin, extension or pre-transfer XSS remains able to clone the PRF or replace application code;
  content addressing is not confidentiality from a hostile origin.
- CSP, Trusted Types, third-party-script exclusion and service-worker/cache behavior need adversarial browser audit.
- Independent cryptographic/source-to-WASM review, reproducibility attestations, mobile measurements and recovery
  exercises are required before either admission bit changes.

**Security approval:** merge the fail-closed candidate. Do not enable live persistence, proving or presentation.
