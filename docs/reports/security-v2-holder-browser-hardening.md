# Security gate — V2 holder browser hardening

- **Gate:** browser isolation, artifact substitution and recovery abuse review
- **Reviewer:** Codex security review
- **Date:** 2026-08-27
- **Verdict:** **PASS — production remains blocked**

No new Critical/High implementation finding remains in this production-disabled slice.

## Controls verified

- Production CSP excludes third-party origins and dangerous embedding/form/object surfaces. Trusted Types requires
  one named policy with a narrow reviewed service/module-Worker URL allowlist; string HTML injection rejects.
- COOP/COEP/CORP isolate the origin. Referrers, ambient credentials and cross-origin Worker/WASM downloads are
  excluded.
- A malicious controlling service worker that substitutes the WASM receives a fail-closed length/content-address
  rejection before circuit execution.
- Ordinary network capabilities are non-configurably masked in the refresh Worker before private decryption.
- Neither Cache Storage, broadcast invalidation nor durable CAS metadata contains decrypted fields, holder/status
  selectors or whole-vault digest receipts.
- Backup ciphertext is independently authenticated; wrong key/tamper/binding cases reject, and empty restore cannot
  overwrite an occupied vault.
- CI and the runtime assert the independent-audit constant and Worker policy bit both remain false.

## Explicit residual threat

The simulated extension/first-party hook successfully clones the synthetic request before native `postMessage`
transfer. This is expected and important evidence: buffer detachment cannot defend against a compromised origin or
extension that runs first. CSP/Trusted Types reduce XSS likelihood but do not make a hostile first party safe. This
residual alone prevents this slice from authorizing live production persistence or refresh.

**Security approval:** merge the hardening harness and fail-closed persistence primitives; do not change either
admission bit.
