# Privacy review — V2 production vault and private status refresh ADR

- **Gate:** explicit internal privacy/architecture review before implementation
- **Reviewer:** architecture/privacy reviewer
- **Date:** 2026-08-25
- **Scope:** ADR-0014 payload, refresh messages, trust/routing model, error surface, metadata and migration
- **Verdict:** **PASS — privacy-approved for implementation only**

No blocking privacy finding remains. This is an internal design approval, not an independent production privacy
audit or authorization to persist live credentials.

## Approved properties

- The complete Schnorr issuer artifact and depth-24 packed-status witness live inside authenticated vault
  ciphertext. Secret nonce material is absent.
- Every admitted public chain/registry/issuer cohort is fetched in a fixed bounded set before unlock. The CDN,
  resolver and host receive no holder-selected status id, chunk, bit, path, commitment or subject request.
- Snapshot bytes are immutable and dual-hashed; profile, issuer, reconciler and resolver trust is locally pinned in
  the worker rather than accepted from host input.
- The decrypted worker has no network and emits no progress. All issuer/status/rollback/activity failures after
  decrypt collapse to `CREDENTIAL_UNUSABLE`, with no arbitrary/nested diagnostics.
- Whole-vault JCS CAS is local/input-only and returns or persists no digest receipt.
- Commitment and status id are described honestly as public one-time issuance facts; the protected property is
  this holder/session/vault association and any selector derived from them.
- The exact 18 presentation signals remain unchanged; root/time are bounded and exact.
- Allocated reissuance is blocked until a separate design preserves duplicate-key and scoped-nullifier continuity.

## Residual metadata and trust

V1 provides selector privacy, not anonymity. CDN/RPC/resolver infrastructure can observe IP, timing, traffic size
and a public cohort/root. Downloads must be unauthenticated, cookie-free, content-addressed, cacheable and free of
per-holder URLs/cache keys; coarse cohort-wide prefetch independent of unlock is preferred.

Vault/backup storage can correlate stable vault id, RP id, passkey credential ids, key-slot count, ciphertext
length, schema/version and update timing. These values must not be joined to analytics. Padding or oblivious backup
access requires a new version.

The first-party origin is a trust root: XSS, a compromised extension or malicious first-party code can clone the
PRF before transfer. Implementation requires a restrictive CSP, Trusted Types, no third-party scripts on
credential routes, a content-addressed same-origin worker, immediate PRF transfer/drop and no network-capable
decrypted worker.

## Validation

- `pnpm test:v2-vault-contract` — PASS
- `pnpm --filter @ubi2/sdk typecheck` — PASS
- `git diff --check` — PASS

**Privacy approval:** the versioned payload parser and private refresh worker may be implemented under these
constraints. Live persistence, presentation and production activation still require runtime privacy tests and an
independent production review.
