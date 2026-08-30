# Privacy gate — V2 holder browser hardening

- **Gate:** selector, storage, cache and network-surface review
- **Reviewer:** Codex privacy review
- **Date:** 2026-08-27
- **Verdict:** **PASS — synthetic production-disabled evidence only**

## Evidence

- The harness uses synthetic encrypted vaults and one repository-public packed-status snapshot only.
- Request URLs/bodies, DOM and Cache Storage contain no decrypted payload or holder/status selector.
- The service worker caches cohort-wide immutable code/WASM only; `/private/*` and non-GET traffic bypass caches.
- IndexedDB persists the encrypted portable vault, generic binding metadata and monotonic revision only. The
  input-only whole-vault digest is not stored as a receipt.
- Broadcast invalidation carries one constant schema string and no vault id, binding, revision, digest or selector.
- E2EE backup exposes only version/cipher/KDF plus random salt/IV/ciphertext. As ADR-0014 records, a backup provider
  can still correlate backup object timing/size and account metadata outside this SDK envelope.
- The extension adversary confirms that an origin-compromising actor can clone pre-transfer data. Production stays
  disabled pending independent browser review and holder-facing integration.

**Privacy approval:** the slice adds no new holder selector or telemetry surface and may merge disabled.
