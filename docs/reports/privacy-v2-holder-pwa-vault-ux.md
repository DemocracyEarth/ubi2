# Privacy review — V2 holder PWA vault UX

**Result: GREEN for synthetic/testnet rehearsal, with production admission closed.**

- The rehearsal payload contains only a dedicated public account, session hash, public testnet id and optional digest
  of an already public voucher tuple. It contains no name, document number, face, birth date, nationality, sanctions
  value, issuer private material, witness, presentation or raw Self nullifier outside the encrypted digest input.
- IndexedDB stores the strict encrypted portable vault only. The account-specific database name is derived from a
  truncated SHA-256 and does not embed the address. Broadcast invalidation remains content-free.
- Recovery packages expose the public account/site/vault locator needed for safe routing and an authenticated
  ciphertext. They omit the recovery key, PRF output, plaintext and browser session. The key is displayed only after
  explicit backup, never persisted, and cleared from UI state on invalidation/hide.
- The PWA service worker has no fetch handler and creates no cache, preventing accidental storage/observation of API
  routes, backup downloads or identity traffic.
- Account changes destroy the in-memory session, hide recovery material and prevent the prior account's summary from
  crossing into the next account view. Returning requires a new acknowledgement and passkey assertion.
- Physical evidence must be sanitized and explicitly forbids account values, recovery keys, screenshots and secret
  material. The committed inventory records only unavailable tooling/device facts.

Residual first-party/extension and explicit clipboard risks remain visible and are not reclassified as anonymity.
