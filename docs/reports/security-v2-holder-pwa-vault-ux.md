# Security gate — V2 holder PWA vault UX

**Result: GREEN for the production-disabled testnet slice; no open High/Critical findings.**

## Boundary review

- Feature activation requires exact public flag `true`, Self staging and explicit `network: "testnet"`; mainnet and
  local classifications fail closed independently of names or configured addresses.
- Persisted rehearsal payloads and recovery packages require literal `productionEligible: false`. The independent
  audit bit and packaged Worker production policy were not opened; the product adds another compile-time false bit.
- WebAuthn capability hints do not grant access. A valid returned public-key credential id and exact 32-byte PRF
  result are mandatory. User verification is required for registration and assertions; attestation is `none`.
- PRF outputs and recovery-key byte arrays are tracked across the active account/session boundary and zeroed after
  use, abort, cancellation or invalidation. Monotonic operation generations discard stale completions and a
  synchronous lock prevents duplicate ceremonies. Secrets are never persisted, fetched, logged or included in evidence.
- Database naming hashes account plus RP id. Recovery binds the public account, schema, RP id and vault id before
  authenticated empty-only restore. Wrong-account/site packages and occupied stores reject.
- Adding a passkey or voucher binding is an atomic complete-vault CAS, so a stale tab cannot silently remove slots or
  replace a newer payload.
- The service worker cannot observe requests and keeps no cache. Download is a user-initiated local Blob. Explicit
  clipboard copy is accurately treated as an OS/user trust boundary.

## Residual risks and non-claims

- Decrypted rehearsal data and the PRF result necessarily enter first-party main-thread JavaScript briefly. The
  existing extension/preload compromise finding still applies; production admission requires the independent browser
  review and stronger isolated execution boundary.
- The separately displayed recovery key is an immutable JavaScript string until garbage-collected after hiding. It is
  testnet-only and never persisted by the app, but a compromised page/extension/clipboard can copy it.
- A recovery package plus key does not recover a lost passkey. This is stated in the UI/runbook and prevents a false
  availability promise.
- The deterministic CI authenticator is not evidence for native iCloud/Google credential sync, authenticator PRF
  behavior, OS cancellation or mobile memory pressure. Physical evidence remains open.
- Next.js' broader app CSP/Trusted Types migration remains outside this slice. The prior isolated Worker harness still
  defines the production cryptographic envelope; this UI is not admitted to that envelope.

No secret/private key was introduced. Public environment flags contain no authority. Mainnet remains disabled.
