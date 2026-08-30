# V2 holder vault UX in the Proof of Humanity PWA

- **Status:** implemented for testnet rehearsal; production admission disabled
- **Product:** [`apps/proofofhumanity`](../../apps/proofofhumanity)
- **Vault:** [`credential-vault-indexeddb.ts`](../../packages/sdk/src/credential-vault-indexeddb.ts)
- **Boundary:** [ADR-0014](adr/0014-v2-production-vault-and-private-status-refresh.md)
- **Physical drill:** [`HOLDER_VAULT_DEVICE_DRILL.md`](../../ops/proofofhumanity/HOLDER_VAULT_DEVICE_DRILL.md)

## Product boundary

The real Proof of Humanity app exposes the holder vault step only when
`NEXT_PUBLIC_V2_HOLDER_VAULT_TESTNET_ENABLED=true`, `NEXT_PUBLIC_SELF_ENV=staging`, and the selected target is
explicitly classified as a public testnet. Local chains and every mainnet fail closed. The encrypted payload is a
bounded rehearsal record with `productionEligible: false`; it contains no passport attributes, issuer production
payload, status witness, proof material or presentation capability.

Both production controls remain false:

- `ZK_HOLDER_PRIVATE_STATUS_REFRESH_INDEPENDENT_AUDIT_APPROVED === false`; and
- the packaged refresh Worker policy remains forcibly `productionApproved: false`.

The additional product UX constant `HOLDER_VAULT_PRODUCT_PRODUCTION_APPROVED` is also false. No environment variable
can override any of these compile-time controls.

## WebAuthn PRF ceremony

Enrollment creates a user-verified discoverable passkey with attestation set to `none` and requests the standard
WebAuthn `prf` extension. Registration output is used only if it contains an exact 32-byte result. Otherwise the app
performs a user-verified assertion for the new credential and fails closed when the authenticator does not return
PRF output. Unlock supplies only enrolled credential ids and each slot's independent 32-byte salt. Multi-passkey
unlock uses `evalByCredential`; the asserted raw credential id must identify one existing slot.

The challenge is local because this ceremony gates local encryption, not a server login. PRF output is copied into
one bounded `Uint8Array`, tracked by the account/session boundary, used to derive a non-extractable AES wrapping key,
then zeroed. It is never placed in React state, IndexedDB, Web Storage, URL, request, log, receipt, recovery package
or telemetry. Browser capability detection changes copy only; an actual 32-byte extension result is always required.

## Account and session invalidation

The encrypted database name is the truncated SHA-256 of the normalized credential account and relying-party id; the
address is not embedded in the name. Each wallet account plus 128-bit Self browser session identifies one in-memory
session boundary. Account, session, chain or voucher-binding changes abort pending WebAuthn operations, zero tracked
byte secrets, invalidate stale async completions, hide the recovery key and relock the vault. A synchronous action
lock prevents duplicate ceremonies before React can rerender. PWA reload/crash also loses all unlocked state. The durable
vault is not deleted on invalidation, so returning to the same account requires a fresh privacy acknowledgement and
passkey assertion.

`inspectIndexedDbCredentialVaultStore` discovers only strict public routing metadata (`vaultId`, binding and enrolled
credential ids). It cannot decrypt or authorize use. Every durable mutation—second passkey or proof binding—uses the
existing whole-vault digest and `IndexedDbCredentialVaultStore.compareAndSwap`; a competing tab wins at most once.

## Enrollment and proof binding

Before a passport callback, enrollment may seal a testnet rehearsal payload bound to the dedicated account, current
session hash and selected testnet. This lets a holder test passkey and recovery support before scanning a document.
After the app receives a verified testnet voucher, an explicit second passkey assertion atomically replaces the
encrypted rehearsal payload with one additionally bound to the SHA-256 of the canonical chain, contract, recipient,
nullifier, epoch and signature tuple. Neither digest is an admission receipt or presentation proof.

## Encrypted recovery

Backup adds an independent AES-256-GCM envelope over the complete encrypted vault. The recovery package contains only
public account/site routing metadata plus the authenticated ciphertext. The separately displayed 256-bit recovery
key is never persisted by the app and is cleared from the current product state on hide, cancellation, account/session
change or unmount. Explicit clipboard use remains a user-controlled OS trust boundary.

Restore is empty-only. The package must match the exact normalized account, RP id, schema and vault id. It cannot
replace a local vault. The recovery key authenticates the backup envelope but does not replace WebAuthn: an enrolled
passkey is still required after restore. Status freshness and production payload validation remain separate closed
gates under ADR-0014.

## PWA and tests

The app now serves a standalone manifest and a lifecycle-only service worker. The worker has no `fetch` handler and
uses no Cache Storage, so it cannot observe or cache API calls, encrypted backups, WebAuthn inputs or vault data.

The production-build Chromium suite uses a deterministic WebAuthn PRF API double (not physical-authenticator evidence)
and verifies enrollment/unlock, second-passkey CAS, encrypted download, fresh-profile restore, crash/reload relock,
cancellation even when a native credential API ignores abort, rapid duplicate-action suppression, account-switch
invalidation, empty Cache Storage and absence of plaintext/recovery secrets in browser
persistence. Representative physical iOS and Android execution remains an explicit admission prerequisite; the
current machine inventory and manual procedure are recorded without claiming simulator evidence as physical.

## Validation

```bash
pnpm --filter @ubi2/proofofhumanity typecheck
pnpm --filter @ubi2/proofofhumanity test:product
pnpm --filter @ubi2/proofofhumanity test:pwa
pnpm --filter @ubi2/sdk typecheck
pnpm test:v2-vault-contract
pnpm test:v2-holder-refresh
pnpm test:v2-holder-refresh-wasm
```
