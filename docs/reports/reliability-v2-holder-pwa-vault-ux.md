# Reliability gate — V2 holder PWA vault UX

**Result: GREEN for testnet rehearsal; production-mobile evidence NOT RUN.**

## Durable-state and cancellation findings

- The product reuses the strict-durability, whole-record IndexedDB CAS from the browser-hardening slice. Second-passkey
  and proof-binding mutations first hash the complete observed vault and commit only on the matching serialized
  revision. Cross-tab notifications are content-free invalidations and force a re-read plus relock.
- PWA reload/crash has no route to reconstruct unlocked state. The production-build drill closes/reloads the page and
  observes the same encrypted vault in `locked` state after a new session acknowledgement.
- Account, Self session, selected chain and proof-binding changes rotate an abort controller, zero all tracked byte
  secrets and relock. A synchronous action lock rejects duplicate ceremonies, and a monotonic operation generation
  prevents an older completion from overwriting newer UI state even when a credential implementation ignores abort.
- Backup restore is empty-only and authenticated before the store becomes usable. A fresh browser context restores
  the complete encrypted vault and requires a new passkey assertion.
- The lifecycle-only service worker has no fetch listener. Cache Storage remains empty after install/control/reload,
  avoiding offline stale identity state and private-request replay.

## Resource bounds

Existing SDK bounds remain: maximum 256 KiB credential plaintext, 16 key slots and 512 KiB backup ciphertext. Product
recovery input is additionally capped at 768 KiB, WebAuthn operations time out at 120 seconds and the local binding
input is capped before hashing. Every restore/mutation is one complete-vault operation.

## Physical lane

Host inventory on 2026-08-30 found Command Line Tools only (`devicectl`/`xctrace` unavailable), no Apple mobile USB
device, no `adb`, no Android USB device and no configured authorized device farm. Therefore no physical iOS or Android
claim was made. The exact crash/recovery/cancellation procedure and sanitized evidence schema are committed in
`ops/proofofhumanity/HOLDER_VAULT_DEVICE_DRILL.md`.

This missing evidence blocks production mobile admission, not the requested fail-closed testnet merge. Both existing
production-admission bits remain false.
