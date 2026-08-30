# Reliability gate — V2 holder browser hardening

- **Gate:** concurrency, durability, recovery and resource review
- **Reviewer:** Codex reliability review
- **Date:** 2026-08-27
- **Verdict:** **PASS — production-disabled evidence only**

## Properties verified

- IndexedDB read/write transactions serialize tabs; a revision recheck inside the durable transaction permits one
  winner from a shared prior digest and rejects the stale writer.
- The digest remains input-only. The persisted record contains one complete encrypted vault plus monotonic revision;
  the cross-tab notification contains no vault, digest, selector or revision receipt.
- Fault injection before commit aborts the transaction. Immediate read, database close/reopen and application-style
  restart all recover the exact old whole vault.
- Backup restore is authenticated and binding-checked. Empty-only mode preserves an occupied store; explicit
  replacement uses the same whole-vault CAS.
- Service-worker caching is restricted to immutable public artifacts. The exact Worker/WASM remain available as
  content-addressed public resources without caching holder inputs or private responses.
- Ten 4× CPU-throttled emulated-mobile probes each measured 1,179,648 bytes WASM linear memory, well below the
  256 MiB hard cap. Twenty disposable-Worker cancellations measured 0.945 ms p95 on the committed run.

## Residual gates

- The mobile numbers are Chromium emulation on macOS, not representative physical-device admission evidence.
- Independent artifact reproducibility and browser-security audits are still required.
- Holder-facing WebAuthn ceremony, multi-device UX and adversarial testnet soak remain outside this harness.

**Reliability approval:** merge with both admission bits false.
