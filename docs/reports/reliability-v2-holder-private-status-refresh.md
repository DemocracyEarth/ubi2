# Reliability gate — V2 holder private status refresh boundary

- **Gate:** implementation consistency and failure-mode review
- **Reviewer:** Codex reliability review
- **Date:** 2026-08-26
- **Scope:** ordering, rollback/equivocation, resource/deadline behavior, Worker lifetime and atomic storage
- **Verdict:** **PASS — boundary implementation only**

## Properties verified

- The Worker accepts exactly one fixed-order cohort set and rejects missing, extra, reordered or invalid decoys
  before decrypt, so cohort failure cannot become a selected-issuer oracle.
- Both host and Worker enforce cohort, byte, chunk, attestation and JSON-depth limits; Worker memory and wall-clock
  limits are fixed constants with no request override.
- Higher snapshot ids require non-regressing publication time. Equal ids return `unchanged` only for exact
  root/watermark/time; lower/divergent state becomes the single private `CREDENTIAL_UNUSABLE` failure.
- Updated output is a complete authenticated vault with a fresh IV. The commit helper delegates one durable
  compare-and-swap transaction over the whole persisted vault; stale key-slot changes win and the refresh is
  discarded.
- Success/failure paths abort the controller, zero transferred buffers where possible, destroy the engine and rely
  on the host to terminate the disposable Worker.

## Residual gates

- A concrete browser storage adapter still needs multi-tab IndexedDB CAS, crash/restart and backup-restore drills.
- The production WASM engine must report real memory, honor cancellation and prove deterministic full-snapshot
  root/path construction under load and on measured mobile hardware.
- Content-addressed Worker packaging and actual browser network-capability removal need adversarial browser tests.

**Reliability approval:** the protocol and storage boundary may merge while admission remains disabled.
