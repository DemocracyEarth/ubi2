# Reliability gate — V2 holder refresh WASM engine

- **Gate:** deterministic execution, limits and lifecycle review
- **Reviewer:** Codex reliability review
- **Date:** 2026-08-27
- **Scope:** reproducible artifacts, sparse-path determinism, memory, cancellation and disposable Worker lifetime
- **Verdict:** **PASS — production-disabled engine candidate only**

## Properties verified

- Native and WASM paths consume the same canonical snapshot bytes and produce the same fail-closed sparse tree and
  depth-24 witness; no status selector is needed to fetch the public input.
- The committed WASM, generated binding and Worker source have explicit SHA-256/byte pins. CI rebuilds and byte-
  compares the WASM under the pinned Rust/wasm-pack toolchain.
- The adapter rejects substituted artifact identities and linear memory above 256 MiB. Existing host/Worker byte,
  chunk, JSON-depth and 60-second job limits remain unchanged.
- Pre-start abort performs no load. An abort while loading suppresses the circuit call. Mid-flight host abort
  detaches the transfer set, terminates the disposable Worker and emits only `CANCELLED`.
- Network masking is irreversible for fetch, XHR, WebSocket, EventSource, WebTransport and `importScripts`; failure
  to mask any existing non-configurable capability rejects the job.

## Residual gates

- Reproduce the content-addressed build in an independent environment and complete an external source-to-WASM
  audit before changing the audit bit.
- Run adversarial Chromium/PWA and measured mobile jobs under real CSP/Trusted Types and extension/service-worker
  conditions.
- Complete multi-tab IndexedDB CAS, crash/restart, backup restore and recovery drills.

**Reliability approval:** merge with admission closed.
