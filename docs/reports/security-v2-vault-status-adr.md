# Security gate — V2 production vault and private status refresh ADR

- **Gate:** internal security review before implementation
- **Reviewer:** security-engineer (authorized defensive review)
- **Date:** 2026-08-25
- **Scope:** ADR-0014, its deterministic contract vector/test and the ADR-0011/0012/0013 trust boundaries
- **Verdict:** **PASS — approved for implementation planning only**

No Critical or High finding remains open. This is approval of a proposed contract and data flow, not live
credential persistence, proving, deployment or production activation.

## Threats reviewed

- issuer public-key, signature, commitment, status-slot and issuance-transcript substitution;
- secret scalar, nonce, auxiliary-randomness and raw-nullifier retention;
- cross-chain/registry/issuer replay and unapproved issuer keys;
- malicious, stale, revoked, rolled-back or selectively equivocated snapshots;
- per-holder witness requests, issuer routing, progress/error or telemetry oracles;
- hostile host/origin, PRF retention, worker network exfiltration and oversized browser inputs;
- ciphertext/key-slot refresh races, crashes and restored backups; and
- issuer rotation/reissuance which could bypass the permanently consumed duplicate key or produce a second scoped
  nullifier.

## Closed findings

| Finding | Original severity | Resolution |
|---|---:|---|
| Allocated “make-before-break” reissuance could not execute in the current registry and a new holder secret could produce two scoped nullifiers | **High** | Allocated reissuance is explicitly blocked pending a separately ratified supersession transition which preserves the consumed duplicate key, proves holder-secret/nullifier continuity, never reuses the old slot and retires every old accepted path. |
| Payload-ciphertext CAS could overwrite concurrent passkey enrollment/recovery | Medium | CAS now hashes RFC 8785/JCS canonical serialization of the whole vault, is input/local-only and commits the complete envelope atomically. |
| A host/RPC could substitute or replay snapshot acceptance/issuer-retirement state | Medium | Worker-pinned reconciler and short-lived resolver quorums bind canonical snapshot hash, registry codehash, active/accepted/revoked state, root, watermark, time, finality and observation block. |
| Pre-decrypt snapshot routing could reveal the vault's issuer | Medium | Every job fetches and validates the same bounded, exact admitted cohort set before unlock; the worker selects only after decryption. |
| Unbounded snapshots/attestations could exhaust browser memory or time | Medium | Aggregate cohort, byte, chunk, attestation, nesting, memory and deadline constants reject before unlock and cannot be raised by a request. |
| The original privacy language overstated protection from the browser host and network metadata | Medium | The first-party origin is an explicit trust root; runtime gates require CSP/Trusted Types, no third-party credential-route scripts, a content-addressed same-origin worker, immediate PRF transfer/drop and no worker network after decrypt. Network/backup residuals are documented. |
| Registry `uint64 publishedAt` could overflow or drift from frozen signal 17 | Medium | V1 requires nonzero `uint32` time and exact destination-policy equality with no truncation/remapping. |

## Residual accepted risks and runtime gates

- XSS or compromised first-party code can clone the PRF before transfer; buffer detachment is not a defense against
  a hostile origin.
- Resolver/reconciler quorums remain explicit public-data trust roots. A future light-client/state proof requires a
  new trust-bundle version.
- An old witness remains usable while governance and a policy still accept its exact old root/time. Local rollback
  checks are defense in depth, not revocation.
- Full all-cohort snapshot distribution has availability and scalability cost. V1 provides selector privacy, not
  network anonymity.

Runtime implementation must add strict-parser mutations, issuer/subgroup/signature negatives, snapshot/quorum
replay and equivocation attacks, worker exfiltration tests, multi-tab CAS/crash recovery, restore drills and
independent circuit/browser/vault audits before any production approval.

## Validation

- `pnpm test:v2-vault-contract` — PASS
- `pnpm --filter @ubi2/sdk typecheck` — PASS
- `git diff --check` — PASS

**Security approval:** ADR-0014 may be implemented. It may not be used to persist or present live credentials,
activate a verifier, deploy production infrastructure or reissue an allocated credential.
