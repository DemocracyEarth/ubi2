# Security gate — M5 Stage A (P2P networking + block sync)

Branch `feat/m5-p2p-network`, diff vs `main`. **Original verdict: FAIL** (one HIGH) → all blockers
fixed in-cycle → **re-gate PASS** (see [`security-m5a-regate.md`](security-m5a-regate.md)).
PoCs: `crates/rpc/tests/sec_m5a.rs`, `crates/network/tests/sec_m5a_regate.rs`,
`crates/rpc/tests/sec_m5a_regate_mempool.rs`. *(Findings table reconstructed by the orchestrator from
the gate's structured result — the gate's own file write did not land; the re-gate report did.)*

## Verified intact (no finding)
- **No block forgery.** A follower validates parent + proposer + signature and **re-executes**, asserting
  its recomputed `state_root` matches; any mismatch (tampered root / wrong proposer / wrong parent /
  skipped number / tampered txs) is rejected with **zero state mutation** (fail-closed, I4). State integrity
  was never at risk.
- **Wrong-network rejection** at handshake (different genesis → disconnect). **Sync responses bounded** by
  `SYNC_MAX_BATCH`. **Determinism (I1/I2)** untouched (runtime not modified).

## Findings
| # | Severity | Title | Disposition |
|---|---|---|---|
| SEC-M5A-1 | **High** | **Forged-high-number → unbounded follower sync loop.** `shallow_verify` skipped the signature check when `proposer_sig` was empty, so a forged *unsigned* block claiming `number=u64::MAX` passed; the follower pinned that bogus tip and the empty/timeout sync response reset in-flight and re-requested forever, never greylisting the peer. **Liveness DoS** (state safe via fail-closed re-exec). | **FIXED** — `shallow_verify` fails closed on absent/mismatched sig; `on_block` only trusts a tip from the designated proposer with a valid sig; `maybe_sync` refuses tips beyond `SYNC_MAX_LOOKAHEAD` (8192); `on_sync_response` only re-issues on forward progress and after `SYNC_MAX_NO_PROGRESS_ROUNDS` (3) **penalizes + clears the peer**. Re-gate: forged block dropped before surfacing; attacker greylisted within a bound. |
| SEC-M5A-2 | Medium | **Inbound sync/Hello not rate-limited** — the per-peer token bucket applied only to gossip, not the request-response path; a `GetBlocks` flood contended the chain lock + amplified M5A-1. | **FIXED** — an independent per-peer sync token bucket + a per-peer concurrent in-flight `GetBlocks` cap (`SYNC_MAX_INFLIGHT_PER_PEER`=4); over-limit dropped + penalized. Re-gate: 400-request flood throttled, victim stayed responsive. |
| SEC-M5A-3 | Medium | **RPC mempool unbounded** — `MEMPOOL_MAX_TXS`/`MEMPOOL_MAX_PER_SENDER` were declared but unenforced (the deferred FU-1 hardening, now load-bearing under multi-node). | **FIXED** — `ingest_raw_tx` enforces both caps at admission with clear JSON-RPC errors. Re-gate: live node rejects the 65th per-sender tx (`-32602`); global cap proven. |
| SEC-M5A-4 | Low | **Persistence `chain.json` adopted verbatim** on load (no `state_root` re-derivation / genesis cross-check). Defensible Stage-A trusted-disk stance. | **→ FU-20** (harden in Stage D: recompute `state_root` on load + verify block-hash/parent linkage + genesis anchor). |
| SEC-M5A-5 | Info | **Eclipse / peer-table monopolization** (no inbound cap / eviction / diversity) — out of scope for Stage-A static bootstrap. | **→ FU-21** (track for Stage D when discovery lands). |
