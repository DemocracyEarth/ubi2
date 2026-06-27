# Security RE-GATE — M5 Stage A (P2P networking + block sync)

- **Branch:** `feat/m5-p2p-network`
- **Scope:** adversarial re-verification that the three Stage-A networking-DoS findings (SEC-M5A-1/2/3)
  are CLOSED, with **LIVE proofs-of-concept on non-default ports** against the real transport + RPC, plus
  the full release gate.
- **Verdict:** **PASS** — all three findings CLOSED; no new High/Critical; suite green; multi-process
  test passes its required 3 consecutive runs (see the reliability note on a one-time mesh-formation
  flake). No `ubi2-node` left running.

The defenses are implemented in `crates/network/src/wire.rs`, `crates/network/src/lib.rs`,
`crates/network/src/ratelimit.rs`, `crates/network/src/consts.rs`, `crates/node/src/net.rs`, and
`crates/rpc/src/lib.rs` (mempool caps). This re-gate adds LIVE adversarial PoCs:

- `crates/network/tests/sec_m5a_regate.rs` — two REAL libp2p swarms on OS-assigned (`/ip4/127.0.0.1/tcp/0`)
  non-default ports, mDNS OFF, one acting as attacker. Covers SEC-M5A-1 and SEC-M5A-2 on the live wire.
- `crates/rpc/tests/sec_m5a_regate_mempool.rs` — a spawned real `ubi2-node` process on **non-default**
  RPC `127.0.0.1:18601` / P2P `tcp/19601`, flooded over JSON-RPC. Covers SEC-M5A-3 end-to-end.

(The pre-existing unit/wire PoCs in `crates/rpc/tests/sec_m5a.rs` — 18 tests — remain green and are kept
as regression anchors.)

---

## SEC-M5A-1 (HIGH) — forged high block-number sync loop — CLOSED

**Threat:** a hostile peer announces a forged, UNSIGNED (or wrong-proposer) block claiming
`number = u64::MAX`. The pre-fix `shallow_verify` skipped the signature check on an empty signature, so
the forgery passed, pinned the peer's tip to `u64::MAX`, and drove an unbounded re-request loop with no
peer penalty.

**Live PoC (`sec_m5a_regate.rs`):**

- `forged_high_number_block_never_surfaces_to_victim` — attacker B (a real swarm peer) gossips a forged
  UNSIGNED `u64::MAX` block and a `u64::MAX` block whose `proposer` ≠ its signer, then a GENUINE block
  signed by the designated proposer. The victim A's network-layer `shallow_verify` gate (now fail-closed
  on an absent/mismatched signature) drops both forgeries before they are ever surfaced as a
  `BlockReceived`, so neither can pin a bogus tip or arm a range request. The ONLY block A surfaces is the
  genuine signed one (`id` and `number` asserted) — proving the gate is **selective**, not a blanket stall.
- `forged_block_flood_greylists_attacker_within_bound` — a sustained flood of distinct forged blocks
  greylists the attacker (`NetEvent::PeerGreylisted` fires) within a bounded number of messages — the
  bounded-termination property at the transport layer (a junk peer is cut off, not chased forever).

**Defense-in-depth (already present, covered by existing tests):**
- `crates/node/src/net.rs::on_block` gap path requires `announced_tip_is_trustworthy()` (valid sig AND
  `proposer == designated_proposer`) before pinning an ahead-tip; otherwise the peer is penalized.
- `maybe_sync()` refuses any tip beyond `head + SYNC_MAX_LOOKAHEAD` (8192) — a forged `u64::MAX` never
  arms a request (`maybe_sync_ignores_implausibly_far_tip`).
- `on_sync_response()` only re-requests on forward progress; after `SYNC_MAX_NO_PROGRESS_ROUNDS` (3) of
  no progress it penalizes + clears the peer's tip (`empty_responses_bound_the_loop_and_clear_the_tip`).
- A forged block also cannot corrupt state: `validate_and_apply_block` re-executes and rolls back on any
  state-root/txs-root/parent/author mismatch (fail-closed, I4) — `sec_m5a.rs::forge_*` regressions.

**Honest path intact:** the live test confirms a genuinely-signed proposer block still delivers; the
multi-process `m5_stage_a` EC-7 confirms a real lagging 4th node syncs genesis→tip to the same state root.

**Status: CLOSED.**

---

## SEC-M5A-2 (Medium) — inbound sync/Hello flood unbounded — CLOSED

**Threat:** the request-response (`ubi2/sync/1`) path was un-rate-limited; a peer could flood expensive
`GetBlocks`/`Hello` requests and open many concurrent range streams, starving the victim.

**Live PoC (`sec_m5a_regate.rs::sync_flood_is_throttled_and_victim_stays_responsive`):** three real swarms
— A (victim), B (attacker), C (well-behaved). B floods 400 `GetBlocks` at A. While the flood is in
flight, C gossips a genuine signed block; the victim A **stays responsive** and surfaces C's block (its
event loop is not starved — the sync path is rate-limited on B's OWN per-peer budget, independent of the
gossip budget). The wire-level `SYNC_MAX_BATCH` (128) bounds every response A would serve.

**Defenses (verified in code + `ratelimit.rs` unit tests):**
- Independent per-peer `sync` token bucket (`allow_sync`) throttles the inbound request-response path.
- `SYNC_MAX_INFLIGHT_PER_PEER` (4) caps concurrent in-flight `GetBlocks`; over-cap → channel dropped
  (requester sees `InboundFailure`) + peer penalized → greylist.
- `Blocks::decode` rejects any claimed count > `SYNC_MAX_BATCH` at decode (no unbounded pre-allocation).

**Status: CLOSED.**

---

## SEC-M5A-3 (Medium) — RPC mempool unbounded — CLOSED

**Threat:** `ingest_raw_tx` admitted individually-valid txs without bound; a flood could grow the mempool
without limit (memory DoS) on both the RPC submit and gossip-ingest path.

**Live PoC (`sec_m5a_regate_mempool.rs::live_mempool_rejects_over_per_sender_cap`):** a real `ubi2-node`
is spawned as a **networked FOLLOWER** (P2P on non-default `tcp/19601`, NO proposer key ⇒ it never mines,
so the mempool is not drained by block production) on non-default RPC `127.0.0.1:18601`. The dev sender
(funded via a back-dated genesis, ~1000 UBI) submits txs over JSON-RPC:

- The first `MEMPOOL_MAX_PER_SENDER` (64) txs admit (each returns a tx hash).
- The 65th is **rejected** with the JSON-RPC error
  `mempool full for sender: at per-sender cap of 64 txs` (code `-32602`), no tx hash returned.

Observed live output:
```
[sec-m5a-3] admitted 64 txs up to the per-sender cap
[sec-m5a-3] over-cap response = {"error":{"code":-32602,
  "message":"mempool full for sender: at per-sender cap of 64 txs"},"id":1,"jsonrpc":"2.0"}
```

`ingest_raw_tx` enforces both `MEMPOOL_MAX_TXS` (global) and `MEMPOOL_MAX_PER_SENDER` BEFORE admission
(`crates/rpc/src/lib.rs`); the global cap is additionally proven by `sec_m5a.rs::mempool_enforces_global_cap`.

**Status: CLOSED.**

---

## Full release gate (truthful results)

| Gate | Command | Result |
|---|---|---|
| Workspace tests | `cargo test --workspace` | **504 passed, 0 failed, 4 ignored** (47 suites; +3 live network PoCs over the prior 501) |
| Format | `cargo fmt --all --check` | clean |
| Lint | `cargo clippy --workspace --all-targets -- -D warnings` | clean (exit 0) |
| Frontend | `pnpm -r build` | exit 0 (wallet emits only pre-existing ESLint warnings; "Done") |
| Live SEC-M5A-1/2 | `cargo test -p ubi2-network --test sec_m5a_regate` | 3 passed |
| Live SEC-M5A-3 | `cargo test -p ubi2-rpc --test sec_m5a_regate_mempool -- --ignored` | 1 passed |
| Multi-process | `cargo test --test m5_stage_a -p ubi2-node -- --ignored` ×3 | **3/3 PASS** (~22–28s each) |

The 4 `--ignored` tests are the multi-process `m5_stage_a` harness, the live mempool PoC, and the two
ignored doc-tests; they run on demand, not in the fast suite.

### Reliability note (NOT a security finding)

The multi-process `m5_stage_a` test failed ONCE on its very first attempt with
`EC-1 FAIL: node 2 has 1 peers (expected 2) after 30s` — a gossip-mesh-formation timeout that occurred
while the machine was still under heavy load from the just-completed clippy/build/pnpm steps. Ports were
confirmed free and stray temp dirs cleaned; the immediate retry and the next three runs (the required 3
consecutive + 1 extra stability run) ALL PASSED. This is a transport timing flake in mesh convergence
under load, not a consensus or security defect (the three findings remain CLOSED). Recommend the
reliability/QA owner tighten the EC-1 convergence window or raise the 30s mesh-formation budget to remove
the flake from CI; it does not gate this security re-gate.

---

## Rules of engagement / hygiene

- Acted only against this project's own devnet, for defense. NON-DEFAULT ports throughout
  (`tcp/0` OS-assigned for the in-process swarms; `18601`/`19601` for the spawned node; the multi-process
  harness uses `1856x`/`1956x`). `ubi2-node` killed (`pkill -9`) before and after every live run; final
  `pgrep` confirms none lingering.
- No commits made.
- Determinism untouched: `crates/runtime` not modified; all changes are transport/node/mempool-side and
  fail-closed (I4). New tests only.

**Open High/Critical: none. GATE VERDICT: PASS.**
