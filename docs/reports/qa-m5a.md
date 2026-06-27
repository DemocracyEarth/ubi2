# QA Report — M5 Stage A (P2P Network + Block Sync)

**Gate:** GATE 1 (QA)
**Branch:** feat/m5-p2p-network (commit ee52814 off main)
**Date:** 2026-06-27
**Engineer:** qa-engineer (claude-sonnet-4-6)
**Verdict:** PASS

---

## Scope

Stage A of M5: real P2P networking + block sync with ONE designated proposer and N followers.
Stage B (rotating proposer), Stage C (cross-node AI quorum) are explicitly out of scope.

What was shipped:
- `crates/network` (NEW): libp2p Noise/TCP/Yamux, gossipsub on `ubi2/tx/1` + `ubi2/block/1` with message-id = tx/block hash, request-response `ubi2/sync/1`, static bootstrap + mDNS, reconnect-until-connected sweep, `NetworkHandle` API.
- `crates/runtime`: `state_root` (FNV-1a-256 sponge over 10 canonical sections) + FU-13 canonicalization (dependency-free, build-enforced by `dependency_free.rs`).
- Extended block header (`txs_root`/`state_root`/`proposer`/`proposer_sig`) + persistence (FU-3, `ChainSnapshot` to `chain.json`).
- `crates/node` wiring: validate-before-rebroadcast tx gossip; proposer produces+broadcasts; followers validate parent+proposer+signature then RE-EXECUTE and match `state_root`, fail-closed; join-sync replays genesis→tip.
- RPC: `ubi_getPeers` / `ubi_consensusStatus` / `ubi_stateRoot`.

---

## Acceptance Criteria Mapping

| AC | Spec EC | Assertion | Test | Result |
|----|---------|-----------|------|--------|
| AC-1 | EC-1 | 3 nodes peer up; `ubi_getPeers` returns 2 peers each | `ec1_ec2_ec3_ec4_ec7_m5_stage_a` (x3 runs) | PASS |
| AC-2 | EC-2 | Tx submitted to A appears in B+C mempools within 2s | `ec1_ec2_ec3_ec4_ec7_m5_stage_a` (x3 runs) | PASS |
| AC-3 | EC-3 | `eth_blockNumber` agrees A/B/C within 1 block interval | `ec1_ec2_ec3_ec4_ec7_m5_stage_a` (x3 runs) | PASS |
| AC-4 | EC-4 | 20 blocks → byte-identical `ubi_stateRoot` across A/B/C | `ec1_ec2_ec3_ec4_ec7_m5_stage_a` + `follower_reaches_identical_state_root` + `state_root_equal_states_produce_identical_root` | PASS |
| AC-7 | EC-7 | 4th node with empty state syncs genesis→tip; same `state_root`; sees live blocks | `ec1_ec2_ec3_ec4_ec7_m5_stage_a` (x3 runs) | PASS |
| AC-10 | EC-10 | `state_root` byte-identical at every height across nodes | `state_root_equal_states_produce_identical_root` + multi-process assertions | PASS |
| AC-F2 | F2 | Block with wrong `state_root` rejected; no state change | `follower_rejects_tampered_state_root_no_apply` | PASS |
| AC-F3 | F3 | Block from wrong proposer rejected | `follower_rejects_wrong_proposer` | PASS |
| (parent check) | — | Block with wrong `parent_hash` rejected | `follower_rejects_wrong_parent` | PASS |
| FU-3 | — | `save→load` round-trip preserves `(height, hash, state_root)` | `persistence_round_trip_preserves_tip_and_state_root`, `persistence_restart_resumes_at_tip_not_genesis`, `persistence_empty_data_dir_returns_none` | PASS |
| RPC shapes | §11 | `ubi_getPeers` → array; `ubi_consensusStatus` → object w/ all fields; `ubi_stateRoot` → 0x-hex-64 | `rpc_ubi_*` (6 tests) | PASS |
| ADR-0004 | §12.7 | `crates/runtime` has no libp2p/tokio/reqwest deps | `runtime_declares_no_async_or_networking_deps` + `runtime_dependency_freedom_is_build_level_enforced` | PASS |
| State root determinism | EC-4 unit | Equal states → equal root; insertion-order-independent | `state_root_equal_states_produce_identical_root`, `state_root_insertion_order_independent` | PASS |
| State root sensitivity | EC-4 unit | Any field change → different root | `state_root_balance_change_changes_root`, `state_root_nonce_change_changes_root`, `state_root_new_account_changes_root`, `state_root_new_juror_changes_root`, `state_root_stream_change_changes_root` | PASS |

---

## Tests Run

### Multi-process integration test (3 runs required, all 3 must pass)

Command: `cargo test --test m5_stage_a -p ubi2-node -- --ignored --nocapture`

| Run | EC-1 | EC-2 | EC-3 | EC-4 state root | EC-7 | Time | Result |
|-----|------|------|------|-----------------|------|------|--------|
| 1 | PASS (2 peers each) | PASS (tx gossiped) | PASS (A=5, B=5, C=5) | `0x038e09...` identical A/B/C | PASS (height 21 live) | 21.97s | PASS |
| 2 | PASS (2 peers each) | PASS (tx gossiped) | PASS (A=5, B=5, C=5) | `0x63d83c...` identical A/B/C | PASS (height 21 live) | 22.05s | PASS |
| 3 | PASS (2 peers each) | PASS (tx gossiped) | PASS (A=5, B=5, C=5) | `0x472cdb...` identical A/B/C | PASS (height 23 live) | 23.86s | PASS |

Note: State roots differ across runs because `genesis_time` differs per run (default `now_secs()`). Within each run they are byte-identical across all 3 nodes, which is the correctness property being tested.

### Follower fail-closed tests

Command: `cargo test --test m5_follower_apply -p ubi2-rpc -- --nocapture`

```
test follower_reaches_identical_state_root ... ok
test follower_rejects_tampered_state_root_no_apply ... ok
test follower_rejects_wrong_proposer ... ok
test follower_rejects_wrong_parent ... ok
test result: ok. 4 passed; 0 failed
```

### New QA tests (m5a_qa.rs)

Command: `cargo test --test m5a_qa -p ubi2-rpc -- --nocapture`

```
test runtime_dependency_freedom_is_build_level_enforced ... ok
test persistence_empty_data_dir_returns_none ... ok
test state_root_equal_states_produce_identical_root ... ok
test state_root_insertion_order_independent ... ok
test state_root_balance_change_changes_root ... ok
test state_root_nonce_change_changes_root ... ok
test state_root_new_account_changes_root ... ok
test state_root_new_juror_changes_root ... ok
test state_root_stream_change_changes_root ... ok
test persistence_round_trip_preserves_tip_and_state_root ... ok
test persistence_restart_resumes_at_tip_not_genesis ... ok
test rpc_ubi_get_peers_returns_array ... ok
test rpc_ubi_get_peers_returns_wired_peers ... ok
test rpc_ubi_consensus_status_shape ... ok
test rpc_ubi_state_root_shape_and_value ... ok
test rpc_ubi_state_root_advances_after_block ... ok
test rpc_ubi_state_root_latest_tag_matches_no_param ... ok
test result: ok. 17 passed; 0 failed
```

### Security tests (pre-existing, confirmed still passing)

Command: `cargo test --test sec_m5a -p ubi2-rpc`

```
14 tests, 14 passed, 0 failed
```

### Full workspace baseline

Command: `cargo test --workspace -- --test-threads=1`

```
493 tests passed, 0 failed
(includes 440 pre-existing + 17 new m5a_qa + 14 sec_m5a + 4 m5_follower_apply + others)
```

Note: Running with default parallelism (`--test-threads=N`) shows intermittent port-collision failures in pre-existing fixed-port tests (`m2_acceptance.rs` ports 18555-18559). This is a pre-existing issue unrelated to Stage A. The new `m5a_qa.rs` tests use `free_port()` (OS-assigned port 0) to avoid this. Single-threaded run (`--test-threads=1`) shows 0 failures.

### pnpm build

Command: `pnpm -r build`

```
✓ Generating static pages (4/4)
Done
```

### cargo fmt + clippy

```
cargo fmt --check --all  → clean (0 diffs)
cargo clippy --workspace → 0 errors
```

---

## Coverage Gaps Identified

**Stage A criteria (in scope):** All covered — EC-1, EC-2, EC-3, EC-4, EC-7, AC-F2, AC-F3, FU-3 persistence, RPC shapes.

**Stage B criteria (out of scope):** AC-5 (EC-5, round-robin), AC-6 (EC-6, kill-proposer recovery) — these require B1-B6 implementation.

**Stage C criteria (out of scope):** AC-8 (EC-8, PoH cross-node quorum), AC-9 (EC-9, contract invocation quorum) — these require C1-C4 implementation.

**Failure modes NOT directly unit-tested in this gate** (would require Stage B):
- AC-F4 (equivocation by a proposer): detection logic exists in spec but Stage B implements the round-robin schedule that would expose it.
- AC-F5 (quorum split aborts deterministically): existing runtime tests cover quorum_tally; the cross-process path is Stage C.
- AC-F7 (wrong-network peer disconnect): the `Hello` handshake genesis-hash check exists in `crates/network`; covered by `handshake_binding_domain_separated_by_genesis` in `sec_m5a.rs`.

---

## Verdict

**PASS** for Stage A. All mapped Stage A acceptance criteria (EC-1, EC-2, EC-3, EC-4, EC-7, AC-F2, AC-F3, FU-3) have passing tests. The multi-process integration test is stable across 3 consecutive runs (21-24 seconds each). No regressions in the 440-test baseline.
