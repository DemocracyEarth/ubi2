# Reliability Report: M5 Stage A — P2P Networking + Block Sync

**Gate:** GATE 2 — Reliability
**Branch:** feat/m5-p2p-network (commit ee52814)
**Verdict:** PASS

---

## Scope

M5 Stage A introduced real P2P networking (libp2p: Noise/TCP/Yamux, gossipsub, request-response sync),
a deterministic state commitment (`state_root` — FNV-1a-256 sponge over 10 canonical sections),
extended block headers (`txs_root`/`state_root`/`proposer`/`proposer_sig`), chain persistence (FU-3),
a dependency-isolation build gate (FU-13), and RPC endpoints (`ubi_getPeers`,
`ubi_consensusStatus`, `ubi_stateRoot`). Stage B (rotating proposer) and Stage C (cross-node AI
quorum) are out of scope here.

Invariants under test: **I1** (deterministic consensus across processes), **I2** (reproducible integer
balances), **I4** (fail-closed), **I6** (least authority / no PII).

---

## Properties Checked

### (a) State Root is a Pure Function of State

**Checked:** No float, wall-clock, or HashMap-iteration nondeterminism exists on the consensus path.

**Method:**
- Code review of `crates/runtime/src/state_root.rs`: all 10 sections are iterated via `State` trait
  accessors that sort before returning (accounts by address, streams by id, humans by address, vouch
  edges by `(voucher, vouchee)`, cleared challenges by `(challenger, subject)`, cases by id, jurors
  by address, contracts by id, exec cases by id). Counters are read via `peek_next_*`.
- `PromptContract.vars` is a `HashMap` but is committed via `sorted_vars()` which sorts by key.
- `Case.votes` and `ExecCase.effects` are `Vec` iterated in insertion order — deterministic because
  all voters use the canonical block tx order (which every node re-executes identically).
- The `Hasher256` sponge uses only integer arithmetic (FNV-1a-256 with `to_be_bytes()`) — no floats.
- The `execute_block` path takes `timestamp` as a parameter (not `SystemTime::now()`) — wall-clock is
  used only for RPC read paths (`eth_getBalance`, balance views), never for state commitment.
- `crates/runtime` has a build-level dependency gate (`dependency_free.rs`) that fails the build if
  libp2p/tokio/reqwest appear in its `Cargo.toml`.

**Tests added:** `r_a1_state_root_pure_function_of_content`, `r_a2_state_root_order_independent`,
`r_a3_state_root_sensitivity` (uses `ubi2_runtime::state_root` and `MemState` directly to bypass the
genesis B256::ZERO placeholder).

**Result:** PASS. No nondeterminism found. The sort discipline covers every HashMap-backed collection.

---

### (b) Follower Re-Execute-and-Match at Every Height

**Checked:** An independent follower applying the proposer's committed tx order reaches a
byte-identical `state_root` at every height, for blocks with transfer txs, empty blocks, and multi-
node meshes.

**Method:**
- Reviewed `Chain::validate_and_apply_block` (rpc/src/lib.rs:1310): it decodes raw user txs, clones
  the inner state as a rollback snapshot, runs `execute_block` with the proposer's `(proposer, sig)`
  override, then compares `produced.state_root` == `claimed_state_root` AND `produced.hash` ==
  `claimed_hash`. On any mismatch it rolls back via `*inner.lock() = backup` (fail-closed, I4).
- The `execute_block` shared path runs the M3/M4 sweeps deterministically (address-sorted scan,
  `block_entropy` from parent hash + number, `select_jury` with sorted candidates).

**Tests added:** `r_b1_follower_matches_proposer_at_every_height_transfers` (10 blocks, 2 transfers
each, asserts state_root and balance agreement at every height), `r_b2_three_followers_match_mixed_tx_kinds`
(15 blocks, 3 independent followers), `r_b3_empty_blocks_match_at_every_height` (5 empty blocks).

**Result:** PASS. All three tests pass across multiple block heights and follower counts.

---

### (c) Sync Correctness: Late Joiner Genesis→Tip

**Checked:** A late joiner with empty state, re-executing genesis→tip in order, reaches the same
`state_root` and tip as the proposer. Tested at tip heights 5, 15, and 30.

**Method:**
- `run_late_joiner_sync(n)` helper builds a proposer to height n (each block has one transfer),
  stores `(block, raw_txs)` pairs, then creates a fresh follower chain with the same genesis and
  replays all blocks via `validate_and_apply_block`. Asserts `joiner.tip() == proposer.tip()` and
  `joiner.state_root() == proposer.state_root()`.
- `r_c4_double_apply_is_rejected_not_applied` verifies idempotency: applying the same block twice
  returns `NonContiguous` and does not change state.

**Tests added:** `r_c1_late_joiner_syncs_at_height_5`, `r_c2_late_joiner_syncs_at_height_15`,
`r_c3_late_joiner_syncs_at_height_30`, `r_c4_double_apply_is_rejected_not_applied`.

**Result:** PASS. Late joiners converge to byte-identical state at all tested heights.

---

### (d) Fail-Closed Under Adversarial Inputs

**Checked:** Tampered state_root, wrong proposer, wrong parent hash, non-contiguous height — every
check rejects the block and leaves the follower's state unchanged.

**Tests added:** `r_d1_tampered_state_root_fail_closed`, `r_d2_wrong_proposer_fail_closed`,
`r_d3_wrong_parent_fail_closed`, `r_d4_non_contiguous_height_fail_closed`.

**Result:** PASS. All adversarial inputs produce the expected `BlockError` variant and no state
mutation occurs (state_root and tip are identical before and after rejection).

---

### (e) Persistence Determinism (FU-3) and Snapshot Round-Trips

**Checked:** `export_snapshot()` → `from_snapshot()` is lossless (same `state_root` and tip), two
snapshots of the same chain produce identical JSON, a restored chain can continue applying blocks
and matching, and the property holds over a range of tip heights.

**Method:**
- `export_state` in `persist.rs` sorts all collections before serialization (accounts by address,
  streams by id, humans via `State::humans()` which sorts, cases via `State::cases()`, etc.).
- Atomic write: snapshot is written to `.chain.json.tmp` and `rename`d to `chain.json`, so a crash
  mid-write cannot corrupt the live file.

**Tests added:** `r_e1_snapshot_roundtrip_preserves_state_root`, `r_e2_snapshot_export_is_deterministic`
(two JSON exports are byte-identical), `r_e3_snapshot_restored_chain_continues_consensus`,
`r_e4_property_joiner_always_converges` (property test over tip heights 1, 3, 7, 10, 20).

**Result:** PASS.

---

### (f) Disk Persistence (FU-3 File I/O)

**Checked:** `save()`/`load()` from a real tempdir round-trips deterministically; atomic overwrite
preserves the latest snapshot.

**Tests added:** `r_f1_disk_snapshot_roundtrip`, `r_f2_atomic_overwrite_is_safe`.

**Result:** PASS.

---

## Architecture Findings

### No Consistency Violations Found

After reviewing the full diff (`git diff main...HEAD`) and all consensus-critical code paths:

1. **state_root is pure**: all `HashMap` collections have sorted accessors on every read path that
   feeds the hash. No float arithmetic, no wall-clock, no model calls.
2. **Tx order is canonical**: the proposer commits tx order via `txs_root`; followers re-execute
   the SAME order. The `votes`/`effects` `Vec` ordering (insertion order) is therefore identical
   across all honest nodes.
3. **Block hash commits both roots**: `hash = keccak256(number ‖ parent ‖ timestamp ‖ txs_root ‖
   state_root ‖ proposer)` so a tampered root necessarily changes the block hash and fails the
   signature check.
4. **Rollback is total**: `validate_and_apply_block` uses `self.inner.lock().unwrap().clone()` as a
   backup before trial execution, and restores it verbatim on any mismatch.

### Observability Signals Present

- `ubi_stateRoot` RPC: returns the tip block's committed `state_root` — usable for cross-node
  comparison at any height.
- `ubi_getPeers`: shows each peer's `tip` field (last-reported height and hash).
- `ubi_consensusStatus`: shows the node's head, author, and role.
- `warn!` on `StateRootMismatch` includes both the expected and re-executed roots.
- `warn!` on peer greylist, wrong-network disconnect, sync block rejection — all include peer ID.

---

## Issues Found

### Low — Genesis State Root is B256::ZERO (Design Decision, Minor Observability Gap)

**Severity:** Low (informational)

The genesis block's `state_root` header field is `B256::ZERO` by design (the block is constructed
before `seed_account`/`seed_verified_human` populate the state). This means `ubi_stateRoot` at height 0
always returns `"0x0000...0000"`, even though the in-memory state contains the dev account and
devnet jurors.

**Impact:** A cross-node comparison of `ubi_stateRoot` is only meaningful from height 1 onward. The
test `rpc_ubi_state_root_shape_and_value` in `m5a_qa.rs` was intermittently failing in parallel test
runs (port conflicts) but also would return zero before block 1 is mined. This is not a consensus
correctness issue (nodes always agree on zero at height 0), but it makes "is my genesis seeding
correct?" harder to diagnose via RPC.

**Reproduction:** `ubi_stateRoot` at height 0 on any node returns `"0x0000...0000"`.

**Recommendation:** Add a doc note to `ubi_stateRoot` clarifying it returns zero at height 0. No
code change needed for consensus correctness.

### Low — RPC Integration Tests Share Hard-Coded Ports (Pre-Existing)

**Severity:** Low (pre-existing)

Multiple integration tests in `crates/rpc/tests/` bind fixed TCP ports (e.g. 18580–18585 in
`m5a_qa.rs`) without isolation. When `cargo test --workspace` runs them in parallel, the tests
racing for the same port cause `Address already in use` failures in `rpc_ubi_get_peers_returns_array`,
`rpc_ubi_state_root_shape_and_value`, and `rpc_ubi_state_root_advances_after_block`. All tests
pass when run with `--test-threads=1` or individually.

**Reproduction:** `cargo test --workspace` (without `--test-threads=1`) may produce these failures.

**Recommendation:** Use `TcpListener::bind("127.0.0.1:0")` (OS-assigned ephemeral ports) in RPC
server test helpers, as the network tests already do.

---

## Tests Added

All added to `crates/rpc/tests/m5a_reliability.rs`:

| Test | Property | Result |
|------|----------|--------|
| `r_a1_state_root_pure_function_of_content` | (a) equal states → equal root | PASS |
| `r_a2_state_root_order_independent` | (a) insertion order independence | PASS |
| `r_a3_state_root_sensitivity` | (a) any field change changes root | PASS |
| `r_b1_follower_matches_proposer_at_every_height_transfers` | (b) I1 at every height, 10 blocks | PASS |
| `r_b2_three_followers_match_mixed_tx_kinds` | (b) 3 followers, 15 blocks | PASS |
| `r_b3_empty_blocks_match_at_every_height` | (b) empty blocks still match | PASS |
| `r_c1_late_joiner_syncs_at_height_5` | (c) sync at tip=5 | PASS |
| `r_c2_late_joiner_syncs_at_height_15` | (c) sync at tip=15 | PASS |
| `r_c3_late_joiner_syncs_at_height_30` | (c) sync at tip=30 | PASS |
| `r_c4_double_apply_is_rejected_not_applied` | (c) idempotency | PASS |
| `r_d1_tampered_state_root_fail_closed` | (d) I4 on bad state_root | PASS |
| `r_d2_wrong_proposer_fail_closed` | (d) I4 on wrong proposer | PASS |
| `r_d3_wrong_parent_fail_closed` | (d) I4 on wrong parent | PASS |
| `r_d4_non_contiguous_height_fail_closed` | (d) I4 on height gap | PASS |
| `r_e1_snapshot_roundtrip_preserves_state_root` | (e) FU-3 lossless | PASS |
| `r_e2_snapshot_export_is_deterministic` | (e) export is deterministic | PASS |
| `r_e3_snapshot_restored_chain_continues_consensus` | (e) restore → new block | PASS |
| `r_e4_property_joiner_always_converges` | (e) property test, 5 tip heights | PASS |
| `r_f1_disk_snapshot_roundtrip` | (f) save/load from disk | PASS |
| `r_f2_atomic_overwrite_is_safe` | (f) atomic overwrite | PASS |

**Total: 20 new tests, all PASS.**

Pre-existing tests: 440 (workspace, `--test-threads=1`) — all PASS. Parallel run has pre-existing
port-conflict flakiness in 3 RPC-server tests (not caused by M5 Stage A changes).

---

## Verdict: PASS

I1 across processes and determinism are demonstrated. No consistency violation was found. Sync
correctness is verified at tip heights 5, 15, and 30. Fail-closed behavior holds for all adversarial
block inputs. Persistence is deterministic and the disk round-trip is lossless. Two Low-severity
non-blocker issues were identified (genesis zero root observability gap; pre-existing port conflict
in RPC tests).
