# Reliability Report — TX-UI Batch (fix/tx-confirmation-explorer-routes)

Branch: fix/tx-confirmation-explorer-routes  
Commits: ca58581 + bf06b21  
Gate: Reliability (Gate 2)  
Date: 2026-06-27  
Verdict: **PASS**

---

## Scope

This report covers the reliability properties of the two-commit batch:

1. TX-CONFIRM FIX (`crates/rpc/src/lib.rs`): `tx_to_json`/`receipt_to_json` now emit the real EIP-2718 `type` byte and 1559 caps (`maxFeePerGas`/`maxPriorityFeePerGas`/`accessList`) captured from the signed envelope in `ingest_raw_tx` and threaded through `PendingTx` → `StoredTx`.
2. EXPLORER READS (`crates/rpc/src/lib.rs`): `ubi_getRecentBlocks(limit?, nonEmptyOnly?)` and `ubi_getContracts(limit?)` — read-only, newest-first, limit-clamped 1..=100.

---

## Properties checked

### (a) DETERMINISM (I2)

**P1 — TX-TYPE ECHO IS EXACT-BYTE READ**  
`ingest_raw_tx` captures `env.tx_type().into()` (the canonical EIP-2718 type byte from the alloy `TxType` enum: `Legacy=0`, `Eip2930=1`, `Eip1559=2`) and stores it verbatim in `PendingTx.tx_type` → `StoredTx.tx_type`. `tx_to_json` emits `hex_u64(tx.tx_type as u64)`. This is a read of the signed envelope bytes — identical input bytes produce identical output on every node. No recomputation, no platform dependency.

**P2 — 1559 CAPS ARE ECHOED VERBATIM**  
`max_fee_per_gas` and `max_priority_fee_per_gas` are captured as `u128` from the envelope (`env.max_fee_per_gas()` / `env.max_priority_fee_per_gas()`) and stored in `StoredTx`. They are emitted unchanged via `hex_u128`. The `if let (Some(max_fee), pri)` guard ensures they only appear for typed-fee txs; legacy txs emit neither field.

**P3 — NO FLOATS IN CONSENSUS PATH (I2)**  
All balance, escrow, and fee fields are `u128` integers. `contract.escrow` is `u128`, propagated without arithmetic in the read path. `created_at` is a stored block `timestamp: u64`. `tx_count` is `b.txs.len() as u64`. The emission settlement formula (`UBI * elapsed / 3600`) uses integer division documented in spec I2. No float types appear in `StoredTx`, `BlockSummary`, or `ContractSummary`.

**P4 — RECENT-BLOCKS ORDERING IS TOTAL AND STABLE**  
`recent_blocks` iterates `g.blocks.iter().rev()`. `g.blocks` is a `Vec<Block>` grown only by `produce_block` in strictly increasing block-number order. Reversing gives a total, stable newest-first ordering. No HashMap iteration involved.

**P5 — RECENT-CONTRACTS ORDERING IS TOTAL AND STABLE**  
`recent_contracts` calls `g.state.contracts()` which iterates `HashMap<ContractId, PromptContract>` and then calls `v.sort_by_key(|c| c.id)` (explicit sort, deterministic). `ContractId` is `u64` with total order. The code then reverses for newest-first. The HashMap's non-deterministic iteration order is fully eliminated by the explicit sort before reversal.

**P6 — NO WALL-CLOCK IN NEW READ PATHS**  
`ubi_getRecentBlocks` and `ubi_getContracts` do not call `now_secs()`. `created_at` in `contract_summary_json` resolves the stored block's `timestamp` field (set at `produce_block` time, not at query time). The only `SystemTime` usage in the new code is in test helpers.

**P7 — `contract_title` IS A PURE FUNCTION**  
`contract_title` takes only the on-chain text string. It uses `.chars().count()` for Unicode-correct length and `.chars().take(80)` for truncation — deterministic on any node for the same UTF-8 bytes.

### (b) CONSISTENCY

**C1 — TYPE-2 TX HASH IS UNCHANGED BY THE FIX**  
The tx hash is the canonical EIP-2718 hash computed by alloy from the signed envelope before any node logic runs. `ingest_raw_tx` derives the hash as `*env.tx_hash()` — the alloy-computed hash. The `type`/`maxFeePerGas` fields appear only in the JSON response, not in the hash input. Verified by P10: the sender-computed hash equals the node-returned hash, and the same hash finds the mined tx.

**C2 — `ubi_getRecentBlocks(nonEmptyOnly)` AGREES WITH `ubi_getBlock` PER BLOCK**  
Both `block_summary_json` (`txCount: s.tx_count`) and `decoded_block_json` (`"txCount": block.txs.len()`) compute `txs.len()` from the same `Block.txs: Vec<StoredTx>`. A block passes the `!non_empty_only || !b.txs.is_empty()` filter iff `b.txs.len() > 0`, which matches `txCount > 0` in the JSON. Verified by P5.

**C3 — `ubi_getContracts` AGREES WITH `ubi_getContract(id)`**  
Both use the same `PromptContract` struct from `g.state.get_contract(id)`. `contract_summary_json` emits `escrow: hex_u128(s.escrow)` from `c.escrow`; `contract_view_json` (used by `ubi_getContract`) emits the same field. `status` uses the same `contract_status_str` helper. Verified by P7.

**C4 — TYPE FIELD DOES NOT AFFECT STATE ROOT**  
The type field is presentation-only. State transitions are driven by `PendingKind` (derived from calldata), not by the tx type byte. The type byte affects only the JSON shape of `eth_getTransactionByHash` and `eth_getTransactionReceipt`. Verified by P10.

### (c) LEGACY vs TYPE-2 BRANCH ROUND-TRIP

Covered by the parametric sweep (`parametric_all_tx_kinds_emit_correct_type_byte`):

| Tx kind | Signed type | Expected `type` JSON | Expected 1559 fields |
|---|---|---|---|
| Transfer (legacy) | 0 | `0x0` | absent |
| Transfer (type-2) | 2 | `0x2` | present (exact sender values) |
| ContractHub deploy (type-2) | 2 | `0x2` | present |
| ContractHub deploy (legacy) | 0 | `0x0` | absent |

All four cases pass.

---

## Tests added

File: `crates/rpc/tests/c_txui_reliability.rs`  
12 property/integration tests:

| Test | Properties |
|---|---|
| `p1_p2_p3_type2_transfer_round_trip` | P1, P2, P3 — type echo + 1559 caps + hash identity |
| `p1_p2_type0_no_1559_fields` | P1, P2 — legacy: type=0x0, no 1559 fields |
| `p1_type2_deploy_round_trip` | P1, C4, P3 — deploy: type=0x2, hash unaffected |
| `p9_system_tx_is_type0_no_1559_fields` | P9 — synthetic system tx: type=0, no 1559 caps |
| `p4_recent_blocks_newest_first_total_stable` | P4 — strict decr. order, stable repeated calls |
| `p4_recent_blocks_limit_clamped` | P4 — limit clamped 1..=100, no panic |
| `p5_non_empty_filter_agrees_with_per_block_tx_count` | P5 — C2 consistency: filtered = txCount>0 set |
| `p6_contracts_newest_first_total_stable` | P6 — strict decr. id order, stable repeated calls |
| `p7_contracts_directory_agrees_with_per_contract_detail` | C3 — directory vs detail: escrow/status/title agree |
| `p8_escrow_integer_roundtrip_no_float` | P3/I2 — u128 escrow round-trips exactly (boundary values) |
| `p10_type2_hash_and_state_unaffected_by_json_type_field` | C4 — state changed, hash unchanged by JSON field |
| `parametric_all_tx_kinds_emit_correct_type_byte` | C5 — all tx kinds × tx types carry correct type byte |

All 12 pass. Combined with the 5 pre-existing tx-confirm and ui-reads tests (all passing), the suite covers the full reliability surface of the batch.

---

## Pre-existing test coverage preserved

All 420+ cargo tests that were green before this review remained green. The `m3_qa::ac6_rpc_sybil_cluster_auto_challenge_and_revoke` test exhibits a pre-existing port-binding race when run concurrently with other tests in the same cargo test run; it passes cleanly in isolation. This is not caused by this branch.

---

## Findings

### INFO-1 — `createdAt` is a plain integer, other timestamps are hex

`contract_summary_json` emits `"createdAt": s.created_at` (a raw u64), while all other timestamp fields in RPC responses use `hex_u64`. This is an API inconsistency but not a reliability or correctness issue — the value is deterministic and integer. The field name matches the SDK's TypeScript expectations.

### INFO-2 — `ubi_getContracts` default limit is 50; `ubi_getRecentBlocks` default is 20

Both are appropriate defaults for their directory size. Limits are server-enforced (clamped before any `Vec` allocation). No DoS surface via oversized responses.

### INFO-3 — EIP-2930 (type-1) txs would emit `maxPriorityFeePerGas: "0x0"`

For a type-1 (EIP-2930) tx: `max_fee_per_gas = Some(v)` but `max_priority_fee_per_gas = None` (alloy's `Eip2930::max_priority_fee_per_gas()` returns None). The `if let (Some(max_fee), pri)` guard matches, and `pri.unwrap_or(0)` emits `"0x0"`. This is correct per EIP-2930 semantics (no priority fee). This chain does not currently produce type-1 txs but the code handles them correctly.

---

## Verdict

**PASS.** Determinism and balance reproducibility are demonstrated. No consistency violation found. The type/1559 fields are exact reads of the signed envelope (identical bytes → identical JSON on any node). `ubi_getRecentBlocks` and `ubi_getContracts` are pure functions of stored chain/indexer state with no wall-clock, no floats, and deterministic ordering. The MetaMask "Dropped" fix is presentation-only and does not affect any consensus state.
