# Reliability Report — Cycle 6

**Gate:** GATE 2 — Reliability  
**Branch:** feat/cycle6-contracts-vouch-docs  
**Commit:** d6cbbe5  
**Date:** 2026-06-23  
**Verdict:** PASS

---

## Scope

Cycle 6 made two changes that touch the consensus path:

1. **FAILED-TX RECEIPTS** — a queued op that fails at block time is now mined as a status-0x0 tx (fee charged to treasury, nonce consumed deterministically as `p.nonce+1`, decoded revert reason carried, no op state change) instead of being silently dropped.

2. **CONTRACT TEXT ON-CHAIN** — `deployContract(string text, address[])` stores the full NL text plus `text_ref=keccak256(utf8(text))` plus `deploy_block`/`deploy_tx` in `PromptContract`; the interpreter reads `contract.text`; `ubi_getContract` returns full detail including cases.

The gate asks four questions:
- **(a) DETERMINISM** — mined-failed txs are reproducible across two nodes.
- **(b) CONSERVATION** — fee moves sender→treasury on a failed op; no value created/lost.
- **(c) NONCE INTEGRITY** — no path produces a nonce gap or double-bump.
- **(d) CONTRACT TEXT DETERMINISM** — `text_ref` and stored text introduce no nondeterminism.

---

## Method

1. Read all relevant source: `crates/runtime/src/lib.rs` (`charge_fee`, `apply_transfer`, `MemState`), `crates/runtime/src/contracts.rs` (`deploy_contract`, `invoke_contract`, `fund_contract`, `resolve_case`), `crates/rpc/src/lib.rs` (`produce_block`, `ingest_raw_tx`, `consume_nonce`, `spendable_debit`), `crates/rpc/src/contracts.rs` (`text_commitment`, `decode_effect`).

2. Traced every failure path in `produce_block` for each `PendingKind` to verify where the nonce sits at error time and that the SET-to-`p.nonce+1` idiom is correct for each.

3. Wrote 16 property tests in `crates/runtime/tests/c6_reliability.rs` (name `c6_reliability`) that exercise the four gate properties over random timelines (1,000–5,000 iterations per property, plus a 500-block soak).

4. Ran the existing `c6_failed_tx` integration tests (3 tests) and the full cargo test suite (30 test binaries, 0 failures).

---

## Properties Checked

### (a) Determinism

**C6-D3** (5,000 iter): Two independent states applying the same mixed succeed/fail sequence reach the same nonce post-state. Covers three failure modes: `SucceedTransfer`, `FailTransfer` (absurd value), `FailHubOp` (hub consume_nonce path).

**C6-D8** (2,000 iter): Two independent states apply the same `deploy`+`fail-invoke` sequence; their nonce and treasury agree byte-for-byte.

**C6-D9** (1,000 iter): `ExecCase.resolved_at` is stamped to the same block height on two independent nodes (the `MockInterpreter` quorums immediately; both nodes see `Some(block_height)`).

**C6-D1** (5,000 iter): `charge_fee` charges exactly `gas * GAS_PRICE_WEI` from the sender and credits exactly the same to the treasury — to the base unit — for all four fee-bearing gas tiers. No float, no rounding.

**C6-block-hash**: The block hash formula `keccak256(number || parent_hash || timestamp)` is a pure function: same inputs yield same output; any field change changes the output. Structural determinism of the RPC's `Block::compute_hash`.

**Result: No divergence found. Both simulated nodes always agree.**

### (b) Conservation

**C6-D2a** (5,000 iter): A failed op charges the fee but moves no value. Treasury increases by exactly `fee`; recipient remains at 0; total settled = initial + emission_folded (no value created or destroyed).

**C6-D2b** (2,000 iter): Over a random sequence of mixed succeed/fail transfers, total settled never exceeds `initial + emission`. No value is ever created.

**C6-D10** (500-block soak): Over 500 simulated blocks of random succeed/fail txs, treasury balance is monotonically non-decreasing, nonce is monotonically non-decreasing, and the global conservation identity `total_settled <= initial + total_emission_folded` holds at every block. The soak completes without violating any bound.

**Result: Conservation holds. Fee always moves sender→treasury; no value created or destroyed.**

### (c) Nonce Integrity

The critical correctness argument for Cycle 6's nonce handling:

- **Hub ops** (`Vouch`, `Challenge`, `SubmitVerdict`, `RequestVerification`, `DeployContract`, `InvokeContract`, `SubmitEffect`): all run as `consume_nonce(p.nonce).and_then(op)`. If `op` fails, `consume_nonce` has **already bumped** the nonce from `p.nonce` to `p.nonce+1`. The failure handler's SET-to-`p.nonce+1` is **idempotent** — the nonce is already at the target value.

- **Transfer / FundContract** (`apply_transfer`, `fund_contract`): both use validate-before-mutate. On `Err`, the nonce has **not been bumped**. The failure handler's SET-to-`p.nonce+1` is the **only nonce bump** — exactly correct.

- No path produces `p.nonce+2` (double-bump) or stays at `p.nonce` (gap).

**C6-D4** (1,000 iter): After a failed transfer at nonce `N`, the chain nonce is `N+1`, and a follow-up transfer at nonce `N+1` succeeds. No cascade.

**C6-D5** (2,000 iter): A failing hub op (`consume_nonce` then op fails) lands at `p.nonce+1`, not `p.nonce+2`. The SET-to-`p.nonce+1` in the failure handler is confirmed idempotent.

**`c6_fund_contract_failure_nonce_not_bumped_before_set`**: Verifies that `fund_contract`'s internal `apply_transfer` path does NOT bump the nonce on error (validate-before-mutate), and that the SET-to-`p.nonce+1` is the necessary and sufficient fix. A follow-up transfer at `p.nonce+1` then succeeds.

**Result: No nonce gap or double-bump found. Every path lands at exactly `p.nonce+1`.**

### (d) Contract Text Determinism

**C6-D6** (1,000 iter): `keccak256(utf8(text))` is a pure function: the same text yields the same `text_ref` on every call; distinct texts yield distinct refs (no trivial aliasing confirmed for the empty string, single-char, and long strings).

**C6-D7** (1,000 iter): `deploy_contract` stores the exact text verbatim in `PromptContract.text` and stores the supplied `text_ref` unchanged. Two independent deploys of the same text/parties produce identical records. The interpreter reads `contract.text` from chain state — interpretation is reproducible from chain state alone (no off-chain text fetch).

**`c6_d7_empty_text_is_deterministic`**: The empty string is a valid text; its `text_ref` is deterministic; two deploys agree.

**`deploy_block`/`deploy_tx` stamping** (code review): The deploy block/tx are stamped from the block's own `number` and `p.hash` fields, both of which are consensus values (block height is sequential; block hash is `keccak256(number || parent_hash || timestamp)`). Both nodes computing the same block at the same height with the same parent and timestamp will stamp the same `deploy_block` and `deploy_tx`. No hidden nondeterminism.

**Result: No nondeterminism found in the contract text path.**

---

## Existing Tests Verified

| Test binary | Tests | Result |
|---|---|---|
| `c6_failed_tx` (rpc integration) | 3 | PASS |
| `c6_reliability` (new, runtime) | 16 | PASS |
| `c5_reliability` (runtime) | 17 | PASS |
| `m4_reliability` (runtime) | 25 | PASS |
| `m3_reliability` (runtime) | 23 | PASS |
| All other test binaries | 259 | PASS |
| **Total** | **343** | **PASS** |

---

## Findings

No consistency violations found.

### Observation: nonce SET-to-`p.nonce+1` is subtle but correct

The failure handler in `produce_block` (lines 1320–1326 of `crates/rpc/src/lib.rs`) uses:

```rust
acct.nonce = p.nonce + 1;   // SET, not += 1
```

rather than `+= 1`. This is intentional and correct: for hub ops, `consume_nonce` has already bumped the nonce, so `+= 1` would produce `p.nonce+2` (a gap). For transfer/fund ops, the nonce was not bumped, so `+= 1` on the current value would be correct too — but the SET-to-`p.nonce+1` is cleaner and idempotent for both cases. The FIFO mempool + submit gate guarantee `p.nonce` equals the pre-tx chain nonce, making the SET the unique correct post-state.

The `c6_d5_no_double_bump_failing_hub_op` and `c6_fund_contract_failure_nonce_not_bumped_before_set` tests together pin this subtle invariant.

### Observation: `spendable_debit` includes fee at submit time

The submit gate (`ingest_raw_tx`) uses `spendable_debit` which now includes `fee_for_gas(gas_for_kind(kind))` in the affordability check. This means the submit gate rejects a sender who cannot afford the fee synchronously — preventing the one case where a tx would be dropped at block time (the `continue` path in `produce_block` that logs "dropping tx: cannot pay gas fee"). This is the correct cycle-6 guarantee: the only tx that is NOT mined is one the submit gate already rejected.

### Observation: `FundContract` does not call `consume_nonce` separately

`fund_contract` calls `apply_transfer` internally, which handles both nonce and balance validation atomically. The `produce_block` comment explicitly notes "do NOT call `consume_nonce` here (that would double-count)". This means a failed `fund_contract` (e.g. `NoSuchContract`) errors before `apply_transfer` runs — nonce is 0 bumps — and the SET-to-`p.nonce+1` is the needed correction. The `c6_fund_contract_failure_nonce_not_bumped_before_set` test captures this exact edge case.

---

## Observability

The `produce_block` failure path emits:
```
WARN tx=<hash> error=<reason> "mining failed tx (status 0x0)"
```

This is the primary observability signal for a failed-tx event. The `revert_reason` field on `StoredTx` is surfaced via:
- `eth_getTransactionReceipt` → `revertReason` field
- `ubi_getTransaction` → `result.reason` field
- `ubi_getBlock` → per-tx `status` + (via decoded tx) `result.reason`

All three surfaces are verified by the `c6_failed_tx` integration test's `assert_failed_reason` helper. The reason string is the `Display` of the runtime error (e.g. "vouchee has no open registration", "no such contract: 999") — human-readable and actionable.

**Gap:** There is no metric counter for `status=0x0` txs mined per block. A Prometheus counter `ubi2_failed_txs_mined_total{kind=<PendingKind>}` would make fleet-level monitoring of failed-tx rates possible. This is not a correctness issue but an operational observability gap.

---

## Verdict

**PASS.**

Determinism, conservation, and nonce integrity are all demonstrated by property tests. No consistency violation was found. The contract text path is deterministic. The 500-block soak confirms the system remains consistent under load with mixed succeed/fail traffic.
