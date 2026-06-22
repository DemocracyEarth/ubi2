# Reliability Gate — Cycle 5 (fee model + oracle admin)

**Gate:** GATE 2 — Reliability  
**Milestone:** C5 (native UBI gas fees, oracle hot-swap, LLM backend, deep-explorer reads)  
**Branch:** feat/fees-llm-explorer-ui @ 741e27f  
**Date:** 2026-06-22  
**Verdict:** PASS

---

## Scope

Cycle 5 adds: (1) a UBI gas fee on every tx (fee = gas_used × 1 gwei, credited to TREASURY); (2) a
loopback-only oracle admin RPC that hot-swaps the node's LLM backend; (3) a configurable Anthropic/
Ollama/OpenAI backend; (4) deep-explorer reads (ubi_getBlock / ubi_getTransaction).

This report focuses on whether the fee model — which now sits on the consensus path — satisfies
invariants I2 (reproducible balances), I4 (fail-closed, no partial state), and I1 (no hidden
nondeterminism).

---

## Properties checked

### A. Determinism / reproducibility

**A1 — Fee computation is exact integer arithmetic (no floats)**

`fee_for_gas(gas) = (gas as u128) * GAS_PRICE_WEI` in `crates/runtime/src/lib.rs:104`. Pure const
fn, no division, no rounding. Verified by test `f1_fee_for_gas_is_exact_integer`.

**A2 — Two nodes agree to the base unit with fees**

Two independently-built MemState instances applying the same `charge_fee` sequence reach identical
sender and treasury balances. Proved over 5 000 random timelines (property test
`f2_fee_determinism_two_nodes_agree`). A mixed charge+transfer replay also agrees to the base unit
(`f2_fee_plus_transfer_replay_is_deterministic`, 2 000 iters).

**A3 — Balance/emission/stream reproducibility holds with fees**

Streams running concurrently with fee-bearing txs: two nodes at the same timestamp agree exactly,
fees included. Proved over 2 000 random timelines with both `open_stream` and `stop_stream`
following fee charges (`f6_balance_with_fees_and_streams_is_reproducible`,
`f6_stop_stream_with_fee_is_reproducible`).

**Finding: `incoming()` / `outgoing()` index returns unsorted Vec<StreamId>.**  
These are only consumed in the `balance()` fold via `saturating_add`, which is order-independent for
the numerical sum. Two nodes with the same insertion sequence produce the same order, and the sum is
insensitive to permutation. Not a consensus risk in the current single-node devnet; the multi-node
path should sort these before any cross-node comparison. Documented, not a blocker.

### B. Conservation

**B1 — sender_debit = treasury_credit + value_transferred (per-kind)**

For each of the four fee-bearing gas tiers (GAS_TRANSFER=21 000, GAS_STREAM=60 000,
GAS_HUMANITY=80 000, GAS_CONTRACT=120 000), the sender loses exactly `fee` and the treasury gains
exactly `fee`. Proved analytically in `f3_fee_conservation_per_kind`. All arithmetic is `u128`;
the treasury uses `saturating_add` which at realistic supply levels (no UBI ever exceeds u128::MAX)
is exact.

**B2 — Global conservation across mixed random sequences**

Over 2 000 random sequences of `charge_fee` + `apply_transfer`, total settled balances never exceed
genesis_credit + emission_materialized. The one-directional truncation loss (≤1 base unit per
`settle()` call, previously documented in reliability-m1.md finding F1) is bounded and only a loss,
never a gain. Proved by `f3_global_conservation_mixed_tx_sequence` and
`f5_global_conservation_never_creates_value`.

**B3 — Stream conservation with fees**

`accrued + refund == deposit` for every stopped stream. Proved over 1 000 random timelines with fee
charges surrounding the open/stop in `f6_stop_stream_with_fee_is_reproducible`.

### C. Pre-fee rollback atomicity (I4)

The block-apply path in `produce_block` (crates/rpc/src/lib.rs:985-1293) captures
`sender_pre = state.get(&from_addr)` and `treasury_pre = state.get(&TREASURY)` before calling
`charge_fee`. On op failure, it restores both snapshots. Four rollback scenarios were property-tested:

- Bad nonce (deterministic failure): `f4_rollback_on_failed_op_leaves_zero_partial_state`
- Insufficient balance for value (after fee): `f4_rollback_on_insufficient_value_no_partial_state`
- Self-stream (deterministic failure): `f4_rollback_on_failed_stream_no_partial_state`
- Random failure modes (2 000 iters): `f4_property_rollback_always_atomic_no_partial_state`

All confirm: after rollback, sender balance/nonce and treasury balance are byte-identical to
pre-charge snapshots, no recipient is created, and no stream is indexed.

**Minor observation (not a bug):** When `treasury_pre = None` (treasury has never been touched)
and the op that follows a zero-fee charge (`GAS_ONBOARD`) fails, the rollback path writes a
default zero-balance Account for the treasury. This is harmless (zero balance, no conservation
violation) but leaves a materialized treasury entry. Occurs only on the fee-exempt onboarding path,
which cannot fail the subsequent op with a balance error (onboarding costs nothing). The only
onboarding failure is a lifecycle error (already registered, etc.) — which is fine because the
treasury snapshot is restored to None-equivalent (zero balance). Confirmed in `f9`.

### D. Oracle hot-swap — off consensus path

`ubi_setOracleConfig` mutates only `OracleAdmin`'s internal `RwLock<AdminState>` (config + health +
Arc pointers to oracle/interpreter). It has no path into `MemState`, `Chain::inner`, or any of the
fee/balance/stream functions. Proved structurally:

- `charge_fee(state: &mut dyn State, ...)` — no oracle parameter
- `apply_transfer(state: &mut dyn State, ...)` — no oracle parameter
- `open_stream(state: &mut dyn State, ...)` — no oracle parameter
- `State` trait has no oracle methods
- `MemState` has no oracle field

Two independent oracle-free computations from the same inputs agree (`f7_oracle_config_reads_are_deterministic`).

The oracle is read once per block via `self.oracle_admin.oracle()` / `interpreter()` before locking
state (line 963-964 in lib.rs). A mid-flight `setOracleConfig` swap therefore takes effect at the
next block boundary, not mid-block — making the swap atomic at the block level. Committed on-chain
state is unaffected.

### E. Hidden nondeterminism hunt

| Source | Risk | Finding |
|---|---|---|
| `fee_for_gas()` | None — pure const fn, no map iteration | Clean |
| `charge_fee()` | Accesses treasury by fixed address, not by map iteration | Clean |
| `gas_for_kind()` | Pattern match on enum variant — fully deterministic | Clean |
| Pre-fee rollback | Two imperative puts by fixed address — no iteration | Clean |
| `incoming()` / `outgoing()` in `balance()` | Unsorted Vec, but fold is commutative sum | Not a consensus risk in single-node; see A3 note |
| `oracle_admin.oracle()` | Read under `RwLock::read` — thread-safe, not nondeterministic | Clean |
| `now_secs()` | Only used in submit-time checks and balance reads, NOT in `produce_block` apply path | Clean |
| Floats | None found in any consensus path | Clean |
| `SystemTime` | Used only in `now_secs()` for submit-time estimates, not fee charges | Clean |

**F8 test**: Two states with accounts inserted in opposite order, same fee+transfer sequence applied
→ byte-identical post-state (1 000 iters, `f8_fee_accounting_independent_of_account_insertion_order`).

### F. Fee-exempt onboarding (bootstrap invariant)

`GAS_ONBOARD = 0` and `fee_for_gas(0) = 0`. Treasury balance stays zero after a zero-fee charge.
A zero-balance, unverified account can call `charge_fee` with `GAS_ONBOARD` and succeed. Proved
in `f9_onboarding_is_fee_exempt_treasury_untouched`. The spec comment (crates/runtime/src/lib.rs:87)
is correct.

---

## Test suite

New property tests: `crates/runtime/tests/c5_reliability.rs` — 17 tests, all passing.

| Test | Property | Iters |
|---|---|---|
| f1_fee_for_gas_is_exact_integer | Fee is exact u128, no floats | analytic |
| f2_fee_determinism_two_nodes_agree | Two nodes agree on fee deduction | 5 000 |
| f2_fee_plus_transfer_replay_is_deterministic | Mixed charge+transfer replay | 2 000 |
| f3_fee_conservation_per_kind | sender_loss = treasury_gain = fee | 4 tiers |
| f3_global_conservation_mixed_tx_sequence | Global conservation over mixed ops | 2 000 |
| f4_rollback_on_failed_op_leaves_zero_partial_state | Bad-nonce rollback is atomic | named |
| f4_rollback_on_insufficient_value_no_partial_state | Insufficient-value rollback | named |
| f4_rollback_on_failed_stream_no_partial_state | Self-stream rollback | named |
| f4_property_rollback_always_atomic_no_partial_state | Random-failure rollback | 2 000 |
| f5_global_conservation_never_creates_value | No value created in any sequence | 2 000 |
| f6_balance_with_fees_and_streams_is_reproducible | Stream balance with fees, two nodes | 2 000 |
| f6_stop_stream_with_fee_is_reproducible | Stop-stream+fee balance + conservation | 1 000 |
| f7_oracle_config_is_off_consensus_path | Oracle-free fee/transfer path | structural |
| f7_oracle_config_reads_are_deterministic | Oracle-free determinism | analytic |
| f8_fee_accounting_independent_of_account_insertion_order | No HashMap nondeterminism | 1 000 |
| f9_onboarding_is_fee_exempt_treasury_untouched | GAS_ONBOARD = 0, treasury zero | analytic |
| fee_amounts_are_feasible_relative_to_ubi_emission | Spec comment validation | analytic |

All 308 existing tests also pass unchanged (`cargo test -p ubi2-runtime -p ubi2-rpc`).

---

## Findings summary

| ID | Severity | Title | Status |
|---|---|---|---|
| C5-R1 | Info | `incoming()`/`outgoing()` stream index is unsorted | Not a consensus risk (sum is commutative); document for multi-node |
| C5-R2 | Info | Zero-fee rollback leaves a materialized zero-balance treasury entry | Harmless; only on onboarding failure path (fee-exempt) |

No conservation violations, no divergent state, no partial writes, no float paths, no map-iteration nondeterminism, no oracle-config bleed into consensus state were found.

---

## Verdict: PASS

Determinism holds (same tx sequence → same balances + treasury on every node), conservation is
provably tight (no value created; truncation loss bounded by ≤1 base unit per settle call as
documented in M1), rollback is atomic (failed-op leaves zero partial state), and the oracle hot-swap
is fully off the consensus path.
