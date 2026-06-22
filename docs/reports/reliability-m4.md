# Reliability Gate — M4 Prompt Contracts (board M4-T7)

**Gate:** PASS

**Date:** 2026-06-22

**Scope:** Determinism, balance reproducibility, M3-semantics equivalence after `quorum_tally`
refactor, hidden nondeterminism hunt, and soak across the M4 prompt-contract layer
(`crates/runtime/src/contracts.rs`, `crates/rpc/src/contracts.rs`, `crates/rpc/src/lib.rs`,
`crates/oracle/src/interpreter.rs`).

**Test file added:** `crates/runtime/tests/m4_reliability.rs` — 25 new tests, all PASS.
**Baseline kept green:** All pre-existing 217 cargo tests still pass (0 failures).

---

## Properties verified

### R1 — Interpreter-quorum determinism (I1)

**What was checked.** Same `(text, state, trigger)` inputs + `MockInterpreter` produce the same
`CanonicalEffect` (byte-identical `effect_hash`) on every interpreter and across independently-built
states. A quorum reaching >= QUORUM commits; a split aborts deterministically with no state change.

**How proved.**
- Named edge cases: unanimous 3-juror quorum; explicit `Abort` op quorum commits as Aborted with no
  state change; mixed Abort/Transfer distribution via the shared `quorum_tally` generic.
- Property test (`r1_property_quorum_determinism_and_split_aborts`): 10 000 iterations, jury sizes
  3..=9, all six candidate effect types, deterministic PRNG (SplitMix64 seed 0xB1A4...). Verifies
  tally determinism (same subs → same outcome) and order independence (reversed subs → same outcome).
- Property test (`r1_property_m4_split_aborts_no_state_change`): 2 000 iterations, unanimous quorum
  on random amounts, two independently built states agree on case status and committed `effect_hash`
  (I1), and agree on escrow and payee balances to the base unit (I2).

**Result.** All pass. No divergence found.

### R2 — Effect-application reproducibility (I2)

**What was checked.** `apply_effect` is a pure deterministic function. Two nodes building identical
state from the same op sequence agree to the base unit on escrow, balances, and any stream values.
Conservation holds: value entering escrow equals value leaving (to payees/parties/stream deposits).

**How proved.**
- Deterministic pair checks for each op type: `Transfer`, `Refund`, `SetVar`, and
  `OpenStream`/`StopStream` (500 random timelines).
- Conservation: `payee_balance + escrow == original_fund` after every Transfer/stream scenario.
- Two-node agreement: every scenario builds the same precondition twice and asserts field-by-field
  equality of escrow, payee balance, and vars.

**Result.** All pass. No base-unit divergence found. The integer-only arithmetic (no floats, using
`saturating_add`/`saturating_sub` throughout) maintains exact conservation across all 500 random
stream timelines.

### R3 — Validate-whole-then-apply atomicity (I4 / no-partial-state)

**What was checked.** Any op that fails validation aborts the **entire** effect — no partial
application. Failure cases tested: over-escrow on the Nth op (first op valid), non-party `Refund`
buried as the second op, `StopStream` on an un-owned stream, `Abort` op mixed with Transfer ops,
and zero-rate `OpenStream`.

**How proved.**
- 5 named atomicity tests, each asserting that after an abort: escrow equals pre-invoke escrow,
  all recipient balances equal pre-invoke values, and the case status is `Aborted`.

**Result.** All pass. The two-phase validate-then-apply structure in `apply_effect` correctly
prevents any partial write. The `EffectError::AbortOp` path catches an `Abort` op mixed with
state-changing ops (both are rejected; the explicit single-`Abort` effect path is handled one layer
up in `resolve_case`).

### R4 — Quorum-tally M3 semantics equivalence (shared `quorum_tally`)

**What was checked.** The generic `quorum_tally` refactor shared between M3 (`CanonicalVerdict`)
and M4 (`CanonicalEffect`) preserves all M3 tally semantics exactly.

**How proved.**
- Reference implementation test (`r4_quorum_tally_m3_semantics_unchanged`): 5 000 random tally
  scenarios, jury sizes 3..=7, all seven verdict/confidence combinations. A direct-count reference
  tally (the pre-refactor approach) is compared against the generic `quorum_tally`-backed `tally()`
  function. They agree on every case: Pending, Committed (verdict, confidence), Escalated.
- Spot-check test (`r4_m3_contract_tests_still_pass`): drives the full M3 happy-path
  (Pending→Verified→Emission), sybil-revoke path, and false-challenge-slash path through the shared
  `quorum_tally`. All produce the expected results, confirming M3 semantics are unchanged.
- All 15 M3 acceptance tests (`m3_humanity.rs`) and 4 M3 QA tests (`m3_qa.rs`) still pass.

**Result.** PASS. The refactor is semantics-preserving.

### R5 — No HashMap iteration on any consensus path (I1)

**What was checked.** All structures returned from `MemState` that are used on the consensus path are
sorted before use, eliminating any hash-map iteration order dependency.

**Paths audited:**
- `active_jurors()`: `values().filter().collect()` sorted by `sort_unstable()`. Test confirms
  identical output across forward, reversed, and shuffled insertion orders (15 jurors, 3 orderings).
- `contract.sorted_vars()`: `HashMap::iter().collect()` followed by `sort_unstable()`. Test
  confirms identical output across 3 insertion orders of 8 key-value pairs.
- `state.outgoing(&escrow_addr)`: returns a `Vec<StreamId>`, sorted by `sort_unstable()` in
  `state_view()` before handing to the interpreter.
- `contract.parties`: sorted and deduped at construction in `PromptContract::new()`.
- `case.effects`: stored as `Vec<(Address, CanonicalEffect)>` (insertion order), tallied by
  `tally_effects()` which uses the order-independent `quorum_tally()` — proved via order-reversal
  test.
- `HashSet<StreamId>` in `apply_effect`: used only for `contains()` membership checks, not
  iteration. Order-safe.
- `PromptContract.vars`: `HashMap<Hash, Hash>` — iterated in `sorted_vars()` (sorted before
  consensus use) and in `apply_effect`/`SetVar` (point writes, not iterated). Safe.
- `MockInterpreter.by_text_trigger`/`by_trigger`: HashMap lookups (no iteration on consensus path).
  Safe.

**Result.** PASS. No HashMap iteration on any consensus path was found.

### R6 — `effect_hash` stability (I1)

**What was checked.** The same op list always produces the same `effect_hash`. Different ops produce
different hashes. The canonical encoding is self-delimiting and the FNV-1a-based digest is
byte-reproducible across invocations.

**How proved.**
- 2 000-iteration property test: random op lists (length 1..=5 from a pool of 7 op variants);
  constructs the same `CanonicalEffect` twice and asserts `effect_hash` equality; mutates one op and
  asserts hash inequality.
- Op tag prefix test: all 4 tested op variants with identical trailing fields produce distinct
  hashes (no aliasing due to the 1-byte discriminant prefix).
- Encode round-trip: `effect.encode()` is stable across repeated calls.

**Minor documentation issue found (not a functional defect):** The docstring for `fnv1a_256` says
"eight independent FNV-1a lanes" but the function actually uses `BASES: [u64; 4]` — four lanes, each
producing 8 bytes = 32 bytes total. The hash computation is correct; only the comment is wrong.
This does not affect determinism or safety.

**Result.** PASS.

### R7 — Light soak (deterministic in-process node)

**What was checked.** Deploying N=20 contracts, funding each, invoking with random amounts, and
verifying that all committed effects reconcile to the base unit and that two independently-built
states agree exactly. Mixed-effect soak (Transfer, SetVar, Abort, over-escrow) and deferred
`submit_effect` path.

**How proved.**
- `r7_soak_multiple_contracts_deterministic_effects`: 20 contracts, random amounts 1–5 UBI, payee
  balance equals exact sum of all committed transfers, second independent state agrees exactly.
- `r7_soak_mixed_effects_no_partial_state`: four scenario types per contract, each verified for
  correct committed/aborted outcome and correct state invariants.
- `r7_submit_effect_deferred_path_commits_deterministically`: non-jury submit returns `NotOnJury`,
  double-submit returns `AlreadySubmitted`, state unchanged after both rejections (fail-closed, I4).

**Result.** PASS. All soak scenarios produce deterministic, reconciled outcomes.

---

## Hidden nondeterminism hunt

| Concern | Verdict |
|---|---|
| Floats in consensus path | None found. All arithmetic is integer (`u128`, `u64`). `temperature: 0.0` in `ClaudeInterpreter` is a JSON field for the model API, not used in any state computation. |
| `HashMap` iteration order | All `MemState` reads that feed the consensus path (`active_jurors`, `sorted_vars`, `contracts`, `exec_cases`, `humans`, `cases`) sort before returning. No unsorted iteration on any consensus path. |
| `SystemTime::now()` | Used only in `now_secs()` helper in the RPC layer — feeds the `timestamp` argument to `produce_block()`. The `timestamp` is a block-level input agreed by consensus; individual handlers use the block's timestamp, not wall clock. No live `now()` call inside state transitions. |
| Random seed / PRNG | All consensus randomness flows from `block_entropy(hash, number)` — a deterministic function of the block hash and height, both consensus values. `SplitMix64` in `select_jury`/`interpreter_seed` is seeded from this. |
| Model / seed pinning | `ClaudeInterpreter` uses temperature 0 and a pinned model id. The `MockInterpreter` is fully deterministic by construction. |
| Locale / string formatting | No locale-sensitive operations in any consensus path. |
| `HashSet` in `apply_effect` | Used only for `contains()` on a set of `StreamId` values. No iteration. |
| `effect_hash` via FNV-1a | Deterministic: fixed prime, fixed bases, fixed field order in `Op::encode_into`. The "eight lanes" docstring is inaccurate (actually four lanes), but the function is correct and deterministic. |

---

## Observability

The following signals are confirmed present:
- `ContractDeployed` log (topic[0] = event sig, topic[1] = contract id).
- `CaseOpened` log (topic[1] = case id, topic[2] = contract id).
- `EffectCommitted(caseId, contractId, effectHash)` log — carries the `effect_hash` so any monitor
  can verify quorum agreement across nodes.
- `EffectAborted(caseId, contractId)` log.
- `ubi_getContract(id)`, `ubi_getExecCase(id)`, `ubi_getContractsOf(address)` RPC reads expose
  full case status, submitted effects, and jury composition.

**Observability gap:** There is no per-interpreter submission log (only the terminal
`EffectCommitted`/`EffectAborted`). In a multi-node setup with an off-chain juror daemon (FU-7), a
split would be visible only by querying `ubi_getExecCase` and examining the `effects` array — no
on-chain event fires for individual `submitEffect` submissions. This is adequate for the M4 devnet
(the MockInterpreter is always unanimous) but should be addressed before a multi-node live
deployment.

---

## Consistency violations found

None.

---

## Tests added

File: `/Users/santisiri/AI/ubi2/crates/runtime/tests/m4_reliability.rs`

| Test name | Property |
|---|---|
| `r1_unanimous_quorum_commits_deterministically` | R1 named edge case; two-node byte-identical |
| `r1_three_way_split_aborts_deterministically` | R1 named edge case; NoQuorum path |
| `r1_property_quorum_determinism_and_split_aborts` | R1 property: 10k iters, tally determinism + order-independence |
| `r1_property_m4_split_aborts_no_state_change` | R1 property: 2k iters, two-node effect_hash agreement |
| `r1_explicit_abort_quorum_commits_as_aborted_no_state_change` | R1 named edge case; Abort quorum = Aborted + no state change |
| `r1_mixed_abort_transfer_split_aborts` | R1 named edge case; mixed effect split via shared quorum path |
| `r2_transfer_reproducible_two_nodes` | R2 Transfer conservation + two-node agreement |
| `r2_refund_reproducible_two_nodes` | R2 Refund two-node agreement |
| `r2_setvar_reproducible_two_nodes` | R2 SetVar two-node var agreement |
| `r2_stream_reproducible_two_nodes` | R2 OpenStream/StopStream 500-iter conservation |
| `r3_multi_op_first_valid_second_over_escrow_aborts_atomically` | R3 atomicity: over-escrow on Nth op |
| `r3_non_party_refund_buried_aborts_atomically` | R3 atomicity: authority violation mid-effect |
| `r3_stop_unowned_stream_aborts_atomically` | R3 atomicity: stream ownership violation |
| `r3_abort_op_in_mixed_effect_aborts_atomically` | R3 atomicity: Abort op in mixed effect |
| `r3_zero_rate_stream_aborts_atomically` | R3 atomicity: zero-rate stream validation |
| `r4_quorum_tally_m3_semantics_unchanged` | R4 5k iters: reference vs generic tally equivalence |
| `r4_m3_contract_tests_still_pass` | R4 M3 happy-path + sybil + false-challenge via shared tally |
| `r5_active_jurors_is_insertion_order_independent` | R5 insertion-order independence of active_jurors |
| `r5_contract_sorted_vars_is_insertion_order_independent` | R5 insertion-order independence of sorted_vars |
| `r5_exec_case_effects_order_independence` | R5 tally order-independence via effects Vec |
| `r6_effect_hash_is_stable_and_distinguishes_ops` | R6 2k-iter hash stability and collision safety |
| `r6_op_tag_prefix_prevents_aliasing` | R6 op tag distinguishes all variants |
| `r7_soak_multiple_contracts_deterministic_effects` | R7 20-contract soak, two-node conservation |
| `r7_soak_mixed_effects_no_partial_state` | R7 mixed-effect soak, all abort/commit invariants |
| `r7_submit_effect_deferred_path_commits_deterministically` | R7 deferred path: NotOnJury, AlreadySubmitted fail-closed |
