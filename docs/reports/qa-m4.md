# QA Report — M4 Prompt Contracts (GATE 1)

**Date:** 2026-06-22  
**Branch:** m4-prompt-contracts  
**Commit:** ce1de45  
**Verdict:** PASS  

---

## Scope

Spec: `docs/specs/04-prompt-contracts.md` — 6 acceptance criteria (AC1–AC6).  
Invariants from `docs/specs/00-overview.md`: I1 (deterministic quorum), I2 (integer effects), I4 (fail-closed), I6 (least authority).

---

## Reproduce

All tests run with no live model calls and no external services (invariant I5 — MockInterpreter and recorded fixtures only).

```sh
# Full workspace
cargo test --workspace

# M4-specific by file
cargo test -p ubi2-runtime --lib contracts
cargo test -p ubi2-oracle
cargo test -p ubi2-rpc --test m4_acceptance
cargo test -p ubi2-rpc --test m4_qa
```

No node boot on the default port; each integration test uses a distinct port in the 18550–18558 range and stops the server handle after the test.

---

## Test count

| Suite | Tests | Result |
|---|---|---|
| `ubi2-runtime --lib contracts` | 15 | ok |
| `ubi2-oracle` (unit + fixture replay) | 10+9 | ok |
| `ubi2-rpc --test m4_acceptance` | 3 | ok |
| `ubi2-rpc --test m4_qa` (new) | 10 | ok |
| All other workspace tests | 186 | ok |
| **Workspace total** | **233** | **ok** |

---

## Criterion-to-test mapping

### AC1 — Deploy → fund → invoke → Transfer from escrow; balances reconcile to the base unit

**Tests (all passing):**

- `crates/runtime/src/contracts.rs::contracts::tests::ac1_deploy_fund_invoke_transfers_from_escrow`
  Unit: MockInterpreter scripted to Transfer 5 UBI; asserts `payee balance +5 UBI`, `escrow -5 UBI`, `ExecStatus::Committed`.

- `crates/rpc/tests/m4_acceptance.rs::deploy_fund_invoke_transfers_from_escrow`
  RPC integration: full EIP-155 tx path `deployContract → fundContract → invokeContract`; asserts `ubi_getContract`, `ubi_getExecCase`, `eth_getBalance` reconcile to the base unit.

- `crates/rpc/tests/m4_qa.rs::ac1_full_escrow_drain_balances_reconcile`
  RPC integration: drains 100% of escrow (10 UBI); asserts `escrow = 0` and `payee delta = 10 UBI`.

- `crates/oracle/tests/interpreter_replay.rs::live_interpreter_commits_intended_transfer_end_to_end`
  End-to-end with ClaudeInterpreter backed by a recorded fixture (no live model).

---

### AC2 — Solvency/authority: over-escrow or non-party effect aborts atomically, no state change

**Tests (all passing):**

- `contracts::tests::ac2_over_escrow_aborts_no_state_change` — runtime unit
- `contracts::tests::ac2_refund_to_non_party_aborts_no_state_change` — runtime unit (I6)
- `contracts::tests::ac2_multi_op_partial_over_escrow_aborts_atomically` — atomicity: valid first op + invalid second op → whole effect aborts (I4)
- `m4_qa.rs::ac2_over_escrow_effect_aborts_at_rpc_level` — RPC integration: over-escrow → `status.type = "Aborted"`, escrow and payee balance unchanged
- `m4_qa.rs::ac2b_multi_op_partial_over_escrow_aborts_atomically_via_rpc` — RPC integration: 2+5 UBI combined exceeds 6 UBI escrow; both recipients untouched after abort

---

### AC3 — Quorum determinism (I1): identical inputs + MockInterpreter → identical CanonicalEffect; split aborts deterministically

**Tests (all passing):**

- `contracts::tests::ac3_split_aborts_deterministically` — tally of 3 distinct effects → `EffectTally::NoQuorum`
- `contracts::tests::ac3_quorum_determinism_two_nodes_agree` — two independent MemState instances, same seed → same `ExecCaseId`, same committed effect, same jury
- `contracts::tests::ac3_property_tally_order_independent_and_deterministic` — 5000 random 3-juror configurations; verified order-independence (tally of shuffled list = tally of original)
- `m4_qa.rs::ac3_two_invocations_same_trigger_same_effect_hash` — RPC integration: two sequential invocations with the same trigger_ref → both cases `Committed` with byte-identical `effect_hash` (I1 at the wire level)
- `interpreter_replay.rs::quorum_forms_when_independent_interpreters_replay_same_effect` — three independent ClaudeInterpreter instances (fixture transport) emit byte-identical effect hashes

---

### AC4 — Injection resistance: crafted contract/trigger cannot produce an out-of-scope or over-authority effect; the runtime backstop rejects it (I4/I6)

**Tests (all passing):**

- `interpreter_replay.rs::injection_fixture_fails_closed_to_abort` — recorded model response for an injection-attempt contract+trigger is a single `abort` op (the expected fenced, fail-closed behavior)
- `interpreter_replay.rs::ac4_over_authority_effect_is_rejected_by_the_runtime_backstop` — a fixture-backed ClaudeInterpreter that emits a 1000 UBI drain from a 3 UBI escrow; the runtime backstop (apply_effect solvency check) aborts the invocation, attacker balance = 0, escrow intact
- `oracle/src/interpreter.rs::tests::request_is_pinned_temperature_zero_effect_schema_and_fenced` — verifies the request is temperature 0, constrained to the closed effect schema, and the contract+trigger are fenced as UNTRUSTED
- `contract_prompt.rs::tests::injected_close_marker_is_defanged` — forged DATA_CLOSE inside a contract text is redacted; the real fence markers are 2 (not 3)
- `m4_qa.rs::ac4_injection_crafted_over_authority_effect_rejected_by_runtime_backstop` — RPC integration: MockInterpreter scripted to emit a 1000 UBI drain from a 2 UBI escrow; RPC case shows `Aborted`, attacker balance = 0, escrow = 2 UBI
- `m4_qa.rs::ac4b_refund_to_non_party_rejected_by_runtime_backstop` — RPC integration: Refund to ATTACKER (not in parties list) → `Aborted`, escrow = 5 UBI
- `m4_qa.rs::ac4c_schema_fence_injection_in_trigger_aborts_closed` — RPC integration: interpreter scripted to return explicit `Abort` op (simulating model's fail-closed response) → `Aborted`, escrow intact

The two-layer defense is verified: the model-level fence (I5 fixture tests) AND the runtime backstop (RPC integration tests) both prevent out-of-scope effects from committing.

---

### AC5 — Streaming contract: OpenStream from escrow; stop/refund conserves totals

**Tests (all passing):**

- `contracts::tests::ac5_streaming_contract_opens_stream_from_escrow` — runtime unit: OpenStream depletes escrow field; M2 stream from escrow account exists; Bob accrues exactly 4h of flow at t=4h
- `contracts::tests::ac5_stop_stream_refunds_escrow_conserved` — runtime unit: stop 3h in; Bob keeps 3h, escrow regains 7h; total = original 10h deposit (conservation); Refund of 7h to funder leaves escrow = 0
- `interpreter_replay.rs::stream_fixture_maps_to_canonical_open_stream` — ClaudeInterpreter fixture maps to canonical OpenStream op (byte-identical to runtime building the same op)
- `m4_qa.rs::ac5_open_stream_from_escrow_via_rpc` — RPC integration: invokeContract → `ubi_getExecCase` shows `Committed` with `OpenStream` op; escrow drained to 0 (all locked in stream deposit)

---

### AC6 — Wallet/SDK data path: deploy → fund → invoke and read ubi_getContract / ubi_getExecCase / ubi_getAccount / ubi_getAddressActivity

**Tests (all passing):**

- `m4_acceptance.rs::deploy_fund_invoke_transfers_from_escrow` — full EIP-155 wallet path: `deployContract` → `fundContract` → `invokeContract`; verifies `ubi_getContract`, `ubi_getExecCase` (ops + effect_hash), `eth_getBalance`, `ubi_getContractsOf`
- `m4_acceptance.rs::address_indexer_shapes` — EXPL-1: `ubi_getAddressActivity` for deployer shows `DeployContract/FundContract/InvokeContract` rows with correct shape; `ubi_getAccount` shows `balance`, `nonce`, `human_status`, `contracts`, `tx_count`, `streams_out`, `streams_in`
- `m4_acceptance.rs::submit_effect_via_tx_commits` — submitEffect calldata wire codec: `encode_effect` → ABI-encoded `submitEffect(caseId, bytes)` → node ingests and correctly handles closed-case guard
- `m4_qa.rs::ac6_encode_decode_effect_round_trips_all_op_types` — `encode_effect` / `decode_effect` round-trips all 6 op types (Transfer, Refund, OpenStream, StopStream, SetVar, Abort); recomputed `effect_hash` matches original (I1 — wire never trusts a transmitted hash)
- `m4_qa.rs::ac6_ubi_get_exec_case_aborted_shape` — `ubi_getExecCase` returns the correct `Aborted` shape (has `id`, `status.type = "Aborted"`, no `effect` field) so the SDK can handle the failure path

---

## Invariant verification

| Invariant | Evidence |
|---|---|
| **I1** deterministic interpreter quorum | `ac3_*` tests; `replay_is_deterministic_byte_identical` (10 replays, byte-identical); `ac6_encode_decode_effect_round_trips` (hash recomputed from ops, not trusted from wire) |
| **I2** integer effects | All amounts are `u128` base units; no floats on any consensus path; confirmed by encoding tests |
| **I4** fail-closed abort | `ac2_*`, `ac4_*` tests: any invalid/over-authority/injection effect → `Aborted`, no partial state |
| **I6** least authority | `ac4b` (non-party refund blocked), `ac4` (attacker never receives funds), `interpreter_replay::ac4` (fooled interpreter still bounded by runtime backstop) |

---

## Gaps found and addressed

The pre-existing `m4_acceptance.rs` covered AC1 and AC6 at the RPC level. AC2, AC3, AC4, and AC5 had only runtime unit tests or oracle fixture replays — no RPC-level integration evidence. The new `crates/rpc/tests/m4_qa.rs` (10 tests) fills those gaps:

- AC2: two RPC-level abort tests (over-escrow, multi-op combined over-escrow)
- AC3: one RPC-level determinism test (two invocations, same effect_hash)
- AC4: three RPC-level injection tests (over-authority drain, non-party refund, explicit-abort schema fence)
- AC5: one RPC-level OpenStream test
- AC6: supplemental wire-codec round-trip test + Aborted shape test

No untestable criterion was found. All 6 AC criteria are covered by passing tests.

---

## Verdict: PASS

Every M4 acceptance criterion has at least one passing test with real observed output. No criterion fails, no criterion is unteested, and no invariant is violated.
