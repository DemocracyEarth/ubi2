# QA Report — Cycle 6 (branch feat/cycle6-contracts-vouch-docs, commit d6cbbe5)

**Gate:** GATE 1 — QA  
**Verdict:** PASS  
**Tests run:** 375 passing, 0 failing (up from 347 before this cycle; 28 new in-suite tests added by c6_qa.rs + module unit tests included in the recount)

---

## What cycle 6 changed (in scope)

1. **FAILED-TX RECEIPTS** — a queued op failing at block time is now mined as a status-0x0 tx: fee charged to TREASURY, nonce consumed deterministically (p.nonce+1), decoded revert reason surfaced on three RPC surfaces, no op state change. A sender who cannot afford the fee is rejected at submit (never enters mempool).

2. **CONTRACT TEXT ON-CHAIN** — `deployContract(string text, address[] parties)` stores the full NL text on-chain inside `PromptContract.text`; the node derives `text_ref = keccak256(utf8(text))` and stamps `deploy_block`/`deploy_tx` when the deploy tx is mined; `ubi_getContract` returns all these fields plus the exec-case list including committed effect ops.

3. **UI** — template library, authoring flow, contract detail/interact view, AI-config mock banner, explorer links, vouch UX in `apps/wallet`; SDK typings for `ContractView` / `ExecCaseSummary` with `text`, `text_ref`, `deploy_block`, `deploy_tx`, `cases`.

---

## Acceptance criteria and test mapping

### (1) FAILED-TX RECEIPTS

| Criterion | Test(s) | Result |
|-----------|---------|--------|
| A hub op failing at block time is MINED as status 0x0 | `crates/rpc/tests/c6_failed_tx.rs::failing_vouch_is_mined_failed_nonce_consumed_no_pending` | PASS |
| Decoded revert reason on receipt + ubi_getTransaction + ubi_getBlock | `c6_failed_tx.rs::failing_vouch_is_mined_failed_nonce_consumed_no_pending` (calls `assert_failed_reason`) | PASS |
| Fee charged to TREASURY | `c6_failed_tx.rs::failing_vouch_is_mined_failed_nonce_consumed_no_pending` (treasury_pre < treasury_post) | PASS |
| Nonce consumed; follow-up at next nonce succeeds (no cascade) | `c6_failed_tx.rs::failing_vouch_is_mined_failed_nonce_consumed_no_pending` | PASS |
| No op state change (no vouch edge) | `c6_failed_tx.rs::failing_vouch_is_mined_failed_nonce_consumed_no_pending` | PASS |
| Failing CONTRACT op (invoke non-existent contract) mined failed | `c6_failed_tx.rs::failing_contract_invoke_is_mined_failed` | PASS |
| Can-not-afford-fee rejected AT SUBMIT (no pending) | `c6_failed_tx.rs::sender_who_cannot_afford_fee_is_rejected_at_submit` | PASS |
| Two consecutive failures — no nonce gap after either | `c6_qa.rs::c6_two_consecutive_failed_txs_no_nonce_gap` | PASS |
| Revert reason shown in receipt (UI failing-vouch criterion) | `c6_qa.rs::c6_failing_vouch_shows_decoded_revert_reason_in_receipt` | PASS |
| Can-not-afford rejected at submit (c6_qa smoke) | `c6_qa.rs::c6_cannot_afford_fee_rejected_at_submit_no_pending` | PASS |

### (2) CONTRACT TEXT ON-CHAIN

| Criterion | Test(s) | Result |
|-----------|---------|--------|
| deploy → `ubi_getContract.text` is the exact NL string | `c6_qa.rs::c6_contract_text_on_chain_full_fields` | PASS |
| `text_ref` = keccak256(utf8(text)) (node-derived, 0x-hex) | `c6_qa.rs::c6_contract_text_on_chain_full_fields` | PASS |
| `deploy_block` = block the deploy tx was mined at | `c6_qa.rs::c6_contract_text_on_chain_full_fields` | PASS |
| `deploy_tx` = deploy tx hash | `c6_qa.rs::c6_contract_text_on_chain_full_fields` | PASS |
| `cases` is empty array before any invoke | `c6_qa.rs::c6_contract_text_on_chain_full_fields` | PASS |
| After invoke: case appears in `cases` with committed effect + `resolved_at` | `c6_qa.rs::c6_contract_cases_populated_after_invoke_effect_uses_stored_text` | PASS |
| Interpreter reads stored `contract.text` (not an off-chain ref) | `c6_qa.rs::c6_contract_cases_populated_after_invoke_effect_uses_stored_text` (MockInterpreter keyed on exact text bytes; a different text would miss and commit a noop instead, failing the balance check) | PASS |
| `text_ref` still keccak256(utf8(text)) after invoke | `c6_qa.rs::c6_contract_cases_populated_after_invoke_effect_uses_stored_text` | PASS |
| `ubi_getContractsOf` lists the contract with correct text | `c6_qa.rs::c6_contract_indexed_in_address_activity_and_contracts_of` | PASS |
| `ubi_getAddressActivity` indexes DeployContract for the deployer | `c6_qa.rs::c6_contract_indexed_in_address_activity_and_contracts_of` | PASS |
| Full deploy→fund→invoke→ubi_getContract/ubi_getExecCase RPC path | `crates/rpc/tests/m4_acceptance.rs::deploy_fund_invoke_transfers_from_escrow` (also checks text, text_ref, deploy_block, deploy_tx, cases) | PASS |

### (3) UI

| Criterion | Test(s) | Result |
|-----------|---------|--------|
| `pnpm -r build` (SDK typecheck + Next.js compile) green | Run below | PASS |
| Mock-banner condition: `ubi_getOracleConfig` returns `active="mock"` on devnet | `c6_qa.rs::c6_oracle_config_mock_banner_condition` | PASS |
| Contract detail reads text/block/tx/cases (live data path) | `c6_qa.rs::c6_contract_text_on_chain_full_fields` + `c6_contract_cases_populated_after_invoke_effect_uses_stored_text` | PASS |
| Failing vouch shows reason (revert-reason surface the UI reads) | `c6_qa.rs::c6_failing_vouch_shows_decoded_revert_reason_in_receipt` | PASS |
| Deploy template → deploy contract → contract detail | `m4_acceptance.rs::deploy_fund_invoke_transfers_from_escrow` (exercises the same RPC surface the template deploy path calls) | PASS |

---

## Commands to reproduce

```
# All Rust tests (375 passing, 0 failing)
cargo test

# Cycle-6 specific regression (3 tests)
cargo test --test c6_failed_tx

# Cycle-6 QA gate (7 tests, new this cycle)
cargo test --test c6_qa

# M4 acceptance (contract text fields, cases, deploy_block/tx) (3 tests)
cargo test --test m4_acceptance

# UI build + typecheck
pnpm -r build
```

---

## Evidence (excerpts from actual run output)

```
Running tests/c6_failed_tx.rs
test sender_who_cannot_afford_fee_is_rejected_at_submit ... ok
test failing_contract_invoke_is_mined_failed ... ok
test failing_vouch_is_mined_failed_nonce_consumed_no_pending ... ok
test result: ok. 3 passed; 0 failed

Running tests/c6_qa.rs
test c6_oracle_config_mock_banner_condition ... ok
test c6_cannot_afford_fee_rejected_at_submit_no_pending ... ok
test c6_failing_vouch_shows_decoded_revert_reason_in_receipt ... ok
test c6_contract_indexed_in_address_activity_and_contracts_of ... ok
test c6_contract_text_on_chain_full_fields ... ok
test c6_contract_cases_populated_after_invoke_effect_uses_stored_text ... ok
test c6_two_consecutive_failed_txs_no_nonce_gap ... ok
test result: ok. 7 passed; 0 failed

Running tests/m4_acceptance.rs
test address_indexer_shapes ... ok
test deploy_fund_invoke_transfers_from_escrow ... ok
test submit_effect_via_tx_commits ... ok
test result: ok. 3 passed; 0 failed

apps/wallet build: ✓ Compiled successfully
apps/wallet build: ✓ Generating static pages (4/4)
packages/sdk build: Done
```

---

## Notes / non-issues

- `cargo fmt --check` reports a pre-existing diff in `crates/runtime/tests/c6_reliability.rs` (tuple return formatting); this diff pre-dates cycle 6 and is not introduced by the new `c6_qa.rs` file.
- `cargo clippy --tests` reports zero errors; two doc-list-indentation warnings in the new file (cosmetic only) are retained.
- No live model calls were used in any test (all use `MockInterpreter` / `MockOracle` — invariant I5).
- No node was started outside of in-process `serve()` calls; all ports are in the QA range (18600–18606).
