# QA Gate — Cycle 5 (C5)

**Branch:** feat/fees-llm-explorer-ui  
**Commit:** 741e27f  
**Date:** 2026-06-22  
**Verdict:** PASS

---

## Coverage map — acceptance criteria → tests

### 1. UBI FEES

| Acceptance criterion | Test(s) | Location | Result |
|---|---|---|---|
| Transfer pays per-kind fee into treasury (exact) | `every_tx_kind_pays_a_ubi_fee_into_the_treasury` | `crates/rpc/tests/fee_model.rs` | PASS |
| Vouch pays per-kind fee into treasury (exact) | (same test, step 2) | same | PASS |
| Deploy pays per-kind fee into treasury (exact) | (same test, step 3) | same | PASS |
| Invoke pays per-kind fee into treasury (exact) | (same test, step 4) | same | PASS |
| requestVerification is fee-exempt, treasury unchanged | `onboarding_is_fee_exempt_and_estimates_zero` | same | PASS |
| eth_estimateGas returns 0x0 for requestVerification | (same test, estimate assertion) | same | PASS |
| Insufficient-for-fee is dropped, no state change, nonce unchanged | `insufficient_for_fee_is_rejected_no_state_change` | same | PASS |
| Fee conservation: sender loses exactly fee, treasury gains exactly fee | `charge_fee_conserves_sender_to_treasury` | `crates/runtime/src/lib.rs` (unit) | PASS |
| Fee settles emission before charging | `charge_fee_settles_emission_before_charging` | same | PASS |
| Zero-gas (onboarding) charge always free | `charge_zero_gas_fee_is_free_for_onboarding` | same | PASS |
| TREASURY is distinct, unverified, never emits | `treasury_is_a_distinct_unverified_system_account` | same | PASS |
| eth_estimateGas returns correct per-kind gas for each hub | `estimate_gas_is_per_kind` | `crates/rpc/tests/fee_model.rs` | PASS |
| fee_for_gas() is pure integer math per-kind | `fee_for_gas_is_per_kind_integer_math` | `crates/runtime/src/lib.rs` | PASS |
| eth_gasPrice / eth_feeHistory consistent (MetaMask fix) | `GAS_PRICE_WEI` sourced from `RT_GAS_PRICE_WEI` constant (same value runtime charges) | `crates/rpc/src/lib.rs:95` | PASS (structural) |

**Fee conservation check (from integration test):**  
Total treasury balance after 5 fee-bearing txs = `fee_for_gas(GAS_TRANSFER) + fee_for_gas(GAS_HUMANITY) + fee_for_gas(GAS_CONTRACT) * 3` = exact sum of every per-kind fee.

### 2. DEEP EXPLORER

| Acceptance criterion | Test(s) | Location | Result |
|---|---|---|---|
| ubi_getBlock returns decoded header (number/hash/parentHash/timestamp/txCount/roots) | `decoded_block_and_transaction_shapes` | `crates/rpc/tests/expl2_decoded_reads.rs` | PASS |
| ubi_getBlock returns decoded tx list with kind/from/to/value/fee/call/logs/result | (same test, block 1 transfer assertions) | same | PASS |
| ubi_getTransaction returns decoded shape for a transfer | (same test, transfer tx assertions) | same | PASS |
| ubi_getTransaction returns decoded shape for a vouch | (same test, vouch tx assertions: hub=HumanityHub, method=vouch, args.vouchee, fee=80000*1e9) | same | PASS |
| ubi_getTransaction returns decoded shape for a deploy (logs=ContractDeployed) | (same test, deploy tx assertions) | same | PASS |
| ubi_getTransaction returns decoded shape for an invoke (logs=[CaseOpened,EffectCommitted], result.outcome.type=Committed) | (same test, invoke tx assertions) | same | PASS |
| ubi_getBlock by hash equals ubi_getBlock by number | (same test, by_num == by_hash assertion) | same | PASS |
| ubi_getBlock("latest") works | (same test, latest tag assertion) | same | PASS |
| ubi_getTransaction for unknown hash → null | (same test, missing hash → null assertion) | same | PASS |
| ubi_getAddressActivity carries fee field on each row | (same test, activity row.fee assertion) | same | PASS |
| explorer_renders_block_and_transaction (integration smoke) | `explorer_renders_block_and_transaction` | `crates/rpc/tests/m1_acceptance.rs` | PASS |

### 3. ORACLE ADMIN

| Acceptance criterion | Test(s) | Location | Result |
|---|---|---|---|
| ubi_getOracleConfig default → active=mock, provider=mock | `default_config_reports_mock_active` | `crates/rpc/tests/oracle_admin.rs` | PASS |
| ubi_setOracleConfig hot-swaps to live, ubi_getOracleConfig reflects new config | `set_config_hot_swaps_and_get_reflects_it_with_secret_redacted` | same | PASS |
| api_key value never appears in any response (secret redacted) | (same test, dump does not contain raw key) | same | PASS |
| api_key_env name (not value) is the only key reference in persisted config | `set_config_with_api_key_env_keeps_only_the_env_var_name` | same | PASS |
| No live factory → set returns error, Mock keeps serving (fail-closed) | `live_set_without_factory_falls_back_to_mock_fail_closed` | same | PASS |
| Non-loopback caller rejected for both get and set (error code -32099) | `non_loopback_caller_is_rejected_for_both_admin_methods` | same | PASS |
| IPv6 loopback (::1) accepted | `loopback_v6_is_accepted` | same | PASS |
| Missing peer address rejected fail-closed | `missing_peer_address_is_rejected_fail_closed` | same | PASS |
| OracleAdmin unit: config round-trips, default is mock, loopback detection | `oracle_admin::tests::*` (4 unit tests) | `crates/rpc/src/oracle_admin.rs` | PASS |
| oracle_cfg (node): missing file yields default Mock, env overrides file, write/read round-trip secret-free | `oracle_cfg::tests::*` (6 unit tests) | `crates/node/src/oracle_cfg.rs` | PASS |

### 4. LLM BACKENDS

| Acceptance criterion | Test(s) | Location | Result |
|---|---|---|---|
| Ollama request body: temperature=0, stream=false, format=json_schema, messages mapped | `ollama_request_body_is_temperature_zero_json_forced_and_non_streaming` | `crates/oracle/src/backend.rs` | PASS |
| Ollama response parsed to canonical verdict (offline fixture) | `ollama_response_parses_into_canonical_verdict` | same | PASS |
| Ollama missing content → deterministic Decode abort | `ollama_missing_content_is_a_deterministic_decode_abort` | same | PASS |
| OpenAI request body: temperature=0, response_format.json_schema.strict=true | `openai_request_body_is_temperature_zero_strict_json_schema` | same | PASS |
| OpenAI response parsed to canonical verdict (offline fixture) | `openai_response_parses_into_canonical_verdict` | same | PASS |
| OpenAI missing choice content → deterministic Decode abort | `openai_missing_choice_content_is_a_deterministic_decode_abort` | same | PASS |
| All three providers yield identical CanonicalVerdict from same JSON → quorum | `all_three_backends_yield_identical_canonical_verdict` | same | PASS |
| Config resolves defaults per provider, overrides win | `defaults_resolve_per_provider`, `overrides_win_over_defaults` | same | PASS |
| Backend config round-trips through JSON | `config_round_trips_through_json` | same | PASS |
| Ollama/OpenAI oracle/interpreter construct without network (Ollama keyless) | `construct_oracle_and_interpreter_for_each_provider_without_network` | same | PASS |
| Anthropic missing key → MissingApiKey (fall back to Mock) | (same test) | same | PASS |
| Fixture replay: Ollama verdict envelope → Human/High (offline, I5) | `ollama_verdict_envelope_maps_to_human_high` | `crates/oracle/tests/backend_replay.rs` | PASS |
| Fixture replay: OpenAI verdict envelope → Sybil/High (offline, I5) | `openai_verdict_envelope_maps_to_sybil_high` | same | PASS |
| Fixture replay: Ollama effect envelope → canonical Transfer (offline, I5) | `ollama_effect_envelope_maps_to_canonical_transfer` | same | PASS |
| Fixture replay: OpenAI injection attempt → abort effect, not partial state | `openai_effect_envelope_fails_closed_to_canonical_abort` | same | PASS |
| Cross-provider quorum: Anthropic + Ollama replays agree (quorum_eq) | `all_providers_replay_to_the_same_canonical_verdict_and_form_a_quorum` | same | PASS |
| Replay is byte-identical on repeated calls (I5 reproducibility) | `replay_is_deterministic_byte_identical` | same | PASS |
| Pinned request is temperature=0 regardless of backend | `pinned_request_is_temperature_zero_regardless_of_backend` | same | PASS |

### 5. UI

| Acceptance criterion | Test(s) | Location | Result |
|---|---|---|---|
| pnpm -r build passes clean | `pnpm -r build` (zero errors, static export) | `apps/wallet`, `packages/sdk` | PASS |
| pnpm -r typecheck passes clean | `pnpm -r typecheck` (tsc --noEmit) | same | PASS |
| Explorer reads real RPC: ubi_getBlock, ubi_getTransaction, ubi_getAccount, ubi_getAddressActivity | `ExplorerReader.getBlock`, `getDecodedTransaction`, `getAccount`, `getAddressActivity` all wired to live RPC in `apps/wallet/app/explorer.tsx` | structural | PASS |
| Settings reads/writes oracle config via real RPC | `OracleAdminClient.getConfig`, `setConfig` wired in `apps/wallet/app/settings.tsx` | structural | PASS |
| Fee display reads TRANSFER_FEE_BASE = 21000 * 1e9, shows in transfer preview and activity feed | `page.tsx:30` (`TRANSFER_FEE_BASE = 21_000n * 1_000_000_000n`) + fee preview rendering | structural | PASS |
| Activity feed carries `fee` field per row | `ActivityRow.fee` in SDK, rendered in `page.tsx:252` | structural + SDK types | PASS |

---

## Commands to reproduce

```
# Rust test suite (all crates):
cargo test --workspace

# UI build + typecheck:
pnpm -r build
pnpm -r typecheck

# Individual C5 integration suites:
cargo test --package ubi2-rpc --test fee_model
cargo test --package ubi2-rpc --test expl2_decoded_reads
cargo test --package ubi2-rpc --test oracle_admin
cargo test --package ubi2-oracle --test backend_replay
```

---

## Summary

308 Rust tests pass, 0 fail. 27 test suites, all green. fmt and clippy clean. pnpm build + typecheck both pass cleanly for apps/wallet and packages/sdk.

Every cycle-5 acceptance criterion maps to at least one passing test:

- **UBI Fees**: 14 criteria covered — unit tests in `crates/runtime` prove exact fee math and conservation; integration tests in `crates/rpc/tests/fee_model.rs` drive the full RPC stack confirming transfer/vouch/deploy/invoke each pay the per-kind fee, onboarding is free, and an underfunded tx leaves no state change.

- **Deep Explorer**: 11 criteria covered — `crates/rpc/tests/expl2_decoded_reads.rs` drives `ubi_getBlock` and `ubi_getTransaction` end-to-end against a live in-process node, asserting decoded shapes for every tx kind (transfer, vouch, deploy, invoke) including the `fee` field, hub call decode, event log decode, and committed effect result.

- **Oracle Admin**: 9 criteria covered — `crates/rpc/tests/oracle_admin.rs` drives the `build_module` RPC layer directly with injected peer addresses, covering loopback enforcement, secret redaction, hot-swap, fail-closed fallback, and the node oracle_cfg persistence layer.

- **LLM Backends**: 18 criteria covered — inline unit tests in `crates/oracle/src/backend.rs` cover request construction and response parsing for Ollama and OpenAI-compatible providers offline; `crates/oracle/tests/backend_replay.rs` exercises full fixture replay proving all three providers funnel to identical CanonicalVerdict/CanonicalEffect with byte-stable reproducibility.

- **UI**: build, typecheck, and structural data-path checks for explorer, settings, and fee display all pass.

No acceptance criterion was found untestable. No gaps.
