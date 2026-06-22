# QA Report — M3 AI Proof-of-Humanity

**Gate:** QA (board M3-T6)
**Branch:** m3-proof-of-humanity
**Commit:** bd669d2
**Date:** 2026-06-22
**Verdict:** PASS

---

## Scope

This report maps every acceptance criterion from `docs/specs/03-proof-of-humanity.md` §"Acceptance criteria" to one or more passing tests, and documents the evidence. All tests use the `MockOracle` (no live model calls, invariant I5). Invariants I1, I2, I4, I6 are verified both at the runtime layer and the RPC/wire layer.

---

## Acceptance Criteria Coverage

### AC1 — Unverified → Pending → Verified, then balance streams

**Criterion:** A new account goes `Unverified → Pending → Verified` only after liveness-pass + ≥MIN_VOUCHES + a clean challenge window, and only then does its balance start streaming.

**Tests:**
- `crates/runtime/tests/m3_humanity.rs::happy_path_unverified_to_verified_then_streams` — full lifecycle in-memory: requestVerification → Pending, vouch×2, early finalize rejected (fail-closed), window clears → Verified, 1 UBI/h from verified_at.
- `crates/runtime/tests/m3_humanity.rs::pending_account_does_not_stream` — balance is 0 no matter how far forward we read while Pending.
- `crates/rpc/tests/m3_acceptance.rs::unverified_to_verified_then_streams` — full lifecycle on the wire: RPC server on :18561, EIP-155 txs via eth_sendRawTransaction, auto-finalize sweep confirms Verified, eth_getBalance returns UBI.

**Evidence (from run):**
```
test happy_path_unverified_to_verified_then_streams ... ok
test pending_account_does_not_stream ... ok
test unverified_to_verified_then_streams ... ok
```

---

### AC2 — Sybil caught: challenge → quorum Sybil → Revoked, emission stopped, vouchers slashed

**Criterion:** A duplicate/sybil is caught: challenge → AI-jury quorum returns Sybil by ≥QUORUM → subject Revoked/rejected, UBI not granted (or stopped), vouchers' reputation slashed.

**Tests:**
- `crates/runtime/tests/m3_humanity.rs::sybil_challenge_revokes_and_slashes_vouchers` — full revoke path: Verified → Challenged → Revoked; voucher reputation slashed by SYBIL_SLASH; balance frozen.
- `crates/runtime/tests/m3_humanity.rs::sybil_applicant_never_finalizes` — a Pending applicant with an upheld Sybil challenge cannot finalize; UBI never granted.
- `crates/rpc/tests/m3_acceptance.rs::challenge_sybil_quorum_revokes_and_stops_emission` — full wire path: challenge tx, two juror Sybil verdicts by quorum, subject Revoked, verified_at cleared, balance frozen.

**Evidence:**
```
test sybil_challenge_revokes_and_slashes_vouchers ... ok
test sybil_applicant_never_finalizes ... ok
test challenge_sybil_quorum_revokes_and_stops_emission ... ok
```

---

### AC3 — Quorum determinism (I1): fixed evidence → same verdict; split → Escalate

**Criterion:** With fixed evidence + MockOracle, all honest jurors produce the same CanonicalVerdict; ≥QUORUM commits; a split deterministically Escalates — reproducible across two nodes.

**Tests:**
- `crates/runtime/tests/m3_humanity.rs::quorum_determinism_identical_verdicts_commit` — two independent MemState instances + same oracle on same evidence → byte-identical Committed(Sybil).
- `crates/runtime/tests/m3_humanity.rs::quorum_split_escalates` — three different verdicts → Escalated; subject stays Challenged (not Revoked, I4).
- `crates/runtime/tests/m3_humanity.rs::property_quorum_is_deterministic_across_nodes` — 5,000 randomised (jury size, entropy, verdict) iterations; two independent states always reach the same tally.
- `crates/oracle/tests/fixture_replay.rs::quorum_forms_when_independent_jurors_replay_same_effect` — three ClaudeOracle instances on recorded fixtures; j1 and j2 agree (quorum), j3 disagrees (uncertain); runtime tally commits correctly.
- `crates/oracle/tests/fixture_replay.rs::split_jury_escalates_deterministically` — three different fixture effects → Tally::Escalated.
- `crates/rpc/tests/m3_qa.rs::ac3_two_node_quorum_determinism` — two independently-booted Chain instances (separate RPC servers on :18546/:18547) receive the same op sequence; both case objects report identical Committed(Sybil) verdict via ubi_getCase.

**Evidence:**
```
test quorum_determinism_identical_verdicts_commit ... ok
test quorum_split_escalates ... ok
test property_quorum_is_deterministic_across_nodes ... ok
test quorum_forms_when_independent_jurors_replay_same_effect ... ok
test split_jury_escalates_deterministically ... ok
[ac3] node A verdict="Sybil" confidence="High", node B verdict="Sybil" confidence="High" — identical (I1)
[ac3] both nodes agree: subject Revoked. Two-node quorum determinism verified.
test ac3_two_node_quorum_determinism ... ok
```

---

### AC4 — Vouch constraints: only Verified vouchers; capacity; no self/duplicate vouch

**Criterion:** Only Verified vouchers; capacity (VOUCH_CAPACITY) enforced; no self/duplicate vouch.

**Tests:**
- `crates/runtime/tests/m3_humanity.rs::vouch_constraints_enforced` — Unverified voucher rejected (VoucherNotVerified), self-vouch rejected (SelfVouch), duplicate vouch rejected (DuplicateVouch).
- `crates/runtime/tests/m3_humanity.rs::vouch_capacity_enforced` — VOUCH_CAPACITY vouches succeed, the (capacity+1)-th fails (VouchCapacityReached).

**Evidence:**
```
test vouch_constraints_enforced ... ok
test vouch_capacity_enforced ... ok
```

---

### AC5 — Emission gating: accrues iff Verified; Revoke stops it; genesis dev account is Verified

**Criterion:** Emission accrues iff Verified; Revoke stops it to the base unit. The genesis dev account is migrated to Verified (devnet continuity).

**Tests:**
- `crates/runtime/tests/m3_humanity.rs::emission_gates_on_verified_and_revoke_stops` — seed_verified_human starts streaming; revoke() sets status=Revoked and balance drops to 0 at all future times.
- `crates/rpc/tests/m3_qa.rs::ac8_sdk_wallet_data_path` — genesis dev account (seeded Verified) shows balance >0 via eth_getBalance; confirmed 5×10^18 base units streaming.

**Evidence:**
```
test emission_gates_on_verified_and_revoke_stops ... ok
[ac8] genesis dev balance = 5000000000000000000 base units (streaming confirmed, AC5)
test ac8_sdk_wallet_data_path ... ok
```

---

### AC6 — AI sybil-cluster detection: synthetic vouch farm flagged and auto-challenged

**Criterion:** A synthetic vouch farm (improbable cluster) is flagged and auto-challenged.

**Tests:**
- `crates/runtime/tests/m3_humanity.rs::sybil_cluster_scan_auto_challenges` — MockOracle scripted Sybil for subject; analyze_sybil returns flag; challenge auto-filed; jury quorum Sybil → Revoked; finalize blocked.
- `crates/rpc/tests/m3_qa.rs::ac6_rpc_sybil_cluster_auto_challenge_and_revoke` — full wire path: oracle scripted Sybil for subject address; the node's watch-loop reads oracle.analyze_sybil(graph) → Sybil flag; challenge filed via eth_sendRawTransaction; case visible in ubi_getPendingCases; two juror Sybil verdicts by quorum → subject Revoked; balance permanently 0.

**Evidence:**
```
test sybil_cluster_scan_auto_challenges ... ok
[ac6] analyze_sybil flagged subject as Sybil (CanonicalVerdict { verdict: Sybil, ... })
[ac6] auto-challenge landed → case #1 opened
[ac6] case #1 is open and visible in ubi_getPendingCases
[ac6] Revoked: balance=0, UBI never granted
test ac6_rpc_sybil_cluster_auto_challenge_and_revoke ... ok
```

---

### AC7 — Privacy (I6): no PII/biometric on-chain; only commitments + canonical verdicts + reason hashes

**Criterion:** No PII or biometric on-chain; only commitments (liveness_ref, evidence_ref), canonical verdicts, and reason hashes.

**Tests:**
- `crates/runtime/tests/m3_humanity.rs::privacy_only_commitments_on_chain` — the Case struct has no field that can hold raw challenge/response bytes (structural type enforcement); liveness_ref is stored as the exact 32-byte commitment.
- `crates/rpc/tests/m3_qa.rs::ac7_rpc_no_pii_on_wire` — ubi_getHuman response has exactly the expected fields (address, status, verified_at, liveness_ref, vouches_in, reputation); no "challenge", "response", "transcript", "biometric", "raw" fields; liveness_ref is the exact 32-byte commitment hex; evidence_ref in ubi_getCase is exactly 32 bytes; no raw evidence fields in the case object.

**Evidence:**
```
test privacy_only_commitments_on_chain ... ok
[ac7] ubi_getHuman fields: ["address", "liveness_ref", "reputation", "status", "verified_at", "vouches_in"]
[ac7] ubi_getCase fields: ["evidence_ref", "id", "jury", "kind", "opened_at", "status", "subject", "votes"]
[ac7] privacy check passed: no PII fields on wire from ubi_* methods (I6)
test ac7_rpc_no_pii_on_wire ... ok
```

---

### AC8 — Wallet: apply→liveness→vouch→status flow; juror submits verdict; user challenges

**Criterion:** Apply→liveness→vouch→status flow works against the devnet; a juror can submit a verdict and a user can challenge another account.

**Tests:**
- `crates/rpc/tests/m3_qa.rs::ac8_sdk_wallet_data_path` — full SDK data path against a live in-process node on :18548:
  - `ubi_getHuman` returns correct HumanRecord shape (all fields match SDK TypeScript interface).
  - `ubi_getJurors` returns 3 jurors with address/stake/active fields (JurorRecord interface).
  - `ubi_getVouches` returns VouchSet with incoming/outgoing arrays.
  - `ubi_getPendingCases` returns array.
  - `requestVerification` tx → Pending status; receipt has CaseOpened log; `ubi_getCase` returns full CaseRecord with id/subject/kind/evidence_ref/jury/votes/status/opened_at.
  - `vouch×2` → ubi_getVouches.incoming.length = 2; vouches_in on ubi_getHuman updated.
  - `challenge(Verified target)` → target status = Challenged; receipt has CaseOpened log; challenge case in ubi_getPendingCases with correct CaseRecord shape.
  - Two juror Human verdicts → target restored to Verified; challenge case Committed(Human).
  - `eth_getBalance` for genesis dev account returns >0 (streaming confirmed, AC5).

**Evidence:**
```
[ac8] ubi_getHuman shape OK: status="Verified", verified_at=1782080148
[ac8] ubi_getJurors shape OK: 3 jurors
[ac8] ubi_getVouches shape OK: outgoing=0 incoming=0
[ac8] ubi_getPendingCases shape OK: 0 open cases at genesis
[ac8] requestVerification: subject is Pending
[ac8] requestVerification → reg case #0 opened (from receipt logs)
[ac8] ubi_getCase shape OK: case #0 (3 votes)
[ac8] ubi_getVouches: 2 incoming vouches for subject
[ac8] challenge submitted via wallet path, target status = Challenged
[ac8] challenge receipt: 2 log(s)
[ac8] ubi_getPendingCases: challenge case #1 found with correct shape
[ac8] after Human jury verdict: target restored to Verified
[ac8] all SDK/wallet data-path methods verified end-to-end
[ac8] genesis dev balance = 5000000000000000000 base units (streaming confirmed, AC5)
test ac8_sdk_wallet_data_path ... ok
```

---

## Additional Coverage

### Invariant I1 — Deterministic quorum (oracle layer)

- `crates/oracle/tests/fixture_replay.rs::replay_is_deterministic_byte_identical` — same input replays to byte-identical canonical effect (10 iterations).
- `crates/oracle/tests/fixture_replay.rs::pinned_request_is_temperature_zero_and_schema_constrained` — temperature=0.0, schema closed, evidence fenced as UNTRUSTED (injection resistance).
- `crates/oracle/tests/fixture_replay.rs::injection_attempt_is_graded_sybil_not_human` — prompt injection attempt → Sybil/High; injection is never rewarded.

### Invariant I4 — Fail closed

- `crates/runtime/tests/m3_humanity.rs::no_jurors_fails_closed` — requestVerification with no active jurors → NoJurors error.
- `crates/runtime/tests/m3_humanity.rs::submit_verdict_authorization` — non-juror → NotOnJury; double-vote → AlreadyVoted.
- `crates/runtime/tests/m3_humanity.rs::quorum_split_escalates` — three different verdicts → Escalated; subject not mutated.

### Tally + jury selection (unit layer)

- `crates/runtime/src/humanity.rs` (inline unit tests): `tally_commits_at_quorum`, `tally_pending_then_escalates_on_split`, `tally_uncertain_quorum_escalates`, `quorum_requires_matching_confidence`, `jury_selection_is_deterministic_and_sized`, `jury_selection_small_pool_returns_all`, `quorum_eq_ignores_reasons_hash`, `mock_oracle_is_scripted_and_deterministic`.

---

## Test Commands (reproduce)

```sh
# Full suite (all 18 suites, ~156 tests)
cargo test --workspace

# New QA gate tests only
cargo test --test m3_qa -p ubi2-rpc -- --nocapture

# M3 lifecycle runtime tests
cargo test --test m3_humanity -p ubi2-runtime -- --nocapture

# M3 acceptance RPC integration tests
cargo test --test m3_acceptance -p ubi2-rpc -- --nocapture

# Oracle fixture replay (I1/I5)
cargo test --test fixture_replay -p ubi2-oracle -- --nocapture
```

---

## Summary of New Tests Added

File: `crates/rpc/tests/m3_qa.rs`

| Test | Criterion | What it verifies |
|------|-----------|-----------------|
| `ac3_two_node_quorum_determinism` | AC3 | Two independently-booted RPC nodes reach identical Committed(Sybil) verdict on the same case (I1 at the wire level) |
| `ac6_rpc_sybil_cluster_auto_challenge_and_revoke` | AC6 | Oracle flags synthetic vouch farm; challenge filed via RPC; juror quorum Sybil; subject Revoked; balance=0 |
| `ac7_rpc_no_pii_on_wire` | AC7 | ubi_getHuman and ubi_getCase carry only commitment fields; no PII field names; evidence_ref is exactly 32 bytes |
| `ac8_sdk_wallet_data_path` | AC8, AC5 | All ubi_* methods match SDK TypeScript interface shapes; full apply→vouch→challenge→verdict flow end-to-end on a live node |

---

## Verdict

**PASS.** All 8 M3 acceptance criteria have at least one passing test. All 18 test suites (156 tests total) pass with zero failures. No acceptance criterion is untestable.
