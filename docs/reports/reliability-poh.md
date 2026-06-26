# Reliability Gate Report — Proof-of-Humanity NFT (feat/poh-nft-branding)

**Branch:** feat/poh-nft-branding  
**Commit:** 2bee8d2  
**Gate:** GATE 2 — Reliability  
**Verdict:** PASS

---

## Scope

The POH NFT feature adds a soulbound ERC-721 "Proof of Humanity" collection answered by the
HumanityHub (`0x…5048`). The three gate properties are:

- **(a) DETERMINISM** — `tokenURI` / the card is a pure function of `(human state)`: identical
  bytes across two nodes for the same state; no floats, wall-clock, HashMap-order in the card or
  ownership path.
- **(b) OWNERSHIP CONSISTENCY** — the `Transfer` mint/burn log stream is a faithful transcript:
  token exists IFF `status == Verified`; every `Verified<->not-Verified` crossing emits exactly one
  `Transfer`; no double-mint or double-burn.
- **(c) LOG/STATE AGREEMENT** — `balanceOf`/`ownerOf` agree with the log stream and with
  `ubi_getHuman.status` across random lifecycle sequences.

---

## Files Audited

- `crates/rpc/src/poh_nft.rs` — ABI surface, tokenId scheme, card rendering
- `crates/rpc/src/lib.rs` — `poh_nft_call` dispatcher, `humanity_status_logs`, mint/burn log builders, `SubmitVerdict`/`Challenge`/`sweep_finalize` paths
- `crates/runtime/src/lifecycle.rs` — `challenge`, `submit_verdict`, `revoke` state machine
- `crates/runtime/src/humanity.rs` — `HumanStatus`, `CanonicalVerdict`, `quorum_tally`
- `crates/rpc/tests/poh_nft.rs` — existing integration tests
- `crates/runtime/tests/m3_reliability.rs` — existing runtime reliability tests

---

## How Properties Were Verified

### (a) Determinism

**Code audit findings:**

1. `render_token_uri` / `render_svg` are pure string-template functions. No `std::time`, no
   `rand`, no floats, no `HashMap` iteration. All date arithmetic uses Howard Hinnant's civil-date
   algorithm (`civil_from_days`), which is pure integer division on the day-count.

2. The card's gradient and fingerprint path are compile-time string constants (`FINGERPRINT_PATH`,
   colour literals). They cannot differ between calls or nodes.

3. `token_id_of` / `addr_of_token_id` are pure big-endian byte casts with a 160-bit mask check.
   No nondeterminism.

4. ABI selectors are derived by `alloy_sol_types::sol!` at compile-time from keccak4 of the
   Solidity signatures; they are stable across compilations (verified by D5 test).

5. The `poh_nft_call` dispatcher reads only `chain.get_human()`, which is a pure state read
   (Mutex-guarded `MemState::get_human`). No wall-clock call on the dispatch path.

**Property tests added (`c_poh_reliability.rs`):**

| Test | Coverage | Iterations |
|------|----------|-----------|
| `d1_token_uri_deterministic_same_state` | Two independent calls with identical inputs produce identical bytes | 5 000 |
| `d2_token_uri_sensitive_to_all_inputs` | Every field (addr/verified_at/vouches/reputation) changes the output | 1 000 |
| `d3_token_uri_structure_and_brand` | Data-URI structure, JSON, SVG brand strings, gradient stops, no floats | 1 |
| `d4_token_id_address_roundtrip_injective` | Round-trip over random addrs; 160-bit mask; injectivity | 10 000 |
| `d5_abi_selectors_match_keccak` | All six view selectors match keccak4 of canonical Solidity sigs | 6 asserts |
| `d5b_interface_ids_are_standard` | ERC-165/721/721-Metadata constants match published values | 3 asserts |
| `d6_name_symbol_constants_stable` | POH_NAME / POH_SYMBOL appear verbatim in tokenURI JSON | 1 |

All determinism tests pass. No floats, wall-clock, HashMap iteration, or unpinned randomness
found on any path that touches `tokenURI`, `balanceOf`, `ownerOf`, or `supportsInterface`.

---

### (b) Ownership Consistency

**Code audit findings — `humanity_status_logs` (lib.rs:649-663):**

The function takes `prev: Option<HumanStatus>` and `next: HumanStatus` and applies:

```rust
let was_verified = prev == Some(HumanStatus::Verified);
let is_verified  = status == HumanStatus::Verified;
if is_verified && !was_verified  { emit mint }
else if was_verified && !is_verified { emit burn }
```

This predicate is sound for all lifecycle transitions:

| Transition | was_verified | is_verified | Transfer |
|------------|-------------|-------------|----------|
| None → Pending | false | false | none |
| Pending → Verified | false | true | **mint** |
| Verified → Challenged | true | false | **burn** |
| **Challenged → Revoked** | **false** | **false** | **none** (no double-burn) |
| Challenged → Verified | false | true | **mint** (re-mint) |
| Pending → Revoked | false | false | none (never minted) |
| Verified → Revoked | true | false | **burn** |

**Critical path — `PendingKind::Challenge` (lib.rs:1239-1247):**

The `prev` passed to `humanity_status_logs` is hardcoded as `Some(HumanStatus::Verified)`.
This is only reached when `h.status == HumanStatus::Challenged` after the challenge is applied —
and the lifecycle only flips `Pending` subjects to `Challenged` if their pre-challenge status
was `Verified` (see `lifecycle.rs:379`). A `Pending` subject stays `Pending` when challenged;
the `h.status == HumanStatus::Challenged` guard prevents a spurious burn.

**Critical path — `PendingKind::SubmitVerdict` (lib.rs:1251-1286):**

`pre_status` is snapshotted from the current human record *before* `submit_verdict` mutates
state. When `Challenged → Revoked`, `pre_status = Some(Challenged)`. The `humanity_status_logs`
call receives `(subj, Some(Challenged), Revoked)` → `was_verified = false` → **no second burn**.
This is the critical Challenged→Revoked path the gate specifically asks about.

**Critical path — `sweep_finalize` (lib.rs:775-785):**

For `Pending → Verified`, `prev` is always `Some(HumanStatus::Pending)`. No duplicate mint
can arise because finalization is guarded by `has_pending_or_upheld_challenge` and the subject
must currently be `Pending` to reach this path.

**Property tests added (`c_poh_reliability.rs`):**

| Test | Coverage |
|------|----------|
| `o1_token_exists_iff_verified` | All 5 statuses × all source states; predicate correctness exhaustive |
| `o2_transfer_events_for_lifecycle_crossings` | 8 named lifecycle crossings; mint/burn counts |
| `o3_no_double_mint_no_double_burn_property` | 10 000 random sequences; index_balance ∈ {0,1} always |
| `o4_challenged_to_revoked_no_double_burn` | Explicit regression guard for the double-burn path |
| `o5_indexer_replay_reconstructs_ownership_full_sequence` | Full lifecycle sequence incl. re-registration |

All ownership consistency tests pass. No double-mint or double-burn path was found.

---

### (c) Log/State Agreement

**Code audit:**

`poh_nft_call` for `balanceOf` (lib.rs:2300-2308) reads `chain.get_human(&addr).map(|h| h.status == Verified)` — the same state that `ubi_getHuman` reads. There is no separate token ownership cache; the token-existence predicate is computed live from human status on every call. This structurally guarantees agreement between `balanceOf`, `ownerOf`, `tokenURI`, and `ubi_getHuman.status`.

**Property tests added (`c_poh_reliability.rs`):**

| Test | Coverage |
|------|----------|
| `c1_balance_of_agrees_with_status` | All 5 statuses; balance 1 iff Verified |
| `c2_owner_of_agrees_with_status` | tokenId roundtrip; revert for non-Verified |
| `c3_balance_of_consistent_with_status_random_sequences` | 10 000 random sequences |
| `c4_token_uri_only_for_verified` | tokenURI gate condition |
| `c5_two_node_identical_bytes` | Cross-node reproduction: 2 000 random states |

All log/state agreement tests pass.

---

## Test Results

```
crates/rpc/tests/c_poh_reliability.rs — 17 tests — 17 passed, 0 failed
crates/rpc/tests/poh_nft.rs           —  4 tests —  4 passed, 0 failed
crates/runtime/tests/m3_reliability.rs — 11 tests — 11 passed, 0 failed
crates/runtime/tests/m3_humanity.rs   — 15 tests — 15 passed, 0 failed
All other rpc/runtime suites          — green (no regressions)
```

Pre-existing baseline: 388 cargo tests, all green before and after.

---

## Findings

### PASS — No Consistency Violations Found

No divergence, double-mint, double-burn, nondeterminism source, or log/state disagreement was
found after static analysis and property testing.

### Observability Note (INFO)

The `StatusChanged` logs and ERC-721 `Transfer` mint/burn logs are emitted in receipts and
carried by the synthetic `humanity-finalize-sweep` system tx. An indexer can reconstruct full
ownership history from Transfer logs alone. No additional observability gap for the NFT path.

### Confirmed: Challenged→Revoked does NOT double-burn (O4)

The pre-snapshot `prev = Some(Challenged)` correctly suppresses the second burn in the
`SubmitVerdict` Sybil path. Regression test `o4_challenged_to_revoked_no_double_burn` guards
this explicitly.

### Confirmed: Pending→Challenged does NOT emit a burn (Challenge on non-Verified subject)

The `PendingKind::Challenge` log path gates on `h.status == HumanStatus::Challenged` before
emitting any `humanity_status_logs` with `prev=Some(Verified)`. A Pending subject's status
stays Pending after a challenge is opened (lifecycle.rs:379) — the guard fires and no burn
is emitted. Correct.

### Confirmed: No floats, wall-clock, HashMap iteration in the POH consensus path

`render_token_uri` / `render_svg` / `civil_from_days` / `token_id_of` / `addr_of_token_id` /
`poh_nft_call` are all pure integer or byte-slice operations. The Rust type system enforces this
statically; the D1–D6 property tests confirm no rounding divergence over 5 000–10 000 inputs.

---

## Verdict: PASS

Determinism and ownership/log consistency are demonstrated. No consistency violation was found.
