# Reliability report — M1 (board task M1-T8, GATE 2)

**Gate:** reliability-engineer (Definition-of-Done GATE 2)
**Scope:** invariant **I2** — determinism / reproducibility of time-based balances.
**Date:** 2026-06-21
**Verdict:** **PASS** — determinism and balance reproducibility are demonstrated; no cross-node
consistency violation found. One bounded, value-safe rounding behavior was discovered, characterized,
locked behind tests, and recorded as follow-up F1 (does **not** break I2; does **not** block M1).

---

## 1. What was proved

### Determinism / reproducibility (invariant I2)
`balance(account, t)` and emission/settlement are exact **integer** functions of `(state, t)`. Proved by
property tests over randomized timelines (deterministic SplitMix64 PRNG, fixed seeds, no external crate,
no network — also satisfies I5 "determinism is testable offline"). New suite:
`crates/runtime/tests/i2_determinism.rs`.

| Prop | Property | Coverage | Result |
|------|----------|----------|--------|
| P1/P6 | Two independent computations of the same `(verified_at, now)` agree to the base unit, and match an independent reference impl of `UBI*elapsed/3600` | 50,000 random timelines, `verified_at`/`now` up to ~100 years | PASS |
| P2a | Intermediate settlement: discrepancy vs. a straight-shot read is **bounded (≤1 base unit per settle)** and **one-directional (always a loss, never creates UBI)** | 20,000 timelines × ≤8 settle points | PASS |
| P2b | Settlement is **exactly** path-independent when settle points are hour-aligned (exact division) | 20,000 hour-aligned ladders | PASS |
| P3 | Balance reads are exactly monotonic non-decreasing in `now` (a polling wallet never sees it go backwards) | 5,000 timelines × 64 samples | PASS |
| P4 | A transfer to an unverified recipient conserves value exactly: `dev_post + rcpt_post == dev_pre` | 20,000 random `(verified_at, t, value)` | PASS |
| P5 | Replaying the same op-sequence + timestamps on two independently-built states yields byte-identical account state and balances (consensus effect is a pure function of the op log) | 2,000 random op logs (≤12 ops) | PASS |

Plus the 12 pre-existing runtime unit tests and 6 rpc lib unit tests, all green.

### Live liveness / soak (single-node devnet, `127.0.0.1:28545`, 1s tick)
- `eth_chainId = 0x5542`, `net_version = 21826` — correct.
- Block height ticks **steadily and strictly increasing** over the run (observed 17 → 43).
- Dev-account balance is **strictly monotonic** over ~10s, accruing ≈ `10^18/3600` wei/s — exactly the
  1 UBI/hour stream.
- **Signed transfer end-to-end:** an EIP-155 legacy tx signed with the public dev key was accepted by
  `eth_sendRawTransaction`, mined (receipt `status=0x1`), recipient received the value **to the base
  unit**, dev nonce incremented `0→1`.
- **Settlement did not lose emission:** after the transfer the dev account **kept streaming** (balance
  continued rising), while the **unverified recipient stayed frozen** at exactly the received amount (no
  spurious emission). Conservation held.

## 2. Hidden-nondeterminism hunt — findings

| Area | Result |
|------|--------|
| **Floats in the balance/consensus path** | **None.** The only `f64` in the tree is `json!(0.0)` for `gasUsedRatio` in `eth_feeHistory` (`crates/rpc/src/lib.rs`) — RPC-cosmetic, never touches balances or committed state. All emission/transfer math is `u128`. |
| **HashMap iteration-order dependence** | **None consensus-affecting.** The only order-sensitive call, `State::accounts()` (iterates a `HashMap`), has **zero callers** in the balance/consensus path and is already documented "order unspecified; callers must not depend on it." Block production iterates the mempool (`Vec`, FIFO) and `block.txs` (`Vec`) — both order-stable. |
| **Time / locale assumptions** | None. Time is unix seconds (`u64`); no locale, no string-cased comparisons, no wall-clock-dependent branching in the runtime. `now` is injected into every runtime fn, so the runtime itself is clock-agnostic and fully testable. |
| **Randomness / unpinned seed** | None in the runtime (M1 has no AI layer yet; I1 is out of M1 scope). |

## 3. Finding F1 — settlement is not *strictly* path-independent (bounded, value-safe)

**What:** Settling emission at non-hour-aligned timestamps can differ from a single straight-shot
balance read by up to **1 base unit (1 attowei = 1e-18 UBI) per settlement event**, and the difference
is **always a loss to the holder, never a gain**.

**Root cause:** `UBI = 10^18` is **not divisible** by `EMISSION_PERIOD_SECS = 3600`
(`10^18 % 3600 = 2800`). `Account::pending_emission` uses truncating division `UBI*elapsed/3600`; each
settle truncates the sub-unit remainder independently, and those dropped remainders do **not** carry
forward. Reproduction (from the failing initial run of P2):

```
verified_at = 0, read at t = 3_161_143_493 s
straight-shot balance  = 878095414722222222222222
settle once at t=1s,
  then read at t        = 878095414722222222222221   (delta = -1 attowei)
```

**Why this does NOT break I2 and does NOT block M1:**
- **No cross-node divergence.** Two nodes applying the *same ordered op-sequence at the same
  timestamps* settle at the *same points* and reach **byte-identical state** (proved by P5). I2's hard
  requirement — "two nodes computing a balance at the same height/timestamp agree to the smallest
  unit" — holds, because `last_settled_at`/`settled_balance` are part of the height.
- **Value-safe direction.** The effect is a monotone *loss* of at most 1 attowei per settle; UBI is
  **never created**, so there is no inflation / double-spend vector. This is the safe rounding
  direction for a token.
- **Negligible magnitude** (1e-18 UBI per settle) and deterministic.

The original unit test `settle_is_idempotent_in_total` only used **hour-aligned** settle points (3h, 7h)
where division is exact, so it never exercised this case. The new P2a/P2b lock in the *actual*
guarantee (bounded one-directional loss in general; exact when hour-aligned).

**Follow-up (post-M1, an ADR-worthy decision):** decide the canonical rounding policy before
account-to-account streams (M2) and demurrage (M5) multiply settlement frequency. Options:
(a) accept the bounded loss and document it as the spec's rounding rule; (b) carry the sub-unit
remainder in `Account` (e.g. an accumulated-remainder field) so settlement becomes exactly
path-independent; (c) redefine the rate so the period divides `UBI`. Recommend (b) if exact
conservation is ever required at the protocol level; (a) is acceptable for M1.

## 4. Out-of-scope reliability gaps (recorded, not failed — per M1 spec §"Out of scope")

These are genuinely deferred by the M1 spec and are **not** counted against this gate:

- **No persistence / restart-from-checkpoint.** State is in-memory (`MemState`); a restart loses all
  state and `verified_at` resets to the new genesis time. The spec calls a checkpoint "optional for
  M1." Acceptance criterion 5's "across a restart" clause cannot be exercised against a live process
  until a checkpoint exists — the *reproducibility* it asserts is instead proved at the function level
  by P1/P5 (same `(verified_at,t)` ⇒ same balance, deterministically). **Follow-up:** add the optional
  JSON/bincode checkpoint behind the `State` trait and a process-restart reproducibility test.
- **Single-node only — no multi-node consensus, no quorum (I1).** M1 is single-node by design; I1's
  interpreter/verifier quorum and deterministic-abort path do not exist yet. Cross-node agreement is
  therefore proved structurally (pure-function determinism, P1/P5) rather than by running two nodes.
  **Follow-up:** revisit at M3 when the AI layer lands.
- **Mempool ordering is FIFO only** (spec-acknowledged); no fairness/ordering guarantees beyond that.
- **Observability is light:** `tracing` logs exist (block produced, dropped tx) but there are no
  metrics/counters (blocks, mempool depth, dropped-tx count) or balance/settlement traces. Adequate for
  a single-node devnet; **follow-up:** add counters before multi-node.
- **Concurrent-load / RPC stress** not exercised here (single-`Mutex` state; correctness is serialized
  by the lock). **Follow-up:** add a concurrent-RPC soak when load matters.

## 5. Cross-gate note (not this gate's verdict)

`crates/rpc/tests/m1_acceptance.rs` (the QA gate's M1-T7 acceptance suite — new, uncommitted, with a
just-added `k256` dev-dependency) currently **does not compile**: it calls the async `rpc()` helper as
if synchronous (`rpc(...)["result"]` on an `impl Future`, ~23 errors). This blocks
`cargo test --workspace`. It is **out of scope for M1-T8 (I2)** and owned by the qa gate; flagging it so
it isn't mistaken for a reliability regression. All in-scope crates build and test cleanly in isolation.

## 6. How to reproduce

```sh
# Property tests (I2 determinism suite) — the core of this gate:
cargo test -p ubi2-runtime --test i2_determinism

# Full in-scope unit tests:
cargo test -p ubi2-runtime
cargo test -p ubi2-rpc --lib

# Live soak (separate terminal), on the gate-2 port to avoid collisions:
UBI2_RPC_ADDR=127.0.0.1:28545 UBI2_BLOCK_MS=1000 cargo run -p ubi2-node
#   then poll eth_blockNumber / eth_getBalance and submit an EIP-155 signed transfer.
```

### Test output summary
```
ubi2-runtime  i2_determinism : 6 passed; 0 failed
ubi2-runtime  lib            : 12 passed; 0 failed
ubi2-rpc      lib            : 6 passed; 0 failed
live soak     blocks tick + balance monotonic over 10s; signed transfer settled
              (recipient exact to base unit, dev keeps streaming, conservation holds)
```
