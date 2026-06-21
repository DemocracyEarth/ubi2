# Reliability report — M2 streaming (board task M2-T6, GATE 2)

**Gate:** reliability-engineer (Definition-of-Done GATE 2)
**Scope:** invariant **I2** for the M2 streaming primitive — determinism / reproducibility of stream
balances, solvency-by-construction, bounded conservation, and `tokenURI` rendering determinism.
**Date:** 2026-06-21
**Verdict:** **PASS** — determinism, solvency, and bounded conservation are demonstrated across random
`(rate, deposit, started_at, now, stop?)` including the documented extremes; `tokenURI` is byte-identical
across calls and instances; no cross-node consistency violation found. The single bounded, value-safe
rounding behavior (ADR-0002) is asserted as a bound, not failed. One non-solvency-affecting code
observation (`t_end()` u64 truncation) is recorded as a follow-up. Out-of-scope items (multi-node,
persistence) are deferred per spec, **not** counted against this gate.

---

## 1. What was proved

All stream balance math is integer (`u128`/`u64`); the only `f64` in the tree is `json!(0.0)` for
`gasUsedRatio` in `eth_feeHistory` (`crates/rpc/src/lib.rs`) — RPC-cosmetic, never touches balances or
the SVG/JSON card. The card number/date formatters (`fmt_ubi`, `fmt_rate_per_hour`, `pct`, the
progress-bar width, `fmt_ts`/`civil_from_days`) are all integer math — **no floats in the card
formatting** (a specific concern of this task; confirmed by grep and by property test T3 below).

### New property suites (deterministic SplitMix64 PRNG, fixed seeds, no network — also satisfies I5)

`crates/runtime/tests/m2_stream_consistency.rs` — stream balance / `accrued()` consistency:

| ID | Property | Coverage | Result |
|----|----------|----------|--------|
| S1 | `Stream::accrued(now)` is a pure integer function of `(stream, now)`: two independently-built identical streams agree to the base unit | 200,000 random streams | PASS |
| S2 | **Solvency:** `accrued(now) ≤ deposit` for **every** input, incl. `now == u64::MAX`, `rate == MAX_RATE`, deposit up to ~1e9 UBI, `started_at` extremes — no over-draw, no panic/overflow (debug overflow checks on) | 200,000 random + named boundary cases | PASS |
| S3 | `accrued` is monotonic non-decreasing in `now`, exactly flat once `now ≥ end_or_stop` | 200,000 random (later-read sample each) | PASS |
| S4 | A `Stopped(at)` stream freezes accrual at the stop instant: `accrued(t) == accrued(stop)` ∀ `t ≥ stop`, capped at deposit | 50,000 × 6 future reads | PASS |
| S5 | **Conservation (ADR-0002 bound):** `open→[stop]→read` total `≤ baseline` always (UBI never created), and `baseline − total ≤ 4` base units (one-directional loss) | 30,000 random lifecycles, incl. `u64::MAX` reads | PASS |
| S6 | **Cross-node reproducibility:** two independently-built `MemState`s replaying the same op-sequence agree on both balances, the refund, **and the full stream record** | 30,000 random | PASS |

`crates/rpc/tests/m2_tokenuri_determinism.rs` — `tokenURI`/SVG rendering determinism:

| ID | Property | Coverage | Result |
|----|----------|----------|--------|
| T1 | `render_token_uri` is **byte-identical across repeated calls** at a fixed `now` (no map-order/locale/float jitter) | 20,000 random streams, both sides | PASS |
| T2 | `render_token_uri` is **byte-identical across two independently-constructed `CardData`** instances (the "two nodes" check), incl. `now == u64::MAX` | 20,000 random | PASS |
| T3 | Card formatters are pure integer functions: identical inputs ⇒ identical strings, exactly 2 decimals, **no float artifacts** (`e`/`E`/`NaN`/`inf` never appear), match an independent integer reference | 100,000 random amounts + named edges (incl. `u128::MAX`) | PASS |
| T4 | The decoded inline SVG is well-formed (`<svg…</svg>`) for the whole corpus | 20,000 random | PASS |

Plus all pre-existing tests stay green (see §5). The in-crate
`property_streams_solvent_conserved_reproducible` (20k iters) is retained and complemented — the new
suites widen coverage to the documented extremes (`u64::MAX`, `MAX_RATE`, multi-magnitude deposits) and
add the `accrued`/`tokenURI`-level purity checks it didn't cover.

### Determinism / solvency / conservation — the four required properties

- **Determinism/reproducibility (I2):** S1/S6 + T1/T2 — stream balances, `accrued()`, the refund, the
  full stream record, and the rendered `tokenURI` are all exact functions of `(state/inputs, now)`; two
  independent computations agree to the base unit / byte. No nondeterminism (no float, no map-order, no
  locale/time branching) in the stream balance or card-rendering path.
- **Solvency invariant:** S2 (200k random incl. `now=u64::MAX`, rate/deposit extremes) + named boundary
  cases — `accrued(now) ≤ deposit` always; the `.min(deposit)` cap in `Stream::accrued` is the
  load-bearing guard, so over-draw is impossible regardless of horizon arithmetic. No panic/overflow.
- **Conservation:** S5 — `open→accrue→stop` refund conserves value with `total ≤ baseline` always
  (UBI is never created) and a bounded one-directional loss `≤ 4` base units per lifecycle, exactly the
  ADR-0002 settlement-rounding bound. Asserted as a bound, not strict equality off hour-boundaries.
- **tokenURI determinism:** T1/T2/T3 — byte-identical across calls and instances; no floats in the card
  number formatting.

### Live soak / liveness (single-node devnet, `127.0.0.1:28545`, 1s block tick)

Booted the real node (`UBI2_RPC_ADDR=127.0.0.1:28545 UBI2_BLOCK_MS=1000`), signed an `openStream`
dev→recipient (rate = 1 base unit/sec, deposit = 4h = 14,400 units) with the public devnet key, mined it,
then polled for ~10s:

- `eth_chainId = 0x5542`, `net_version = 21826` — correct.
- `openStream` mined: receipt `status = 0x1`, **3 logs** (`StreamOpened` + 2 ERC-721 `Transfer` mints),
  `ubi_getStream(0)` → `Active`, rate `0x1`, deposit `0x3840`.
- **Recipient balance strictly monotonic**, climbing exactly **+1 base unit/sec** (1 → 11 over 10s) —
  matches the configured rate to the base unit.
- **Block height strictly advancing** 14 → 24 (steady 1s ticks).
- **Live solvency:** recipient balance stayed `≤ deposit` (14,400) at every sample.
- Node killed cleanly after the run (`pkill -f 'target/.*ubi2-node'`).

## 2. Hidden-nondeterminism hunt (streaming surface) — findings

| Area | Result |
|------|--------|
| **Floats in stream balance / card path** | **None.** `Stream::accrued`/`t_end`/`end_or_stop`, the net-stream `State::balance`, and every card formatter (`fmt_ubi`, `fmt_rate_per_hour`, `pct`, bar width, `fmt_ts`, `civil_from_days`) are integer-only. The lone `f64` (`gasUsedRatio` `0.0`) is RPC-cosmetic. Verified by grep + property tests T3 (100k amounts: no `e`/`NaN`/`inf`, exact integer reference match). |
| **Map-iteration / locale order in `tokenURI`** | **None.** The JSON is hand-built with a fixed field order; `attributes` is a fixed array; the SVG is a fixed string template. T1/T2 prove 40,000 renders are byte-identical across calls and independent instances. |
| **Stream-op consensus path** | Block production iterates the mempool (`Vec`, FIFO) and `block.txs` (`Vec`) — order-stable. `MemState`'s per-account `incoming`/`outgoing` indexes are `Vec`s appended in open-order; `State::balance` *sums* incoming accrual (order-independent). No HashMap iteration in the balance path. |
| **Overflow / panic on extremes** | None observed across 200k random `accrued` reads at `now=u64::MAX`, `rate=MAX_RATE`, near-`u128::MAX` deposits, with debug overflow checks on. Saturating math throughout; the `.min(deposit)` cap bounds the result. |

## 3. Finding F2 — `Stream::t_end()` truncates `deposit/rate` via `as u64` (non-solvency-affecting)

**What:** `t_end()` computes `whole = deposit.checked_div(rate)` (a `u128`) then casts `whole as u64`.
For pathological inputs where `deposit/rate` exceeds `u64::MAX` (e.g. a `u128::MAX` deposit at a small
rate), the cast **truncates** (wraps) rather than saturating, so the reported `t_end` / accrual horizon is
a wrapped value rather than `u64::MAX`.

**Why it does NOT break solvency or I2:**
- **Solvency is enforced by the `.min(self.deposit)` cap in `accrued`, not by `t_end`.** The code comment
  on `t_end` already states "the cap, not this bound, is load-bearing for solvency." S2 confirms it:
  across 200k random inputs including this regime, `accrued(now) ≤ deposit` holds with zero violations.
- **Deterministic.** The truncation is a pure integer function, so two nodes compute the identical
  (wrapped) `t_end` and identical `accrued` — no cross-node divergence.
- **Unreachable in practice.** `deposit/rate > u64::MAX` requires a deposit far beyond any fundable
  balance (the protocol supply is ≪ `u128::MAX`) combined with a tiny rate; `MAX_RATE` and balance
  limits keep real streams many orders of magnitude away.

**Follow-up (cosmetic, low priority):** make `t_end` use `saturating` instead of `as u64`
(`u64::try_from(whole).unwrap_or(u64::MAX)`) so the reported horizon and the `StreamView.t_end` / card
"Ends" field are correct at the extreme. No state/consensus impact; purely the displayed end instant for
an unreachable input. Recorded here; does not block M2.

## 4. Out-of-scope reliability gaps (recorded, not failed — per M2 spec & board FU-4)

Genuinely deferred by the M2 spec; **not** counted against this gate:

- **Multi-node consensus / quorum (I1).** M2 is single-node, in-memory **by design** (spec §"Deferred":
  "Multi-node consensus arrives with M3"). Cross-node agreement is therefore proved *structurally* —
  pure-function determinism, S1/S6 + T1/T2 (independent recomputation agrees to the base unit / byte) —
  rather than by running two live nodes. **Follow-up FU-4:** two-node soak once the M3 quorum exists.
- **Persistence / restart-from-checkpoint.** State is `MemState` (in-memory); a restart loses streams and
  re-seeds `verified_at` to the new genesis. The `State` trait is persistence-swappable, so the
  reproducibility a restart would assert is proved at the function level (same op-sequence ⇒ identical
  state/record, S6). **Follow-up:** add a checkpoint behind `State` + a process-restart reproducibility
  test before persistence matters.
- **Observability** is light: `tracing` logs (block produced, dropped tx) but no metrics/counters
  (mempool depth, dropped-tx count, stream count). Adequate for a single-node devnet. **Follow-up FU-4:**
  add counters before multi-node.
- **Concurrent-load / RPC stress** not exercised (single-`Mutex` state serializes correctness).
  **Follow-up:** concurrent-RPC soak when load matters.

## 5. How to reproduce

```sh
# New stream-consistency + tokenURI-determinism property suites (the core of this gate):
cargo test -p ubi2-runtime --test m2_stream_consistency
cargo test -p ubi2-rpc     --test m2_tokenuri_determinism

# Full workspace (all suites green):
cargo test --workspace

# Live soak (separate terminal, gate-2 port to avoid collisions):
pkill -f 'target/.*ubi2-node'
UBI2_RPC_ADDR=127.0.0.1:28545 UBI2_BLOCK_MS=1000 cargo run -p ubi2-node
#   then sign+send an openStream to 0x…5742, poll eth_getBalance(recipient) (climbs at rate)
#   and eth_blockNumber (ticks); kill the node after.
```

### Test output summary
```
ubi2-runtime  m2_stream_consistency   : 4 passed; 0 failed   (S1–S6 + boundary, ~480k iters total)
ubi2-rpc      m2_tokenuri_determinism : 3 passed; 0 failed   (T1–T4, ~160k iters total)
ubi2-runtime  lib                     : 22 passed; 0 failed
ubi2-runtime  i2_determinism          : 6 passed; 0 failed
ubi2-rpc      lib (incl. streams)     : 13 passed; 0 failed
ubi2-rpc      m1_acceptance           : 3 passed; 0 failed
ubi2-rpc      m2_acceptance           : 4 passed; 0 failed
live soak     openStream mined (status 0x1, 3 logs); recipient balance strictly monotonic +1/s
              (1→11 over 10s); blocks tick 14→24; balance ≤ deposit at all samples
fmt + clippy  clean (workspace, incl. the two new test files)
```
