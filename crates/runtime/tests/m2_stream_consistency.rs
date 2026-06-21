//! M2 stream consistency property tests (reliability gate, board task M2-T6, GATE 2).
//!
//! These strengthen the in-crate `property_streams_solvent_conserved_reproducible` test with the
//! consistency properties the reliability gate must prove for **streams** under invariant I2
//! (`docs/specs/00-overview.md`): stream balances and `accrued()` are exact integer functions of
//! `(state, now)` — two independent computations agree to the base unit, accrual is solvent by
//! construction for *all* inputs (including `now == u64::MAX` and rate/deposit extremes, with no
//! panic/overflow), and open→accrue→stop conserves value up to the documented ADR-0002 settlement
//! rounding bound (one-directional, ≤1 base unit per settle).
//!
//! Properties proved over randomized timelines (deterministic SplitMix64 PRNG — no external crate, no
//! network, satisfies I5 "determinism is testable offline"; fixed seeds ⇒ failures reproduce exactly):
//!   S1  `Stream::accrued(now)` is a pure integer function of `(stream, now)`: two independently-built
//!       identical streams agree to the base unit at the same `now`.
//!   S2  Solvency: `accrued(now) <= deposit` for **every** input, including `now == u64::MAX`, the
//!       max permitted `rate` (`MAX_RATE`), and deposit/started_at extremes — never over-draws, never
//!       panics or overflows (debug overflow checks are on under `cargo test`).
//!   S3  `accrued` is monotonic non-decreasing in `now` (a recipient's stream read never goes
//!       backwards) and exactly flat once `now >= end_or_stop`.
//!   S4  A stopped stream freezes accrual at the stop instant: `accrued(t) == accrued(stop)` for all
//!       `t >= stop`, capped at deposit.
//!   S5  End-to-end conservation of `open → [stop] → read` against the sender's pure-emission baseline
//!       holds with a *bounded, one-directional* loss (ADR-0002): `total <= baseline` always, and
//!       `baseline - total <= MAX_SETTLE_LOSS` — value is never created, lost at most a few base units.
//!   S6  Two independently-built `MemState`s replaying the same `open[/stop]` op-sequence agree on
//!       both balances, the refund, and the full stream record — the committed effect is a pure
//!       function of `(params, timestamps)` (cross-node agreement, the heart of I2).

use ubi2_runtime::{
    open_stream, stop_stream, Account, Address, MemState, State, Stream, StreamStatus, MAX_RATE,
    UBI,
};

/// Deterministic SplitMix64 — same seed ⇒ same sequence on every machine/run (reproducible failures).
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    /// Uniform-ish in `[0, n)` (n > 0).
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
    fn below_u128(&mut self, n: u128) -> u128 {
        let hi = (self.next_u64() as u128) << 64;
        (hi | self.next_u64() as u128) % n
    }
}

fn addr(b: u8) -> Address {
    [b; 20]
}

/// A bare `Stream` with the given fields (drawn=0, Active) — for accrual-only properties that don't
/// need a `State`.
fn mk_stream(rate: u128, deposit: u128, started_at: u64, status: StreamStatus) -> Stream {
    Stream {
        id: 0,
        from: addr(1),
        to: addr(2),
        rate,
        deposit,
        drawn: 0,
        started_at,
        status,
    }
}

/// Seed `addr` as a verified sender with `settled` UBI already settled at t=0 (affords any deposit).
fn seed_funded(state: &mut MemState, a: Address, settled: u128) {
    state.put(Account {
        address: a,
        verified: true,
        verified_at: 0,
        last_settled_at: 0,
        settled_balance: settled,
        nonce: 0,
    });
}

/// S1 + S2 + S3 — `accrued` is a pure, solvent, monotonic integer function of `(stream, now)`, proved
/// directly on `Stream` (no `State`) across the full input space *including the documented extremes*
/// (`now == u64::MAX`, `rate == MAX_RATE`, deposit/started_at extremes). Debug overflow checks are on
/// under `cargo test`, so any arithmetic overflow on a sampled input would panic the test.
#[test]
fn accrued_is_pure_solvent_monotonic_over_extremes() {
    let mut rng = Rng::new(0x5142_0001);
    for _ in 0..200_000 {
        // Cover the whole permitted rate range, biased to also hit the MAX_RATE boundary exactly.
        let rate = match rng.below(8) {
            0 => MAX_RATE,
            1 => 1,
            _ => 1 + rng.below_u128(MAX_RATE),
        };
        // Deposit up to ~1e9 UBI (far beyond any realistic stream) so `deposit / rate` and the cap are
        // exercised across many magnitudes; never 0 (open rejects it, accrual treats it as the cap).
        let deposit = 1 + rng.below_u128(1_000_000_000u128 * UBI);
        let started_at = rng.below(u64::MAX / 2);
        // `now` spans below started_at (clock skew → 0 accrual), within the stream, and the absolute
        // extreme `u64::MAX` (the worst case for `rate * elapsed` overflow before the cap clamps it).
        let now = match rng.below(6) {
            0 => u64::MAX,
            1 => started_at.saturating_sub(rng.below(10_000)),
            2 => started_at,
            _ => started_at.saturating_add(rng.below(u64::MAX / 4)),
        };

        let status = match rng.below(3) {
            0 => StreamStatus::Active,
            1 => StreamStatus::Stopped(started_at.saturating_add(rng.below(1_000_000_000))),
            _ => StreamStatus::Completed,
        };
        let s = mk_stream(rate, deposit, started_at, status);

        // S2 — solvency: never exceeds deposit, on any input, no panic/overflow (would crash above).
        let acc = s.accrued(now);
        assert!(
            acc <= deposit,
            "solvency violated: accrued {acc} > deposit {deposit} (rate={rate}, started_at={started_at}, now={now}, status={status:?})"
        );

        // S1 — purity: an independent identical stream agrees to the base unit at the same `now`.
        let s2 = mk_stream(rate, deposit, started_at, status);
        assert_eq!(
            acc,
            s2.accrued(now),
            "accrued diverged for identical streams"
        );

        // S3 — monotonic non-decreasing in `now`, and flat past end_or_stop.
        let eos = s.end_or_stop();
        if now < u64::MAX {
            let later = now.saturating_add(1 + rng.below(100_000));
            assert!(
                s.accrued(later) >= acc,
                "accrued went backwards: now={now} later={later} (rate={rate}, deposit={deposit})"
            );
        }
        if now >= eos {
            // At/after the accrual horizon the value is frozen (cap or stop), so any later read equals it.
            assert_eq!(
                s.accrued(now),
                s.accrued(u64::MAX),
                "accrued not flat past end_or_stop (eos={eos}, now={now})"
            );
        }
    }
}

/// S4 — a `Stopped(at)` stream freezes accrual at `at`: every later read equals the accrued-at-stop
/// value (still capped at deposit). Distinct from S3's "flat" check: this pins the *value* to the stop
/// instant specifically, the cross-node guarantee a wallet relies on after a `stopStream`.
#[test]
fn stopped_stream_freezes_accrual_at_stop_instant() {
    let mut rng = Rng::new(0x5142_0002);
    for _ in 0..50_000 {
        let rate = 1 + rng.below_u128(MAX_RATE);
        let deposit = 1 + rng.below_u128(10_000u128 * UBI);
        let started_at = rng.below(1_000_000_000);
        let stop_at = started_at.saturating_add(rng.below(2_000_000));
        let s = mk_stream(rate, deposit, started_at, StreamStatus::Stopped(stop_at));

        let frozen = s.accrued(stop_at);
        for _ in 0..6 {
            let t = stop_at.saturating_add(rng.below(u64::MAX / 8));
            assert_eq!(
                s.accrued(t),
                frozen,
                "stopped stream kept accruing: stop_at={stop_at} t={t} (rate={rate}, deposit={deposit})"
            );
        }
        assert!(frozen <= deposit, "frozen value over deposit");
    }
}

/// S5 + S6 — full-lifecycle conservation (bounded by ADR-0002) **and** cross-node reproducibility,
/// driven through the real runtime ops on `MemState`. Mirrors the in-crate property test but with
/// wider input coverage (rate up to MAX_RATE, deposit across magnitudes, `now == u64::MAX` reads) and
/// an explicit second-node replay that also compares the *full stream record*, not just balances.
#[test]
fn open_stop_conserves_bounded_and_reproduces_across_nodes() {
    let mut rng = Rng::new(0x5142_0003);
    // The lifecycle settles the sender at most twice (open + stop) and the recipient at most twice, so
    // the one-directional ADR-0002 loss is bounded by a small constant. Assert the bound, not equality.
    const MAX_SETTLE_LOSS: u128 = 4;

    for _ in 0..30_000 {
        let rate = match rng.below(4) {
            0 => MAX_RATE,
            _ => 1 + rng.below_u128(MAX_RATE),
        };
        let deposit = 1 + rng.below_u128(1_000u128 * UBI);
        let open_at = rng.below(1_000_000_000);
        let life = rng.below(2_000_000);
        // Read at a normal point, and occasionally at the absolute extreme to exercise the cap there.
        let now = if rng.below(10) == 0 {
            u64::MAX
        } else {
            open_at.saturating_add(life)
        };
        let do_stop = rng.below(2) == 1;
        let stop_at = open_at.saturating_add(if life == 0 { 0 } else { rng.below(life + 1) });

        // Build one state from the params; returns (state, refund?).
        let build = || -> (MemState, Option<u128>) {
            let mut s = MemState::new();
            seed_funded(&mut s, addr(1), deposit.saturating_add(10 * UBI));
            open_stream(&mut s, &addr(1), &addr(2), rate, deposit, open_at).unwrap();
            let refund = if do_stop {
                Some(stop_stream(&mut s, 0, &addr(1), stop_at).unwrap())
            } else {
                None
            };
            (s, refund)
        };

        let (sa, refund_a) = build();
        let (sb, refund_b) = build();

        // S6 — reproducibility: balances, refund, and the full stream record agree to the base unit.
        assert_eq!(refund_a, refund_b, "refund diverged across nodes");
        assert_eq!(
            sa.balance(&addr(1), now),
            sb.balance(&addr(1), now),
            "sender balance diverged (rate={rate}, deposit={deposit}, open={open_at}, now={now})"
        );
        assert_eq!(
            sa.balance(&addr(2), now),
            sb.balance(&addr(2), now),
            "recipient balance diverged"
        );
        assert_eq!(
            sa.get_stream(0),
            sb.get_stream(0),
            "stream record diverged across nodes"
        );

        // S2 again at the state level, including the u64::MAX read.
        let st = sa.get_stream(0).unwrap();
        assert!(
            st.accrued(now) <= deposit,
            "state-level solvency violated: accrued {} > deposit {deposit}",
            st.accrued(now)
        );

        // S5 — conservation against the sender's pure-emission baseline. The recipient is unverified
        // (no emission of its own); the stream only redistributes the sender's prefund + emission. For
        // an Active stream `deposit - accrued(now)` is still escrowed; for Stopped/Completed it is 0.
        let prefund = deposit.saturating_add(10 * UBI);
        let baseline = prefund.saturating_add(UBI.saturating_mul(now as u128) / 3_600u128);
        let locked = match st.status {
            StreamStatus::Active => st.deposit.saturating_sub(st.accrued(now)),
            StreamStatus::Stopped(_) | StreamStatus::Completed => 0,
        };
        let total = sa
            .balance(&addr(1), now)
            .saturating_add(sa.balance(&addr(2), now))
            .saturating_add(locked);

        assert!(
            total <= baseline,
            "conservation CREATED value: total {total} > baseline {baseline} (stop={do_stop}, stop_at={stop_at}, rate={rate}, deposit={deposit}, open={open_at}, now={now})"
        );
        assert!(
            baseline - total <= MAX_SETTLE_LOSS,
            "conservation lost more than the ADR-0002 bound: lost {} (>{MAX_SETTLE_LOSS}) (stop={do_stop}, stop_at={stop_at}, rate={rate}, deposit={deposit}, open={open_at}, now={now})",
            baseline - total
        );
    }
}

/// S2 (boundary, explicit) — the documented worst cases as concrete asserts (not random), so a
/// regression is named clearly: a MAX_RATE stream with a tiny deposit read at `u64::MAX`, and a huge
/// deposit that would overflow `rate * elapsed` if the cap were not applied first.
#[test]
fn solvency_boundary_cases_named() {
    // (a) MAX_RATE, 1-base-unit deposit, read at the absolute end of time: caps at the 1-unit deposit.
    let a = mk_stream(MAX_RATE, 1, 0, StreamStatus::Active);
    assert_eq!(
        a.accrued(u64::MAX),
        1,
        "MAX_RATE tiny deposit must cap at deposit"
    );

    // (b) MAX_RATE with a u128::MAX deposit read at u64::MAX — the worst case for `rate * elapsed`.
    // What matters for solvency: the read does not panic/overflow and the result stays ≤ deposit. (The
    // result is governed by the flow term here since the cap can't bind at a u128::MAX deposit. Note:
    // `t_end()` truncates `deposit/rate` via `as u64`, so the accrual horizon here is *not* u64::MAX —
    // an observation recorded in the report as a non-solvency-affecting quirk: accrued stays bounded by
    // the cap regardless, so it can never over-draw.) The point is purely no-overflow + bounded.
    let big = mk_stream(MAX_RATE, u128::MAX, 0, StreamStatus::Active);
    let acc_big = big.accrued(u64::MAX); // must not panic (debug overflow checks are on)
    assert!(
        acc_big <= big.deposit,
        "huge-deposit accrual must stay ≤ deposit"
    );

    // (b') A deposit chosen so the flow term governs and is exactly computable: deposit far exceeds
    // `rate * elapsed`, so accrued == rate * elapsed (no cap), proving the multiply is exact (no
    // overflow, no saturation) for a realistic-magnitude stream read.
    let elapsed: u64 = 1_000_000_000; // ~31 years
    let exact = mk_stream(MAX_RATE, u128::MAX, 0, StreamStatus::Active);
    assert_eq!(
        exact.accrued(elapsed),
        MAX_RATE * elapsed as u128,
        "uncapped flow term must be exactly rate*elapsed"
    );

    // (c) started_at == u64::MAX (no time can elapse): always 0 accrued, never underflows.
    let future = mk_stream(MAX_RATE, 100 * UBI, u64::MAX, StreamStatus::Active);
    assert_eq!(future.accrued(0), 0, "now < started_at ⇒ 0 (no underflow)");
    assert_eq!(future.accrued(u64::MAX), 0, "started_at == now ⇒ 0 elapsed");

    // (d) Stopped(at) far past t_end: end_or_stop clamps to t_end, accrual caps at deposit.
    let drained_then_stopped = mk_stream(
        1,
        (4 * 3_600) as u128,
        0,
        StreamStatus::Stopped(1_000_000_000),
    );
    assert_eq!(
        drained_then_stopped.accrued(u64::MAX),
        (4 * 3_600) as u128,
        "a stop after full drain still caps at deposit"
    );
}
