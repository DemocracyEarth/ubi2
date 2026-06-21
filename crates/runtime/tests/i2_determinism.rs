//! Invariant I2 property tests (reliability gate, board task M1-T8).
//!
//! These assert the *reproducibility / determinism* of time-based balances:
//!   `balance(account, t)` and emission/settlement are exact integer functions of `(state, t)`.
//!
//! Properties proved over randomized timelines (deterministic PRNG, no external crate, no network —
//! satisfies invariant I5 "determinism is testable offline"):
//!   P1  Two independent computations of the same `(verified_at, now)` agree to the base unit.
//!   P2  Settlement at arbitrary intermediate points never changes the final balance
//!       (no UBI lost or created — path-independence of settlement).
//!   P3  Emission is exactly monotonic non-decreasing in `now` (a balance read never goes backwards).
//!   P4  Across a transfer, total value is conserved exactly when neither party streams new emission
//!       after the settle point (no UBI created/destroyed by the move itself).
//!   P5  Replaying the same transfer sequence on two independently-built states yields byte-identical
//!       account state (the consensus effect is a pure function of the op sequence + timestamps).
//!   P6  The closed-form `pending_emission` equals an independent reference implementation
//!       (`UBI * elapsed / 3600`, u128) for random `(elapsed)` — guards against arithmetic drift.
//!
//! The PRNG is a fixed-seed SplitMix64 so failures reproduce exactly: rerun the test, same timelines.

use ubi2_runtime::{apply_transfer, Account, Address, MemState, State, EMISSION_PERIOD_SECS, UBI};

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
}

fn verified(verified_at: u64) -> Account {
    Account {
        verified: true,
        verified_at,
        last_settled_at: verified_at,
        ..Default::default()
    }
}

fn addr(b: u8) -> Address {
    [b; 20]
}

/// Independent reference for pending emission (must match `Account::pending_emission` exactly).
fn ref_emission(verified_at: u64, last_settled_at: u64, now: u64) -> u128 {
    let since = last_settled_at.max(verified_at);
    let elapsed = now.saturating_sub(since) as u128;
    UBI.saturating_mul(elapsed) / EMISSION_PERIOD_SECS as u128
}

/// P1 + P6: balance is a pure integer function of `(verified_at, now)`, matching a reference, and two
/// independent computations agree to the base unit. 50k random timelines.
#[test]
fn balance_is_reproducible_pure_integer_function() {
    let mut rng = Rng::new(0x5EED_0001);
    for _ in 0..50_000 {
        // verified_at up to ~100 years; now up to ~100 years past verification.
        let v = rng.below(3_200_000_000);
        let now = v + rng.below(3_200_000_000);

        let a = verified(v);
        let b = verified(v); // independently constructed "second node"
        let ba = a.balance(now);
        let bb = b.balance(now);

        assert_eq!(ba, bb, "two nodes disagree at (v={v}, now={now})");
        assert_eq!(
            ba,
            ref_emission(v, v, now),
            "closed-form diverges from reference at (v={v}, now={now})"
        );
    }
}

/// P2a — **Settlement bound (documents a real finding).** Settling at arbitrary intermediate
/// timestamps may differ from a single straight-shot read by at most `n_settles` base units, and the
/// difference is always a *loss* to the holder, never a gain. Root cause: `UBI (=10^18)` is **not**
/// divisible by `EMISSION_PERIOD_SECS (=3600)` (`10^18 % 3600 = 2800`), so the truncating division in
/// `pending_emission` drops a sub-unit (≤1 attowei) remainder at each non-hour-aligned settle point;
/// those dropped remainders do not carry forward. This is deterministic (same op-sequence ⇒ same
/// result, see P5) and value-safe (UBI is never *created*), so it does NOT break invariant I2's
/// node-agreement requirement — but it does mean settlement is *not* strictly path-independent. See
/// `docs/reports/reliability-m1.md` (finding F1). 20k random timelines × up to 8 settle points.
#[test]
fn intermediate_settlement_loss_is_bounded_and_one_directional() {
    let mut rng = Rng::new(0x5EED_0002);
    for _ in 0..20_000 {
        let v = rng.below(1_000_000_000);
        let span = 1 + rng.below(3_200_000_000);
        let t_final = v + span;

        // Reference: a single straight-shot balance read with no intermediate settlement.
        let reference = verified(v).balance(t_final);

        // Subject: settle at a random ladder of monotonically non-decreasing points, then read.
        let mut a = verified(v);
        let n_settles = rng.below(9); // 0..=8
        let mut settle_points: Vec<u64> = (0..n_settles).map(|_| v + rng.below(span + 1)).collect();
        settle_points.sort_unstable(); // a real clock only moves forward
        let mut prev_settled = a.settled_balance;
        for t in &settle_points {
            a.settle(*t);
            assert!(
                a.settled_balance >= prev_settled,
                "settle() decreased settled_balance: {} < {prev_settled}",
                a.settled_balance
            );
            prev_settled = a.settled_balance;
        }
        let got = a.balance(t_final);
        // The discrepancy is always a (bounded) loss to the holder — never a gain. UBI is never created.
        assert!(
            got <= reference,
            "settlement CREATED value: got={got} > ref={reference} (v={v})"
        );
        let lost = reference - got;
        assert!(
            lost <= n_settles as u128,
            "settlement lost more than 1 base unit per settle: lost={lost} settles={n_settles} (v={v}, t_final={t_final})"
        );
    }
}

/// P2b — **Strict path-independence when settle points are hour-aligned.** If every settlement lands
/// on an exact `EMISSION_PERIOD_SECS` boundary the division is exact, so intermediate settlement is
/// *exactly* equal to a straight-shot read (no remainder to drop). This is the regime the original
/// `settle_is_idempotent_in_total` unit test exercises, generalized to random hour-aligned ladders.
#[test]
fn hour_aligned_settlement_is_exactly_path_independent() {
    let mut rng = Rng::new(0x5EED_0006);
    for _ in 0..20_000 {
        let v_hours = rng.below(1_000_000);
        let v = v_hours * EMISSION_PERIOD_SECS;
        let span_hours = 1 + rng.below(1_000_000);
        let t_final = v + span_hours * EMISSION_PERIOD_SECS;

        let reference = verified(v).balance(t_final);

        let mut a = verified(v);
        let mut points: Vec<u64> = (0..rng.below(9))
            .map(|_| v + rng.below(span_hours + 1) * EMISSION_PERIOD_SECS)
            .collect();
        points.sort_unstable();
        for t in &points {
            a.settle(*t);
        }
        assert_eq!(
            a.balance(t_final),
            reference,
            "hour-aligned settlement was NOT path-independent (v={v}, t_final={t_final})"
        );
    }
}

/// P3: balance reads are exactly monotonic non-decreasing in `now` for a verified account that is
/// never debited (a wallet polling the stream never sees it go backwards). 5k timelines × 64 samples.
#[test]
fn balance_is_monotonic_in_time() {
    let mut rng = Rng::new(0x5EED_0003);
    for _ in 0..5_000 {
        let v = rng.below(1_000_000_000);
        let a = verified(v);
        let mut t = v;
        let mut prev = a.balance(t);
        for _ in 0..64 {
            t += rng.below(10_000); // non-negative time step (clock only moves forward)
            let cur = a.balance(t);
            assert!(
                cur >= prev,
                "balance went backwards: v={v} t={t} {cur} < {prev}"
            );
            prev = cur;
        }
    }
}

/// P4: across a transfer to an *unverified* recipient (no new stream), the sum of both live balances
/// immediately after equals the sender's pre-transfer balance — value conserved, none created. 20k.
#[test]
fn transfer_conserves_value_exactly() {
    let mut rng = Rng::new(0x5EED_0004);
    for _ in 0..20_000 {
        let v = rng.below(1_000_000_000);
        // Pick a transfer time with enough accrued balance. Bound elapsed to ~1000h so `pre`
        // (≤ ~1000 UBI ≈ 1e21) stays well inside u64 for the value draw — keeps the test honest
        // without u128→u64 truncation games.
        let elapsed = 1 + rng.below(1_000 * EMISSION_PERIOD_SECS);
        let t = v + elapsed;

        let mut s = MemState::new();
        s.put(verified_at_addr(addr(1), v));
        let pre = s.balance(&addr(1), t);
        if pre == 0 {
            continue;
        }
        // Draw a transfer value in [0, pre]; `pre` fits in u64 by construction (bounded elapsed).
        let pre_u64 = pre as u64;
        let value = rng.below(pre_u64 + 1) as u128;

        apply_transfer(&mut s, &addr(1), &addr(2), value, 0, t).unwrap();
        let post = s.balance(&addr(1), t) + s.balance(&addr(2), t);
        assert_eq!(
            pre, post,
            "value not conserved: v={v} t={t} value={value} pre={pre} post={post}"
        );
    }
}

/// P5: replaying the same op sequence (transfers with timestamps) on two independently-constructed
/// states yields identical account state for every touched address — the committed effect is a pure
/// function of (genesis, op-sequence). This is the consensus-determinism property at the runtime layer.
#[test]
fn replay_is_deterministic_across_states() {
    let mut rng = Rng::new(0x5EED_0005);
    for _ in 0..2_000 {
        // Build a random but valid op log against a freshly verified sender.
        let v = rng.below(1_000_000);
        let mut ops: Vec<(u8, u128, u64)> = Vec::new(); // (to_addr_byte, value, timestamp)
        let mut t = v;
        let n_ops = 1 + rng.below(12);
        for _ in 0..n_ops {
            t += rng.below(100_000); // advance the clock (monotonic)
            let to = 2 + (rng.below(5) as u8); // recipients 2..=6
                                               // Keep value modest so it's affordable; sender accrues 1 UBI/hr.
            let value = rng.below((UBI / 4 + 1) as u64) as u128;
            ops.push((to, value, t));
        }

        let final_t = t + rng.below(100_000);

        let st_a = run_ops(v, &ops);
        let st_b = run_ops(v, &ops);

        // Every account that exists in A must exist identically in B, with identical balance at final_t.
        for byte in 1u8..=6 {
            let a = st_a.get(&addr(byte));
            let b = st_b.get(&addr(byte));
            assert_eq!(a, b, "account {byte} diverged across replay");
            assert_eq!(
                st_a.balance(&addr(byte), final_t),
                st_b.balance(&addr(byte), final_t),
                "balance of {byte} diverged at final_t={final_t}"
            );
        }
        assert_eq!(
            st_a.nonce(&addr(1)),
            st_b.nonce(&addr(1)),
            "sender nonce diverged"
        );
    }
}

fn verified_at_addr(a: Address, v: u64) -> Account {
    Account {
        address: a,
        verified: true,
        verified_at: v,
        last_settled_at: v,
        ..Default::default()
    }
}

/// Apply an op log to a fresh state; skips ops the sender can't currently afford so the sequence is
/// always valid (we're testing determinism, not balance enforcement here). Nonce advances on success.
fn run_ops(v: u64, ops: &[(u8, u128, u64)]) -> MemState {
    let mut s = MemState::new();
    s.put(verified_at_addr(addr(1), v));
    let mut nonce = 0u64;
    for &(to_byte, value, t) in ops {
        let have = s.balance(&addr(1), t);
        if have < value {
            continue; // unaffordable in this timeline; deterministically skipped in both runs
        }
        apply_transfer(&mut s, &addr(1), &addr(to_byte), value, nonce, t).unwrap();
        nonce += 1;
    }
    s
}
