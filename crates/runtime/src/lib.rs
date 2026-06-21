//! ubi2 deterministic runtime (M0 skeleton).
//!
//! This crate is the source of truth for state transitions and **must** stay deterministic
//! (see `docs/specs/00-overview.md`, invariant I2): balances are pure integer functions of
//! `(state, timestamp)` — no floats in any consensus path.
//!
//! The M0 skeleton implements just enough of the M1 account/emission model to compile, test, and
//! give the `protocol-engineer` a correct starting point. It is intentionally dependency-free.

/// One UBI expressed in base units (wei-style, 18 decimals).
pub const UBI: u128 = 1_000_000_000_000_000_000;

/// Seconds per hour — the emission period (1 UBI per hour).
pub const EMISSION_PERIOD_SECS: u64 = 3_600;

/// A network account. Addresses are Ethereum-style 20-byte values (H160) in the full design;
/// the skeleton uses a 20-byte array placeholder.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub address: [u8; 20],
    pub verified: bool,
    /// Unix seconds when the account was verified (0 if never).
    pub verified_at: u64,
    /// Emission already folded into the balance, in base units.
    pub settled_balance: u128,
    /// Unix seconds of the last settlement.
    pub last_settled_at: u64,
}

impl Account {
    /// Unsettled emission accrued between `last_settled_at`/`verified_at` and `now`, in base units.
    ///
    /// Deterministic integer math: `UBI * elapsed_secs / EMISSION_PERIOD_SECS`. Returns 0 for
    /// unverified accounts or non-monotonic clocks. The remainder is intentionally retained in the
    /// formula (truncating division) so two nodes computing the same `now` agree to the base unit.
    pub fn pending_emission(&self, now: u64) -> u128 {
        if !self.verified {
            return 0;
        }
        let since = self.last_settled_at.max(self.verified_at);
        let elapsed = now.saturating_sub(since) as u128;
        // UBI (1e18) * elapsed fits comfortably in u128 for any realistic timeline.
        UBI.saturating_mul(elapsed) / EMISSION_PERIOD_SECS as u128
    }

    /// Live balance at `now`: settled balance plus pending streaming emission.
    pub fn balance(&self, now: u64) -> u128 {
        self.settled_balance.saturating_add(self.pending_emission(now))
    }

    /// Fold pending emission into the settled balance and advance the settlement clock.
    /// Call before any balance-changing operation so emission is never lost or double-counted.
    pub fn settle(&mut self, now: u64) {
        let pending = self.pending_emission(now);
        self.settled_balance = self.settled_balance.saturating_add(pending);
        if now > self.last_settled_at {
            self.last_settled_at = now;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified_at(t: u64) -> Account {
        Account { verified: true, verified_at: t, last_settled_at: t, ..Default::default() }
    }

    #[test]
    fn one_ubi_per_hour() {
        let a = verified_at(0);
        assert_eq!(a.balance(EMISSION_PERIOD_SECS), UBI); // exactly 1 UBI after one hour
        assert_eq!(a.balance(EMISSION_PERIOD_SECS * 24), UBI * 24); // 24 UBI/day
    }

    #[test]
    fn unverified_accrues_nothing() {
        let a = Account { verified: false, verified_at: 0, ..Default::default() };
        assert_eq!(a.balance(EMISSION_PERIOD_SECS * 100), 0);
    }

    #[test]
    fn settle_is_idempotent_in_total() {
        // Settling partway must not change the eventual balance (I2: no UBI lost/created).
        let mut a = verified_at(0);
        let t_final = EMISSION_PERIOD_SECS * 10;
        let direct = verified_at(0).balance(t_final);
        a.settle(EMISSION_PERIOD_SECS * 3);
        a.settle(EMISSION_PERIOD_SECS * 7);
        assert_eq!(a.balance(t_final), direct);
    }

    #[test]
    fn reproducible_across_random_timelines() {
        // Two independent computations of the same (verified_at, now) must agree to the base unit.
        for (v, n) in [(0u64, 1u64), (5, 9_999), (100, 100), (1, 86_400), (3_600, 7_201)] {
            let a = verified_at(v);
            let b = verified_at(v);
            assert_eq!(a.balance(n), b.balance(n));
        }
    }
}
