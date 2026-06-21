//! ubi2 deterministic runtime (M1).
//!
//! This crate is the source of truth for state transitions and **must** stay deterministic
//! (see `docs/specs/00-overview.md`, invariant I2): balances are pure integer functions of
//! `(state, timestamp)` — no floats in any consensus path.
//!
//! M1 (see `docs/specs/01-evm-rpc-and-wallet.md`) extends the M0 emission skeleton with:
//!   * a per-account `nonce` and an EIP-155-style value transfer that settles emission on both
//!     accounts *before* moving value (so no UBI is lost or double-counted across settlement),
//!   * a `State` container behind a trait so persistence is swappable (M1 is in-memory),
//!   * a `Verifier` trait (M1 just trusts the genesis `verified` flag; M3 replaces it).
//!
//! The emission arithmetic is unchanged from M0 and is authoritative per spec §M1-T1.1.

use std::collections::HashMap;

/// Ethereum-style 20-byte address (H160).
pub type Address = [u8; 20];

/// One UBI expressed in base units (wei-style, 18 decimals).
pub const UBI: u128 = 1_000_000_000_000_000_000;

/// Seconds per hour — the emission period (1 UBI per hour).
pub const EMISSION_PERIOD_SECS: u64 = 3_600;

/// A network account. Addresses are Ethereum-style 20-byte values (H160).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Account {
    pub address: Address,
    pub verified: bool,
    /// Unix seconds when the account was verified (0 if never).
    pub verified_at: u64,
    /// Emission already folded into the balance, in base units.
    pub settled_balance: u128,
    /// Unix seconds of the last settlement.
    pub last_settled_at: u64,
    /// Transaction count (EIP-155 replay protection). The next valid tx must carry this nonce.
    pub nonce: u64,
}

impl Account {
    /// Unsettled emission accrued between `last_settled_at`/`verified_at` and `now`, in base units.
    ///
    /// Deterministic integer math: `UBI * elapsed_secs / EMISSION_PERIOD_SECS` (spec §M1-T1.1).
    /// Returns 0 for unverified accounts or non-monotonic clocks. The remainder is intentionally
    /// retained in the formula (truncating division) so two nodes computing the same `now` agree to
    /// the base unit (invariant I2).
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
        self.settled_balance
            .saturating_add(self.pending_emission(now))
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

/// Why a transfer was rejected. Deterministic so two nodes reject identically (invariant I2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransferError {
    /// Sender nonce did not match `Account::nonce` (replay / out-of-order).
    BadNonce { expected: u64, got: u64 },
    /// Sender's settled balance (after settlement) is below `value`.
    InsufficientBalance { have: u128, need: u128 },
}

impl std::fmt::Display for TransferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransferError::BadNonce { expected, got } => {
                write!(f, "invalid nonce: expected {expected}, got {got}")
            }
            TransferError::InsufficientBalance { have, need } => {
                write!(f, "insufficient balance: have {have}, need {need}")
            }
        }
    }
}

impl std::error::Error for TransferError {}

/// A verification oracle. M1 trusts the genesis-seeded `Account::verified` flag, so the trivial
/// `GenesisVerifier` just reads it back. M3's proof-of-humanity layer replaces this behind the same
/// trait (invariant I4: deny on uncertainty) without touching the runtime transfer/emission path.
pub trait Verifier: Send + Sync {
    /// Whether `addr` is a verified human at `now`. Determines whether emission accrues.
    fn is_verified(&self, state: &dyn State, addr: &Address, now: u64) -> bool;
}

/// M1 verifier: trusts whatever the genesis loader set on the account. No AI, no network.
#[derive(Clone, Copy, Debug, Default)]
pub struct GenesisVerifier;

impl Verifier for GenesisVerifier {
    fn is_verified(&self, state: &dyn State, addr: &Address, _now: u64) -> bool {
        state.get(addr).map(|a| a.verified).unwrap_or(false)
    }
}

/// The account store behind a trait so persistence is swappable (spec §M1-T1.2). M1 ships the
/// in-memory [`MemState`]; an embedded KV / checkpointed store can implement the same trait without
/// touching RPC or runtime logic.
///
/// The trait is deliberately small: read an account, upsert an account, and iterate. All
/// balance/emission semantics live on [`Account`] / the free functions below, keeping the store dumb.
pub trait State: Send + Sync {
    /// Read an account by address, if it exists.
    fn get(&self, addr: &Address) -> Option<Account>;
    /// Insert or replace an account.
    fn put(&mut self, account: Account);
    /// Snapshot of all accounts (order unspecified; callers must not depend on it).
    fn accounts(&self) -> Vec<Account>;

    /// Live balance of `addr` at `now` (0 for unknown accounts). Pure read.
    fn balance(&self, addr: &Address, now: u64) -> u128 {
        self.get(addr).map(|a| a.balance(now)).unwrap_or(0)
    }

    /// Current nonce of `addr` (0 for unknown accounts). Pure read.
    fn nonce(&self, addr: &Address) -> u64 {
        self.get(addr).map(|a| a.nonce).unwrap_or(0)
    }
}

/// In-memory account store (M1 default). Deterministic given the same sequence of operations.
#[derive(Clone, Debug, Default)]
pub struct MemState {
    accounts: HashMap<Address, Account>,
}

impl MemState {
    pub fn new() -> Self {
        Self::default()
    }
}

impl State for MemState {
    fn get(&self, addr: &Address) -> Option<Account> {
        self.accounts.get(addr).cloned()
    }
    fn put(&mut self, account: Account) {
        self.accounts.insert(account.address, account);
    }
    fn accounts(&self) -> Vec<Account> {
        self.accounts.values().cloned().collect()
    }
}

/// Apply a value transfer of `value` base units from `from` to `to` at `now`.
///
/// Order is load-bearing for invariant I2:
///   1. **Settle emission on both accounts first** (fold pending stream into `settled_balance`),
///      so the transfer operates on fully-materialized balances and no UBI is lost or double-counted.
///   2. Validate the sender's `nonce` (EIP-155 replay protection) and balance.
///   3. Move `value`, then **increment the sender's nonce**.
///
/// `to` is created (unverified, zero balance) if it does not exist — matching Ethereum, where
/// sending to a fresh address simply funds it. A self-transfer settles emission and bumps the nonce
/// but is value-neutral. On any error the state is left untouched (fail-closed, no partial writes).
pub fn apply_transfer(
    state: &mut dyn State,
    from: &Address,
    to: &Address,
    value: u128,
    nonce: u64,
    now: u64,
) -> Result<(), TransferError> {
    // 1. Settle the sender (always exists for a recovered, balance-bearing signer).
    let mut sender = state.get(from).unwrap_or(Account {
        address: *from,
        ..Default::default()
    });
    sender.settle(now);

    // 2. Validate nonce + balance against the *settled* sender before any mutation.
    if nonce != sender.nonce {
        return Err(TransferError::BadNonce {
            expected: sender.nonce,
            got: nonce,
        });
    }
    if sender.settled_balance < value {
        return Err(TransferError::InsufficientBalance {
            have: sender.settled_balance,
            need: value,
        });
    }

    // Self-transfer: settle + bump nonce, value is a no-op. Avoids aliasing two copies of one account.
    if from == to {
        sender.nonce += 1;
        state.put(sender);
        return Ok(());
    }

    // 1b. Settle the recipient too, so its pending stream is materialized before we add to it.
    let mut recipient = state.get(to).unwrap_or(Account {
        address: *to,
        ..Default::default()
    });
    recipient.settle(now);

    // 3. Move value and bump the sender nonce. (saturating_add is safe; total supply ≪ u128::MAX.)
    sender.settled_balance -= value;
    sender.nonce += 1;
    recipient.settled_balance = recipient.settled_balance.saturating_add(value);

    state.put(sender);
    state.put(recipient);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn verified_at(t: u64) -> Account {
        Account {
            verified: true,
            verified_at: t,
            last_settled_at: t,
            ..Default::default()
        }
    }

    #[test]
    fn one_ubi_per_hour() {
        let a = verified_at(0);
        assert_eq!(a.balance(EMISSION_PERIOD_SECS), UBI); // exactly 1 UBI after one hour
        assert_eq!(a.balance(EMISSION_PERIOD_SECS * 24), UBI * 24); // 24 UBI/day
    }

    #[test]
    fn unverified_accrues_nothing() {
        let a = Account {
            verified: false,
            verified_at: 0,
            ..Default::default()
        };
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
        for (v, n) in [
            (0u64, 1u64),
            (5, 9_999),
            (100, 100),
            (1, 86_400),
            (3_600, 7_201),
        ] {
            let a = verified_at(v);
            let b = verified_at(v);
            assert_eq!(a.balance(n), b.balance(n));
        }
    }

    // ---- M1: nonce + transfer settlement ----

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    fn seed(state: &mut MemState, a: Address, verified_at_t: u64) {
        state.put(Account {
            address: a,
            verified: true,
            verified_at: verified_at_t,
            last_settled_at: verified_at_t,
            ..Default::default()
        });
    }

    #[test]
    fn transfer_settles_emission_before_moving_value() {
        // Sender verified at t=0; after 2h it holds exactly 2 UBI. Transfer 1 UBI at t=2h.
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        let t = 2 * EMISSION_PERIOD_SECS;

        apply_transfer(&mut s, &addr(1), &addr(2), UBI, 0, t).unwrap();

        let sender = s.get(&addr(1)).unwrap();
        let recipient = s.get(&addr(2)).unwrap();
        // Sender: 2 UBI accrued, settled, minus 1 UBI sent = 1 UBI settled; nonce bumped.
        assert_eq!(sender.settled_balance, UBI);
        assert_eq!(sender.nonce, 1);
        assert_eq!(sender.last_settled_at, t);
        // Recipient: created unverified, holds exactly the 1 UBI received, does NOT stream.
        assert_eq!(recipient.settled_balance, UBI);
        assert!(!recipient.verified);
        assert_eq!(recipient.balance(t + EMISSION_PERIOD_SECS), UBI);
    }

    #[test]
    fn no_ubi_lost_or_double_counted_across_transfer() {
        // Conservation: sender_balance(now) + recipient_balance(now) right after the transfer
        // equals what the sender alone would have held (recipient is unverified, no new stream).
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        let t = 5 * EMISSION_PERIOD_SECS + 137; // arbitrary, mid-period
        let pre = s.get(&addr(1)).unwrap().balance(t);

        apply_transfer(&mut s, &addr(1), &addr(2), UBI / 2, 0, t).unwrap();

        let post = s.balance(&addr(1), t) + s.balance(&addr(2), t);
        assert_eq!(
            pre, post,
            "value must be conserved exactly across settlement"
        );
    }

    #[test]
    fn bad_nonce_is_rejected_without_mutation() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        let t = EMISSION_PERIOD_SECS;
        // Sender nonce is 0; sending with nonce 1 must fail and leave state untouched.
        let err = apply_transfer(&mut s, &addr(1), &addr(2), UBI, 1, t).unwrap_err();
        assert_eq!(
            err,
            TransferError::BadNonce {
                expected: 0,
                got: 1
            }
        );
        assert!(s.get(&addr(2)).is_none(), "no recipient created on failure");
        assert_eq!(
            s.get(&addr(1)).unwrap().nonce,
            0,
            "nonce unchanged on failure"
        );
    }

    #[test]
    fn insufficient_balance_is_rejected() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        let t = EMISSION_PERIOD_SECS; // only 1 UBI accrued
        let err = apply_transfer(&mut s, &addr(1), &addr(2), UBI * 2, 0, t).unwrap_err();
        assert!(matches!(err, TransferError::InsufficientBalance { .. }));
    }

    #[test]
    fn self_transfer_bumps_nonce_value_neutral() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        let t = 3 * EMISSION_PERIOD_SECS;
        let before = s.get(&addr(1)).unwrap().balance(t);
        apply_transfer(&mut s, &addr(1), &addr(1), UBI, 0, t).unwrap();
        let a = s.get(&addr(1)).unwrap();
        assert_eq!(a.nonce, 1);
        assert_eq!(a.balance(t), before, "self-transfer is value-neutral");
    }

    #[test]
    fn sequential_transfers_increment_nonce() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        let t = 10 * EMISSION_PERIOD_SECS;
        apply_transfer(&mut s, &addr(1), &addr(2), UBI, 0, t).unwrap();
        apply_transfer(&mut s, &addr(1), &addr(2), UBI, 1, t).unwrap();
        assert_eq!(s.nonce(&addr(1)), 2);
        assert_eq!(s.balance(&addr(2), t), 2 * UBI);
    }

    #[test]
    fn balance_reproducible_across_two_states() {
        // I2: the same (verified_at, now) yields identical balances in two independently-built states.
        for (v, n) in [
            (0u64, 1u64),
            (5, 9_999),
            (100, 100),
            (1, 86_400),
            (3_600, 7_201),
        ] {
            let mut a = MemState::new();
            let mut b = MemState::new();
            seed(&mut a, addr(7), v);
            seed(&mut b, addr(7), v);
            assert_eq!(a.balance(&addr(7), n), b.balance(&addr(7), n));
        }
    }

    #[test]
    fn balance_reproducible_across_restart() {
        // I2 (spec criterion 5): a node "restart" — rebuilding state from the same genesis params —
        // must yield byte-identical balances at every timestamp. We model a restart as dropping the
        // store and re-seeding it from the persisted `(address, verified_at)`, then re-deriving the
        // balance. The check is that pre- and post-restart balances agree to the base unit.
        let verified_at = 1_700_000_000u64; // arbitrary unix genesis
        let mut pre = MemState::new();
        seed(&mut pre, addr(9), verified_at);

        for offset in [0u64, 1, 59, 3_600, 3_601, 86_400, 1_000_000, 31_536_000] {
            let t = verified_at + offset;
            let before = pre.balance(&addr(9), t);
            // "Restart": fresh store re-seeded from the same genesis fact.
            let mut post = MemState::new();
            seed(&mut post, addr(9), verified_at);
            let after = post.balance(&addr(9), t);
            assert_eq!(before, after, "restart changed balance at t={t}");
        }
    }

    #[test]
    fn genesis_verifier_reads_flag() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        s.put(Account {
            address: addr(2),
            verified: false,
            ..Default::default()
        });
        let v = GenesisVerifier;
        assert!(v.is_verified(&s, &addr(1), 100));
        assert!(!v.is_verified(&s, &addr(2), 100));
        assert!(!v.is_verified(&s, &addr(3), 100)); // unknown account
    }
}
