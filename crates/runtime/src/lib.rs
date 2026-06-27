//! ubi2 deterministic runtime (M1 + M2).
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
//! M2 (see `docs/specs/02-streaming.md`) adds the **collateralized streaming primitive**: an account
//! can lock a `deposit` and drip it to a recipient at a chosen `rate` (base units/sec). The recipient's
//! balance climbs live; the sender's deposit is removed at open. Streams are *solvent by construction*
//! (D1): a stream can never pay out more than its `deposit`. All stream math is integer (I2): two nodes
//! computing `balance(a, now)` — settled + emission + Σ incoming accrued — agree to the base unit.
//!
//! The emission arithmetic is unchanged from M0 and is authoritative per spec §M1-T1.1.

use std::collections::HashMap;

pub mod humanity;
pub use humanity::{
    quorum_tally, select_jury, tally, CanonicalVerdict, Case, CaseId, CaseKind, CaseStatus,
    Confidence, GraphView, Hash, Human, HumanStatus, HumanityOracle, Juror, MockOracle, QuorumEq,
    QuorumOutcome, Tally, Verdict, Vouch, CHALLENGE_WINDOW, FALSE_CHALLENGE_SLASH, JURY_SIZE,
    MIN_VOUCHES, QUORUM, SYBIL_SLASH, VOUCH_CAPACITY,
};

pub mod lifecycle;
pub use lifecycle::{
    challenge, finalize_registration, register_juror, request_verification, revoke,
    seed_verified_human, submit_verdict, system_challenge, vouch, LifecycleError, LivenessEvidence,
};

pub mod state_root;
pub use state_root::state_root;

pub mod contracts;
pub use contracts::{
    contract_address, deploy_contract, fund_contract, invoke_contract, submit_effect,
    CanonicalEffect, ContractError, ContractId, ContractInterpreter, ContractStateView,
    ContractStatus, EffectError, ExecCase, ExecCaseId, ExecStatus, MockInterpreter, Op,
    PromptContract, CONTRACT_HUB,
};

/// Ethereum-style 20-byte address (H160).
pub type Address = [u8; 20];

/// One UBI expressed in base units (wei-style, 18 decimals).
pub const UBI: u128 = 1_000_000_000_000_000_000;

/// Seconds per hour — the emission period (1 UBI per hour).
pub const EMISSION_PERIOD_SECS: u64 = 3_600;

// ---------------------------------------------------------------------------------------------
// Fee model (M5 fee-recycling foundation) — a **real, deterministic UBI gas fee** on every tx.
//
// Gas is charged in UBI (the native currency): `fee = gas_used * gas_price` in base units, deducted
// from the sender's settled balance at apply time *before* the op runs, and credited to the reserved
// `TREASURY` account. Both `gas_used` (a small per-kind constant) and `gas_price` (a flat constant)
// are part of consensus state, so the fee is a pure integer function of the tx kind (invariant I2):
// two nodes charge the same sender the same fee to the base unit. Fees never leave the system — they
// move sender → treasury, conserving total supply to the base unit (the basis for M5 redistribution).
// ---------------------------------------------------------------------------------------------

/// The flat devnet gas price in UBI base units per gas unit. **1 gwei** (`10^9`), matching the value
/// `eth_gasPrice` advertises so a wallet's `fee = gasLimit * gasPrice` preview equals what is charged.
/// At `21000` gas a transfer costs `21000 * 10^9 = 2.1 * 10^13` base units (`0.000021` UBI) — small
/// relative to the `10^18`-per-hour emission, so verified accounts always cover it.
pub const GAS_PRICE_WEI: u128 = 1_000_000_000;

/// Gas a plain value transfer costs (the EVM intrinsic, `21000`).
pub const GAS_TRANSFER: u64 = 21_000;

/// Gas a StreamHub op (`openStream` / `stopStream`) costs — modestly above a transfer to reflect the
/// extra escrow/index bookkeeping. Deterministic per-kind constant (no metering).
pub const GAS_STREAM: u64 = 60_000;

/// Gas a HumanityHub op (vouch / challenge / submitVerdict) costs.
pub const GAS_HUMANITY: u64 = 80_000;

/// Gas a `requestVerification` (onboarding) op costs — **0, fee-exempt**. This is the network's
/// bootstrap gate: an account requesting verification is by construction not yet `Verified`, so it has
/// no streaming UBI and *cannot* pay a fee (chicken-and-egg). The network subsidizes onboarding — the
/// only fee-free tx kind — so a brand-new human can request verification from a zero balance. Every
/// other action (vouch / challenge / verdict / stream / contract) is taken by an account that already
/// earns UBI and pays the real fee. Documented deviation (spec 03 §"Bootstrapping").
pub const GAS_ONBOARD: u64 = 0;

/// Gas a ContractHub op (deploy / fund / invoke / submitEffect) costs — the heaviest tx kind
/// (interpreter quorum + effect application), so it pays the most gas. For `deployContract` this is
/// the **base** gas; the full fee scales with the stored text length (see [`GAS_PER_TEXT_BYTE`] /
/// [`gas_for_deploy`]) so permanent on-chain storage has a real per-byte cost.
pub const GAS_CONTRACT: u64 = 120_000;

/// Per-byte gas surcharge on a `deployContract`'s stored UTF-8 text — EVM-calldata-like (`16` gas per
/// byte). The on-chain `text` is permanent, un-prunable state, so its fee must scale with its length
/// (otherwise storing a byte is free, an unbounded-input DoS — C6-SEC-1). The total deploy fee is
/// `GAS_CONTRACT + GAS_PER_TEXT_BYTE * text.len()`; see [`gas_for_deploy`]. Deterministic (I2): the
/// text length is consensus input, so every node charges the same sender the same fee for the same tx.
pub const GAS_PER_TEXT_BYTE: u64 = 16;

/// Hard upper bound on a `deployContract`'s on-chain UTF-8 text, in bytes. Generous for a real
/// plain-language agreement (8 KiB ≈ a few pages of prose), but tiny relative to the multi-MB blobs an
/// attacker would need to bloat state cheaply. Enforced at SUBMIT (before the bytes enter the mempool)
/// and re-checked in [`deploy_contract`] (defense in depth) — C6-SEC-1.
pub const MAX_CONTRACT_TEXT_BYTES: usize = 8192;

/// Hard upper bound on a `deployContract`'s declared `parties` count. A real agreement has a handful of
/// signatories; the array is `O(n log n)` sorted+deduped and stored on-chain, so it is a (smaller)
/// amplifier and must be bounded too — C6-SEC-1.
pub const MAX_CONTRACT_PARTIES: usize = 16;

/// The size-metered gas for a `deployContract` whose on-chain text is `text_len` bytes:
/// `GAS_CONTRACT + GAS_PER_TEXT_BYTE * text_len`. Pure integer math (I2); saturating so an (already
/// cap-rejected) absurd length fails closed rather than wrapping. Storing more text costs more gas, so
/// the wallet's `eth_estimateGas` preview and the charged UBI fee both scale with the text.
pub const fn gas_for_deploy(text_len: usize) -> u64 {
    GAS_CONTRACT.saturating_add((GAS_PER_TEXT_BYTE).saturating_mul(text_len as u64))
}

/// The reserved **TREASURY / commons** system account that collected fees accrue to (whitepaper fee
/// recycling; the basis for M5 redistribution). A documented, well-known address in the system-address
/// space: `0x…5542`, distinct from the StreamHub (`0x…5742`), HumanityHub (`0x…5048`) and ContractHub
/// (`0x…5043`). It is never a signer (no key); value only ever flows *into* it via fees, so total
/// supply is conserved (sender → treasury) to the base unit.
pub const TREASURY: Address = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x55, 0x42,
];

/// The UBI fee (base units) for a tx whose `gas_used` is `gas`. Pure integer math (I2).
pub const fn fee_for_gas(gas: u64) -> u128 {
    (gas as u128) * GAS_PRICE_WEI
}

/// Why a fee charge was rejected. Deterministic so two nodes reject identically (invariant I2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FeeError {
    /// Sender's settled balance (after settlement) is below the required `fee`.
    InsufficientForFee { have: u128, fee: u128 },
}

impl std::fmt::Display for FeeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeeError::InsufficientForFee { have, fee } => write!(
                f,
                "insufficient balance for gas fee: have {have}, fee {fee}"
            ),
        }
    }
}

impl std::error::Error for FeeError {}

/// Charge `gas`-worth of UBI gas fee to `from` and credit it to the [`TREASURY`] at unix second `now`.
///
/// Order (load-bearing for I2 / conservation): settle the sender's emission first so the check runs on
/// the materialized balance, require `settled_balance >= fee`, debit the sender, then credit the
/// treasury by the **same** amount (settling the treasury too so its own clock stays consistent — it is
/// unverified so this only advances `last_settled_at`). Fail-closed: on insufficient balance nothing is
/// written (no partial state, I4) and the op the fee precedes must not run.
///
/// Returns the fee charged on success. Total supply is conserved: the sender loses exactly `fee` and
/// the treasury gains exactly `fee`.
pub fn charge_fee(
    state: &mut dyn State,
    from: &Address,
    gas: u64,
    now: u64,
) -> Result<u128, FeeError> {
    let fee = fee_for_gas(gas);

    let mut sender = state.get(from).unwrap_or(Account {
        address: *from,
        ..Default::default()
    });
    sender.settle(now);
    if sender.settled_balance < fee {
        return Err(FeeError::InsufficientForFee {
            have: sender.settled_balance,
            fee,
        });
    }
    sender.settled_balance -= fee;

    // FU-13: a **zero** fee (the fee-exempt onboarding op, `GAS_ONBOARD == 0`) must not create or
    // touch the TREASURY account. Creating a zero-balance `TREASURY` entry on a zero-gas op left a
    // stray account in `MemState::accounts` that perturbs the state-root (a node that has processed an
    // onboarding op would have a TREASURY entry a node that has not would lack), breaking byte-identical
    // roots (EC-4/EC-10). When `fee == 0` nothing moves, so we write only the (nonce-untouched) sender —
    // and even that only after settlement — and skip the treasury entirely.
    if fee == 0 {
        state.put(sender);
        return Ok(0);
    }

    let mut treasury = state.get(&TREASURY).unwrap_or(Account {
        address: TREASURY,
        ..Default::default()
    });
    treasury.settle(now);
    treasury.settled_balance = treasury.settled_balance.saturating_add(fee);

    state.put(sender);
    state.put(treasury);
    Ok(fee)
}

/// A sequential stream identifier, assigned at `open_stream` (spec D2/Q3 — `u64`, fits a log topic).
pub type StreamId = u64;

/// Upper bound on a stream's `rate` (base units per second) — the anti-grief bound (spec §Safety,
/// "Rate control"). Chosen as **1000 UBI/hour** worth of per-second flow: high enough that any
/// realistic human→human stream is allowed, low enough that a single op can't request an absurd rate
/// that would overflow downstream arithmetic. `MAX_RATE * (a century in secs)` stays far below
/// `u128::MAX`, so `rate * elapsed` never overflows on any plausible timeline.
pub const MAX_RATE: u128 = 1_000 * UBI / EMISSION_PERIOD_SECS as u128;

/// Lifecycle of a [`Stream`]. A stream is `Active` until it is either stopped early by the sender
/// (`Stopped(at)`) or fully drained (`Completed`). The variant is part of consensus state, so it is
/// derived purely from deterministic transitions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamStatus {
    /// Still flowing: accrues `rate * elapsed`, capped at `deposit`.
    Active,
    /// Cancelled by the sender at the given unix second; accrual is frozen at that instant.
    Stopped(u64),
    /// Fully drained — `drawn == deposit`. No refund (everything was paid out).
    Completed,
}

/// A collateralized, one-to-one payment stream (spec §"Data model"). The sender's `deposit` is
/// removed from their settled balance at open; the recipient accrues `rate * elapsed`, **capped at
/// `deposit`** (D1 — solvent by construction). `drawn` tracks how much of the deposit has already been
/// folded into the recipient's settled balance via [`settle_stream`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stream {
    /// Sequential id assigned at open.
    pub id: StreamId,
    /// Sender (deposit was locked from this account).
    pub from: Address,
    /// Recipient (accrues the drip).
    pub to: Address,
    /// Flow rate in base units per second.
    pub rate: u128,
    /// Total locked at open, in base units. Hard cap on lifetime payout.
    pub deposit: u128,
    /// Amount already settled to `to` (folded into `to.settled_balance`).
    pub drawn: u128,
    /// Unix seconds when the stream opened (accrual epoch).
    pub started_at: u64,
    /// Lifecycle status.
    pub status: StreamStatus,
}

impl Stream {
    /// The instant beyond which the stream stops accruing time: `min(t_end, stop_time)` where
    /// `t_end = started_at + deposit / rate`. For an `Active` stream this is `t_end`; for a
    /// `Stopped(at)` stream it is `min(t_end, at)` (a stop never extends accrual past the deposit);
    /// for a `Completed` stream it is `t_end`. Pure integer math.
    pub fn end_or_stop(&self) -> u64 {
        let t_end = self.t_end();
        match self.status {
            StreamStatus::Stopped(at) => at.min(t_end),
            _ => t_end,
        }
    }

    /// `t_end = started_at + ceil(deposit / rate)` — the instant the deposit is fully drained for an
    /// uninterrupted stream. Exposed for `StreamView` / RPC and reused by [`end_or_stop`].
    ///
    /// Uses `ceil` so a partial last tick is still bounded by the `min(.., deposit)` cap in
    /// [`accrued`](Stream::accrued); this keeps `t_end` ≥ the true drain instant, and the deposit cap
    /// clamps the value — so the cap, not this bound, is load-bearing for solvency. `rate > 0` is
    /// enforced at open, but `checked_div` guards a zero rate anyway (deny on 0).
    pub fn t_end(&self) -> u64 {
        let Some(whole) = self.deposit.checked_div(self.rate) else {
            return self.started_at; // rate == 0: never drains by flow
        };
        let rem = self.deposit % self.rate;
        // `whole` is u128; saturate (not wrap/truncate) into u64 for extreme inputs. Solvency does
        // not depend on this — the `accrued().min(deposit)` cap is load-bearing — but it keeps the
        // card's "Ends" display correct. (Reliability gate M2 F2.)
        self.started_at
            .saturating_add(u64::try_from(whole).unwrap_or(u64::MAX))
            .saturating_add(if rem > 0 { 1 } else { 0 })
    }

    /// Total amount accrued to the recipient by `now`, **capped at `deposit`** (D1). This is the gross
    /// lifetime payout — `accrued - drawn` is what an immediate [`settle_stream`] would still owe.
    ///
    /// `accrued(now) = min(rate * (min(now, end_or_stop) - started_at), deposit)`. Saturating integer
    /// math throughout: non-monotonic clocks (now < started_at) yield 0; `rate * elapsed` is clamped to
    /// `deposit` so it can never exceed the collateral (solvency, spec criterion 3).
    pub fn accrued(&self, now: u64) -> u128 {
        let until = now.min(self.end_or_stop());
        let elapsed = until.saturating_sub(self.started_at) as u128;
        self.rate.saturating_mul(elapsed).min(self.deposit)
    }
}

/// Why a stream operation was rejected. Deterministic so two nodes reject identically (invariant I2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// `from == to` — a stream to oneself is meaningless.
    SelfStream,
    /// `rate == 0`.
    ZeroRate,
    /// `deposit == 0`.
    ZeroDeposit,
    /// `rate > MAX_RATE` (anti-grief bound).
    RateTooHigh { rate: u128, max: u128 },
    /// Sender's settled balance (after settlement) is below the requested `deposit`.
    InsufficientBalance { have: u128, need: u128 },
    /// No stream with the given id.
    NoSuchStream(StreamId),
    /// `stop_stream` caller is not the stream's sender (M2: only `from` may cancel — Q2).
    NotSender,
    /// The stream is already `Stopped`/`Completed` and cannot be stopped again.
    NotActive,
}

impl std::fmt::Display for StreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamError::SelfStream => write!(f, "stream sender and recipient must differ"),
            StreamError::ZeroRate => write!(f, "stream rate must be > 0"),
            StreamError::ZeroDeposit => write!(f, "stream deposit must be > 0"),
            StreamError::RateTooHigh { rate, max } => {
                write!(f, "stream rate {rate} exceeds MAX_RATE {max}")
            }
            StreamError::InsufficientBalance { have, need } => {
                write!(
                    f,
                    "insufficient balance for deposit: have {have}, need {need}"
                )
            }
            StreamError::NoSuchStream(id) => write!(f, "no such stream: {id}"),
            StreamError::NotSender => write!(f, "only the stream sender may stop it"),
            StreamError::NotActive => write!(f, "stream is not active"),
        }
    }
}

impl std::error::Error for StreamError {}

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

/// The account + stream store behind a trait so persistence is swappable (spec §M1-T1.2). M1 shipped
/// the in-memory [`MemState`]; M2 adds the stream registry + per-account indexes to the same trait so
/// an embedded KV / checkpointed store can implement it without touching RPC or runtime logic.
///
/// The trait stays deliberately dumb: read/upsert accounts and streams, iterate, and look up an
/// account's incoming/outgoing stream ids. All balance/emission/accrual semantics live on [`Account`]
/// / [`Stream`] / the free functions below.
pub trait State: Send + Sync {
    /// Read an account by address, if it exists.
    fn get(&self, addr: &Address) -> Option<Account>;
    /// Insert or replace an account.
    fn put(&mut self, account: Account);
    /// Snapshot of all accounts (order unspecified; callers must not depend on it).
    fn accounts(&self) -> Vec<Account>;

    // ---- M2: stream registry ----

    /// Read a stream by id, if it exists.
    fn get_stream(&self, id: StreamId) -> Option<Stream>;
    /// Insert or replace a stream **and** keep the per-account `outgoing`/`incoming` indexes in sync.
    /// Implementations must make indexing idempotent (re-putting an existing id must not duplicate it).
    fn put_stream(&mut self, stream: Stream);
    /// The stream ids `addr` is the **sender** of (order unspecified).
    fn outgoing(&self, addr: &Address) -> Vec<StreamId>;
    /// The stream ids `addr` is the **recipient** of (order unspecified).
    fn incoming(&self, addr: &Address) -> Vec<StreamId>;
    /// Reserve and return the next sequential [`StreamId`], advancing the counter. Called once per
    /// successful `open_stream`.
    fn next_stream_id(&mut self) -> StreamId;
    /// Snapshot of all streams (order unspecified). For explorer / debugging.
    fn streams(&self) -> Vec<Stream>;

    /// Live balance of `addr` at `now` (0 for unknown accounts). Pure read of `(state, now)` — I2.
    ///
    /// M2 extension (spec D3): the balance is `settled + emission + Σ accrued(s, now)` over the
    /// account's **incoming active** streams (the sender's deposit was already removed at open, so we
    /// only add the inflow). We add `accrued - drawn` so already-settled portions aren't double-counted
    /// against the live read. All integer math; no floats.
    fn balance(&self, addr: &Address, now: u64) -> u128 {
        let base = self.get(addr).map(|a| a.balance(now)).unwrap_or(0);
        let inflow: u128 = self
            .incoming(addr)
            .into_iter()
            .filter_map(|id| self.get_stream(id))
            // `accrued - drawn` is the not-yet-settled inflow; `drawn` is already in `settled_balance`.
            .map(|s| s.accrued(now).saturating_sub(s.drawn))
            .fold(0u128, |acc, x| acc.saturating_add(x));
        base.saturating_add(inflow)
    }

    /// Current nonce of `addr` (0 for unknown accounts). Pure read.
    fn nonce(&self, addr: &Address) -> u64 {
        self.get(addr).map(|a| a.nonce).unwrap_or(0)
    }

    // ---- M3: proof-of-humanity registry (spec 03 §"On-chain state") ----
    //
    // All registry reads return owned snapshots and all index reads return **sorted** vectors, so no
    // consensus-affecting path ever depends on hash-iteration order (invariant I1).

    /// Read a human record by address, if it exists. `None` ⇒ the address is `Unverified`.
    fn get_human(&self, addr: &Address) -> Option<Human>;
    /// Insert or replace a human record.
    fn put_human(&mut self, human: Human);
    /// Snapshot of all human records, **sorted by address** (deterministic order — I1).
    fn humans(&self) -> Vec<Human>;

    /// Record a vouch edge, keeping the forward (`vouches_out`) and reverse (`vouchers_of`) indexes in
    /// sync. Idempotent on the indexes: re-recording an existing `(voucher, vouchee)` pair must not
    /// duplicate it.
    fn put_vouch(&mut self, vouch: Vouch);
    /// Vouchees `addr` has vouched **for** (forward edge), sorted by address. Pure read.
    fn vouches_out(&self, addr: &Address) -> Vec<Address>;
    /// Vouchers that have vouched **for** `addr` (reverse edge), sorted by address. Pure read.
    fn vouchers_of(&self, addr: &Address) -> Vec<Address>;
    /// All vouch edges in the graph, sorted by `(voucher, vouchee)`. For [`GraphView`] / sybil scan.
    fn vouch_edges(&self) -> Vec<(Address, Address)>;
    /// Remove every vouch edge touching `subject` (as voucher OR vouchee) from both the forward and
    /// reverse indexes (reliability finding F-REL-1). Called on `revoke`/re-register so a re-registered
    /// subject can be re-vouched by its prior vouchers. Deterministic: a set difference over sorted
    /// indexes, no hash-iteration ordering leaks (the indexes are returned sorted by their readers).
    fn clear_vouch_edges(&mut self, subject: &Address);

    /// Record that `challenger`'s challenge against `subject` cleared a `Human` verdict (security
    /// finding A cooldown). After this, `challenge` rejects a re-file by the same challenger against
    /// the same subject (`ChallengeOnCooldown`) so a false challenger cannot stall finalization by
    /// re-filing. Idempotent.
    fn record_challenge_cleared(&mut self, challenger: &Address, subject: &Address);
    /// Has `challenger` already cleared a `Human`-verdict challenge against `subject`? Pure read.
    fn challenge_cleared(&self, challenger: &Address, subject: &Address) -> bool;

    /// Read a case by id, if it exists.
    fn get_case(&self, id: CaseId) -> Option<Case>;
    /// Insert or replace a case.
    fn put_case(&mut self, case: Case);
    /// Reserve and return the next sequential [`CaseId`], advancing the counter. Called once per case.
    fn next_case_id(&mut self) -> CaseId;
    /// Ids of all cases with `status == Open`, sorted ascending. For RPC `getPendingCases`. Pure read.
    fn open_cases(&self) -> Vec<CaseId>;
    /// Snapshot of all cases, sorted by id. For the explorer / debugging.
    fn cases(&self) -> Vec<Case>;

    /// Read a juror by address, if registered.
    fn get_juror(&self, addr: &Address) -> Option<Juror>;
    /// Insert or replace a juror.
    fn put_juror(&mut self, juror: Juror);
    /// Addresses of all `active` jurors, **sorted ascending** (the deterministic candidate pool that
    /// [`select_jury`] draws from — I1). Pure read.
    fn active_jurors(&self) -> Vec<Address>;

    /// Build a deterministic [`GraphView`] (sorted edges) for the AI sybil scan. Pure read (I1/I6:
    /// only the graph topology — addresses + edges — is exposed, never any PII).
    fn graph_view(&self) -> GraphView {
        GraphView {
            edges: self.vouch_edges(),
        }
    }

    // ---- M4: prompt-contract registry (spec 04 §"Data model") ----
    //
    // All registry reads return owned snapshots and all listing reads return **sorted** vectors, so
    // no consensus-affecting path ever depends on hash-iteration order (invariant I1).

    /// Read a prompt contract by id, if it exists.
    fn get_contract(&self, id: ContractId) -> Option<PromptContract>;
    /// Insert or replace a prompt contract.
    fn put_contract(&mut self, contract: PromptContract);
    /// Reserve and return the next sequential [`ContractId`], advancing the counter.
    fn next_contract_id(&mut self) -> ContractId;
    /// Snapshot of all prompt contracts, sorted by id (deterministic order — I1).
    fn contracts(&self) -> Vec<PromptContract>;

    /// Read an exec case by id, if it exists.
    fn get_exec_case(&self, id: ExecCaseId) -> Option<ExecCase>;
    /// Insert or replace an exec case.
    fn put_exec_case(&mut self, case: ExecCase);
    /// Reserve and return the next sequential [`ExecCaseId`], advancing the counter.
    fn next_exec_case_id(&mut self) -> ExecCaseId;
    /// Snapshot of all exec cases, sorted by id (deterministic order — I1).
    fn exec_cases(&self) -> Vec<ExecCase>;

    // ---- M5: id-counter peeks (read-only; for the deterministic state root) ----
    //
    // The next-id counters are part of consensus state: a rolled-back op can advance a counter without
    // leaving a registry entry, so two states with the same entries but different counters are NOT
    // logically equal and must produce different roots. These read-only peeks let `state_root` commit
    // the counters without mutating them. Default impls return 0 so non-`MemState` stores compile;
    // `MemState` overrides them with the real values.

    /// The id the next [`open_stream`] will receive (read-only peek of the counter). Pure read.
    fn peek_next_stream_id(&self) -> StreamId {
        0
    }
    /// The id the next case will receive (read-only peek). Pure read.
    fn peek_next_case_id(&self) -> CaseId {
        0
    }
    /// The id the next [`deploy_contract`] will receive (read-only peek). Pure read.
    fn peek_next_contract_id(&self) -> ContractId {
        0
    }
    /// The id the next exec case will receive (read-only peek). Pure read.
    fn peek_next_exec_case_id(&self) -> ExecCaseId {
        0
    }
}

/// In-memory account + stream store (M1 default, extended for M2). Deterministic given the same
/// sequence of operations.
#[derive(Clone, Debug, Default)]
pub struct MemState {
    accounts: HashMap<Address, Account>,
    /// Stream registry, keyed by id.
    streams: HashMap<StreamId, Stream>,
    /// Per-account outgoing (sender) stream-id index.
    outgoing: HashMap<Address, Vec<StreamId>>,
    /// Per-account incoming (recipient) stream-id index.
    incoming: HashMap<Address, Vec<StreamId>>,
    /// Sequential id counter — the id the next `open_stream` will receive.
    next_id: StreamId,

    // ---- M3: proof-of-humanity registry ----
    /// Human records, keyed by address.
    humans: HashMap<Address, Human>,
    /// Forward vouch index: voucher → vouchees it has vouched for.
    vouches_out: HashMap<Address, Vec<Address>>,
    /// Reverse vouch index: vouchee → vouchers that vouched for it.
    vouchers_of: HashMap<Address, Vec<Address>>,
    /// Case registry, keyed by id.
    cases: HashMap<CaseId, Case>,
    /// Sequential case-id counter — the id the next case will receive.
    next_case_id: CaseId,
    /// Juror registry, keyed by address.
    jurors: HashMap<Address, Juror>,
    /// `(challenger, subject)` pairs whose challenge cleared a `Human` verdict — the false-challenge
    /// cooldown set (security finding A). Membership bars a re-file by that challenger on that subject.
    cleared_challenges: std::collections::HashSet<(Address, Address)>,

    // ---- M4: prompt-contract registry ----
    /// Prompt contracts, keyed by id.
    contracts: HashMap<ContractId, PromptContract>,
    /// Sequential contract-id counter — the id the next `deploy_contract` will receive.
    next_contract_id: ContractId,
    /// Exec cases, keyed by id.
    exec_cases: HashMap<ExecCaseId, ExecCase>,
    /// Sequential exec-case-id counter.
    next_exec_case_id: ExecCaseId,
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

    fn get_stream(&self, id: StreamId) -> Option<Stream> {
        self.streams.get(&id).copied()
    }

    fn put_stream(&mut self, stream: Stream) {
        let is_new = !self.streams.contains_key(&stream.id);
        if is_new {
            // Keep the indexes idempotent: only append on first insert. Re-putting an existing id
            // (e.g. after a settle/stop mutation) updates the registry but must not duplicate the id
            // in either index.
            self.outgoing
                .entry(stream.from)
                .or_default()
                .push(stream.id);
            self.incoming.entry(stream.to).or_default().push(stream.id);
        }
        self.streams.insert(stream.id, stream);
    }

    fn outgoing(&self, addr: &Address) -> Vec<StreamId> {
        // FU-13: return the index **sorted** so no consensus path (the `state_root` serialization, the
        // `balance` inflow sum) depends on insertion order. Stream ids are assigned monotonically, so a
        // single-node run is already ascending; sorting makes it order-independent across any path that
        // could re-put streams out of id order, guaranteeing two logically-equal states iterate the same.
        let mut v = self.outgoing.get(addr).cloned().unwrap_or_default();
        v.sort_unstable();
        v
    }

    fn incoming(&self, addr: &Address) -> Vec<StreamId> {
        // FU-13: sorted, for the same determinism reason as `outgoing` above.
        let mut v = self.incoming.get(addr).cloned().unwrap_or_default();
        v.sort_unstable();
        v
    }

    fn next_stream_id(&mut self) -> StreamId {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    fn streams(&self) -> Vec<Stream> {
        self.streams.values().copied().collect()
    }

    // ---- M3: proof-of-humanity registry ----

    fn get_human(&self, addr: &Address) -> Option<Human> {
        self.humans.get(addr).cloned()
    }
    fn put_human(&mut self, human: Human) {
        self.humans.insert(human.address, human);
    }
    fn humans(&self) -> Vec<Human> {
        let mut v: Vec<Human> = self.humans.values().cloned().collect();
        v.sort_by_key(|h| h.address);
        v
    }

    fn put_vouch(&mut self, vouch: Vouch) {
        // Idempotent on both indexes: only append a `(voucher, vouchee)` pair the first time.
        let out = self.vouches_out.entry(vouch.voucher).or_default();
        if !out.contains(&vouch.vouchee) {
            out.push(vouch.vouchee);
        }
        let rev = self.vouchers_of.entry(vouch.vouchee).or_default();
        if !rev.contains(&vouch.voucher) {
            rev.push(vouch.voucher);
        }
    }
    fn vouches_out(&self, addr: &Address) -> Vec<Address> {
        let mut v = self.vouches_out.get(addr).cloned().unwrap_or_default();
        v.sort_unstable();
        v
    }
    fn vouchers_of(&self, addr: &Address) -> Vec<Address> {
        let mut v = self.vouchers_of.get(addr).cloned().unwrap_or_default();
        v.sort_unstable();
        v
    }
    fn vouch_edges(&self) -> Vec<(Address, Address)> {
        let mut edges: Vec<(Address, Address)> = self
            .vouches_out
            .iter()
            .flat_map(|(voucher, vouchees)| vouchees.iter().map(move |v| (*voucher, *v)))
            .collect();
        edges.sort_unstable();
        edges
    }
    fn clear_vouch_edges(&mut self, subject: &Address) {
        // Drop the subject's own forward/reverse buckets entirely.
        self.vouches_out.remove(subject);
        self.vouchers_of.remove(subject);
        // And drop the subject wherever it appears inside another account's buckets.
        for vouchees in self.vouches_out.values_mut() {
            vouchees.retain(|v| v != subject);
        }
        for vouchers in self.vouchers_of.values_mut() {
            vouchers.retain(|v| v != subject);
        }
    }

    fn record_challenge_cleared(&mut self, challenger: &Address, subject: &Address) {
        self.cleared_challenges.insert((*challenger, *subject));
    }
    fn challenge_cleared(&self, challenger: &Address, subject: &Address) -> bool {
        self.cleared_challenges.contains(&(*challenger, *subject))
    }

    fn get_case(&self, id: CaseId) -> Option<Case> {
        self.cases.get(&id).cloned()
    }
    fn put_case(&mut self, case: Case) {
        self.cases.insert(case.id, case);
    }
    fn next_case_id(&mut self) -> CaseId {
        let id = self.next_case_id;
        self.next_case_id += 1;
        id
    }
    fn open_cases(&self) -> Vec<CaseId> {
        let mut v: Vec<CaseId> = self
            .cases
            .values()
            .filter(|c| matches!(c.status, CaseStatus::Open))
            .map(|c| c.id)
            .collect();
        v.sort_unstable();
        v
    }
    fn cases(&self) -> Vec<Case> {
        let mut v: Vec<Case> = self.cases.values().cloned().collect();
        v.sort_by_key(|c| c.id);
        v
    }

    fn get_juror(&self, addr: &Address) -> Option<Juror> {
        self.jurors.get(addr).copied()
    }
    fn put_juror(&mut self, juror: Juror) {
        self.jurors.insert(juror.address, juror);
    }
    fn active_jurors(&self) -> Vec<Address> {
        let mut v: Vec<Address> = self
            .jurors
            .values()
            .filter(|j| j.active)
            .map(|j| j.address)
            .collect();
        v.sort_unstable();
        v
    }

    // ---- M4: prompt-contract registry ----

    fn get_contract(&self, id: ContractId) -> Option<PromptContract> {
        self.contracts.get(&id).cloned()
    }
    fn put_contract(&mut self, contract: PromptContract) {
        self.contracts.insert(contract.id, contract);
    }
    fn next_contract_id(&mut self) -> ContractId {
        let id = self.next_contract_id;
        self.next_contract_id += 1;
        id
    }
    fn contracts(&self) -> Vec<PromptContract> {
        let mut v: Vec<PromptContract> = self.contracts.values().cloned().collect();
        v.sort_by_key(|c| c.id);
        v
    }

    fn get_exec_case(&self, id: ExecCaseId) -> Option<ExecCase> {
        self.exec_cases.get(&id).cloned()
    }
    fn put_exec_case(&mut self, case: ExecCase) {
        self.exec_cases.insert(case.id, case);
    }
    fn next_exec_case_id(&mut self) -> ExecCaseId {
        let id = self.next_exec_case_id;
        self.next_exec_case_id += 1;
        id
    }
    fn exec_cases(&self) -> Vec<ExecCase> {
        let mut v: Vec<ExecCase> = self.exec_cases.values().cloned().collect();
        v.sort_by_key(|c| c.id);
        v
    }

    fn peek_next_stream_id(&self) -> StreamId {
        self.next_id
    }
    fn peek_next_case_id(&self) -> CaseId {
        self.next_case_id
    }
    fn peek_next_contract_id(&self) -> ContractId {
        self.next_contract_id
    }
    fn peek_next_exec_case_id(&self) -> ExecCaseId {
        self.next_exec_case_id
    }
}

impl MemState {
    /// The cleared-challenge cooldown set, returned **sorted** by `(challenger, subject)` for the
    /// deterministic state root (the underlying store is a `HashSet`, whose iteration order is not
    /// canonical). Pure read. Not on the [`State`] trait — only the root serializer needs it, and only
    /// for `MemState`.
    pub fn cleared_challenges_sorted(&self) -> Vec<(Address, Address)> {
        let mut v: Vec<(Address, Address)> = self.cleared_challenges.iter().copied().collect();
        v.sort_unstable();
        v
    }

    // ---- M5 (FU-3 persistence): id-counter setters used to restore a loaded snapshot ----
    //
    // The id counters are part of consensus state (a rolled-back op can advance one without leaving an
    // entry — see `state_root`). Persistence captures them via the `peek_next_*` reads and restores
    // them here so a node that stops/restarts has byte-identical state (same root). Concrete-type only
    // (not on the `State` trait): only the persistence layer reaches for them.

    /// Restore the next-stream-id counter (FU-3 load path).
    pub fn set_next_stream_id(&mut self, id: StreamId) {
        self.next_id = id;
    }
    /// Restore the next-case-id counter (FU-3 load path).
    pub fn set_next_case_id(&mut self, id: CaseId) {
        self.next_case_id = id;
    }
    /// Restore the next-contract-id counter (FU-3 load path).
    pub fn set_next_contract_id(&mut self, id: ContractId) {
        self.next_contract_id = id;
    }
    /// Restore the next-exec-case-id counter (FU-3 load path).
    pub fn set_next_exec_case_id(&mut self, id: ExecCaseId) {
        self.next_exec_case_id = id;
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

// ---------------------------------------------------------------------------------------------
// M2: stream operations (spec §"Operations") — deterministic, fail-closed state transitions.
// ---------------------------------------------------------------------------------------------

/// Open a collateralized stream `from → to` at `rate` base units/sec, locking `deposit` (spec D1/D2).
///
/// Steps (any error leaves state **untouched** — fail-closed, no partial writes; we validate fully
/// before mutating):
///   1. Validate: `from != to`, `rate > 0`, `deposit > 0`, `rate ≤ MAX_RATE`. (`deposit % rate == 0`
///      is *recommended* per spec but not required — a partial last tick is allowed and capped.)
///   2. `settle(from, now)`; require `from.settled_balance ≥ deposit`; subtract `deposit` (lock it).
///   3. Mint a `Stream{ id, .., drawn: 0, started_at: now, status: Active }` and index it.
///
/// Returns the assigned [`StreamId`] on success. The sender's deposit is removed up-front, so the
/// recipient's live balance simply adds `accrued(now)` over the stream's lifetime (D3) — no inflow is
/// ever double-counted against the locked collateral.
pub fn open_stream(
    state: &mut dyn State,
    from: &Address,
    to: &Address,
    rate: u128,
    deposit: u128,
    now: u64,
) -> Result<StreamId, StreamError> {
    // 1. Validate everything before touching state (fail-closed).
    if from == to {
        return Err(StreamError::SelfStream);
    }
    if rate == 0 {
        return Err(StreamError::ZeroRate);
    }
    if deposit == 0 {
        return Err(StreamError::ZeroDeposit);
    }
    if rate > MAX_RATE {
        return Err(StreamError::RateTooHigh {
            rate,
            max: MAX_RATE,
        });
    }

    // 2. Settle the sender, then check it can fund the deposit. We compute on a *copy* and only
    //    commit once the stream is fully constructed, so a later error can't leave a debited sender.
    let mut sender = state.get(from).unwrap_or(Account {
        address: *from,
        ..Default::default()
    });
    sender.settle(now);
    if sender.settled_balance < deposit {
        return Err(StreamError::InsufficientBalance {
            have: sender.settled_balance,
            need: deposit,
        });
    }
    sender.settled_balance -= deposit; // lock the collateral

    // 3. Assign id, build + index the stream, then commit the debited sender. Reserving the id last
    //    (after all fallible checks) keeps the counter from advancing on a rejected open.
    let id = state.next_stream_id();
    let stream = Stream {
        id,
        from: *from,
        to: *to,
        rate,
        deposit,
        drawn: 0,
        started_at: now,
        status: StreamStatus::Active,
    };
    state.put(sender);
    state.put_stream(stream);
    Ok(id)
}

/// Internal: fold any newly-accrued amount of stream `id` into the recipient's settled balance and
/// advance `drawn` (spec §`settle_stream`). Idempotent up to `now`: calling it repeatedly at the same
/// (or non-increasing) `now` pays nothing further. Marks the stream `Completed` once fully drawn.
///
/// `owed = accrued(now) - drawn`, where `accrued` is already capped at `deposit` (solvency). The
/// recipient is settled first so its own emission is materialized before we add the stream payment.
/// Returns the amount paid (0 if nothing new accrued or the stream is unknown).
pub fn settle_stream(state: &mut dyn State, id: StreamId, now: u64) -> u128 {
    let Some(mut stream) = state.get_stream(id) else {
        return 0;
    };

    let owed = stream.accrued(now).saturating_sub(stream.drawn);

    // Always settle the recipient's own emission clock forward (even if owed == 0) so a later read is
    // consistent; this never loses value (settle only folds in emission).
    let mut recipient = state.get(&stream.to).unwrap_or(Account {
        address: stream.to,
        ..Default::default()
    });
    recipient.settle(now);

    if owed > 0 {
        recipient.settled_balance = recipient.settled_balance.saturating_add(owed);
        stream.drawn = stream.drawn.saturating_add(owed);
    }
    state.put(recipient);

    // Auto-completion: once fully drawn, mark Completed (unless already stopped — a Stopped stream
    // that happens to be fully drained keeps its Stopped status as the historical record).
    if stream.drawn >= stream.deposit && matches!(stream.status, StreamStatus::Active) {
        stream.status = StreamStatus::Completed;
    }
    state.put_stream(stream);
    owed
}

/// Stop an active stream early (spec §`stopStream`). Only the sender (`caller == from`) may cancel
/// (M2 decision Q2). Pays the recipient everything accrued up to `now`, freezes accrual at `now`
/// (`status = Stopped(now)`), and **refunds the unused deposit** (`deposit - drawn`) to the sender.
///
/// Fail-closed: a wrong caller / unknown / already-inactive stream returns an error and mutates
/// nothing. On success, totals are conserved to the base unit — the recipient gains exactly the
/// accrued-to-stop amount and the sender is refunded the remainder of the locked deposit.
pub fn stop_stream(
    state: &mut dyn State,
    id: StreamId,
    caller: &Address,
    now: u64,
) -> Result<u128, StreamError> {
    let stream = state.get_stream(id).ok_or(StreamError::NoSuchStream(id))?;
    if stream.from != *caller {
        return Err(StreamError::NotSender);
    }
    if !matches!(stream.status, StreamStatus::Active) {
        return Err(StreamError::NotActive);
    }

    // 1. Pay the recipient everything accrued up to `now` (settles `to` internally, bumps `drawn`).
    settle_stream(state, id, now);

    // 2. Re-read the (now partly-drawn) stream, freeze accrual, and refund the remainder to `from`.
    let mut stream = state
        .get_stream(id)
        .expect("stream still present after settle");
    let refund = stream.deposit.saturating_sub(stream.drawn);

    let mut sender = state.get(&stream.from).unwrap_or(Account {
        address: stream.from,
        ..Default::default()
    });
    sender.settle(now);
    sender.settled_balance = sender.settled_balance.saturating_add(refund);
    state.put(sender);

    stream.status = StreamStatus::Stopped(now);
    state.put_stream(stream);
    Ok(refund)
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

    // =========================================================================================
    // M2 — streams (spec 02-streaming.md §"Operations" + acceptance criteria 1–5)
    // =========================================================================================

    /// Seed `addr` as a verified sender with `prefund` UBI already *settled* on top of emission, so
    /// it can afford a deposit immediately. Verified at t=0.
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

    /// SplitMix64 — deterministic PRNG for the property test (reproducible failures, no extern crate).
    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }

    /// Criterion 1 — opening a stream locks the sender's deposit immediately (spendable drops by
    /// exactly `deposit`) and creates an indexed `Active` stream.
    #[test]
    fn open_locks_deposit_and_indexes() {
        let mut s = MemState::new();
        // Sender verified at 0; at t=10h it holds 10 UBI of emission.
        seed(&mut s, addr(1), 0);
        let now = 10 * EMISSION_PERIOD_SECS;
        let deposit = 6 * UBI;
        let rate = UBI / EMISSION_PERIOD_SECS as u128; // 1 UBI/hour

        let pre = s.balance(&addr(1), now);
        let id = open_stream(&mut s, &addr(1), &addr(2), rate, deposit, now).unwrap();
        assert_eq!(id, 0, "first stream id is 0");

        // Sender spendable dropped by exactly the deposit (no double counting of locked collateral).
        assert_eq!(s.balance(&addr(1), now), pre - deposit);
        // Recipient sees nothing yet (no elapsed time).
        assert_eq!(s.balance(&addr(2), now), 0);

        // Indexed both ways; stream is Active.
        assert_eq!(s.outgoing(&addr(1)), vec![0]);
        assert_eq!(s.incoming(&addr(2)), vec![0]);
        let st = s.get_stream(0).unwrap();
        assert_eq!(st.status, StreamStatus::Active);
        assert_eq!(st.deposit, deposit);
        assert_eq!(st.drawn, 0);
    }

    /// Criterion 2 — the recipient's live balance climbs at `rate` while the stream is active, and the
    /// sender's spendable does not double-count the locked deposit.
    #[test]
    fn recipient_balance_climbs_at_rate() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        // Open late enough that the sender's emission alone covers the deposit.
        let open_at = 100 * EMISSION_PERIOD_SECS; // 100 UBI emission accrued
                                                  // Use a rate that makes `rate * elapsed` exact at the sampled instants (1 base unit/sec).
        let rate: u128 = 1;
        let deposit = 5 * UBI;
        open_stream(&mut s, &addr(1), &addr(2), rate, deposit, open_at).unwrap();

        // After `dt` seconds, the recipient has accrued exactly `rate * dt` (unverified ⇒ no emission).
        let dt1 = 1_000u64;
        assert_eq!(s.balance(&addr(2), open_at + dt1), rate * dt1 as u128);
        let dt2 = 2_500u64;
        assert_eq!(s.balance(&addr(2), open_at + dt2), rate * dt2 as u128);

        // Sender spendable = emission_to_now - deposit (deposit stays fully locked, not re-added).
        let now = open_at + dt2;
        let sender_emission = UBI.saturating_mul(now as u128) / EMISSION_PERIOD_SECS as u128;
        assert_eq!(s.balance(&addr(1), now), sender_emission - deposit);
    }

    /// Criterion 3 — solvency cap: accrued never exceeds `deposit`, even arbitrarily far past `t_end`.
    #[test]
    fn accrued_caps_at_deposit_past_t_end() {
        let mut s = MemState::new();
        // Prefund the sender so it can lock the deposit at t=0.
        seed_funded(&mut s, addr(1), 10 * UBI);
        let open_at = 0u64;
        // 1 base unit/sec, deposit = 4*3600 base units ⇒ drains in exactly 4 hours, clean t_end.
        let rate: u128 = 1;
        let deposit = (4 * EMISSION_PERIOD_SECS) as u128;
        open_stream(&mut s, &addr(1), &addr(2), rate, deposit, open_at).unwrap();
        let t_end = s.get_stream(0).unwrap().t_end();
        assert_eq!(t_end, 4 * EMISSION_PERIOD_SECS);

        // Far past t_end (a year), recipient still holds exactly `deposit` — never a base unit more.
        let far = 365 * 24 * EMISSION_PERIOD_SECS;
        assert_eq!(s.balance(&addr(2), far), deposit);
        assert_eq!(s.get_stream(0).unwrap().accrued(far), deposit);
        assert_eq!(s.get_stream(0).unwrap().accrued(u64::MAX), deposit);
    }

    /// Settling a fully-drained stream marks it `Completed` and pays out exactly the deposit (no more).
    #[test]
    fn settle_marks_completed_at_full_drain() {
        let mut s = MemState::new();
        seed_funded(&mut s, addr(1), 10 * UBI);
        let rate: u128 = 1;
        let deposit = (3 * EMISSION_PERIOD_SECS) as u128; // drains in 3 hours, clean
        open_stream(&mut s, &addr(1), &addr(2), rate, deposit, 0).unwrap();

        let after_end = 10 * EMISSION_PERIOD_SECS; // well past the 3h drain
        let paid = settle_stream(&mut s, 0, after_end);
        assert_eq!(paid, deposit, "a full settle pays exactly the deposit");
        assert_eq!(s.get_stream(0).unwrap().status, StreamStatus::Completed);
        assert_eq!(s.get_stream(0).unwrap().drawn, deposit);
        // A second settle pays nothing more (idempotent at the cap).
        assert_eq!(
            settle_stream(&mut s, 0, after_end + EMISSION_PERIOD_SECS),
            0
        );
        assert_eq!(s.balance(&addr(2), u64::MAX), deposit);
    }

    /// Criterion 4 — `stopStream` by the sender pays the accrued-to-stop and refunds the remainder;
    /// totals are conserved exactly (no UBI created or lost).
    #[test]
    fn stop_pays_accrued_refunds_remainder_conserved() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        // 1 base unit/sec; deposit = 10h worth. Stop 3h in ⇒ recipient gets 3h, sender refunded 7h.
        let rate: u128 = 1;
        let hour = EMISSION_PERIOD_SECS as u128;
        let deposit = 10 * hour; // 10h worth of flow
        let open_at = 50 * EMISSION_PERIOD_SECS;
        open_stream(&mut s, &addr(1), &addr(2), rate, deposit, open_at).unwrap();

        let stop_at = open_at + 3 * EMISSION_PERIOD_SECS;
        // Conservation baseline: total system value at stop_at *before* stopping (escrow included).
        let pre_st = s.get_stream(0).unwrap();
        let pre_locked = pre_st.deposit - pre_st.accrued(stop_at);
        let pre_total = s.balance(&addr(1), stop_at) + s.balance(&addr(2), stop_at) + pre_locked;

        let refund = stop_stream(&mut s, 0, &addr(1), stop_at).unwrap();
        assert_eq!(refund, 7 * hour, "unused 7h of deposit refunded");

        assert_eq!(
            s.balance(&addr(2), stop_at),
            3 * hour,
            "recipient paid 3h of flow"
        );
        // Status frozen.
        assert_eq!(
            s.get_stream(0).unwrap().status,
            StreamStatus::Stopped(stop_at)
        );

        // Conservation: total value unchanged by the stop (escrow fully released, just redistributed).
        let post_total = s.balance(&addr(1), stop_at) + s.balance(&addr(2), stop_at);
        assert_eq!(pre_total, post_total, "stop must conserve total value");

        // After stop, the recipient's stream accrual is frozen — no more dripping even much later.
        assert_eq!(
            s.balance(&addr(2), stop_at + 100 * EMISSION_PERIOD_SECS),
            3 * hour
        );
    }

    /// Full lifecycle conservation: open → accrue → stop. No UBI created or lost end to end, measured
    /// against what the sender alone would have held had it never opened the stream.
    #[test]
    fn open_accrue_stop_conserves_no_ubi_created_or_lost() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0);
        let rate: u128 = 3; // 3 base units/sec (exact arithmetic)
        let deposit = 12 * EMISSION_PERIOD_SECS as u128; // affordable from emission past ~12h
        let open_at = 20 * EMISSION_PERIOD_SECS + 1234; // late enough to fund, arbitrary phase
        let stop_at = open_at + 90 * 60; // stop 1.5h in (partial)

        // What the sender would hold at stop_at with NO stream at all (pure emission). After a stop
        // the escrow is fully released, so sender + recipient must equal exactly this baseline.
        let baseline = UBI.saturating_mul(stop_at as u128) / EMISSION_PERIOD_SECS as u128;

        open_stream(&mut s, &addr(1), &addr(2), rate, deposit, open_at).unwrap();
        stop_stream(&mut s, 0, &addr(1), stop_at).unwrap();

        let total = s.balance(&addr(1), stop_at) + s.balance(&addr(2), stop_at);
        assert_eq!(
            total, baseline,
            "open→accrue→stop neither created nor destroyed UBI"
        );
    }

    /// Validation: all the open-time rejections fire and leave state untouched (fail-closed).
    #[test]
    fn open_validation_fails_closed() {
        let mut s = MemState::new();
        seed_funded(&mut s, addr(1), 100 * UBI);
        let now = EMISSION_PERIOD_SECS;
        let rate = UBI / EMISSION_PERIOD_SECS as u128;

        // self-stream
        assert_eq!(
            open_stream(&mut s, &addr(1), &addr(1), rate, UBI, now).unwrap_err(),
            StreamError::SelfStream
        );
        // zero rate / deposit
        assert_eq!(
            open_stream(&mut s, &addr(1), &addr(2), 0, UBI, now).unwrap_err(),
            StreamError::ZeroRate
        );
        assert_eq!(
            open_stream(&mut s, &addr(1), &addr(2), rate, 0, now).unwrap_err(),
            StreamError::ZeroDeposit
        );
        // rate too high
        assert!(matches!(
            open_stream(&mut s, &addr(1), &addr(2), MAX_RATE + 1, UBI, now).unwrap_err(),
            StreamError::RateTooHigh { .. }
        ));
        // insufficient balance: ask for more than the sender holds.
        let have = s.balance(&addr(1), now);
        assert!(matches!(
            open_stream(&mut s, &addr(1), &addr(2), rate, have + UBI, now).unwrap_err(),
            StreamError::InsufficientBalance { .. }
        ));

        // None of the failures created a stream or advanced the id counter.
        assert!(s.streams().is_empty(), "no stream created on any rejection");
        assert_eq!(s.next_stream_id(), 0, "id counter not advanced by failures");
    }

    /// Only the sender may stop; recipient/stranger and double-stop are rejected without mutation.
    #[test]
    fn stop_authorization_and_state() {
        let mut s = MemState::new();
        seed_funded(&mut s, addr(1), 100 * UBI);
        let rate = UBI / EMISSION_PERIOD_SECS as u128;
        open_stream(&mut s, &addr(1), &addr(2), rate, 5 * UBI, 0).unwrap();

        // Recipient cannot cancel (M2: only `from`).
        assert_eq!(
            stop_stream(&mut s, 0, &addr(2), EMISSION_PERIOD_SECS).unwrap_err(),
            StreamError::NotSender
        );
        // Unknown stream id.
        assert_eq!(
            stop_stream(&mut s, 99, &addr(1), EMISSION_PERIOD_SECS).unwrap_err(),
            StreamError::NoSuchStream(99)
        );
        // Sender stops once — ok.
        stop_stream(&mut s, 0, &addr(1), EMISSION_PERIOD_SECS).unwrap();
        // Second stop is rejected (not active).
        assert_eq!(
            stop_stream(&mut s, 0, &addr(1), 2 * EMISSION_PERIOD_SECS).unwrap_err(),
            StreamError::NotActive
        );
    }

    /// Criterion 3/5 — **property test** over random `(rate, deposit, started_at, now, stop?)`.
    /// Invariants asserted on every random stream:
    ///   * solvency: `accrued(now) ≤ deposit` always (never over-draws collateral);
    ///   * conservation: open→[stop]→read leaves `sender + recipient` exactly equal to the sender's
    ///     pure-emission baseline at the read time (no UBI created/lost by streaming);
    ///   * reproducibility (I2): two independently-built states agree to the base unit.
    #[test]
    fn property_streams_solvent_conserved_reproducible() {
        let mut rng = Rng(0x57EA_0001);
        for _ in 0..20_000 {
            // Verified sender at t=0; pick params within solvent, non-overflowing bounds.
            let rate = 1 + rng.below(MAX_RATE.min(u64::MAX as u128) as u64) as u128;
            // Deposit up to ~1000 UBI, but the sender must be able to afford it — prefund generously.
            let deposit = 1 + rng.below(1_000 * (UBI as u64 / 1_000)) as u128 * 1_000;
            let open_at = rng.below(1_000_000_000);
            let life = rng.below(2_000_000); // seconds the stream may run before we read
            let now = open_at + life;
            let do_stop = rng.below(2) == 1;
            // Stop somewhere within [open_at, now].
            let stop_at = open_at + if life == 0 { 0 } else { rng.below(life + 1) };

            // Build two independent states from the same params (I2 reproducibility check).
            let build = |stop: bool| -> (MemState, Option<u128>) {
                let mut s = MemState::new();
                // Prefund enough to always afford the deposit.
                seed_funded(&mut s, addr(1), deposit + 10 * UBI);
                open_stream(&mut s, &addr(1), &addr(2), rate, deposit, open_at).unwrap();
                let refund = if stop {
                    Some(stop_stream(&mut s, 0, &addr(1), stop_at).unwrap())
                } else {
                    None
                };
                (s, refund)
            };

            let (sa, refund_a) = build(do_stop);
            let (sb, refund_b) = build(do_stop);

            // Solvency: gross accrued never exceeds the deposit.
            let acc = sa.get_stream(0).unwrap().accrued(now);
            assert!(
                acc <= deposit,
                "solvency violated: accrued {acc} > deposit {deposit} (rate={rate}, open={open_at}, now={now})"
            );

            // Reproducibility: both nodes agree on both balances and the refund, to the base unit.
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

            // Conservation: sender + recipient + still-locked escrow == the system's total value at
            // `now` = the sender's prefund (`deposit + 10*UBI`, settled at t=0) plus its emission to
            // `now`. (The recipient is unverified, so contributes no emission of its own; the stream
            // merely redistributes the sender's collateral.) For a stopped/completed stream the escrow
            // is fully released (refund to sender, or fully paid to recipient), so `locked` is 0; for
            // an in-flight `Active` stream `deposit - accrued(now)` is still in escrow — value neither
            // spendable by the sender nor yet owned by the recipient.
            let prefund = deposit + 10 * UBI;
            let baseline = prefund + UBI.saturating_mul(now as u128) / EMISSION_PERIOD_SECS as u128;
            let st = sa.get_stream(0).unwrap();
            let locked = match st.status {
                StreamStatus::Active => st.deposit.saturating_sub(st.accrued(now)),
                StreamStatus::Stopped(_) | StreamStatus::Completed => 0,
            };
            let total = sa.balance(&addr(1), now) + sa.balance(&addr(2), now) + locked;
            // Conservation is exact up to the documented F1 settlement-rounding loss: because
            // `UBI (10^18) % EMISSION_PERIOD_SECS (3600) != 0`, each non-hour-aligned `settle()` drops
            // a sub-unit (≤1 base unit) remainder that does not carry forward (see
            // `crates/runtime/tests/i2_determinism.rs` P2a / reliability finding F1). The stream
            // lifecycle settles the sender at most twice (open + stop) and the recipient at most twice
            // (the stop's `settle_stream` + the final read folds nothing new), so the loss is bounded
            // by a small constant and is always a *loss* (UBI is never created). This is deterministic
            // (same op-sequence ⇒ same result, verified by the reproducibility assert above), so it
            // does not break I2's node-agreement requirement.
            const MAX_SETTLE_LOSS: u128 = 4;
            assert!(
                total <= baseline,
                "conservation CREATED value: total {total} > baseline {baseline} (stop={do_stop}, stop_at={stop_at}, rate={rate}, deposit={deposit}, open={open_at}, now={now})"
            );
            assert!(
                baseline - total <= MAX_SETTLE_LOSS,
                "conservation lost more than F1 bound: lost {} (>{MAX_SETTLE_LOSS}) (stop={do_stop}, stop_at={stop_at}, rate={rate}, deposit={deposit}, open={open_at}, now={now})",
                baseline - total
            );
        }
    }

    // =========================================================================================
    // Fee model — a real, deterministic UBI gas fee on every tx (M5 fee-recycling foundation).
    // =========================================================================================

    /// `fee_for_gas` is exact integer math: `gas * GAS_PRICE_WEI`, with the documented per-kind values.
    #[test]
    fn fee_for_gas_is_per_kind_integer_math() {
        assert_eq!(fee_for_gas(GAS_TRANSFER), 21_000 * GAS_PRICE_WEI);
        assert_eq!(fee_for_gas(GAS_STREAM), 60_000 * GAS_PRICE_WEI);
        assert_eq!(fee_for_gas(GAS_HUMANITY), 80_000 * GAS_PRICE_WEI);
        assert_eq!(fee_for_gas(GAS_CONTRACT), 120_000 * GAS_PRICE_WEI);
        // Onboarding is fee-exempt (bootstrap gate): a zero-gas tx costs nothing.
        assert_eq!(fee_for_gas(GAS_ONBOARD), 0);
        // A transfer fee is ~2.1e13 base units — tiny vs the 1e18/hour emission, so a verified human
        // always covers it after a few seconds of streaming.
        assert_eq!(fee_for_gas(GAS_TRANSFER), 21_000_000_000_000);
    }

    /// Charging a fee debits the sender by exactly `fee` and credits the TREASURY by exactly `fee` —
    /// total supply is conserved to the base unit (sender → treasury, value never leaves the system).
    #[test]
    fn charge_fee_conserves_sender_to_treasury() {
        let mut s = MemState::new();
        seed_funded(&mut s, addr(1), 10 * UBI);
        let now = EMISSION_PERIOD_SECS;
        let pre_total = s.balance(&addr(1), now) + s.balance(&TREASURY, now);

        let fee = charge_fee(&mut s, &addr(1), GAS_CONTRACT, now).unwrap();
        assert_eq!(fee, fee_for_gas(GAS_CONTRACT));
        assert_eq!(
            s.balance(&TREASURY, now),
            fee,
            "treasury credited exactly the fee"
        );
        let post_total = s.balance(&addr(1), now) + s.balance(&TREASURY, now);
        assert_eq!(pre_total, post_total, "fee conserves total supply exactly");
    }

    /// A fee charge settles the sender's emission first, so the insufficiency check runs on the
    /// materialized balance — a verified account with enough streamed UBI pays even with 0 prefund.
    #[test]
    fn charge_fee_settles_emission_before_charging() {
        let mut s = MemState::new();
        seed(&mut s, addr(1), 0); // verified at t=0, no prefund
                                  // After 1 hour it has streamed exactly 1 UBI — ample for any fee.
        let fee = charge_fee(&mut s, &addr(1), GAS_TRANSFER, EMISSION_PERIOD_SECS).unwrap();
        assert_eq!(fee, fee_for_gas(GAS_TRANSFER));
        assert_eq!(
            s.get(&addr(1)).unwrap().settled_balance,
            UBI - fee,
            "sender pays the fee out of settled emission"
        );
    }

    /// Insufficient balance for the fee is rejected (fail-closed, I4): no debit, no treasury credit,
    /// and a clear error carrying the shortfall.
    #[test]
    fn charge_fee_insufficient_is_rejected_without_mutation() {
        let mut s = MemState::new();
        // Unverified, zero-balance account cannot pay a non-zero fee.
        s.put(Account {
            address: addr(1),
            ..Default::default()
        });
        let now = 5 * EMISSION_PERIOD_SECS;
        let err = charge_fee(&mut s, &addr(1), GAS_TRANSFER, now).unwrap_err();
        assert_eq!(
            err,
            FeeError::InsufficientForFee {
                have: 0,
                fee: fee_for_gas(GAS_TRANSFER)
            }
        );
        // Nothing moved: sender still 0, treasury untouched.
        assert_eq!(s.balance(&addr(1), now), 0);
        assert_eq!(s.balance(&TREASURY, now), 0);
    }

    /// A zero-gas (onboarding) charge always succeeds even from a zero balance and moves nothing — the
    /// bootstrap gate a brand-new, not-yet-verified human passes through.
    #[test]
    fn charge_zero_gas_fee_is_free_for_onboarding() {
        let mut s = MemState::new();
        s.put(Account {
            address: addr(1),
            ..Default::default()
        });
        let now = 0;
        let fee = charge_fee(&mut s, &addr(1), GAS_ONBOARD, now).unwrap();
        assert_eq!(fee, 0, "onboarding is fee-exempt");
        assert_eq!(s.balance(&TREASURY, now), 0, "treasury unchanged");
    }

    /// The TREASURY is a documented system address distinct from every hub, and it never streams
    /// emission (it is unverified) — value only ever flows *into* it via fees.
    #[test]
    fn treasury_is_a_distinct_unverified_system_account() {
        assert_ne!(TREASURY, CONTRACT_HUB);
        let mut s = MemState::new();
        // After collecting a fee, the treasury holds it and does not accrue emission over time.
        seed_funded(&mut s, addr(1), 10 * UBI);
        charge_fee(&mut s, &addr(1), GAS_CONTRACT, 0).unwrap();
        let at_open = s.balance(&TREASURY, 0);
        let a_year = s.balance(&TREASURY, 365 * 24 * EMISSION_PERIOD_SECS);
        assert_eq!(at_open, a_year, "treasury never streams (unverified)");
    }
}
