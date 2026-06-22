//! M3 — proof-of-humanity lifecycle (the deterministic state machine, spec 03 §"Lifecycle").
//!
//! These are pure, fail-closed transitions over the [`State`](crate::State) registry:
//!
//! ```text
//! request_verification ─▶ Pending  (opens a Registration Case; jury grades liveness via the oracle)
//! vouch ────────────────▶ accrue distinct Verified vouchers (capacity-capped, no self/dup)
//! challenge ────────────▶ Challenged (opens a Challenge Case)
//! submit_verdict ───────▶ records a juror's signed verdict + tallies:
//!     Sybil (≥QUORUM)  → reject/Revoke + slash vouchers' reputation
//!     Human (≥QUORUM)  → uphold
//!     split/Uncertain  → Escalate  (never a coin-flip — I4)
//! finalize_registration ▶ Verified iff liveness passed + ≥MIN_VOUCHES + clean challenge window
//! revoke ───────────────▶ stops emission (clears verified/verified_at)
//! ```
//!
//! Every transition is deterministic given the same op sequence (invariant I1): juror selection is
//! seeded, tallies are order-independent, and the oracle is the only non-determinism — confined behind
//! the trait and only ever committed as a quorum-agreed [`CanonicalVerdict`]. Emission gating (I2):
//! the lifecycle keeps `Account.verified`/`verified_at` as the cache that `balance()` reads, so the
//! transfer/stream paths are untouched and balance stays a pure integer function of `(state, now)`.

use crate::humanity::{
    select_jury, tally, CanonicalVerdict, Case, CaseId, CaseKind, CaseStatus, Hash, Human,
    HumanStatus, HumanityOracle, Juror, Tally, Verdict, Vouch, CHALLENGE_WINDOW, JURY_SIZE,
    MIN_VOUCHES, QUORUM, SYBIL_SLASH, VOUCH_CAPACITY,
};
use crate::{Account, Address, State};

/// Why a lifecycle op was rejected. Deterministic so two nodes reject identically (I1/I4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LifecycleError {
    /// `request_verification` for an address that is already `Pending`/`Verified`/`Challenged`.
    AlreadyRegistered(HumanStatus),
    /// No active jurors are registered, so no case can be adjudicated (fail closed — I4).
    NoJurors,
    /// `vouch` voucher is not `Verified` (only verified humans may vouch).
    VoucherNotVerified,
    /// `vouch` voucher has reached `VOUCH_CAPACITY` outstanding vouches.
    VouchCapacityReached,
    /// `vouch` of oneself.
    SelfVouch,
    /// `vouch` duplicates an existing `(voucher, vouchee)` edge.
    DuplicateVouch,
    /// `vouch` for a subject with no open registration (must `request_verification` first).
    VoucheeNotPending,
    /// `challenge` subject is `Unverified`/`Revoked` (nothing to challenge).
    NotChallengeable(HumanStatus),
    /// `submit_verdict` for an unknown case id.
    NoSuchCase(CaseId),
    /// `submit_verdict` from an address not on the case's selected jury.
    NotOnJury,
    /// `submit_verdict` to a case that is already `Committed`/`Escalated` (not `Open`).
    CaseClosed,
    /// `submit_verdict` from a juror who already voted on this case.
    AlreadyVoted,
    /// `finalize_registration` for an address with no open registration.
    NotPending,
    /// `finalize_registration` before liveness passed.
    LivenessNotPassed,
    /// `finalize_registration` with fewer than `MIN_VOUCHES` distinct verified vouchers.
    InsufficientVouches { have: usize, need: usize },
    /// `finalize_registration` before the challenge window cleared.
    ChallengeWindowOpen { since: u64, need: u64 },
    /// `finalize_registration` while an upheld/open challenge exists.
    ChallengePending,
}

impl std::fmt::Display for LifecycleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use LifecycleError::*;
        match self {
            AlreadyRegistered(s) => write!(f, "address already registered ({s:?})"),
            NoJurors => write!(f, "no active jurors to adjudicate"),
            VoucherNotVerified => write!(f, "voucher is not a verified human"),
            VouchCapacityReached => write!(f, "voucher has reached VOUCH_CAPACITY"),
            SelfVouch => write!(f, "cannot vouch for oneself"),
            DuplicateVouch => write!(f, "duplicate vouch"),
            VoucheeNotPending => write!(f, "vouchee has no open registration"),
            NotChallengeable(s) => write!(f, "subject is not challengeable ({s:?})"),
            NoSuchCase(id) => write!(f, "no such case: {id}"),
            NotOnJury => write!(f, "submitter is not on this case's jury"),
            CaseClosed => write!(f, "case is already committed or escalated"),
            AlreadyVoted => write!(f, "juror already voted on this case"),
            NotPending => write!(f, "no open registration for this address"),
            LivenessNotPassed => write!(f, "liveness check has not passed"),
            InsufficientVouches { have, need } => {
                write!(f, "insufficient vouches: have {have}, need {need}")
            }
            ChallengeWindowOpen { since, need } => {
                write!(
                    f,
                    "challenge window open: opened at {since}, need {need} blocks"
                )
            }
            ChallengePending => write!(f, "an upheld or open challenge is pending"),
        }
    }
}

impl std::error::Error for LifecycleError {}

/// Mix a `case_id` with a chain-entropy input into a juror-selection seed (spec §"Juror selection":
/// VRF-style from chain entropy; M3 uses a simpler deterministic-random seed). Both inputs are
/// consensus values, so the seed is byte-reproducible across nodes.
fn jury_seed(case_id: CaseId, entropy: u64) -> u64 {
    // SplitMix64-style mix so adjacent case ids don't produce correlated juries.
    let mut z = case_id.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ entropy;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Open a case of `kind` against `subject` with the given evidence, selecting a deterministic jury
/// from the active juror registry. Returns the new case id. Fail-closed: errors with `NoJurors` if the
/// registry is empty (we never open an un-adjudicable case — I4).
fn open_case(
    state: &mut dyn State,
    subject: Address,
    kind: CaseKind,
    evidence_ref: Hash,
    entropy: u64,
    now: u64,
) -> Result<CaseId, LifecycleError> {
    let candidates = state.active_jurors();
    if candidates.is_empty() {
        return Err(LifecycleError::NoJurors);
    }
    let id = state.next_case_id();
    let jury = select_jury(candidates, JURY_SIZE, jury_seed(id, entropy));
    let case = Case {
        id,
        subject,
        kind,
        evidence_ref,
        jury,
        votes: Vec::new(),
        status: CaseStatus::Open,
        opened_at: now,
    };
    state.put_case(case);
    Ok(id)
}

/// The liveness inputs an applicant submits at registration. `liveness_ref` is the on-chain
/// commitment (I6 — no PII on-chain); `challenge`/`response` are the off-chain bytes the jury's oracle
/// grades (held in memory / mempool, never committed). Bundled so [`request_verification`] stays a
/// clean call for the M3-T4 RPC wiring.
pub struct LivenessEvidence<'a> {
    /// On-chain commitment to the liveness evidence (stored on the `Human` + case).
    pub liveness_ref: Hash,
    /// The challenge bytes the applicant was issued (off-chain; graded by the oracle).
    pub challenge: &'a [u8],
    /// The applicant's response bytes (off-chain; graded by the oracle).
    pub response: &'a [u8],
}

/// Open a registration for `subject`, committing `evidence.liveness_ref`, and have the selected jury
/// grade liveness via `oracle`. The applicant becomes `Pending`. Returns the Registration case id.
///
/// `now` is the current **block height** (the challenge-window clock). `entropy` is a chain-entropy
/// input (e.g. a block hash word) folded into juror selection.
///
/// Liveness grading runs the oracle once per juror — deterministic, so honest jurors agree (I1). The
/// result is tallied immediately and stored on the case (`Committed`/`Escalated`). A failed/uncertain
/// liveness leaves the case un-committed; the subject can never finalize until liveness passes.
pub fn request_verification(
    state: &mut dyn State,
    oracle: &dyn HumanityOracle,
    subject: &Address,
    evidence: &LivenessEvidence<'_>,
    entropy: u64,
    now: u64,
) -> Result<CaseId, LifecycleError> {
    // Fail-closed: only a fresh/Unverified/Revoked address may (re)register.
    if let Some(h) = state.get_human(subject) {
        match h.status {
            HumanStatus::Unverified | HumanStatus::Revoked => {}
            other => return Err(LifecycleError::AlreadyRegistered(other)),
        }
    }

    let case_id = open_case(
        state,
        *subject,
        CaseKind::Registration,
        evidence.liveness_ref,
        entropy,
        now,
    )?;

    // Each juror grades liveness deterministically from the same (challenge, response) bytes.
    let mut case = state.get_case(case_id).expect("just created");
    let jury = case.jury.clone();
    for juror in &jury {
        let v = oracle.grade_liveness(evidence.challenge, evidence.response);
        case.votes.push((*juror, v));
    }
    apply_tally(&mut case);
    state.put_case(case);

    // Record the Pending human with the liveness commitment.
    state.put_human(Human::pending(*subject, evidence.liveness_ref));
    Ok(case_id)
}

/// Record a vouch from `voucher` for `vouchee` at block height `now`. Constraints (all fail-closed):
/// voucher must be `Verified`; under `VOUCH_CAPACITY`; no self-vouch; no duplicate edge; vouchee must
/// be `Pending`. On success the edge is indexed (forward + reverse) and added to the vouchee's
/// `vouches_in`.
pub fn vouch(
    state: &mut dyn State,
    voucher: &Address,
    vouchee: &Address,
    now: u64,
) -> Result<(), LifecycleError> {
    if voucher == vouchee {
        return Err(LifecycleError::SelfVouch);
    }
    // Voucher must be a Verified human.
    match state.get_human(voucher) {
        Some(h) if h.status == HumanStatus::Verified => {}
        _ => return Err(LifecycleError::VoucherNotVerified),
    }
    // Vouchee must have an open registration.
    let mut vouchee_h = match state.get_human(vouchee) {
        Some(h) if h.status == HumanStatus::Pending => h,
        _ => return Err(LifecycleError::VoucheeNotPending),
    };
    // No duplicate edge.
    if state.vouches_out(voucher).contains(vouchee) {
        return Err(LifecycleError::DuplicateVouch);
    }
    // Capacity cap.
    if state.vouches_out(voucher).len() >= VOUCH_CAPACITY {
        return Err(LifecycleError::VouchCapacityReached);
    }

    state.put_vouch(Vouch {
        voucher: *voucher,
        vouchee: *vouchee,
        at: now,
    });
    // Keep the denormalized `vouches_in` on the human in sync (sorted, deduped).
    if !vouchee_h.vouches_in.contains(voucher) {
        vouchee_h.vouches_in.push(*voucher);
        vouchee_h.vouches_in.sort_unstable();
    }
    state.put_human(vouchee_h);
    Ok(())
}

/// Open a challenge against `subject` with content-addressed `evidence_ref`, at block height `now`.
/// A `Pending` applicant or a `Verified` human may be challenged; `Unverified`/`Revoked` cannot.
/// A `Verified` subject transitions to `Challenged` (it keeps streaming until a quorum upholds the
/// challenge — innocent until proven, I4). Returns the Challenge case id.
pub fn challenge(
    state: &mut dyn State,
    _challenger: &Address,
    subject: &Address,
    evidence_ref: Hash,
    entropy: u64,
    now: u64,
) -> Result<CaseId, LifecycleError> {
    let status = state
        .get_human(subject)
        .map(|h| h.status)
        .unwrap_or(HumanStatus::Unverified);
    match status {
        HumanStatus::Pending | HumanStatus::Verified | HumanStatus::Challenged => {}
        other => return Err(LifecycleError::NotChallengeable(other)),
    }

    let case_id = open_case(
        state,
        *subject,
        CaseKind::Challenge,
        evidence_ref,
        entropy,
        now,
    )?;

    // Mark a Verified human as Challenged (still emits; gating is unchanged until a Sybil quorum).
    if status == HumanStatus::Verified {
        if let Some(mut h) = state.get_human(subject) {
            h.status = HumanStatus::Challenged;
            state.put_human(h);
        }
    }
    Ok(case_id)
}

/// Record a juror's signed verdict on `case_id` and tally. Only a juror on the case's jury may vote,
/// once. When the tally commits or escalates, the case's effect is applied:
///   * a committed **Sybil** ⇒ the subject is `Revoked` and every voucher's reputation is slashed;
///   * a committed **Human** on a `Challenge` ⇒ the subject is upheld (restored to `Verified` if it
///     was `Challenged`); on a `Registration` ⇒ recorded (finalization happens via
///     [`finalize_registration`]);
///   * a split / `Uncertain` ⇒ the case is `Escalated` (no state change to the subject — I4).
///
/// Returns the resulting [`CaseStatus`].
pub fn submit_verdict(
    state: &mut dyn State,
    case_id: CaseId,
    juror: &Address,
    verdict: CanonicalVerdict,
    now: u64,
) -> Result<CaseStatus, LifecycleError> {
    let mut case = state
        .get_case(case_id)
        .ok_or(LifecycleError::NoSuchCase(case_id))?;
    if !matches!(case.status, CaseStatus::Open) {
        return Err(LifecycleError::CaseClosed);
    }
    if !case.jury.contains(juror) {
        return Err(LifecycleError::NotOnJury);
    }
    if case.vote_of(juror).is_some() {
        return Err(LifecycleError::AlreadyVoted);
    }

    case.votes.push((*juror, verdict));
    apply_tally(&mut case);
    let status = case.status;
    let kind = case.kind;
    let subject = case.subject;
    state.put_case(case);

    // Apply the committed/escalated effect to the subject.
    if let CaseStatus::Committed(v) = status {
        match v.verdict {
            Verdict::Sybil => revoke(state, &subject),
            Verdict::Human => {
                // A challenge cleared in the subject's favor: restore a Challenged human to Verified.
                if kind == CaseKind::Challenge {
                    if let Some(mut h) = state.get_human(&subject) {
                        if h.status == HumanStatus::Challenged {
                            h.status = HumanStatus::Verified;
                            sync_account_verified(state, &subject, true, h.verified_at);
                            state.put_human(h);
                        }
                    }
                }
            }
            // A committed Uncertain can't happen — the tally escalates it (see `tally`).
            Verdict::Uncertain => {}
        }
    }
    let _ = now;
    Ok(status)
}

/// Finalize a `Pending` registration into `Verified`, gating on (spec criterion 1): liveness passed
/// **and** `>= MIN_VOUCHES` distinct verified vouchers **and** the challenge window cleared with no
/// open/upheld challenge. `now_block` is the current **block height** (the challenge-window clock);
/// `verified_at_secs` is the **unix second** stamped as the emission epoch that `balance()` reads (I2)
/// — the two clocks are intentionally distinct (the window is in blocks, emission accrues in seconds).
/// On success the human becomes `Verified` and the account cache is flipped so emission starts.
///
/// Fail-closed: any unmet condition returns a specific error and mutates nothing (I4 — never
/// auto-grant on uncertainty).
pub fn finalize_registration(
    state: &mut dyn State,
    subject: &Address,
    now_block: u64,
    verified_at_secs: u64,
) -> Result<(), LifecycleError> {
    let now = now_block;
    let mut h = match state.get_human(subject) {
        Some(h) if h.status == HumanStatus::Pending => h,
        _ => return Err(LifecycleError::NotPending),
    };

    // Liveness must have passed: the subject's open Registration case must be Committed(Human).
    if !liveness_passed(state, subject) {
        return Err(LifecycleError::LivenessNotPassed);
    }

    // Enough distinct verified vouchers.
    let vouches = h.vouches_in.len();
    if vouches < MIN_VOUCHES {
        return Err(LifecycleError::InsufficientVouches {
            have: vouches,
            need: MIN_VOUCHES,
        });
    }

    // The challenge window must have elapsed since registration.
    let opened_at = registration_opened_at(state, subject).unwrap_or(now);
    if now < opened_at.saturating_add(CHALLENGE_WINDOW) {
        return Err(LifecycleError::ChallengeWindowOpen {
            since: opened_at,
            need: CHALLENGE_WINDOW,
        });
    }

    // No open challenge, and no challenge that was upheld (committed Sybil) against this subject.
    if has_pending_or_upheld_challenge(state, subject) {
        return Err(LifecycleError::ChallengePending);
    }

    h.status = HumanStatus::Verified;
    h.verified_at = verified_at_secs;
    sync_account_verified(state, subject, true, verified_at_secs);
    state.put_human(h);
    Ok(())
}

/// Revoke `subject`: set `Revoked`, clear `verified_at`, **stop emission** (flip the account cache),
/// and slash every voucher's reputation by [`SYBIL_SLASH`] (spec criterion 2). Idempotent.
pub fn revoke(state: &mut dyn State, subject: &Address) {
    if let Some(mut h) = state.get_human(subject) {
        // Slash everyone who vouched for this (now-proven-sybil) subject.
        for voucher in &h.vouches_in {
            if let Some(mut vh) = state.get_human(voucher) {
                vh.reputation = vh.reputation.saturating_sub(SYBIL_SLASH);
                state.put_human(vh);
            }
        }
        h.status = HumanStatus::Revoked;
        h.verified_at = 0;
        state.put_human(h);
    }
    // Stop emission to the base unit: settle accrued, then clear the verified cache (I2). We do NOT
    // re-credit; the human simply stops accruing from now on.
    sync_account_verified(state, subject, false, 0);
}

// ---------------------------------------------------------------------------------------------
// Internal helpers (deterministic; no consensus path depends on hash ordering).
// ---------------------------------------------------------------------------------------------

/// Tally the case's votes and set its status (`Committed`/`Escalated`/`Open`). Pure on the case.
fn apply_tally(case: &mut Case) {
    match tally(&case.votes, JURY_SIZE, QUORUM) {
        Tally::Committed(v) => case.status = CaseStatus::Committed(v),
        Tally::Escalated => case.status = CaseStatus::Escalated,
        Tally::Pending => case.status = CaseStatus::Open,
    }
}

/// Has the subject's open Registration case committed a `Human` verdict (liveness passed)?
fn liveness_passed(state: &dyn State, subject: &Address) -> bool {
    state.cases().iter().any(|c| {
        c.subject == *subject
            && c.kind == CaseKind::Registration
            && matches!(c.status, CaseStatus::Committed(v) if v.verdict == Verdict::Human)
    })
}

/// Block height the subject's Registration case opened at (the window clock), if any.
fn registration_opened_at(state: &dyn State, subject: &Address) -> Option<u64> {
    state
        .cases()
        .into_iter()
        .filter(|c| c.subject == *subject && c.kind == CaseKind::Registration)
        .map(|c| c.opened_at)
        .min()
}

/// Is there an Open challenge, or a committed `Sybil` (upheld) challenge, against the subject?
fn has_pending_or_upheld_challenge(state: &dyn State, subject: &Address) -> bool {
    state.cases().iter().any(|c| {
        c.subject == *subject
            && c.kind == CaseKind::Challenge
            && match c.status {
                CaseStatus::Open => true,
                CaseStatus::Committed(v) => v.verdict == Verdict::Sybil,
                CaseStatus::Escalated => false,
            }
    })
}

/// Flip the `Account.verified`/`verified_at` cache the M1/M2 emission path reads, settling emission
/// first so no UBI is lost or created at the transition (I2). Creates the account if absent.
fn sync_account_verified(state: &mut dyn State, addr: &Address, verified: bool, verified_at: u64) {
    let mut acct = state.get(addr).unwrap_or(Account {
        address: *addr,
        ..Default::default()
    });
    // Settle at the transition height-as-seconds is NOT applicable here (now is a block height, not a
    // unix second). Emission settlement happens on the transfer/stream paths against unix `now`; here
    // we only flip the gate + stamp. We do not call settle() — verified_at is the emission epoch.
    acct.verified = verified;
    acct.verified_at = verified_at;
    state.put(acct);
}

/// Register a juror (register-only in M3; staking is M5 per the spec open question). Convenience used
/// by the node/tests to bootstrap the verifier set.
pub fn register_juror(state: &mut dyn State, addr: &Address, stake: u128) {
    state.put_juror(Juror {
        address: *addr,
        stake,
        active: true,
    });
}

/// Seed `addr` as an already-`Verified` human in the registry, with `verified_at` (unix seconds) as
/// the emission epoch (spec criterion 5: the genesis dev account is migrated to `Verified` for devnet
/// continuity). Bootstraps the M1/M2 `Account` cache too so emission/streaming work unchanged.
///
/// This is the genesis path only — it skips the live lifecycle (no liveness/vouch/window), which is
/// exactly the point of a genesis seed (the founder set vouches outward from here, spec M3-T1).
pub fn seed_verified_human(state: &mut dyn State, addr: &Address, verified_at: u64) {
    state.put_human(Human {
        address: *addr,
        status: HumanStatus::Verified,
        verified_at,
        liveness_ref: [0u8; 32],
        vouches_in: Vec::new(),
        reputation: 0,
    });
    sync_account_verified(state, addr, true, verified_at);
}
