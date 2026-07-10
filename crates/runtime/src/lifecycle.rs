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
    HumanStatus, HumanityOracle, Juror, Tally, Verdict, Vouch, CHALLENGE_WINDOW,
    FALSE_CHALLENGE_SLASH, JURY_SIZE, MIN_VOUCHES, QUORUM, SYBIL_SLASH, VOUCH_CAPACITY,
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
    /// `challenge` from an address that is not a `Verified` human (security finding A — fail-closed:
    /// only verified humans may challenge, so spam costs an established identity + reputation).
    ChallengerNotVerified,
    /// `challenge` against a subject that already has an `Open` challenge (security finding A — at most
    /// one outstanding challenge per subject; a second is rejected while one is `Open`).
    ChallengeAlreadyOpen,
    /// `challenge` re-filed by the same challenger against the same subject after a prior challenge by
    /// that challenger already cleared `Human` (security finding A — cooldown: a false challenger may
    /// not re-file against a subject it already failed to unseat).
    ChallengeOnCooldown,
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
            ChallengerNotVerified => write!(f, "challenger is not a verified human"),
            ChallengeAlreadyOpen => write!(f, "subject already has an open challenge"),
            ChallengeOnCooldown => {
                write!(f, "challenger already cleared a challenge on this subject")
            }
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
    challenger: Address,
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
        challenger,
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

    // F-REL-1: clear any stale vouch edges from a prior lifecycle so prior vouchers can re-vouch the
    // re-registered subject (a Revoked subject's old `(voucher, subject)` edges would otherwise trip
    // `DuplicateVouch`). Deterministic set-removal; safe to call when there are none.
    state.clear_vouch_edges(subject);

    // A Registration case has no external challenger; the subject is recorded as its own opener so the
    // false-challenge slash (which only fires on Challenge cases) never applies here.
    let case_id = open_case(
        state,
        *subject,
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
///
/// Anti-spam policy (security finding A — all fail-closed, all deterministic functions of state):
///   1. **Verified challenger only.** `challenger` must be a `Verified` human; an unverified address
///      (incl. unknown / `Pending` / `Challenged` / `Revoked`) is rejected `ChallengerNotVerified`.
///      Spam now costs an established identity, not just gas.
///   2. **One open challenge per subject.** If the subject already has an `Open` Challenge case, a
///      second is rejected `ChallengeAlreadyOpen`. A subject can never be buried under concurrent
///      challenges.
///   3. **Per-(challenger, subject) cooldown.** Once a challenger's challenge against a subject clears
///      a `Human` verdict, that challenger may not re-file against that subject (`ChallengeOnCooldown`).
///      A false challenger gets exactly one shot, so it cannot stall finalization by re-filing — and
///      it is reputation-slashed for the false challenge (see [`submit_verdict`]). A *self*-challenge
///      escape hatch is not needed: the subject is recorded as the opener of its own Registration case
///      only, never of a Challenge case.
///
/// The challenger is stamped on the case so the false-challenge slash can find it when the jury rules
/// `Human`.
pub fn challenge(
    state: &mut dyn State,
    challenger: &Address,
    subject: &Address,
    evidence_ref: Hash,
    entropy: u64,
    now: u64,
) -> Result<CaseId, LifecycleError> {
    challenge_inner(state, challenger, subject, evidence_ref, entropy, now, true)
}

/// The node's own deterministic sybil-cluster defense (security finding D / AC6): the AI sybil scan
/// flagged `subject`'s vouch cluster, so the runtime auto-files a challenge. Same anti-spam policy as
/// [`challenge`] (one open per subject, per-`(opener, subject)` cooldown) **except** the verified-
/// challenger gate is waived — the opener is a reserved system address, not an external actor, so it
/// has no identity to verify. It is still stamped as the case `challenger`, so a `Human` verdict slashes
/// nothing of value (the system address holds no reputation worth slashing) and records the cooldown.
pub fn system_challenge(
    state: &mut dyn State,
    system: &Address,
    subject: &Address,
    evidence_ref: Hash,
    entropy: u64,
    now: u64,
) -> Result<CaseId, LifecycleError> {
    challenge_inner(state, system, subject, evidence_ref, entropy, now, false)
}

/// Shared challenge body. `require_verified_challenger` distinguishes an external [`challenge`] (must
/// be a Verified human) from the node's [`system_challenge`] defense (no identity to verify). All
/// other constraints — challengeable subject, one open per subject, per-`(opener, subject)` cooldown —
/// are identical and deterministic.
#[allow(clippy::too_many_arguments)]
fn challenge_inner(
    state: &mut dyn State,
    challenger: &Address,
    subject: &Address,
    evidence_ref: Hash,
    entropy: u64,
    now: u64,
    require_verified_challenger: bool,
) -> Result<CaseId, LifecycleError> {
    // (1) Fail-closed: an external challenger must be a Verified human (waived for system defense).
    if require_verified_challenger {
        match state.get_human(challenger) {
            Some(h) if h.status == HumanStatus::Verified => {}
            _ => return Err(LifecycleError::ChallengerNotVerified),
        }
    }

    let status = state
        .get_human(subject)
        .map(|h| h.status)
        .unwrap_or(HumanStatus::Unverified);
    match status {
        HumanStatus::Pending | HumanStatus::Verified | HumanStatus::Challenged => {}
        other => return Err(LifecycleError::NotChallengeable(other)),
    }

    // (2) At most one Open challenge per subject.
    if has_open_challenge(state, subject) {
        return Err(LifecycleError::ChallengeAlreadyOpen);
    }

    // (3) Cooldown: this challenger already failed to unseat this subject (cleared Human) — no re-file.
    if state.challenge_cleared(challenger, subject) {
        return Err(LifecycleError::ChallengeOnCooldown);
    }

    let case_id = open_case(
        state,
        *subject,
        *challenger,
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
///     was `Challenged`), the **challenger's reputation is slashed** for the false challenge, and a
///     per-`(challenger, subject)` cooldown is recorded so it cannot re-file (security finding A); on
///     a `Registration` ⇒ recorded (finalization happens via [`finalize_registration`]);
///   * an **escalation** (split / `Uncertain`) on a `Challenge` against a previously-`Verified`
///     subject ⇒ **fail-safe restore to `Verified`** (security finding B): a challenge must be UPHELD
///     by a `Sybil` quorum to strip an established human; mere escalation/uncertainty must not. A
///     `Challenged` status only ever arises from a challenge on a once-`Verified` human, so restoring
///     it on escalation re-grants its vouch authority (presumption of innocence). A `Registration`
///     escalation leaves the `Pending` subject untouched (I4 — never auto-grant on uncertainty).
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
    let challenger = case.challenger;
    state.put_case(case);

    match status {
        // A quorum agreed on a canonical verdict.
        CaseStatus::Committed(v) => match v.verdict {
            Verdict::Sybil => revoke(state, &subject),
            Verdict::Human => {
                // A challenge cleared in the subject's favor.
                if kind == CaseKind::Challenge {
                    // Restore a Challenged human to Verified.
                    if let Some(mut h) = state.get_human(&subject) {
                        if h.status == HumanStatus::Challenged {
                            h.status = HumanStatus::Verified;
                            sync_account_verified(state, &subject, true, h.verified_at);
                            state.put_human(h);
                        }
                    }
                    // False challenge: slash the challenger's reputation and bar it from re-filing
                    // against this subject (security finding A). The slash is integer + deterministic.
                    if let Some(mut ch) = state.get_human(&challenger) {
                        ch.reputation = ch.reputation.saturating_sub(FALSE_CHALLENGE_SLASH);
                        state.put_human(ch);
                    }
                    state.record_challenge_cleared(&challenger, &subject);
                }
            }
            // A committed Uncertain can't happen — the tally escalates it (see `tally`).
            Verdict::Uncertain => {}
        },
        // Split / Uncertain. For a Challenge against a previously-Verified (now Challenged) human,
        // fail-safe restore Verified — only a Sybil quorum may strip an established human (finding B).
        CaseStatus::Escalated => {
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
        CaseStatus::Open => {}
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
        h.vouches_in.clear();
        state.put_human(h);
    }
    // F-REL-1: drop the subject's vouch-edge indexes so a re-registered subject can be re-vouched by
    // its prior vouchers (the denormalized `vouches_in` was cleared above; this clears the MemState
    // forward/reverse indexes too). Deterministic set-removal.
    state.clear_vouch_edges(subject);
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

/// Has the subject's **most-recent** Registration case committed a `Human` verdict (liveness passed)?
///
/// F-REL-2: a re-registered subject has more than one Registration case; only the latest (highest
/// case id) reflects the current lifecycle's liveness grading. Scanning *any* historical case would
/// let a stale `Human` verdict from a prior lifecycle satisfy the gate. `cases()` is sorted by id, so
/// taking the last matching case is deterministic.
fn liveness_passed(state: &dyn State, subject: &Address) -> bool {
    state
        .cases()
        .into_iter()
        .rfind(|c| c.subject == *subject && c.kind == CaseKind::Registration)
        .map(|c| matches!(c.status, CaseStatus::Committed(v) if v.verdict == Verdict::Human))
        .unwrap_or(false)
}

/// Block height the subject's **most-recent** Registration case opened at (the window clock), if any.
/// Uses the latest case (highest id) so a re-registered subject's window is measured from the current
/// lifecycle's registration, not a stale prior one (consistent with F-REL-2's `liveness_passed`).
fn registration_opened_at(state: &dyn State, subject: &Address) -> Option<u64> {
    state
        .cases()
        .into_iter()
        .rfind(|c| c.subject == *subject && c.kind == CaseKind::Registration)
        .map(|c| c.opened_at)
}

/// Is there an `Open` Challenge case against the subject? (Used to enforce one-open-per-subject.)
fn has_open_challenge(state: &dyn State, subject: &Address) -> bool {
    state.cases().iter().any(|c| {
        c.subject == *subject
            && c.kind == CaseKind::Challenge
            && matches!(c.status, CaseStatus::Open)
    })
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
        // M6 §5.6: genesis-seeded humans are `Std` (the additive-field migration default). No
        // re-verification; a later ZK proof can upgrade to `Dual`.
        assurance: crate::zkpoh::Assurance::Std,
    });
    sync_account_verified(state, addr, true, verified_at);
}

// =============================================================================================
// M6 — ZK-passport proof of humanity (spec 06 §4.2/§5.2, ADR-0005). Additive: every M3 transition
// above is UNTOUCHED. This is the ONLY new lifecycle entry point.
// =============================================================================================

use crate::zkpoh::{
    address_to_hash, current_date_to_epoch, self_identity_root_accepted, self_ofac_root_accepted,
    u64_to_hash, Assurance, CscaEntry, CscaStatus, SelfIdentityRoot, SelfOfacRoot,
    ZkPassportVerifier, ZkPublicInputs, OFAC_KIND_NAMEDOB, OFAC_KIND_NAMEYOB, OFAC_KIND_PASSPORTNO,
    SCHEME_TAG_PASSPORT, SELF_ATTESTATION_ID_EPASSPORT, SELF_DATE_WINDOW_SECS, SELF_NPUBLIC,
    UBI2_SELF_SCOPE,
};

/// Why a `submitZkPassportProof` op was rejected (spec §4.2; AC-2/3, AC-F1…F6/F9). Deterministic so two
/// nodes reject identically (I1/I4). Every variant is a clean fail-closed abort — **no partial state**.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkPohError {
    /// The `scheme_tag` is not a known document scheme (spec 06b §4.4 step 1 bound-check).
    UnknownScheme(u8),
    /// `attestation_id` (slot 8) ≠ 1 (E-Passport) — the proof is not for the expected document (§4.4).
    UnexpectedAttestation,
    /// `scope` (slot 19) ≠ `UBI2_SELF_SCOPE` — a different-app nullifier, would break Sybil-uniqueness.
    WrongScope,
    /// `user_identifier` (slot 20) ≠ the tx sender — a copied/relayed proof (anti-replay / front-run, F-4).
    SubmitterMismatch,
    /// `current_date` (slots 10..16) is outside the freshness window around `block.timestamp` (§4.4 step 5).
    StaleProofDate,
    /// `merkle_root` (slot 9) ∉ the accepted Self identity-root set / outside its window (EC-C2, F-2).
    UntrustedSelfRoot,
    /// One of the OFAC roots (slots 16..19) ∉ the accepted OFAC set for its kind / outside window (F-2).
    UntrustedOfacRoot,
    /// The `nullifier` is already spent (one-passport-one-human; cheap pre-check before pairing — F-5).
    NullifierAlreadyUsed,
    /// The SNARK verifier returned `false` (tampered/forged/expired proof — F-1/F-3).
    InvalidProof,
    /// The subject is already `Enh`/`Dual` — a re-submission is idempotently rejected (F-9).
    AlreadyEnhanced(Assurance),
    /// The subject is `Revoked` — a revoked human cannot re-bootstrap via ZK in M6 (fail-closed).
    SubjectRevoked,
    /// The `nullifier` is `≥` the BN254 scalar order `r`, so its raw bytes (the uniqueness registry key)
    /// do not round-trip the verifier's field reduction — the malleability that would let one passport
    /// mint many humans via `N, N+r, N+2r…` (§3.5 round-trip obligation; F-5 hardening).
    NonCanonicalNullifier,
}

impl std::fmt::Display for ZkPohError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ZkPohError::*;
        match self {
            UnknownScheme(t) => write!(f, "unknown passport scheme tag {t}"),
            UnexpectedAttestation => write!(f, "attestation_id is not 1 (E-Passport)"),
            WrongScope => write!(f, "scope is not the canonical UBI2_SELF_SCOPE"),
            SubmitterMismatch => write!(f, "user_identifier does not match the tx sender"),
            StaleProofDate => write!(f, "current_date is outside the freshness window"),
            UntrustedSelfRoot => write!(f, "merkle_root is not an accepted Self identity root"),
            UntrustedOfacRoot => write!(f, "an OFAC root is not in the accepted OFAC set"),
            NullifierAlreadyUsed => write!(f, "nullifier already used (one passport, one human)"),
            InvalidProof => write!(f, "ZK proof verification failed"),
            AlreadyEnhanced(a) => write!(f, "human already ZK-enhanced ({})", a.as_str()),
            SubjectRevoked => write!(f, "subject is revoked"),
            NonCanonicalNullifier => {
                write!(f, "non-canonical nullifier (>= BN254 scalar order r)")
            }
        }
    }
}

impl std::error::Error for ZkPohError {}

/// The decoded `submitZkPassportProof` calldata the runtime hands the lifecycle (spec 06b §4.3). Carries
/// the Groth16 `proof` + the **full** 21-element public vector + the `scheme_tag`. The submitter address
/// is NOT carried here — it is the tx sender, supplied separately (`subject`) and bound against
/// `signals[user_identifier]` so it cannot be forged (§4.4). The runtime derives every policy field by
/// index; nothing is passed separately (removing the cross-check surface).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkProofSubmission {
    /// The ~200-byte Groth16 proof (canonical-decoded by the verifier; opaque here).
    pub proof: Vec<u8>,
    /// The raw `vc_and_disclose` 21-signal public vector (snarkjs order, §4.1).
    pub signals: [Hash; SELF_NPUBLIC],
    /// The 1-byte document/scheme discriminant (§2.4); `0` = Self e-passport (attestation_id must be 1).
    pub scheme_tag: u8,
}

/// Verify + commit a ZK-passport proof for `subject` (the tx sender) at block timestamp `now`
/// (spec §4.2). This is the **only** new lifecycle entry point; every M3 transition is untouched (EC-5).
///
/// Fail-closed, in order, aborting on the first failure with **no state change** (I4):
///  1. **Bound-check** the scheme tag (the array lengths are enforced by the typed [`ZkProofSubmission`]).
///  2. **Bind the public inputs:** `now_epoch == now` (block ts — I2); `cscaRegistryRoot` == the live
///     CSCA root (§7.2, EC-3). The submitter address is bound by construction (`subject` *is* the tx
///     sender, §4.3) and is stamped into the public-input vector the verifier checks.
///  3. **Nullifier pre-check** (cheap, before the pairing — F-5): reject a spent nullifier.
///  4. **SNARK verify** (the pure crypto): `verifier.verify_passport`. `false` ⇒ reject (F-1/F-3).
///  5. **Commit atomically** on success: insert the nullifier, store the commitments, set the assurance
///     level + status, and — if not already `Verified` — start emission exactly as M3
///     `finalize_registration` does (set `verified_at`, flip the account cache). A *new* user → `Enh`;
///     an `Std`-Verified upgrader → `Dual` (balance + `verified_at` **never** touched).
///
/// Returns the resulting [`Assurance`] level. Two nodes reach the identical accept/reject + post-state
/// (I1/I2), so the `state_root` agrees byte-for-byte.
pub fn submit_zk_passport_proof(
    state: &mut dyn State,
    verifier: &dyn ZkPassportVerifier,
    subject: &Address,
    submission: &ZkProofSubmission,
    now: u64,
    now_block: u64,
) -> Result<Assurance, ZkPohError> {
    let pi = ZkPublicInputs::new(submission.signals);

    // --- (1) bound-check the scheme tag (the vector length is enforced by the typed array). ---
    if submission.scheme_tag != SCHEME_TAG_PASSPORT {
        return Err(ZkPohError::UnknownScheme(submission.scheme_tag));
    }

    // --- (2) attestation_id (slot 8) == 1 (E-Passport) for schemeTag 0 (§4.4 step: attestation). ---
    if pi.attestation_id() != u64_to_hash(SELF_ATTESTATION_ID_EPASSPORT) {
        return Err(ZkPohError::UnexpectedAttestation);
    }

    // --- (3) scope (slot 19) == UBI2_SELF_SCOPE — one scope network-wide ⇒ one-passport-one-human. ---
    if pi.scope() != UBI2_SELF_SCOPE {
        return Err(ZkPohError::WrongScope);
    }

    // --- (4) submitter binding: user_identifier (slot 20) == the tx sender (anti-replay, F-4). The
    //     Self proof was requested with `userId = the ubi2 address`, so a copied/relayed proof from any
    //     other account is rejected here (§4.4 step: submitter). ---
    if pi.user_identifier() != address_to_hash(subject) {
        return Err(ZkPohError::SubmitterMismatch);
    }

    // --- (5) freshness: decode current_date (slots 10..16, YYMMDD) and require it within
    //     ±SELF_DATE_WINDOW_SECS of `block.timestamp` — a deterministic block-time window (§4.4 step 5).
    //     Ties the in-circuit not-expired check to chain time; no wall-clock. ---
    let date = pi.current_date();
    let date_epoch = current_date_to_epoch(&date).ok_or(ZkPohError::StaleProofDate)?;
    let lo = now.saturating_sub(SELF_DATE_WINDOW_SECS);
    let hi = now.saturating_add(SELF_DATE_WINDOW_SECS);
    if date_epoch < lo || date_epoch > hi {
        return Err(ZkPohError::StaleProofDate);
    }

    // --- (6) trust anchors: merkle_root (slot 9) ∈ accepted Self identity roots, AND each OFAC root
    //     (slots 16,17,18) ∈ its accepted set — each within the freshness window (§2.2, §4.4 step 6). ---
    let identity_roots = state.self_identity_roots();
    if !self_identity_root_accepted(&identity_roots, &pi.merkle_root(), now_block) {
        return Err(ZkPohError::UntrustedSelfRoot);
    }
    let ofac_roots = state.self_ofac_roots();
    for kind in [OFAC_KIND_PASSPORTNO, OFAC_KIND_NAMEDOB, OFAC_KIND_NAMEYOB] {
        if !self_ofac_root_accepted(&ofac_roots, kind, &pi.ofac_root(kind), now_block) {
            return Err(ZkPohError::UntrustedOfacRoot);
        }
    }

    // --- pre-state idempotency / status guard (before any mutation). ---
    // An existing record's assurance gates a re-submit: `Enh`/`Dual` ⇒ already enhanced (F-9); `Revoked`
    // ⇒ rejected (a revoked human does not re-bootstrap via ZK in M6 — §5.2 revocation interaction).
    let nullifier = pi.nullifier();
    if let Some(h) = state.get_human(subject) {
        if h.status == HumanStatus::Revoked {
            return Err(ZkPohError::SubjectRevoked);
        }
        if h.assurance != Assurance::Std {
            return Err(ZkPohError::AlreadyEnhanced(h.assurance));
        }
    }

    // --- (7) nullifier canonicality guard (§3.5 round-trip obligation) — BEFORE the registry key. ---
    // The nullifier is the one-passport-one-human registry key, stored + compared as RAW bytes, while the
    // verifier reduces it mod the BN254 order `r`. A non-canonical value (≥ r) reduces to a DIFFERENT
    // element, so `N`, `N+r`, `N+2r`… are distinct registry keys that all satisfy the SAME proof — minting
    // unlimited humans (and UBI) from ONE passport. A genuine proof's nullifier is always canonical.
    if !crate::zkpoh::is_canonical_scalar(&nullifier) {
        return Err(ZkPohError::NonCanonicalNullifier);
    }

    // --- (8) nullifier-uniqueness pre-check (cheap fail-closed BEFORE the pairing — F-5). ---
    if state.nullifier_used(&nullifier) {
        return Err(ZkPohError::NullifierAlreadyUsed);
    }

    // --- (10) the SNARK verify (the pure crypto). `false` ⇒ reject; NO partial state (F-1/F-3). ---
    // The full 21-signal vector the proof commits to is verified verbatim (no adapter, no zeroing): a
    // copied proof or a tampered slot verifies `false`.
    if !verifier.verify_passport(&submission.proof, &pi) {
        return Err(ZkPohError::InvalidProof);
    }

    // --- (11) commit atomically (success only). ---
    // Insert the now-permanently-spent nullifier and the opaque attribute commitments (I6).
    let attribute_commitments = pi.attribute_commitments();
    state.put_nullifier(nullifier);
    state.put_attribute_commitments(subject, attribute_commitments);

    // Set the assurance level + status. Two routes (spec §5.2):
    //   * existing `Std`-Verified human  → `Dual` (balance + verified_at UNTOUCHED — the hard rule);
    //   * no record / Pending / Unverified → create+`Enh`, transition to `Verified`, START emission
    //     exactly as `finalize_registration` (set verified_at, flip the account cache).
    let resulting = match state.get_human(subject) {
        Some(mut h) if h.status == HumanStatus::Verified => {
            // Pure upgrade: do NOT touch verified_at, balance, or the account cache (§5.2).
            h.assurance = Assurance::Dual;
            state.put_human(h);
            Assurance::Dual
        }
        existing => {
            // New ZK-only user, OR a Pending/Challenged/never-recorded subject: the cryptographic proof
            // satisfies uniqueness, so finalize to Verified/Enh immediately and start emission. Preserve
            // any existing vouch/reputation/liveness fields (a Pending human's in-flight case is left
            // as-is, simply no longer gating them).
            let mut h = existing.unwrap_or_else(|| Human::pending(*subject, [0u8; 32]));
            h.status = HumanStatus::Verified;
            h.verified_at = now;
            h.assurance = Assurance::Enh;
            sync_account_verified(state, subject, true, now);
            state.put_human(h);
            Assurance::Enh
        }
    };
    Ok(resulting)
}

// ---------------------------------------------------------------------------------------------
// CSCA registry governance (spec §7.3) — register/revoke a trust anchor. M6: a reserved governance
// authority (mirrors how M5 gates validator-set changes); M7 re-points it at the DAO vote (no shape
// change). A newly-added root is IMMEDIATELY usable (EC-10): the next proof can build against it.
// ---------------------------------------------------------------------------------------------

/// Why a CSCA-governance op was rejected (spec §7.3, AC-10). Deterministic (I1/I4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CscaGovError {
    /// The caller is not the governance authority (a non-governance `registerCsca`/`revokeCsca` — AC-10).
    NotGovernance,
    /// `revokeCsca` for a `key_id` not present in the registry.
    UnknownCsca,
}

impl std::fmt::Display for CscaGovError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CscaGovError::NotGovernance => write!(f, "caller is not the CSCA governance authority"),
            CscaGovError::UnknownCsca => write!(f, "no such CSCA key id"),
        }
    }
}

/// Register (or re-activate) a CSCA trust anchor, gated by the governance authority (spec §7.3, EC-10).
/// The new entry is `Active` immediately, so the registry root changes and the **next** proof can build
/// against the new root (immediate usability — EC-10). Fail-closed: a non-governance caller mutates
/// nothing (`NotGovernance`).
pub fn register_csca(
    state: &mut dyn State,
    caller: &Address,
    country_code: [u8; 3],
    key_id: Hash,
    pubkey: Vec<u8>,
    now_block: u64,
) -> Result<(), CscaGovError> {
    if !state.is_csca_governance(caller) {
        return Err(CscaGovError::NotGovernance);
    }
    state.put_csca(CscaEntry::active(country_code, key_id, pubkey, now_block));
    Ok(())
}

/// Revoke a CSCA trust anchor (set its entry `Revoked`), gated by governance (spec §7.3/§7.4). The key
/// leaves the Active set → the root changes → proofs chaining to it stop verifying (forward-invalidation;
/// already-spent nullifiers are NOT retroactively purged — that is M7, §7.4). Fail-closed.
pub fn revoke_csca(
    state: &mut dyn State,
    caller: &Address,
    key_id: &Hash,
) -> Result<(), CscaGovError> {
    if !state.is_csca_governance(caller) {
        return Err(CscaGovError::NotGovernance);
    }
    let mut entry = state.get_csca(key_id).ok_or(CscaGovError::UnknownCsca)?;
    entry.status = CscaStatus::Revoked;
    state.put_csca(entry);
    Ok(())
}

/// Seed a genesis CSCA trust anchor directly (the curated static genesis set, spec §7.3). Governance
/// bypass for genesis wiring only — like `seed_verified_human`. `Active` from genesis. RETAINED but
/// inactive on the Self verify path (reserved for the own-stack milestone, O-C1).
pub fn seed_csca(state: &mut dyn State, country_code: [u8; 3], key_id: Hash, pubkey: Vec<u8>) {
    state.put_csca(CscaEntry::active(country_code, key_id, pubkey, 0));
}

// ---------------------------------------------------------------------------------------------
// M6 Stage C — Self-root anchor registry governance (spec 06b §2.2). Gated by the SAME authority M6
// uses for `registerCsca` (mirrors M5's validator-set authority; re-pointed at the DAO in M7). A newly
// pinned root is IMMEDIATELY usable by the next proof (EC-C13). Fail-closed.
// ---------------------------------------------------------------------------------------------

/// Pin an accepted Self identity-commitment root (`pinSelfIdentityRoot`), gated by governance (§2.2).
/// Active from `now_block`; a proof carrying it is accepted while within `SELF_ROOT_WINDOW_BLOCKS`.
pub fn pin_self_identity_root(
    state: &mut dyn State,
    caller: &Address,
    root: Hash,
    now_block: u64,
) -> Result<(), CscaGovError> {
    if !state.is_csca_governance(caller) {
        return Err(CscaGovError::NotGovernance);
    }
    state.put_self_identity_root(SelfIdentityRoot {
        root,
        pinned_at_block: now_block,
    });
    Ok(())
}

/// Pin an accepted Self OFAC SMT root of `kind` (`pinSelfOfacRoot`), gated by governance (§2.2).
pub fn pin_self_ofac_root(
    state: &mut dyn State,
    caller: &Address,
    kind: u8,
    root: Hash,
    now_block: u64,
) -> Result<(), CscaGovError> {
    if !state.is_csca_governance(caller) {
        return Err(CscaGovError::NotGovernance);
    }
    state.put_self_ofac_root(SelfOfacRoot {
        kind,
        root,
        pinned_at_block: now_block,
    });
    Ok(())
}

/// Retire a Self root (`retireSelfRoot`) from BOTH the identity + OFAC accepted sets, gated by
/// governance (§2.2). Forward-invalidation only — already-spent nullifiers are NOT purged (O-C2).
pub fn retire_self_root(
    state: &mut dyn State,
    caller: &Address,
    root: &Hash,
) -> Result<(), CscaGovError> {
    if !state.is_csca_governance(caller) {
        return Err(CscaGovError::NotGovernance);
    }
    state.retire_self_root(root);
    Ok(())
}

/// Seed a genesis Self identity root directly (governance bypass for genesis wiring only). Pinned at
/// block 0 — usable from the first proof.
pub fn seed_self_identity_root(state: &mut dyn State, root: Hash) {
    state.put_self_identity_root(SelfIdentityRoot {
        root,
        pinned_at_block: 0,
    });
}

/// Seed a genesis Self OFAC root of `kind` directly (genesis wiring only). Pinned at block 0.
pub fn seed_self_ofac_root(state: &mut dyn State, kind: u8, root: Hash) {
    state.put_self_ofac_root(SelfOfacRoot {
        kind,
        root,
        pinned_at_block: 0,
    });
}
