//! SECURITY GATE (M3-T8) — red-team PoCs for the proof-of-humanity surface.
//!
//! These tests are written by the security-engineer to *demonstrate* attacks, not to assert the
//! happy path. A test that PASSES here means the attack SUCCEEDS (the vulnerability is real) unless
//! its name says `_is_blocked`. Each maps to a finding in the security-m3 report.

use ubi2_runtime::{
    challenge, finalize_registration, register_juror, request_verification, submit_verdict, vouch,
    CanonicalVerdict, CaseId, CaseStatus, Confidence, HumanStatus, HumanityOracle, LifecycleError,
    LivenessEvidence, MemState, MockOracle, State, Verdict, CHALLENGE_WINDOW, JURY_SIZE,
};

type Address = [u8; 20];
fn addr(b: u8) -> Address {
    [b; 20]
}
fn human_v() -> CanonicalVerdict {
    CanonicalVerdict::new(Verdict::Human, Confidence::High)
}
fn req(
    s: &mut MemState,
    oracle: &dyn HumanityOracle,
    subject: &Address,
    entropy: u64,
    now: u64,
) -> Result<CaseId, LifecycleError> {
    let ev = LivenessEvidence {
        liveness_ref: [7u8; 32],
        challenge: b"challenge",
        response: b"response",
    };
    request_verification(s, oracle, subject, &ev, entropy, now)
}
fn bootstrap(s: &mut MemState, founders: &[Address]) {
    for i in 0..(JURY_SIZE as u8) {
        register_juror(s, &addr(200 + i), 0);
    }
    for f in founders {
        ubi2_runtime::seed_verified_human(s, f, 0);
    }
}
/// Drive a case to a committed verdict.
fn jury_votes(s: &mut MemState, case_id: u64, v: CanonicalVerdict) {
    let jury = s.get_case(case_id).unwrap().jury.clone();
    for j in &jury {
        if let Ok(CaseStatus::Committed(_)) = submit_verdict(s, case_id, j, v, 0) {
            break;
        }
    }
}

// ============================================================================================
// FINDING A (HIGH): unauthenticated, free challenge-spam can block a legitimate human from
// finalizing **forever**. Each challenge opens an Open case; an Open challenge case blocks
// finalize (`has_pending_or_upheld_challenge`). The challenger is never checked, costs only gas,
// and there is no cap on the number of challenges nor any per-subject cooldown. An attacker
// re-files a fresh challenge every block; the jury clearing one Human verdict does not help
// because a new Open case is always pending.
// ============================================================================================
#[test]
fn poc_a_challenge_spam_blocks_finalize_indefinitely() {
    let mut s = MemState::new();
    let founders = [addr(1), addr(2)];
    bootstrap(&mut s, &founders);
    let victim = addr(50);
    let oracle = MockOracle::default();

    // Victim is a perfectly legitimate human: liveness passed, two real vouches.
    req(&mut s, &oracle, &victim, 9, 10).unwrap();
    vouch(&mut s, &founders[0], &victim, 10).unwrap();
    vouch(&mut s, &founders[1], &victim, 10).unwrap();

    // The challenge window has long since cleared (height 1000 >> 10 + CHALLENGE_WINDOW).
    let after_window = 10 + CHALLENGE_WINDOW + 1000;

    // Attacker (any address — NOT verified, NOT a juror, NOT staked) spams challenges.
    let attacker = addr(99);
    assert!(s.get_human(&attacker).is_none(), "attacker is a nobody");

    for round in 0..50u64 {
        // 1 fresh challenge => 1 Open case against the victim.
        let case = challenge(
            &mut s,
            &attacker,
            &victim,
            [round as u8; 32],
            1234 + round,
            after_window,
        )
        .unwrap();
        assert!(matches!(s.get_case(case).unwrap().status, CaseStatus::Open));

        // While the Open case stands, the victim CANNOT finalize — even though the window cleared.
        let r = finalize_registration(&mut s, &victim, after_window, 1_000);
        assert!(
            matches!(r, Err(LifecycleError::ChallengePending)),
            "victim blocked by the open challenge (round {round})"
        );

        // The jury even clears it in the victim's favor (Human) — but the attacker just re-files.
        jury_votes(&mut s, case, human_v());
    }

    // After 50 rounds the victim is STILL Pending and has never streamed a single unit, despite
    // being a legitimate human who cleared the window. The block is unbounded (attack succeeds).
    assert_eq!(s.get_human(&victim).unwrap().status, HumanStatus::Pending);
    // One more open challenge keeps it blocked; the loop can run forever for the cost of gas.
    let last = challenge(&mut s, &attacker, &victim, [255u8; 32], 9999, after_window).unwrap();
    assert!(matches!(
        finalize_registration(&mut s, &victim, after_window, 1_000),
        Err(LifecycleError::ChallengePending)
    ));
    let _ = last;
}

// ============================================================================================
// FINDING B (MEDIUM): re-challenge griefing on an ALREADY-Verified human. A challenge flips a
// Verified human to Challenged. If the jury splits/Uncertain, the case Escalates and the human is
// STUCK in `Challenged` (submit_verdict only restores Verified on a committed Human; Escalated
// does nothing). Emission continues (good — I4), but a malicious challenger can keep any verified
// human permanently flagged `Challenged` in the UI / read surface, and a Verified human under an
// open challenge cannot be the SAME as a clean one for downstream logic (e.g. vouching paths key
// off `status == Verified`). Demonstrates the stuck-Challenged state with no auto-recovery.
// ============================================================================================
#[test]
fn poc_b_escalated_challenge_leaves_human_stuck_challenged() {
    let mut s = MemState::new();
    bootstrap(&mut s, &[]);
    let victim = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &victim, 0);
    assert_eq!(s.get_human(&victim).unwrap().status, HumanStatus::Verified);

    // Attacker challenges; victim flips to Challenged.
    let case = challenge(&mut s, &addr(99), &victim, [3u8; 32], 77, 0).unwrap();
    assert_eq!(
        s.get_human(&victim).unwrap().status,
        HumanStatus::Challenged
    );

    // Jury splits => Escalated. No state machine path returns a Challenged human to Verified on
    // an escalation, so the victim is stuck Challenged indefinitely.
    let jury = s.get_case(case).unwrap().jury.clone();
    let split = [
        human_v(),
        CanonicalVerdict::new(Verdict::Sybil, Confidence::High),
        CanonicalVerdict::new(Verdict::Uncertain, Confidence::Low),
    ];
    for (j, v) in jury.iter().zip(split.iter()) {
        let _ = submit_verdict(&mut s, case, j, *v, 0);
    }
    assert_eq!(s.get_case(case).unwrap().status, CaseStatus::Escalated);
    // STUCK: still Challenged, no resolution path in M3.
    assert_eq!(
        s.get_human(&victim).unwrap().status,
        HumanStatus::Challenged
    );

    // And because the victim is no longer `Verified`, it can no longer vouch (downstream authority
    // loss) — a permanent griefing effect for the cost of one challenge tx.
    let applicant = addr(60);
    let oracle = MockOracle::default();
    req(&mut s, &oracle, &applicant, 1, 1).unwrap();
    assert_eq!(
        vouch(&mut s, &victim, &applicant, 1).unwrap_err(),
        LifecycleError::VoucherNotVerified,
        "a stuck-Challenged human loses its vouching authority"
    );
}

// ============================================================================================
// CONTROL (defenses that DO hold) — documented so the report can confirm them.
// ============================================================================================

/// A non-selected juror cannot vote (authorization holds). With JURY_SIZE==pool the jury is the
/// whole registry, so this also confirms a random outsider is rejected.
#[test]
fn control_non_juror_cannot_vote_is_blocked() {
    let mut s = MemState::new();
    bootstrap(&mut s, &[]);
    let subj = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subj, 0);
    let case = challenge(&mut s, &addr(1), &subj, [1u8; 32], 42, 0).unwrap();
    assert_eq!(
        submit_verdict(&mut s, case, &addr(123), human_v(), 0).unwrap_err(),
        LifecycleError::NotOnJury
    );
}

/// A single malicious juror (1 of 3, QUORUM=2) cannot flip a verdict: with two honest Sybil votes
/// the case commits Sybil regardless of the third juror. Confirms a hostile MINORITY is powerless.
#[test]
fn control_malicious_minority_juror_cannot_flip_is_blocked() {
    let mut s = MemState::new();
    bootstrap(&mut s, &[]);
    let subj = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subj, 0);
    let case = challenge(&mut s, &addr(1), &subj, [1u8; 32], 42, 0).unwrap();
    let jury = s.get_case(case).unwrap().jury.clone();
    // juror 0 lies (Human), jurors 1+2 are honest (Sybil) => commits Sybil.
    submit_verdict(&mut s, case, &jury[0], human_v(), 0).unwrap();
    submit_verdict(
        &mut s,
        case,
        &jury[1],
        CanonicalVerdict::new(Verdict::Sybil, Confidence::High),
        0,
    )
    .unwrap();
    let st = submit_verdict(
        &mut s,
        case,
        &jury[2],
        CanonicalVerdict::new(Verdict::Sybil, Confidence::High),
        0,
    )
    .unwrap();
    assert!(matches!(st, CaseStatus::Committed(v) if v.verdict == Verdict::Sybil));
}

/// A voucher cannot exceed VOUCH_CAPACITY across multiple accounts, and cannot self/duplicate
/// vouch — confirms the anti-farm caps hold at the per-voucher level.
#[test]
fn control_vouch_caps_hold_is_blocked() {
    let mut s = MemState::new();
    let founder = addr(1);
    bootstrap(&mut s, &[founder]);
    assert_eq!(
        vouch(&mut s, &founder, &founder, 0).unwrap_err(),
        LifecycleError::SelfVouch
    );
}
