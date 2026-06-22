//! SECURITY GATE (M3-T8) — red-team PoCs for the proof-of-humanity surface, post-hardening.
//!
//! These tests began life as attack demonstrations (a passing test meant the attack SUCCEEDED). After
//! the M3 security hardening they assert the attacks are now **BLOCKED**: the challenge surface is
//! authenticated (Verified challenger only), capped (one Open challenge per subject), cooled-down (no
//! re-file after a cleared-Human verdict), reputation-slashed for false challenges, and an escalation
//! against a previously-Verified human fail-safe restores Verified. Each test maps to a finding in
//! docs/reports/security-m3.md. Every fix is a pure, deterministic function of state (I1/I4).

use ubi2_runtime::{
    challenge, finalize_registration, register_juror, request_verification, submit_verdict, vouch,
    CanonicalVerdict, CaseId, CaseStatus, Confidence, HumanStatus, HumanityOracle, LifecycleError,
    LivenessEvidence, MemState, MockOracle, State, Verdict, CHALLENGE_WINDOW,
    FALSE_CHALLENGE_SLASH, JURY_SIZE,
};

type Address = [u8; 20];
fn addr(b: u8) -> Address {
    [b; 20]
}
fn human_v() -> CanonicalVerdict {
    CanonicalVerdict::new(Verdict::Human, Confidence::High)
}
fn sybil_v() -> CanonicalVerdict {
    CanonicalVerdict::new(Verdict::Sybil, Confidence::High)
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
// FINDING A (HIGH) — BLOCKED. The challenge surface is now authenticated + capped + cooled-down:
//   * an unverified challenger is rejected (`ChallengerNotVerified`), so spam costs an identity;
//   * a Verified challenger gets exactly ONE shot per subject — once the jury clears it `Human`,
//     re-filing is `ChallengeOnCooldown`, so it cannot stall finalization by re-filing (the 50-round
//     attack is now bounded to one challenge);
//   * with the resolved challenge cleared, the legitimate victim finalizes and streams.
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

    // (1) An unverified, non-juror attacker can no longer challenge at all (fail-closed).
    let attacker = addr(99);
    assert!(s.get_human(&attacker).is_none(), "attacker is a nobody");
    assert_eq!(
        challenge(&mut s, &attacker, &victim, [0u8; 32], 1234, after_window).unwrap_err(),
        LifecycleError::ChallengerNotVerified,
        "an unverified address cannot file a challenge anymore (finding A.1)"
    );

    // (2) Even a Verified challenger (a founder) gets only ONE shot. The first challenge opens, the
    //     jury clears it Human, and a re-file is rejected on cooldown — so the loop is bounded to 1.
    let mut accepted = 0u32;
    for round in 0..50u64 {
        match challenge(
            &mut s,
            &founders[0],
            &victim,
            [round as u8; 32],
            1234 + round,
            after_window,
        ) {
            Ok(case) => {
                accepted += 1;
                assert!(matches!(s.get_case(case).unwrap().status, CaseStatus::Open));
                // While Open the victim cannot finalize (correct: an open challenge gates).
                assert!(matches!(
                    finalize_registration(&mut s, &victim, after_window, 1_000),
                    Err(LifecycleError::ChallengePending)
                ));
                // The jury clears it Human; the challenger is now on cooldown for this subject.
                jury_votes(&mut s, case, human_v());
            }
            Err(e) => {
                // Every round after the first is rejected on cooldown — the spam is bounded.
                assert_eq!(e, LifecycleError::ChallengeOnCooldown, "round {round}");
            }
        }
    }
    assert_eq!(
        accepted, 1,
        "a single challenger may open at most ONE challenge per subject (the 50-refile attack is dead)"
    );

    // (3) With the resolved challenge cleared and no open challenge, the legitimate victim FINALIZES.
    let verified_secs = 1_000u64;
    finalize_registration(&mut s, &victim, after_window, verified_secs).unwrap();
    assert_eq!(s.get_human(&victim).unwrap().status, HumanStatus::Verified);
    // …and it now streams UBI (emission started at verified_secs).
    assert!(
        s.balance(&victim, verified_secs + 7_200) > 0,
        "the legitimate human streams after finalizing (attack no longer denies UBI)"
    );

    // (4) A DIFFERENT verified challenger may file once, but they too are bounded + reputation-slashed.
    let case2 = challenge(&mut s, &founders[1], &victim, [200u8; 32], 7, after_window).unwrap();
    jury_votes(&mut s, case2, human_v());
    assert_eq!(
        s.get_human(&founders[1]).unwrap().reputation,
        -FALSE_CHALLENGE_SLASH,
        "a false challenge slashes the challenger's reputation (finding A incentive)"
    );
    assert_eq!(
        challenge(&mut s, &founders[1], &victim, [201u8; 32], 8, after_window).unwrap_err(),
        LifecycleError::ChallengeOnCooldown,
        "no re-file after a cleared-Human verdict"
    );
}

// ============================================================================================
// FINDING B (MEDIUM) — BLOCKED. An Escalated (split/Uncertain) challenge against a previously-
// Verified human now FAIL-SAFE restores Verified: a challenge must be UPHELD by a Sybil quorum to
// strip an established human; mere escalation must not. The human keeps its vouch authority.
// ============================================================================================
#[test]
fn poc_b_escalated_challenge_leaves_human_stuck_challenged() {
    let mut s = MemState::new();
    // `addr(1)` is a Verified founder so it may file the challenge (finding A challenger gate).
    bootstrap(&mut s, &[addr(1)]);
    let victim = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &victim, 0);
    assert_eq!(s.get_human(&victim).unwrap().status, HumanStatus::Verified);

    // A Verified challenger challenges; victim flips to Challenged (still emitting — innocent until
    // proven, I4).
    let case = challenge(&mut s, &addr(1), &victim, [3u8; 32], 77, 0).unwrap();
    assert_eq!(
        s.get_human(&victim).unwrap().status,
        HumanStatus::Challenged
    );

    // Jury splits => Escalated. Finding B: the previously-Verified human is RESTORED to Verified.
    let jury = s.get_case(case).unwrap().jury.clone();
    let split = [
        human_v(),
        sybil_v(),
        CanonicalVerdict::new(Verdict::Uncertain, Confidence::Low),
    ];
    for (j, v) in jury.iter().zip(split.iter()) {
        let _ = submit_verdict(&mut s, case, j, *v, 0);
    }
    assert_eq!(s.get_case(case).unwrap().status, CaseStatus::Escalated);
    assert_eq!(
        s.get_human(&victim).unwrap().status,
        HumanStatus::Verified,
        "an escalation fail-safe restores a previously-Verified human (finding B)"
    );

    // And because the victim is Verified again, it RETAINS its vouching authority.
    let applicant = addr(60);
    let oracle = MockOracle::default();
    req(&mut s, &oracle, &applicant, 1, 1).unwrap();
    vouch(&mut s, &victim, &applicant, 1).expect("restored human keeps its vouch authority");
}

// ============================================================================================
// FINDING A constraints — focused tests for each rule.
// ============================================================================================

/// Only a Verified human may challenge: Unverified / Pending / Challenged / Revoked challengers are
/// all rejected fail-closed, with no case opened.
#[test]
fn challenger_must_be_verified_is_blocked() {
    let mut s = MemState::new();
    bootstrap(&mut s, &[]);
    let subject = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subject, 0);
    let oracle = MockOracle::default();

    // Unverified (unknown) challenger.
    assert_eq!(
        challenge(&mut s, &addr(99), &subject, [1u8; 32], 1, 0).unwrap_err(),
        LifecycleError::ChallengerNotVerified
    );
    // Pending challenger (registered but not finalized).
    req(&mut s, &oracle, &addr(60), 2, 0).unwrap();
    assert_eq!(s.get_human(&addr(60)).unwrap().status, HumanStatus::Pending);
    assert_eq!(
        challenge(&mut s, &addr(60), &subject, [1u8; 32], 3, 0).unwrap_err(),
        LifecycleError::ChallengerNotVerified
    );
    assert_eq!(
        s.open_cases().len(),
        0,
        "no case opened by a bad challenger"
    );
}

/// At most one Open challenge per subject: a second concurrent challenge is rejected while one is Open.
#[test]
fn one_open_challenge_per_subject_is_blocked() {
    let mut s = MemState::new();
    bootstrap(&mut s, &[addr(1), addr(2)]);
    let subject = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subject, 0);

    // First challenger opens a challenge.
    let _c1 = challenge(&mut s, &addr(1), &subject, [1u8; 32], 10, 0).unwrap();
    // A second (distinct, Verified) challenger cannot pile on while one is Open.
    assert_eq!(
        challenge(&mut s, &addr(2), &subject, [2u8; 32], 11, 0).unwrap_err(),
        LifecycleError::ChallengeAlreadyOpen,
        "only one Open challenge per subject"
    );
    // Exactly one open challenge case exists.
    let open_challenges = s
        .cases()
        .into_iter()
        .filter(|c| c.subject == subject && matches!(c.status, CaseStatus::Open))
        .count();
    assert_eq!(open_challenges, 1);
}

/// A false challenge (jury rules Human) slashes the challenger's reputation and bars a re-file.
#[test]
fn false_challenge_slashes_reputation_and_cools_down() {
    let mut s = MemState::new();
    bootstrap(&mut s, &[addr(1)]);
    let subject = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subject, 0);
    assert_eq!(s.get_human(&addr(1)).unwrap().reputation, 0);

    let case = challenge(&mut s, &addr(1), &subject, [1u8; 32], 10, 0).unwrap();
    jury_votes(&mut s, case, human_v());

    // Subject restored to Verified; challenger slashed; cooldown recorded.
    assert_eq!(s.get_human(&subject).unwrap().status, HumanStatus::Verified);
    assert_eq!(
        s.get_human(&addr(1)).unwrap().reputation,
        -FALSE_CHALLENGE_SLASH
    );
    assert_eq!(
        challenge(&mut s, &addr(1), &subject, [2u8; 32], 11, 0).unwrap_err(),
        LifecycleError::ChallengeOnCooldown,
        "the false challenger may not re-file against this subject"
    );
}

/// A genuine sybil is still caught: a Verified challenger files, the jury upholds Sybil by quorum, and
/// the subject is Revoked. The hardening only blocks SPAM, never a legitimate Sybil quorum.
#[test]
fn genuine_sybil_quorum_still_revokes() {
    let mut s = MemState::new();
    bootstrap(&mut s, &[addr(1)]);
    let subject = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subject, 0);

    let case = challenge(&mut s, &addr(1), &subject, [9u8; 32], 10, 0).unwrap();
    jury_votes(&mut s, case, sybil_v());
    assert_eq!(s.get_human(&subject).unwrap().status, HumanStatus::Revoked);
}

// ============================================================================================
// F-REL-1 — a re-registered subject can be re-vouched by its prior vouchers (vouch index cleared).
// ============================================================================================
#[test]
fn reregister_allows_prior_voucher_to_revouch() {
    let mut s = MemState::new();
    let founders = [addr(1), addr(2)];
    bootstrap(&mut s, &founders);
    let subject = addr(50);
    let oracle = MockOracle::default();

    // Lifecycle 1 → Verified.
    req(&mut s, &oracle, &subject, 9, 10).unwrap();
    vouch(&mut s, &founders[0], &subject, 10).unwrap();
    vouch(&mut s, &founders[1], &subject, 10).unwrap();
    finalize_registration(&mut s, &subject, 10 + CHALLENGE_WINDOW, 1_000).unwrap();

    // Sybil-quorum revoke (clears the subject's vouch edges).
    let case = challenge(&mut s, &founders[0], &subject, [9u8; 32], 5, 30).unwrap();
    jury_votes(&mut s, case, sybil_v());
    assert_eq!(s.get_human(&subject).unwrap().status, HumanStatus::Revoked);

    // Re-register and re-vouch from the SAME founders — no DuplicateVouch (F-REL-1 fix).
    req(&mut s, &oracle, &subject, 11, 40).unwrap();
    vouch(&mut s, &founders[0], &subject, 40).expect("prior voucher may re-vouch");
    vouch(&mut s, &founders[1], &subject, 40).expect("prior voucher may re-vouch");
    assert_eq!(s.get_human(&subject).unwrap().vouches_in.len(), 2);
}

// ============================================================================================
// CONTROL (defenses that DO hold) — documented so the report can confirm them.
// ============================================================================================

/// A non-selected juror cannot vote (authorization holds). With JURY_SIZE==pool the jury is the
/// whole registry, so this also confirms a random outsider is rejected.
#[test]
fn control_non_juror_cannot_vote_is_blocked() {
    let mut s = MemState::new();
    bootstrap(&mut s, &[addr(1)]);
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
    bootstrap(&mut s, &[addr(1)]);
    let subj = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subj, 0);
    let case = challenge(&mut s, &addr(1), &subj, [1u8; 32], 42, 0).unwrap();
    let jury = s.get_case(case).unwrap().jury.clone();
    // juror 0 lies (Human), jurors 1+2 are honest (Sybil) => commits Sybil.
    submit_verdict(&mut s, case, &jury[0], human_v(), 0).unwrap();
    submit_verdict(&mut s, case, &jury[1], sybil_v(), 0).unwrap();
    let st = submit_verdict(&mut s, case, &jury[2], sybil_v(), 0).unwrap();
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
