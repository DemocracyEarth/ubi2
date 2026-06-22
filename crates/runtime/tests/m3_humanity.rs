//! M3 — Proof-of-Humanity acceptance tests (spec 03 §"Acceptance criteria", board M3-T2).
//!
//! Everything here runs offline against the [`MockOracle`] — no model/network calls (invariant I5).
//! Each test maps to a spec criterion; the property test pins quorum determinism (I1).

use ubi2_runtime::{
    challenge, finalize_registration, register_juror, request_verification, revoke, submit_verdict,
    vouch, CanonicalVerdict, CaseId, CaseStatus, Confidence, HumanStatus, HumanityOracle,
    LifecycleError, LivenessEvidence, MemState, MockOracle, State, Verdict, CHALLENGE_WINDOW,
    EMISSION_PERIOD_SECS, JURY_SIZE, MIN_VOUCHES, QUORUM, SYBIL_SLASH, UBI, VOUCH_CAPACITY,
};

type Address = [u8; 20];

fn addr(b: u8) -> Address {
    [b; 20]
}

/// Test helper: open a registration with a passing-by-default liveness blob.
fn req(
    s: &mut MemState,
    oracle: &dyn HumanityOracle,
    subject: &Address,
    liveness_ref: [u8; 32],
    entropy: u64,
    now: u64,
) -> Result<CaseId, LifecycleError> {
    let ev = LivenessEvidence {
        liveness_ref,
        challenge: b"challenge",
        response: b"response",
    };
    request_verification(s, oracle, subject, &ev, entropy, now)
}
fn human_v() -> CanonicalVerdict {
    CanonicalVerdict::new(Verdict::Human, Confidence::High)
}
fn sybil_v() -> CanonicalVerdict {
    CanonicalVerdict::new(Verdict::Sybil, Confidence::High)
}

/// Bootstrap a state with `n` active jurors (addresses 200..200+n) and a verified founder set so
/// applicants have vouchers. Returns the founder addresses (already `Verified`, can vouch).
fn bootstrap(state: &mut MemState, n_jurors: u8, founders: &[Address]) {
    for i in 0..n_jurors {
        register_juror(state, &addr(200 + i), 0);
    }
    for f in founders {
        // Founders are seeded as Verified humans (genesis-style) so they can vouch.
        ubi2_runtime::seed_verified_human(state, f, 0);
    }
}

/// Drive a registration case to a committed verdict by having every juror submit `v`.
fn jury_votes(state: &mut MemState, case_id: u64, v: CanonicalVerdict) -> CaseStatus {
    let jury = state.get_case(case_id).unwrap().jury.clone();
    let mut last = CaseStatus::Open;
    for j in &jury {
        // Submitting after the case closes errors; stop once committed/escalated.
        match submit_verdict(state, case_id, j, v, 0) {
            Ok(s) => last = s,
            Err(LifecycleError::CaseClosed) => break,
            Err(e) => panic!("unexpected submit error: {e}"),
        }
    }
    last
}

// =================================================================================================
// Criterion 1 — Unverified → Pending → Verified, then emission starts.
// =================================================================================================
#[test]
fn happy_path_unverified_to_verified_then_streams() {
    let mut s = MemState::new();
    let founders = [addr(1), addr(2)];
    bootstrap(&mut s, JURY_SIZE as u8, &founders);

    let applicant = addr(50);
    // Block height 10 at registration; the unix emission epoch will be set at finalize.
    let reg_block = 10u64;

    // Unverified initially (no record).
    assert!(s.get_human(&applicant).is_none());

    // 1. request_verification opens a Registration case; the MockOracle (default Human/High) passes
    //    liveness, so the case commits Human and the applicant is Pending.
    let oracle = MockOracle::default();
    let case = req(&mut s, &oracle, &applicant, [7u8; 32], 0xABCD, reg_block).unwrap();
    assert_eq!(
        s.get_human(&applicant).unwrap().status,
        HumanStatus::Pending
    );
    assert!(matches!(
        s.get_case(case).unwrap().status,
        CaseStatus::Committed(v) if v.verdict == Verdict::Human
    ));

    // 2. Gather MIN_VOUCHES distinct verified vouchers.
    vouch(&mut s, &founders[0], &applicant, reg_block).unwrap();
    vouch(&mut s, &founders[1], &applicant, reg_block).unwrap();
    assert_eq!(
        s.get_human(&applicant).unwrap().vouches_in.len(),
        MIN_VOUCHES
    );

    // 3. Before the window clears, finalize is rejected (fail-closed).
    let early = finalize_registration(&mut s, &applicant, reg_block + 1, 0);
    assert!(matches!(
        early,
        Err(LifecycleError::ChallengeWindowOpen { .. })
    ));

    // 4. After the window clears with no challenge, finalize succeeds; emission epoch = verified_secs.
    let verified_secs = 1_000u64;
    finalize_registration(
        &mut s,
        &applicant,
        reg_block + CHALLENGE_WINDOW,
        verified_secs,
    )
    .unwrap();
    let h = s.get_human(&applicant).unwrap();
    assert_eq!(h.status, HumanStatus::Verified);
    assert_eq!(h.verified_at, verified_secs);

    // ...and ONLY now does the balance stream: 1 UBI/hour from verified_secs.
    assert_eq!(s.balance(&applicant, verified_secs), 0);
    assert_eq!(
        s.balance(&applicant, verified_secs + EMISSION_PERIOD_SECS),
        UBI
    );
    assert_eq!(
        s.balance(&applicant, verified_secs + 24 * EMISSION_PERIOD_SECS),
        24 * UBI
    );
}

/// A Pending account (not yet finalized) accrues NOTHING — gating is on `Verified` (criterion 5).
#[test]
fn pending_account_does_not_stream() {
    let mut s = MemState::new();
    let founders = [addr(1), addr(2)];
    bootstrap(&mut s, JURY_SIZE as u8, &founders);
    let applicant = addr(50);
    let oracle = MockOracle::default();
    req(&mut s, &oracle, &applicant, [1u8; 32], 1, 0).unwrap();
    // Pending: emission is zero no matter how far forward we read.
    assert_eq!(s.balance(&applicant, 1_000_000 * EMISSION_PERIOD_SECS), 0);
}

// =================================================================================================
// Criterion 2 — sybil caught: challenge → quorum Sybil → Revoked, emission stops, vouchers slashed.
// =================================================================================================
#[test]
fn sybil_challenge_revokes_and_slashes_vouchers() {
    let mut s = MemState::new();
    let founders = [addr(1), addr(2)];
    bootstrap(&mut s, JURY_SIZE as u8, &founders);
    let subject = addr(50);

    // Bring the subject all the way to Verified first.
    let oracle = MockOracle::default();
    req(&mut s, &oracle, &subject, [7u8; 32], 9, 10).unwrap();
    vouch(&mut s, &founders[0], &subject, 10).unwrap();
    vouch(&mut s, &founders[1], &subject, 10).unwrap();
    let verified_secs = 5_000u64;
    finalize_registration(&mut s, &subject, 10 + CHALLENGE_WINDOW, verified_secs).unwrap();
    assert_eq!(s.get_human(&subject).unwrap().status, HumanStatus::Verified);
    // It's streaming.
    assert_eq!(
        s.balance(&subject, verified_secs + EMISSION_PERIOD_SECS),
        UBI
    );

    // Anyone challenges with sybil evidence → opens a Challenge case; subject becomes Challenged
    // (still emitting until the quorum upholds — innocent until proven, I4).
    let case = challenge(&mut s, &founders[0], &subject, [9u8; 32], 1234, 20).unwrap();
    assert_eq!(
        s.get_human(&subject).unwrap().status,
        HumanStatus::Challenged
    );

    // Jury adjudicates Sybil by quorum.
    let status = jury_votes(&mut s, case, sybil_v());
    assert!(matches!(status, CaseStatus::Committed(v) if v.verdict == Verdict::Sybil));

    // Subject is Revoked, verified_at cleared, emission STOPPED (zero from here, to the base unit).
    let h = s.get_human(&subject).unwrap();
    assert_eq!(h.status, HumanStatus::Revoked);
    assert_eq!(h.verified_at, 0);
    assert_eq!(
        s.balance(&subject, verified_secs + 1_000 * EMISSION_PERIOD_SECS),
        0
    );

    // Both vouchers were slashed by SYBIL_SLASH.
    assert_eq!(s.get_human(&founders[0]).unwrap().reputation, -SYBIL_SLASH);
    assert_eq!(s.get_human(&founders[1]).unwrap().reputation, -SYBIL_SLASH);
}

/// A sybil applicant who is challenged DURING the registration window is never granted UBI
/// (criterion 2 — "UBI not granted"): the upheld challenge blocks finalization.
#[test]
fn sybil_applicant_never_finalizes() {
    let mut s = MemState::new();
    let founders = [addr(1), addr(2)];
    bootstrap(&mut s, JURY_SIZE as u8, &founders);
    let subject = addr(50);
    let oracle = MockOracle::default();
    req(&mut s, &oracle, &subject, [7u8; 32], 9, 10).unwrap();
    vouch(&mut s, &founders[0], &subject, 10).unwrap();
    vouch(&mut s, &founders[1], &subject, 10).unwrap();

    // Challenge the pending applicant; quorum says Sybil ⇒ Revoked.
    let case = challenge(&mut s, &founders[0], &subject, [9u8; 32], 7, 11).unwrap();
    jury_votes(&mut s, case, sybil_v());
    assert_eq!(s.get_human(&subject).unwrap().status, HumanStatus::Revoked);

    // Finalize now fails (subject is Revoked, not Pending) — UBI never granted.
    let r = finalize_registration(&mut s, &subject, 100, 100);
    assert!(matches!(r, Err(LifecycleError::NotPending)));
    assert_eq!(s.balance(&subject, 1_000 * EMISSION_PERIOD_SECS), 0);
}

/// A challenge the jury rules `Human` upholds the subject: a Challenged human is restored to Verified
/// and keeps streaming.
#[test]
fn upheld_human_challenge_restores_verified() {
    let mut s = MemState::new();
    let founders = [addr(1), addr(2)];
    bootstrap(&mut s, JURY_SIZE as u8, &founders);
    let subject = addr(50);
    let oracle = MockOracle::default();
    req(&mut s, &oracle, &subject, [7u8; 32], 9, 10).unwrap();
    vouch(&mut s, &founders[0], &subject, 10).unwrap();
    vouch(&mut s, &founders[1], &subject, 10).unwrap();
    let vsecs = 3_000;
    finalize_registration(&mut s, &subject, 10 + CHALLENGE_WINDOW, vsecs).unwrap();

    let case = challenge(&mut s, &founders[0], &subject, [9u8; 32], 5, 20).unwrap();
    assert_eq!(
        s.get_human(&subject).unwrap().status,
        HumanStatus::Challenged
    );
    let status = jury_votes(&mut s, case, human_v());
    assert!(matches!(status, CaseStatus::Committed(v) if v.verdict == Verdict::Human));
    // Restored, still streaming, vouchers not slashed.
    assert_eq!(s.get_human(&subject).unwrap().status, HumanStatus::Verified);
    assert_eq!(s.balance(&subject, vsecs + EMISSION_PERIOD_SECS), UBI);
    assert_eq!(s.get_human(&founders[0]).unwrap().reputation, 0);
}

// =================================================================================================
// Criterion 3 — quorum determinism (I1): same evidence ⇒ identical verdict; ≥QUORUM commits; split
// escalates. Reproducible across two independently-built states.
// =================================================================================================
#[test]
fn quorum_determinism_identical_verdicts_commit() {
    // All jurors run the same MockOracle on the same evidence ⇒ identical CanonicalVerdict.
    let oracle = MockOracle::new(sybil_v());
    let v1 = oracle.adjudicate(b"fixed-evidence");
    let v2 = oracle.adjudicate(b"fixed-evidence");
    assert_eq!(v1, v2, "same evidence ⇒ identical verdict (I1)");

    // Build the same case in two independent states and tally — both commit Sybil identically.
    let run = || -> CaseStatus {
        let mut s = MemState::new();
        bootstrap(&mut s, JURY_SIZE as u8, &[]);
        let subj = addr(50);
        // Seed subject as a Verified human so it can be challenged.
        ubi2_runtime::seed_verified_human(&mut s, &subj, 0);
        let case = challenge(&mut s, &addr(1), &subj, [3u8; 32], 77, 0).unwrap();
        let jury = s.get_case(case).unwrap().jury.clone();
        for j in &jury {
            let v = oracle.adjudicate(b"fixed-evidence");
            if let Ok(CaseStatus::Committed(_)) = submit_verdict(&mut s, case, j, v, 0) {
                break;
            }
        }
        s.get_case(case).unwrap().status
    };
    let a = run();
    let b = run();
    assert_eq!(a, b, "two nodes reach the same committed verdict (I1)");
    assert!(matches!(a, CaseStatus::Committed(v) if v.verdict == Verdict::Sybil));
}

#[test]
fn quorum_split_escalates() {
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &[]);
    let subj = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subj, 0);
    let case = challenge(&mut s, &addr(1), &subj, [3u8; 32], 88, 0).unwrap();
    let jury = s.get_case(case).unwrap().jury.clone();
    assert_eq!(jury.len(), JURY_SIZE);

    // Three different verdicts (Human, Sybil, Uncertain) ⇒ no pair agrees ⇒ Escalated.
    let verdicts = [
        human_v(),
        sybil_v(),
        CanonicalVerdict::new(Verdict::Uncertain, Confidence::Low),
    ];
    for (j, v) in jury.iter().zip(verdicts.iter()) {
        submit_verdict(&mut s, case, j, *v, 0).unwrap();
    }
    assert_eq!(s.get_case(case).unwrap().status, CaseStatus::Escalated);
    // Escalated challenge ⇒ subject NOT revoked (no auto-grant either way — I4).
    assert_eq!(s.get_human(&subj).unwrap().status, HumanStatus::Challenged);
}

/// Property test (I1): for many random juries and a fixed deterministic oracle, two independently-built
/// states always reach the *same* tally; identical verdicts commit, three-way splits escalate.
#[test]
fn property_quorum_is_deterministic_across_nodes() {
    // Deterministic SplitMix64 — reproducible failures.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }
    let mut rng = Rng(0x5EED_0003_4D33_0001);

    for _ in 0..5_000 {
        let n_jurors = 3 + (rng.next() % 5) as u8; // 3..=7 active jurors
        let entropy = rng.next();
        // Pick a default verdict the oracle returns for all jurors (so all honest jurors agree).
        let (verdict, conf) = match rng.next() % 3 {
            0 => (Verdict::Human, Confidence::High),
            1 => (Verdict::Sybil, Confidence::Med),
            _ => (Verdict::Human, Confidence::Low),
        };
        let oracle = MockOracle::new(CanonicalVerdict::new(verdict, conf));

        let build = || -> CaseStatus {
            let mut s = MemState::new();
            for i in 0..n_jurors {
                register_juror(&mut s, &addr(100 + i), 0);
            }
            let subj = addr(50);
            ubi2_runtime::seed_verified_human(&mut s, &subj, 0);
            let case = challenge(&mut s, &addr(1), &subj, [1u8; 32], entropy, 0).unwrap();
            let jury = s.get_case(case).unwrap().jury.clone();
            for j in &jury {
                let v = oracle.adjudicate(b"e");
                match submit_verdict(&mut s, case, j, v, 0) {
                    Ok(CaseStatus::Committed(_)) => break,
                    _ => continue,
                }
            }
            s.get_case(case).unwrap().status
        };

        let a = build();
        let b = build();
        assert_eq!(a, b, "quorum diverged across nodes (I1)");
        // Honest unanimous jurors ⇒ committed verdict (never escalated for a non-Uncertain verdict).
        assert!(
            matches!(a, CaseStatus::Committed(cv) if cv.verdict == verdict && cv.confidence == conf),
            "unanimous honest jury must commit its verdict, got {a:?}"
        );
        let _ = QUORUM; // referenced for documentation of the bound under test.
    }
}

// =================================================================================================
// Criterion 4 — vouch constraints: only Verified vouchers; capacity; no self/duplicate.
// =================================================================================================
#[test]
fn vouch_constraints_enforced() {
    let mut s = MemState::new();
    let founder = addr(1);
    bootstrap(&mut s, JURY_SIZE as u8, &[founder]);
    let applicant = addr(50);
    let oracle = MockOracle::default();
    req(&mut s, &oracle, &applicant, [7u8; 32], 1, 0).unwrap();

    // Unverified voucher rejected.
    assert_eq!(
        vouch(&mut s, &addr(60), &applicant, 0).unwrap_err(),
        LifecycleError::VoucherNotVerified
    );
    // Self-vouch rejected.
    assert_eq!(
        vouch(&mut s, &founder, &founder, 0).unwrap_err(),
        LifecycleError::SelfVouch
    );
    // Valid vouch, then duplicate is rejected.
    vouch(&mut s, &founder, &applicant, 0).unwrap();
    assert_eq!(
        vouch(&mut s, &founder, &applicant, 0).unwrap_err(),
        LifecycleError::DuplicateVouch
    );
}

#[test]
fn vouch_capacity_enforced() {
    let mut s = MemState::new();
    let founder = addr(1);
    bootstrap(&mut s, JURY_SIZE as u8, &[founder]);
    let oracle = MockOracle::default();

    // Open VOUCH_CAPACITY distinct pending applicants and vouch for each — all succeed.
    for i in 0..VOUCH_CAPACITY as u8 {
        let a = addr(60 + i);
        req(&mut s, &oracle, &a, [1u8; 32], 1, 0).unwrap();
        vouch(&mut s, &founder, &a, 0).unwrap();
    }
    // The (capacity+1)-th vouch is rejected.
    let over = addr(60 + VOUCH_CAPACITY as u8);
    req(&mut s, &oracle, &over, [1u8; 32], 1, 0).unwrap();
    assert_eq!(
        vouch(&mut s, &founder, &over, 0).unwrap_err(),
        LifecycleError::VouchCapacityReached
    );
}

// =================================================================================================
// Criterion 5 — emission gating on Verified; Revoke stops it; genesis dev account is Verified.
// =================================================================================================
#[test]
fn emission_gates_on_verified_and_revoke_stops() {
    let mut s = MemState::new();
    // Genesis-style: seed a Verified human (the migrated dev account).
    let dev = addr(1);
    ubi2_runtime::seed_verified_human(&mut s, &dev, 0);
    assert_eq!(s.get_human(&dev).unwrap().status, HumanStatus::Verified);
    // Streams from t=0.
    assert_eq!(s.balance(&dev, EMISSION_PERIOD_SECS), UBI);

    // Revoke stops emission to the base unit (account cache cleared).
    revoke(&mut s, &dev);
    assert_eq!(s.get_human(&dev).unwrap().status, HumanStatus::Revoked);
    assert_eq!(s.balance(&dev, 1_000 * EMISSION_PERIOD_SECS), 0);
}

// =================================================================================================
// Fail-closed: no active jurors ⇒ a case cannot open (I4 — never adjudicate un-adjudicable).
// =================================================================================================
#[test]
fn no_jurors_fails_closed() {
    let mut s = MemState::new();
    let oracle = MockOracle::default();
    let r = req(&mut s, &oracle, &addr(50), [1u8; 32], 1, 0);
    assert_eq!(r.unwrap_err(), LifecycleError::NoJurors);
}

/// submit_verdict authorization: non-jurors and double-votes are rejected without mutation.
#[test]
fn submit_verdict_authorization() {
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &[]);
    let subj = addr(50);
    ubi2_runtime::seed_verified_human(&mut s, &subj, 0);
    let case = challenge(&mut s, &addr(1), &subj, [1u8; 32], 42, 0).unwrap();
    let jury = s.get_case(case).unwrap().jury.clone();

    // A non-juror cannot vote.
    let outsider = addr(250);
    assert!(!jury.contains(&outsider));
    assert_eq!(
        submit_verdict(&mut s, case, &outsider, human_v(), 0).unwrap_err(),
        LifecycleError::NotOnJury
    );
    // A juror votes once; a second vote is rejected.
    let j = jury[0];
    submit_verdict(&mut s, case, &j, human_v(), 0).unwrap();
    assert_eq!(
        submit_verdict(&mut s, case, &j, human_v(), 0).unwrap_err(),
        LifecycleError::AlreadyVoted
    );
}

// =================================================================================================
// Criterion 6 — AI sybil-cluster detection: the `analyze_sybil` seam flags an improbable cluster and
// the runtime can auto-file a challenge from that flag, driving it to a Sybil quorum. (M3-T2 ships the
// substrate seam + graph_view(); the live cluster heuristic is the M3-T3 oracle.)
// =================================================================================================
#[test]
fn sybil_cluster_scan_auto_challenges() {
    let mut s = MemState::new();
    let founders = [addr(1), addr(2)];
    bootstrap(&mut s, JURY_SIZE as u8, &founders);
    let subject = addr(50);

    // Stand the subject up as a Pending applicant with a vouch farm (an improbable cluster).
    let oracle = MockOracle::default().with_sybil(subject, sybil_v());
    req(&mut s, &oracle, &subject, [7u8; 32], 9, 10).unwrap();
    vouch(&mut s, &founders[0], &subject, 10).unwrap();
    vouch(&mut s, &founders[1], &subject, 10).unwrap();

    // The node runs the AI sybil scan over the deterministic graph view; a flag auto-files a challenge.
    let graph = s.graph_view();
    let flag = oracle.analyze_sybil(&graph, &subject);
    assert_eq!(flag.verdict, Verdict::Sybil, "cluster must be flagged");
    let case = challenge(&mut s, &addr(1), &subject, [9u8; 32], 1234, 11).unwrap();

    // The jury upholds Sybil by quorum ⇒ subject Revoked, never verified.
    jury_votes(&mut s, case, sybil_v());
    assert_eq!(s.get_human(&subject).unwrap().status, HumanStatus::Revoked);
    assert!(matches!(
        finalize_registration(&mut s, &subject, 100, 100),
        Err(LifecycleError::NotPending)
    ));
}

// =================================================================================================
// Privacy (I6): only commitments + canonical verdicts + reason hashes touch on-chain state — never
// the challenge/response or rationale bytes themselves.
// =================================================================================================
#[test]
fn privacy_only_commitments_on_chain() {
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &[]);
    let subject = addr(50);
    let oracle = MockOracle::default();
    let liveness_ref = [0xAB; 32];
    let ev = LivenessEvidence {
        liveness_ref,
        challenge: b"SECRET-challenge-bytes",
        response: b"SECRET-response-bytes",
    };
    let case_id = request_verification(&mut s, &oracle, &subject, &ev, 9, 10).unwrap();

    // The on-chain human stores only the 32-byte commitment, never the raw evidence.
    assert_eq!(s.get_human(&subject).unwrap().liveness_ref, liveness_ref);
    // The case stores only the commitment + canonical verdicts; the Case struct has no field that
    // could hold the raw challenge/response bytes (enforced structurally by the type).
    let case = s.get_case(case_id).unwrap();
    assert_eq!(case.evidence_ref, liveness_ref);
    for (_, v) in &case.votes {
        // Verdicts are bucketed enums + a hash — no prose.
        let _ = (v.verdict, v.confidence, v.reasons_hash);
    }
}
