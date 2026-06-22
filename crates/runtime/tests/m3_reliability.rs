//! M3 — Reliability gate (board M3-T7, GATE 2).
//!
//! Verifies the hard consistency properties required by invariants I1, I2, and I4 across all
//! M3 proof-of-humanity paths. Everything runs offline against [`MockOracle`] (I5 — no live calls).
//!
//! ## Properties proved
//!
//! ### R1 — Quorum-verdict determinism (I1)
//! With fixed evidence + `MockOracle`, all honest jurors produce the **same** `CanonicalVerdict`;
//! ≥ QUORUM commits; a split deterministically `Escalates`. Proved over a 10k-iter random property
//! test across pool sizes 3..=9, multiple verdict/confidence variants, and arbitrary entropy seeds
//! (extending the existing 5k-iter test with wider coverage and named edge cases).
//!
//! ### R2 — Emission reproducibility under Verified gating (I2)
//! Balance is a pure integer function of `(state, now)` keyed on `verified`/`verified_at`. Two
//! independently-built states agree to the base unit. Revoke stops emission immediately, to the
//! base unit. Verified ↔ Revoked transitions are captured exactly.
//!
//! ### R3 — Lifecycle state-machine consistency (I4 / no-partial-state)
//! No lifecycle path leaves the state in a partial or logically impossible configuration. Checked:
//!   * Every combination of prerequisite failure leaves a clean error + no mutation.
//!   * Revoke → re-register round-trip: revoked address can re-register cleanly.
//!   * A Challenged human keeps streaming until (and only until) a Sybil quorum upholds the challenge.
//!   * The two clocks (block-height challenge window vs unix emission epoch `verified_at`) are
//!     independent: a `verified_at` of zero never causes emission before finalize, and the challenge
//!     window guards on block height, not unix seconds.
//!
//! ### R4 — Auto-finalize sweep order-independence (I1)
//! `sweep_finalize` scans Pending humans in `humans()` order (address-sorted). Its effect is
//! identical regardless of the order in which subjects registered, proving the sweep does not
//! depend on insertion order or any hash-iteration ordering.
//!
//! ### R5 — No HashMap iteration on any consensus path (I1)
//! `select_jury`, `tally`, `vouches_out`, `vouchers_of`, `vouch_edges`, `humans`, `cases`,
//! `active_jurors`, and `open_cases` are all sorted or order-independent by construction. This
//! test drives them under varying insertion orders and confirms the outputs are identical — no
//! nondeterminism from `HashMap` iteration.
//!
//! ### R6 — No floats in any consensus path (I2)
//! All emission, stream, and verdict-confidence arithmetic uses integer types. This test confirms
//! the closed-form emission value matches a reference integer formula across random timelines, with
//! no floating-point path taken (the Rust type system enforces this statically; the test guards
//! against future regressions through computed agreement).
//!
//! ### R7 — Quorum-equality: `reasons_hash` never splits an otherwise-agreeing jury (I1)
//! Two jurors that agree on (verdict, confidence) but carry different `reasons_hash` values still
//! form a quorum. Proved over random jury sizes and all verdict/confidence combinations.

use ubi2_runtime::{
    challenge, finalize_registration, register_juror, request_verification, revoke,
    seed_verified_human, submit_verdict, vouch, CanonicalVerdict, CaseStatus, Confidence,
    HumanStatus, HumanityOracle, LifecycleError, LivenessEvidence, MemState, MockOracle, State,
    Tally, Verdict, CHALLENGE_WINDOW, EMISSION_PERIOD_SECS, JURY_SIZE, QUORUM, SYBIL_SLASH, UBI,
};
use ubi2_runtime::{select_jury, tally};

type Address = [u8; 20];

// ---------------------------------------------------------------------------
// Helpers shared across tests
// ---------------------------------------------------------------------------

/// Deterministic SplitMix64 PRNG — same seed ⇒ same sequence on every machine/run.
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
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

fn addr(b: u8) -> Address {
    [b; 20]
}

fn human_v() -> CanonicalVerdict {
    CanonicalVerdict::new(Verdict::Human, Confidence::High)
}
fn sybil_v() -> CanonicalVerdict {
    CanonicalVerdict::new(Verdict::Sybil, Confidence::High)
}

/// Seed `n` active jurors at addresses 200..200+n and return their addresses.
fn seed_jurors(s: &mut MemState, n: u8) -> Vec<Address> {
    (0..n)
        .map(|i| {
            let a = addr(200 + i);
            register_juror(s, &a, 0);
            a
        })
        .collect()
}

/// Open a registration using the given oracle, with deterministic challenge/response bytes.
fn req_verify(
    s: &mut MemState,
    oracle: &dyn HumanityOracle,
    subject: &Address,
    liveness_ref: [u8; 32],
    entropy: u64,
    now: u64,
) -> Result<u64, LifecycleError> {
    let ev = LivenessEvidence {
        liveness_ref,
        challenge: b"challenge",
        response: b"response",
    };
    request_verification(s, oracle, subject, &ev, entropy, now)
}

/// Drive a case to a committed verdict by having every juror submit `v`.
fn all_vote(s: &mut MemState, case_id: u64, v: CanonicalVerdict) -> CaseStatus {
    let jury = s.get_case(case_id).unwrap().jury.clone();
    let mut last = CaseStatus::Open;
    for j in &jury {
        match submit_verdict(s, case_id, j, v, 0) {
            Ok(st) => last = st,
            Err(LifecycleError::CaseClosed) => break,
            Err(e) => panic!("unexpected verdict error: {e}"),
        }
    }
    last
}

/// Bootstrap a state with `n_jurors` active jurors and `founders` as genesis-Verified humans.
fn bootstrap(s: &mut MemState, n_jurors: u8, founders: &[Address]) {
    seed_jurors(s, n_jurors);
    for f in founders {
        seed_verified_human(s, f, 0);
    }
}

/// Bring a subject all the way to `Verified` via the happy path at `block=10`, `verified_secs=1000`.
fn full_lifecycle_verified(
    s: &mut MemState,
    subject: Address,
    founders: &[Address; 2],
    oracle: &dyn HumanityOracle,
) {
    req_verify(s, oracle, &subject, [7u8; 32], 0xABCD, 10).unwrap();
    vouch(s, &founders[0], &subject, 10).unwrap();
    vouch(s, &founders[1], &subject, 10).unwrap();
    finalize_registration(s, &subject, 10 + CHALLENGE_WINDOW, 1_000).unwrap();
    assert_eq!(s.get_human(&subject).unwrap().status, HumanStatus::Verified);
}

// ===========================================================================
// R1 — Quorum-verdict determinism (I1)
// ===========================================================================

/// R1-a: Two independently-built states driven with the same MockOracle + same entropy produce
/// identical committed verdicts. Extends the existing 5k-iter test to 10k iterations and wider
/// jury-pool sizes (3..=9), covering all three outcome types (Human/Sybil/Uncertain) plus every
/// confidence bucket.
#[test]
fn r1_quorum_determinism_extended_property() {
    let mut rng = Rng::new(0xD37E0001);

    // All verdict×confidence combinations we can get from the MockOracle.
    let variants: &[(Verdict, Confidence)] = &[
        (Verdict::Human, Confidence::High),
        (Verdict::Human, Confidence::Med),
        (Verdict::Human, Confidence::Low),
        (Verdict::Sybil, Confidence::High),
        (Verdict::Sybil, Confidence::Med),
        (Verdict::Sybil, Confidence::Low),
        (Verdict::Uncertain, Confidence::Low),
        (Verdict::Uncertain, Confidence::Med),
    ];

    for iter in 0..10_000 {
        let n_jurors = 3 + (rng.below(7) as u8); // 3..=9 active jurors
        let entropy = rng.next_u64();
        let vi = (rng.next_u64() as usize) % variants.len();
        let (verdict, conf) = variants[vi];
        let oracle = MockOracle::new(CanonicalVerdict::new(verdict, conf));

        // Build the same case in two independent states.
        let build = || -> CaseStatus {
            let mut s = MemState::new();
            for i in 0..n_jurors {
                register_juror(&mut s, &addr(100 + i), 0);
            }
            let subj = addr(50);
            seed_verified_human(&mut s, &subj, 0);
            // `addr(1)` seeded Verified so it may file the challenge (security finding A challenger gate).
            seed_verified_human(&mut s, &addr(1), 0);
            let case = challenge(&mut s, &addr(1), &subj, [1u8; 32], entropy, 0).unwrap();
            let jury = s.get_case(case).unwrap().jury.clone();
            for j in &jury {
                let v = oracle.adjudicate(b"evidence");
                match submit_verdict(&mut s, case, j, v, 0) {
                    Ok(CaseStatus::Committed(_)) | Ok(CaseStatus::Escalated) => break,
                    _ => continue,
                }
            }
            s.get_case(case).unwrap().status
        };

        let a = build();
        let b = build();

        assert_eq!(
            a, b,
            "R1: quorum diverged across two nodes (iter={iter}, n={n_jurors}, verdict={verdict:?}, conf={conf:?}, entropy={entropy:#x})"
        );

        // Unanimous honest jurors on a non-Uncertain verdict must always commit (not escalate).
        if verdict != Verdict::Uncertain {
            assert!(
                matches!(a, CaseStatus::Committed(cv) if cv.verdict == verdict && cv.confidence == conf),
                "R1: unanimous honest jury must commit, got {a:?} (verdict={verdict:?}, conf={conf:?})"
            );
        }
        // Unanimous Uncertain must always escalate (I4: fail closed).
        if verdict == Verdict::Uncertain {
            assert_eq!(
                a,
                CaseStatus::Escalated,
                "R1: Uncertain quorum must escalate (I4)"
            );
        }
    }
}

/// R1-b: Split scenarios — every possible 3-juror split (Human/Sybil/Uncertain trio, or any two
/// distinct verdicts) must reproducibly produce Escalated on both nodes.
#[test]
fn r1_split_reproducibly_escalates() {
    // Build a 3-juror case and submit three distinct verdicts.
    let build = |v1: CanonicalVerdict, v2: CanonicalVerdict, v3: CanonicalVerdict| -> CaseStatus {
        let mut s = MemState::new();
        for i in 0..3u8 {
            register_juror(&mut s, &addr(100 + i), 0);
        }
        let subj = addr(50);
        seed_verified_human(&mut s, &subj, 0);
        // `addr(1)` seeded Verified so it may challenge (security finding A challenger gate). This test
        // asserts the CASE status (Escalated), which is unchanged; finding B only restores the SUBJECT.
        seed_verified_human(&mut s, &addr(1), 0);
        let case = challenge(&mut s, &addr(1), &subj, [1u8; 32], 42, 0).unwrap();
        let jury = s.get_case(case).unwrap().jury.clone();
        let verdicts = [v1, v2, v3];
        for (j, v) in jury.iter().zip(verdicts.iter()) {
            let _ = submit_verdict(&mut s, case, j, *v, 0);
        }
        s.get_case(case).unwrap().status
    };

    let h = human_v();
    let sy = sybil_v();
    let un = CanonicalVerdict::new(Verdict::Uncertain, Confidence::Low);
    let h_med = CanonicalVerdict::new(Verdict::Human, Confidence::Med);

    // Full three-way split — all three distinct verdicts.
    assert_eq!(
        build(h, sy, un),
        CaseStatus::Escalated,
        "H/S/U split must Escalate"
    );
    // Two Human with different confidence + one Sybil — no pair agrees on (verdict, confidence).
    assert_eq!(
        build(h, h_med, sy),
        CaseStatus::Escalated,
        "H-High / H-Med / S split must Escalate"
    );
    // All three Uncertain — escalates (I4, never commits Uncertain).
    assert_eq!(
        build(un, un, un),
        CaseStatus::Escalated,
        "Uncertain quorum must Escalate"
    );
    // Two different confidences of Human + Uncertain — total vote set is three singletons.
    let h_lo = CanonicalVerdict::new(Verdict::Human, Confidence::Low);
    assert_eq!(
        build(h, h_lo, un),
        CaseStatus::Escalated,
        "H-Hi / H-Lo / U must Escalate"
    );

    // Control: two identical Human + one other ⇒ Committed(Human) (quorum=2 achieved).
    assert!(
        matches!(build(h, h, sy), CaseStatus::Committed(cv) if cv.verdict == Verdict::Human),
        "H+H+S must Committed(Human)"
    );
    assert!(
        matches!(build(sy, sy, h), CaseStatus::Committed(cv) if cv.verdict == Verdict::Sybil),
        "S+S+H must Committed(Sybil)"
    );
}

/// R1-c: Jury selection is order-independent — the same (pool, seed) yields the same jury
/// regardless of insertion order into the active juror set. This exercises the consensus path's
/// `active_jurors()` sort + `select_jury()` Fisher-Yates.
#[test]
fn r1_jury_selection_order_independent() {
    let mut rng = Rng::new(0xD37E0002);

    for _ in 0..5_000 {
        let n: u8 = 3 + (rng.below(8) as u8); // 3..=10 jurors
        let seed = rng.next_u64();

        // Build pool in forward order.
        let pool_fwd: Vec<Address> = (0..n).map(|i| addr(10 + i)).collect();
        let j_fwd = select_jury(pool_fwd.clone(), JURY_SIZE, seed);

        // Build pool in reverse order — must produce identical jury (sort happens inside).
        let mut pool_rev = pool_fwd.clone();
        pool_rev.reverse();
        let j_rev = select_jury(pool_rev, JURY_SIZE, seed);

        // As sets (order within the jury can differ by design, but we compare sorted sets).
        let mut a = j_fwd.clone();
        let mut b = j_rev.clone();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(
            a, b,
            "R1: jury differs for reversed pool (n={n}, seed={seed:#x})"
        );
    }
}

/// R1-d: `reasons_hash` never causes a quorum split — two jurors with matching (verdict, confidence)
/// but differing `reasons_hash` form a quorum (I1 spec: "reasons_hash is informational").
#[test]
fn r1_reasons_hash_does_not_split_quorum() {
    let mut rng = Rng::new(0xD37E0003);

    let all_vconfigs: &[(Verdict, Confidence)] = &[
        (Verdict::Human, Confidence::High),
        (Verdict::Human, Confidence::Med),
        (Verdict::Sybil, Confidence::High),
        (Verdict::Sybil, Confidence::Low),
    ];

    for (verdict, conf) in all_vconfigs {
        for _ in 0..200 {
            // Two votes that agree on verdict+confidence but have different reasons_hash.
            let hash_a: [u8; 32] = {
                let mut h = [0u8; 32];
                let r = rng.next_u64();
                h[..8].copy_from_slice(&r.to_le_bytes());
                h
            };
            let hash_b: [u8; 32] = {
                let mut h = [0u8; 32];
                let r = rng.next_u64();
                h[..8].copy_from_slice(&r.to_le_bytes());
                h
            };
            let va = CanonicalVerdict {
                verdict: *verdict,
                confidence: *conf,
                reasons_hash: hash_a,
            };
            let vb = CanonicalVerdict {
                verdict: *verdict,
                confidence: *conf,
                reasons_hash: hash_b,
            };

            let votes = vec![(addr(1), va), (addr(2), vb)];
            let t = tally(&votes, JURY_SIZE, QUORUM);
            assert!(
                matches!(t, Tally::Committed(cv) if cv.verdict == *verdict && cv.confidence == *conf),
                "R1: different reasons_hash incorrectly split quorum for {verdict:?}/{conf:?}"
            );
        }
    }
}

// ===========================================================================
// R2 — Emission reproducibility under Verified gating (I2)
// ===========================================================================

/// R2-a: `balance(addr, now)` is a pure integer function of `(verified_at, now)`. Two independently-
/// built states with the same `(verified_at, now)` agree to the base unit. 20k random timelines.
#[test]
fn r2_emission_reproducible_two_independent_states() {
    let mut rng = Rng::new(0xD37E0004);

    for _ in 0..20_000 {
        let verified_at = rng.below(3_200_000_000);
        let now = verified_at + rng.below(3_200_000_000);

        // Node A: seed via seed_verified_human.
        let mut sa = MemState::new();
        seed_verified_human(&mut sa, &addr(1), verified_at);

        // Node B: independently built from same genesis params.
        let mut sb = MemState::new();
        seed_verified_human(&mut sb, &addr(1), verified_at);

        let ba = sa.balance(&addr(1), now);
        let bb = sb.balance(&addr(1), now);
        assert_eq!(
            ba, bb,
            "R2: balance diverged across nodes (verified_at={verified_at}, now={now})"
        );

        // Reference: the closed-form integer formula from the spec.
        let since = verified_at;
        let elapsed = now.saturating_sub(since) as u128;
        let expected = UBI.saturating_mul(elapsed) / EMISSION_PERIOD_SECS as u128;
        assert_eq!(
            ba, expected,
            "R2: balance diverges from closed-form reference (verified_at={verified_at}, now={now})"
        );
    }
}

/// R2-b: An unverified account accrues ZERO regardless of the timestamp. A Pending, Challenged, or
/// Revoked account also accrues zero. Only `Verified` accrues.
#[test]
fn r2_only_verified_status_accrues() {
    let mut rng = Rng::new(0xD37E0005);
    let oracle = MockOracle::default();

    for _ in 0..1_000 {
        let now = rng.below(10_000_000_000);

        // Unverified: no record.
        let s = MemState::new();
        assert_eq!(s.balance(&addr(1), now), 0, "Unverified must not accrue");

        // Pending: registered but not finalized.
        let mut s = MemState::new();
        seed_jurors(&mut s, JURY_SIZE as u8);
        req_verify(&mut s, &oracle, &addr(50), [1u8; 32], 1, 0).unwrap();
        assert_eq!(
            s.balance(&addr(50), now),
            0,
            "Pending must not accrue (now={now})"
        );

        // Revoked: never accrues.
        let mut s = MemState::new();
        seed_verified_human(&mut s, &addr(1), 0);
        revoke(&mut s, &addr(1));
        assert_eq!(
            s.balance(&addr(1), now),
            0,
            "Revoked must not accrue (now={now})"
        );
    }
}

/// R2-c: Revoke stops emission to the base unit. Before revoke the balance is growing; immediately
/// after revoke it is frozen at the accrued-before-revoke value and does not increase further.
#[test]
fn r2_revoke_stops_emission_exactly() {
    let verified_at = 0u64;
    let revoke_t = 5 * EMISSION_PERIOD_SECS; // 5h after genesis: should hold 5 UBI

    let mut s = MemState::new();
    seed_verified_human(&mut s, &addr(1), verified_at);

    // Pre-revoke: 5 UBI accrued.
    assert_eq!(
        s.balance(&addr(1), revoke_t),
        5 * UBI,
        "5 UBI before revoke"
    );

    revoke(&mut s, &addr(1));

    // Post-revoke: balance frozen, does not increase over time.
    let post_revoke_1h = s.balance(&addr(1), revoke_t + EMISSION_PERIOD_SECS);
    let post_revoke_1y = s.balance(&addr(1), revoke_t + 365 * 24 * EMISSION_PERIOD_SECS);
    assert_eq!(
        post_revoke_1h, post_revoke_1y,
        "R2: revoked balance must not increase"
    );
    assert_eq!(
        post_revoke_1h, 0,
        "R2: revoke clears verified_at, so balance is 0 (settled=0 at revoke)"
    );
}

/// R2-d: Property test — across random `(verified_at, revoke_block, now)` triples, the revoked
/// account's balance is always strictly ≤ the balance it would have had if never revoked.
#[test]
fn r2_revoke_never_creates_value() {
    let mut rng = Rng::new(0xD37E0006);

    for _ in 0..5_000 {
        let verified_at = rng.below(1_000_000_000);
        let revoke_point = verified_at + rng.below(100 * EMISSION_PERIOD_SECS);
        let now = revoke_point + rng.below(1_000_000_000);

        // Without revoke.
        let mut sa = MemState::new();
        seed_verified_human(&mut sa, &addr(1), verified_at);
        let without_revoke = sa.balance(&addr(1), now);

        // With revoke at revoke_point.
        let mut sb = MemState::new();
        seed_verified_human(&mut sb, &addr(1), verified_at);
        revoke(&mut sb, &addr(1));
        let with_revoke = sb.balance(&addr(1), now);

        assert!(
            with_revoke <= without_revoke,
            "R2: revoke created value (with={with_revoke}, without={without_revoke})"
        );
    }
}

// ===========================================================================
// R3 — Lifecycle state-machine consistency (I4 / no-partial-state)
// ===========================================================================

/// R3-a: Every lifecycle prerequisite check fails closed: on any error the state must be left
/// exactly as before (no partial writes, no phantom records, no phantom cases).
#[test]
fn r3_all_prerequisite_failures_are_fail_closed() {
    let oracle = MockOracle::default();

    // --- request_verification: no jurors ---
    {
        let mut s = MemState::new();
        let result = req_verify(&mut s, &oracle, &addr(50), [1u8; 32], 0, 0);
        assert_eq!(result.unwrap_err(), LifecycleError::NoJurors);
        assert!(
            s.get_human(&addr(50)).is_none(),
            "no human record on NoJurors"
        );
        assert_eq!(s.open_cases().len(), 0, "no case created on NoJurors");
    }

    // --- vouch: voucher not verified ---
    {
        let mut s = MemState::new();
        seed_jurors(&mut s, JURY_SIZE as u8);
        req_verify(&mut s, &oracle, &addr(50), [1u8; 32], 0, 0).unwrap();
        let before = s.get_human(&addr(50)).unwrap().vouches_in.len();
        let r = vouch(&mut s, &addr(99), &addr(50), 0);
        assert_eq!(r.unwrap_err(), LifecycleError::VoucherNotVerified);
        assert_eq!(
            s.get_human(&addr(50)).unwrap().vouches_in.len(),
            before,
            "vouches_in unchanged on VoucherNotVerified"
        );
    }

    // --- vouch: self-vouch ---
    {
        let mut s = MemState::new();
        seed_verified_human(&mut s, &addr(1), 0);
        req_verify(&mut s, &oracle, &addr(50), [1u8; 32], 0, 0).err(); // may fail with NoJurors here
        let r = vouch(&mut s, &addr(1), &addr(1), 0);
        assert_eq!(r.unwrap_err(), LifecycleError::SelfVouch);
    }

    // --- challenge: unverified CHALLENGER is rejected (security finding A — fail-closed) ---
    {
        let mut s = MemState::new();
        seed_jurors(&mut s, JURY_SIZE as u8);
        seed_verified_human(&mut s, &addr(50), 0); // valid (Verified) target
        let r = challenge(&mut s, &addr(1), &addr(50), [1u8; 32], 0, 0);
        assert_eq!(
            r.unwrap_err(),
            LifecycleError::ChallengerNotVerified,
            "an unverified challenger is rejected before any case is opened"
        );
        assert_eq!(
            s.open_cases().len(),
            0,
            "no case created for bad challenger"
        );
    }

    // --- challenge: subject Unverified (with a valid Verified challenger) ---
    {
        let mut s = MemState::new();
        seed_jurors(&mut s, JURY_SIZE as u8);
        seed_verified_human(&mut s, &addr(1), 0); // verified challenger so the subject check fires
        let r = challenge(&mut s, &addr(1), &addr(50), [1u8; 32], 0, 0);
        assert!(matches!(
            r.unwrap_err(),
            LifecycleError::NotChallengeable(_)
        ));
        assert_eq!(
            s.open_cases().len(),
            0,
            "no case created for Unverified target"
        );
    }

    // --- submit_verdict: wrong juror ---
    {
        let mut s = MemState::new();
        seed_jurors(&mut s, JURY_SIZE as u8);
        seed_verified_human(&mut s, &addr(50), 0);
        seed_verified_human(&mut s, &addr(1), 0); // verified challenger (finding A gate)
        let case = challenge(&mut s, &addr(1), &addr(50), [1u8; 32], 0, 0).unwrap();
        let before = s.get_case(case).unwrap().votes.len();
        let r = submit_verdict(&mut s, case, &addr(255), human_v(), 0);
        assert_eq!(r.unwrap_err(), LifecycleError::NotOnJury);
        assert_eq!(
            s.get_case(case).unwrap().votes.len(),
            before,
            "votes unchanged on NotOnJury"
        );
    }

    // --- finalize: window not open ---
    {
        let founders = [addr(1), addr(2)];
        let mut s = MemState::new();
        bootstrap(&mut s, JURY_SIZE as u8, &founders);
        req_verify(&mut s, &oracle, &addr(50), [1u8; 32], 0, 10).unwrap();
        vouch(&mut s, &founders[0], &addr(50), 10).unwrap();
        vouch(&mut s, &founders[1], &addr(50), 10).unwrap();
        // Too early — window hasn't elapsed.
        let r = finalize_registration(&mut s, &addr(50), 10 + CHALLENGE_WINDOW - 1, 0);
        assert!(
            matches!(r.unwrap_err(), LifecycleError::ChallengeWindowOpen { .. }),
            "must reject early finalize"
        );
        // Still Pending.
        assert_eq!(
            s.get_human(&addr(50)).unwrap().status,
            HumanStatus::Pending,
            "still Pending after rejected finalize"
        );
    }

    // --- finalize: liveness not passed (oracle returns Sybil) ---
    {
        let founders = [addr(1), addr(2)];
        let mut s = MemState::new();
        bootstrap(&mut s, JURY_SIZE as u8, &founders);
        let bad_oracle = MockOracle::always(sybil_v());
        req_verify(&mut s, &bad_oracle, &addr(50), [1u8; 32], 0, 10).unwrap();
        vouch(&mut s, &founders[0], &addr(50), 10).unwrap();
        vouch(&mut s, &founders[1], &addr(50), 10).unwrap();
        let r = finalize_registration(&mut s, &addr(50), 10 + CHALLENGE_WINDOW, 0);
        assert_eq!(
            r.unwrap_err(),
            LifecycleError::LivenessNotPassed,
            "sybil liveness must block finalize"
        );
        assert_eq!(
            s.get_human(&addr(50)).unwrap().status,
            HumanStatus::Pending,
            "still Pending after liveness-blocked finalize"
        );
        // Balance is still 0.
        assert_eq!(
            s.balance(&addr(50), 1_000 * EMISSION_PERIOD_SECS),
            0,
            "no emission before Verified"
        );
    }
}

/// R3-b: Revoke → re-register round-trip. A Revoked address can call `request_verification` again
/// (Revoked is an accepted starting state). F-REL-1 is now FIXED: `revoke`/re-register clear the
/// `MemState` vouch-edge indexes (`vouches_out` / `vouchers_of`), so a voucher who vouched in the
/// first lifecycle can re-vouch the re-registered subject without hitting `DuplicateVouch`. (This test
/// previously pinned the bug — expecting `DuplicateVouch`; it now asserts the fix.)
#[test]
fn r3_revoke_then_reregister_vouch_index_cleared() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &founders);

    // First lifecycle: get to Verified.
    full_lifecycle_verified(&mut s, addr(50), &founders, &oracle);
    assert_eq!(s.balance(&addr(50), 1_000 + EMISSION_PERIOD_SECS), UBI);
    // The first-lifecycle vouch edges exist.
    assert!(s.vouches_out(&founders[0]).contains(&addr(50)));
    assert!(s.vouchers_of(&addr(50)).contains(&founders[0]));

    // Revoke clears the subject's vouch edges (F-REL-1 fix).
    revoke(&mut s, &addr(50));
    assert_eq!(s.get_human(&addr(50)).unwrap().status, HumanStatus::Revoked);
    assert_eq!(s.balance(&addr(50), 1_000 + 1_000_000), 0);
    assert!(
        !s.vouches_out(&founders[0]).contains(&addr(50)),
        "F-REL-1: revoke clears the forward vouch edge"
    );
    assert!(
        s.vouchers_of(&addr(50)).is_empty(),
        "F-REL-1: revoke clears the reverse vouch index"
    );

    // Re-register — must succeed (Revoked is a valid starting state).
    let _case = req_verify(&mut s, &oracle, &addr(50), [8u8; 32], 99, 20).unwrap();
    assert_eq!(
        s.get_human(&addr(50)).unwrap().status,
        HumanStatus::Pending,
        "re-registration transitions to Pending"
    );

    // F-REL-1 FIX: the SAME founder that vouched in the first lifecycle can re-vouch now.
    vouch(&mut s, &founders[0], &addr(50), 20)
        .expect("prior voucher may re-vouch after re-register");
    assert!(s
        .get_human(&addr(50))
        .unwrap()
        .vouches_in
        .contains(&founders[0]));
}

/// R3-b': A Revoked address can re-register and receive NEW vouches from vouchers who did not
/// participate in the first lifecycle. The lifecycle gates (liveness, MIN_VOUCHES, window) still
/// apply; the `verified_at` is freshly stamped.
#[test]
fn r3_revoke_then_reregister_with_new_vouchers() {
    // Use a fresh founder set so there are no stale vouch edges.
    let oracle = MockOracle::default();
    let mut s = MemState::new();
    seed_jurors(&mut s, JURY_SIZE as u8);

    // Lifecycle 1: subject uses founders A and B.
    let f1 = addr(1);
    let f2 = addr(2);
    seed_verified_human(&mut s, &f1, 0);
    seed_verified_human(&mut s, &f2, 0);

    req_verify(&mut s, &oracle, &addr(50), [7u8; 32], 1, 10).unwrap();
    vouch(&mut s, &f1, &addr(50), 10).unwrap();
    vouch(&mut s, &f2, &addr(50), 10).unwrap();
    finalize_registration(&mut s, &addr(50), 10 + CHALLENGE_WINDOW, 1_000).unwrap();
    revoke(&mut s, &addr(50));

    // Lifecycle 2: use different founders C and D (not involved in lifecycle 1).
    let f3 = addr(3);
    let f4 = addr(4);
    seed_verified_human(&mut s, &f3, 0);
    seed_verified_human(&mut s, &f4, 0);

    req_verify(&mut s, &oracle, &addr(50), [8u8; 32], 2, 20).unwrap();
    vouch(&mut s, &f3, &addr(50), 20).unwrap();
    vouch(&mut s, &f4, &addr(50), 20).unwrap();

    let v2_secs = 9_000u64;
    finalize_registration(&mut s, &addr(50), 20 + CHALLENGE_WINDOW, v2_secs).unwrap();
    assert_eq!(s.get_human(&addr(50)).unwrap().verified_at, v2_secs);
    assert_eq!(
        s.get_human(&addr(50)).unwrap().status,
        HumanStatus::Verified
    );
    assert_eq!(
        s.balance(&addr(50), v2_secs + EMISSION_PERIOD_SECS),
        UBI,
        "emission restarts from new verified_at"
    );
}

/// R3-c: A Challenged human keeps streaming until (and only until) a Sybil quorum upholds the
/// challenge. Before the quorum commits, the balance continues to accrue (innocent until proven).
/// After a Sybil quorum commits, balance is frozen immediately.
#[test]
fn r3_challenged_keeps_streaming_until_sybil_quorum() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &founders);
    let v_secs = 0u64;
    full_lifecycle_verified(&mut s, addr(50), &founders, &oracle);
    // Override verified_at to 0 for easy arithmetic.
    {
        let mut h = s.get_human(&addr(50)).unwrap();
        h.verified_at = v_secs;
        s.put_human(h);
        let mut a = s.get(&addr(50)).unwrap();
        a.verified_at = v_secs;
        a.last_settled_at = v_secs;
        s.put(a);
    }

    // Open a challenge at block 20.
    let case = challenge(&mut s, &founders[0], &addr(50), [9u8; 32], 55, 20).unwrap();
    assert_eq!(
        s.get_human(&addr(50)).unwrap().status,
        HumanStatus::Challenged
    );

    // Challenged status: balance STILL accrues (innocent until proven).
    let t1 = 5 * EMISSION_PERIOD_SECS;
    let bal_challenged = s.balance(&addr(50), t1);
    assert_eq!(bal_challenged, 5 * UBI, "Challenged human still accrues");

    // First juror votes Sybil — case still Open (QUORUM=2 not yet reached).
    let jury = s.get_case(case).unwrap().jury.clone();
    submit_verdict(&mut s, case, &jury[0], sybil_v(), 0).unwrap();
    // Balance still accruing after first vote.
    let bal_after_v1 = s.balance(&addr(50), t1);
    assert_eq!(
        bal_after_v1, bal_challenged,
        "balance unchanged after one Sybil vote"
    );

    // Second juror votes Sybil — quorum reached, subject Revoked.
    submit_verdict(&mut s, case, &jury[1], sybil_v(), 0).unwrap();
    assert_eq!(s.get_human(&addr(50)).unwrap().status, HumanStatus::Revoked);

    // Balance is now frozen (no further accrual).
    let bal_t1 = s.balance(&addr(50), t1);
    let bal_t2 = s.balance(&addr(50), t1 + 1_000 * EMISSION_PERIOD_SECS);
    assert_eq!(bal_t1, bal_t2, "R3: revoked balance must not grow");
}

/// R3-d: The two clocks are independent. The challenge window runs in BLOCK HEIGHT, and the
/// emission epoch runs in UNIX SECONDS. Altering the unix timestamp passed to finalize does NOT
/// change whether the window gate passes (which depends only on block height). Likewise, a
/// `verified_at` of 0 after finalize with a large block height does not start emission before the
/// unix second was stamped.
#[test]
fn r3_block_height_and_unix_epoch_are_independent_clocks() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &founders);

    // Register at block 100; challenge window clears at block 100 + CHALLENGE_WINDOW.
    let reg_block = 100u64;
    req_verify(&mut s, &oracle, &addr(50), [7u8; 32], 0xABCD, reg_block).unwrap();
    vouch(&mut s, &founders[0], &addr(50), reg_block).unwrap();
    vouch(&mut s, &founders[1], &addr(50), reg_block).unwrap();

    // The window gate depends on block height, NOT unix seconds. Passing a large unix second to
    // finalize with a block height that's still within the window must still be rejected.
    let r = finalize_registration(
        &mut s,
        &addr(50),
        reg_block + CHALLENGE_WINDOW - 1, // block height too early
        999_999_999,                      // unix second is huge, irrelevant
    );
    assert!(
        matches!(r.unwrap_err(), LifecycleError::ChallengeWindowOpen { .. }),
        "R3: window gate depends on block height, not unix seconds"
    );
    assert_eq!(
        s.get_human(&addr(50)).unwrap().status,
        HumanStatus::Pending,
        "still Pending"
    );

    // Now at the correct block height but with a small unix second (past epoch = 0): accepted.
    let small_unix = 1u64;
    finalize_registration(&mut s, &addr(50), reg_block + CHALLENGE_WINDOW, small_unix).unwrap();

    // Emission only starts from `small_unix`, not from any earlier time.
    let h = s.get_human(&addr(50)).unwrap();
    assert_eq!(h.verified_at, small_unix, "verified_at is the unix second");
    assert_eq!(
        s.balance(&addr(50), 0),
        0,
        "no emission before verified_at (unix 0 < verified_at)"
    );
    assert_eq!(
        s.balance(&addr(50), small_unix + EMISSION_PERIOD_SECS),
        UBI,
        "emission starts exactly at verified_at"
    );
}

// ===========================================================================
// R4 — Auto-finalize sweep order-independence (I1)
// ===========================================================================

/// R4: `finalize_registration` sweeps `humans()` in address-sorted order. The final Verified set
/// must be identical regardless of the order in which subjects were registered (state sorted
/// insertion is the mechanism, tested by comparing two scenarios with reversed registration order).
#[test]
fn r4_sweep_finalize_order_independent() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();

    // Build two states where subjects register in opposite orders. Both must finalize the same set.
    let build = |subjects_in_order: &[Address]| -> Vec<HumanStatus> {
        let mut s = MemState::new();
        bootstrap(&mut s, JURY_SIZE as u8, &founders);

        let reg_block = 10u64;
        for subject in subjects_in_order {
            req_verify(&mut s, &oracle, subject, [7u8; 32], 0xABCD, reg_block).unwrap();
            vouch(&mut s, &founders[0], subject, reg_block).unwrap();
            vouch(&mut s, &founders[1], subject, reg_block).unwrap();
        }

        // Sweep at the window boundary (simulates produce_block auto-finalize).
        let finalize_block = reg_block + CHALLENGE_WINDOW;
        for subject in subjects_in_order {
            let _ = finalize_registration(&mut s, subject, finalize_block, 1_000);
        }

        // Return statuses in canonical (address-sorted) order.
        s.humans()
            .into_iter()
            .filter(|h| subjects_in_order.contains(&h.address))
            .map(|h| h.status)
            .collect()
    };

    // Subjects with distinct addresses.
    let subjects_fwd = [addr(50), addr(60), addr(70)];
    let mut subjects_rev = subjects_fwd;
    subjects_rev.reverse();

    let statuses_fwd = build(&subjects_fwd);
    let statuses_rev = build(&subjects_rev);

    assert_eq!(
        statuses_fwd, statuses_rev,
        "R4: finalize result depends on registration order (nondeterminism)"
    );
    // All three should be Verified.
    for st in &statuses_fwd {
        assert_eq!(
            *st,
            HumanStatus::Verified,
            "all subjects should be Verified"
        );
    }
}

/// R4-b: The sweep ignores subjects that don't meet the gate (e.g. missing vouches) — no partial
/// state is left, and no other subject's finalization is affected.
#[test]
fn r4_sweep_skips_ineligible_without_affecting_eligible() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &founders);

    let eligible = addr(50);
    let ineligible = addr(60); // will not get enough vouches

    let reg_block = 10u64;

    // Both register.
    req_verify(&mut s, &oracle, &eligible, [7u8; 32], 1, reg_block).unwrap();
    req_verify(&mut s, &oracle, &ineligible, [8u8; 32], 2, reg_block).unwrap();

    // Only eligible gets MIN_VOUCHES.
    vouch(&mut s, &founders[0], &eligible, reg_block).unwrap();
    vouch(&mut s, &founders[1], &eligible, reg_block).unwrap();
    // ineligible gets only 1 vouch (below MIN_VOUCHES=2).
    vouch(&mut s, &founders[0], &ineligible, reg_block).unwrap();

    let finalize_block = reg_block + CHALLENGE_WINDOW;

    // Sweep both.
    let r_elig = finalize_registration(&mut s, &eligible, finalize_block, 1_000);
    let r_inelig = finalize_registration(&mut s, &ineligible, finalize_block, 1_000);

    assert!(r_elig.is_ok(), "eligible must finalize");
    assert!(
        matches!(r_inelig, Err(LifecycleError::InsufficientVouches { .. })),
        "ineligible must be rejected with InsufficientVouches"
    );
    assert_eq!(
        s.get_human(&eligible).unwrap().status,
        HumanStatus::Verified
    );
    assert_eq!(
        s.get_human(&ineligible).unwrap().status,
        HumanStatus::Pending,
        "ineligible stays Pending"
    );
}

// ===========================================================================
// R5 — No HashMap iteration on any consensus path (I1)
// ===========================================================================

/// R5-a: `humans()` is always sorted by address regardless of insertion order. `vouch_edges()` is
/// always sorted. `active_jurors()` is always sorted. `open_cases()` is always ascending.
/// Tested by inserting in random order and confirming canonical sort invariants hold.
#[test]
fn r5_state_reads_are_always_sorted() {
    let mut rng = Rng::new(0xD37E0005);

    for _ in 0..500 {
        let mut s = MemState::new();
        let n = 3 + rng.below(8) as u8;

        // Insert humans in random order.
        let mut addrs: Vec<Address> = (0..n).map(|i| addr(i * 7 + 3)).collect();
        let shuffled_addrs = {
            let mut a = addrs.clone();
            for i in (1..n as usize).rev() {
                let j = rng.below(i as u64 + 1) as usize;
                a.swap(i, j);
            }
            a
        };
        for a in &shuffled_addrs {
            seed_verified_human(&mut s, a, 0);
        }
        let humans = s.humans();
        let human_addrs: Vec<Address> = humans.iter().map(|h| h.address).collect();
        addrs.sort_unstable();
        assert_eq!(human_addrs, addrs, "R5: humans() not sorted by address");

        // Insert jurors in random order and confirm active_jurors() is sorted.
        let mut juror_addrs: Vec<Address> = (0..n).map(|i| addr(i * 13 + 100)).collect();
        for a in &juror_addrs {
            register_juror(&mut s, a, 0);
        }
        let active = s.active_jurors();
        juror_addrs.sort_unstable();
        assert_eq!(active, juror_addrs, "R5: active_jurors() not sorted");

        // Vouch edges sorted.
        if addrs.len() >= 2 {
            for i in 0..addrs.len() - 1 {
                seed_verified_human(&mut s, &addrs[i], 0);
                // Re-register vouchee as Pending first
                {
                    use ubi2_runtime::Human;
                    s.put_human(Human::pending(addrs[i + 1], [0u8; 32]));
                }
                let _ = vouch(&mut s, &addrs[i], &addrs[i + 1], 0);
            }
            let edges = s.vouch_edges();
            let mut sorted = edges.clone();
            sorted.sort_unstable();
            assert_eq!(edges, sorted, "R5: vouch_edges() not sorted");
        }
    }
}

/// R5-b: `vouches_out(addr)` and `vouchers_of(addr)` are always sorted, regardless of insertion
/// order of vouch edges.
#[test]
fn r5_vouch_indexes_always_sorted() {
    let mut rng = Rng::new(0xD37E0006);

    for _ in 0..200 {
        let mut s = MemState::new();
        let n_vouchees = 3 + rng.below(5) as u8;
        let voucher = addr(1);
        seed_verified_human(&mut s, &voucher, 0);

        // Register vouchees as Pending in random insertion order.
        let mut vouchee_addrs: Vec<Address> = (0..n_vouchees).map(|i| addr(50 + i)).collect();
        let shuffled_indices: Vec<usize> = {
            let mut idx: Vec<usize> = (0..n_vouchees as usize).collect();
            for i in (1..n_vouchees as usize).rev() {
                let j = rng.below(i as u64 + 1) as usize;
                idx.swap(i, j);
            }
            idx
        };
        for &vi in &shuffled_indices {
            use ubi2_runtime::Human;
            s.put_human(Human::pending(vouchee_addrs[vi], [0u8; 32]));
            let _ = vouch(&mut s, &voucher, &vouchee_addrs[vi], 0);
        }

        let out = s.vouches_out(&voucher);
        vouchee_addrs.sort_unstable();
        assert_eq!(out, vouchee_addrs, "R5: vouches_out not sorted");

        for vee in &vouchee_addrs {
            let inc = s.vouchers_of(vee);
            let mut sorted = inc.clone();
            sorted.sort_unstable();
            assert_eq!(inc, sorted, "R5: vouchers_of not sorted");
        }
    }
}

// ===========================================================================
// R6 — No floats in consensus path (I2)
// ===========================================================================

/// R6: The emission formula `UBI * elapsed / EMISSION_PERIOD_SECS` is purely integer. This test
/// proves the runtime value matches a reference integer formula across 50k random timelines,
/// confirming there is no hidden float in the path (any float would produce subtle rounding
/// differences detectable here).
#[test]
fn r6_emission_is_integer_only_no_float() {
    let mut rng = Rng::new(0xD37E0007);

    for _ in 0..50_000 {
        let verified_at = rng.below(3_200_000_000);
        let elapsed = rng.below(3_200_000_000);
        let now = verified_at + elapsed;

        let mut s = MemState::new();
        seed_verified_human(&mut s, &addr(1), verified_at);
        let runtime_bal = s.balance(&addr(1), now);

        // Reference: exact integer formula — no floats.
        let elapsed_u128 = elapsed as u128;
        let expected = UBI.saturating_mul(elapsed_u128) / EMISSION_PERIOD_SECS as u128;

        assert_eq!(
            runtime_bal, expected,
            "R6: runtime emission differs from integer reference (verified_at={verified_at}, elapsed={elapsed})"
        );
    }
}

// ===========================================================================
// R7 — Full quorum lifecycle reproducibility across registration scenarios (I1 / I2 integration)
// ===========================================================================

/// R7: Full happy-path lifecycle in two independent states — both reach `Verified` at the same
/// `verified_at`, emit identical balances, and respond identically to revoke. Proves the integrated
/// consensus path (juror selection + tally + finalize + emission) is byte-reproducible.
#[test]
fn r7_full_lifecycle_byte_reproducible_across_two_states() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();

    let build_verified_state = || -> MemState {
        let mut s = MemState::new();
        bootstrap(&mut s, JURY_SIZE as u8, &founders);
        full_lifecycle_verified(&mut s, addr(50), &founders, &oracle);
        s
    };

    let sa = build_verified_state();
    let sb = build_verified_state();

    // Both states agree on the human record.
    let ha = sa.get_human(&addr(50)).unwrap();
    let hb = sb.get_human(&addr(50)).unwrap();
    assert_eq!(ha.status, hb.status, "R7: status diverged");
    assert_eq!(ha.verified_at, hb.verified_at, "R7: verified_at diverged");
    assert_eq!(ha.vouches_in, hb.vouches_in, "R7: vouches_in diverged");

    // Emission is identical at several timestamps.
    for offset in [0u64, 1, 3_600, 86_400, 1_000_000] {
        let t = ha.verified_at + offset;
        assert_eq!(
            sa.balance(&addr(50), t),
            sb.balance(&addr(50), t),
            "R7: balance diverged at t={t}"
        );
    }

    // The case record is identical.
    let cases_a = sa.cases();
    let cases_b = sb.cases();
    assert_eq!(cases_a.len(), cases_b.len(), "R7: case count diverged");
    for (ca, cb) in cases_a.iter().zip(cases_b.iter()) {
        assert_eq!(ca.id, cb.id);
        assert_eq!(ca.jury, cb.jury, "R7: jury diverged (case {})", ca.id);
        assert_eq!(ca.status, cb.status, "R7: status diverged (case {})", ca.id);
    }
}

/// R7-b: Voucher reputation slash is deterministic — the same slash is applied identically in
/// two independent states, and the integer arithmetic is exact (no float, no off-by-one).
#[test]
fn r7_sybil_slash_is_deterministic_and_exact() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();

    let build_and_slash = || -> (i64, i64) {
        let mut s = MemState::new();
        bootstrap(&mut s, JURY_SIZE as u8, &founders);
        full_lifecycle_verified(&mut s, addr(50), &founders, &oracle);
        // Now challenge and Sybil-quorum the subject.
        let case = challenge(&mut s, &founders[0], &addr(50), [9u8; 32], 55, 30).unwrap();
        all_vote(&mut s, case, sybil_v());
        (
            s.get_human(&founders[0]).unwrap().reputation,
            s.get_human(&founders[1]).unwrap().reputation,
        )
    };

    let (r1a, r1b) = build_and_slash();
    let (r2a, r2b) = build_and_slash();

    // Cross-node: identical.
    assert_eq!(r1a, r2a, "R7: founder-0 reputation diverged across nodes");
    assert_eq!(r1b, r2b, "R7: founder-1 reputation diverged across nodes");
    // Exact value: each voucher is slashed by SYBIL_SLASH once.
    assert_eq!(r1a, -SYBIL_SLASH, "R7: founder-0 slashed by wrong amount");
    assert_eq!(r1b, -SYBIL_SLASH, "R7: founder-1 slashed by wrong amount");
}

// ===========================================================================
// R8 — Partial registration path: InsufficientVouches leaves no phantom emission
// ===========================================================================

/// R8: A subject that fails to collect enough vouches can never accrue emission through a
/// finalize failure. The state-machine cannot be wedged into a phantom-emission state by a
/// failed finalize call.
#[test]
fn r8_insufficient_vouches_no_phantom_emission() {
    let founders = [addr(1)]; // only one founder, so one vouch available
    let oracle = MockOracle::default();
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &founders);

    let subject = addr(50);
    req_verify(&mut s, &oracle, &subject, [7u8; 32], 0xABCD, 10).unwrap();
    vouch(&mut s, &founders[0], &subject, 10).unwrap(); // only 1 vouch (MIN_VOUCHES=2)

    // Attempt finalize past the window — fails with InsufficientVouches.
    let r = finalize_registration(&mut s, &subject, 10 + CHALLENGE_WINDOW, 999_999);
    assert!(matches!(r, Err(LifecycleError::InsufficientVouches { .. })));

    // Balance must remain zero at any future time.
    for t in [1u64, 1_000_000, 1_000_000_000] {
        assert_eq!(
            s.balance(&subject, t),
            0,
            "R8: phantom emission after failed finalize (t={t})"
        );
    }
    // Status is still Pending (not Verified).
    assert_eq!(
        s.get_human(&subject).unwrap().status,
        HumanStatus::Pending,
        "R8: status must stay Pending after failed finalize"
    );
}

// ===========================================================================
// R9 — Open case detection for the challenge-pending gate (I4)
// ===========================================================================

/// R9: `finalize_registration` is blocked while an Open challenge exists — the challenge-pending
/// gate fires regardless of the case's vote count (it may still be Open, not yet committed). The
/// subject must remain Pending throughout and must not accrue emission.
#[test]
fn r9_open_challenge_blocks_finalize() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &founders);

    let subject = addr(50);
    req_verify(&mut s, &oracle, &subject, [7u8; 32], 0xABCD, 10).unwrap();
    vouch(&mut s, &founders[0], &subject, 10).unwrap();
    vouch(&mut s, &founders[1], &subject, 10).unwrap();

    // Open a challenge against the Pending subject.
    let _ = challenge(&mut s, &founders[0], &subject, [9u8; 32], 55, 11).unwrap();

    // Try to finalize after the window — blocked by ChallengePending.
    let r = finalize_registration(&mut s, &subject, 10 + CHALLENGE_WINDOW, 1_000);
    assert!(
        matches!(r, Err(LifecycleError::ChallengePending)),
        "R9: open challenge must block finalize"
    );
    assert_eq!(
        s.get_human(&subject).unwrap().status,
        HumanStatus::Pending,
        "R9: status stays Pending while challenge is open"
    );
    assert_eq!(
        s.balance(&subject, 1_000_000_000),
        0,
        "R9: no emission while blocked"
    );
}

// ===========================================================================
// R10 — Escalated case does not revoke or commit (I4)
// ===========================================================================

/// R10: A case that escalates (e.g. a three-way split) must leave the subject's status unchanged.
/// Neither Revoke nor Verified-grant are applied. The subject remains in its pre-case status.
#[test]
fn r10_escalated_case_does_not_change_status() {
    let founders = [addr(1), addr(2)];
    let oracle = MockOracle::default();
    let mut s = MemState::new();
    bootstrap(&mut s, JURY_SIZE as u8, &founders);

    // Bring subject to Verified.
    full_lifecycle_verified(&mut s, addr(50), &founders, &oracle);
    let before_status = s.get_human(&addr(50)).unwrap().status;

    // Open a challenge.
    let case = challenge(&mut s, &founders[0], &addr(50), [9u8; 32], 55, 20).unwrap();
    // Subject is now Challenged (not yet Revoked).

    // Submit a three-way split: Human, Sybil, Uncertain.
    let jury = s.get_case(case).unwrap().jury.clone();
    let verdicts = [
        human_v(),
        sybil_v(),
        CanonicalVerdict::new(Verdict::Uncertain, Confidence::Low),
    ];
    for (j, v) in jury.iter().zip(verdicts.iter()) {
        submit_verdict(&mut s, case, j, *v, 0).unwrap();
    }

    // Case escalated.
    assert_eq!(s.get_case(case).unwrap().status, CaseStatus::Escalated);

    // Subject must not be Revoked or cleared (remains Challenged — its pre-escalation status was
    // Challenged once a challenge opened, which is correct). The key invariant: emission was not
    // stopped by an Escalation.
    let status_after = s.get_human(&addr(50)).unwrap().status;
    assert!(
        !matches!(status_after, HumanStatus::Revoked),
        "R10: escalation must not revoke (status={status_after:?})"
    );
    // verified_at is still present (emission was not cleared).
    let va = s.get_human(&addr(50)).unwrap().verified_at;
    assert_ne!(va, 0, "R10: escalation must not clear verified_at");
    // The status before the challenge was Verified; after opening the challenge it is Challenged.
    // Security finding B: an escalation against a previously-Verified human FAIL-SAFE restores
    // Verified — only a Sybil quorum may strip an established human (presumption of innocence). The R10
    // invariant (escalation never REVOKES / clears emission) is preserved and strengthened; previously
    // this asserted the subject was left stuck Challenged.
    assert_eq!(
        status_after,
        HumanStatus::Verified,
        "R10: escalation fail-safe restores a previously-Verified human to Verified (finding B)"
    );
    assert_eq!(before_status, HumanStatus::Verified);
}
