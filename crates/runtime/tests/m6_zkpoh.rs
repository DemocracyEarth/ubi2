//! M6 — ZK-passport proof-of-humanity acceptance tests (spec 06 §10, ADR-0005).
//!
//! These run offline against the deterministic [`MockZkVerifier`] — no pairing math, no model, no
//! network (invariant I5). Each test maps to an exit criterion / failure-mode (AC-1…AC-5, AC-8, AC-10,
//! AC-F1…AC-F6, AC-F9). The real-curve soundness leg (AC-3/AC-F1..3 against the actual crypto) lives in
//! `crates/zkpoh/tests/real_curve.rs`.

use ubi2_runtime::{
    csca_registry_root, register_csca, revoke_csca, seed_csca, seed_verified_human, state_root,
    submit_zk_passport_proof, Assurance, CscaGovError, HumanStatus, MemState, MockZkVerifier,
    State, ZkPohError, ZkProofSubmission, EMISSION_PERIOD_SECS, UBI,
};

type Address = [u8; 20];
type Hash = [u8; 32];

fn addr(b: u8) -> Address {
    [b; 20]
}
fn h(b: u8) -> Hash {
    [b; 32]
}

/// The reserved governance address the tests + node seed for the CSCA registry.
const GOV: Address = [0x6f; 20];

/// Seed a single genesis CSCA entry + the governance authority, and return the live registry root (the
/// value a valid proof must carry).
fn bootstrap_csca(state: &mut MemState) -> Hash {
    state.set_csca_governance(GOV);
    seed_csca(state, *b"USA", h(0xC5), vec![1, 2, 3, 4]);
    csca_registry_root(&state.csca_entries())
}

/// Build a well-formed submission for `subject` at `now` against the live `root` with a fresh nullifier.
fn submission(nullifier: Hash, root: Hash, now: u64) -> ZkProofSubmission {
    ZkProofSubmission {
        proof: vec![0xAB; 192],
        nullifier,
        attribute_commitments: [h(1), h(2), h(3)],
        csca_registry_root: root,
        scheme_tag: 0,
        now_epoch: now,
    }
}

// --------------------------------------------------------------------------------------------------
// AC-1 (EC-1): a NEW address with no prior record completes a ZK proof ⇒ Verified/ENH, emission starts.
// --------------------------------------------------------------------------------------------------

#[test]
fn ac1_new_zk_only_user_becomes_verified_enh_and_accrues() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default(); // confident accept
    let user = addr(1);
    let now = 1_000;

    let level = submit_zk_passport_proof(&mut s, &v, &user, &submission(h(7), root, now), now)
        .expect("valid ZK proof verifies");
    assert_eq!(level, Assurance::Enh, "a new ZK-only user lands at ENH");

    let human = s.get_human(&user).expect("human created");
    assert_eq!(
        human.status,
        HumanStatus::Verified,
        "first-class route to Verified"
    );
    assert_eq!(human.assurance, Assurance::Enh);
    assert_eq!(
        human.verified_at, now,
        "emission epoch stamped at the proof block ts"
    );

    // Emission started: one hour later the balance is ~1 UBI (the account cache was flipped).
    assert_eq!(
        s.balance(&user, now + EMISSION_PERIOD_SECS),
        UBI,
        "ENH human accrues 1 UBI/hour exactly like an M3-Verified human"
    );
}

// --------------------------------------------------------------------------------------------------
// AC-2 / AC-F5 (EC-2): a second address with the SAME nullifier is rejected chain-wide, BEFORE the
// pairing check, and the rejection leaves state (and the root) unchanged.
// --------------------------------------------------------------------------------------------------

#[test]
fn ac2_nullifier_reuse_rejected_chain_wide_no_state_change() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let now = 2_000;

    // First user registers nullifier N.
    submit_zk_passport_proof(&mut s, &v, &addr(1), &submission(h(9), root, now), now).unwrap();
    let root_after_first = state_root(&s);

    // A SECOND address submits a proof with the SAME nullifier N ⇒ rejected fail-closed.
    let second = addr(2);
    let err = submit_zk_passport_proof(&mut s, &v, &second, &submission(h(9), root, now), now)
        .unwrap_err();
    assert_eq!(err, ZkPohError::NullifierAlreadyUsed);

    // The second address is NOT Verified and the state root is byte-unchanged (deterministic on all nodes).
    assert!(
        s.get_human(&second).is_none(),
        "rejected submitter has no record"
    );
    assert_eq!(
        state_root(&s),
        root_after_first,
        "a rejected nullifier-reuse leaves state byte-identical (no partial state)"
    );
}

// --------------------------------------------------------------------------------------------------
// SECURITY regression — gate finding zk-nullifier-malleable-1 (HIGH, PoC-confirmed). The nullifier is
// the one-passport-one-human registry key, stored/compared as RAW bytes, while the verifier reduces it
// mod the BN254 order `r`. Without a canonicality guard, N and N+r are distinct registry keys that
// satisfy the SAME proof — so one passport mints unlimited Verified/ENH humans (and UBI streams). The
// guard rejects any non-canonical (≥ r) field input BEFORE the registry/verifier.
// --------------------------------------------------------------------------------------------------

/// Big-endian 32-byte addition with carry — builds `N + r`, the malleated twin of `N` that reduces to
/// the SAME field element the proof commits to.
fn add_be(a: &Hash, b: &Hash) -> Hash {
    let mut out = [0u8; 32];
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        out[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
    out
}

#[test]
fn noncanonical_nullifier_rejected_blocks_malleability_double_mint() {
    use ubi2_runtime::zkpoh::{is_canonical_scalar, BN254_FR_MODULUS_BE};

    // The guard itself: < r is canonical; r and anything above it is not.
    let r = BN254_FR_MODULUS_BE;
    assert!(is_canonical_scalar(&h(7)), "a small value is canonical");
    assert!(
        !is_canonical_scalar(&r),
        "r itself is non-canonical (r ≡ 0)"
    );
    assert!(!is_canonical_scalar(&[0xff; 32]), "all-ones is ≥ r");

    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let now = 1_000;
    // Worst case for the guard: a verifier that ACCEPTS everything (the real Groth16 verifier likewise
    // reduces N+r ≡ N and so would verify the malleated twin against the same proof).
    let v = MockZkVerifier::default();

    // The one legitimate passport registers ONE human under canonical nullifier N.
    let n = h(7);
    submit_zk_passport_proof(&mut s, &v, &addr(1), &submission(n, root, now), now)
        .expect("the canonical nullifier registers the one legitimate human");
    assert!(s.nullifier_used(&n));
    let root_after_one = state_root(&s);

    // The attack: a SECOND address submits the malleated twin N+r. It reduces to N (the verifier would
    // accept it), but the canonicality guard rejects it BEFORE the registry/verifier — no second human,
    // no second UBI stream, from the one passport.
    let n_plus_r = add_be(&n, &r);
    assert!(!is_canonical_scalar(&n_plus_r), "N + r is ≥ r");
    let err = submit_zk_passport_proof(&mut s, &v, &addr(2), &submission(n_plus_r, root, now), now)
        .expect_err("the malleated non-canonical nullifier must be rejected");
    assert_eq!(err, ZkPohError::NonCanonicalNullifier);
    assert!(
        s.get_human(&addr(2)).is_none(),
        "no human minted from the malleated twin"
    );
    assert!(
        !s.nullifier_used(&n_plus_r),
        "the malleated key was never inserted"
    );
    assert_eq!(
        state_root(&s),
        root_after_one,
        "the rejection leaves state byte-identical (I4)"
    );
}

// --------------------------------------------------------------------------------------------------
// AC-3 / AC-F1..F3 (EC-3): fail-closed legs at the lifecycle layer (mock verifier). The real-curve
// soundness against tampered proofs is in crates/zkpoh.
// --------------------------------------------------------------------------------------------------

#[test]
fn ac3_invalid_proof_rejected_no_state_change() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    // A mock scripted to REJECT this (nullifier, submitter) — stands in for a tampered/forged/expired proof.
    let user = addr(1);
    let v = MockZkVerifier::new(false).with_passport(h(7), user, false);
    let now = 3_000;
    let root_before = state_root(&s);

    let err =
        submit_zk_passport_proof(&mut s, &v, &user, &submission(h(7), root, now), now).unwrap_err();
    assert_eq!(err, ZkPohError::InvalidProof);
    assert!(s.get_human(&user).is_none());
    assert!(
        !s.nullifier_used(&h(7)),
        "no nullifier spent on a false proof"
    );
    assert_eq!(
        state_root(&s),
        root_before,
        "no partial state on InvalidProof"
    );
}

#[test]
fn acf1_stale_now_epoch_rejected() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = 4_000;
    // The proof's now_epoch (built for a different block ts) ≠ the block timestamp ⇒ rejected (ties
    // expiry to block time deterministically — F-1).
    let mut sub = submission(h(7), root, now);
    sub.now_epoch = now - 1;
    let err = submit_zk_passport_proof(&mut s, &v, &user, &sub, now).unwrap_err();
    assert_eq!(
        err,
        ZkPohError::StaleNowEpoch {
            got: now - 1,
            expected: now
        }
    );
}

#[test]
fn acf2_untrusted_csca_root_rejected() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = 5_000;
    // A proof built against a CSCA root NOT in the live registry ⇒ rejected (EC-3 / F-2).
    let mut sub = submission(h(7), root, now);
    sub.csca_registry_root = h(0xBA); // not the live root
    let err = submit_zk_passport_proof(&mut s, &v, &user, &sub, now).unwrap_err();
    assert_eq!(err, ZkPohError::UntrustedCscaRoot);
}

#[test]
fn unknown_scheme_tag_rejected() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let mut sub = submission(h(7), root, 6_000);
    sub.scheme_tag = 9; // unknown document scheme
    let err = submit_zk_passport_proof(&mut s, &v, &addr(1), &sub, 6_000).unwrap_err();
    assert_eq!(err, ZkPohError::UnknownScheme(9));
}

// --------------------------------------------------------------------------------------------------
// AC-4 (EC-4): a successful proof stores ONLY commitments (nullifier + 3 attribute commitments) — no PII.
// --------------------------------------------------------------------------------------------------

#[test]
fn ac4_only_commitments_stored_no_pii() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = 7_000;
    let sub = submission(h(7), root, now);
    submit_zk_passport_proof(&mut s, &v, &user, &sub, now).unwrap();

    assert!(s.nullifier_used(&h(7)), "the nullifier is registered");
    let commitments = s.attribute_commitments(&user).expect("commitments stored");
    assert_eq!(
        commitments,
        [h(1), h(2), h(3)],
        "the three opaque Pedersen commitments"
    );
    // The Human record has no PII field by construction — only address/status/verified_at/assurance/etc.
    let human = s.get_human(&user).unwrap();
    assert_eq!(human.assurance, Assurance::Enh);
}

// --------------------------------------------------------------------------------------------------
// AC-5 (EC-5): an STD-Verified human upgrading to DUAL keeps balance + verified_at byte-unchanged, and
// no assurance value affects balance() (the inclusion invariant). STD humans are first-class.
// --------------------------------------------------------------------------------------------------

#[test]
fn ac5_std_upgrade_to_dual_preserves_balance_and_verified_at() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let verified_at = 100;
    // An existing M3 STD human, verified long before the upgrade.
    seed_verified_human(&mut s, &user, verified_at);
    assert_eq!(s.get_human(&user).unwrap().assurance, Assurance::Std);

    // Balance accrued for one hour, captured just before the upgrade.
    let now = verified_at + EMISSION_PERIOD_SECS;
    let balance_before = s.balance(&user, now);
    assert_eq!(balance_before, UBI);

    // The upgrade lands at a LATER block ts — the rule is verified_at must NOT move to `now`.
    let upgrade_ts = now + 10 * EMISSION_PERIOD_SECS;
    let level = submit_zk_passport_proof(
        &mut s,
        &v,
        &user,
        &submission(h(7), root, upgrade_ts),
        upgrade_ts,
    )
    .unwrap();
    assert_eq!(level, Assurance::Dual);

    let human = s.get_human(&user).unwrap();
    assert_eq!(human.assurance, Assurance::Dual);
    assert_eq!(
        human.verified_at, verified_at,
        "verified_at is NEVER touched on an STD→DUAL upgrade (the hard rule)"
    );
    assert_eq!(human.status, HumanStatus::Verified);

    // Balance is uninterrupted: it kept accruing from the ORIGINAL verified_at, not the upgrade ts.
    assert_eq!(
        s.balance(&user, now),
        balance_before,
        "balance at `now` is unchanged by the upgrade"
    );
    assert_eq!(
        s.balance(&user, upgrade_ts),
        UBI + 10 * UBI,
        "emission continued from the original epoch (no reset on upgrade)"
    );
}

#[test]
fn ubi_eligibility_is_independent_of_assurance() {
    // The inclusion invariant: at the SAME age, an STD human and an ENH human accrue identically.
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let now = 0;

    let std_user = addr(1);
    seed_verified_human(&mut s, &std_user, now);

    let enh_user = addr(2);
    submit_zk_passport_proof(&mut s, &v, &enh_user, &submission(h(7), root, now), now).unwrap();

    let t = now + 5 * EMISSION_PERIOD_SECS;
    assert_eq!(
        s.balance(&std_user, t),
        s.balance(&enh_user, t),
        "STD and ENH humans of the same age accrue identical UBI (assurance never gates balance())"
    );
    assert_eq!(s.balance(&std_user, t), 5 * UBI);
}

// --------------------------------------------------------------------------------------------------
// AC-F6: an STD human submitting an INVALID proof stays STD/Verified — no downgrade, no balance loss.
// --------------------------------------------------------------------------------------------------

#[test]
fn acf6_std_human_failed_zk_upgrade_no_downgrade() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let user = addr(1);
    // Mock rejects this submitter's proof.
    let v = MockZkVerifier::new(false);
    let verified_at = 50;
    seed_verified_human(&mut s, &user, verified_at);

    let now = verified_at + EMISSION_PERIOD_SECS;
    let balance_before = s.balance(&user, now);
    let err =
        submit_zk_passport_proof(&mut s, &v, &user, &submission(h(7), root, now), now).unwrap_err();
    assert_eq!(err, ZkPohError::InvalidProof);

    let human = s.get_human(&user).unwrap();
    assert_eq!(human.status, HumanStatus::Verified, "no downgrade");
    assert_eq!(
        human.assurance,
        Assurance::Std,
        "stays STD on a failed upgrade"
    );
    assert_eq!(human.verified_at, verified_at);
    assert_eq!(s.balance(&user, now), balance_before, "no balance loss");
}

// --------------------------------------------------------------------------------------------------
// AC-F9: a DUAL (or ENH) human re-submitting is rejected AlreadyEnhanced — idempotency, no double-store.
// --------------------------------------------------------------------------------------------------

#[test]
fn acf9_already_enhanced_resubmission_rejected() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = 9_000;

    // First proof ⇒ ENH.
    submit_zk_passport_proof(&mut s, &v, &user, &submission(h(7), root, now), now).unwrap();
    let root_after = state_root(&s);

    // A second proof (a DIFFERENT, fresh nullifier) by the same now-ENH human ⇒ AlreadyEnhanced.
    let err =
        submit_zk_passport_proof(&mut s, &v, &user, &submission(h(8), root, now), now).unwrap_err();
    assert_eq!(err, ZkPohError::AlreadyEnhanced(Assurance::Enh));
    assert!(
        !s.nullifier_used(&h(8)),
        "no second nullifier stored (no double-store)"
    );
    assert_eq!(
        state_root(&s),
        root_after,
        "root unchanged (idempotent reject)"
    );
}

// --------------------------------------------------------------------------------------------------
// AC-8 (EC-8): attribute commitments are opaque + unlinkable — two ENH humans (different blinding)
// produce different commitments, retrievable via the attribute store.
// --------------------------------------------------------------------------------------------------

#[test]
fn ac8_attribute_commitments_are_opaque_and_unlinkable() {
    let mut s = MemState::new();
    let root = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();
    let now = 0;

    // Two humans whose underlying attribute (e.g. both over-18) is the same, but whose blinded
    // commitments differ (the device picks per-attribute blinding — §3.4).
    let a = addr(1);
    let mut sub_a = submission(h(10), root, now);
    sub_a.attribute_commitments = [h(0x11), h(0x22), h(0x33)];
    submit_zk_passport_proof(&mut s, &v, &a, &sub_a, now).unwrap();

    let b = addr(2);
    let mut sub_b = submission(h(20), root, now);
    sub_b.attribute_commitments = [h(0xAA), h(0xBB), h(0xCC)];
    submit_zk_passport_proof(&mut s, &v, &b, &sub_b, now).unwrap();

    let ca = s.attribute_commitments(&a).unwrap();
    let cb = s.attribute_commitments(&b).unwrap();
    assert_ne!(
        ca, cb,
        "two humans' commitments differ (blinding ⇒ unlinkable)"
    );

    // The store iterates sorted-by-address (deterministic).
    let store = s.attribute_store();
    assert_eq!(store, vec![(a, ca), (b, cb)]);
}

// --------------------------------------------------------------------------------------------------
// AC-10 (EC-10): the CSCA registry is governance-gated; registerCsca adds a root; a proof built against
// the NEW root is immediately accepted; a non-governance registerCsca is rejected.
// --------------------------------------------------------------------------------------------------

#[test]
fn ac10_csca_governance_register_and_immediate_use() {
    let mut s = MemState::new();
    let root0 = bootstrap_csca(&mut s);
    let v = MockZkVerifier::default();

    // A NON-governance registerCsca is rejected.
    let err = register_csca(&mut s, &addr(1), *b"DEU", h(0xD1), vec![9, 9], 1).unwrap_err();
    assert_eq!(err, CscaGovError::NotGovernance);
    assert_eq!(
        csca_registry_root(&s.csca_entries()),
        root0,
        "rejected ⇒ root unchanged"
    );

    // The governance authority adds a new CSCA root — the registry root changes.
    register_csca(&mut s, &GOV, *b"DEU", h(0xD1), vec![9, 9], 1).unwrap();
    let root1 = csca_registry_root(&s.csca_entries());
    assert_ne!(
        root1, root0,
        "a new CSCA changes the root (immediately usable, EC-10)"
    );

    // A proof built against the NEW root is immediately accepted.
    let user = addr(2);
    let now = 11_000;
    let level =
        submit_zk_passport_proof(&mut s, &v, &user, &submission(h(7), root1, now), now).unwrap();
    assert_eq!(level, Assurance::Enh);

    // A proof still carrying the OLD root is now rejected (no grace window in Stage 1).
    let err = submit_zk_passport_proof(&mut s, &v, &addr(3), &submission(h(8), root0, now), now)
        .unwrap_err();
    assert_eq!(err, ZkPohError::UntrustedCscaRoot);
}

#[test]
fn csca_revoke_is_governance_gated_and_changes_root() {
    let mut s = MemState::new();
    let root0 = bootstrap_csca(&mut s);

    // Non-governance revoke ⇒ rejected.
    assert_eq!(
        revoke_csca(&mut s, &addr(1), &h(0xC5)).unwrap_err(),
        CscaGovError::NotGovernance
    );
    // Unknown key ⇒ rejected.
    assert_eq!(
        revoke_csca(&mut s, &GOV, &h(0xFF)).unwrap_err(),
        CscaGovError::UnknownCsca
    );
    // Governance revoke ⇒ the key leaves the Active set ⇒ the root changes (forward-invalidation).
    revoke_csca(&mut s, &GOV, &h(0xC5)).unwrap();
    assert_ne!(csca_registry_root(&s.csca_entries()), root0);
}

// --------------------------------------------------------------------------------------------------
// state_root determinism INCLUDING the new sections (§5.3) — two independently-built states agree, and
// any of the new fields moves the root.
// --------------------------------------------------------------------------------------------------

#[test]
fn state_root_is_deterministic_over_new_sections() {
    let build = || {
        let mut s = MemState::new();
        let root = bootstrap_csca(&mut s);
        let v = MockZkVerifier::default();
        submit_zk_passport_proof(&mut s, &v, &addr(1), &submission(h(7), root, 0), 0).unwrap();
        submit_zk_passport_proof(&mut s, &v, &addr(2), &submission(h(8), root, 0), 0).unwrap();
        s
    };
    assert_eq!(
        state_root(&build()),
        state_root(&build()),
        "equal ZK state ⇒ equal root (EC-4/EC-10 incl. the new sections)"
    );
}

#[test]
fn each_new_section_moves_the_root() {
    let base = {
        let mut s = MemState::new();
        bootstrap_csca(&mut s);
        s
    };
    let root0 = state_root(&base);

    // A spent nullifier moves the root.
    let mut s = base.clone();
    s.put_nullifier(h(7));
    assert_ne!(state_root(&s), root0, "nullifier registry changes the root");

    // An attribute-store entry moves the root.
    let mut s = base.clone();
    s.put_attribute_commitments(&addr(1), [h(1), h(2), h(3)]);
    assert_ne!(state_root(&s), root0, "attribute store changes the root");

    // A new CSCA entry moves the root.
    let mut s = base.clone();
    seed_csca(&mut s, *b"FRA", h(0xF1), vec![1]);
    assert_ne!(state_root(&s), root0, "CSCA registry changes the root");

    // The assurance tag on a human moves the root.
    let mut s = base.clone();
    seed_verified_human(&mut s, &addr(1), 0);
    let root_std = state_root(&s);
    let mut h1 = s.get_human(&addr(1)).unwrap();
    h1.assurance = Assurance::Dual;
    s.put_human(h1);
    assert_ne!(
        state_root(&s),
        root_std,
        "the assurance tag change moves the root"
    );
}
