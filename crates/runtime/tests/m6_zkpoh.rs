//! M6 Stage C — ZK-passport proof-of-humanity acceptance tests (spec 06b §9, EC-C1..C6/C13).
//!
//! These run offline against the deterministic [`MockZkVerifier`] — no pairing math, no model, no
//! network (invariant I5). Each test maps to an exit criterion / failure-mode. The real-curve soundness
//! leg (a genuine Groth16 proof verifying at arity 21, tampered/wrong-slot failing closed — EC-C2/C6
//! crypto core) lives in `crates/zkpoh/tests/self_arity21.rs`.

use ubi2_runtime::{
    address_to_hash, current_date_to_epoch, pin_self_identity_root, retire_self_root,
    seed_self_identity_root, seed_self_ofac_root, seed_self_scope, seed_verified_human, state_root,
    submit_zk_passport_proof, u64_to_hash, Assurance, CscaGovError, HumanStatus, MemState,
    MockZkVerifier, State, ZkPohError, ZkProofSubmission, EMISSION_PERIOD_SECS, OFAC_KIND_NAMEDOB,
    OFAC_KIND_NAMEYOB, OFAC_KIND_PASSPORTNO, SELF_ATTESTATION_ID_EPASSPORT,
    SELF_IDX_ATTESTATION_ID, SELF_IDX_CURRENT_DATE, SELF_IDX_MERKLE_ROOT, SELF_IDX_NULLIFIER,
    SELF_IDX_OFAC_PASSPORTNO, SELF_IDX_REVEALED_DATA, SELF_IDX_SCOPE, SELF_IDX_USER_IDENTIFIER,
    SELF_NPUBLIC, UBI, UBI2_SELF_SCOPE,
};

type Address = [u8; 20];
type Hash = [u8; 32];

fn addr(b: u8) -> Address {
    [b; 20]
}
fn h(b: u8) -> Hash {
    [b; 32]
}

/// The reserved governance address the tests + node seed (gates CSCA + the Self-root ops).
const GOV: Address = [0x6f; 20];
/// The curated devnet Self identity root + 3 OFAC roots (mirrors `crates/node`).
const IDENTITY_ROOT: Hash = [0x5E; 32];
const OFAC_ROOTS: [Hash; 3] = [[0x0F; 32], [0x1F; 32], [0x2F; 32]];
/// A realistic devnet block time base (2023-11-14 12:00-ish UTC) so `current_date` decodes to 20YY.
const BASE_TS: u64 = 1_700_000_000;
/// A block height well within `SELF_ROOT_WINDOW_BLOCKS` of the genesis-pinned (block-0) roots.
const NOW_BLOCK: u64 = 1;

/// Seed the governance authority + the Self identity root + the 3 OFAC roots (the accepted trust set a
/// valid proof binds against). Returns the pinned identity root.
fn bootstrap_self_roots(state: &mut MemState) -> Hash {
    state.set_csca_governance(GOV);
    seed_self_identity_root(state, IDENTITY_ROOT);
    seed_self_ofac_root(state, OFAC_KIND_PASSPORTNO, OFAC_ROOTS[0]);
    seed_self_ofac_root(state, OFAC_KIND_NAMEDOB, OFAC_ROOTS[1]);
    seed_self_ofac_root(state, OFAC_KIND_NAMEYOB, OFAC_ROOTS[2]);
    seed_self_scope(state, UBI2_SELF_SCOPE);
    IDENTITY_ROOT
}

/// Encode `now`'s civil date (assumed 2000..2099) into the six `current_date` YYMMDD ASCII-digit signals,
/// so `current_date_to_epoch` decodes it to that day's midnight — inside the freshness window of `now`.
fn date_signals(now: u64) -> [Hash; 6] {
    let days = (now / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u8;
    let year = if m <= 2 { y + 1 } else { y };
    let yy = (year.rem_euclid(100)) as u8;
    let digits = [yy / 10, yy % 10, m / 10, m % 10, d / 10, d % 10];
    let mut out = [[0u8; 32]; 6];
    for (i, dg) in digits.iter().enumerate() {
        // Self emits current_date as RAW decimal digits 0-9 (not ASCII codes) — EC-C7.
        out[i] = u64_to_hash(*dg as u64);
    }
    out
}

/// Build a well-formed 21-signal submission for `submitter` at `now`: `nullifier@7`, `attestation_id@8
/// = 1`, `merkle_root@9` = the pinned identity root, `current_date@10..16` ≈ `now`, OFAC@16..18 = the
/// pinned OFAC roots, `scope@19` = UBI2_SELF_SCOPE, `user_identifier@20` = submitter.
fn submission(nullifier: Hash, submitter: Address, now: u64) -> ZkProofSubmission {
    let mut s = [[0u8; 32]; SELF_NPUBLIC];
    s[SELF_IDX_REVEALED_DATA] = h(1);
    s[SELF_IDX_REVEALED_DATA + 1] = h(2);
    s[SELF_IDX_REVEALED_DATA + 2] = h(3);
    s[SELF_IDX_NULLIFIER] = nullifier;
    s[SELF_IDX_ATTESTATION_ID] = u64_to_hash(SELF_ATTESTATION_ID_EPASSPORT);
    s[SELF_IDX_MERKLE_ROOT] = IDENTITY_ROOT;
    let date = date_signals(now);
    s[SELF_IDX_CURRENT_DATE..SELF_IDX_CURRENT_DATE + 6].copy_from_slice(&date);
    s[SELF_IDX_OFAC_PASSPORTNO] = OFAC_ROOTS[0];
    s[SELF_IDX_OFAC_PASSPORTNO + 1] = OFAC_ROOTS[1];
    s[SELF_IDX_OFAC_PASSPORTNO + 2] = OFAC_ROOTS[2];
    s[SELF_IDX_SCOPE] = UBI2_SELF_SCOPE;
    s[SELF_IDX_USER_IDENTIFIER] = address_to_hash(&submitter);
    ZkProofSubmission {
        proof: vec![0xAB; 192],
        signals: s,
        scheme_tag: 0,
    }
}

fn submit(
    s: &mut MemState,
    v: &MockZkVerifier,
    subject: &Address,
    sub: &ZkProofSubmission,
    now: u64,
) -> Result<Assurance, ZkPohError> {
    submit_zk_passport_proof(s, v, subject, sub, now, NOW_BLOCK)
}

// --------------------------------------------------------------------------------------------------
// EC-C7-shape (mock): a NEW address completes a ZK proof ⇒ Verified/ENH, emission starts.
// --------------------------------------------------------------------------------------------------

#[test]
fn new_zk_only_user_becomes_verified_enh_and_accrues() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = BASE_TS;

    let level = submit(&mut s, &v, &user, &submission(h(7), user, now), now)
        .expect("valid ZK proof verifies");
    assert_eq!(level, Assurance::Enh, "a new ZK-only user lands at ENH");

    let human = s.get_human(&user).expect("human created");
    assert_eq!(human.status, HumanStatus::Verified);
    assert_eq!(human.assurance, Assurance::Enh);
    assert_eq!(human.verified_at, now);
    assert_eq!(
        s.balance(&user, now + EMISSION_PERIOD_SECS),
        UBI,
        "ENH human accrues 1 UBI/hour exactly like an M3-Verified human"
    );
}

// --------------------------------------------------------------------------------------------------
// EC-C4: nullifier reuse rejected chain-wide, BEFORE the pairing, leaving state (+ root) unchanged.
// --------------------------------------------------------------------------------------------------

#[test]
fn nullifier_reuse_rejected_chain_wide_no_state_change() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let now = BASE_TS;

    submit(&mut s, &v, &addr(1), &submission(h(9), addr(1), now), now).unwrap();
    let root_after_first = state_root(&s);

    // A SECOND address submits with the SAME nullifier ⇒ rejected fail-closed.
    let second = addr(2);
    let err = submit(&mut s, &v, &second, &submission(h(9), second, now), now).unwrap_err();
    assert_eq!(err, ZkPohError::NullifierAlreadyUsed);
    assert!(s.get_human(&second).is_none());
    assert_eq!(
        state_root(&s),
        root_after_first,
        "a rejected nullifier-reuse leaves state byte-identical (no partial state)"
    );
}

// --------------------------------------------------------------------------------------------------
// EC-C5 (nullifier malleability): the canonicality guard blocks the N, N+r double-mint.
// --------------------------------------------------------------------------------------------------

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

    let r = BN254_FR_MODULUS_BE;
    assert!(is_canonical_scalar(&h(7)));
    assert!(!is_canonical_scalar(&r));
    assert!(!is_canonical_scalar(&[0xff; 32]));

    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let now = BASE_TS;
    let v = MockZkVerifier::default();

    let n = h(7);
    submit(&mut s, &v, &addr(1), &submission(n, addr(1), now), now).unwrap();
    let root_after_one = state_root(&s);

    let n_plus_r = add_be(&n, &r);
    assert!(!is_canonical_scalar(&n_plus_r));
    let err = submit(
        &mut s,
        &v,
        &addr(2),
        &submission(n_plus_r, addr(2), now),
        now,
    )
    .expect_err("the malleated non-canonical nullifier must be rejected");
    assert_eq!(err, ZkPohError::NonCanonicalNullifier);
    assert!(s.get_human(&addr(2)).is_none());
    assert!(!s.nullifier_used(&n_plus_r));
    assert_eq!(
        state_root(&s),
        root_after_one,
        "the rejection leaves state byte-identical (I4)"
    );
}

// --------------------------------------------------------------------------------------------------
// EC-C6 (mock leg): an invalid proof is rejected, no state change. Real-curve leg is in crates/zkpoh.
// --------------------------------------------------------------------------------------------------

#[test]
fn invalid_proof_rejected_no_state_change() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let user = addr(1);
    let v = MockZkVerifier::new(false).with_passport(h(7), user, false);
    let now = BASE_TS;
    let root_before = state_root(&s);

    let err = submit(&mut s, &v, &user, &submission(h(7), user, now), now).unwrap_err();
    assert_eq!(err, ZkPohError::InvalidProof);
    assert!(s.get_human(&user).is_none());
    assert!(!s.nullifier_used(&h(7)));
    assert_eq!(state_root(&s), root_before);
}

// --------------------------------------------------------------------------------------------------
// EC-C5 (freshness) + EC-C3 (attestation / scope / submitter): the by-index bind steps fail closed.
// --------------------------------------------------------------------------------------------------

#[test]
fn stale_proof_date_rejected() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = BASE_TS;
    // current_date encodes a day far outside the ± window (2020-01-01, ~3.7y before `now`).
    let mut sub = submission(h(7), user, now);
    let stale = date_signals(1_577_836_800); // 2020-01-01
    sub.signals[SELF_IDX_CURRENT_DATE..SELF_IDX_CURRENT_DATE + 6].copy_from_slice(&stale);
    assert_eq!(
        submit(&mut s, &v, &user, &sub, now).unwrap_err(),
        ZkPohError::StaleProofDate
    );
}

#[test]
fn unexpected_attestation_rejected() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = BASE_TS;
    let mut sub = submission(h(7), user, now);
    sub.signals[SELF_IDX_ATTESTATION_ID] = u64_to_hash(2); // not an E-Passport
    assert_eq!(
        submit(&mut s, &v, &user, &sub, now).unwrap_err(),
        ZkPohError::UnexpectedAttestation
    );
}

#[test]
fn wrong_scope_rejected() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = BASE_TS;
    let mut sub = submission(h(7), user, now);
    sub.signals[SELF_IDX_SCOPE] = h(0xAB); // a different-app scope
    assert_eq!(
        submit(&mut s, &v, &user, &sub, now).unwrap_err(),
        ZkPohError::WrongScope
    );
}

#[test]
fn submitter_mismatch_rejected() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let now = BASE_TS;
    // A proof whose user_identifier is addr(1), relayed by addr(2) ⇒ SubmitterMismatch (F-4).
    let sub = submission(h(7), addr(1), now);
    assert_eq!(
        submit(&mut s, &v, &addr(2), &sub, now).unwrap_err(),
        ZkPohError::SubmitterMismatch
    );
}

#[test]
fn unknown_scheme_tag_rejected() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let now = BASE_TS;
    let mut sub = submission(h(7), addr(1), now);
    sub.scheme_tag = 9;
    assert_eq!(
        submit(&mut s, &v, &addr(1), &sub, now).unwrap_err(),
        ZkPohError::UnknownScheme(9)
    );
}

// --------------------------------------------------------------------------------------------------
// EC-C2: the Self-root trust anchors — an untrusted merkle_root / OFAC root is rejected fail-closed;
// after pinning, a proof carrying it is accepted.
// --------------------------------------------------------------------------------------------------

#[test]
fn untrusted_self_root_rejected_then_accepted_after_pin() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let now = BASE_TS;

    // A proof carrying a merkle_root NOT in the accepted set ⇒ UntrustedSelfRoot.
    let mut sub = submission(h(7), addr(1), now);
    let fresh_root = h(0x99);
    sub.signals[SELF_IDX_MERKLE_ROOT] = fresh_root;
    assert_eq!(
        submit(&mut s, &v, &addr(1), &sub, now).unwrap_err(),
        ZkPohError::UntrustedSelfRoot
    );

    // Governance pins the fresh root — the same proof is now accepted.
    pin_self_identity_root(&mut s, &GOV, fresh_root, NOW_BLOCK).unwrap();
    assert_eq!(
        submit(&mut s, &v, &addr(1), &sub, now).unwrap(),
        Assurance::Enh
    );
}

#[test]
fn untrusted_ofac_root_rejected() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let now = BASE_TS;
    let mut sub = submission(h(7), addr(1), now);
    sub.signals[SELF_IDX_OFAC_PASSPORTNO] = h(0xEE); // an OFAC root not in the accepted set
    assert_eq!(
        submit(&mut s, &v, &addr(1), &sub, now).unwrap_err(),
        ZkPohError::UntrustedOfacRoot
    );
}

// --------------------------------------------------------------------------------------------------
// EC-C13: the Self-root registry is governance-gated (pin / retire); a non-governance op is rejected.
// --------------------------------------------------------------------------------------------------

#[test]
fn self_root_ops_are_governance_gated() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let now = BASE_TS;

    // Non-governance pin ⇒ rejected.
    assert_eq!(
        pin_self_identity_root(&mut s, &addr(1), h(0x88), NOW_BLOCK).unwrap_err(),
        CscaGovError::NotGovernance
    );
    // Non-governance retire ⇒ rejected.
    assert_eq!(
        retire_self_root(&mut s, &addr(1), &IDENTITY_ROOT).unwrap_err(),
        CscaGovError::NotGovernance
    );

    // Governance retire of the identity root ⇒ a proof carrying it is now rejected (forward-invalidation).
    retire_self_root(&mut s, &GOV, &IDENTITY_ROOT).unwrap();
    assert_eq!(
        submit(&mut s, &v, &addr(2), &submission(h(7), addr(2), now), now).unwrap_err(),
        ZkPohError::UntrustedSelfRoot
    );
}

// --------------------------------------------------------------------------------------------------
// The inclusion invariant + STD→DUAL upgrade (assurance never gates balance).
// --------------------------------------------------------------------------------------------------

#[test]
fn std_upgrade_to_dual_preserves_balance_and_verified_at() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let verified_at = BASE_TS;
    seed_verified_human(&mut s, &user, verified_at);
    assert_eq!(s.get_human(&user).unwrap().assurance, Assurance::Std);

    let now = verified_at + EMISSION_PERIOD_SECS;
    let balance_before = s.balance(&user, now);
    assert_eq!(balance_before, UBI);

    let upgrade_ts = now + 10 * EMISSION_PERIOD_SECS;
    let level = submit(
        &mut s,
        &v,
        &user,
        &submission(h(7), user, upgrade_ts),
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
    assert_eq!(s.balance(&user, now), balance_before);
    assert_eq!(s.balance(&user, upgrade_ts), UBI + 10 * UBI);
}

#[test]
fn ubi_eligibility_is_independent_of_assurance() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let now = BASE_TS;

    let std_user = addr(1);
    seed_verified_human(&mut s, &std_user, now);
    let enh_user = addr(2);
    submit(&mut s, &v, &enh_user, &submission(h(7), enh_user, now), now).unwrap();

    let t = now + 5 * EMISSION_PERIOD_SECS;
    assert_eq!(
        s.balance(&std_user, t),
        s.balance(&enh_user, t),
        "STD and ENH humans of the same age accrue identical UBI (assurance never gates balance())"
    );
    assert_eq!(s.balance(&std_user, t), 5 * UBI);
}

#[test]
fn std_human_failed_zk_upgrade_no_downgrade() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let user = addr(1);
    let v = MockZkVerifier::new(false);
    let verified_at = BASE_TS;
    seed_verified_human(&mut s, &user, verified_at);

    let now = verified_at + EMISSION_PERIOD_SECS;
    let balance_before = s.balance(&user, now);
    let err = submit(&mut s, &v, &user, &submission(h(7), user, now), now).unwrap_err();
    assert_eq!(err, ZkPohError::InvalidProof);

    let human = s.get_human(&user).unwrap();
    assert_eq!(human.status, HumanStatus::Verified, "no downgrade");
    assert_eq!(human.assurance, Assurance::Std);
    assert_eq!(human.verified_at, verified_at);
    assert_eq!(s.balance(&user, now), balance_before, "no balance loss");
}

#[test]
fn already_enhanced_resubmission_rejected() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let user = addr(1);
    let now = BASE_TS;

    submit(&mut s, &v, &user, &submission(h(7), user, now), now).unwrap();
    let root_after = state_root(&s);

    let err = submit(&mut s, &v, &user, &submission(h(8), user, now), now).unwrap_err();
    assert_eq!(err, ZkPohError::AlreadyEnhanced(Assurance::Enh));
    assert!(!s.nullifier_used(&h(8)));
    assert_eq!(state_root(&s), root_after);
}

// --------------------------------------------------------------------------------------------------
// Attribute commitments are opaque + unlinkable (the revealedData_packed slots, stored by index).
// --------------------------------------------------------------------------------------------------

#[test]
fn attribute_commitments_are_opaque_and_unlinkable() {
    let mut s = MemState::new();
    bootstrap_self_roots(&mut s);
    let v = MockZkVerifier::default();
    let now = BASE_TS;

    let a = addr(1);
    let mut sub_a = submission(h(10), a, now);
    sub_a.signals[SELF_IDX_REVEALED_DATA] = h(0x11);
    sub_a.signals[SELF_IDX_REVEALED_DATA + 1] = h(0x22);
    sub_a.signals[SELF_IDX_REVEALED_DATA + 2] = h(0x33);
    submit(&mut s, &v, &a, &sub_a, now).unwrap();

    let b = addr(2);
    let mut sub_b = submission(h(20), b, now);
    sub_b.signals[SELF_IDX_REVEALED_DATA] = h(0xAA);
    sub_b.signals[SELF_IDX_REVEALED_DATA + 1] = h(0xBB);
    sub_b.signals[SELF_IDX_REVEALED_DATA + 2] = h(0xCC);
    submit(&mut s, &v, &b, &sub_b, now).unwrap();

    let ca = s.attribute_commitments(&a).unwrap();
    let cb = s.attribute_commitments(&b).unwrap();
    assert_eq!(ca, [h(0x11), h(0x22), h(0x33)]);
    assert_ne!(ca, cb);
    assert_eq!(s.attribute_store(), vec![(a, ca), (b, cb)]);
}

// --------------------------------------------------------------------------------------------------
// state_root determinism INCLUDING the new Self-root sections (§13) — equal state ⇒ equal root, and
// each new field moves the root.
// --------------------------------------------------------------------------------------------------

#[test]
fn state_root_is_deterministic_over_new_sections() {
    let build = || {
        let mut s = MemState::new();
        bootstrap_self_roots(&mut s);
        let v = MockZkVerifier::default();
        submit(
            &mut s,
            &v,
            &addr(1),
            &submission(h(7), addr(1), BASE_TS),
            BASE_TS,
        )
        .unwrap();
        submit(
            &mut s,
            &v,
            &addr(2),
            &submission(h(8), addr(2), BASE_TS),
            BASE_TS,
        )
        .unwrap();
        s
    };
    assert_eq!(state_root(&build()), state_root(&build()));
}

#[test]
fn each_new_section_moves_the_root() {
    let base = MemState::new();
    let root0 = state_root(&base);

    // A pinned Self identity root moves the root.
    let mut s = base.clone();
    seed_self_identity_root(&mut s, IDENTITY_ROOT);
    assert_ne!(
        state_root(&s),
        root0,
        "Self identity-root registry changes the root"
    );

    // A pinned OFAC root moves the root.
    let mut s = base.clone();
    seed_self_ofac_root(&mut s, OFAC_KIND_PASSPORTNO, OFAC_ROOTS[0]);
    assert_ne!(
        state_root(&s),
        root0,
        "Self OFAC-root registry changes the root"
    );

    // A spent nullifier moves the root.
    let mut s = base.clone();
    s.put_nullifier(h(7));
    assert_ne!(state_root(&s), root0);

    // The assurance tag on a human moves the root.
    let mut s = base.clone();
    seed_verified_human(&mut s, &addr(1), 0);
    let root_std = state_root(&s);
    let mut h1 = s.get_human(&addr(1)).unwrap();
    h1.assurance = Assurance::Dual;
    s.put_human(h1);
    assert_ne!(state_root(&s), root_std);
}

// --------------------------------------------------------------------------------------------------
// Sanity: the date helper round-trips through the runtime decoder within the window.
// --------------------------------------------------------------------------------------------------

#[test]
fn date_signals_decode_within_window() {
    let now = BASE_TS;
    let epoch = current_date_to_epoch(&date_signals(now)).expect("valid YYMMDD");
    assert!(
        now.abs_diff(epoch) <= 86_400,
        "decoded date is the civil day of `now`"
    );
}
