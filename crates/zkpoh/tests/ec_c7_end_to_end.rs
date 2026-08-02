//! EC-C7 END-TO-END — a genuine Self staging proof mints a Verified human through the REAL verifier.
//!
//! This is the load-bearing gate for EC-C7: the captured genuine Self staging proof
//! (`fixtures/self_staging_{proof,public}.json`, a real mock-passport scan) is submitted through
//! `ubi2_runtime::submit_zk_passport_proof` wired with the REAL `Groth16Verifier` (the pinned production
//! `vc_and_disclose` VK), against a state seeded with the proof's OWN captured trust anchors. Every EC-C7
//! reconciliation is exercised together: raw-digit `current_date`, the genesis-seeded `scope`, the
//! `RIPEMD160(SHA256(userContextData))` submitter binding, and the arity-21 Groth16 pairing. A pass proves
//! a real human can mint on ubi2 via the real verifier; the tampered legs prove it stays fail-closed.

use ark_bn254::{Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use serde_json::Value;
use std::str::FromStr;
use ubi2_runtime::{
    seed_self_identity_root, seed_self_ofac_root, seed_self_scope, submit_zk_passport_proof,
    Assurance, HumanStatus, MemState, State, ZkPohError, ZkProofSubmission, EMISSION_PERIOD_SECS,
    SELF_IDX_MERKLE_ROOT, SELF_IDX_OFAC_NAMEDOB, SELF_IDX_OFAC_NAMEYOB, SELF_IDX_OFAC_PASSPORTNO,
    SELF_IDX_SCOPE, SELF_IDX_USER_IDENTIFIER, SELF_NPUBLIC, UBI,
};
use ubi2_zkpoh::{proof_to_canonical_bytes, Groth16Verifier};

const PROOF_JSON: &str = include_str!("../fixtures/self_staging_proof.json");
const PUBLIC_JSON: &str = include_str!("../fixtures/self_staging_public.json");

fn fq(s: &str) -> Fq {
    Fq::from_str(s).unwrap()
}

/// Decimal field-element string -> 32-byte big-endian (the on-chain signal carriage).
fn dec_to_bytes32(s: &str) -> [u8; 32] {
    let be = Fr::from_str(s).unwrap().into_bigint().to_bytes_be();
    let mut out = [0u8; 32];
    out[32 - be.len()..].copy_from_slice(&be);
    out
}

/// The captured 21-signal public vector as `[[u8;32];21]` (the runtime's on-chain carriage).
fn parse_signals() -> [[u8; 32]; SELF_NPUBLIC] {
    let j: Value = serde_json::from_str(PUBLIC_JSON).unwrap();
    let arr = j.as_array().unwrap();
    assert_eq!(arr.len(), SELF_NPUBLIC);
    let mut out = [[0u8; 32]; SELF_NPUBLIC];
    for (i, s) in arr.iter().enumerate() {
        out[i] = dec_to_bytes32(s.as_str().unwrap());
    }
    out
}

/// The captured affine `a`/`b`/`c` proof -> arkworks canonical proof bytes (G2 order confirmed by
/// `ec_c7_gonogo`: swap_b = false).
fn parse_proof_bytes() -> Vec<u8> {
    let j: Value = serde_json::from_str(PROOF_JSON).unwrap();
    let a = j["a"].as_array().unwrap();
    let ga = G1Affine::new_unchecked(fq(a[0].as_str().unwrap()), fq(a[1].as_str().unwrap()));
    let b = j["b"].as_array().unwrap();
    let b0 = b[0].as_array().unwrap();
    let b1 = b[1].as_array().unwrap();
    let gb = G2Affine::new_unchecked(
        Fq2::new(fq(b0[0].as_str().unwrap()), fq(b0[1].as_str().unwrap())),
        Fq2::new(fq(b1[0].as_str().unwrap()), fq(b1[1].as_str().unwrap())),
    );
    let c = j["c"].as_array().unwrap();
    let gc = G1Affine::new_unchecked(fq(c[0].as_str().unwrap()), fq(c[1].as_str().unwrap()));
    proof_to_canonical_bytes(&Proof {
        a: ga,
        b: gb,
        c: gc,
    })
    .unwrap()
}

fn user_context_data() -> Vec<u8> {
    let j: Value = serde_json::from_str(PROOF_JSON).unwrap();
    let hex = j["userContextData"].as_str().unwrap();
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// Seed a fresh state with the captured proof's OWN trust anchors (its scope, identity root, OFAC roots).
fn seed_for_capture(signals: &[[u8; 32]; SELF_NPUBLIC]) -> MemState {
    let mut s = MemState::new();
    seed_self_scope(&mut s, signals[SELF_IDX_SCOPE]);
    seed_self_identity_root(&mut s, signals[SELF_IDX_MERKLE_ROOT]);
    seed_self_ofac_root(&mut s, 0, signals[SELF_IDX_OFAC_PASSPORTNO]);
    seed_self_ofac_root(&mut s, 1, signals[SELF_IDX_OFAC_NAMEDOB]);
    seed_self_ofac_root(&mut s, 2, signals[SELF_IDX_OFAC_NAMEYOB]);
    s
}

/// The captured proof's `current_date` is 2026-07-31; pick `now` = noon that day (inside the freshness
/// window) and a block height inside the root window of the block-0 seeded anchors.
const NOW: u64 = 1_785_456_000 + 43_200;
const NOW_BLOCK: u64 = 1;

#[test]
fn captured_staging_proof_mints_a_verified_human_via_the_real_verifier() {
    let signals = parse_signals();
    let ucd = user_context_data();
    // The real submitter = low 20 bytes of userContextData[32:64].
    let mut subject = [0u8; 20];
    subject.copy_from_slice(&ucd[44..64]);

    let mut state = seed_for_capture(&signals);
    let verifier = Groth16Verifier::from_pinned().expect("real production VK is pinned");
    let submission = ZkProofSubmission {
        proof: parse_proof_bytes(),
        signals,
        scheme_tag: 0,
        user_context_data: ucd,
    };

    let level =
        submit_zk_passport_proof(&mut state, &verifier, &subject, &submission, NOW, NOW_BLOCK)
            .expect("the genuine captured Self proof mints through the REAL Groth16Verifier");
    assert_eq!(level, Assurance::Enh, "a fresh ZK-only human lands at ENH");

    let human = state.get_human(&subject).expect("human record created");
    assert_eq!(human.status, HumanStatus::Verified);
    assert_eq!(human.verified_at, NOW);
    // The PoH-gated native UBI stream now flows to this human.
    assert_eq!(
        state.balance(&subject, NOW + EMISSION_PERIOD_SECS),
        UBI,
        "a verified human accrues 1 UBI/hour"
    );
    // The nullifier (slot 7) is now consumed — a replay is rejected.
    assert!(
        submit_zk_passport_proof(&mut state, &verifier, &subject, &submission, NOW, NOW_BLOCK)
            .is_err(),
        "the same proof cannot mint twice (nullifier single-use)"
    );

    eprintln!(
        "EC-C7 END-TO-END OK: genuine Self staging proof -> Verified/ENH human 0x{} via the real verifier",
        hex_lower(&subject)
    );
}

#[test]
fn fails_closed_when_a_different_relayer_submits_the_captured_proof() {
    // Anti-replay: userContextData[44:64] binds the ORIGINAL address; any other tx sender is rejected.
    let signals = parse_signals();
    let mut state = seed_for_capture(&signals);
    let verifier = Groth16Verifier::from_pinned().unwrap();
    let submission = ZkProofSubmission {
        proof: parse_proof_bytes(),
        signals,
        scheme_tag: 0,
        user_context_data: user_context_data(),
    };
    let attacker = [0x99u8; 20];
    assert_eq!(
        submit_zk_passport_proof(
            &mut state,
            &verifier,
            &attacker,
            &submission,
            NOW,
            NOW_BLOCK
        ),
        Err(ZkPohError::SubmitterMismatch),
        "a relayed proof cannot be re-bound to another account"
    );
}

#[test]
fn fails_closed_on_a_tampered_user_identifier() {
    // If signal 20 no longer equals ripemd160(sha256(userContextData)), the binding rejects it.
    let mut signals = parse_signals();
    signals[SELF_IDX_USER_IDENTIFIER][31] ^= 0x01;
    let ucd = user_context_data();
    let mut subject = [0u8; 20];
    subject.copy_from_slice(&ucd[44..64]);
    let mut state = seed_for_capture(&signals);
    let verifier = Groth16Verifier::from_pinned().unwrap();
    let submission = ZkProofSubmission {
        proof: parse_proof_bytes(),
        signals,
        scheme_tag: 0,
        user_context_data: ucd,
    };
    assert!(
        submit_zk_passport_proof(&mut state, &verifier, &subject, &submission, NOW, NOW_BLOCK)
            .is_err(),
        "a tampered user_identifier fails closed"
    );
}

fn hex_lower(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
