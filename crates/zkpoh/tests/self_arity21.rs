//! Arity-21 real-curve verify test + the pinned-VK generator (spec 06b §4, EC-C2/C6 crypto core).
//!
//! ## SYNTHETIC layout/pipeline lock — NOT Self's production VK
//!
//! The fixtures here (`self_synthetic_{vkey,proof,public}.json`) are a **self-generated Groth16/BN254
//! setup over the CONFIRMED 21-signal `vc_and_disclose` public-signal layout** (nPublic = 21, VK
//! `IC.len() == 22`). They are a **SYNTHETIC layout/pipeline lock**: they prove our verifier, our snarkjs
//! importer, and our full-vector carriage all work at the **real arity + slot order** — a genuine
//! Groth16 proof verifies TRUE through the production `Groth16Verifier` seam at 21 public inputs, and a
//! tampered proof / a wrong-slot public input fails **closed**. They are explicitly **NOT** Self's
//! production `vc_and_disclose` VK (Self's S3 returns 403; the ceremony `.zkey` is uncommitted — spec
//! 06b §4.1 VK-status). Pinning the real production VK + capturing a genuine Self staging proof is EC-C7
//! (the C1 SDK flow), the hard pre-mainnet gate that flips the real verifier to the value-minting default.
//!
//! The synthetic proof's public vector (`self_synthetic_public.json`) is laid out per §4.1:
//! `revealedData[0..3]`, `forbidden[3..7]`, `nullifier@7`, `attestation_id@8`, `merkle_root@9`,
//! `current_date[10..16]`, OFAC `@16..19`, `scope@19`, `user_identifier@20`.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use serde_json::Value;
use std::str::FromStr;
use ubi2_zkpoh::{
    proof_to_canonical_bytes, Groth16Verifier, PassportLayout, SnarkjsVk, ZkPassportVerifier,
    ZkPublicInputs, SELF_IDX_NULLIFIER, SELF_NPUBLIC,
};

const VKEY_JSON: &str = include_str!("../fixtures/self_synthetic_vkey.json");
const PROOF_JSON: &str = include_str!("../fixtures/self_synthetic_proof.json");
const PUBLIC_JSON: &str = include_str!("../fixtures/self_synthetic_public.json");

fn g1_triple(v: &Value) -> [String; 3] {
    let a = v.as_array().unwrap();
    [
        a[0].as_str().unwrap().to_string(),
        a[1].as_str().unwrap().to_string(),
        a[2].as_str().unwrap().to_string(),
    ]
}
fn g2_triple(v: &Value) -> [[String; 2]; 3] {
    let a = v.as_array().unwrap();
    let pair = |i: usize| {
        let p = a[i].as_array().unwrap();
        [
            p[0].as_str().unwrap().to_string(),
            p[1].as_str().unwrap().to_string(),
        ]
    };
    [pair(0), pair(1), pair(2)]
}

fn parse_vk() -> SnarkjsVk {
    let j: Value = serde_json::from_str(VKEY_JSON).unwrap();
    assert_eq!(j["protocol"], "groth16");
    assert_eq!(j["curve"], "bn128");
    let ic = j["IC"]
        .as_array()
        .unwrap()
        .iter()
        .map(g1_triple)
        .collect::<Vec<_>>();
    SnarkjsVk {
        vk_alpha_1: g1_triple(&j["vk_alpha_1"]),
        vk_beta_2: g2_triple(&j["vk_beta_2"]),
        vk_gamma_2: g2_triple(&j["vk_gamma_2"]),
        vk_delta_2: g2_triple(&j["vk_delta_2"]),
        ic,
    }
}

fn fq(s: &str) -> Fq {
    Fq::from_str(s).unwrap()
}

/// Decode the snarkjs proof (`pi_a`/`pi_b`/`pi_c` decimal strings) into an arkworks `Proof<Bn254>`.
fn parse_proof() -> Proof<Bn254> {
    let j: Value = serde_json::from_str(PROOF_JSON).unwrap();
    let a = j["pi_a"].as_array().unwrap();
    let ga = G1Affine::new(fq(a[0].as_str().unwrap()), fq(a[1].as_str().unwrap()));
    let b = j["pi_b"].as_array().unwrap();
    let b0 = b[0].as_array().unwrap();
    let b1 = b[1].as_array().unwrap();
    let gb = G2Affine::new(
        Fq2::new(fq(b0[0].as_str().unwrap()), fq(b0[1].as_str().unwrap())),
        Fq2::new(fq(b1[0].as_str().unwrap()), fq(b1[1].as_str().unwrap())),
    );
    let c = j["pi_c"].as_array().unwrap();
    let gc = G1Affine::new(fq(c[0].as_str().unwrap()), fq(c[1].as_str().unwrap()));
    Proof {
        a: ga,
        b: gb,
        c: gc,
    }
}

/// The 21 public signals as raw 32-byte big-endian [`Hash`]-shaped values — the exact on-chain carriage
/// the runtime hands the verifier (spec 06b §4.3). Each fixture value is a decimal `Fr`.
fn parse_signals() -> [[u8; 32]; SELF_NPUBLIC] {
    let j: Value = serde_json::from_str(PUBLIC_JSON).unwrap();
    let arr = j.as_array().unwrap();
    assert_eq!(arr.len(), SELF_NPUBLIC, "public.json carries 21 signals");
    let mut out = [[0u8; 32]; SELF_NPUBLIC];
    for (i, s) in arr.iter().enumerate() {
        let f = Fr::from_str(s.as_str().unwrap()).unwrap();
        let be = f.into_bigint().to_bytes_be(); // 32 bytes for BN254
        out[i][32 - be.len()..].copy_from_slice(&be);
    }
    out
}

#[test]
fn synthetic_vk_is_arity_21_and_loads_as_self_layout() {
    let pinned = parse_vk().to_pinned().unwrap();
    assert_eq!(
        pinned.num_public_inputs(),
        SELF_NPUBLIC,
        "the synthetic layout-lock VK is nPublic = 21 (IC.len() == 22)"
    );
    assert_eq!(SELF_NPUBLIC, 21);
    // It loads through the real verifier's arity gate as the confirmed Self layout.
    let vk_bytes = pinned.to_canonical_bytes().unwrap();
    let verifier = Groth16Verifier::from_vk_bytes(&vk_bytes).expect("arity-21 VK loads");
    assert_eq!(verifier.layout(), PassportLayout::SelfDisclose);
    assert_eq!(verifier.passport_arity(), SELF_NPUBLIC);
}

#[test]
fn groth16verifier_accepts_the_synthetic_proof_at_arity_21() {
    // EC-C2/C6 crypto core: a genuine Groth16/BN254 proof verifies TRUE through the PRODUCTION
    // `Groth16Verifier` seam at the REAL arity (21) + the CONFIRMED slot layout.
    let pinned = parse_vk().to_pinned().unwrap();
    let verifier = Groth16Verifier::new(pinned);
    let proof_bytes = proof_to_canonical_bytes(&parse_proof()).unwrap();
    let pi = ZkPublicInputs::new(parse_signals());
    assert!(
        verifier.verify_passport(&proof_bytes, &pi),
        "the synthetic proof verifies at arity 21 through the real seam"
    );
}

#[test]
fn fails_closed_on_tampered_proof() {
    let pinned = parse_vk().to_pinned().unwrap();
    let verifier = Groth16Verifier::new(pinned);
    let mut proof_bytes = proof_to_canonical_bytes(&parse_proof()).unwrap();
    // Flip a byte in the proof — canonical decode fails or the pairing no longer holds ⇒ false.
    let last = proof_bytes.len() - 1;
    proof_bytes[last] ^= 0xFF;
    let pi = ZkPublicInputs::new(parse_signals());
    assert!(
        !verifier.verify_passport(&proof_bytes, &pi),
        "a tampered proof fails closed"
    );
}

#[test]
fn fails_closed_on_wrong_slot_public_input() {
    // Flip the nullifier slot (7): the proof no longer satisfies the statement ⇒ false.
    let pinned = parse_vk().to_pinned().unwrap();
    let verifier = Groth16Verifier::new(pinned);
    let proof_bytes = proof_to_canonical_bytes(&parse_proof()).unwrap();
    let mut signals = parse_signals();
    signals[SELF_IDX_NULLIFIER][31] ^= 0x01;
    let pi = ZkPublicInputs::new(signals);
    assert!(
        !verifier.verify_passport(&proof_bytes, &pi),
        "a wrong-slot public input fails closed"
    );
}

/// Regenerate the genesis-pinned canonical VK bytes from the synthetic 21-signal VK JSON. This is the
/// SYNTHETIC layout/pipeline lock the node wires via `Chain::with_verifier` (staging/opt-in) — NOT Self's
/// production VK (EC-C7 gate). Run with `cargo test -p ubi2-zkpoh regen_pinned_synthetic_vk -- --ignored`.
#[test]
#[ignore]
fn regen_pinned_synthetic_vk() {
    let pinned = parse_vk().to_pinned().unwrap();
    let bytes = pinned.to_canonical_bytes().unwrap();
    std::fs::write(
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/self_synthetic_vk.canonical.bin"
        ),
        &bytes,
    )
    .unwrap();
}
