//! EC-C7 GO/NO-GO — does the GENUINE captured Self staging proof verify against our pinned PRODUCTION VK?
//!
//! Fixtures are a real proof captured from a Self mobile-app mock-passport STAGING scan (via the C1 relay
//! `apps/wallet/app/api/self-verify` capture side-channel): `self_staging_proof.json` is the app's affine
//! Groth16 proof (`a`/`b`/`c`, 2 coords each) and `self_staging_public.json` is the 21 public signals
//! (real staging merkle_root@9, scope@19, etc.). It is checked against `self_prod_vkey.json` (Self's real
//! vc_and_disclose VK, extracted on-chain).
//!
//! This is THE gate: if this verifies TRUE through the exact `Groth16Verifier` seam that runs on-chain,
//! our extracted VK matches the staging ceremony and we can pin it + flip the real verifier. We try both
//! G2 coordinate orderings for the proof's `b` point (snarkjs vs solidity-swapped) and report which holds.

use ark_bn254::{Bn254, Fq, Fq2, Fr, G1Affine, G2Affine};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Proof;
use serde_json::Value;
use std::str::FromStr;
use ubi2_zkpoh::{
    proof_to_canonical_bytes, Groth16Verifier, SnarkjsVk, ZkPassportVerifier, ZkPublicInputs,
    SELF_NPUBLIC,
};

const PROD_VKEY_JSON: &str = include_str!("../fixtures/self_prod_vkey.json");
const PROOF_JSON: &str = include_str!("../fixtures/self_staging_proof.json");
const PUBLIC_JSON: &str = include_str!("../fixtures/self_staging_public.json");

fn fq(s: &str) -> Fq {
    Fq::from_str(s).unwrap()
}
fn g1s(v: &Value) -> [String; 3] {
    let a = v.as_array().unwrap();
    [
        a[0].as_str().unwrap().into(),
        a[1].as_str().unwrap().into(),
        a[2].as_str().unwrap().into(),
    ]
}
fn g2s(v: &Value) -> [[String; 2]; 3] {
    let a = v.as_array().unwrap();
    let p = |i: usize| {
        let q = a[i].as_array().unwrap();
        [q[0].as_str().unwrap().into(), q[1].as_str().unwrap().into()]
    };
    [p(0), p(1), p(2)]
}
fn prod_vk() -> SnarkjsVk {
    let j: Value = serde_json::from_str(PROD_VKEY_JSON).unwrap();
    let ic = j["IC"].as_array().unwrap().iter().map(g1s).collect();
    SnarkjsVk {
        vk_alpha_1: g1s(&j["vk_alpha_1"]),
        vk_beta_2: g2s(&j["vk_beta_2"]),
        vk_gamma_2: g2s(&j["vk_gamma_2"]),
        vk_delta_2: g2s(&j["vk_delta_2"]),
        ic,
    }
}

/// Build the arkworks Proof from the captured affine `a`/`b`/`c`. `swap_b` flips the Fq2 component order
/// of the G2 `b` point (snarkjs `[c0,c1]` vs solidity `[c1,c0]`). new_unchecked so a wrong ordering can't
/// panic — an off-curve point is rejected fail-closed by the verifier's validated canonical decode.
fn parse_proof(swap_b: bool) -> Proof<Bn254> {
    let j: Value = serde_json::from_str(PROOF_JSON).unwrap();
    let a = j["a"].as_array().unwrap();
    let ga = G1Affine::new_unchecked(fq(a[0].as_str().unwrap()), fq(a[1].as_str().unwrap()));
    let b = j["b"].as_array().unwrap();
    let b0 = b[0].as_array().unwrap();
    let b1 = b[1].as_array().unwrap();
    let (b00, b01) = (fq(b0[0].as_str().unwrap()), fq(b0[1].as_str().unwrap()));
    let (b10, b11) = (fq(b1[0].as_str().unwrap()), fq(b1[1].as_str().unwrap()));
    let gb = if swap_b {
        G2Affine::new_unchecked(Fq2::new(b01, b00), Fq2::new(b11, b10))
    } else {
        G2Affine::new_unchecked(Fq2::new(b00, b01), Fq2::new(b10, b11))
    };
    let c = j["c"].as_array().unwrap();
    let gc = G1Affine::new_unchecked(fq(c[0].as_str().unwrap()), fq(c[1].as_str().unwrap()));
    Proof {
        a: ga,
        b: gb,
        c: gc,
    }
}

fn parse_signals() -> [[u8; 32]; SELF_NPUBLIC] {
    let j: Value = serde_json::from_str(PUBLIC_JSON).unwrap();
    let arr = j.as_array().unwrap();
    assert_eq!(
        arr.len(),
        SELF_NPUBLIC,
        "captured public.json carries 21 signals"
    );
    let mut out = [[0u8; 32]; SELF_NPUBLIC];
    for (i, s) in arr.iter().enumerate() {
        let f = Fr::from_str(s.as_str().unwrap()).unwrap();
        let be = f.into_bigint().to_bytes_be();
        out[i][32 - be.len()..].copy_from_slice(&be);
    }
    out
}

#[test]
fn captured_staging_proof_verifies_against_production_vk() {
    let verifier = Groth16Verifier::from_vk_bytes(
        &prod_vk().to_pinned().unwrap().to_canonical_bytes().unwrap(),
    )
    .expect("production VK loads at arity 21");
    let pi = ZkPublicInputs::new(parse_signals());

    let mut winner: Option<bool> = None;
    for &swap in &[false, true] {
        // proof_to_canonical_bytes may fail for a truly off-curve ordering; treat that as "not this one".
        let ok = match proof_to_canonical_bytes(&parse_proof(swap)) {
            Ok(bytes) => verifier.verify_passport(&bytes, &pi),
            Err(_) => false,
        };
        eprintln!("  G2 b ordering swap_b={swap:<5} -> verify = {ok}");
        if ok {
            winner = Some(swap);
            break;
        }
    }

    match winner {
        Some(swap) => eprintln!(
            "\n✅ EC-C7 GO — captured Self staging proof VERIFIES against the production VK (b swap_b={swap}). \
             The extracted VK matches the staging ceremony; safe to pin + flip."
        ),
        None => eprintln!(
            "\n❌ EC-C7 NO-GO — the captured proof did NOT verify against the extracted VK under either G2 \
             ordering. The staging deployment likely uses a different ceremony; extract that verifier's own VK."
        ),
    }
    assert!(
        winner.is_some(),
        "captured staging proof must verify against the pinned production VK (GO/NO-GO gate)"
    );
}
