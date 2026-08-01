//! EC-C7 de-risk — the **real** Self production `vc_and_disclose` VK loads through our pin pipeline.
//!
//! `fixtures/self_prod_vkey.json` is the production 21-signal `vc_and_disclose` V2 verifying key,
//! reconstructed from Self's on-chain Groth16 verifier and adversarially cross-checked byte-for-byte
//! against two independent primary sources: the GitHub generated
//! `contracts/contracts/verifiers/disclose/Verifier_vc_and_disclose.sol`, and the Celoscan-verified live
//! Celo-mainnet deployment `0x0A57C317800865194496763377d25CA2082DB649` (byte-identical to the
//! Celo-Sepolia staging verifier `0x7C2FBA7F...`, so one VK serves both). The G2 coordinates are emitted
//! in snarkjs `[[c0,c1],...]` order (the `.sol` stores `c1,c0`); the swap direction was proven by reducing
//! `vk_gamma_2` to the canonical BN254 G2 generator, and all 4 fixed points + 22 IC points pass on-curve
//! + prime-order-subgroup validation.
//!
//! This test does NOT assert a proof verifies (that needs a captured genuine staging proof — the human
//! step of EC-C7). It asserts the load-bearing mechanical fact: our `SnarkjsVk -> to_pinned ->
//! to_canonical_bytes -> from_canonical_bytes(Validate::Yes) -> Groth16Verifier::from_vk_bytes` pipeline
//! ACCEPTS this real VK at the confirmed arity (nPublic = 21, `IC.len() == 22`) with full validation. If
//! this holds, the VK is pinnable; the only thing then gating the flip is capturing a real proof.

use serde_json::Value;
use ubi2_zkpoh::{Groth16Verifier, PinnedVerifyingKey, SnarkjsVk, SELF_NPUBLIC};

const PROD_VKEY_JSON: &str = include_str!("../fixtures/self_prod_vkey.json");

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

fn parse_prod_vk() -> (SnarkjsVk, usize) {
    let j: Value = serde_json::from_str(PROD_VKEY_JSON).unwrap();
    assert_eq!(j["protocol"], "groth16", "expected a groth16 vkey");
    assert_eq!(j["curve"], "bn128", "expected a BN254/bn128 vkey");
    assert_eq!(
        j["nPublic"], 21,
        "production vc_and_disclose is a 21-signal circuit"
    );
    let ic = j["IC"]
        .as_array()
        .unwrap()
        .iter()
        .map(g1_triple)
        .collect::<Vec<_>>();
    let ic_len = ic.len();
    (
        SnarkjsVk {
            vk_alpha_1: g1_triple(&j["vk_alpha_1"]),
            vk_beta_2: g2_triple(&j["vk_beta_2"]),
            vk_gamma_2: g2_triple(&j["vk_gamma_2"]),
            vk_delta_2: g2_triple(&j["vk_delta_2"]),
            ic,
        },
        ic_len,
    )
}

#[test]
fn prod_vk_imports_at_confirmed_arity() {
    let (vk, ic_len) = parse_prod_vk();
    // The confirmed Self layout: 21 public signals => IC has nPublic + 1 = 22 points.
    assert_eq!(
        ic_len, 22,
        "vc_and_disclose VK must carry 22 IC points (21 signals + 1)"
    );

    // 1. snarkjs import -> arkworks: every fixed point + all 22 IC points decode on-curve/in-subgroup.
    let pinned = vk
        .to_pinned()
        .expect("real production VK must import through SnarkjsVk::to_pinned (all points valid)");
    assert_eq!(
        pinned.num_public_inputs(),
        SELF_NPUBLIC,
        "pinned production VK must report the confirmed arity (21)"
    );

    // 2. Canonical-compressed round-trip WITH validation (the exact genesis-pin form, Validate::Yes).
    let bytes = pinned
        .to_canonical_bytes()
        .expect("pinned VK must serialize to canonical-compressed bytes");
    let reloaded = PinnedVerifyingKey::from_canonical_bytes(&bytes).expect(
        "canonical bytes must re-load with full validation (on-curve, subgroup, canonical)",
    );
    assert_eq!(reloaded.num_public_inputs(), SELF_NPUBLIC);

    // 3. The exact constructor crates/node uses for the real verifier accepts it (arity gate passes,
    //    where the stale 20-signal legacy VK would be rejected as a foreign circuit).
    let verifier = Groth16Verifier::from_vk_bytes(&bytes)
        .expect("Groth16Verifier::from_vk_bytes must accept the real 21-signal production VK");
    assert_eq!(verifier.passport_arity(), SELF_NPUBLIC);

    eprintln!(
        "EC-C7 de-risk OK: production vc_and_disclose VK pins cleanly — nPublic={}, IC={}, canonical VK = {} bytes",
        SELF_NPUBLIC, ic_len, bytes.len()
    );
}
