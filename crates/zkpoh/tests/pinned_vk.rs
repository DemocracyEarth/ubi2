//! The genesis-pinned VK is the real Self VK, byte-for-byte (M6 ZK-PoH Stage 2).
//!
//! Asserts that the VK embedded in `genesis_vk.rs` (`HAS_PINNED_PASSPORT_VK == true`) is exactly the real
//! Self `vc_and_disclose` VK from the fixture, re-imported and canonically re-serialized — i.e. the
//! genesis trust anchor *is* the real artifact, not a placeholder. This is the Stage-2 closure of "pin
//! the REAL verifying key" + the `state_root`-commit byte-stability guarantee (§5.3).

use serde_json::Value;
use ubi2_zkpoh::{
    pinned_passport_vk, Groth16Verifier, PassportLayout, PinnedVerifyingKey, SnarkjsVk,
    HAS_PINNED_PASSPORT_VK, SELF_NPUBLIC,
};

const REAL_VK_JSON: &str = include_str!("fixtures/self_vc_and_disclose_vkey.json");

fn g1(v: &Value) -> [String; 3] {
    let a = v.as_array().unwrap();
    [
        a[0].as_str().unwrap().into(),
        a[1].as_str().unwrap().into(),
        a[2].as_str().unwrap().into(),
    ]
}
fn g2(v: &Value) -> [[String; 2]; 3] {
    let a = v.as_array().unwrap();
    let pair = |i: usize| {
        let p = a[i].as_array().unwrap();
        [p[0].as_str().unwrap().into(), p[1].as_str().unwrap().into()]
    };
    [pair(0), pair(1), pair(2)]
}

fn fixture_vk() -> PinnedVerifyingKey {
    let j: Value = serde_json::from_str(REAL_VK_JSON).unwrap();
    let ic = j["IC"].as_array().unwrap().iter().map(g1).collect();
    SnarkjsVk {
        vk_alpha_1: g1(&j["vk_alpha_1"]),
        vk_beta_2: g2(&j["vk_beta_2"]),
        vk_gamma_2: g2(&j["vk_gamma_2"]),
        vk_delta_2: g2(&j["vk_delta_2"]),
        ic,
    }
    .to_pinned()
    .unwrap()
}

#[test]
fn pinned_vk_is_the_real_self_vk_byte_for_byte() {
    // Read the const through a runtime binding so this is a genuine runtime assertion (Stage 2 sets it).
    let has_pinned = HAS_PINNED_PASSPORT_VK;
    assert!(has_pinned, "Stage 2 pins a real VK");

    let pinned = pinned_passport_vk().expect("a real VK is pinned");
    assert_eq!(
        pinned.num_public_inputs(),
        SELF_NPUBLIC,
        "the pinned VK is the real 20-signal Self disclose arity"
    );

    // The embedded canonical bytes equal the fixture import's canonical bytes — the genesis trust anchor
    // IS the real Self VK, not a placeholder.
    let pinned_bytes = pinned.to_canonical_bytes().unwrap();
    let fixture_bytes = fixture_vk().to_canonical_bytes().unwrap();
    assert_eq!(
        pinned_bytes, fixture_bytes,
        "the genesis-pinned VK bytes match the real Self VK fixture exactly"
    );
}

#[test]
fn from_pinned_wires_the_self_layout_verifier() {
    let verifier = Groth16Verifier::from_pinned().expect("from_pinned wires the real VK");
    assert_eq!(verifier.layout(), PassportLayout::SelfDisclose);
    assert_eq!(verifier.passport_arity(), SELF_NPUBLIC);
}
