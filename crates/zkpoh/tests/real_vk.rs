//! Real Self/OpenPassport verifying-key binding test (spec §2.2, §6.3, ADR-0005 D1).
//!
//! This closes the "attempt to fetch a REAL Self/OpenPassport Groth16 verifying key and verify it" item:
//! the fixture `fixtures/self_vc_and_disclose_vkey.json` is the **actual** Self protocol
//! `vc_and_disclose` circuit verifying key (Groth16 over BN254, `nPublic = 20`), taken verbatim from the
//! Self monorepo (`selfxyz/self`, `common/src/constants/vkey.ts` — the `zk-passport/openpassport` repo
//! now redirects there). It proves three things end-to-end against a real artifact:
//!
//!   1. **Format alignment.** Our [`SnarkjsVk`] importer ingests the real snarkjs `verification_key.json`
//!      shape (`vk_alpha_1` / `vk_beta_2` / `vk_gamma_2` / `vk_delta_2` / `IC`) — confirming the design
//!      pin (Groth16/BN254/snarkjs, ADR-0005 D1) matches the real circuits' published keys.
//!   2. **On-curve validation + canonical round-trip.** Every VK point loads through arkworks'
//!      validating constructors, and the loaded VK re-serializes to canonical bytes and re-parses
//!      identically (the `state_root`-commit form, §5.3) — the cross-node trust-anchor agreement.
//!   3. **The arity pin holds against a real foreign VK.** The disclose circuit emits `nPublic = 20`
//!      public inputs, NOT our pinned §3.5 layout of 8. [`Groth16Verifier::from_vk_bytes`] therefore
//!      *rejects* it — exactly the fail-closed behavior we want until the circuit's public outputs are
//!      adapted to emit our 8-field vector (nullifier, 3 attr commitments, CSCA root, submitter, now,
//!      scheme tag). That adaptation + a re-run Phase-2 ceremony is the documented next step; it changes
//!      the VK bytes + the circuit, never this crate's verifier code.

use serde_json::Value;
use ubi2_zkpoh::{Groth16Verifier, PinnedVerifyingKey, SnarkjsVk};

const REAL_VK_JSON: &str = include_str!("fixtures/self_vc_and_disclose_vkey.json");

/// Pull a G1 `[x, y, z]` triple of decimal strings out of a snarkjs JSON array.
fn g1(v: &Value) -> [String; 3] {
    let a = v.as_array().expect("G1 point is an array");
    [
        a[0].as_str().unwrap().to_string(),
        a[1].as_str().unwrap().to_string(),
        a[2].as_str().unwrap().to_string(),
    ]
}

/// Pull a G2 `[[x0,x1],[y0,y1],[z0,z1]]` out of a snarkjs JSON array.
fn g2(v: &Value) -> [[String; 2]; 3] {
    let a = v.as_array().expect("G2 point is an array");
    let pair = |i: usize| {
        let p = a[i].as_array().unwrap();
        [
            p[0].as_str().unwrap().to_string(),
            p[1].as_str().unwrap().to_string(),
        ]
    };
    [pair(0), pair(1), pair(2)]
}

fn parse_real_vk() -> SnarkjsVk {
    let j: Value = serde_json::from_str(REAL_VK_JSON).expect("fixture is valid JSON");
    assert_eq!(j["protocol"], "groth16", "real VK is Groth16");
    assert_eq!(j["curve"], "bn128", "real VK is over BN254 (alt-bn128)");
    let ic = j["IC"]
        .as_array()
        .expect("IC array")
        .iter()
        .map(g1)
        .collect::<Vec<_>>();
    SnarkjsVk {
        vk_alpha_1: g1(&j["vk_alpha_1"]),
        vk_beta_2: g2(&j["vk_beta_2"]),
        vk_gamma_2: g2(&j["vk_gamma_2"]),
        vk_delta_2: g2(&j["vk_delta_2"]),
        ic,
    }
}

#[test]
fn real_self_disclose_vk_loads_validates_and_round_trips() {
    let snark_vk = parse_real_vk();
    // The real disclose circuit has nPublic = 20 ⇒ IC has 21 points.
    assert_eq!(
        snark_vk.ic.len(),
        21,
        "Self disclose VK has nPublic+1 = 21 IC points"
    );

    // Import + on-curve-validate every point. A bogus VK would fail here; the real one loads.
    let pinned: PinnedVerifyingKey = snark_vk
        .to_pinned()
        .expect("the real Self disclose VK imports + validates on-curve");
    assert_eq!(
        pinned.num_public_inputs(),
        20,
        "imported arity matches the circuit's nPublic"
    );

    // Canonical round-trip: serialize to the `state_root`-commit bytes and re-parse to the same arity.
    let bytes = pinned
        .to_canonical_bytes()
        .expect("real VK serializes canonically");
    let reloaded = PinnedVerifyingKey::from_canonical_bytes(&bytes)
        .expect("real VK re-parses from its canonical bytes");
    assert_eq!(reloaded.num_public_inputs(), 20);
    let bytes2 = reloaded.to_canonical_bytes().unwrap();
    assert_eq!(
        bytes, bytes2,
        "canonical VK encoding is byte-stable (cross-node agreement)"
    );
}

#[test]
fn real_foreign_arity_vk_is_rejected_by_the_passport_arity_pin() {
    let snark_vk = parse_real_vk();
    let pinned = snark_vk.to_pinned().unwrap();
    let vk_bytes = pinned.to_canonical_bytes().unwrap();

    // The disclose VK is a perfectly valid Groth16/BN254 VK — but for arity 20, not our pinned 8 (§3.5).
    // The passport verifier loader rejects it, fail-closed, rather than mis-applying a foreign circuit.
    assert!(
        Groth16Verifier::from_vk_bytes(&vk_bytes).is_none(),
        "a real 20-input Self VK must be rejected by the 8-input passport arity pin (§3.5)"
    );
}
