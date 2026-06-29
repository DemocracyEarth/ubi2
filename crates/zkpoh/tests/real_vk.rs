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
//!   3. **The real arity now LOADS (Stage 2).** The disclose circuit emits `nPublic = 20` public inputs.
//!      In Stage 1 our verifier pinned only the 8-field domain arity, so the real VK was rejected
//!      fail-closed. Stage 2 implements the real **20-signal** Self layout (`crate::self_layout`):
//!      [`Groth16Verifier::from_vk_bytes`] now recognizes the 20-arity and loads the real VK as a
//!      `SelfDisclose`-layout passport verifier, with the runtime's domain inputs (spec §3.5) mapped onto
//!      the real 20-signal vector by the documented adapter. A VK of any *other* arity (neither 8 nor 20)
//!      is still rejected fail-closed. The remaining gap to a fully production binding is Self's
//!      ceremony `.zkey` (needed to generate a proof under their *production* VK), which is not committed
//!      to the open repo — see `real_curve_self_layout.rs`, which proves a genuine proof at the real
//!      arity through a self-generated setup (the spec §6.3 real-curve fixture path).

use serde_json::Value;
use ubi2_zkpoh::{
    Groth16Verifier, PassportLayout, PinnedVerifyingKey, SnarkjsVk, ZkPassportVerifier,
    SELF_NPUBLIC,
};

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
fn real_self_disclose_vk_loads_as_self_layout_passport_verifier() {
    // Stage 2: the real 20-input Self disclose VK now LOADS as a `SelfDisclose`-layout passport verifier
    // (the Stage-1 8-arity rejection is replaced by the real-arity binding, `crate::self_layout`).
    let snark_vk = parse_real_vk();
    assert_eq!(snark_vk.ic.len() - 1, SELF_NPUBLIC);
    let pinned = snark_vk.to_pinned().unwrap();
    let vk_bytes = pinned.to_canonical_bytes().unwrap();

    let verifier = Groth16Verifier::from_vk_bytes(&vk_bytes)
        .expect("the real 20-input Self VK loads as a Self-layout passport verifier (Stage 2)");
    assert_eq!(verifier.layout(), PassportLayout::SelfDisclose);
    assert_eq!(verifier.passport_arity(), SELF_NPUBLIC);

    // A garbage proof against the real VK still fails closed (no proof ⇒ no accept; we have no production
    // ceremony zkey to generate a real proof under this exact VK — see real_curve_self_layout.rs).
    let dummy_pi = ubi2_zkpoh::ZkPublicInputs::new(
        [1u8; 32],
        [[0u8; 32]; 3],
        [0u8; 32],
        [0u8; 20],
        1_700_000_000,
        0,
    );
    assert!(
        !verifier.verify_passport(&[0xFFu8; 256], &dummy_pi),
        "a non-canonical proof against the real VK fails closed"
    );
}

#[test]
fn a_foreign_arity_vk_is_still_rejected() {
    // A VK whose arity is neither the 8-field domain layout nor the 20-signal Self layout is rejected
    // fail-closed (the arity guard still protects against an unrecognized circuit). We synthesize a
    // 1-input VK to exercise this.
    use ark_bn254::{Bn254, Fr};
    use ark_groth16::Groth16;
    use ark_relations::lc;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
    use ark_serialize::{CanonicalSerialize, Compress};
    use ark_snark::SNARK;
    use ark_std::rand::{rngs::StdRng, SeedableRng};

    struct OneInput {
        x: Fr,
        w: Fr,
    }
    impl ConstraintSynthesizer<Fr> for OneInput {
        fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
            let x = cs.new_input_variable(|| Ok(self.x))?;
            let w = cs.new_witness_variable(|| Ok(self.w))?;
            cs.enforce_constraint(lc!() + w, lc!() + w, lc!() + x)?;
            Ok(())
        }
    }
    let mut rng = StdRng::seed_from_u64(7);
    let w = Fr::from(9u64);
    let (_, vk) =
        Groth16::<Bn254>::circuit_specific_setup(OneInput { x: w * w, w }, &mut rng).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
        .unwrap();
    assert!(
        Groth16Verifier::from_vk_bytes(&vk_bytes).is_none(),
        "a 1-input VK is neither the 8 nor 20 arity ⇒ rejected fail-closed"
    );
}
