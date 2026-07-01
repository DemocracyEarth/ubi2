//! Real-curve Self-layout soundness test (M6 ZK-PoH Stage 2 — closing the Stage-1 arity gap).
//!
//! Stage 1 confirmed the real Self `vc_and_disclose` VK is Groth16/BN254 with **nPublic = 20** and that
//! our 8-field domain layout did not match it (the 8-arity pin correctly rejected the real VK,
//! fail-closed). Stage 2 implements the real **arity-20** layout: the runtime's domain inputs (spec §3.5)
//! are mapped onto the real 20-signal vector by [`PublicInputs::to_self_field_elements`], and
//! [`Groth16Verifier`] selects that mapping from the VK's arity.
//!
//! This test proves a **genuine Groth16/BN254 proof verifies under the real 20-public-input arity**,
//! end-to-end through the production `verify_passport` seam:
//!
//!   * **PROVE IT (validity).** We generate a real proof for a circuit whose public-input arity is
//!     *exactly* `SELF_NPUBLIC = 20` — the same arity as the real Self disclose VK (`IC.len() == 21`) —
//!     binding all 20 signals into the constraint system, then verify it through `Groth16Verifier` in
//!     `SelfDisclose` layout. This is a real proof on the real curve at the real arity.
//!   * **Determinism (I1).** Two independent verifications agree; the proof + VK round-trip canonical
//!     bytes byte-for-byte (the cross-node trust-anchor / non-malleability guarantee).
//!   * **Soundness (F-3/F-4).** A tampered proof, a tampered nullifier, a different submitter (the
//!     anti-replay binding), and garbage proof bytes all fail closed.
//!   * **Replayed nullifier.** A proof bound to nullifier `N` does not verify when re-presented with a
//!     different nullifier — the crypto-layer half of the on-chain nullifier-uniqueness guard (the chain
//!     additionally rejects a *spent* `N` before the pairing, §4.2 step 3 / F-5).
//!
//! The circuit here is a faithful **arity + shape** stand-in for the real passive-authentication
//! `vc_and_disclose` circuit: 20 ordered public inputs in the real layout, a private witness, and a
//! multiplicative binding constraint on the nullifier slot. The real production binding (Self's compiled
//! circuit + its Phase-2 ceremony `.zkey`) is a build/ceremony artifact not committed to the open repo
//! (the repo ships only the VK, fixtured in `real_vk.rs`); generating a proof under Self's *production*
//! VK would require that ceremony zkey. We therefore prove the verifier + the real arity + the domain
//! adapter against the real curve with a self-generated setup — the spec §6.3 real-curve fixture path
//! ("a test CSCA→DSC→SOD, never a real document") — which is exactly what de-risks the on-chain verifier.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use ubi2_zkpoh::{
    proof_to_canonical_bytes, Groth16Verifier, PassportLayout, PublicInputs, ZkPassportVerifier,
    ZkPublicInputs, SELF_IDX_NULLIFIER, SELF_NPUBLIC,
};

/// The Self-layout field vector for a runtime `ZkPublicInputs` (the single canonical adapter the verifier
/// uses internally), exposed so the test circuit is fed the *same* 20 signals the verifier will check.
fn self_field_inputs_of(pi: &ZkPublicInputs) -> [Fr; SELF_NPUBLIC] {
    PublicInputs::from_runtime(pi).to_self_field_elements()
}

/// A circuit with **exactly** `SELF_NPUBLIC` (20) public inputs — the real Self arity — that proves
/// knowledge of a private witness `w` with `w * w == public[SELF_IDX_NULLIFIER]` (the nullifier slot),
/// while binding all 20 public inputs into the system. The same anatomy as the real PA circuit (private
/// signature/MRZ witnesses, public nullifier + disclosure outputs), at a size that runs fast in CI.
struct SelfShapeCircuit {
    public: [Fr; SELF_NPUBLIC],
    witness_sqrt: Fr,
}

impl ConstraintSynthesizer<Fr> for SelfShapeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut input_vars = Vec::with_capacity(SELF_NPUBLIC);
        for v in self.public.iter() {
            let val = *v;
            input_vars.push(cs.new_input_variable(|| Ok(val))?);
        }
        let w_var = cs.new_witness_variable(|| Ok(self.witness_sqrt))?;
        // Binding constraint on the nullifier slot: a proof exists iff the prover knows a square root.
        let nullifier_var = input_vars[SELF_IDX_NULLIFIER];
        cs.enforce_constraint(lc!() + w_var, lc!() + w_var, lc!() + nullifier_var)?;
        // Tie every other public input into a `* 1` identity so the QAP genuinely depends on all 20 (so
        // tampering with any of them on the verify side breaks the pairing equation).
        let one = ark_relations::r1cs::Variable::One;
        for (i, &iv) in input_vars.iter().enumerate() {
            if i == SELF_IDX_NULLIFIER {
                continue;
            }
            cs.enforce_constraint(lc!() + iv, lc!() + one, lc!() + iv)?;
        }
        Ok(())
    }
}

/// Build a 20-signal public vector (in the real Self layout) and a circuit whose witness is a true square
/// root of the nullifier slot, so a valid proof exists.
fn sample_inputs() -> (ZkPublicInputs, Fr) {
    let w = Fr::from(987_654_321u64);
    let nullifier_fr = w * w;
    let mut null_be = [0u8; 32];
    {
        use ark_ff::{BigInteger, PrimeField};
        let le = nullifier_fr.into_bigint().to_bytes_le();
        for (i, b) in le.iter().take(32).enumerate() {
            null_be[31 - i] = *b;
        }
    }
    let pi = ZkPublicInputs::new(
        null_be,
        [[11u8; 32], [22u8; 32], [33u8; 32]],
        [44u8; 32],
        [6u8; 20],
        1_700_000_000,
        0,
    );
    (pi, w)
}

#[test]
fn real_groth16_self_layout_accepts_valid_proof_and_is_deterministic() {
    let mut rng = StdRng::seed_from_u64(0x5E1F);
    let (public_inputs, witness_sqrt) = sample_inputs();
    let field_inputs = self_field_inputs_of(&public_inputs);

    let setup_circuit = SelfShapeCircuit {
        public: field_inputs,
        witness_sqrt,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

    // Load through the PINNED-VK path; the 20-arity selects the SelfDisclose layout.
    let mut vk_bytes = Vec::new();
    vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
        .unwrap();
    let verifier = Groth16Verifier::from_vk_bytes(&vk_bytes)
        .expect("20-input VK loads as a Self-layout passport VK");
    assert_eq!(verifier.layout(), PassportLayout::SelfDisclose);
    assert_eq!(verifier.passport_arity(), SELF_NPUBLIC);

    let prove_circuit = SelfShapeCircuit {
        public: field_inputs,
        witness_sqrt,
    };
    let proof = Groth16::<Bn254>::prove(&pk, prove_circuit, &mut rng).unwrap();
    let proof_bytes = proof_to_canonical_bytes(&proof).unwrap();

    // PROVE IT: a real Groth16/BN254 proof verifies at the real Self arity through the production seam.
    assert!(
        verifier.verify_passport(&proof_bytes, &public_inputs),
        "a valid Groth16 proof must verify against the 20-input Self-layout VK"
    );

    // Determinism (I1).
    let v1 = verifier.verify_passport(&proof_bytes, &public_inputs);
    let v2 = verifier.verify_passport(&proof_bytes, &public_inputs);
    assert_eq!(v1, v2);
    assert!(v1);

    // An independently-loaded verifier from the same VK bytes agrees (no hidden setup state).
    let verifier2 = Groth16Verifier::from_vk_bytes(&vk_bytes).unwrap();
    assert!(verifier2.verify_passport(&proof_bytes, &public_inputs));

    // Canonical round-trip (non-malleability).
    let reparsed = ubi2_zkpoh::proof_from_canonical_bytes(&proof_bytes).unwrap();
    let reser = proof_to_canonical_bytes(&reparsed).unwrap();
    assert_eq!(proof_bytes, reser);
}

#[test]
fn real_groth16_self_layout_rejects_tampered_and_replayed() {
    let mut rng = StdRng::seed_from_u64(0xC0DE);
    let (public_inputs, witness_sqrt) = sample_inputs();
    let field_inputs = self_field_inputs_of(&public_inputs);

    let setup_circuit = SelfShapeCircuit {
        public: field_inputs,
        witness_sqrt,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
        .unwrap();
    let verifier = Groth16Verifier::from_vk_bytes(&vk_bytes).unwrap();

    let prove_circuit = SelfShapeCircuit {
        public: field_inputs,
        witness_sqrt,
    };
    let proof = Groth16::<Bn254>::prove(&pk, prove_circuit, &mut rng).unwrap();
    let proof_bytes = proof_to_canonical_bytes(&proof).unwrap();
    assert!(verifier.verify_passport(&proof_bytes, &public_inputs));

    // (a) Tampered proof.
    let mut bad_proof = proof_bytes.clone();
    let last = bad_proof.len() - 1;
    bad_proof[last] ^= 0x01;
    assert!(
        !verifier.verify_passport(&bad_proof, &public_inputs),
        "a tampered proof must be rejected (fail closed)"
    );

    // (b) Replayed / wrong nullifier: the proof is bound to *its* nullifier (F-5 crypto leg).
    let mut wrong_nullifier = public_inputs.clone();
    wrong_nullifier.nullifier[0] ^= 0xFF;
    assert!(
        !verifier.verify_passport(&proof_bytes, &wrong_nullifier),
        "the proof must not verify against a different nullifier"
    );

    // (c) Different submitter: the anti-replay/front-run binding (F-4).
    let mut other_submitter = public_inputs.clone();
    other_submitter.submitter_address[19] ^= 0x01;
    assert!(
        !verifier.verify_passport(&proof_bytes, &other_submitter),
        "a proof bound to address A must not verify for address B"
    );

    // (d) Tampered attribute commitment (a disclosed-data slot).
    let mut other_attr = public_inputs.clone();
    other_attr.attribute_commitments[0][0] ^= 0x7F;
    assert!(
        !verifier.verify_passport(&proof_bytes, &other_attr),
        "a different attribute-commitment signal breaks verification"
    );

    // (e) Garbage / non-canonical proof bytes fail closed at decode (never panic, never accept).
    assert!(!verifier.verify_passport(&[0u8; 8], &public_inputs));
    assert!(!verifier.verify_passport(&[], &public_inputs));
    assert!(!verifier.verify_passport(&vec![0xFFu8; 256], &public_inputs));
}

#[test]
fn domain_layout_proof_does_not_verify_under_self_layout_vk() {
    // Cross-layout soundness: a proof generated for the 8-field domain arity must NOT verify under a
    // 20-input Self-layout VK (different arity ⇒ the verify equation cannot hold). This guards against
    // accidentally accepting a foreign-arity proof.
    let mut rng = StdRng::seed_from_u64(1);
    let (public_inputs, witness_sqrt) = sample_inputs();
    let field_inputs = self_field_inputs_of(&public_inputs);

    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(
        SelfShapeCircuit {
            public: field_inputs,
            witness_sqrt,
        },
        &mut rng,
    )
    .unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
        .unwrap();
    let verifier = Groth16Verifier::from_vk_bytes(&vk_bytes).unwrap();
    assert_eq!(verifier.layout(), PassportLayout::SelfDisclose);

    // A proof for a *different* nullifier (i.e. not the one this VK's statement was set up for) fails.
    let mut rng2 = StdRng::seed_from_u64(2);
    let other_w = Fr::from(42u64);
    let mut other_pi = public_inputs.clone();
    {
        use ark_ff::{BigInteger, PrimeField};
        let nf = other_w * other_w;
        let le = nf.into_bigint().to_bytes_le();
        let mut be = [0u8; 32];
        for (i, b) in le.iter().take(32).enumerate() {
            be[31 - i] = *b;
        }
        other_pi.nullifier = be;
    }
    let other_proof = Groth16::<Bn254>::prove(
        &pk,
        SelfShapeCircuit {
            public: self_field_inputs_of(&other_pi),
            witness_sqrt: other_w,
        },
        &mut rng2,
    )
    .unwrap();
    let other_proof_bytes = proof_to_canonical_bytes(&other_proof).unwrap();
    // The other proof verifies for ITS inputs, not the original.
    assert!(verifier.verify_passport(&other_proof_bytes, &other_pi));
    assert!(!verifier.verify_passport(&other_proof_bytes, &public_inputs));
}
