//! Real-curve soundness + determinism test (spec §6.3, ADR-0005 D2 — "a focused real-curve test guards
//! soundness"). This is the test that proves the *actual* arkworks Groth16/BN254 verifier behind the
//! `ZkPassportVerifier` seam, not the mock:
//!
//!   * **PROVE IT (validity):** generate a genuine Groth16 proof for a small circuit whose public-input
//!     arity is *exactly* our pinned §3.5 layout (8 inputs), then verify it through `Groth16Verifier`.
//!   * **Determinism (I1):** two independent verifications of the same `(vk, proof, public_inputs)`
//!     agree, and the proof + VK round-trip canonical bytes byte-for-byte (the cross-node guarantee).
//!   * **Soundness (F-3/F-4):** a tampered proof, a tampered public input, a non-canonical/garbage proof
//!     blob, and a wrong-arity VK all fail closed (`false`), never silently accept.
//!
//! The circuit here is a *stand-in* for the real OpenPassport/Self passive-authentication circuit — it
//! is deliberately small (the de-risk is the verifier + the wire format, not the PA-in-ZK gadget). It
//! binds all 8 public inputs into the constraint system exactly as the real circuit will, so the arity
//! pin, the canonical encodings, and the public-input ordering are all exercised against the real curve.
//! The real-circuit binding (adapt OpenPassport's public outputs, re-run Phase-2) is the documented next
//! step; it changes the VK bytes + the circuit, never this crate's verifier code.

use ark_bn254::{Bn254, Fr};
use ark_groth16::Groth16;
use ark_relations::lc;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::{CanonicalSerialize, Compress};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};

use ubi2_zkpoh::{
    proof_to_canonical_bytes, Groth16Verifier, PublicInputs, ZkPassportVerifier, ZkPublicInputs,
    NUM_PUBLIC_INPUTS,
};

/// Field-element vector for a runtime `ZkPublicInputs` (the single canonical mapping the verifier uses
/// internally), exposed here so the test circuit is fed the *same* 8 inputs the verifier will check.
fn field_inputs_of(pi: &ZkPublicInputs) -> [Fr; NUM_PUBLIC_INPUTS] {
    PublicInputs::from_runtime(pi).to_field_elements()
}

/// A small circuit with **exactly** [`NUM_PUBLIC_INPUTS`] (8) public inputs — the §3.5 arity — that
/// proves knowledge of a private witness `w` such that `w * w == nullifier` (i.e. `nullifier` is a
/// quadratic residue with a known root), while pinning the other 7 public inputs into the system so they
/// are bound to the statement. This is a faithful *shape* stand-in: 8 ordered public inputs, a private
/// witness, and a multiplicative constraint — the same anatomy as a passive-authentication circuit
/// (private signature/MRZ witnesses, public nullifier + commitments), at a size that runs fast in CI.
struct PassportShapeCircuit {
    /// The 8 public inputs in the canonical §3.5 order (the verifier feeds these same 8 to verify).
    public: [Fr; NUM_PUBLIC_INPUTS],
    /// The private witness: a square root of `public[0]` (the nullifier). Never revealed.
    witness_sqrt: Fr,
}

impl ConstraintSynthesizer<Fr> for PassportShapeCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // Allocate all 8 public inputs in canonical order (input index 0 == nullifier, ...). The Groth16
        // verifier consumes them in this same order, so a permutation is a different statement.
        let mut input_vars = Vec::with_capacity(NUM_PUBLIC_INPUTS);
        for v in self.public.iter() {
            let val = *v;
            input_vars.push(cs.new_input_variable(|| Ok(val))?);
        }
        // The private witness `w`.
        let w_var = cs.new_witness_variable(|| Ok(self.witness_sqrt))?;
        // Enforce `w * w == nullifier` (public input 0). This is the binding constraint: a proof exists
        // iff the prover knows a square root of the nullifier. The other 7 public inputs are bound into
        // the system by being allocated as inputs (a proof commits to all of them via the public-input
        // MSM), so tampering with any of them on the verify side breaks the pairing equation.
        let nullifier_var = input_vars[0];
        cs.enforce_constraint(lc!() + w_var, lc!() + w_var, lc!() + nullifier_var)?;
        // Tie the remaining public inputs into a constraint so the QAP genuinely depends on them (a `* 1`
        // identity). Without referencing them in a constraint, arkworks would still include them in the
        // public-input MSM, but we make the dependence explicit to mirror the real circuit.
        let one = ark_relations::r1cs::Variable::One;
        for &iv in input_vars.iter().skip(1) {
            cs.enforce_constraint(lc!() + iv, lc!() + one, lc!() + iv)?;
        }
        Ok(())
    }
}

/// Build a canonical 8-input public vector and a circuit instance whose witness is a true square root of
/// the chosen nullifier, so a valid proof exists. We pick `nullifier = w^2` for a known `w`.
fn sample_inputs() -> (ZkPublicInputs, Fr) {
    // Pick a small witness and set nullifier = w^2 so the constraint is satisfiable.
    let w = Fr::from(123_456_789u64);
    let nullifier_fr = w * w;
    // Serialize nullifier_fr to its 32-byte big-endian form so the canonical mapping re-derives the
    // *same* field element (round-trips through `to_field_elements`).
    let mut null_be = [0u8; 32];
    {
        // Fr -> big-endian 32 bytes via its little-endian BigInt, reversed.
        use ark_ff::{BigInteger, PrimeField};
        let le = nullifier_fr.into_bigint().to_bytes_le();
        for (i, b) in le.iter().take(32).enumerate() {
            null_be[31 - i] = *b;
        }
    }
    let pi = ZkPublicInputs::new(
        null_be,
        [[2u8; 32], [3u8; 32], [4u8; 32]],
        [5u8; 32],
        [6u8; 20],
        1_700_000_000,
        0,
    );
    (pi, w)
}

#[test]
fn real_groth16_verifier_accepts_valid_proof_and_is_deterministic() {
    let mut rng = StdRng::seed_from_u64(0xC0FFEE);
    let (public_inputs, witness_sqrt) = sample_inputs();
    let field_inputs = field_inputs_of(&public_inputs);

    // Trusted setup for this exact circuit shape (the test's stand-in for the genesis ceremony).
    let setup_circuit = PassportShapeCircuit {
        public: field_inputs,
        witness_sqrt,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();

    // Serialize the VK canonically and load it through the PINNED-VK path (exercises the arity pin +
    // canonical (de)serialize the node uses at genesis).
    let mut vk_bytes = Vec::new();
    vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
        .unwrap();
    let verifier =
        Groth16Verifier::from_vk_bytes(&vk_bytes).expect("8-input VK loads + arity pin passes");
    assert_eq!(verifier.passport_arity(), NUM_PUBLIC_INPUTS);

    // Generate a genuine proof.
    let prove_circuit = PassportShapeCircuit {
        public: field_inputs,
        witness_sqrt,
    };
    let proof = Groth16::<Bn254>::prove(&pk, prove_circuit, &mut rng).unwrap();
    let proof_bytes = proof_to_canonical_bytes(&proof).unwrap();

    // PROVE IT: the real verifier accepts the valid proof.
    assert!(
        verifier.verify_passport(&proof_bytes, &public_inputs),
        "valid Groth16 proof must verify against the pinned VK"
    );

    // DETERMINISM (I1): two independent verifications of the same inputs agree, bit-for-bit.
    let v1 = verifier.verify_passport(&proof_bytes, &public_inputs);
    let v2 = verifier.verify_passport(&proof_bytes, &public_inputs);
    assert_eq!(
        v1, v2,
        "two independent verifications must agree (determinism)"
    );
    assert!(v1);

    // A freshly-loaded verifier from the same VK bytes agrees too (no hidden setup state).
    let verifier2 = Groth16Verifier::from_vk_bytes(&vk_bytes).unwrap();
    assert!(
        verifier2.verify_passport(&proof_bytes, &public_inputs),
        "an independently-loaded verifier reaches the same boolean"
    );

    // Canonical round-trip: re-serializing the decoded proof yields byte-identical bytes (the
    // single-encoding-per-element / non-malleability guarantee).
    let reparsed = ubi2_zkpoh::proof_from_canonical_bytes(&proof_bytes).unwrap();
    let reser = proof_to_canonical_bytes(&reparsed).unwrap();
    assert_eq!(
        proof_bytes, reser,
        "proof bytes are canonical (round-trip stable)"
    );
}

#[test]
fn real_groth16_verifier_rejects_tampered_proof_and_inputs() {
    let mut rng = StdRng::seed_from_u64(0xBEEF);
    let (public_inputs, witness_sqrt) = sample_inputs();
    let field_inputs = field_inputs_of(&public_inputs);

    let setup_circuit = PassportShapeCircuit {
        public: field_inputs,
        witness_sqrt,
    };
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(setup_circuit, &mut rng).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
        .unwrap();
    let verifier = Groth16Verifier::from_vk_bytes(&vk_bytes).unwrap();

    let prove_circuit = PassportShapeCircuit {
        public: field_inputs,
        witness_sqrt,
    };
    let proof = Groth16::<Bn254>::prove(&pk, prove_circuit, &mut rng).unwrap();
    let proof_bytes = proof_to_canonical_bytes(&proof).unwrap();
    assert!(verifier.verify_passport(&proof_bytes, &public_inputs));

    // (a) SOUNDNESS — tampered proof: flip a byte. Either it fails canonical decode (off-curve) or the
    // pairing equation fails — both ⇒ false. Never an accept.
    let mut bad_proof = proof_bytes.clone();
    let last = bad_proof.len() - 1;
    bad_proof[last] ^= 0x01;
    assert!(
        !verifier.verify_passport(&bad_proof, &public_inputs),
        "a tampered proof must be rejected (fail closed)"
    );

    // (b) SOUNDNESS — tampered public input: change the nullifier. The valid proof was generated for the
    // original nullifier; a different one breaks the public-input MSM ⇒ pairing fails ⇒ false. This is
    // the F-4 anti-replay leg in miniature: the proof is bound to *its* public inputs.
    let mut tampered_pi = public_inputs.clone();
    tampered_pi.nullifier[0] ^= 0xFF;
    assert!(
        !verifier.verify_passport(&proof_bytes, &tampered_pi),
        "the proof must not verify against a different public-input vector"
    );

    // (c) Changing the SUBMITTER (the address-binding public input) also breaks verification — the
    // anti-replay/front-run guarantee at the crypto layer (a copied proof verifies false for another
    // sender, F-4).
    let mut other_submitter = public_inputs.clone();
    other_submitter.submitter_address[19] ^= 0x01;
    assert!(
        !verifier.verify_passport(&proof_bytes, &other_submitter),
        "a proof bound to address A must not verify for address B"
    );

    // (d) Garbage / non-canonical proof bytes fail closed at decode (never panic, never accept).
    assert!(!verifier.verify_passport(&[0u8; 8], &public_inputs));
    assert!(!verifier.verify_passport(&[], &public_inputs));
    assert!(!verifier.verify_passport(&vec![0xFFu8; 256], &public_inputs));
}

#[test]
fn wrong_arity_vk_is_rejected_at_load() {
    // A VK from a circuit with a DIFFERENT public-input count must not load as a passport VK — the arity
    // pin (spec §3.5) prevents mis-applying a foreign circuit's VK.
    let mut rng = StdRng::seed_from_u64(7);

    // A trivial 1-public-input circuit: prove knowledge of w with w*w == x.
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
    let w = Fr::from(9u64);
    let (_, vk) =
        Groth16::<Bn254>::circuit_specific_setup(OneInput { x: w * w, w }, &mut rng).unwrap();
    let mut vk_bytes = Vec::new();
    vk.serialize_with_mode(&mut vk_bytes, Compress::Yes)
        .unwrap();

    // The bytes are a perfectly valid VK — but for arity 1, not 8. The pinned loader rejects it.
    assert!(
        Groth16Verifier::from_vk_bytes(&vk_bytes).is_none(),
        "a 1-input VK must be rejected by the 8-input arity pin"
    );
}
