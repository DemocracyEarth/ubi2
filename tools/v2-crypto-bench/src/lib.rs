//! Reproducible Stage-1 circuit-authentication spike for ubi2 ZK Identity v2.
//!
//! This is measurement code, not a production circuit. It deliberately lives
//! in an isolated Cargo workspace so none of its prover or gadget dependencies
//! can enter `ubi2-zkpoh`'s consensus verifier graph.

use ark_bn254::{Bn254, Fr as CircuitField};
use ark_crypto_primitives::sponge::{
    constraints::CryptographicSpongeVar,
    poseidon::{
        constraints::PoseidonSpongeVar, find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge,
    },
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ec::{AdditiveGroup, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{constraints::EdwardsVar, EdwardsProjective, Fr as JubjubScalar};
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::Groth16;
use ark_r1cs_std::{
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
    prelude::*,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::CanonicalSerialize;
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
use std::time::Instant;

mod status_registry;

pub use status_registry::{
    refresh_status_witness, StatusActivation, StatusCheckpoint, StatusRegistry,
    StatusRegistryDelta, StatusRegistryError, StatusWitness, STATUS_REGISTRY_DELTA_MAX_JSON_BYTES,
    STATUS_REGISTRY_DELTA_SCHEMA,
};

/// Native field used by the Stage-1 status-registry prototype.
pub type StatusField = CircuitField;

// The ABI has 13 logical fields. Its three bytes32 fields are split into two
// lossless 128-bit limbs, so the circuit commitment absorbs 16 field elements.
pub const CREDENTIAL_ELEMENT_COUNT: usize = 16;
pub const NULLIFIER_FIELD_COUNT: usize = 6;
pub const REGISTRY_DEPTH: usize = 32;
pub const REGISTRY_DEPTH_PROFILES: [usize; 4] = [32, 64, 96, 128];
pub const REGISTRY_DEPTH_CONSTRAINTS: [usize; 4] = [21_723, 37_147, 52_571, 67_995];
const CREDENTIAL_HOLDER_SECRET_INDEX: usize = 7;
const CREDENTIAL_ISSUER_KEY_ID_HIGH_INDEX: usize = 3;
const CREDENTIAL_ISSUER_KEY_ID_LOW_INDEX: usize = 4;
const CREDENTIAL_STATUS_ID_HIGH_INDEX: usize = 5;
const CREDENTIAL_STATUS_ID_LOW_INDEX: usize = 6;
const NULLIFIER_HOLDER_SECRET_INDEX: usize = 3;
const BYTES32_LIMB_BITS: usize = 128;

// Deliberately pinned by CI. A gadget or relation change must update the
// measured report and these budgets in the same reviewed change.
pub const ISSUER_SIGNATURE_CONSTRAINTS: usize = 13_528;
pub const ACTIVE_REGISTRY_CONSTRAINTS: usize = 21_723;
pub const HYBRID_CONSTRAINTS: usize = 31_843;

const CREDENTIAL_DOMAIN: u64 = 1;
const NULLIFIER_DOMAIN: u64 = 2;
const REGISTRY_NODE_DOMAIN: u64 = 3;
const SIGNATURE_CHALLENGE_DOMAIN: u64 = 4;
const ISSUER_KEY_DOMAIN: u64 = 5;
const STATUS_LEAF_DOMAIN: u64 = 6;
const STATUS_INDEX_DOMAIN: u64 = 7;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authentication {
    IssuerSignature,
    ActiveRegistry,
    SignatureAndRegistry,
}

impl Authentication {
    fn includes_signature(self) -> bool {
        matches!(self, Self::IssuerSignature | Self::SignatureAndRegistry)
    }

    fn includes_registry(self) -> bool {
        matches!(self, Self::ActiveRegistry | Self::SignatureAndRegistry)
    }
}

#[derive(Clone)]
pub struct SpikeCircuit {
    authentication: Authentication,
    credential_elements: [CircuitField; CREDENTIAL_ELEMENT_COUNT],
    nullifier_fields: [CircuitField; NULLIFIER_FIELD_COUNT],
    expected_nullifier: CircuitField,
    issuer_public_key: EdwardsProjective,
    issuer_key_id: [CircuitField; 2],
    signature_commitment: EdwardsProjective,
    signature_response: JubjubScalar,
    registry_siblings: Vec<CircuitField>,
    expected_registry_root: [CircuitField; 2],
}

#[derive(Debug, Serialize)]
pub struct SuiteReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub curve: &'static str,
    pub poseidon_profile: &'static str,
    pub registry_depth: usize,
    pub proof_measurements_enabled: bool,
    pub build_profile: &'static str,
    pub target_os: &'static str,
    pub target_arch: &'static str,
    pub results: Vec<CandidateReport>,
}

#[derive(Debug, Serialize)]
pub struct CandidateReport {
    pub authentication: Authentication,
    pub constraints: usize,
    pub public_inputs: usize,
    pub witness_variables: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setup_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prove_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verify_ms: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verifying_key_bytes: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof_verified: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct RegistryDepthSuiteReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub curve: &'static str,
    pub poseidon_profile: &'static str,
    pub proof_measurements_enabled: bool,
    pub build_profile: &'static str,
    pub target_os: &'static str,
    pub target_arch: &'static str,
    pub results: Vec<RegistryDepthCandidateReport>,
}

#[derive(Debug, Serialize)]
pub struct RegistryDepthCandidateReport {
    pub depth: usize,
    #[serde(flatten)]
    pub measurement: CandidateReport,
}

struct SignatureWitness {
    issuer_public_key: EdwardsProjective,
    issuer_key_id: [FpVar<CircuitField>; 2],
    signature_commitment: EdwardsProjective,
    signature_response: JubjubScalar,
}

impl SpikeCircuit {
    pub fn fixture(authentication: Authentication) -> Self {
        Self::fixture_with_registry_depth(authentication, REGISTRY_DEPTH)
    }

    pub fn fixture_with_registry_depth(
        authentication: Authentication,
        registry_depth: usize,
    ) -> Self {
        assert!(registry_depth > 0, "registry depth must be non-zero");
        assert!(
            registry_depth <= CircuitField::MODULUS_BIT_SIZE as usize,
            "registry depth exceeds the status-index field"
        );
        let poseidon = poseidon_config();
        let mut credential_elements =
            std::array::from_fn(|index| CircuitField::from((index as u64 + 1) * 1_000_003));
        let mut nullifier_fields =
            std::array::from_fn(|index| CircuitField::from((index as u64 + 1) * 9_000_001));
        nullifier_fields[NULLIFIER_HOLDER_SECRET_INDEX] =
            credential_elements[CREDENTIAL_HOLDER_SECRET_INDEX];
        let expected_nullifier =
            poseidon_native(&poseidon, NULLIFIER_DOMAIN, nullifier_fields.as_slice());

        let issuer_secret = JubjubScalar::from(4_242_424u64);
        let issuer_public_key = EdwardsProjective::generator() * issuer_secret;
        let issuer_key_digest = issuer_key_digest_native(&poseidon, &issuer_public_key);
        let issuer_key_id = split_field_to_u128_limbs(issuer_key_digest);
        credential_elements[CREDENTIAL_ISSUER_KEY_ID_HIGH_INDEX] = issuer_key_id[0];
        credential_elements[CREDENTIAL_ISSUER_KEY_ID_LOW_INDEX] = issuer_key_id[1];
        let credential_commitment =
            poseidon_native(&poseidon, CREDENTIAL_DOMAIN, credential_elements.as_slice());
        let signature_nonce = JubjubScalar::from(8_181_818u64);
        let signature_commitment = EdwardsProjective::generator() * signature_nonce;
        let challenge = signature_challenge_native(
            &poseidon,
            &signature_commitment,
            &issuer_public_key,
            credential_commitment,
        );
        let challenge_scalar = jubjub_scalar_from_circuit_field(challenge);
        let signature_response = signature_nonce - challenge_scalar * issuer_secret;

        let registry_siblings = (0..registry_depth)
            .map(|index| CircuitField::from((index as u64 + 1) * 7_000_001))
            .collect::<Vec<_>>();
        let status_id = [
            credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX],
            credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX],
        ];
        let active_leaf = active_status_leaf_native(&poseidon, status_id, credential_commitment);
        let registry_directions =
            status_path_directions_native(&poseidon, status_id, registry_depth);
        let expected_registry_root = split_field_to_u128_limbs(merkle_root_native(
            &poseidon,
            active_leaf,
            &registry_siblings,
            &registry_directions,
        ));

        Self {
            authentication,
            credential_elements,
            nullifier_fields,
            expected_nullifier,
            issuer_public_key,
            issuer_key_id,
            signature_commitment,
            signature_response,
            registry_siblings,
            expected_registry_root,
        }
    }

    #[cfg(test)]
    fn recompute_registry_root(&mut self) {
        let poseidon = poseidon_config();
        let credential_commitment = poseidon_native(
            &poseidon,
            CREDENTIAL_DOMAIN,
            self.credential_elements.as_slice(),
        );
        let status_id = [
            self.credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX],
            self.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX],
        ];
        let active_leaf = active_status_leaf_native(&poseidon, status_id, credential_commitment);
        let directions =
            status_path_directions_native(&poseidon, status_id, self.registry_siblings.len());
        self.expected_registry_root = split_field_to_u128_limbs(merkle_root_native(
            &poseidon,
            active_leaf,
            &self.registry_siblings,
            &directions,
        ));
    }

    pub fn authentication(&self) -> Authentication {
        self.authentication
    }

    pub fn registry_depth(&self) -> usize {
        self.registry_siblings.len()
    }

    pub fn public_inputs(&self) -> Vec<CircuitField> {
        let mut inputs = vec![self.expected_nullifier];
        inputs.extend_from_slice(&self.issuer_key_id);
        if self.authentication.includes_registry() {
            inputs.extend_from_slice(&self.expected_registry_root);
        }
        inputs
    }

    #[cfg(test)]
    fn tamper_signature(&mut self) {
        self.signature_response += JubjubScalar::from(1u64);
    }

    #[cfg(test)]
    fn tamper_issuer_key_id(&mut self) {
        self.issuer_key_id[1] += CircuitField::from(1u64);
    }

    #[cfg(test)]
    fn make_issuer_key_id_limb_wide(&mut self) {
        let wide_limb = CircuitField::from_be_bytes_mod_order(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        self.issuer_key_id[0] = wide_limb;
        self.credential_elements[CREDENTIAL_ISSUER_KEY_ID_HIGH_INDEX] = wide_limb;
    }

    #[cfg(test)]
    fn make_status_id_limb_wide(&mut self) {
        self.credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX] =
            CircuitField::from_be_bytes_mod_order(&[
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ]);
    }

    #[cfg(test)]
    fn replace_issuer_key(&mut self) {
        self.issuer_public_key = EdwardsProjective::generator() * JubjubScalar::from(9_999_991u64);
    }

    #[cfg(test)]
    fn tamper_registry(&mut self) {
        let middle = self.registry_siblings.len() / 2;
        self.registry_siblings[middle] += CircuitField::from(1u64);
    }

    #[cfg(test)]
    fn rotate_unrelated_registry_leaf(&mut self) {
        let poseidon = poseidon_config();
        let status_id = [
            self.credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX],
            self.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX],
        ];
        let directions =
            status_path_directions_native(&poseidon, status_id, self.registry_siblings.len());
        let changed_index = directions
            .iter()
            .position(|current_is_right| !current_is_right)
            .expect("fixture path has a sibling leaf to rotate");
        self.registry_siblings[changed_index] += CircuitField::from(1u64);
        self.recompute_registry_root();
    }

    #[cfg(test)]
    fn revoke_active_credential(&mut self) {
        let poseidon = poseidon_config();
        let status_id = [
            self.credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX],
            self.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX],
        ];
        let directions =
            status_path_directions_native(&poseidon, status_id, self.registry_siblings.len());
        self.expected_registry_root = split_field_to_u128_limbs(merkle_root_native(
            &poseidon,
            CircuitField::from(0u64),
            &self.registry_siblings,
            &directions,
        ));
    }

    #[cfg(test)]
    fn alias_registry_root_by_field_modulus(&mut self) {
        let mut encoded = [0u8; 32];
        for (limb_index, limb) in self.expected_registry_root.iter().enumerate() {
            let bytes = limb.into_bigint().to_bytes_be();
            encoded[limb_index * 16..(limb_index + 1) * 16]
                .copy_from_slice(&bytes[bytes.len() - 16..]);
        }
        let modulus = CircuitField::MODULUS.to_bytes_be();
        let mut carry = 0u16;
        for index in (0..32).rev() {
            let sum = encoded[index] as u16 + modulus[index] as u16 + carry;
            encoded[index] = sum as u8;
            carry = sum >> 8;
        }
        assert_eq!(carry, 0, "two BN254 scalars fit in bytes32");
        self.expected_registry_root = [
            CircuitField::from_be_bytes_mod_order(&encoded[..16]),
            CircuitField::from_be_bytes_mod_order(&encoded[16..]),
        ];
    }

    #[cfg(test)]
    fn tamper_credential(&mut self) {
        self.credential_elements[CREDENTIAL_ELEMENT_COUNT / 2] += CircuitField::from(1u64);
    }

    #[cfg(test)]
    fn tamper_holder_secret(&mut self) {
        self.credential_elements[CREDENTIAL_HOLDER_SECRET_INDEX] += CircuitField::from(1u64);
    }

    #[cfg(test)]
    fn tamper_nullifier_preimage(&mut self) {
        self.nullifier_fields[NULLIFIER_HOLDER_SECRET_INDEX + 1] += CircuitField::from(1u64);
    }
}

impl ConstraintSynthesizer<CircuitField> for SpikeCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let poseidon = poseidon_config();
        let credential_vars = self
            .credential_elements
            .iter()
            .map(|value| FpVar::new_witness(cs.clone(), || Ok(*value)))
            .collect::<Result<Vec<_>, _>>()?;
        let credential_commitment = poseidon_gadget(
            cs.clone(),
            &poseidon,
            CREDENTIAL_DOMAIN,
            credential_vars.as_slice(),
        )?;

        let nullifier_vars = self
            .nullifier_fields
            .iter()
            .enumerate()
            .map(|(index, value)| {
                if index == NULLIFIER_HOLDER_SECRET_INDEX {
                    Ok(credential_vars[CREDENTIAL_HOLDER_SECRET_INDEX].clone())
                } else {
                    FpVar::new_witness(cs.clone(), || Ok(*value))
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        let computed_nullifier = poseidon_gadget(
            cs.clone(),
            &poseidon,
            NULLIFIER_DOMAIN,
            nullifier_vars.as_slice(),
        )?;
        let public_nullifier = FpVar::new_input(cs.clone(), || Ok(self.expected_nullifier))?;
        computed_nullifier.enforce_equal(&public_nullifier)?;

        let public_issuer_key_id = [
            FpVar::new_input(cs.clone(), || Ok(self.issuer_key_id[0]))?,
            FpVar::new_input(cs.clone(), || Ok(self.issuer_key_id[1]))?,
        ];
        // Signature relations reconstruct these limbs into the computed key
        // digest below. Registry-only authentication still needs explicit limb
        // bounds because it has no private issuer key to derive that digest.
        if !self.authentication.includes_signature() {
            enforce_u128_limb(&public_issuer_key_id[0])?;
            enforce_u128_limb(&public_issuer_key_id[1])?;
        }
        credential_vars[CREDENTIAL_ISSUER_KEY_ID_HIGH_INDEX]
            .enforce_equal(&public_issuer_key_id[0])?;
        credential_vars[CREDENTIAL_ISSUER_KEY_ID_LOW_INDEX]
            .enforce_equal(&public_issuer_key_id[1])?;

        if self.authentication.includes_signature() {
            enforce_signature(
                cs.clone(),
                &poseidon,
                &credential_commitment,
                SignatureWitness {
                    issuer_public_key: self.issuer_public_key,
                    issuer_key_id: public_issuer_key_id,
                    signature_commitment: self.signature_commitment,
                    signature_response: self.signature_response,
                },
            )?;
        }

        if self.authentication.includes_registry() {
            enforce_registry_membership(
                cs,
                &poseidon,
                credential_commitment,
                credential_vars[CREDENTIAL_STATUS_ID_HIGH_INDEX].clone(),
                credential_vars[CREDENTIAL_STATUS_ID_LOW_INDEX].clone(),
                &self.registry_siblings,
                self.expected_registry_root,
            )?;
        }

        Ok(())
    }
}

pub fn run_suite(with_proofs: bool) -> Result<SuiteReport, SynthesisError> {
    let mut results = Vec::new();
    for authentication in [
        Authentication::IssuerSignature,
        Authentication::ActiveRegistry,
        Authentication::SignatureAndRegistry,
    ] {
        results.push(measure_candidate(
            SpikeCircuit::fixture(authentication),
            with_proofs,
        )?);
    }

    Ok(SuiteReport {
        schema: "org.proofofhumanity.v2-crypto-benchmark/1",
        warning: "research harness only; not a production circuit or cryptographic ratification",
        curve: "Groth16/BN254 with Baby-Jubjub authentication model",
        poseidon_profile: "width=3 rate=2 capacity=1 alpha=5 full=8 partial=57 skip_matrices=0",
        registry_depth: REGISTRY_DEPTH,
        proof_measurements_enabled: with_proofs,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        results,
    })
}

pub fn run_registry_depth_suite(
    with_proofs: bool,
) -> Result<RegistryDepthSuiteReport, SynthesisError> {
    let mut results = Vec::new();
    for depth in REGISTRY_DEPTH_PROFILES {
        let circuit =
            SpikeCircuit::fixture_with_registry_depth(Authentication::ActiveRegistry, depth);
        results.push(RegistryDepthCandidateReport {
            depth,
            measurement: measure_candidate(circuit, with_proofs)?,
        });
    }

    Ok(RegistryDepthSuiteReport {
        schema: "org.proofofhumanity.v2-registry-depth-benchmark/1",
        warning: "research harness only; depth profiles do not ratify a production accumulator",
        curve: "Groth16/BN254",
        poseidon_profile: "width=3 rate=2 capacity=1 alpha=5 full=8 partial=57 skip_matrices=0",
        proof_measurements_enabled: with_proofs,
        build_profile: if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        },
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        results,
    })
}

fn measure_candidate(
    circuit: SpikeCircuit,
    with_proofs: bool,
) -> Result<CandidateReport, SynthesisError> {
    let cs = ConstraintSystem::<CircuitField>::new_ref();
    circuit.clone().generate_constraints(cs.clone())?;
    cs.finalize();
    if !cs.is_satisfied()? {
        return Err(SynthesisError::Unsatisfiable);
    }

    let mut result = CandidateReport {
        authentication: circuit.authentication(),
        constraints: cs.num_constraints(),
        public_inputs: cs.num_instance_variables().saturating_sub(1),
        witness_variables: cs.num_witness_variables(),
        setup_ms: None,
        prove_ms: None,
        verify_ms: None,
        proof_bytes: None,
        verifying_key_bytes: None,
        proof_verified: None,
    };

    if with_proofs {
        let seed = match circuit.authentication() {
            Authentication::IssuerSignature => 0x51_47_4e,
            Authentication::ActiveRegistry => 0x52_45_47,
            Authentication::SignatureAndRegistry => 0x48_59_42,
        };
        let mut setup_rng = StdRng::seed_from_u64(seed);
        let setup_started = Instant::now();
        let (proving_key, verifying_key) =
            Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut setup_rng)?;
        result.setup_ms = Some(milliseconds(setup_started));

        let mut proof_rng = StdRng::seed_from_u64(seed ^ 0xa5_a5_a5);
        let prove_started = Instant::now();
        let proof = Groth16::<Bn254>::prove(&proving_key, circuit.clone(), &mut proof_rng)?;
        result.prove_ms = Some(milliseconds(prove_started));

        let processed = Groth16::<Bn254>::process_vk(&verifying_key)?;
        let verify_started = Instant::now();
        let verified = Groth16::<Bn254>::verify_with_processed_vk(
            &processed,
            &circuit.public_inputs(),
            &proof,
        )?;
        result.verify_ms = Some(milliseconds(verify_started));

        let mut proof_bytes = Vec::new();
        proof
            .serialize_compressed(&mut proof_bytes)
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        let mut verifying_key_bytes = Vec::new();
        verifying_key
            .serialize_compressed(&mut verifying_key_bytes)
            .map_err(|_| SynthesisError::Unsatisfiable)?;
        result.proof_bytes = Some(proof_bytes.len());
        result.verifying_key_bytes = Some(verifying_key_bytes.len());
        result.proof_verified = Some(verified);
    }

    Ok(result)
}

fn milliseconds(started: Instant) -> f64 {
    started.elapsed().as_secs_f64() * 1_000.0
}

fn poseidon_config() -> PoseidonConfig<CircuitField> {
    const FULL_ROUNDS: u64 = 8;
    const PARTIAL_ROUNDS: u64 = 57;
    const RATE: usize = 2;
    let (ark, mds) = find_poseidon_ark_and_mds::<CircuitField>(
        CircuitField::MODULUS_BIT_SIZE as u64,
        RATE,
        FULL_ROUNDS,
        PARTIAL_ROUNDS,
        0,
    );
    PoseidonConfig::new(
        FULL_ROUNDS as usize,
        PARTIAL_ROUNDS as usize,
        5,
        mds,
        ark,
        RATE,
        1,
    )
}

fn poseidon_native(
    config: &PoseidonConfig<CircuitField>,
    domain: u64,
    inputs: &[CircuitField],
) -> CircuitField {
    let mut sponge = PoseidonSponge::new(config);
    sponge.absorb(&CircuitField::from(domain));
    sponge.absorb(&inputs);
    sponge.squeeze_native_field_elements(1)[0]
}

fn poseidon_gadget(
    cs: ConstraintSystemRef<CircuitField>,
    config: &PoseidonConfig<CircuitField>,
    domain: u64,
    inputs: &[FpVar<CircuitField>],
) -> Result<FpVar<CircuitField>, SynthesisError> {
    let mut sponge = PoseidonSpongeVar::new(cs, config);
    sponge.absorb(&FpVar::Constant(CircuitField::from(domain)))?;
    sponge.absorb(&inputs)?;
    Ok(sponge.squeeze_field_elements(1)?[0].clone())
}

fn signature_challenge_native(
    config: &PoseidonConfig<CircuitField>,
    signature_commitment: &EdwardsProjective,
    issuer_public_key: &EdwardsProjective,
    credential_commitment: CircuitField,
) -> CircuitField {
    let r = signature_commitment.into_affine();
    let a = issuer_public_key.into_affine();
    poseidon_native(
        config,
        SIGNATURE_CHALLENGE_DOMAIN,
        &[r.x, r.y, a.x, a.y, credential_commitment],
    )
}

fn issuer_key_digest_native(
    config: &PoseidonConfig<CircuitField>,
    issuer_public_key: &EdwardsProjective,
) -> CircuitField {
    let key = issuer_public_key.into_affine();
    poseidon_native(config, ISSUER_KEY_DOMAIN, &[key.x, key.y])
}

fn split_field_to_u128_limbs(value: CircuitField) -> [CircuitField; 2] {
    let mut bytes = value.into_bigint().to_bytes_be();
    if bytes.len() < 32 {
        let mut padded = vec![0u8; 32 - bytes.len()];
        padded.extend_from_slice(&bytes);
        bytes = padded;
    }
    [
        CircuitField::from_be_bytes_mod_order(&bytes[..16]),
        CircuitField::from_be_bytes_mod_order(&bytes[16..]),
    ]
}

fn jubjub_scalar_from_circuit_field(value: CircuitField) -> JubjubScalar {
    JubjubScalar::from_be_bytes_mod_order(&value.into_bigint().to_bytes_be())
}

fn enforce_signature(
    cs: ConstraintSystemRef<CircuitField>,
    config: &PoseidonConfig<CircuitField>,
    credential_commitment: &FpVar<CircuitField>,
    witness: SignatureWitness,
) -> Result<(), SynthesisError> {
    let public_key = EdwardsVar::new_witness(cs.clone(), || Ok(witness.issuer_public_key))?;
    public_key.enforce_prime_order()?;
    public_key.is_zero()?.enforce_equal(&Boolean::FALSE)?;
    let computed_key_id = poseidon_gadget(
        cs.clone(),
        config,
        ISSUER_KEY_DOMAIN,
        &[public_key.x.clone(), public_key.y.clone()],
    )?;
    enforce_lossless_bytes32_limbs(
        &computed_key_id,
        &witness.issuer_key_id[0],
        &witness.issuer_key_id[1],
    )?;

    let r = EdwardsVar::new_witness(cs.clone(), || Ok(witness.signature_commitment))?;
    r.is_zero()?.enforce_equal(&Boolean::FALSE)?;
    let challenge = poseidon_gadget(
        cs.clone(),
        config,
        SIGNATURE_CHALLENGE_DOMAIN,
        &[
            r.x.clone(),
            r.y.clone(),
            public_key.x.clone(),
            public_key.y.clone(),
            credential_commitment.clone(),
        ],
    )?;

    let response = EmulatedFpVar::<JubjubScalar, CircuitField>::new_witness(cs, || {
        Ok(witness.signature_response)
    })?;
    let response_bits = response.to_bits_le()?;
    let mut response_times_generator = EdwardsVar::zero();
    let mut generator_power = EdwardsProjective::generator();
    let mut generator_powers = Vec::with_capacity(response_bits.len());
    for _ in 0..response_bits.len() {
        generator_powers.push(generator_power);
        generator_power.double_in_place();
    }
    response_times_generator
        .precomputed_base_scalar_mul_le(response_bits.iter().zip(generator_powers.iter()))?;

    let challenge_bits = challenge.to_bits_le()?;
    let challenge_times_key = public_key.scalar_mul_le(challenge_bits.iter())?;
    (response_times_generator + challenge_times_key).enforce_equal(&r)
}

fn enforce_lossless_bytes32_limbs(
    value: &FpVar<CircuitField>,
    high: &FpVar<CircuitField>,
    low: &FpVar<CircuitField>,
) -> Result<(), SynthesisError> {
    let (high_bits, _) = high.to_bits_le_with_top_bits_zero(BYTES32_LIMB_BITS)?;
    let (low_bits, _) = low.to_bits_le_with_top_bits_zero(BYTES32_LIMB_BITS)?;
    let mut reconstructed_bits = low_bits;
    reconstructed_bits.extend(high_bits);
    // `le_bits_to_fp` deliberately reduces values modulo the field. Reject
    // bytes32 encodings outside the canonical field range first, otherwise
    // `digest` and `digest + modulus` would satisfy the same equality.
    Boolean::enforce_in_field_le(&reconstructed_bits)?;
    let reconstructed = Boolean::le_bits_to_fp(&reconstructed_bits)?;
    reconstructed.enforce_equal(value)
}

fn enforce_u128_limb(value: &FpVar<CircuitField>) -> Result<(), SynthesisError> {
    let _ = value.to_bits_le_with_top_bits_zero(BYTES32_LIMB_BITS)?;
    Ok(())
}

fn merkle_root_native(
    config: &PoseidonConfig<CircuitField>,
    leaf: CircuitField,
    siblings: &[CircuitField],
    directions: &[bool],
) -> CircuitField {
    assert_eq!(siblings.len(), directions.len());
    siblings
        .iter()
        .zip(directions)
        .fold(leaf, |current, (sibling, current_is_right)| {
            let (left, right) = if *current_is_right {
                (*sibling, current)
            } else {
                (current, *sibling)
            };
            poseidon_native(config, REGISTRY_NODE_DOMAIN, &[left, right])
        })
}

fn enforce_registry_membership(
    cs: ConstraintSystemRef<CircuitField>,
    config: &PoseidonConfig<CircuitField>,
    credential_commitment: FpVar<CircuitField>,
    status_id_high: FpVar<CircuitField>,
    status_id_low: FpVar<CircuitField>,
    siblings: &[CircuitField],
    expected_root: [CircuitField; 2],
) -> Result<(), SynthesisError> {
    let _ = status_id_high.to_bits_le_with_top_bits_zero(BYTES32_LIMB_BITS)?;
    let _ = status_id_low.to_bits_le_with_top_bits_zero(BYTES32_LIMB_BITS)?;
    let mut current = poseidon_gadget(
        cs.clone(),
        config,
        STATUS_LEAF_DOMAIN,
        &[
            status_id_high.clone(),
            status_id_low.clone(),
            credential_commitment,
        ],
    )?;
    let path_digest = poseidon_gadget(
        cs.clone(),
        config,
        STATUS_INDEX_DOMAIN,
        &[status_id_high, status_id_low],
    )?;
    let path_bits = path_digest.to_bits_le()?;
    for (sibling, current_is_right) in siblings.iter().zip(path_bits.iter()) {
        let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling))?;
        let left = current_is_right.select(&sibling, &current)?;
        let right = current_is_right.select(&current, &sibling)?;
        current = poseidon_gadget(cs.clone(), config, REGISTRY_NODE_DOMAIN, &[left, right])?;
    }
    let public_root_high = FpVar::new_input(cs.clone(), || Ok(expected_root[0]))?;
    let public_root_low = FpVar::new_input(cs, || Ok(expected_root[1]))?;
    enforce_lossless_bytes32_limbs(&current, &public_root_high, &public_root_low)
}

fn active_status_leaf_native(
    config: &PoseidonConfig<CircuitField>,
    status_id: [CircuitField; 2],
    credential_commitment: CircuitField,
) -> CircuitField {
    poseidon_native(
        config,
        STATUS_LEAF_DOMAIN,
        &[status_id[0], status_id[1], credential_commitment],
    )
}

fn status_path_directions_native(
    config: &PoseidonConfig<CircuitField>,
    status_id: [CircuitField; 2],
    depth: usize,
) -> Vec<bool> {
    assert!(depth <= CircuitField::MODULUS_BIT_SIZE as usize);
    let digest = poseidon_native(config, STATUS_INDEX_DOMAIN, &status_id).into_bigint();
    (0..depth).map(|bit| digest.get_bit(bit)).collect()
}

fn status_path_index_native(
    config: &PoseidonConfig<CircuitField>,
    status_id: [CircuitField; 2],
) -> u32 {
    let digest = poseidon_native(config, STATUS_INDEX_DOMAIN, &status_id).into_bigint();
    (0..REGISTRY_DEPTH).fold(0u32, |index, bit| {
        index | (u32::from(digest.get_bit(bit)) << bit)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_candidate_relations_are_satisfied() {
        let report = run_suite(false).expect("all benchmark fixtures synthesize");
        assert_eq!(report.results.len(), 3);
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.constraints)
                .collect::<Vec<_>>(),
            [
                ISSUER_SIGNATURE_CONSTRAINTS,
                ACTIVE_REGISTRY_CONSTRAINTS,
                HYBRID_CONSTRAINTS,
            ],
            "constraint drift requires an explicit benchmark-report review"
        );
    }

    #[test]
    fn a_modified_issuer_signature_fails_closed() {
        let mut circuit = SpikeCircuit::fixture(Authentication::IssuerSignature);
        circuit.tamper_signature();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn issuer_key_id_is_losslessly_bound_to_the_private_key_coordinates() {
        for authentication in [
            Authentication::IssuerSignature,
            Authentication::SignatureAndRegistry,
        ] {
            let mut wrong_id = SpikeCircuit::fixture(authentication);
            wrong_id.tamper_issuer_key_id();
            let cs = ConstraintSystem::<CircuitField>::new_ref();
            wrong_id.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());

            let mut wrong_key = SpikeCircuit::fixture(authentication);
            wrong_key.replace_issuer_key();
            let cs = ConstraintSystem::<CircuitField>::new_ref();
            wrong_key.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());

            let mut wide_limb = SpikeCircuit::fixture(authentication);
            wide_limb.make_issuer_key_id_limb_wide();
            let cs = ConstraintSystem::<CircuitField>::new_ref();
            wide_limb.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn registry_authentication_binds_a_canonical_issuer_key_id() {
        let mut wrong_id = SpikeCircuit::fixture(Authentication::ActiveRegistry);
        wrong_id.tamper_issuer_key_id();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        wrong_id.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());

        let mut wide_limb = SpikeCircuit::fixture(Authentication::ActiveRegistry);
        wide_limb.make_issuer_key_id_limb_wide();
        wide_limb.recompute_registry_root();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        wide_limb.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn registry_authentication_rejects_a_non_canonical_status_id() {
        let mut circuit = SpikeCircuit::fixture(Authentication::ActiveRegistry);
        circuit.make_status_id_limb_wide();
        circuit.recompute_registry_root();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn a_modified_registry_path_fails_closed() {
        let mut circuit = SpikeCircuit::fixture(Authentication::ActiveRegistry);
        circuit.tamper_registry();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn revoked_active_leaf_fails_closed() {
        let mut circuit = SpikeCircuit::fixture(Authentication::ActiveRegistry);
        circuit.revoke_active_credential();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn active_root_rejects_a_modular_alias() {
        let mut circuit = SpikeCircuit::fixture(Authentication::ActiveRegistry);
        circuit.alias_registry_root_by_field_modulus();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn unrelated_leaf_update_rejects_a_stale_witness_and_accepts_a_refreshed_one() {
        let stale = SpikeCircuit::fixture(Authentication::ActiveRegistry);
        let previous_root = stale.expected_registry_root;
        let mut refreshed = stale.clone();
        refreshed.rotate_unrelated_registry_leaf();
        assert_ne!(refreshed.expected_registry_root, previous_root);

        let mut stale = stale;
        stale.expected_registry_root = refreshed.expected_registry_root;
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        stale.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        refreshed.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn operational_registry_witness_satisfies_the_exact_circuit_relation() {
        let mut circuit = SpikeCircuit::fixture(Authentication::ActiveRegistry);
        let poseidon = poseidon_config();
        let status_id = [
            circuit.credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX],
            circuit.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX],
        ];
        let credential_commitment = poseidon_native(
            &poseidon,
            CREDENTIAL_DOMAIN,
            circuit.credential_elements.as_slice(),
        );
        let mut registry = StatusRegistry::new();
        let activation = registry.activate(status_id, credential_commitment).unwrap();

        circuit.registry_siblings = activation.witness.siblings.to_vec();
        circuit.expected_registry_root = split_field_to_u128_limbs(activation.witness.root);
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.clone().generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        registry
            .activate(
                [CircuitField::from(0u64), CircuitField::from(42u64)],
                CircuitField::from(4_242u64),
            )
            .unwrap();
        let refreshed = refresh_status_witness(
            &activation.witness,
            registry.deltas_since(activation.witness.epoch).unwrap(),
            registry.checkpoint(),
        )
        .unwrap();
        circuit.registry_siblings = refreshed.siblings.to_vec();
        circuit.expected_registry_root = split_field_to_u128_limbs(refreshed.root);
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn a_modified_credential_fails_both_authentication_relations() {
        for authentication in [
            Authentication::IssuerSignature,
            Authentication::ActiveRegistry,
            Authentication::SignatureAndRegistry,
        ] {
            let mut circuit = SpikeCircuit::fixture(authentication);
            circuit.tamper_credential();
            let cs = ConstraintSystem::<CircuitField>::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(
                !cs.is_satisfied().unwrap(),
                "{authentication:?} must bind the complete credential commitment"
            );
        }
    }

    #[test]
    fn a_modified_nullifier_preimage_fails_closed() {
        let mut circuit = SpikeCircuit::fixture(Authentication::IssuerSignature);
        circuit.tamper_nullifier_preimage();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn holder_secret_is_bound_to_authentication_and_nullifier() {
        let mut circuit = SpikeCircuit::fixture(Authentication::SignatureAndRegistry);
        circuit.tamper_holder_secret();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn hybrid_cost_contains_both_authentication_costs() {
        let report = run_suite(false).unwrap();
        let signature = &report.results[0];
        let registry = &report.results[1];
        let hybrid = &report.results[2];
        assert!(hybrid.constraints > signature.constraints);
        assert!(hybrid.constraints > registry.constraints);
        assert_eq!(signature.public_inputs, 3);
        assert_eq!(registry.public_inputs, 5);
        assert_eq!(hybrid.public_inputs, 5);
    }

    #[test]
    fn registry_depth_profile_constraints_are_pinned() {
        let report = run_registry_depth_suite(false).expect("all depth profiles synthesize");
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.depth)
                .collect::<Vec<_>>(),
            REGISTRY_DEPTH_PROFILES
        );
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.measurement.constraints)
                .collect::<Vec<_>>(),
            REGISTRY_DEPTH_CONSTRAINTS,
            "depth-profile constraint drift requires an explicit benchmark review"
        );
        assert!(report
            .results
            .iter()
            .all(|result| result.measurement.public_inputs == 5));
        assert!(report.results.windows(2).all(|pair| {
            pair[1].measurement.constraints - pair[0].measurement.constraints == 15_424
        }));
    }

    #[test]
    fn every_registry_depth_profile_rejects_a_tampered_upper_path() {
        for depth in REGISTRY_DEPTH_PROFILES {
            let mut circuit =
                SpikeCircuit::fixture_with_registry_depth(Authentication::ActiveRegistry, depth);
            *circuit
                .registry_siblings
                .last_mut()
                .expect("depth profiles are non-zero") += CircuitField::from(1u64);

            let cs = ConstraintSystem::<CircuitField>::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(
                !cs.is_satisfied().unwrap(),
                "depth {depth} must bind the highest registry sibling"
            );
        }
    }

    #[test]
    #[ignore = "CI runs the release-mode Groth16 round trip explicitly"]
    fn all_candidates_generate_verified_groth16_proofs() {
        let report = run_suite(true).expect("all candidates prove and verify");
        assert!(report.results.iter().all(|result| {
            result.proof_verified == Some(true) && result.proof_bytes == Some(128)
        }));
        let depth_report =
            run_registry_depth_suite(true).expect("all registry depth profiles prove and verify");
        assert!(depth_report.results.iter().all(|result| {
            result.measurement.proof_verified == Some(true)
                && result.measurement.proof_bytes == Some(128)
        }));
    }
}
