//! Reproducible Stage-1 circuit-authentication spike for ubi2 ZK Identity v2.
//!
//! This is measurement code, not a production circuit. It deliberately lives
//! in an isolated Cargo workspace so none of its prover or gadget dependencies
//! can enter `ubi2-zkpoh`'s consensus verifier graph.

use ark_bn254::{Bn254, Fr as CircuitField, G1Affine, G2Affine};
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
use ark_groth16::{Groth16, ProvingKey};
use ark_r1cs_std::{
    fields::{emulated_fp::EmulatedFpVar, fp::FpVar},
    prelude::*,
};
use ark_relations::r1cs::{
    ConstraintSynthesizer, ConstraintSystem, ConstraintSystemRef, SynthesisError,
};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, SerializationError};
use ark_snark::SNARK;
use ark_std::rand::{rngs::StdRng, SeedableRng};
use serde::Serialize;
#[cfg(not(all(target_arch = "wasm32", feature = "browser")))]
use std::time::Instant;
use std::{error::Error, fmt};
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
use wasm_bindgen::{prelude::*, JsCast};

mod holder_credential;
mod status_distribution;
mod status_registry;
mod status_snapshot;

pub use holder_credential::{
    build_holder_credential_commitment, holder_credential_commitment_from_json,
    holder_credential_field_elements, synthetic_holder_credential_reference_vector,
    HolderCredentialCommitment, HolderCredentialCommitmentInput, HolderCredentialError,
    HolderCredentialReferenceVector, HOLDER_CREDENTIAL_COMMITMENT_SCHEMA,
    HOLDER_CREDENTIAL_COMMITMENT_SCHEME, HOLDER_CREDENTIAL_INPUT_SCHEMA,
    HOLDER_CREDENTIAL_PRIVATE_SCHEMA,
};

pub use status_distribution::{
    run_status_distribution_bakeoff, DeliveryMode, PackedStatusBatchEstimate,
    SparseMerkleBatchEstimate, StatusDistributionReport, StatusDistributionWorkloadReport,
    PACKED_STATUS_BITS_PER_CHUNK, PACKED_STATUS_DEPTH, SPARSE_STATUS_DEPTH,
};
pub use status_registry::{
    refresh_status_witness, StatusActivation, StatusCheckpoint, StatusRegistry,
    StatusRegistryDelta, StatusRegistryError, StatusWitness, STATUS_REGISTRY_DELTA_MAX_JSON_BYTES,
    STATUS_REGISTRY_DELTA_SCHEMA,
};
pub use status_snapshot::{
    advance_packed_status_snapshot_from_json, build_packed_status_snapshot_from_json,
    FinalizedStatusBlock, PackedStatusChunk, PackedStatusSnapshot, PackedStatusSnapshotBuilder,
    PackedStatusSnapshotChunk, PackedStatusSnapshotError, PackedStatusSourceEvent,
    PackedStatusWitness, SourceBlockRef, PACKED_STATUS_SNAPSHOT_SCHEMA,
    PACKED_STATUS_SOURCE_SCHEMA, PACKED_STATUS_WITNESS_SCHEMA,
};

/// Browser-local commitment entry point. The JSON source is consumed in WASM
/// memory and the returned descriptor contains no private fields.
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = buildHolderCredentialCommitment)]
pub fn build_holder_credential_commitment_wasm(source: &str) -> Result<String, JsValue> {
    holder_credential_commitment_from_json(source)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

/// Native field used by the Stage-1 status-registry prototype.
pub type StatusField = CircuitField;

// The ABI has 13 logical fields. Its three bytes32 fields are split into two
// lossless 128-bit limbs, so the circuit commitment absorbs 16 field elements.
pub const CREDENTIAL_ELEMENT_COUNT: usize = 16;
pub const NULLIFIER_FIELD_COUNT: usize = 6;
pub const DYNAMIC_STATUS_PUBLIC_SIGNAL_COUNT: usize = 18;
pub const REGISTRY_DEPTH: usize = 32;
pub const REGISTRY_DEPTH_PROFILES: [usize; 4] = [32, 64, 96, 128];
pub const REGISTRY_DEPTH_CONSTRAINTS: [usize; 4] = [21_723, 37_147, 52_571, 67_995];
pub const REGISTRY_DEPTH_WITNESS_VARIABLES: [usize; 4] = [21_301, 36_757, 52_213, 67_669];
pub const BROWSER_REGISTRY_DEPTHS: [usize; 2] = [96, 128];
pub const BROWSER_REGISTRY_PROVING_KEY_BYTES: [usize; 2] = [10_452_496, 15_022_608];
pub const BROWSER_PACKED_STATUS_PROVING_KEY_BYTES: usize = 5_250_320;
/// Non-cryptographic drift fingerprint of the compact fixture-export JSON.
/// A change requires reviewing and regenerating the Solidity verifier fixture.
pub const PACKED_STATUS_EVM_FIXTURE_FNV64: u64 = 0x6d5b_42a8_22c9_3acd;
/// Fingerprint of the deterministic 18-signal research fixture export.
pub const DYNAMIC_STATUS_EVM_FIXTURE_FNV64: u64 = 0x3e08_2adc_0c10_07e6;
const CREDENTIAL_HOLDER_SECRET_INDEX: usize = 7;
const CREDENTIAL_ISSUED_AT_EPOCH_INDEX: usize = 15;
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
pub const SIGNATURE_AND_PACKED_STATUS_CONSTRAINTS: usize = 27_157;
pub const SIGNATURE_AND_PACKED_STATUS_WITNESS_VARIABLES: usize = 26_253;
pub const DYNAMIC_STATUS_PRESENTATION_CONSTRAINTS: usize = 28_499;
pub const DYNAMIC_STATUS_PRESENTATION_WITNESS_VARIABLES: usize = 27_561;

const CREDENTIAL_DOMAIN: u64 = 1;
const NULLIFIER_DOMAIN: u64 = 2;
const REGISTRY_NODE_DOMAIN: u64 = 3;
const SIGNATURE_CHALLENGE_DOMAIN: u64 = 4;
const ISSUER_KEY_DOMAIN: u64 = 5;
const STATUS_LEAF_DOMAIN: u64 = 6;
const STATUS_INDEX_DOMAIN: u64 = 7;
const PACKED_STATUS_LEAF_DOMAIN: u64 = 8;

// Canonical EVM fixture values for the research-only dynamic sanctions-clear
// presentation. bytes32 values are represented high-limb first.
const DYNAMIC_STATUS_CIRCUIT_ID: [u128; 2] = [
    289_702_399_193_246_464_478_010_289_331_281_785_396,
    48_741_886_182_628_607_789_356_429_954_167_136_159,
];
const DYNAMIC_STATUS_POLICY_HASH: [u128; 2] = [
    193_982_682_682_601_763_857_871_921_400_019_234_941,
    144_791_356_043_039_333_640_796_404_275_935_384_537,
];
const DYNAMIC_STATUS_PRESENTATION_BINDING: [u128; 2] = [
    251_146_112_810_056_859_446_043_645_491_032_321_007,
    180_051_849_839_934_735_603_729_905_154_568_835_574,
];
const DYNAMIC_STATUS_NULLIFIER_SCOPE: [u128; 2] = [
    217_086_243_769_357_075_757_050_964_729_507_721_374,
    147_556_859_725_270_294_027_880_020_698_272_123_538,
];
const NULLIFIER_PREIMAGE_DOMAIN: [u128; 2] = [
    3_753_063_511_814_324_395_807_447_140_844_095_217,
    39_595_397_136_107_903_161_255_285_981_469_469_429,
];
const DYNAMIC_STATUS_CREDENTIAL_EPOCH: u32 = 230;
const DYNAMIC_STATUS_PUBLISHED_AT: u32 = 1_788_480_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Authentication {
    IssuerSignature,
    ActiveRegistry,
    SignatureAndRegistry,
    SignatureAndPackedStatus,
}

impl Authentication {
    fn includes_signature(self) -> bool {
        matches!(
            self,
            Self::IssuerSignature | Self::SignatureAndRegistry | Self::SignatureAndPackedStatus
        )
    }

    fn includes_registry(self) -> bool {
        matches!(self, Self::ActiveRegistry | Self::SignatureAndRegistry)
    }

    fn includes_packed_status(self) -> bool {
        matches!(self, Self::SignatureAndPackedStatus)
    }

    fn includes_status_root(self) -> bool {
        self.includes_registry() || self.includes_packed_status()
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
    // Two little-endian u128 limbs encode 256 activation/status bits in a
    // packed-status chunk. Zero means allocated+active; one means
    // unallocated or revoked, so an issuer signature alone cannot activate a
    // slot that the canonical issuance registry never allocated.
    packed_status_chunk: [CircuitField; 2],
    registry_siblings: Vec<CircuitField>,
    expected_registry_root: [CircuitField; 2],
}

/// Research bridge from the authenticated packed-status relation to the exact
/// product 18-signal ABI. It is intentionally a sanctions-clear circuit: the
/// adapter authenticates Keccak policy/binding values and governed freshness,
/// while this relation proves the signed status slot is clear under that root.
#[derive(Clone)]
pub struct DynamicStatusPresentationCircuit {
    inner: SpikeCircuit,
    public_signals: [CircuitField; DYNAMIC_STATUS_PUBLIC_SIGNAL_COUNT],
}

#[derive(Debug, Serialize)]
pub struct SuiteReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub curve: &'static str,
    pub poseidon_profile: &'static str,
    pub registry_depth: usize,
    pub packed_status_depth: usize,
    pub packed_statuses_per_chunk: usize,
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

#[derive(Debug, Serialize)]
pub struct BrowserRegistryProofReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub depth: usize,
    pub authentication: Authentication,
    pub constraints: usize,
    pub public_inputs: usize,
    pub witness_variables: usize,
    pub proving_key_bytes: usize,
    pub key_deserialize_ms: f64,
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub proof_bytes: usize,
    pub verifying_key_bytes: usize,
    pub proof_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct BrowserPackedStatusProofReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub depth: usize,
    pub statuses_per_chunk: usize,
    pub authentication: Authentication,
    pub constraints: usize,
    pub public_inputs: usize,
    pub witness_variables: usize,
    pub proving_key_bytes: usize,
    pub key_deserialize_ms: f64,
    pub prove_ms: f64,
    pub verify_ms: f64,
    pub proof_bytes: usize,
    pub verifying_key_bytes: usize,
    pub proof_verified: bool,
}

/// EIP-197 affine G1 encoding. Decimal strings keep the report lossless when
/// consumed by Solidity generators or JavaScript tooling.
#[derive(Debug, Serialize)]
pub struct EvmG1Point {
    pub x: String,
    pub y: String,
}

/// EIP-197 affine G2 encoding. The precompile encodes `a * i + b` as
/// `(a, b)`, so each coordinate is intentionally emitted imaginary-first.
#[derive(Debug, Serialize)]
pub struct EvmG2Point {
    pub x_imaginary: String,
    pub x_real: String,
    pub y_imaginary: String,
    pub y_real: String,
}

#[derive(Debug, Serialize)]
pub struct EvmGroth16Proof {
    pub a: EvmG1Point,
    pub b: EvmG2Point,
    pub c: EvmG1Point,
}

/// Reproducible bridge from the packed-status research fixture to the exact
/// word order consumed by the BN254 EVM precompiles. This is deliberately not
/// the product's 18-signal verifier artifact.
#[derive(Debug, Serialize)]
pub struct PackedStatusEvmFixtureReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub public_input_count: usize,
    pub public_inputs: Vec<String>,
    pub alpha_g1: EvmG1Point,
    pub beta_g2: EvmG2Point,
    pub gamma_g2: EvmG2Point,
    pub delta_g2: EvmG2Point,
    pub gamma_abc_g1: Vec<EvmG1Point>,
    pub proof: EvmGroth16Proof,
    pub proof_verified: bool,
}

/// Exact 18-signal EVM artifact for the dynamic sanctions-clear research
/// relation. The deterministic setup is intentionally public toxic waste.
#[derive(Debug, Serialize)]
pub struct DynamicStatusEvmFixtureReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub constraints: usize,
    pub witness_variables: usize,
    pub public_input_count: usize,
    pub public_inputs: Vec<String>,
    pub alpha_g1: EvmG1Point,
    pub beta_g2: EvmG2Point,
    pub gamma_g2: EvmG2Point,
    pub delta_g2: EvmG2Point,
    pub gamma_abc_g1: Vec<EvmG1Point>,
    pub proof: EvmGroth16Proof,
    pub proof_verified: bool,
}

#[derive(Debug, Serialize)]
pub struct RegistryTransportEstimateReport {
    pub schema: &'static str,
    pub warning: &'static str,
    pub results: Vec<RegistryTransportEstimate>,
}

#[derive(Debug, Serialize)]
pub struct RegistryTransportEstimate {
    pub depth: usize,
    pub index_bytes: usize,
    pub merkle_path_bytes: usize,
    pub holder_witness_floor_bytes: usize,
    pub single_delta_floor_bytes: usize,
    pub thousand_delta_floor_bytes: usize,
    pub hundred_thousand_delta_floor_bytes: usize,
}

#[derive(Debug)]
pub enum BrowserBenchmarkError {
    UnsupportedDepth(usize),
    ProvingKeySizeMismatch { expected: usize, actual: usize },
    Synthesis(SynthesisError),
    Serialization(SerializationError),
    ProofRejected,
}

impl fmt::Display for BrowserBenchmarkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedDepth(depth) => write!(
                formatter,
                "registry depth {depth} is not a browser benchmark profile"
            ),
            Self::ProvingKeySizeMismatch { expected, actual } => write!(
                formatter,
                "proving key has {actual} bytes; benchmark profile requires exactly {expected}"
            ),
            Self::Synthesis(error) => write!(formatter, "circuit synthesis failed: {error}"),
            Self::Serialization(error) => {
                write!(formatter, "proving-key encoding failed: {error}")
            }
            Self::ProofRejected => formatter.write_str("generated proof did not verify"),
        }
    }
}

impl Error for BrowserBenchmarkError {}

impl From<SynthesisError> for BrowserBenchmarkError {
    fn from(error: SynthesisError) -> Self {
        Self::Synthesis(error)
    }
}

impl From<SerializationError> for BrowserBenchmarkError {
    fn from(error: SerializationError) -> Self {
        Self::Serialization(error)
    }
}

#[cfg(not(all(target_arch = "wasm32", feature = "browser")))]
struct BenchmarkTimer(Instant);

#[cfg(not(all(target_arch = "wasm32", feature = "browser")))]
impl BenchmarkTimer {
    fn start() -> Self {
        Self(Instant::now())
    }

    fn elapsed_ms(&self) -> f64 {
        self.0.elapsed().as_secs_f64() * 1_000.0
    }
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
struct BenchmarkTimer(f64);

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
impl BenchmarkTimer {
    fn start() -> Self {
        Self(js_sys::Date::now())
    }

    fn elapsed_ms(&self) -> f64 {
        js_sys::Date::now() - self.0
    }
}

struct SignatureWitness {
    issuer_public_key: EdwardsProjective,
    issuer_key_id: [FpVar<CircuitField>; 2],
    signature_commitment: EdwardsProjective,
    signature_response: JubjubScalar,
}

impl SpikeCircuit {
    pub fn fixture(authentication: Authentication) -> Self {
        let depth = if authentication.includes_packed_status() {
            PACKED_STATUS_DEPTH
        } else {
            REGISTRY_DEPTH
        };
        Self::fixture_with_registry_depth(authentication, depth)
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
        if authentication.includes_packed_status() {
            assert_eq!(
                registry_depth, PACKED_STATUS_DEPTH,
                "packed status uses the pinned 24-bit chunk index"
            );
        }
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
        if authentication.includes_packed_status() {
            // Research convention: the signed bytes32 statusId is a canonical
            // uint32 slot. Its low eight bits select a bit within a chunk and
            // the next 24 bits select the chunk's Merkle path.
            credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX] = CircuitField::from(0u64);
            credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX] = CircuitField::from(7_000_021u64);
        }
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
        let packed_status_chunk = if authentication.includes_packed_status() {
            packed_status_chunk_with_active_slot(status_id[1])
        } else {
            [CircuitField::from(0u64); 2]
        };
        let (status_leaf, registry_directions) = if authentication.includes_packed_status() {
            (
                packed_status_leaf_native(&poseidon, packed_status_chunk),
                packed_status_path_directions_native(status_id[1]),
            )
        } else {
            (
                active_status_leaf_native(&poseidon, status_id, credential_commitment),
                status_path_directions_native(&poseidon, status_id, registry_depth),
            )
        };
        let expected_registry_root = split_field_to_u128_limbs(merkle_root_native(
            &poseidon,
            status_leaf,
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
            packed_status_chunk,
            registry_siblings,
            expected_registry_root,
        }
    }

    #[cfg(test)]
    fn recompute_registry_root(&mut self) {
        let poseidon = poseidon_config();
        let status_id = [
            self.credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX],
            self.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX],
        ];
        let (status_leaf, directions) = if self.authentication.includes_packed_status() {
            (
                packed_status_leaf_native(&poseidon, self.packed_status_chunk),
                packed_status_path_directions_native(status_id[1]),
            )
        } else {
            let credential_commitment = poseidon_native(
                &poseidon,
                CREDENTIAL_DOMAIN,
                self.credential_elements.as_slice(),
            );
            (
                active_status_leaf_native(&poseidon, status_id, credential_commitment),
                status_path_directions_native(&poseidon, status_id, self.registry_siblings.len()),
            )
        };
        self.expected_registry_root = split_field_to_u128_limbs(merkle_root_native(
            &poseidon,
            status_leaf,
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
        if self.authentication.includes_status_root() {
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
        let directions = if self.authentication.includes_packed_status() {
            packed_status_path_directions_native(status_id[1])
        } else {
            status_path_directions_native(&poseidon, status_id, self.registry_siblings.len())
        };
        let changed_index = directions
            .iter()
            .position(|current_is_right| !current_is_right)
            .expect("fixture path has a sibling leaf to rotate");
        self.registry_siblings[changed_index] += CircuitField::from(1u64);
        self.recompute_registry_root();
    }

    #[cfg(test)]
    fn revoke_packed_status(&mut self) {
        let status_low = self.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX].into_bigint();
        let selected_bit = (0..8).fold(0usize, |index, bit| {
            index | (usize::from(status_low.get_bit(bit)) << bit)
        });
        self.set_packed_status_bit(selected_bit);
    }

    #[cfg(test)]
    fn activate_unrelated_packed_status_bit(&mut self) {
        let status_low = self.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX].into_bigint();
        let selected_bit = (0..8).fold(0usize, |index, bit| {
            index | (usize::from(status_low.get_bit(bit)) << bit)
        });
        self.clear_packed_status_bit((selected_bit + 1) % PACKED_STATUS_BITS_PER_CHUNK);
    }

    #[cfg(test)]
    fn set_packed_status_bit(&mut self, selected_bit: usize) {
        let limb_index = selected_bit / BYTES32_LIMB_BITS;
        let limb_bit = selected_bit % BYTES32_LIMB_BITS;
        self.packed_status_chunk[limb_index] += CircuitField::from(1u128 << limb_bit);
        self.recompute_registry_root();
    }

    #[cfg(test)]
    fn clear_packed_status_bit(&mut self, selected_bit: usize) {
        let limb_index = selected_bit / BYTES32_LIMB_BITS;
        let limb_bit = selected_bit % BYTES32_LIMB_BITS;
        self.packed_status_chunk[limb_index] -= CircuitField::from(1u128 << limb_bit);
        self.recompute_registry_root();
    }

    #[cfg(test)]
    fn make_packed_status_chunk_limb_wide(&mut self) {
        self.packed_status_chunk[0] = CircuitField::from_be_bytes_mod_order(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
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

impl DynamicStatusPresentationCircuit {
    pub fn fixture() -> Self {
        let poseidon = poseidon_config();
        let mut inner = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);

        // Bind the public credential epoch to the signed credential rather than
        // carrying a presentation-only timestamp.
        inner.credential_elements[CREDENTIAL_ISSUED_AT_EPOCH_INDEX] =
            CircuitField::from(DYNAMIC_STATUS_CREDENTIAL_EPOCH);
        let credential_commitment = poseidon_native(
            &poseidon,
            CREDENTIAL_DOMAIN,
            inner.credential_elements.as_slice(),
        );
        let issuer_secret = JubjubScalar::from(4_242_424u64);
        let challenge = signature_challenge_native(
            &poseidon,
            &inner.signature_commitment,
            &inner.issuer_public_key,
            credential_commitment,
        );
        inner.signature_response = JubjubScalar::from(8_181_818u64)
            - jubjub_scalar_from_circuit_field(challenge) * issuer_secret;

        let nullifier_preimage = [
            CircuitField::from(NULLIFIER_PREIMAGE_DOMAIN[0]),
            CircuitField::from(NULLIFIER_PREIMAGE_DOMAIN[1]),
            CircuitField::from(1u64),
            inner.credential_elements[CREDENTIAL_HOLDER_SECRET_INDEX],
            CircuitField::from(DYNAMIC_STATUS_NULLIFIER_SCOPE[0]),
            CircuitField::from(DYNAMIC_STATUS_NULLIFIER_SCOPE[1]),
        ];
        let scoped_nullifier = poseidon_native(&poseidon, NULLIFIER_DOMAIN, &nullifier_preimage);
        let subject = CircuitField::from_be_bytes_mod_order(&[0x33; 20]);

        let mut public_signals = [CircuitField::from(0u64); DYNAMIC_STATUS_PUBLIC_SIGNAL_COUNT];
        public_signals[0] = CircuitField::from(1u64);
        public_signals[1] = CircuitField::from(DYNAMIC_STATUS_CIRCUIT_ID[0]);
        public_signals[2] = CircuitField::from(DYNAMIC_STATUS_CIRCUIT_ID[1]);
        public_signals[3..5].copy_from_slice(&inner.issuer_key_id);
        public_signals[5..7].copy_from_slice(&inner.expected_registry_root);
        public_signals[7] = CircuitField::from(DYNAMIC_STATUS_POLICY_HASH[0]);
        public_signals[8] = CircuitField::from(DYNAMIC_STATUS_POLICY_HASH[1]);
        public_signals[9] = CircuitField::from(DYNAMIC_STATUS_PRESENTATION_BINDING[0]);
        public_signals[10] = CircuitField::from(DYNAMIC_STATUS_PRESENTATION_BINDING[1]);
        public_signals[11] = CircuitField::from(DYNAMIC_STATUS_NULLIFIER_SCOPE[0]);
        public_signals[12] = CircuitField::from(DYNAMIC_STATUS_NULLIFIER_SCOPE[1]);
        public_signals[13] = scoped_nullifier;
        public_signals[14] = subject;
        public_signals[15] = CircuitField::from(1u64);
        public_signals[16] = CircuitField::from(DYNAMIC_STATUS_CREDENTIAL_EPOCH);
        public_signals[17] = CircuitField::from(DYNAMIC_STATUS_PUBLISHED_AT);

        Self {
            inner,
            public_signals,
        }
    }

    pub fn public_inputs(&self) -> Vec<CircuitField> {
        self.public_signals.to_vec()
    }

    #[cfg(test)]
    fn set_public_signal(&mut self, index: usize, value: CircuitField) {
        self.public_signals[index] = value;
    }

    #[cfg(test)]
    fn revoke_packed_status(&mut self) {
        self.inner.revoke_packed_status();
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
                cs.clone(),
                &poseidon,
                credential_commitment,
                credential_vars[CREDENTIAL_STATUS_ID_HIGH_INDEX].clone(),
                credential_vars[CREDENTIAL_STATUS_ID_LOW_INDEX].clone(),
                &self.registry_siblings,
                self.expected_registry_root,
            )?;
        }

        if self.authentication.includes_packed_status() {
            enforce_packed_status_nonrevocation(
                cs,
                &poseidon,
                credential_vars[CREDENTIAL_STATUS_ID_HIGH_INDEX].clone(),
                credential_vars[CREDENTIAL_STATUS_ID_LOW_INDEX].clone(),
                self.packed_status_chunk,
                &self.registry_siblings,
                self.expected_registry_root,
            )?;
        }

        Ok(())
    }
}

impl ConstraintSynthesizer<CircuitField> for DynamicStatusPresentationCircuit {
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<CircuitField>,
    ) -> Result<(), SynthesisError> {
        let poseidon = poseidon_config();
        let public = self
            .public_signals
            .iter()
            .map(|value| FpVar::new_input(cs.clone(), || Ok(*value)))
            .collect::<Result<Vec<_>, _>>()?;

        public[0].enforce_equal(&FpVar::Constant(CircuitField::from(1u64)))?;
        public[1].enforce_equal(&FpVar::Constant(CircuitField::from(
            DYNAMIC_STATUS_CIRCUIT_ID[0],
        )))?;
        public[2].enforce_equal(&FpVar::Constant(CircuitField::from(
            DYNAMIC_STATUS_CIRCUIT_ID[1],
        )))?;
        for high_index in [1usize, 3, 5, 7, 9, 11] {
            enforce_identifier(&public[high_index], &public[high_index + 1])?;
        }

        let credential_vars = self
            .inner
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
        credential_vars[CREDENTIAL_ISSUER_KEY_ID_HIGH_INDEX].enforce_equal(&public[3])?;
        credential_vars[CREDENTIAL_ISSUER_KEY_ID_LOW_INDEX].enforce_equal(&public[4])?;
        credential_vars[CREDENTIAL_ISSUED_AT_EPOCH_INDEX].enforce_equal(&public[16])?;

        enforce_signature(
            cs.clone(),
            &poseidon,
            &credential_commitment,
            SignatureWitness {
                issuer_public_key: self.inner.issuer_public_key,
                issuer_key_id: [public[3].clone(), public[4].clone()],
                signature_commitment: self.inner.signature_commitment,
                signature_response: self.inner.signature_response,
            },
        )?;
        enforce_packed_status_nonrevocation_with_public_root(
            cs.clone(),
            &poseidon,
            credential_vars[CREDENTIAL_STATUS_ID_HIGH_INDEX].clone(),
            credential_vars[CREDENTIAL_STATUS_ID_LOW_INDEX].clone(),
            self.inner.packed_status_chunk,
            &self.inner.registry_siblings,
            [public[5].clone(), public[6].clone()],
        )?;

        let nullifier_preimage = [
            FpVar::Constant(CircuitField::from(NULLIFIER_PREIMAGE_DOMAIN[0])),
            FpVar::Constant(CircuitField::from(NULLIFIER_PREIMAGE_DOMAIN[1])),
            FpVar::Constant(CircuitField::from(1u64)),
            credential_vars[CREDENTIAL_HOLDER_SECRET_INDEX].clone(),
            public[11].clone(),
            public[12].clone(),
        ];
        let scoped_nullifier =
            poseidon_gadget(cs.clone(), &poseidon, NULLIFIER_DOMAIN, &nullifier_preimage)?;
        scoped_nullifier.enforce_equal(&public[13])?;
        public[13].is_zero()?.enforce_equal(&Boolean::FALSE)?;

        let _ = public[14].to_bits_le_with_top_bits_zero(160)?;
        public[14].is_zero()?.enforce_equal(&Boolean::FALSE)?;
        public[15].enforce_equal(&FpVar::Constant(CircuitField::from(1u64)))?;
        let _ = public[16].to_bits_le_with_top_bits_zero(32)?;
        let _ = public[17].to_bits_le_with_top_bits_zero(32)?;
        public[17].is_zero()?.enforce_equal(&Boolean::FALSE)?;

        Ok(())
    }
}

pub fn run_suite(with_proofs: bool) -> Result<SuiteReport, SynthesisError> {
    let mut results = Vec::new();
    for authentication in [
        Authentication::IssuerSignature,
        Authentication::ActiveRegistry,
        Authentication::SignatureAndRegistry,
        Authentication::SignatureAndPackedStatus,
    ] {
        results.push(measure_candidate(
            SpikeCircuit::fixture(authentication),
            with_proofs,
        )?);
    }

    Ok(SuiteReport {
        schema: "org.proofofhumanity.v2-crypto-benchmark/2",
        warning: "research harness only; not a production circuit or cryptographic ratification",
        curve: "Groth16/BN254 with Baby-Jubjub authentication model",
        poseidon_profile: "width=3 rate=2 capacity=1 alpha=5 full=8 partial=57 skip_matrices=0",
        registry_depth: REGISTRY_DEPTH,
        packed_status_depth: PACKED_STATUS_DEPTH,
        packed_statuses_per_chunk: PACKED_STATUS_BITS_PER_CHUNK,
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

pub fn run_registry_transport_estimates() -> RegistryTransportEstimateReport {
    const FIELD_BYTES: usize = 32;
    const EPOCH_BYTES: usize = 4;
    let results = REGISTRY_DEPTH_PROFILES
        .into_iter()
        .map(|depth| {
            let index_bytes = depth.div_ceil(8);
            let merkle_path_bytes = depth * FIELD_BYTES;
            let holder_witness_floor_bytes =
                EPOCH_BYTES + FIELD_BYTES + FIELD_BYTES + merkle_path_bytes;
            let single_delta_floor_bytes =
                EPOCH_BYTES * 2 + FIELD_BYTES * 4 + index_bytes + merkle_path_bytes;
            RegistryTransportEstimate {
                depth,
                index_bytes,
                merkle_path_bytes,
                holder_witness_floor_bytes,
                single_delta_floor_bytes,
                thousand_delta_floor_bytes: single_delta_floor_bytes * 1_000,
                hundred_thousand_delta_floor_bytes: single_delta_floor_bytes * 100_000,
            }
        })
        .collect();

    RegistryTransportEstimateReport {
        schema: "org.proofofhumanity.v2-registry-transport-estimate/1",
        warning: "research depth projection; binary lower bounds exclude framing, schema, authentication and compression",
        results,
    }
}

pub fn generate_registry_proving_key(depth: usize) -> Result<Vec<u8>, BrowserBenchmarkError> {
    validate_browser_registry_depth(depth)?;
    let circuit = SpikeCircuit::fixture_with_registry_depth(Authentication::ActiveRegistry, depth);
    let mut setup_rng = StdRng::seed_from_u64(registry_benchmark_seed(depth));
    let (proving_key, _) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut setup_rng)?;
    let mut bytes = Vec::new();
    proving_key.serialize_compressed(&mut bytes)?;
    let expected = browser_proving_key_bytes(depth);
    if bytes.len() != expected {
        return Err(BrowserBenchmarkError::ProvingKeySizeMismatch {
            expected,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

pub fn prove_registry_depth_with_key(
    depth: usize,
    proving_key_bytes: &[u8],
) -> Result<BrowserRegistryProofReport, BrowserBenchmarkError> {
    let (constraints, witness_variables) = validate_browser_registry_depth(depth)?;
    let expected_proving_key_bytes = browser_proving_key_bytes(depth);
    if proving_key_bytes.len() != expected_proving_key_bytes {
        return Err(BrowserBenchmarkError::ProvingKeySizeMismatch {
            expected: expected_proving_key_bytes,
            actual: proving_key_bytes.len(),
        });
    }
    let key_started = BenchmarkTimer::start();
    let proving_key = ProvingKey::<Bn254>::deserialize_compressed(proving_key_bytes)?;
    let key_deserialize_ms = key_started.elapsed_ms();

    let circuit = SpikeCircuit::fixture_with_registry_depth(Authentication::ActiveRegistry, depth);
    let mut proof_rng =
        StdRng::seed_from_u64(registry_benchmark_seed(depth) ^ 0xa5_a5_a5_a5_a5_a5_a5_a5);
    let prove_started = BenchmarkTimer::start();
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit.clone(), &mut proof_rng)?;
    let prove_ms = prove_started.elapsed_ms();

    let processed = Groth16::<Bn254>::process_vk(&proving_key.vk)?;
    let verify_started = BenchmarkTimer::start();
    let proof_verified =
        Groth16::<Bn254>::verify_with_processed_vk(&processed, &circuit.public_inputs(), &proof)?;
    let verify_ms = verify_started.elapsed_ms();
    if !proof_verified {
        return Err(BrowserBenchmarkError::ProofRejected);
    }

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    let mut verifying_key_bytes = Vec::new();
    proving_key
        .vk
        .serialize_compressed(&mut verifying_key_bytes)?;

    Ok(BrowserRegistryProofReport {
        schema: "org.proofofhumanity.v2-browser-registry-proof/1",
        warning: "research harness only; deterministic fixture key and proof are not deployable",
        depth,
        authentication: Authentication::ActiveRegistry,
        constraints,
        public_inputs: 5,
        witness_variables,
        proving_key_bytes: proving_key_bytes.len(),
        key_deserialize_ms,
        prove_ms,
        verify_ms,
        proof_bytes: proof_bytes.len(),
        verifying_key_bytes: verifying_key_bytes.len(),
        proof_verified,
    })
}

pub fn generate_packed_status_proving_key() -> Result<Vec<u8>, BrowserBenchmarkError> {
    let circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
    let mut setup_rng = StdRng::seed_from_u64(packed_status_benchmark_seed());
    let (proving_key, _) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut setup_rng)?;
    let mut bytes = Vec::new();
    proving_key.serialize_compressed(&mut bytes)?;
    if bytes.len() != BROWSER_PACKED_STATUS_PROVING_KEY_BYTES {
        return Err(BrowserBenchmarkError::ProvingKeySizeMismatch {
            expected: BROWSER_PACKED_STATUS_PROVING_KEY_BYTES,
            actual: bytes.len(),
        });
    }
    Ok(bytes)
}

pub fn prove_packed_status_with_key(
    proving_key_bytes: &[u8],
) -> Result<BrowserPackedStatusProofReport, BrowserBenchmarkError> {
    if proving_key_bytes.len() != BROWSER_PACKED_STATUS_PROVING_KEY_BYTES {
        return Err(BrowserBenchmarkError::ProvingKeySizeMismatch {
            expected: BROWSER_PACKED_STATUS_PROVING_KEY_BYTES,
            actual: proving_key_bytes.len(),
        });
    }
    let key_started = BenchmarkTimer::start();
    let proving_key = ProvingKey::<Bn254>::deserialize_compressed(proving_key_bytes)?;
    let key_deserialize_ms = key_started.elapsed_ms();

    let circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
    let mut proof_rng =
        StdRng::seed_from_u64(packed_status_benchmark_seed() ^ 0xa5_a5_a5_a5_a5_a5_a5_a5);
    let prove_started = BenchmarkTimer::start();
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit.clone(), &mut proof_rng)?;
    let prove_ms = prove_started.elapsed_ms();

    let processed = Groth16::<Bn254>::process_vk(&proving_key.vk)?;
    let verify_started = BenchmarkTimer::start();
    let proof_verified =
        Groth16::<Bn254>::verify_with_processed_vk(&processed, &circuit.public_inputs(), &proof)?;
    let verify_ms = verify_started.elapsed_ms();
    if !proof_verified {
        return Err(BrowserBenchmarkError::ProofRejected);
    }

    let mut proof_bytes = Vec::new();
    proof.serialize_compressed(&mut proof_bytes)?;
    let mut verifying_key_bytes = Vec::new();
    proving_key
        .vk
        .serialize_compressed(&mut verifying_key_bytes)?;

    Ok(BrowserPackedStatusProofReport {
        schema: "org.proofofhumanity.v2-browser-packed-status-proof/1",
        warning: "research harness only; deterministic fixture key and proof are not deployable",
        depth: PACKED_STATUS_DEPTH,
        statuses_per_chunk: PACKED_STATUS_BITS_PER_CHUNK,
        authentication: Authentication::SignatureAndPackedStatus,
        constraints: SIGNATURE_AND_PACKED_STATUS_CONSTRAINTS,
        public_inputs: 5,
        witness_variables: SIGNATURE_AND_PACKED_STATUS_WITNESS_VARIABLES,
        proving_key_bytes: proving_key_bytes.len(),
        key_deserialize_ms,
        prove_ms,
        verify_ms,
        proof_bytes: proof_bytes.len(),
        verifying_key_bytes: verifying_key_bytes.len(),
        proof_verified,
    })
}

/// Generate the deterministic packed-status setup and export one verified
/// proof plus its verifying key in EIP-197 word order.
pub fn generate_packed_status_evm_fixture(
) -> Result<PackedStatusEvmFixtureReport, BrowserBenchmarkError> {
    let proving_key = generate_packed_status_proving_key()?;
    export_packed_status_evm_fixture_with_key(&proving_key)
}

/// Generate the deterministic 18-signal sanctions-clear setup and export one
/// verified proof plus its verifying key in EIP-197 word order.
pub fn generate_dynamic_status_evm_fixture(
) -> Result<DynamicStatusEvmFixtureReport, BrowserBenchmarkError> {
    let circuit = DynamicStatusPresentationCircuit::fixture();
    let measurement_cs = ConstraintSystem::<CircuitField>::new_ref();
    circuit
        .clone()
        .generate_constraints(measurement_cs.clone())?;
    if !measurement_cs.is_satisfied()? {
        return Err(BrowserBenchmarkError::ProofRejected);
    }
    let constraints = measurement_cs.num_constraints();
    let witness_variables = measurement_cs.num_witness_variables();
    let public_inputs = circuit.public_inputs();

    // Public deterministic seeds make this reproducible and make the output
    // categorically unsafe for production use.
    let mut setup_rng = StdRng::seed_from_u64(0x44_59_4e_53_54_41_54_55);
    let (proving_key, _) =
        Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut setup_rng)?;
    let mut proof_rng = StdRng::seed_from_u64(0x53_54_41_54_55_53_5f_31);
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit, &mut proof_rng)?;
    let processed = Groth16::<Bn254>::process_vk(&proving_key.vk)?;
    let proof_verified =
        Groth16::<Bn254>::verify_with_processed_vk(&processed, &public_inputs, &proof)?;
    if !proof_verified {
        return Err(BrowserBenchmarkError::ProofRejected);
    }

    Ok(DynamicStatusEvmFixtureReport {
        schema: "org.proofofhumanity.v2-dynamic-status-evm-fixture/1",
        warning:
            "research fixture only; deterministic toxic-waste setup is public and not deployable",
        constraints,
        witness_variables,
        public_input_count: public_inputs.len(),
        public_inputs: public_inputs
            .into_iter()
            .map(field_element_decimal)
            .collect(),
        alpha_g1: evm_g1(&proving_key.vk.alpha_g1),
        beta_g2: evm_g2(&proving_key.vk.beta_g2),
        gamma_g2: evm_g2(&proving_key.vk.gamma_g2),
        delta_g2: evm_g2(&proving_key.vk.delta_g2),
        gamma_abc_g1: proving_key.vk.gamma_abc_g1.iter().map(evm_g1).collect(),
        proof: EvmGroth16Proof {
            a: evm_g1(&proof.a),
            b: evm_g2(&proof.b),
            c: evm_g1(&proof.c),
        },
        proof_verified,
    })
}

fn export_packed_status_evm_fixture_with_key(
    proving_key_bytes: &[u8],
) -> Result<PackedStatusEvmFixtureReport, BrowserBenchmarkError> {
    if proving_key_bytes.len() != BROWSER_PACKED_STATUS_PROVING_KEY_BYTES {
        return Err(BrowserBenchmarkError::ProvingKeySizeMismatch {
            expected: BROWSER_PACKED_STATUS_PROVING_KEY_BYTES,
            actual: proving_key_bytes.len(),
        });
    }
    let proving_key = ProvingKey::<Bn254>::deserialize_compressed(proving_key_bytes)?;
    let circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
    let public_inputs = circuit.public_inputs();
    let mut proof_rng =
        StdRng::seed_from_u64(packed_status_benchmark_seed() ^ 0xa5_a5_a5_a5_a5_a5_a5_a5);
    let proof = Groth16::<Bn254>::prove(&proving_key, circuit, &mut proof_rng)?;
    let processed = Groth16::<Bn254>::process_vk(&proving_key.vk)?;
    let proof_verified =
        Groth16::<Bn254>::verify_with_processed_vk(&processed, &public_inputs, &proof)?;
    if !proof_verified {
        return Err(BrowserBenchmarkError::ProofRejected);
    }

    Ok(PackedStatusEvmFixtureReport {
        schema: "org.proofofhumanity.v2-packed-status-evm-fixture/1",
        warning: "research fixture only; deterministic toxic-waste setup and 5-input relation are not deployable",
        public_input_count: public_inputs.len(),
        public_inputs: public_inputs
            .into_iter()
            .map(field_element_decimal)
            .collect(),
        alpha_g1: evm_g1(&proving_key.vk.alpha_g1),
        beta_g2: evm_g2(&proving_key.vk.beta_g2),
        gamma_g2: evm_g2(&proving_key.vk.gamma_g2),
        delta_g2: evm_g2(&proving_key.vk.delta_g2),
        gamma_abc_g1: proving_key
            .vk
            .gamma_abc_g1
            .iter()
            .map(evm_g1)
            .collect(),
        proof: EvmGroth16Proof {
            a: evm_g1(&proof.a),
            b: evm_g2(&proof.b),
            c: evm_g1(&proof.c),
        },
        proof_verified,
    })
}

fn field_element_decimal<F: PrimeField>(value: F) -> String {
    value.into_bigint().to_string()
}

fn evm_g1(point: &G1Affine) -> EvmG1Point {
    EvmG1Point {
        x: field_element_decimal(point.x),
        y: field_element_decimal(point.y),
    }
}

fn evm_g2(point: &G2Affine) -> EvmG2Point {
    EvmG2Point {
        // EIP-197 encodes a * i + b, while arkworks stores c0 + c1 * u.
        x_imaginary: field_element_decimal(point.x.c1),
        x_real: field_element_decimal(point.x.c0),
        y_imaginary: field_element_decimal(point.y.c1),
        y_real: field_element_decimal(point.y.c0),
    }
}

fn validate_browser_registry_depth(depth: usize) -> Result<(usize, usize), BrowserBenchmarkError> {
    if !BROWSER_REGISTRY_DEPTHS.contains(&depth) {
        return Err(BrowserBenchmarkError::UnsupportedDepth(depth));
    }
    let profile_index = REGISTRY_DEPTH_PROFILES
        .iter()
        .position(|candidate| *candidate == depth)
        .expect("browser depth profiles are registry depth profiles");
    Ok((
        REGISTRY_DEPTH_CONSTRAINTS[profile_index],
        REGISTRY_DEPTH_WITNESS_VARIABLES[profile_index],
    ))
}

fn registry_benchmark_seed(depth: usize) -> u64 {
    0x52_45_47_49_53_54_52_59 ^ depth as u64
}

fn packed_status_benchmark_seed() -> u64 {
    0x50_41_43_4b_45_44_53_54
}

fn browser_proving_key_bytes(depth: usize) -> usize {
    let index = BROWSER_REGISTRY_DEPTHS
        .iter()
        .position(|candidate| *candidate == depth)
        .expect("validated browser registry depth");
    BROWSER_REGISTRY_PROVING_KEY_BYTES[index]
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = generateRegistryProvingKey)]
pub fn browser_generate_registry_proving_key(depth: u32) -> Result<Vec<u8>, JsValue> {
    generate_registry_proving_key(depth as usize).map_err(browser_benchmark_js_error)
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = proveRegistryDepth)]
pub fn browser_prove_registry_depth(depth: u32, proving_key: &[u8]) -> Result<String, JsValue> {
    let report = prove_registry_depth_with_key(depth as usize, proving_key)
        .map_err(browser_benchmark_js_error)?;
    serde_json::to_string(&report).map_err(|error| JsValue::from_str(&error.to_string()))
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = generatePackedStatusProvingKey)]
pub fn browser_generate_packed_status_proving_key() -> Result<Vec<u8>, JsValue> {
    generate_packed_status_proving_key().map_err(browser_benchmark_js_error)
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = provePackedStatus)]
pub fn browser_prove_packed_status(proving_key: &[u8]) -> Result<String, JsValue> {
    let report = prove_packed_status_with_key(proving_key).map_err(browser_benchmark_js_error)?;
    serde_json::to_string(&report).map_err(|error| JsValue::from_str(&error.to_string()))
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = wasmLinearMemoryBytes)]
pub fn browser_wasm_linear_memory_bytes() -> u32 {
    let memory: js_sys::WebAssembly::Memory = wasm_bindgen::memory().unchecked_into();
    let buffer: js_sys::ArrayBuffer = memory.buffer().unchecked_into();
    buffer.byte_length()
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
fn browser_benchmark_js_error(error: BrowserBenchmarkError) -> JsValue {
    JsValue::from_str(&error.to_string())
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
            Authentication::SignatureAndPackedStatus => 0x50_41_43,
        };
        let mut setup_rng = StdRng::seed_from_u64(seed);
        let setup_started = BenchmarkTimer::start();
        let (proving_key, verifying_key) =
            Groth16::<Bn254>::circuit_specific_setup(circuit.clone(), &mut setup_rng)?;
        result.setup_ms = Some(setup_started.elapsed_ms());

        let mut proof_rng = StdRng::seed_from_u64(seed ^ 0xa5_a5_a5);
        let prove_started = BenchmarkTimer::start();
        let proof = Groth16::<Bn254>::prove(&proving_key, circuit.clone(), &mut proof_rng)?;
        result.prove_ms = Some(prove_started.elapsed_ms());

        let processed = Groth16::<Bn254>::process_vk(&verifying_key)?;
        let verify_started = BenchmarkTimer::start();
        let verified = Groth16::<Bn254>::verify_with_processed_vk(
            &processed,
            &circuit.public_inputs(),
            &proof,
        )?;
        result.verify_ms = Some(verify_started.elapsed_ms());

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

fn enforce_identifier(
    high: &FpVar<CircuitField>,
    low: &FpVar<CircuitField>,
) -> Result<(), SynthesisError> {
    enforce_u128_limb(high)?;
    enforce_u128_limb(low)?;
    Boolean::enforce_kary_nand(&[high.is_zero()?, low.is_zero()?])
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

fn enforce_packed_status_nonrevocation(
    cs: ConstraintSystemRef<CircuitField>,
    config: &PoseidonConfig<CircuitField>,
    status_id_high: FpVar<CircuitField>,
    status_id_low: FpVar<CircuitField>,
    packed_status_chunk: [CircuitField; 2],
    siblings: &[CircuitField],
    expected_root: [CircuitField; 2],
) -> Result<(), SynthesisError> {
    let public_root = [
        FpVar::new_input(cs.clone(), || Ok(expected_root[0]))?,
        FpVar::new_input(cs.clone(), || Ok(expected_root[1]))?,
    ];
    enforce_packed_status_nonrevocation_with_public_root(
        cs,
        config,
        status_id_high,
        status_id_low,
        packed_status_chunk,
        siblings,
        public_root,
    )
}

fn enforce_packed_status_nonrevocation_with_public_root(
    cs: ConstraintSystemRef<CircuitField>,
    config: &PoseidonConfig<CircuitField>,
    status_id_high: FpVar<CircuitField>,
    status_id_low: FpVar<CircuitField>,
    packed_status_chunk: [CircuitField; 2],
    siblings: &[CircuitField],
    public_root: [FpVar<CircuitField>; 2],
) -> Result<(), SynthesisError> {
    status_id_high.enforce_equal(&FpVar::Constant(CircuitField::from(0u64)))?;
    let (status_id_low_bits, _) = status_id_low.to_bits_le_with_top_bits_zero(32)?;
    let chunk_vars = [
        FpVar::new_witness(cs.clone(), || Ok(packed_status_chunk[0]))?,
        FpVar::new_witness(cs.clone(), || Ok(packed_status_chunk[1]))?,
    ];
    let (chunk_low_bits, _) = chunk_vars[0].to_bits_le_with_top_bits_zero(BYTES32_LIMB_BITS)?;
    let (chunk_high_bits, _) = chunk_vars[1].to_bits_le_with_top_bits_zero(BYTES32_LIMB_BITS)?;
    let mut selected_bits = chunk_low_bits;
    selected_bits.extend(chunk_high_bits);

    // The low eight status-slot bits select one of the 256 status bits.
    // Collapse the table one selector bit at a time, rather than allocating a
    // 256-way equality test. Zero is allocated+active; one is unallocated or
    // revoked. Root construction, not this local bit check, enforces that
    // allocation events are processed in order.
    for selector in status_id_low_bits.iter().take(8) {
        selected_bits = selected_bits
            .chunks_exact(2)
            .map(|pair| selector.select(&pair[1], &pair[0]))
            .collect::<Result<Vec<_>, _>>()?;
    }
    selected_bits[0].enforce_equal(&Boolean::FALSE)?;

    let mut current = poseidon_gadget(cs.clone(), config, PACKED_STATUS_LEAF_DOMAIN, &chunk_vars)?;
    if siblings.len() != PACKED_STATUS_DEPTH {
        return Err(SynthesisError::Unsatisfiable);
    }
    for (sibling, current_is_right) in siblings
        .iter()
        .zip(status_id_low_bits.iter().skip(8).take(PACKED_STATUS_DEPTH))
    {
        let sibling = FpVar::new_witness(cs.clone(), || Ok(*sibling))?;
        let left = current_is_right.select(&sibling, &current)?;
        let right = current_is_right.select(&current, &sibling)?;
        current = poseidon_gadget(cs.clone(), config, REGISTRY_NODE_DOMAIN, &[left, right])?;
    }
    enforce_lossless_bytes32_limbs(&current, &public_root[0], &public_root[1])
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

fn packed_status_leaf_native(
    config: &PoseidonConfig<CircuitField>,
    packed_status_chunk: [CircuitField; 2],
) -> CircuitField {
    poseidon_native(config, PACKED_STATUS_LEAF_DOMAIN, &packed_status_chunk)
}

fn packed_status_chunk_with_active_slot(status_id_low: CircuitField) -> [CircuitField; 2] {
    let status_bits = status_id_low.into_bigint();
    let selected_bit = (0..8).fold(0usize, |index, bit| {
        index | (usize::from(status_bits.get_bit(bit)) << bit)
    });
    let mut limbs = [u128::MAX; 2];
    limbs[selected_bit / BYTES32_LIMB_BITS] &= !(1u128 << (selected_bit % BYTES32_LIMB_BITS));
    [CircuitField::from(limbs[0]), CircuitField::from(limbs[1])]
}

fn packed_status_path_directions_native(status_id_low: CircuitField) -> Vec<bool> {
    let status_bits = status_id_low.into_bigint();
    (8..8 + PACKED_STATUS_DEPTH)
        .map(|bit| status_bits.get_bit(bit))
        .collect()
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
        assert_eq!(report.results.len(), 4);
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
                SIGNATURE_AND_PACKED_STATUS_CONSTRAINTS,
            ],
            "constraint drift requires an explicit benchmark-report review"
        );
        assert_eq!(
            report.results[3].witness_variables, SIGNATURE_AND_PACKED_STATUS_WITNESS_VARIABLES,
            "packed-status witness drift requires an explicit browser-report review"
        );
    }

    #[test]
    fn dynamic_status_presentation_uses_the_exact_eighteen_signal_layout() {
        let circuit = DynamicStatusPresentationCircuit::fixture();
        let inputs = circuit.public_inputs();
        assert_eq!(inputs.len(), DYNAMIC_STATUS_PUBLIC_SIGNAL_COUNT);
        assert_eq!(inputs[0], CircuitField::from(1u64));
        assert_eq!(inputs[1], CircuitField::from(DYNAMIC_STATUS_CIRCUIT_ID[0]));
        assert_eq!(inputs[2], CircuitField::from(DYNAMIC_STATUS_CIRCUIT_ID[1]));
        assert_eq!(&inputs[3..5], &circuit.inner.issuer_key_id);
        assert_eq!(&inputs[5..7], &circuit.inner.expected_registry_root);
        assert_eq!(
            inputs[14],
            CircuitField::from_be_bytes_mod_order(&[0x33; 20])
        );
        assert_eq!(inputs[15], CircuitField::from(1u64));
        assert_eq!(
            inputs[16],
            CircuitField::from(DYNAMIC_STATUS_CREDENTIAL_EPOCH)
        );
        assert_eq!(inputs[17], CircuitField::from(DYNAMIC_STATUS_PUBLISHED_AT));

        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_instance_variables() - 1, 18);
        assert_eq!(
            cs.num_constraints(),
            DYNAMIC_STATUS_PRESENTATION_CONSTRAINTS,
            "constraint drift requires explicit verifier-artifact review"
        );
        assert_eq!(
            cs.num_witness_variables(),
            DYNAMIC_STATUS_PRESENTATION_WITNESS_VARIABLES,
            "witness drift requires explicit verifier-artifact review"
        );
    }

    #[test]
    fn dynamic_status_presentation_binds_scope_epoch_and_circuit() {
        for index in [1usize, 11, 16] {
            let mut circuit = DynamicStatusPresentationCircuit::fixture();
            let changed = circuit.public_signals[index] + CircuitField::from(1u64);
            circuit.set_public_signal(index, changed);
            let cs = ConstraintSystem::<CircuitField>::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(!cs.is_satisfied().unwrap(), "signal {index} must be bound");
        }
    }

    #[test]
    fn dynamic_status_presentation_rejects_the_selected_sanctions_bit() {
        let mut circuit = DynamicStatusPresentationCircuit::fixture();
        circuit.revoke_packed_status();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
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
            Authentication::SignatureAndPackedStatus,
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
    fn packed_status_rejects_the_selected_revocation_bit() {
        let mut circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
        circuit.revoke_packed_status();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn packed_status_allows_an_unrelated_slot_activation() {
        let mut circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
        circuit.activate_unrelated_packed_status_bit();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn packed_status_fixture_fails_closed_for_every_unallocated_bit() {
        let circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
        let status_low = circuit.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX].into_bigint();
        let selected_bit = (0..8).fold(0usize, |index, bit| {
            index | (usize::from(status_low.get_bit(bit)) << bit)
        });
        for bit in 0..PACKED_STATUS_BITS_PER_CHUNK {
            let limb = circuit.packed_status_chunk[bit / BYTES32_LIMB_BITS].into_bigint();
            assert_eq!(limb.get_bit(bit % BYTES32_LIMB_BITS), bit != selected_bit);
        }
    }

    #[test]
    fn packed_status_rejects_non_canonical_slot_high_bits() {
        let circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
        let valid_slot = circuit.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX];
        for (status_high, status_low) in [
            (CircuitField::from(1u64), valid_slot),
            (
                CircuitField::from(0u64),
                valid_slot + CircuitField::from(1u64 << 32),
            ),
        ] {
            let cs = ConstraintSystem::<CircuitField>::new_ref();
            let status_id_high = FpVar::new_witness(cs.clone(), || Ok(status_high)).unwrap();
            let status_id_low = FpVar::new_witness(cs.clone(), || Ok(status_low)).unwrap();
            enforce_packed_status_nonrevocation(
                cs.clone(),
                &poseidon_config(),
                status_id_high,
                status_id_low,
                circuit.packed_status_chunk,
                &circuit.registry_siblings,
                circuit.expected_registry_root,
            )
            .unwrap();
            assert!(!cs.is_satisfied().unwrap());
        }
    }

    #[test]
    fn packed_status_rejects_a_modified_path() {
        let mut circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
        circuit.tamper_registry();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn packed_status_rejects_a_non_canonical_chunk_limb() {
        let mut circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
        circuit.make_packed_status_chunk_limb_wide();
        let cs = ConstraintSystem::<CircuitField>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn packed_status_root_rejects_a_modular_alias() {
        let mut circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
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
    fn a_modified_credential_fails_all_authentication_relations() {
        for authentication in [
            Authentication::IssuerSignature,
            Authentication::ActiveRegistry,
            Authentication::SignatureAndRegistry,
            Authentication::SignatureAndPackedStatus,
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
        let packed_status = &report.results[3];
        assert!(hybrid.constraints > signature.constraints);
        assert!(hybrid.constraints > registry.constraints);
        assert_eq!(signature.public_inputs, 3);
        assert_eq!(registry.public_inputs, 5);
        assert_eq!(hybrid.public_inputs, 5);
        assert!(packed_status.constraints > signature.constraints);
        assert_eq!(packed_status.public_inputs, 5);
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
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.measurement.witness_variables)
                .collect::<Vec<_>>(),
            REGISTRY_DEPTH_WITNESS_VARIABLES,
            "depth-profile witness drift requires an explicit benchmark review"
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
    fn registry_transport_lower_bounds_are_pinned() {
        let report = run_registry_transport_estimates();
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.index_bytes)
                .collect::<Vec<_>>(),
            [4, 8, 12, 16]
        );
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.single_delta_floor_bytes)
                .collect::<Vec<_>>(),
            [1_164, 2_192, 3_220, 4_248]
        );
        assert_eq!(
            report
                .results
                .iter()
                .map(|result| result.holder_witness_floor_bytes)
                .collect::<Vec<_>>(),
            [1_092, 2_116, 3_140, 4_164]
        );
    }

    #[test]
    fn browser_prover_rejects_unsupported_profiles_before_proving() {
        assert!(matches!(
            generate_registry_proving_key(64),
            Err(BrowserBenchmarkError::UnsupportedDepth(64))
        ));
        assert!(matches!(
            prove_registry_depth_with_key(32, &[]),
            Err(BrowserBenchmarkError::UnsupportedDepth(32))
        ));
        assert!(matches!(
            prove_packed_status_with_key(&[]),
            Err(BrowserBenchmarkError::ProvingKeySizeMismatch { .. })
        ));
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
        for depth in BROWSER_REGISTRY_DEPTHS {
            let proving_key = generate_registry_proving_key(depth)
                .expect("browser profile proving key serializes");
            let report = prove_registry_depth_with_key(depth, &proving_key)
                .expect("serialized browser profile key proves and verifies");
            assert!(report.proof_verified);
            assert_eq!(report.proof_bytes, 128);
            assert_eq!(proving_key.len(), browser_proving_key_bytes(depth));
            assert_eq!(report.proving_key_bytes, proving_key.len());
        }
        let proving_key = generate_packed_status_proving_key()
            .expect("packed-status browser proving key serializes");
        let report = prove_packed_status_with_key(&proving_key)
            .expect("serialized packed-status key proves and verifies");
        assert!(report.proof_verified);
        assert_eq!(report.proof_bytes, 128);
        assert_eq!(proving_key.len(), BROWSER_PACKED_STATUS_PROVING_KEY_BYTES);
        assert_eq!(report.proving_key_bytes, proving_key.len());

        let evm_fixture = export_packed_status_evm_fixture_with_key(&proving_key)
            .expect("packed-status fixture exports in EIP-197 order");
        assert!(evm_fixture.proof_verified);
        assert_eq!(evm_fixture.public_input_count, 5);
        assert_eq!(evm_fixture.gamma_abc_g1.len(), 6);
        let serialized = serde_json::to_vec(&evm_fixture).expect("EVM fixture serializes");
        let fingerprint = serialized
            .iter()
            .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
            });
        assert_eq!(
            fingerprint, PACKED_STATUS_EVM_FIXTURE_FNV64,
            "fixture drift requires regenerating and reviewing the Solidity verifier"
        );

        let dynamic_fixture = generate_dynamic_status_evm_fixture()
            .expect("dynamic-status fixture exports in EIP-197 order");
        assert!(dynamic_fixture.proof_verified);
        assert_eq!(dynamic_fixture.public_input_count, 18);
        assert_eq!(dynamic_fixture.gamma_abc_g1.len(), 19);
        assert_eq!(
            dynamic_fixture.constraints,
            DYNAMIC_STATUS_PRESENTATION_CONSTRAINTS
        );
        assert_eq!(
            dynamic_fixture.witness_variables,
            DYNAMIC_STATUS_PRESENTATION_WITNESS_VARIABLES
        );
        let serialized = serde_json::to_vec(&dynamic_fixture).expect("EVM fixture serializes");
        let fingerprint = serialized
            .iter()
            .fold(0xcbf2_9ce4_8422_2325u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
            });
        assert_eq!(
            fingerprint, DYNAMIC_STATUS_EVM_FIXTURE_FNV64,
            "fixture drift requires regenerating and reviewing the 18-signal Solidity verifier"
        );
    }
}
