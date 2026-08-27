//! Isolated circuit-native ADR-0014 holder refresh engine.
//!
//! The production sanctions circuit crate is a frozen ceremony input. This
//! separate crate consumes only its public circuit-native types and repeats the
//! ratified Poseidon parameter derivation, so holder packaging cannot mutate
//! that frozen source manifest.

use ark_bn254::Fr as CircuitField;
use ark_crypto_primitives::sponge::{
    poseidon::{find_poseidon_ark_and_mds, PoseidonConfig, PoseidonSponge},
    CryptographicSponge, FieldBasedCryptographicSponge,
};
use ark_ec::CurveGroup;
use ark_ed_on_bn254::{EdwardsProjective, Fr as JubjubScalar};
use ark_ff::{BigInteger, PrimeField};
#[cfg(all(target_arch = "wasm32", feature = "browser"))]
use wasm_bindgen::{prelude::*, JsCast};

pub use circuit::{
    build_holder_credential_commitment, HolderCredentialCommitmentInput, PackedStatusChunk,
    PackedStatusSnapshot, PackedStatusSnapshotError, PACKED_STATUS_DEPTH,
    PRODUCTION_CRYPTO_PROFILE_ID,
};

const REGISTRY_NODE_DOMAIN: u64 = 3;
const SIGNATURE_CHALLENGE_DOMAIN: u64 = 4;
const ISSUER_KEY_DOMAIN: u64 = 5;
const PACKED_STATUS_LEAF_DOMAIN: u64 = 8;

mod holder_refresh_engine;

pub use holder_refresh_engine::{
    build_packed_status_path_json, validate_packed_status_snapshot_json,
    verify_production_vault_payload_json, HolderRefreshEngineError,
};

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

fn jubjub_scalar_from_circuit_field(value: CircuitField) -> JubjubScalar {
    JubjubScalar::from_be_bytes_mod_order(&value.into_bigint().to_bytes_be())
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

fn packed_status_leaf_native(
    config: &PoseidonConfig<CircuitField>,
    packed_status_chunk: [CircuitField; 2],
) -> CircuitField {
    poseidon_native(config, PACKED_STATUS_LEAF_DOMAIN, &packed_status_chunk)
}

fn packed_status_path_directions_native(status_id_low: CircuitField) -> Vec<bool> {
    let status_bits = status_id_low.into_bigint();
    (8..8 + PACKED_STATUS_DEPTH)
        .map(|bit| status_bits.get_bit(bit))
        .collect()
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = verifyProductionVaultPayload)]
pub fn verify_production_vault_payload_wasm(source: &str) -> Result<(), JsValue> {
    verify_production_vault_payload_json(source)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = validatePackedStatusSnapshot)]
pub fn validate_packed_status_snapshot_wasm(source: &str) -> Result<(), JsValue> {
    validate_packed_status_snapshot_json(source)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = buildPackedStatusPath)]
pub fn build_packed_status_path_wasm(source: &str, status_id: u32) -> Result<String, JsValue> {
    build_packed_status_path_json(source, status_id)
        .map_err(|error| JsValue::from_str(&error.to_string()))
}

#[cfg(all(target_arch = "wasm32", feature = "browser"))]
#[wasm_bindgen(js_name = wasmLinearMemoryBytes)]
pub fn wasm_linear_memory_bytes() -> u32 {
    let memory: js_sys::WebAssembly::Memory = wasm_bindgen::memory().unchecked_into();
    let buffer: js_sys::ArrayBuffer = memory.buffer().unchecked_into();
    buffer.byte_length()
}
