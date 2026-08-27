//! Circuit-native ADR-0014 holder-vault verification and packed-status refresh.
//!
//! This module deliberately reuses the exact Poseidon, Baby-Jubjub and sparse
//! snapshot primitives consumed by the circuit implementation. It contains no
//! network, storage, clock or admission-policy code; those remain in the
//! disposable browser Worker boundary.

use ark_ec::{twisted_edwards::Affine as TwistedEdwardsAffine, AffineRepr, CurveGroup, PrimeGroup};
use ark_ed_on_bn254::{EdwardsConfig, EdwardsProjective, Fr as JubjubScalar};
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt, str::FromStr};

use super::{
    build_holder_credential_commitment, issuer_key_digest_native, jubjub_scalar_from_circuit_field,
    merkle_root_native, packed_status_leaf_native, packed_status_path_directions_native,
    poseidon_config, poseidon_native, signature_challenge_native, CircuitField,
    HolderCredentialCommitmentInput, PackedStatusChunk, PackedStatusSnapshot,
    PackedStatusSnapshotError, PACKED_STATUS_DEPTH, PRODUCTION_CRYPTO_PROFILE_ID,
    REGISTRY_NODE_DOMAIN,
};

const PRODUCTION_VAULT_SCHEMA: &str = "org.proofofhumanity.zk-holder-production-vault-payload/1";
const PARAMETER_MANIFEST_SHA256: &str =
    "b328af00b6d2cff39b5796b5abb37019dfaad5952fe23e10ba96913ab2a624bb";
const COMMITMENT_SCHEMA: &str = "org.proofofhumanity.zk-holder-credential-commitment/1";
const PRIVATE_CREDENTIAL_SCHEMA: &str = "org.proofofhumanity.zk-private-credential/1";
const COMMITMENT_SCHEME: &str = "poseidon-bn254-arkworks-0.5-x5-rate2/1";
const ISSUER_ARTIFACT_SCHEMA: &str = "org.proofofhumanity.zk-issuer-schnorr-artifact/1";
const ISSUER_SCHEME: &str = "schnorr-babyjubjub-poseidon-sha512-nonce/1";
const STATUS_WITNESS_SCHEMA: &str = "org.proofofhumanity.zk-packed-status-witness/1";
const STATUS_WITNESS_SCHEME: &str = "poseidon-bn254-packed-status-depth24/1";
const MAX_PAYLOAD_JSON_BYTES: usize = 256 * 1024;
const MAX_SNAPSHOT_JSON_BYTES: usize = 64 * 1024 * 1024;

type BabyJubjubAffine = TwistedEdwardsAffine<EdwardsConfig>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HolderRefreshEngineError {
    InputTooLarge,
    InvalidPayload,
    InvalidCredential,
    CommitmentMismatch,
    InvalidPoint,
    InvalidSubgroup,
    IssuerKeyMismatch,
    SignatureRejected,
    StatusPathRejected,
    SnapshotRejected,
    InactiveStatus,
}

impl fmt::Display for HolderRefreshEngineError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InputTooLarge => "holder refresh input exceeds its fixed resource limit",
            Self::InvalidPayload => "holder refresh payload is invalid",
            Self::InvalidCredential => "holder refresh credential is invalid",
            Self::CommitmentMismatch => "holder refresh commitment verification failed",
            Self::InvalidPoint => "holder refresh issuer point is invalid",
            Self::InvalidSubgroup => "holder refresh issuer point is outside the prime subgroup",
            Self::IssuerKeyMismatch => "holder refresh issuer key verification failed",
            Self::SignatureRejected => "holder refresh issuer signature verification failed",
            Self::StatusPathRejected => "holder refresh status path verification failed",
            Self::SnapshotRejected => "holder refresh snapshot verification failed",
            Self::InactiveStatus => "holder refresh status is not active",
        })
    }
}

impl Error for HolderRefreshEngineError {}

impl From<PackedStatusSnapshotError> for HolderRefreshEngineError {
    fn from(_: PackedStatusSnapshotError) -> Self {
        Self::SnapshotRejected
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProductionPayloadWire {
    schema: String,
    version: u32,
    profile: ProfileWire,
    credential: HolderCredentialCommitmentInput,
    commitment: CommitmentWire,
    issuer_authentication: IssuerAuthenticationWire,
    issuance_transcript: serde_json::Value,
    status_witness: StatusWitnessWire,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProfileWire {
    profile_id: String,
    parameter_manifest_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CommitmentWire {
    schema: String,
    credential_schema: String,
    commitment_scheme: String,
    issuer_key_id: String,
    status_id: u32,
    issued_at_epoch: u32,
    commitment: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IssuerAuthenticationWire {
    schema: String,
    scheme: String,
    issuer_key_id: String,
    credential_commitment: String,
    issuer_public_key: PointWire,
    nonce_commitment: PointWire,
    response_scalar: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PointWire {
    x: String,
    y: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusWitnessWire {
    schema: String,
    scheme: String,
    issuer_key_id: String,
    status_id: u32,
    snapshot: WitnessSnapshotWire,
    chunk_limbs_little_endian: [String; 2],
    siblings_bottom_up: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WitnessSnapshotWire {
    chain_id: String,
    issuance_registry: String,
    snapshot_id: u32,
    root: String,
    activated_through_status_id: u32,
    published_at: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct DerivedStatusPathWire {
    chunk_limbs_little_endian: [String; 2],
    siblings_bottom_up: Vec<String>,
}

/// Verify every ADR-0014 cryptographic payload relation with the circuit's
/// exact native primitives. The caller has already performed the strict
/// cross-object schema parse; this second parse is intentionally independent.
pub fn verify_production_vault_payload_json(source: &str) -> Result<(), HolderRefreshEngineError> {
    if source.len() > MAX_PAYLOAD_JSON_BYTES {
        return Err(HolderRefreshEngineError::InputTooLarge);
    }
    let payload: ProductionPayloadWire =
        serde_json::from_str(source).map_err(|_| HolderRefreshEngineError::InvalidPayload)?;
    if payload.schema != PRODUCTION_VAULT_SCHEMA
        || payload.version != 1
        || payload.profile.profile_id != PRODUCTION_CRYPTO_PROFILE_ID
        || payload.profile.parameter_manifest_sha256 != PARAMETER_MANIFEST_SHA256
        || !payload.issuance_transcript.is_object()
    {
        return Err(HolderRefreshEngineError::InvalidPayload);
    }
    verify_commitment(&payload)?;
    verify_issuer_authentication(&payload)?;
    verify_stored_status_path(&payload)?;
    Ok(())
}

/// Strictly parse and reconstruct the complete sparse snapshot root. Omitted
/// nodes use the same fail-closed default tree as the circuit relation.
pub fn validate_packed_status_snapshot_json(source: &str) -> Result<(), HolderRefreshEngineError> {
    if source.len() > MAX_SNAPSHOT_JSON_BYTES {
        return Err(HolderRefreshEngineError::InputTooLarge);
    }
    let snapshot = PackedStatusSnapshot::from_json(source)?;
    let reconstructed = reconstruct_snapshot(&snapshot, None);
    if reconstructed.root != snapshot.root {
        return Err(HolderRefreshEngineError::SnapshotRejected);
    }
    Ok(())
}

/// Build the one private depth-24 path locally from a full authenticated
/// snapshot. No selector or path leaves the Worker except inside ciphertext.
pub fn build_packed_status_path_json(
    source: &str,
    status_id: u32,
) -> Result<String, HolderRefreshEngineError> {
    if source.len() > MAX_SNAPSHOT_JSON_BYTES {
        return Err(HolderRefreshEngineError::InputTooLarge);
    }
    let snapshot = PackedStatusSnapshot::from_json(source)?;
    if status_id == 0 || u64::from(status_id) >= snapshot.next_status_id {
        return Err(HolderRefreshEngineError::SnapshotRejected);
    }
    let chunk_index = status_id >> 8;
    let chunk = snapshot
        .chunks
        .binary_search_by_key(&chunk_index, |entry| entry.index)
        .ok()
        .map(|index| snapshot.chunks[index].value)
        .unwrap_or(PackedStatusChunk::FAIL_CLOSED);
    if chunk.is_revoked_or_unallocated((status_id & 0xff) as usize) {
        return Err(HolderRefreshEngineError::InactiveStatus);
    }
    let reconstructed = reconstruct_snapshot(&snapshot, Some(chunk_index));
    if reconstructed.root != snapshot.root || reconstructed.siblings.len() != PACKED_STATUS_DEPTH {
        return Err(HolderRefreshEngineError::SnapshotRejected);
    }
    serde_json::to_string(&DerivedStatusPathWire {
        chunk_limbs_little_endian: [chunk.low.to_string(), chunk.high.to_string()],
        siblings_bottom_up: reconstructed
            .siblings
            .iter()
            .map(ToString::to_string)
            .collect(),
    })
    .map_err(|_| HolderRefreshEngineError::SnapshotRejected)
}

struct ReconstructedSnapshot {
    root: CircuitField,
    siblings: Vec<CircuitField>,
}

/// Reconstruct one sparse layer at a time. Unlike the operator builder this
/// intentionally drops each completed layer, keeping peak memory O(chunks)
/// instead of retaining up to depth*chunks nodes inside the 256 MiB Worker.
fn reconstruct_snapshot(
    snapshot: &PackedStatusSnapshot,
    selected_chunk_index: Option<u32>,
) -> ReconstructedSnapshot {
    let poseidon = poseidon_config();
    let mut defaults = [CircuitField::from(0u64); PACKED_STATUS_DEPTH + 1];
    defaults[0] = packed_status_leaf_native(
        &poseidon,
        [
            CircuitField::from(PackedStatusChunk::FAIL_CLOSED.low),
            CircuitField::from(PackedStatusChunk::FAIL_CLOSED.high),
        ],
    );
    for level in 0..PACKED_STATUS_DEPTH {
        defaults[level + 1] = poseidon_native(
            &poseidon,
            REGISTRY_NODE_DOMAIN,
            &[defaults[level], defaults[level]],
        );
    }
    let mut current = snapshot
        .chunks
        .iter()
        .map(|entry| {
            (
                entry.index,
                packed_status_leaf_native(
                    &poseidon,
                    [
                        CircuitField::from(entry.value.low),
                        CircuitField::from(entry.value.high),
                    ],
                ),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut siblings = Vec::with_capacity(PACKED_STATUS_DEPTH);
    for level in 0..PACKED_STATUS_DEPTH {
        if let Some(selected) = selected_chunk_index {
            let sibling_index = (selected >> level) ^ 1;
            siblings.push(
                current
                    .get(&sibling_index)
                    .copied()
                    .unwrap_or(defaults[level]),
            );
        }
        let mut next = BTreeMap::new();
        let mut previous_parent = None;
        for index in current.keys().copied() {
            let parent = index >> 1;
            if previous_parent == Some(parent) {
                continue;
            }
            previous_parent = Some(parent);
            let left = current
                .get(&(parent << 1))
                .copied()
                .unwrap_or(defaults[level]);
            let right = current
                .get(&((parent << 1) | 1))
                .copied()
                .unwrap_or(defaults[level]);
            let value = poseidon_native(&poseidon, REGISTRY_NODE_DOMAIN, &[left, right]);
            if value != defaults[level + 1] {
                next.insert(parent, value);
            }
        }
        current = next;
    }
    ReconstructedSnapshot {
        root: current
            .get(&0)
            .copied()
            .unwrap_or(defaults[PACKED_STATUS_DEPTH]),
        siblings,
    }
}

fn verify_commitment(payload: &ProductionPayloadWire) -> Result<(), HolderRefreshEngineError> {
    let commitment = &payload.commitment;
    if commitment.schema != COMMITMENT_SCHEMA
        || commitment.credential_schema != PRIVATE_CREDENTIAL_SCHEMA
        || commitment.commitment_scheme != COMMITMENT_SCHEME
        || commitment.issuer_key_id != payload.credential.issuer_key_id
        || commitment.status_id != payload.credential.status_id
        || commitment.issued_at_epoch != payload.credential.issued_at_epoch
    {
        return Err(HolderRefreshEngineError::CommitmentMismatch);
    }
    let computed = build_holder_credential_commitment(&payload.credential)
        .map_err(|_| HolderRefreshEngineError::InvalidCredential)?;
    if computed.commitment != commitment.commitment {
        return Err(HolderRefreshEngineError::CommitmentMismatch);
    }
    Ok(())
}

fn verify_issuer_authentication(
    payload: &ProductionPayloadWire,
) -> Result<(), HolderRefreshEngineError> {
    let artifact = &payload.issuer_authentication;
    if artifact.schema != ISSUER_ARTIFACT_SCHEMA
        || artifact.scheme != ISSUER_SCHEME
        || artifact.issuer_key_id != payload.commitment.issuer_key_id
        || artifact.credential_commitment != payload.commitment.commitment
    {
        return Err(HolderRefreshEngineError::IssuerKeyMismatch);
    }
    let public_key = parse_point(&artifact.issuer_public_key)?;
    let nonce_commitment = parse_point(&artifact.nonce_commitment)?;
    let public_key_projective: EdwardsProjective = public_key.into_group();
    let nonce_projective: EdwardsProjective = nonce_commitment.into_group();
    let poseidon = poseidon_config();
    let expected_key_id = field_hex(issuer_key_digest_native(&poseidon, &public_key_projective));
    if expected_key_id != artifact.issuer_key_id {
        return Err(HolderRefreshEngineError::IssuerKeyMismatch);
    }
    let credential_commitment = parse_field_hex(&artifact.credential_commitment)?;
    let challenge = jubjub_scalar_from_circuit_field(signature_challenge_native(
        &poseidon,
        &nonce_projective,
        &public_key_projective,
        credential_commitment,
    ));
    let response = parse_scalar_decimal(&artifact.response_scalar)?;
    let recovered = EdwardsProjective::generator() * response + public_key_projective * challenge;
    if recovered.into_affine() != nonce_commitment {
        return Err(HolderRefreshEngineError::SignatureRejected);
    }
    Ok(())
}

fn verify_stored_status_path(
    payload: &ProductionPayloadWire,
) -> Result<(), HolderRefreshEngineError> {
    let witness = &payload.status_witness;
    if witness.schema != STATUS_WITNESS_SCHEMA
        || witness.scheme != STATUS_WITNESS_SCHEME
        || witness.issuer_key_id != payload.commitment.issuer_key_id
        || witness.status_id != payload.credential.status_id
        || witness.snapshot.activated_through_status_id < witness.status_id
        || witness.snapshot.chain_id.is_empty()
        || witness.snapshot.issuance_registry.is_empty()
        || witness.snapshot.snapshot_id == 0
        || witness.snapshot.published_at.is_empty()
        || witness.siblings_bottom_up.len() != PACKED_STATUS_DEPTH
    {
        return Err(HolderRefreshEngineError::StatusPathRejected);
    }
    let low = parse_u128_decimal(&witness.chunk_limbs_little_endian[0])?;
    let high = parse_u128_decimal(&witness.chunk_limbs_little_endian[1])?;
    let selected = witness.status_id & 0xff;
    let selected_is_set = if selected < 128 {
        low & (1u128 << selected) != 0
    } else {
        high & (1u128 << (selected - 128)) != 0
    };
    if selected_is_set {
        return Err(HolderRefreshEngineError::InactiveStatus);
    }
    let siblings = witness
        .siblings_bottom_up
        .iter()
        .map(|value| parse_field_decimal(value))
        .collect::<Result<Vec<_>, _>>()?;
    let poseidon = poseidon_config();
    let leaf = packed_status_leaf_native(
        &poseidon,
        [CircuitField::from(low), CircuitField::from(high)],
    );
    let directions = packed_status_path_directions_native(CircuitField::from(witness.status_id));
    let root = merkle_root_native(&poseidon, leaf, &siblings, &directions);
    if field_hex(root) != witness.snapshot.root {
        return Err(HolderRefreshEngineError::StatusPathRejected);
    }
    Ok(())
}

fn parse_point(wire: &PointWire) -> Result<BabyJubjubAffine, HolderRefreshEngineError> {
    let point = BabyJubjubAffine::new_unchecked(
        parse_field_decimal(&wire.x)?,
        parse_field_decimal(&wire.y)?,
    );
    if point.is_zero() || !point.is_on_curve() {
        return Err(HolderRefreshEngineError::InvalidPoint);
    }
    if !point.is_in_correct_subgroup_assuming_on_curve() {
        return Err(HolderRefreshEngineError::InvalidSubgroup);
    }
    Ok(point)
}

fn parse_scalar_decimal(value: &str) -> Result<JubjubScalar, HolderRefreshEngineError> {
    if !canonical_decimal(value) {
        return Err(HolderRefreshEngineError::SignatureRejected);
    }
    let scalar =
        JubjubScalar::from_str(value).map_err(|_| HolderRefreshEngineError::SignatureRejected)?;
    if scalar.to_string() != value {
        return Err(HolderRefreshEngineError::SignatureRejected);
    }
    Ok(scalar)
}

fn parse_field_decimal(value: &str) -> Result<CircuitField, HolderRefreshEngineError> {
    if !canonical_decimal(value) {
        return Err(HolderRefreshEngineError::InvalidPayload);
    }
    let field =
        CircuitField::from_str(value).map_err(|_| HolderRefreshEngineError::InvalidPayload)?;
    if field.to_string() != value {
        return Err(HolderRefreshEngineError::InvalidPayload);
    }
    Ok(field)
}

fn parse_u128_decimal(value: &str) -> Result<u128, HolderRefreshEngineError> {
    if !canonical_decimal(value) {
        return Err(HolderRefreshEngineError::StatusPathRejected);
    }
    let parsed = value
        .parse::<u128>()
        .map_err(|_| HolderRefreshEngineError::StatusPathRejected)?;
    if parsed.to_string() != value {
        return Err(HolderRefreshEngineError::StatusPathRejected);
    }
    Ok(parsed)
}

fn parse_field_hex(value: &str) -> Result<CircuitField, HolderRefreshEngineError> {
    if value.len() != 66 || !value.starts_with("0x") {
        return Err(HolderRefreshEngineError::InvalidPayload);
    }
    let mut bytes = [0u8; 32];
    for (index, output) in bytes.iter_mut().enumerate() {
        let start = 2 + index * 2;
        *output = u8::from_str_radix(&value[start..start + 2], 16)
            .map_err(|_| HolderRefreshEngineError::InvalidPayload)?;
    }
    let field = CircuitField::from_be_bytes_mod_order(&bytes);
    if field_hex(field) != value {
        return Err(HolderRefreshEngineError::InvalidPayload);
    }
    Ok(field)
}

fn field_hex(value: CircuitField) -> String {
    let encoded = value.into_bigint().to_bytes_be();
    let mut result = String::from("0x");
    for _ in 0..32 - encoded.len() {
        result.push_str("00");
    }
    for byte in encoded {
        use std::fmt::Write;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn canonical_decimal(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn production_payload() -> Value {
        serde_json::from_str::<Value>(include_str!(
            "../../../fixtures/v2-identity/production-vault-status-v1.json"
        ))
        .unwrap()["payload"]
            .clone()
    }

    #[test]
    fn production_vector_verifies_with_circuit_native_primitives() {
        verify_production_vault_payload_json(&production_payload().to_string()).unwrap();
    }

    #[test]
    fn commitment_signature_and_path_mutations_fail_closed() {
        let baseline = production_payload();
        for pointer in [
            "/credential/holderSecret",
            "/issuerAuthentication/responseScalar",
            "/statusWitness/siblingsBottomUp/0",
        ] {
            let mut changed = baseline.clone();
            *changed.pointer_mut(pointer).unwrap() = json!("1");
            assert!(verify_production_vault_payload_json(&changed.to_string()).is_err());
        }
    }

    #[test]
    fn invalid_and_non_subgroup_points_are_rejected() {
        let mut invalid = production_payload();
        invalid["issuerAuthentication"]["issuerPublicKey"] = json!({"x":"0","y":"0"});
        assert_eq!(
            verify_production_vault_payload_json(&invalid.to_string()),
            Err(HolderRefreshEngineError::InvalidPoint)
        );

        // (0, -1) is the Baby-Jubjub order-two point: on curve, nonzero and
        // deliberately outside the prime-order subgroup.
        let mut torsion = production_payload();
        torsion["issuerAuthentication"]["issuerPublicKey"] = json!({
            "x": "0",
            "y": (-CircuitField::from(1u64)).to_string()
        });
        assert_eq!(
            verify_production_vault_payload_json(&torsion.to_string()),
            Err(HolderRefreshEngineError::InvalidSubgroup)
        );
    }

    #[test]
    fn sparse_snapshot_validation_and_path_are_exact() {
        let snapshot = include_str!("../../v2-crypto-bench/fixtures/packed-status-snapshot.json");
        validate_packed_status_snapshot_json(snapshot).unwrap();
        let path: Value =
            serde_json::from_str(&build_packed_status_path_json(snapshot, 2).unwrap()).unwrap();
        assert_eq!(
            path["chunkLimbsLittleEndian"][0],
            (u128::MAX - 4).to_string()
        );
        assert_eq!(path["chunkLimbsLittleEndian"][1], u128::MAX.to_string());
        assert_eq!(path["siblingsBottomUp"].as_array().unwrap().len(), 24);
        assert!(build_packed_status_path_json(snapshot, 0).is_err());
        assert!(build_packed_status_path_json(snapshot, 1).is_err());
        assert!(build_packed_status_path_json(snapshot, 3).is_err());
    }
}
