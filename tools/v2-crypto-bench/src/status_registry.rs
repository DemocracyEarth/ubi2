//! Transport-neutral active-credential registry and witness-update prototype.
//!
//! The registry publishes the same delta feed to every holder. A client applies
//! all deltas since its local witness epoch and checks the result against an
//! independently accepted checkpoint. It never sends its private `statusId` to
//! a witness endpoint. Root governance and authenticated transport remain out
//! of scope for this Stage-1 research harness.

use super::{
    active_status_leaf_native, poseidon_config, poseidon_native, status_path_index_native,
    StatusField, REGISTRY_DEPTH, REGISTRY_NODE_DOMAIN,
};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, error::Error, fmt};

pub const STATUS_REGISTRY_DELTA_SCHEMA: &str = "org.proofofhumanity.v2-status-registry-delta/1";
pub const STATUS_REGISTRY_DELTA_MAX_JSON_BYTES: usize = 4_096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatusCheckpoint {
    pub epoch: u32,
    pub root: StatusField,
}

/// Public, transport-neutral update. It contains no raw status identifier or
/// credential commitment. The old/new leaf and sibling path let every holder
/// independently recompute both declared roots before applying the update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusRegistryDelta {
    pub schema: &'static str,
    pub from: StatusCheckpoint,
    pub to: StatusCheckpoint,
    pub changed_index: u32,
    pub old_leaf: StatusField,
    pub new_leaf: StatusField,
    pub siblings: [StatusField; REGISTRY_DEPTH],
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct StatusRegistryDeltaWire {
    schema: String,
    from_epoch: u32,
    from_root: String,
    to_epoch: u32,
    to_root: String,
    changed_index: u32,
    old_leaf: String,
    new_leaf: String,
    siblings: Vec<String>,
}

impl StatusRegistryDelta {
    /// Canonical JSON transport encoding. Every field value is a lowercase,
    /// zero-padded bytes32 string; unknown fields and modular aliases reject.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(&StatusRegistryDeltaWire {
            schema: self.schema.to_owned(),
            from_epoch: self.from.epoch,
            from_root: field_to_hex(self.from.root),
            to_epoch: self.to.epoch,
            to_root: field_to_hex(self.to.root),
            changed_index: self.changed_index,
            old_leaf: field_to_hex(self.old_leaf),
            new_leaf: field_to_hex(self.new_leaf),
            siblings: self.siblings.iter().copied().map(field_to_hex).collect(),
        })
    }

    /// Decode untrusted JSON into a strictly validated delta. Structural Merkle
    /// validity is checked later against the holder's current witness and an
    /// independently accepted checkpoint by [`refresh_status_witness`].
    pub fn from_json(json: &str) -> Result<Self, StatusRegistryError> {
        if json.len() > STATUS_REGISTRY_DELTA_MAX_JSON_BYTES {
            return Err(StatusRegistryError::InvalidDeltaEncoding);
        }
        let wire: StatusRegistryDeltaWire =
            serde_json::from_str(json).map_err(|_| StatusRegistryError::InvalidDeltaEncoding)?;
        if wire.schema != STATUS_REGISTRY_DELTA_SCHEMA || wire.siblings.len() != REGISTRY_DEPTH {
            return Err(StatusRegistryError::InvalidDeltaEncoding);
        }
        let siblings = wire
            .siblings
            .iter()
            .map(|value| field_from_hex(value))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .map_err(|_| StatusRegistryError::InvalidDeltaEncoding)?;
        Ok(Self {
            schema: STATUS_REGISTRY_DELTA_SCHEMA,
            from: StatusCheckpoint {
                epoch: wire.from_epoch,
                root: field_from_hex(&wire.from_root)?,
            },
            to: StatusCheckpoint {
                epoch: wire.to_epoch,
                root: field_from_hex(&wire.to_root)?,
            },
            changed_index: wire.changed_index,
            old_leaf: field_from_hex(&wire.old_leaf)?,
            new_leaf: field_from_hex(&wire.new_leaf)?,
            siblings,
        })
    }
}

/// Holder-private state. `leaf_index` and the siblings must remain in the
/// encrypted vault/prover boundary because they can become correlating data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusWitness {
    pub epoch: u32,
    pub root: StatusField,
    pub leaf_index: u32,
    pub active_leaf: StatusField,
    pub siblings: [StatusField; REGISTRY_DEPTH],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatusActivation {
    pub delta: StatusRegistryDelta,
    pub witness: StatusWitness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StatusRegistryError {
    NonCanonicalStatusId,
    ZeroStatusId,
    StatusAlreadyRegistered,
    StatusIndexCollision,
    UnknownStatus,
    CredentialCommitmentMismatch,
    CredentialRevoked,
    StatusAlreadyRevoked,
    EpochOverflow,
    WitnessEpochAhead,
    DeltaGap,
    DeltaRootMismatch,
    WitnessRootMismatch,
    AcceptedCheckpointMismatch,
    CredentialStatusChanged,
    InvalidDeltaEncoding,
}

impl fmt::Display for StatusRegistryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::NonCanonicalStatusId => "status id limbs must be unsigned 128-bit integers",
            Self::ZeroStatusId => "status id must not be zero",
            Self::StatusAlreadyRegistered => "status id is already registered",
            Self::StatusIndexCollision => "status id collides with a reserved registry index",
            Self::UnknownStatus => "credential status is not registered",
            Self::CredentialCommitmentMismatch => {
                "credential commitment does not match the registered status"
            }
            Self::CredentialRevoked => "credential status is revoked",
            Self::StatusAlreadyRevoked => "credential status is already revoked",
            Self::EpochOverflow => "status registry epoch overflow",
            Self::WitnessEpochAhead => "witness epoch is ahead of the registry",
            Self::DeltaGap => "status delta sequence has a gap or is out of order",
            Self::DeltaRootMismatch => "status delta does not reproduce its declared root",
            Self::WitnessRootMismatch => {
                "saved status witness does not reproduce its declared root"
            }
            Self::AcceptedCheckpointMismatch => {
                "refreshed witness does not match the independently accepted checkpoint"
            }
            Self::CredentialStatusChanged => {
                "the holder credential's own status leaf changed unexpectedly"
            }
            Self::InvalidDeltaEncoding => "status delta encoding is invalid or non-canonical",
        })
    }
}

impl Error for StatusRegistryError {}

#[derive(Clone, Debug)]
struct StatusRecord {
    status_id: [StatusField; 2],
    credential_commitment: StatusField,
    active: bool,
}

/// In-memory sparse Merkle registry used to exercise the operational update
/// model. Production persistence, authorization, root publication, signatures,
/// and retention policy are deliberately not implied by this type.
pub struct StatusRegistry {
    poseidon: PoseidonConfig<StatusField>,
    defaults: [StatusField; REGISTRY_DEPTH + 1],
    nodes: BTreeMap<(usize, u32), StatusField>,
    records: BTreeMap<u32, StatusRecord>,
    history: Vec<StatusRegistryDelta>,
    epoch: u32,
}

impl Default for StatusRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl StatusRegistry {
    pub fn new() -> Self {
        let poseidon = poseidon_config();
        let mut defaults = [StatusField::from(0u64); REGISTRY_DEPTH + 1];
        for level in 0..REGISTRY_DEPTH {
            defaults[level + 1] = registry_node(&poseidon, defaults[level], defaults[level]);
        }
        Self {
            poseidon,
            defaults,
            nodes: BTreeMap::new(),
            records: BTreeMap::new(),
            history: Vec::new(),
            epoch: 0,
        }
    }

    pub fn checkpoint(&self) -> StatusCheckpoint {
        StatusCheckpoint {
            epoch: self.epoch,
            root: self.root(),
        }
    }

    pub fn activate(
        &mut self,
        status_id: [StatusField; 2],
        credential_commitment: StatusField,
    ) -> Result<StatusActivation, StatusRegistryError> {
        validate_status_id(status_id)?;
        let index = status_path_index_native(&self.poseidon, status_id);
        if let Some(existing) = self.records.get(&index) {
            return Err(if existing.status_id == status_id {
                StatusRegistryError::StatusAlreadyRegistered
            } else {
                StatusRegistryError::StatusIndexCollision
            });
        }
        self.next_epoch()?;

        let active_leaf =
            active_status_leaf_native(&self.poseidon, status_id, credential_commitment);
        let delta = self.commit_leaf(index, active_leaf);
        self.records.insert(
            index,
            StatusRecord {
                status_id,
                credential_commitment,
                active: true,
            },
        );
        let witness = self.witness(status_id, credential_commitment)?;
        Ok(StatusActivation { delta, witness })
    }

    pub fn revoke(
        &mut self,
        status_id: [StatusField; 2],
    ) -> Result<StatusRegistryDelta, StatusRegistryError> {
        validate_status_id(status_id)?;
        let index = status_path_index_native(&self.poseidon, status_id);
        let record = self
            .records
            .get(&index)
            .ok_or(StatusRegistryError::UnknownStatus)?;
        if record.status_id != status_id {
            return Err(StatusRegistryError::UnknownStatus);
        }
        if !record.active {
            return Err(StatusRegistryError::StatusAlreadyRevoked);
        }
        self.next_epoch()?;

        let delta = self.commit_leaf(index, StatusField::from(0u64));
        self.records
            .get_mut(&index)
            .expect("record was checked before the Merkle update")
            .active = false;
        Ok(delta)
    }

    pub fn witness(
        &self,
        status_id: [StatusField; 2],
        credential_commitment: StatusField,
    ) -> Result<StatusWitness, StatusRegistryError> {
        validate_status_id(status_id)?;
        let leaf_index = status_path_index_native(&self.poseidon, status_id);
        let record = self
            .records
            .get(&leaf_index)
            .ok_or(StatusRegistryError::UnknownStatus)?;
        if record.status_id != status_id {
            return Err(StatusRegistryError::UnknownStatus);
        }
        if !record.active {
            return Err(StatusRegistryError::CredentialRevoked);
        }
        if record.credential_commitment != credential_commitment {
            return Err(StatusRegistryError::CredentialCommitmentMismatch);
        }

        let siblings = std::array::from_fn(|level| {
            let sibling_index = (leaf_index >> level) ^ 1;
            self.node(level, sibling_index)
        });
        let active_leaf =
            active_status_leaf_native(&self.poseidon, status_id, credential_commitment);
        let witness = StatusWitness {
            epoch: self.epoch,
            root: self.root(),
            leaf_index,
            active_leaf,
            siblings,
        };
        debug_assert_eq!(root_from_witness(&self.poseidon, &witness), witness.root);
        Ok(witness)
    }

    /// Public feed since `epoch`; no holder identifier is accepted by this API.
    pub fn deltas_since(&self, epoch: u32) -> Result<&[StatusRegistryDelta], StatusRegistryError> {
        if epoch > self.epoch {
            return Err(StatusRegistryError::WitnessEpochAhead);
        }
        Ok(&self.history[epoch as usize..])
    }

    fn root(&self) -> StatusField {
        self.node(REGISTRY_DEPTH, 0)
    }

    fn node(&self, level: usize, index: u32) -> StatusField {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.defaults[level])
    }

    fn next_epoch(&self) -> Result<u32, StatusRegistryError> {
        self.epoch
            .checked_add(1)
            .ok_or(StatusRegistryError::EpochOverflow)
    }

    fn commit_leaf(&mut self, changed_index: u32, new_leaf: StatusField) -> StatusRegistryDelta {
        let from = self.checkpoint();
        let old_leaf = self.node(0, changed_index);
        let siblings = std::array::from_fn(|level| {
            let sibling_index = (changed_index >> level) ^ 1;
            self.node(level, sibling_index)
        });
        self.set_node(0, changed_index, new_leaf);

        let mut current = new_leaf;
        let mut current_index = changed_index;
        for level in 0..REGISTRY_DEPTH {
            let sibling = self.node(level, current_index ^ 1);
            current = if current_index & 1 == 0 {
                registry_node(&self.poseidon, current, sibling)
            } else {
                registry_node(&self.poseidon, sibling, current)
            };
            current_index >>= 1;
            self.set_node(level + 1, current_index, current);
        }

        self.epoch = self
            .epoch
            .checked_add(1)
            .expect("callers check epoch capacity before committing");
        let to = self.checkpoint();
        let delta = StatusRegistryDelta {
            schema: STATUS_REGISTRY_DELTA_SCHEMA,
            from,
            to,
            changed_index,
            old_leaf,
            new_leaf,
            siblings,
        };
        self.history.push(delta.clone());
        delta
    }

    fn set_node(&mut self, level: usize, index: u32, value: StatusField) {
        if value == self.defaults[level] {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), value);
        }
    }
}

/// Apply an unkeyed delta batch without mutating the caller's old witness. The
/// returned witness is usable only when every delta is contiguous and its final
/// root equals the independently accepted checkpoint.
pub fn refresh_status_witness(
    witness: &StatusWitness,
    deltas: &[StatusRegistryDelta],
    accepted: StatusCheckpoint,
) -> Result<StatusWitness, StatusRegistryError> {
    let poseidon = poseidon_config();
    if root_from_witness(&poseidon, witness) != witness.root {
        return Err(StatusRegistryError::WitnessRootMismatch);
    }
    let mut refreshed = witness.clone();

    for delta in deltas {
        let expected_to_epoch = delta
            .from
            .epoch
            .checked_add(1)
            .ok_or(StatusRegistryError::DeltaGap)?;
        if delta.schema != STATUS_REGISTRY_DELTA_SCHEMA
            || delta.from.epoch != refreshed.epoch
            || delta.to.epoch != expected_to_epoch
        {
            return Err(StatusRegistryError::DeltaGap);
        }
        if delta.from.root != refreshed.root
            || root_from_path(
                &poseidon,
                delta.old_leaf,
                delta.changed_index,
                &delta.siblings,
            ) != delta.from.root
            || root_from_path(
                &poseidon,
                delta.new_leaf,
                delta.changed_index,
                &delta.siblings,
            ) != delta.to.root
        {
            return Err(StatusRegistryError::DeltaRootMismatch);
        }
        if delta.changed_index == refreshed.leaf_index {
            return Err(if delta.new_leaf == StatusField::from(0u64) {
                StatusRegistryError::CredentialRevoked
            } else {
                StatusRegistryError::CredentialStatusChanged
            });
        }

        let difference = delta.changed_index ^ refreshed.leaf_index;
        let divergence = (u32::BITS - 1 - difference.leading_zeros()) as usize;
        refreshed.siblings[divergence] = subtree_from_path(
            &poseidon,
            delta.new_leaf,
            delta.changed_index,
            &delta.siblings,
            divergence,
        );
        refreshed.root = root_from_witness(&poseidon, &refreshed);
        refreshed.epoch = delta.to.epoch;
        if refreshed.root != delta.to.root {
            return Err(StatusRegistryError::DeltaRootMismatch);
        }
    }

    if refreshed.epoch != accepted.epoch || refreshed.root != accepted.root {
        return Err(StatusRegistryError::AcceptedCheckpointMismatch);
    }
    Ok(refreshed)
}

fn validate_status_id(status_id: [StatusField; 2]) -> Result<(), StatusRegistryError> {
    if status_id
        .iter()
        .any(|limb| limb.into_bigint().num_bits() > 128)
    {
        return Err(StatusRegistryError::NonCanonicalStatusId);
    }
    if status_id == [StatusField::from(0u64); 2] {
        return Err(StatusRegistryError::ZeroStatusId);
    }
    Ok(())
}

fn field_to_hex(value: StatusField) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let bytes = value.into_bigint().to_bytes_be();
    let mut encoded = String::with_capacity(66);
    encoded.push_str("0x");
    for _ in bytes.len()..32 {
        encoded.push_str("00");
    }
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn field_from_hex(encoded: &str) -> Result<StatusField, StatusRegistryError> {
    if encoded.len() != 66 || !encoded.starts_with("0x") {
        return Err(StatusRegistryError::InvalidDeltaEncoding);
    }
    let mut bytes = [0u8; 32];
    for (index, pair) in encoded.as_bytes()[2..].chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    let field = StatusField::from_be_bytes_mod_order(&bytes);
    if field_to_hex(field) != encoded {
        return Err(StatusRegistryError::InvalidDeltaEncoding);
    }
    Ok(field)
}

fn hex_nibble(value: u8) -> Result<u8, StatusRegistryError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(StatusRegistryError::InvalidDeltaEncoding),
    }
}

fn registry_node(
    poseidon: &PoseidonConfig<StatusField>,
    left: StatusField,
    right: StatusField,
) -> StatusField {
    poseidon_native(poseidon, REGISTRY_NODE_DOMAIN, &[left, right])
}

fn root_from_witness(
    poseidon: &PoseidonConfig<StatusField>,
    witness: &StatusWitness,
) -> StatusField {
    witness
        .siblings
        .iter()
        .enumerate()
        .fold(witness.active_leaf, |current, (level, sibling)| {
            if witness.leaf_index & (1u32 << level) == 0 {
                registry_node(poseidon, current, *sibling)
            } else {
                registry_node(poseidon, *sibling, current)
            }
        })
}

fn root_from_path(
    poseidon: &PoseidonConfig<StatusField>,
    leaf: StatusField,
    leaf_index: u32,
    siblings: &[StatusField; REGISTRY_DEPTH],
) -> StatusField {
    subtree_from_path(poseidon, leaf, leaf_index, siblings, REGISTRY_DEPTH)
}

fn subtree_from_path(
    poseidon: &PoseidonConfig<StatusField>,
    leaf: StatusField,
    leaf_index: u32,
    siblings: &[StatusField; REGISTRY_DEPTH],
    levels: usize,
) -> StatusField {
    siblings
        .iter()
        .take(levels)
        .enumerate()
        .fold(leaf, |current, (level, sibling)| {
            if leaf_index & (1u32 << level) == 0 {
                registry_node(poseidon, current, *sibling)
            } else {
                registry_node(poseidon, *sibling, current)
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(value: u64) -> [StatusField; 2] {
        [StatusField::from(0u64), StatusField::from(value)]
    }

    fn commitment(value: u64) -> StatusField {
        StatusField::from(value)
    }

    #[test]
    fn activation_returns_a_current_witness_and_unkeyed_public_delta() {
        let mut registry = StatusRegistry::new();
        let activation = registry.activate(status(1), commitment(101)).unwrap();

        assert_eq!(activation.delta.from.epoch, 0);
        assert_eq!(activation.delta.changed_index, 1_695_650_145);
        assert_eq!(
            field_to_hex(activation.delta.from.root),
            "0x09406479041c48f083c90ecc97aeec419279ef6f505bc99fb5b461aae1a8f8cc"
        );
        assert_eq!(
            field_to_hex(activation.delta.to.root),
            "0x259abca35d2066c9f1a6f39115ef08700acdc2e0dd6f43c38877b8f28e025794"
        );
        assert_eq!(
            field_to_hex(activation.delta.new_leaf),
            "0x2378d46cc815434dc7e6f0317674e03e9509ffa31534da668c5369c65c2dfb1f"
        );
        assert_eq!(activation.delta.to, registry.checkpoint());
        assert_eq!(activation.witness.epoch, 1);
        assert_eq!(activation.witness.root, registry.checkpoint().root);
        assert_eq!(registry.deltas_since(0).unwrap(), &[activation.delta]);
    }

    #[test]
    fn delta_json_round_trips_canonically_and_rejects_untrusted_variants() {
        let mut registry = StatusRegistry::new();
        let delta = registry.activate(status(1), commitment(101)).unwrap().delta;
        let json = delta.to_json().unwrap();
        assert_eq!(StatusRegistryDelta::from_json(&json).unwrap(), delta);
        assert!(json.contains(STATUS_REGISTRY_DELTA_SCHEMA));
        assert!(!json.contains("statusId"));
        assert!(!json.contains("credentialCommitment"));

        let unknown_field = json.replacen('{', "{\"unexpected\":true,", 1);
        assert_eq!(
            StatusRegistryDelta::from_json(&unknown_field),
            Err(StatusRegistryError::InvalidDeltaEncoding)
        );
        let uppercase = json.replacen("0x", "0X", 1);
        assert_eq!(
            StatusRegistryDelta::from_json(&uppercase),
            Err(StatusRegistryError::InvalidDeltaEncoding)
        );
        assert_eq!(
            StatusRegistryDelta::from_json(&" ".repeat(STATUS_REGISTRY_DELTA_MAX_JSON_BYTES + 1)),
            Err(StatusRegistryError::InvalidDeltaEncoding)
        );
    }

    #[test]
    fn offline_holder_refreshes_through_unrelated_activation_and_revocation() {
        let mut registry = StatusRegistry::new();
        let holder = registry.activate(status(1), commitment(101)).unwrap();
        registry.activate(status(2), commitment(202)).unwrap();
        registry.activate(status(3), commitment(303)).unwrap();
        registry.revoke(status(2)).unwrap();

        let refreshed = refresh_status_witness(
            &holder.witness,
            registry.deltas_since(holder.witness.epoch).unwrap(),
            registry.checkpoint(),
        )
        .unwrap();
        assert_eq!(refreshed.epoch, 4);
        assert_eq!(refreshed.root, registry.checkpoint().root);
    }

    #[test]
    fn batched_refresh_survives_many_unrelated_updates() {
        let mut registry = StatusRegistry::new();
        let holder = registry.activate(status(1), commitment(101)).unwrap();
        for value in 2..66 {
            registry
                .activate(status(value), commitment(value * 101))
                .unwrap();
        }
        for value in (2..66).step_by(3) {
            registry.revoke(status(value)).unwrap();
        }

        let refreshed = refresh_status_witness(
            &holder.witness,
            registry.deltas_since(holder.witness.epoch).unwrap(),
            registry.checkpoint(),
        )
        .unwrap();
        assert_eq!(
            refreshed,
            registry.witness(status(1), commitment(101)).unwrap()
        );
    }

    #[test]
    fn revocation_fails_closed_for_stale_and_new_witness_requests() {
        let mut registry = StatusRegistry::new();
        let holder = registry.activate(status(1), commitment(101)).unwrap();
        registry.revoke(status(1)).unwrap();

        assert_eq!(
            registry.witness(status(1), commitment(101)),
            Err(StatusRegistryError::CredentialRevoked)
        );
        assert_eq!(
            refresh_status_witness(
                &holder.witness,
                registry.deltas_since(holder.witness.epoch).unwrap(),
                registry.checkpoint(),
            ),
            Err(StatusRegistryError::CredentialRevoked)
        );
    }

    #[test]
    fn missing_reordered_or_tampered_deltas_fail_without_a_partial_witness() {
        let mut registry = StatusRegistry::new();
        let holder = registry.activate(status(1), commitment(101)).unwrap();
        registry.activate(status(2), commitment(202)).unwrap();
        registry.activate(status(3), commitment(303)).unwrap();
        let deltas = registry.deltas_since(holder.witness.epoch).unwrap();

        assert_eq!(
            refresh_status_witness(&holder.witness, &deltas[1..], registry.checkpoint()),
            Err(StatusRegistryError::DeltaGap)
        );

        let reordered = [deltas[1].clone(), deltas[0].clone()];
        assert_eq!(
            refresh_status_witness(&holder.witness, &reordered, registry.checkpoint()),
            Err(StatusRegistryError::DeltaGap)
        );

        let mut tampered = deltas.to_vec();
        let difference = tampered[0].changed_index ^ holder.witness.leaf_index;
        let divergence = (u32::BITS - 1 - difference.leading_zeros()) as usize;
        tampered[0].siblings[divergence] += StatusField::from(1u64);
        assert_eq!(
            refresh_status_witness(&holder.witness, &tampered, registry.checkpoint()),
            Err(StatusRegistryError::DeltaRootMismatch)
        );

        assert_eq!(holder.witness.epoch, 1, "the original witness is immutable");
    }

    #[test]
    fn final_root_must_come_from_an_independently_accepted_checkpoint() {
        let mut registry = StatusRegistry::new();
        let holder = registry.activate(status(1), commitment(101)).unwrap();
        registry.activate(status(2), commitment(202)).unwrap();
        let mut wrong = registry.checkpoint();
        wrong.root += StatusField::from(1u64);

        assert_eq!(
            refresh_status_witness(
                &holder.witness,
                registry.deltas_since(holder.witness.epoch).unwrap(),
                wrong,
            ),
            Err(StatusRegistryError::AcceptedCheckpointMismatch)
        );
    }

    #[test]
    fn corrupted_saved_witness_fails_even_when_no_delta_is_needed() {
        let mut registry = StatusRegistry::new();
        let mut holder = registry
            .activate(status(1), commitment(101))
            .unwrap()
            .witness;
        holder.siblings[0] += StatusField::from(1u64);

        assert_eq!(
            refresh_status_witness(&holder, &[], registry.checkpoint()),
            Err(StatusRegistryError::WitnessRootMismatch)
        );
    }

    #[test]
    fn status_lifecycle_and_private_inputs_are_strict() {
        let mut registry = StatusRegistry::new();
        assert_eq!(
            registry.activate([StatusField::from(0u64); 2], commitment(101)),
            Err(StatusRegistryError::ZeroStatusId)
        );

        registry.activate(status(1), commitment(101)).unwrap();
        assert_eq!(
            registry.activate(status(1), commitment(101)),
            Err(StatusRegistryError::StatusAlreadyRegistered)
        );
        assert_eq!(
            registry.witness(status(1), commitment(999)),
            Err(StatusRegistryError::CredentialCommitmentMismatch)
        );
        registry.revoke(status(1)).unwrap();
        assert_eq!(
            registry.revoke(status(1)),
            Err(StatusRegistryError::StatusAlreadyRevoked)
        );

        let wide = StatusField::from_be_bytes_mod_order(&[
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        ]);
        assert_eq!(
            registry.activate([wide, StatusField::from(1u64)], commitment(202)),
            Err(StatusRegistryError::NonCanonicalStatusId)
        );
    }
}
