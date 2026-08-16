//! Deterministic public packed-status snapshot builder.
//!
//! The builder consumes an already-filtered, finalized source-chain event
//! stream for one issuer namespace. It deliberately has no RPC, signer or
//! persistence dependency: those operational boundaries remain visible to the
//! caller, while this module owns the consensus-sensitive bit layout, Poseidon
//! tree and fork rollback rules shared with the research circuit.

use super::{
    packed_status_leaf_native, poseidon_config, poseidon_native, StatusField,
    PACKED_STATUS_BITS_PER_CHUNK, PACKED_STATUS_DEPTH, REGISTRY_NODE_DOMAIN,
};
use ark_crypto_primitives::sponge::poseidon::PoseidonConfig;
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    fmt,
};

pub const PACKED_STATUS_SOURCE_SCHEMA: &str = "org.proofofhumanity.v2-packed-status-source/1";
pub const PACKED_STATUS_SNAPSHOT_SCHEMA: &str = "org.proofofhumanity.v2-packed-status-snapshot/1";
pub const PACKED_STATUS_WITNESS_SCHEMA: &str = "org.proofofhumanity.v2-packed-status-witness/1";

const ZERO_HASH: [u8; 32] = [0u8; 32];
const ZERO_ADDRESS: [u8; 20] = [0u8; 20];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SourceBlockRef {
    pub number: u64,
    pub hash: [u8; 32],
    pub parent_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PackedStatusSourceEvent {
    CredentialAllocated {
        log_index: u32,
        issuer_key_id: [u8; 32],
        status_id: u32,
    },
    CredentialRevoked {
        log_index: u32,
        issuer_key_id: [u8; 32],
        status_id: u32,
        /// Nonzero content address of the independently authorized revocation.
        /// This builder records the boundary but does not decide authorization.
        authorization_reference: [u8; 32],
    },
}

impl PackedStatusSourceEvent {
    fn log_index(self) -> u32 {
        match self {
            Self::CredentialAllocated { log_index, .. }
            | Self::CredentialRevoked { log_index, .. } => log_index,
        }
    }

    fn issuer_key_id(self) -> [u8; 32] {
        match self {
            Self::CredentialAllocated { issuer_key_id, .. }
            | Self::CredentialRevoked { issuer_key_id, .. } => issuer_key_id,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FinalizedStatusBlock {
    pub source: SourceBlockRef,
    /// Source events in canonical EVM log order.
    pub events: Vec<PackedStatusSourceEvent>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PackedStatusChunk {
    /// Status bits 0..127, least-significant bit first.
    pub low: u128,
    /// Status bits 128..255, least-significant bit first.
    pub high: u128,
}

impl PackedStatusChunk {
    pub const FAIL_CLOSED: Self = Self {
        low: u128::MAX,
        high: u128::MAX,
    };

    pub fn is_revoked_or_unallocated(self, bit: usize) -> bool {
        debug_assert!(bit < PACKED_STATUS_BITS_PER_CHUNK);
        let (limb, limb_bit) = if bit < 128 {
            (self.low, bit)
        } else {
            (self.high, bit - 128)
        };
        limb & (1u128 << limb_bit) != 0
    }

    fn with_fail_closed_bit(mut self, bit: usize, fail_closed: bool) -> Self {
        debug_assert!(bit < PACKED_STATUS_BITS_PER_CHUNK);
        let (limb, limb_bit) = if bit < 128 {
            (&mut self.low, bit)
        } else {
            (&mut self.high, bit - 128)
        };
        if fail_closed {
            *limb |= 1u128 << limb_bit;
        } else {
            *limb &= !(1u128 << limb_bit);
        }
        self
    }

    fn fields(self) -> [StatusField; 2] {
        [StatusField::from(self.low), StatusField::from(self.high)]
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedStatusWitness {
    pub schema: &'static str,
    pub status_id: u32,
    pub root: StatusField,
    pub chunk_index: u32,
    pub chunk: PackedStatusChunk,
    /// Bottom-up siblings, matching status-id bits 8..31 in the circuit.
    pub siblings: [StatusField; PACKED_STATUS_DEPTH],
}

impl PackedStatusWitness {
    pub fn is_active(&self) -> bool {
        !self
            .chunk
            .is_revoked_or_unallocated((self.status_id & 0xff) as usize)
    }

    pub fn recompute_root(&self) -> StatusField {
        let poseidon = poseidon_config();
        root_from_path(
            &poseidon,
            packed_status_leaf_native(&poseidon, self.chunk.fields()),
            self.chunk_index,
            &self.siblings,
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedStatusSnapshotChunk {
    pub index: u32,
    pub value: PackedStatusChunk,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackedStatusSnapshot {
    pub schema: &'static str,
    pub chain_id: u64,
    pub issuance_registry: [u8; 20],
    pub issuer_key_id: [u8; 32],
    pub source: SourceBlockRef,
    pub next_status_id: u64,
    pub root: StatusField,
    /// Only non-default chunks, sorted by index. Every omitted chunk is all 1s.
    pub chunks: Vec<PackedStatusSnapshotChunk>,
}

impl PackedStatusSnapshot {
    pub fn activated_through_status_id(&self) -> u32 {
        u32::try_from(self.next_status_id - 1)
            .expect("builder bounds next_status_id to uint32 maximum plus one")
    }

    /// Deterministic JSON for public replication and independent root rebuilds.
    /// This is not an authenticated envelope; signing is a separate boundary.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        let wire = SnapshotWire {
            schema: self.schema.to_owned(),
            chain_id: self.chain_id.to_string(),
            issuance_registry: bytes_to_hex(&self.issuance_registry),
            issuer_key_id: bytes_to_hex(&self.issuer_key_id),
            source_block_number: self.source.number.to_string(),
            source_block_hash: bytes_to_hex(&self.source.hash),
            source_block_parent_hash: bytes_to_hex(&self.source.parent_hash),
            next_status_id: self.next_status_id,
            activated_through_status_id: self.activated_through_status_id(),
            root: field_to_hex(self.root),
            chunks: self
                .chunks
                .iter()
                .map(|chunk| SnapshotChunkWire {
                    index: chunk.index,
                    value: chunk_to_hex(chunk.value),
                })
                .collect(),
        };
        serde_json::to_string(&wire)
    }
}

#[derive(Clone, Debug)]
struct EventUndo {
    status_id: u32,
    previous_chunk: PackedStatusChunk,
    previously_revoked: bool,
}

#[derive(Clone, Debug)]
struct BlockUndo {
    source: SourceBlockRef,
    previous_tip: SourceBlockRef,
    previous_next_status_id: u64,
    events: Vec<EventUndo>,
}

pub struct PackedStatusSnapshotBuilder {
    chain_id: u64,
    issuance_registry: [u8; 20],
    issuer_key_id: [u8; 32],
    anchor: SourceBlockRef,
    tip: SourceBlockRef,
    next_status_id: u64,
    poseidon: PoseidonConfig<StatusField>,
    defaults: [StatusField; PACKED_STATUS_DEPTH + 1],
    chunks: BTreeMap<u32, PackedStatusChunk>,
    nodes: BTreeMap<(usize, u32), StatusField>,
    revoked: BTreeSet<u32>,
    history: Vec<BlockUndo>,
}

impl PackedStatusSnapshotBuilder {
    pub fn new(
        chain_id: u64,
        issuance_registry: [u8; 20],
        issuer_key_id: [u8; 32],
        anchor: SourceBlockRef,
    ) -> Result<Self, PackedStatusSnapshotError> {
        if chain_id == 0
            || issuance_registry == ZERO_ADDRESS
            || issuer_key_id == ZERO_HASH
            || anchor.hash == ZERO_HASH
        {
            return Err(PackedStatusSnapshotError::InvalidTrustAnchor);
        }
        let poseidon = poseidon_config();
        let mut defaults = [StatusField::from(0u64); PACKED_STATUS_DEPTH + 1];
        defaults[0] = packed_status_leaf_native(&poseidon, PackedStatusChunk::FAIL_CLOSED.fields());
        for level in 0..PACKED_STATUS_DEPTH {
            defaults[level + 1] = registry_node(&poseidon, defaults[level], defaults[level]);
        }
        Ok(Self {
            chain_id,
            issuance_registry,
            issuer_key_id,
            anchor,
            tip: anchor,
            next_status_id: 1,
            poseidon,
            defaults,
            chunks: BTreeMap::new(),
            nodes: BTreeMap::new(),
            revoked: BTreeSet::new(),
            history: Vec::new(),
        })
    }

    pub fn tip(&self) -> SourceBlockRef {
        self.tip
    }

    pub fn next_status_id(&self) -> u64 {
        self.next_status_id
    }

    pub fn root(&self) -> StatusField {
        self.node(PACKED_STATUS_DEPTH, 0)
    }

    pub fn apply_finalized_block(
        &mut self,
        block: FinalizedStatusBlock,
    ) -> Result<(), PackedStatusSnapshotError> {
        let expected_number = self
            .tip
            .number
            .checked_add(1)
            .ok_or(PackedStatusSnapshotError::BlockNumberOverflow)?;
        if block.source.number != expected_number {
            return Err(PackedStatusSnapshotError::NonContiguousBlock);
        }
        if block.source.parent_hash != self.tip.hash || block.source.hash == ZERO_HASH {
            return Err(PackedStatusSnapshotError::ParentHashMismatch);
        }
        if block.source.hash == self.anchor.hash
            || self
                .history
                .iter()
                .any(|entry| entry.source.hash == block.source.hash)
        {
            return Err(PackedStatusSnapshotError::DuplicateBlockHash);
        }

        let previous_tip = self.tip;
        let previous_next_status_id = self.next_status_id;
        let mut undo = Vec::with_capacity(block.events.len());
        let mut previous_log_index = None;

        for event in block.events.iter().copied() {
            if previous_log_index.is_some_and(|previous| event.log_index() <= previous) {
                self.rollback_events(&undo, previous_next_status_id);
                return Err(PackedStatusSnapshotError::NonCanonicalLogOrder);
            }
            previous_log_index = Some(event.log_index());
            match self.apply_event(event) {
                Ok(event_undo) => undo.push(event_undo),
                Err(error) => {
                    self.rollback_events(&undo, previous_next_status_id);
                    return Err(error);
                }
            }
        }

        self.tip = block.source;
        self.history.push(BlockUndo {
            source: block.source,
            previous_tip,
            previous_next_status_id,
            events: undo,
        });
        Ok(())
    }

    /// Rewind only to the configured anchor or an applied ancestor. Unknown
    /// hashes fail without mutating state.
    pub fn rewind_to(&mut self, ancestor_hash: [u8; 32]) -> Result<(), PackedStatusSnapshotError> {
        if ancestor_hash == self.tip.hash {
            return Ok(());
        }
        let known = ancestor_hash == self.anchor.hash
            || self
                .history
                .iter()
                .any(|entry| entry.source.hash == ancestor_hash);
        if !known {
            return Err(PackedStatusSnapshotError::UnknownAncestor);
        }
        while self.tip.hash != ancestor_hash {
            let entry = self
                .history
                .pop()
                .expect("known ancestor check guarantees a rollback entry");
            self.rollback_events(&entry.events, entry.previous_next_status_id);
            self.tip = entry.previous_tip;
        }
        Ok(())
    }

    pub fn snapshot(&self) -> PackedStatusSnapshot {
        PackedStatusSnapshot {
            schema: PACKED_STATUS_SNAPSHOT_SCHEMA,
            chain_id: self.chain_id,
            issuance_registry: self.issuance_registry,
            issuer_key_id: self.issuer_key_id,
            source: self.tip,
            next_status_id: self.next_status_id,
            root: self.root(),
            chunks: self
                .chunks
                .iter()
                .map(|(index, value)| PackedStatusSnapshotChunk {
                    index: *index,
                    value: *value,
                })
                .collect(),
        }
    }

    pub fn witness(
        &self,
        status_id: u32,
    ) -> Result<PackedStatusWitness, PackedStatusSnapshotError> {
        if status_id == 0 || u64::from(status_id) >= self.next_status_id {
            return Err(PackedStatusSnapshotError::UnallocatedStatus);
        }
        let chunk_index = status_id >> 8;
        let chunk = self.chunk(chunk_index);
        let siblings = std::array::from_fn(|level| self.node(level, (chunk_index >> level) ^ 1));
        Ok(PackedStatusWitness {
            schema: PACKED_STATUS_WITNESS_SCHEMA,
            status_id,
            root: self.root(),
            chunk_index,
            chunk,
            siblings,
        })
    }

    fn apply_event(
        &mut self,
        event: PackedStatusSourceEvent,
    ) -> Result<EventUndo, PackedStatusSnapshotError> {
        if event.issuer_key_id() != self.issuer_key_id {
            return Err(PackedStatusSnapshotError::WrongIssuer);
        }
        let (status_id, fail_closed) = match event {
            PackedStatusSourceEvent::CredentialAllocated { status_id, .. } => {
                if self.next_status_id > u64::from(u32::MAX) {
                    return Err(PackedStatusSnapshotError::StatusSlotsExhausted);
                }
                if u64::from(status_id) != self.next_status_id {
                    return Err(PackedStatusSnapshotError::UnexpectedStatusId);
                }
                (status_id, false)
            }
            PackedStatusSourceEvent::CredentialRevoked {
                status_id,
                authorization_reference,
                ..
            } => {
                if authorization_reference == ZERO_HASH {
                    return Err(PackedStatusSnapshotError::InvalidRevocationAuthorization);
                }
                if status_id == 0 || u64::from(status_id) >= self.next_status_id {
                    return Err(PackedStatusSnapshotError::UnallocatedStatus);
                }
                if self.revoked.contains(&status_id) {
                    return Err(PackedStatusSnapshotError::StatusAlreadyRevoked);
                }
                (status_id, true)
            }
        };

        let chunk_index = status_id >> 8;
        let selected_bit = (status_id & 0xff) as usize;
        let previous_chunk = self.chunk(chunk_index);
        let previously_fail_closed = previous_chunk.is_revoked_or_unallocated(selected_bit);
        if fail_closed == previously_fail_closed {
            return Err(if fail_closed {
                PackedStatusSnapshotError::StatusAlreadyRevoked
            } else {
                PackedStatusSnapshotError::StatusAlreadyAllocated
            });
        }
        let previously_revoked = self.revoked.contains(&status_id);
        self.set_chunk(
            chunk_index,
            previous_chunk.with_fail_closed_bit(selected_bit, fail_closed),
        );
        if fail_closed {
            self.revoked.insert(status_id);
        } else {
            self.next_status_id += 1;
        }
        Ok(EventUndo {
            status_id,
            previous_chunk,
            previously_revoked,
        })
    }

    fn rollback_events(&mut self, events: &[EventUndo], previous_next_status_id: u64) {
        for event in events.iter().rev() {
            self.set_chunk(event.status_id >> 8, event.previous_chunk);
            if event.previously_revoked {
                self.revoked.insert(event.status_id);
            } else {
                self.revoked.remove(&event.status_id);
            }
        }
        self.next_status_id = previous_next_status_id;
    }

    fn chunk(&self, index: u32) -> PackedStatusChunk {
        self.chunks
            .get(&index)
            .copied()
            .unwrap_or(PackedStatusChunk::FAIL_CLOSED)
    }

    fn set_chunk(&mut self, index: u32, chunk: PackedStatusChunk) {
        if chunk == PackedStatusChunk::FAIL_CLOSED {
            self.chunks.remove(&index);
        } else {
            self.chunks.insert(index, chunk);
        }
        let leaf = packed_status_leaf_native(&self.poseidon, chunk.fields());
        self.set_node(0, index, leaf);
        let mut current = leaf;
        let mut current_index = index;
        for level in 0..PACKED_STATUS_DEPTH {
            let sibling = self.node(level, current_index ^ 1);
            current = if current_index & 1 == 0 {
                registry_node(&self.poseidon, current, sibling)
            } else {
                registry_node(&self.poseidon, sibling, current)
            };
            current_index >>= 1;
            self.set_node(level + 1, current_index, current);
        }
    }

    fn node(&self, level: usize, index: u32) -> StatusField {
        self.nodes
            .get(&(level, index))
            .copied()
            .unwrap_or(self.defaults[level])
    }

    fn set_node(&mut self, level: usize, index: u32, value: StatusField) {
        if value == self.defaults[level] {
            self.nodes.remove(&(level, index));
        } else {
            self.nodes.insert((level, index), value);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PackedStatusSnapshotError {
    InvalidTrustAnchor,
    InvalidSourceEncoding,
    BlockNumberOverflow,
    NonContiguousBlock,
    ParentHashMismatch,
    DuplicateBlockHash,
    NonCanonicalLogOrder,
    WrongIssuer,
    UnexpectedStatusId,
    StatusAlreadyAllocated,
    StatusSlotsExhausted,
    UnallocatedStatus,
    StatusAlreadyRevoked,
    InvalidRevocationAuthorization,
    UnknownAncestor,
}

impl fmt::Display for PackedStatusSnapshotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidTrustAnchor => "status snapshot trust anchor is invalid",
            Self::InvalidSourceEncoding => "status snapshot source encoding is invalid",
            Self::BlockNumberOverflow => "source block number overflow",
            Self::NonContiguousBlock => "source blocks must be contiguous",
            Self::ParentHashMismatch => "source block parent hash does not match the current tip",
            Self::DuplicateBlockHash => {
                "source block hash is already present in the indexed branch"
            }
            Self::NonCanonicalLogOrder => "source events must be strictly ordered by log index",
            Self::WrongIssuer => "source event belongs to a different issuer key",
            Self::UnexpectedStatusId => {
                "credential allocations must be contiguous and start at one"
            }
            Self::StatusAlreadyAllocated => "credential status is already allocated",
            Self::StatusSlotsExhausted => "credential status slots are exhausted",
            Self::UnallocatedStatus => "credential status is not allocated",
            Self::StatusAlreadyRevoked => "credential status is already revoked",
            Self::InvalidRevocationAuthorization => {
                "credential revocation requires a nonzero authorization reference"
            }
            Self::UnknownAncestor => "requested rollback target is not a known ancestor",
        })
    }
}

impl Error for PackedStatusSnapshotError {}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SourceWire {
    schema: String,
    chain_id: String,
    issuance_registry: String,
    issuer_key_id: String,
    anchor: BlockRefWire,
    blocks: Vec<BlockWire>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlockRefWire {
    number: String,
    hash: String,
    parent_hash: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BlockWire {
    number: String,
    hash: String,
    parent_hash: String,
    events: Vec<EventWire>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EventWire {
    kind: String,
    log_index: u32,
    issuer_key_id: String,
    status_id: u32,
    authorization_reference: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotWire {
    schema: String,
    chain_id: String,
    issuance_registry: String,
    issuer_key_id: String,
    source_block_number: String,
    source_block_hash: String,
    source_block_parent_hash: String,
    next_status_id: u64,
    activated_through_status_id: u32,
    root: String,
    chunks: Vec<SnapshotChunkWire>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct SnapshotChunkWire {
    index: u32,
    value: String,
}

/// Strictly parse a finalized source transcript and return its deterministic
/// public snapshot JSON. RPC event collection and finality selection remain
/// operator responsibilities.
pub fn build_packed_status_snapshot_from_json(
    json: &str,
) -> Result<String, PackedStatusSnapshotError> {
    let wire: SourceWire =
        serde_json::from_str(json).map_err(|_| PackedStatusSnapshotError::InvalidSourceEncoding)?;
    if wire.schema != PACKED_STATUS_SOURCE_SCHEMA {
        return Err(PackedStatusSnapshotError::InvalidSourceEncoding);
    }
    let chain_id = parse_canonical_u64(&wire.chain_id)?;
    let issuance_registry = bytes_from_hex::<20>(&wire.issuance_registry)?;
    let issuer_key_id = bytes_from_hex::<32>(&wire.issuer_key_id)?;
    let anchor = parse_block_ref(wire.anchor)?;
    let mut builder =
        PackedStatusSnapshotBuilder::new(chain_id, issuance_registry, issuer_key_id, anchor)?;

    for block in wire.blocks {
        let source = parse_block_ref(BlockRefWire {
            number: block.number,
            hash: block.hash,
            parent_hash: block.parent_hash,
        })?;
        let events = block
            .events
            .into_iter()
            .map(parse_event)
            .collect::<Result<Vec<_>, _>>()?;
        builder.apply_finalized_block(FinalizedStatusBlock { source, events })?;
    }
    builder
        .snapshot()
        .to_json()
        .map_err(|_| PackedStatusSnapshotError::InvalidSourceEncoding)
}

fn parse_event(event: EventWire) -> Result<PackedStatusSourceEvent, PackedStatusSnapshotError> {
    let issuer_key_id = bytes_from_hex::<32>(&event.issuer_key_id)?;
    match (event.kind.as_str(), event.authorization_reference) {
        ("credential-allocated", None) => Ok(PackedStatusSourceEvent::CredentialAllocated {
            log_index: event.log_index,
            issuer_key_id,
            status_id: event.status_id,
        }),
        ("credential-revoked", Some(reference)) => Ok(PackedStatusSourceEvent::CredentialRevoked {
            log_index: event.log_index,
            issuer_key_id,
            status_id: event.status_id,
            authorization_reference: bytes_from_hex::<32>(&reference)?,
        }),
        _ => Err(PackedStatusSnapshotError::InvalidSourceEncoding),
    }
}

fn parse_block_ref(wire: BlockRefWire) -> Result<SourceBlockRef, PackedStatusSnapshotError> {
    Ok(SourceBlockRef {
        number: parse_canonical_u64(&wire.number)?,
        hash: bytes_from_hex::<32>(&wire.hash)?,
        parent_hash: bytes_from_hex::<32>(&wire.parent_hash)?,
    })
}

fn parse_canonical_u64(value: &str) -> Result<u64, PackedStatusSnapshotError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| PackedStatusSnapshotError::InvalidSourceEncoding)?;
    if parsed.to_string() != value {
        return Err(PackedStatusSnapshotError::InvalidSourceEncoding);
    }
    Ok(parsed)
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(2 + bytes.len() * 2);
    encoded.push_str("0x");
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn bytes_from_hex<const N: usize>(encoded: &str) -> Result<[u8; N], PackedStatusSnapshotError> {
    if encoded.len() != 2 + N * 2 || !encoded.starts_with("0x") {
        return Err(PackedStatusSnapshotError::InvalidSourceEncoding);
    }
    let mut bytes = [0u8; N];
    for (index, pair) in encoded.as_bytes()[2..].chunks_exact(2).enumerate() {
        bytes[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
    }
    if bytes_to_hex(&bytes) != encoded {
        return Err(PackedStatusSnapshotError::InvalidSourceEncoding);
    }
    Ok(bytes)
}

fn hex_nibble(value: u8) -> Result<u8, PackedStatusSnapshotError> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        _ => Err(PackedStatusSnapshotError::InvalidSourceEncoding),
    }
}

fn field_to_hex(value: StatusField) -> String {
    let bytes = value.into_bigint().to_bytes_be();
    let mut padded = [0u8; 32];
    padded[32 - bytes.len()..].copy_from_slice(&bytes);
    bytes_to_hex(&padded)
}

fn chunk_to_hex(chunk: PackedStatusChunk) -> String {
    format!("0x{:032x}{:032x}", chunk.high, chunk.low)
}

fn registry_node(
    poseidon: &PoseidonConfig<StatusField>,
    left: StatusField,
    right: StatusField,
) -> StatusField {
    poseidon_native(poseidon, REGISTRY_NODE_DOMAIN, &[left, right])
}

fn root_from_path(
    poseidon: &PoseidonConfig<StatusField>,
    leaf: StatusField,
    leaf_index: u32,
    siblings: &[StatusField; PACKED_STATUS_DEPTH],
) -> StatusField {
    siblings
        .iter()
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
    use crate::{
        jubjub_scalar_from_circuit_field, signature_challenge_native, split_field_to_u128_limbs,
        Authentication, SpikeCircuit, CREDENTIAL_DOMAIN, CREDENTIAL_STATUS_ID_HIGH_INDEX,
        CREDENTIAL_STATUS_ID_LOW_INDEX,
    };
    use ark_ed_on_bn254::Fr as JubjubScalar;
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};

    const REGISTRY: [u8; 20] = [0x11; 20];
    const ISSUER: [u8; 32] = [0x22; 32];
    const ANCHOR: SourceBlockRef = SourceBlockRef {
        number: 100,
        hash: [0x01; 32],
        parent_hash: [0x00; 32],
    };

    fn builder() -> PackedStatusSnapshotBuilder {
        PackedStatusSnapshotBuilder::new(84_532, REGISTRY, ISSUER, ANCHOR).unwrap()
    }

    fn block(
        number: u64,
        hash: u8,
        parent_hash: u8,
        events: Vec<PackedStatusSourceEvent>,
    ) -> FinalizedStatusBlock {
        FinalizedStatusBlock {
            source: SourceBlockRef {
                number,
                hash: [hash; 32],
                parent_hash: [parent_hash; 32],
            },
            events,
        }
    }

    fn allocation(log_index: u32, status_id: u32) -> PackedStatusSourceEvent {
        PackedStatusSourceEvent::CredentialAllocated {
            log_index,
            issuer_key_id: ISSUER,
            status_id,
        }
    }

    fn revocation(log_index: u32, status_id: u32) -> PackedStatusSourceEvent {
        PackedStatusSourceEvent::CredentialRevoked {
            log_index,
            issuer_key_id: ISSUER,
            status_id,
            authorization_reference: [0x77; 32],
        }
    }

    #[test]
    fn allocations_are_dense_fail_closed_and_circuit_compatible() {
        let mut builder = builder();
        let events = (1..=42)
            .map(|status_id| allocation(status_id - 1, status_id))
            .collect();
        builder
            .apply_finalized_block(block(101, 0x02, 0x01, events))
            .unwrap();

        let witness = builder.witness(42).unwrap();
        assert!(witness.is_active());
        assert_eq!(witness.recompute_root(), builder.root());
        assert!(builder.witness(43).is_err());

        let mut circuit = SpikeCircuit::fixture(Authentication::SignatureAndPackedStatus);
        circuit.credential_elements[CREDENTIAL_STATUS_ID_HIGH_INDEX] = StatusField::from(0u64);
        circuit.credential_elements[CREDENTIAL_STATUS_ID_LOW_INDEX] =
            StatusField::from(witness.status_id);
        let poseidon = poseidon_config();
        let credential_commitment = poseidon_native(
            &poseidon,
            CREDENTIAL_DOMAIN,
            circuit.credential_elements.as_slice(),
        );
        let challenge = signature_challenge_native(
            &poseidon,
            &circuit.signature_commitment,
            &circuit.issuer_public_key,
            credential_commitment,
        );
        circuit.signature_response = JubjubScalar::from(8_181_818u64)
            - jubjub_scalar_from_circuit_field(challenge) * JubjubScalar::from(4_242_424u64);
        circuit.packed_status_chunk = witness.chunk.fields();
        circuit.registry_siblings = witness.siblings.to_vec();
        circuit.expected_registry_root = split_field_to_u128_limbs(witness.root);
        let cs = ConstraintSystem::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(
            cs.is_satisfied().unwrap(),
            "builder witness must satisfy the exact packed-status circuit"
        );
    }

    #[test]
    fn an_invalid_event_rolls_back_the_entire_block() {
        let mut builder = builder();
        let initial_root = builder.root();
        let error = builder
            .apply_finalized_block(block(
                101,
                0x02,
                0x01,
                vec![allocation(0, 1), allocation(1, 3)],
            ))
            .unwrap_err();
        assert_eq!(error, PackedStatusSnapshotError::UnexpectedStatusId);
        assert_eq!(builder.root(), initial_root);
        assert_eq!(builder.next_status_id(), 1);
        assert_eq!(builder.tip(), ANCHOR);
    }

    #[test]
    fn revocation_is_fail_closed_and_irreversible_on_one_branch() {
        let mut builder = builder();
        builder
            .apply_finalized_block(block(
                101,
                0x02,
                0x01,
                vec![allocation(0, 1), allocation(1, 2)],
            ))
            .unwrap();
        builder
            .apply_finalized_block(block(102, 0x03, 0x02, vec![revocation(0, 1)]))
            .unwrap();
        assert!(!builder.witness(1).unwrap().is_active());
        assert!(builder.witness(2).unwrap().is_active());
        assert_eq!(
            builder
                .apply_finalized_block(block(103, 0x04, 0x03, vec![revocation(0, 1)]))
                .unwrap_err(),
            PackedStatusSnapshotError::StatusAlreadyRevoked
        );
        assert_eq!(builder.tip().hash, [0x03; 32]);
    }

    #[test]
    fn rollback_and_replay_produce_the_same_alternate_snapshot() {
        let mut forked = builder();
        forked
            .apply_finalized_block(block(101, 0x02, 0x01, vec![allocation(0, 1)]))
            .unwrap();
        forked
            .apply_finalized_block(block(102, 0x03, 0x02, vec![allocation(0, 2)]))
            .unwrap();
        forked.rewind_to([0x02; 32]).unwrap();
        forked
            .apply_finalized_block(block(
                102,
                0x04,
                0x02,
                vec![allocation(0, 2), revocation(1, 1)],
            ))
            .unwrap();

        let mut replayed = builder();
        replayed
            .apply_finalized_block(block(101, 0x02, 0x01, vec![allocation(0, 1)]))
            .unwrap();
        replayed
            .apply_finalized_block(block(
                102,
                0x04,
                0x02,
                vec![allocation(0, 2), revocation(1, 1)],
            ))
            .unwrap();
        assert_eq!(
            forked.snapshot().to_json().unwrap(),
            replayed.snapshot().to_json().unwrap()
        );
    }

    #[test]
    fn unknown_rollback_and_wrong_issuer_do_not_mutate_state() {
        let mut builder = builder();
        let initial = builder.snapshot().to_json().unwrap();
        assert_eq!(
            builder.rewind_to([0x99; 32]).unwrap_err(),
            PackedStatusSnapshotError::UnknownAncestor
        );
        let wrong_issuer = PackedStatusSourceEvent::CredentialAllocated {
            log_index: 0,
            issuer_key_id: [0x33; 32],
            status_id: 1,
        };
        assert_eq!(
            builder
                .apply_finalized_block(block(101, 0x02, 0x01, vec![wrong_issuer]))
                .unwrap_err(),
            PackedStatusSnapshotError::WrongIssuer
        );
        assert_eq!(builder.snapshot().to_json().unwrap(), initial);
    }

    #[test]
    fn duplicate_block_hash_and_reordered_logs_fail_without_mutation() {
        let mut builder = builder();
        let initial = builder.snapshot().to_json().unwrap();
        assert_eq!(
            builder
                .apply_finalized_block(block(101, 0x01, 0x01, vec![]))
                .unwrap_err(),
            PackedStatusSnapshotError::DuplicateBlockHash
        );
        assert_eq!(
            builder
                .apply_finalized_block(block(
                    101,
                    0x02,
                    0x01,
                    vec![allocation(2, 1), allocation(1, 2)],
                ))
                .unwrap_err(),
            PackedStatusSnapshotError::NonCanonicalLogOrder
        );
        assert_eq!(builder.snapshot().to_json().unwrap(), initial);
    }

    #[test]
    fn strict_json_builder_is_deterministic_and_sorted() {
        let source = format!(
            r#"{{"schema":"{PACKED_STATUS_SOURCE_SCHEMA}","chainId":"84532","issuanceRegistry":"{}","issuerKeyId":"{}","anchor":{{"number":"100","hash":"{}","parentHash":"{}"}},"blocks":[{{"number":"101","hash":"{}","parentHash":"{}","events":[{{"kind":"credential-allocated","logIndex":0,"issuerKeyId":"{}","statusId":1}}]}}]}}"#,
            bytes_to_hex(&REGISTRY),
            bytes_to_hex(&ISSUER),
            bytes_to_hex(&[0x01; 32]),
            bytes_to_hex(&[0x00; 32]),
            bytes_to_hex(&[0x02; 32]),
            bytes_to_hex(&[0x01; 32]),
            bytes_to_hex(&ISSUER),
        );
        let first = build_packed_status_snapshot_from_json(&source).unwrap();
        let second = build_packed_status_snapshot_from_json(&source).unwrap();
        assert_eq!(first, second);
        assert!(first.contains(r#""nextStatusId":2"#));
        assert!(first.contains(r#""activatedThroughStatusId":1"#));
        assert!(first.contains(r#""chunks":[{"index":0,"value":"0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd"}]"#));

        let noncanonical = source.replace(r#""chainId":"84532""#, r#""chainId":"084532""#);
        assert_eq!(
            build_packed_status_snapshot_from_json(&noncanonical).unwrap_err(),
            PackedStatusSnapshotError::InvalidSourceEncoding
        );
    }
}
