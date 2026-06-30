//! Canonical wire encodings (spec `05-p2p-network.md` §3.1, §4.1, §4.2).
//!
//! The network crate only *moves bytes* and verifies the hashes/signatures it can; it never owns the
//! runtime state model. So the wire types here are deliberately self-contained, length-prefixed binary
//! structures keyed by the same hashes the chain already uses:
//!
//!   * **`TxAnnounce`** (`ubi2/tx/1`) — the raw EIP-155 tx bytes *verbatim* (exactly what
//!     `eth_sendRawTransaction` accepts). The gossipsub **message-id = `keccak256(rlp)` = the tx hash**
//!     (§3.1), giving free, correct dedup. The network layer does not parse the tx; the node validates
//!     it via the existing `ingest_raw_tx` path before re-broadcast (§3.2).
//!
//!   * **`BlockAnnounce`** (`ubi2/block/1`) — the full block: the §2.2 header fields in fixed order,
//!     then `txs.len()`, then each raw tx (verbatim RLP). The message-id = the block `hash` (§3.1). The
//!     network verifies only that the announced `hash` matches the header pre-image and (if a signature
//!     is present) that `ecrecover(proposer_sig) == proposer`; full re-execution/validation is the
//!     node's `validate_and_apply_block` (§5.1).
//!
//!   * **`Hello`** (handshake, §4.1) — `genesis_hash`, `chain_id`, `tip`, optional `validator`,
//!     `peer_proof` (validator-key sig over `PeerId ‖ genesis_hash`), `protocol_ver`.
//!
//!   * **`GetBlocks` / `Blocks`** (request-response `ubi2/sync/1`, §4.2) — an inclusive height range and
//!     the canonically-encoded blocks in ascending height order.
//!
//! ## Encoding rules (canonical, stable across nodes)
//! Fixed-width integers are **big-endian**. Variable-length byte fields are length-prefixed with a
//! `u32` big-endian length. There is exactly one encoding for any value, so the message-id (a hash over
//! the bytes) is identical on every node — the property gossipsub dedup relies on.

use alloy_primitives::{keccak256, Address, B256};

use crate::consts::{MAX_BLOCK_BYTES, MAX_TX_BYTES};

/// A 32-byte hash (block hash / tx hash / genesis hash).
pub type Hash = B256;

/// Errors decoding a wire payload. The network drops the message and (for gossip) may penalize the
/// source peer — it never panics on attacker-controlled bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before a field finished.
    Truncated,
    /// A length prefix exceeds the message's stated/maximum bound.
    TooLong,
    /// Trailing bytes after the message (non-canonical).
    TrailingBytes,
    /// A field held a value outside its domain (e.g. a bad enum tag).
    Invalid(&'static str),
}

impl std::fmt::Display for WireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WireError::Truncated => write!(f, "wire: truncated"),
            WireError::TooLong => write!(f, "wire: length prefix too long"),
            WireError::TrailingBytes => write!(f, "wire: trailing bytes"),
            WireError::Invalid(w) => write!(f, "wire: invalid {w}"),
        }
    }
}

impl std::error::Error for WireError {}

// ---------------------------------------------------------------------------------------------
// Low-level cursor: canonical big-endian, length-prefixed reads/writes. No allocation per field.
// ---------------------------------------------------------------------------------------------

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], WireError> {
        let end = self.pos.checked_add(n).ok_or(WireError::TooLong)?;
        if end > self.buf.len() {
            return Err(WireError::Truncated);
        }
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }
    fn u8(&mut self) -> Result<u8, WireError> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16, WireError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    fn u32(&mut self) -> Result<u32, WireError> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    fn u64(&mut self) -> Result<u64, WireError> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes(b.try_into().unwrap()))
    }
    fn b256(&mut self) -> Result<B256, WireError> {
        Ok(B256::from_slice(self.take(32)?))
    }
    fn address(&mut self) -> Result<Address, WireError> {
        Ok(Address::from_slice(self.take(20)?))
    }
    /// A `u32`-length-prefixed byte blob, bounded by `max`.
    fn bytes(&mut self, max: usize) -> Result<Vec<u8>, WireError> {
        let n = self.u32()? as usize;
        if n > max {
            return Err(WireError::TooLong);
        }
        Ok(self.take(n)?.to_vec())
    }
    fn finish(self) -> Result<(), WireError> {
        if self.pos == self.buf.len() {
            Ok(())
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

// ---------------------------------------------------------------------------------------------
// TxAnnounce — raw RLP tx bytes verbatim (§3.1). message-id = keccak256(rlp) = the tx hash.
// ---------------------------------------------------------------------------------------------

/// A gossiped transaction: the raw EIP-155 tx bytes exactly as `eth_sendRawTransaction` accepts them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxAnnounce {
    /// The raw RLP tx bytes. The network never parses these; the node validates via `ingest_raw_tx`.
    pub raw: Vec<u8>,
}

impl TxAnnounce {
    pub fn new(raw: Vec<u8>) -> Self {
        TxAnnounce { raw }
    }
    /// The gossipsub message-id = `keccak256(rlp)` = the tx hash (§3.1) — free, correct dedup.
    pub fn message_id(&self) -> Hash {
        keccak256(&self.raw)
    }
    /// The wire payload is the raw RLP verbatim (no framing — the topic is the type tag).
    pub fn encode(&self) -> Vec<u8> {
        self.raw.clone()
    }
    /// Decode a `ubi2/tx/1` payload: the raw bytes, length-bounded (`MAX_TX_BYTES`).
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.is_empty() {
            return Err(WireError::Truncated);
        }
        if buf.len() > MAX_TX_BYTES {
            return Err(WireError::TooLong);
        }
        Ok(TxAnnounce { raw: buf.to_vec() })
    }
}

// ---------------------------------------------------------------------------------------------
// WireBlock / BlockAnnounce — the §2.2 header fields in fixed order, then txs.
// ---------------------------------------------------------------------------------------------

/// A block on the wire (spec §2.2 header + ordered raw txs). This mirrors `rpc::Block`'s consensus
/// fields without depending on `crates/rpc`: the node maps `rpc::Block` ↔ `WireBlock` at the seam.
///
/// `txs` are the raw EIP-155 tx bytes (verbatim RLP) in block order — the same bytes that gossiped on
/// `ubi2/tx/1`. The header pre-image (and thus `hash`) commits only to `txs_root`, not the raw txs, so a
/// follower recomputes `txs_root` from these and rejects a tampered tx set (§5.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireBlock {
    pub number: u64,
    pub parent_hash: Hash,
    pub timestamp: u64,
    pub txs_root: Hash,
    pub state_root: Hash,
    pub proposer: Address,
    /// 65-byte `r‖s‖v` proposer signature over the header pre-image, or empty (unsigned devnet block).
    pub proposer_sig: Vec<u8>,
    /// Raw EIP-155 tx bytes in block order.
    pub txs: Vec<Vec<u8>>,
}

impl WireBlock {
    /// The header pre-image `number ‖ parent_hash ‖ timestamp ‖ txs_root ‖ state_root ‖ proposer`
    /// (spec §2.2) — byte-identical to `rpc::Block::header_preimage` so the hashes match cross-crate.
    pub fn header_preimage(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 32 + 32 + 20);
        buf.extend_from_slice(&self.number.to_be_bytes());
        buf.extend_from_slice(self.parent_hash.as_slice());
        buf.extend_from_slice(&self.timestamp.to_be_bytes());
        buf.extend_from_slice(self.txs_root.as_slice());
        buf.extend_from_slice(self.state_root.as_slice());
        buf.extend_from_slice(self.proposer.as_slice());
        buf
    }

    /// The block hash = `keccak256(header_preimage)` (spec §2.2) = the gossipsub message-id.
    pub fn hash(&self) -> Hash {
        keccak256(self.header_preimage())
    }

    /// Recompute `txs_root` from the carried raw txs: `keccak256(count ‖ each tx hash)` where each tx
    /// hash is `keccak256(raw)` (spec §5.3). Matches `rpc::Block::compute_txs_root`, so a follower's
    /// recomputation equals the proposer's committed root iff the tx set + order are intact.
    pub fn recompute_txs_root(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + self.txs.len() * 32);
        buf.extend_from_slice(&(self.txs.len() as u64).to_be_bytes());
        for raw in &self.txs {
            buf.extend_from_slice(keccak256(raw).as_slice());
        }
        keccak256(&buf)
    }

    /// Canonical encoding: header fields (§2.2 order), then `txs.len()` (`u32`), then each raw tx as a
    /// length-prefixed blob. Exactly one encoding per block ⇒ a stable message-id.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.txs.iter().map(|t| t.len() + 4).sum::<usize>());
        out.extend_from_slice(&self.number.to_be_bytes());
        out.extend_from_slice(self.parent_hash.as_slice());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(self.txs_root.as_slice());
        out.extend_from_slice(self.state_root.as_slice());
        out.extend_from_slice(self.proposer.as_slice());
        put_bytes(&mut out, &self.proposer_sig);
        out.extend_from_slice(&(self.txs.len() as u32).to_be_bytes());
        for raw in &self.txs {
            put_bytes(&mut out, raw);
        }
        out
    }

    fn read(r: &mut Reader<'_>) -> Result<Self, WireError> {
        let number = r.u64()?;
        let parent_hash = r.b256()?;
        let timestamp = r.u64()?;
        let txs_root = r.b256()?;
        let state_root = r.b256()?;
        let proposer = r.address()?;
        let proposer_sig = r.bytes(65)?;
        let count = r.u32()? as usize;
        // Bound the tx count so a malformed length can't trigger a huge pre-allocation.
        if count > (MAX_BLOCK_BYTES / 4) {
            return Err(WireError::TooLong);
        }
        let mut txs = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            txs.push(r.bytes(MAX_TX_BYTES)?);
        }
        Ok(WireBlock {
            number,
            parent_hash,
            timestamp,
            txs_root,
            state_root,
            proposer,
            proposer_sig,
            txs,
        })
    }

    /// Decode a single canonically-encoded block (bounded by `MAX_BLOCK_BYTES`).
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() > MAX_BLOCK_BYTES {
            return Err(WireError::TooLong);
        }
        let mut r = Reader::new(buf);
        let b = Self::read(&mut r)?;
        r.finish()?;
        Ok(b)
    }

    /// Recover the proposer address from `proposer_sig` over the header hash, if a signature is present.
    /// Returns `None` for an unsigned block or a malformed signature. Mirrors `rpc::recover_proposer`.
    pub fn recover_proposer(&self) -> Option<Address> {
        recover_secp256k1(&self.hash(), &self.proposer_sig)
    }

    /// The network-layer "verify what we can" check (§3.1, fail-closed): the carried `txs_root` matches
    /// the txs **and** the block carries a valid proposer signature (`ecrecover(proposer_sig) ==
    /// proposer`). Full re-execution/parent/slot validation is the node's `validate_and_apply_block`
    /// (§5.1); this only rejects obviously-malformed/unauthenticated announcements so they are not
    /// forwarded — and, critically, so they are never **trusted for their NUMBER** by the sync driver.
    ///
    /// SECURITY (SEC-M5A-1): a previous version SKIPPED the signature check when `proposer_sig` was
    /// empty. That let a forged, UNSIGNED block claiming `number = u64::MAX` pass shallow-verify, get its
    /// (forged) tip pinned, and drive an unbounded sync loop. A gossiped/announced block that wants to be
    /// believed about its height MUST be authenticated. We therefore **fail closed on an absent
    /// signature**: an unsigned block never shallow-verifies. (Unsigned blocks only ever exist in the
    /// single-node devnet, which does not gossip; the follower path always supplies a signed proposer.)
    pub fn shallow_verify(&self) -> bool {
        if self.recompute_txs_root() != self.txs_root {
            return false;
        }
        // Fail closed: an unsigned/empty signature is NOT trusted on the gossip/sync path.
        if self.proposer_sig.is_empty() {
            return false;
        }
        match self.recover_proposer() {
            Some(addr) => addr == self.proposer,
            None => false,
        }
    }
}

/// A gossiped block announcement (`ubi2/block/1`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockAnnounce {
    pub block: WireBlock,
}

impl BlockAnnounce {
    pub fn new(block: WireBlock) -> Self {
        BlockAnnounce { block }
    }
    /// The gossipsub message-id = the block `hash` (§3.1).
    pub fn message_id(&self) -> Hash {
        self.block.hash()
    }
    pub fn encode(&self) -> Vec<u8> {
        self.block.encode()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        Ok(BlockAnnounce {
            block: WireBlock::decode(buf)?,
        })
    }
}

// ---------------------------------------------------------------------------------------------
// Hello handshake (§4.1).
// ---------------------------------------------------------------------------------------------

/// The `Hello` a peer sends on a new connection (spec §4.1). Drives network-mismatch rejection and the
/// PeerId↔validator-address binding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hello {
    /// MUST equal locally — else disconnect (wrong network).
    pub genesis_hash: Hash,
    /// MUST equal locally — else disconnect.
    pub chain_id: u64,
    /// `(height, hash)` of the sender's current head; drives sync.
    pub tip: (u64, Hash),
    /// The sender's validator address, if it is a validator.
    pub validator: Option<Address>,
    /// validator-key signature over `(peer_id_bytes ‖ genesis_hash)` — binds PeerId↔address (§4.1,
    /// ADR Decision 3). 65-byte `r‖s‖v`, or empty for a non-validator peer.
    pub peer_proof: Vec<u8>,
    /// Protocol version (`PROTOCOL_VERSION`).
    pub protocol_ver: u16,
}

impl Hello {
    /// The bytes a validator signs to prove `PeerId` speaks for its validator address (§4.1): the
    /// keccak256 of `peer_id_bytes ‖ genesis_hash`. A 32-byte digest so the same secp256k1 prehash
    /// signing the chain already uses applies.
    pub fn proof_digest(peer_id_bytes: &[u8], genesis_hash: &Hash) -> Hash {
        let mut buf = Vec::with_capacity(peer_id_bytes.len() + 32);
        buf.extend_from_slice(peer_id_bytes);
        buf.extend_from_slice(genesis_hash.as_slice());
        keccak256(&buf)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        out.extend_from_slice(self.genesis_hash.as_slice());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(&self.tip.0.to_be_bytes());
        out.extend_from_slice(self.tip.1.as_slice());
        match self.validator {
            Some(a) => {
                out.push(1);
                out.extend_from_slice(a.as_slice());
            }
            None => out.push(0),
        }
        put_bytes(&mut out, &self.peer_proof);
        out.extend_from_slice(&self.protocol_ver.to_be_bytes());
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(buf);
        let genesis_hash = r.b256()?;
        let chain_id = r.u64()?;
        let tip_h = r.u64()?;
        let tip_hash = r.b256()?;
        let validator = match r.u8()? {
            0 => None,
            1 => Some(r.address()?),
            _ => return Err(WireError::Invalid("validator-tag")),
        };
        let peer_proof = r.bytes(65)?;
        let protocol_ver = r.u16()?;
        r.finish()?;
        Ok(Hello {
            genesis_hash,
            chain_id,
            tip: (tip_h, tip_hash),
            validator,
            peer_proof,
            protocol_ver,
        })
    }

    /// Verify the PeerId↔validator binding: if a `validator` and `peer_proof` are present, the proof
    /// must `ecrecover` to that validator over `proof_digest(peer_id_bytes, genesis_hash)`. Returns the
    /// **bound** validator address (`Some` only on a verified binding); a failed/absent binding returns
    /// `None` (the peer may still relay gossip but its blocks/verdicts are not validator-trusted, §4.1).
    pub fn verify_binding(&self, peer_id_bytes: &[u8]) -> Option<Address> {
        let claimed = self.validator?;
        if self.peer_proof.is_empty() {
            return None;
        }
        let digest = Hello::proof_digest(peer_id_bytes, &self.genesis_hash);
        match recover_secp256k1(&digest, &self.peer_proof) {
            Some(addr) if addr == claimed => Some(addr),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Sync request-response (`ubi2/sync/1`, §4.2).
// ---------------------------------------------------------------------------------------------

/// `GetBlocks { from, to }` — an inclusive height range; the server clamps `to` to `from + SYNC_MAX_BATCH
/// − 1` before reading (§4.2/§10).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetBlocks {
    pub from: u64,
    pub to: u64,
}

impl GetBlocks {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&self.from.to_be_bytes());
        out.extend_from_slice(&self.to.to_be_bytes());
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(buf);
        let from = r.u64()?;
        let to = r.u64()?;
        r.finish()?;
        Ok(GetBlocks { from, to })
    }
}

/// `GetGenesis` — a light client asks the gateway for the **seeded genesis anchor**: the block-0 hash,
/// the seeded genesis `state_root`, genesis time, the authorized PoA proposer, and the canonical genesis
/// state SNAPSHOT (the seeded accounts/humans/jurors/CSCA/governance). The light client re-derives the
/// snapshot's `state_root` locally and rejects the gateway unless it equals its PINNED constant (so the
/// snapshot is untrusted DATA verified against a hard-coded anchor — a lying gateway is caught, spec 07
/// §3.4 / ADR-0006). The request carries no body. (`ln-trust-1`/`ln-trust-2` fix.)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GetGenesis;

impl GetGenesis {
    pub fn encode(&self) -> Vec<u8> {
        Vec::new()
    }
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        // No body. A non-empty buffer is non-canonical.
        if buf.is_empty() {
            Ok(GetGenesis)
        } else {
            Err(WireError::TrailingBytes)
        }
    }
}

/// `Genesis` — the gateway's reply to `GetGenesis` (spec 07 §3.4): the verifiable genesis anchor + the
/// seeded genesis state snapshot. The light client (a) checks `genesis_hash`/`state_root`/`chain_id`/
/// `proposer` against its PINNED constants, then (b) imports `snapshot` and re-derives its `state_root`,
/// rejecting unless it equals the pinned root. Only then does it re-execute blocks on the verified state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Genesis {
    /// The block-0 hash (the network-identity anchor — must equal the pinned constant).
    pub genesis_hash: Hash,
    /// The chain id (must equal the pinned constant).
    pub chain_id: u64,
    /// The **seeded** genesis `state_root` over the snapshot below — the light client re-derives it and
    /// rejects on mismatch with the pinned constant. (NOT the block-0 header's `state_root`, which is a
    /// fixed `ZERO` anchor; the seeded root is what re-execution of block #1 builds upon.)
    pub state_root: Hash,
    /// Genesis unix time (the anchor timestamp for the verified tip at height 0).
    pub genesis_time: u64,
    /// The authorized PoA proposer/validator (the light client verifies every block proposer ∈ the
    /// pinned set; on a single-proposer devnet this IS that set).
    pub proposer: Address,
    /// The canonical genesis state snapshot bytes — the `runtime-wasm` snapshot `state` section
    /// (accounts/streams/humans/jurors/contracts/CSCA/governance/…), serialized as JSON. Opaque to the
    /// network; the light client decodes + verifies it. Length-prefixed, bounded by `MAX_BLOCK_BYTES`.
    pub snapshot: Vec<u8>,
}

impl Genesis {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128 + self.snapshot.len());
        out.extend_from_slice(self.genesis_hash.as_slice());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        out.extend_from_slice(self.state_root.as_slice());
        out.extend_from_slice(&self.genesis_time.to_be_bytes());
        out.extend_from_slice(self.proposer.as_slice());
        put_bytes(&mut out, &self.snapshot);
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(buf);
        let genesis_hash = r.b256()?;
        let chain_id = r.u64()?;
        let state_root = r.b256()?;
        let genesis_time = r.u64()?;
        let proposer = r.address()?;
        let snapshot = r.bytes(MAX_BLOCK_BYTES)?;
        r.finish()?;
        Ok(Genesis {
            genesis_hash,
            chain_id,
            state_root,
            genesis_time,
            proposer,
            snapshot,
        })
    }
}

/// `Blocks { blocks }` — the requested blocks, ascending height, each canonically encoded (§4.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blocks {
    pub blocks: Vec<WireBlock>,
}

impl Blocks {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.blocks.len() * 256);
        out.extend_from_slice(&(self.blocks.len() as u32).to_be_bytes());
        for b in &self.blocks {
            put_bytes(&mut out, &b.encode());
        }
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let mut r = Reader::new(buf);
        let count = r.u32()? as usize;
        // A response is bounded by SYNC_MAX_BATCH; reject an over-large claimed count outright (AC-F8).
        if count as u64 > crate::consts::SYNC_MAX_BATCH {
            return Err(WireError::TooLong);
        }
        let mut blocks = Vec::with_capacity(count);
        for _ in 0..count {
            let raw = r.bytes(MAX_BLOCK_BYTES)?;
            blocks.push(WireBlock::decode(&raw)?);
        }
        r.finish()?;
        Ok(Blocks { blocks })
    }
}

// ---------------------------------------------------------------------------------------------
// The `ubi2/sync/1` request/response envelope. A single request-response protocol carries BOTH the
// `Hello` handshake (exchanged "on a new connection", §4.1) and the block-range pull (§4.2): the
// initiator sends a `SyncRequest`, the responder replies with a `SyncResponse`. A leading tag byte
// disambiguates, so a peer that initiates with a `Hello` gets the responder's `Hello` back (the
// handshake), and a `GetBlocks` gets `Blocks` back (the pull). One protocol, one negotiation.
// ---------------------------------------------------------------------------------------------

/// Tag for a `Hello` request/response.
const SYNC_TAG_HELLO: u8 = 0;
/// Tag for a `GetBlocks` request / `Blocks` response.
const SYNC_TAG_BLOCKS: u8 = 1;
/// Tag for a `GetGenesis` request / `Genesis` response (the verifiable genesis anchor, spec 07 §3.4).
const SYNC_TAG_GENESIS: u8 = 2;

/// A `ubi2/sync/1` request: the connection handshake, a block-range pull, or a genesis-anchor fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncRequest {
    /// The handshake (§4.1): "here is my genesis/chain/tip/validator-binding; send me yours".
    Hello(Hello),
    /// A block-range pull (§4.2): "send me `[from, to]`".
    GetBlocks(GetBlocks),
    /// A genesis-anchor fetch (spec 07 §3.4): "send me the seeded genesis snapshot + anchor".
    GetGenesis(GetGenesis),
}

impl SyncRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            SyncRequest::Hello(h) => {
                out.push(SYNC_TAG_HELLO);
                out.extend_from_slice(&h.encode());
            }
            SyncRequest::GetBlocks(g) => {
                out.push(SYNC_TAG_BLOCKS);
                out.extend_from_slice(&g.encode());
            }
            SyncRequest::GetGenesis(g) => {
                out.push(SYNC_TAG_GENESIS);
                out.extend_from_slice(&g.encode());
            }
        }
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let (&tag, rest) = buf.split_first().ok_or(WireError::Truncated)?;
        match tag {
            SYNC_TAG_HELLO => Ok(SyncRequest::Hello(Hello::decode(rest)?)),
            SYNC_TAG_BLOCKS => Ok(SyncRequest::GetBlocks(GetBlocks::decode(rest)?)),
            SYNC_TAG_GENESIS => Ok(SyncRequest::GetGenesis(GetGenesis::decode(rest)?)),
            _ => Err(WireError::Invalid("sync-request-tag")),
        }
    }
}

/// A `ubi2/sync/1` response: the responder's `Hello`, the requested `Blocks`, or the `Genesis` anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SyncResponse {
    Hello(Hello),
    Blocks(Blocks),
    Genesis(Genesis),
}

impl SyncResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        match self {
            SyncResponse::Hello(h) => {
                out.push(SYNC_TAG_HELLO);
                out.extend_from_slice(&h.encode());
            }
            SyncResponse::Blocks(b) => {
                out.push(SYNC_TAG_BLOCKS);
                out.extend_from_slice(&b.encode());
            }
            SyncResponse::Genesis(g) => {
                out.push(SYNC_TAG_GENESIS);
                out.extend_from_slice(&g.encode());
            }
        }
        out
    }
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        let (&tag, rest) = buf.split_first().ok_or(WireError::Truncated)?;
        match tag {
            SYNC_TAG_HELLO => Ok(SyncResponse::Hello(Hello::decode(rest)?)),
            SYNC_TAG_BLOCKS => Ok(SyncResponse::Blocks(Blocks::decode(rest)?)),
            SYNC_TAG_GENESIS => Ok(SyncResponse::Genesis(Genesis::decode(rest)?)),
            _ => Err(WireError::Invalid("sync-response-tag")),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// secp256k1 ecrecover — the same scheme `rpc::recover_proposer` uses (65-byte r‖s‖v, v = 27 + recid).
// Kept here so the network can verify proposer sigs / peer proofs without depending on crates/rpc.
// ---------------------------------------------------------------------------------------------

/// Recover an EVM address from a 65-byte `r‖s‖v` secp256k1 signature over a 32-byte digest. Returns
/// `None` on a malformed signature. Byte-for-byte compatible with `rpc::recover_proposer` and the
/// chain's tx recovery.
pub fn recover_secp256k1(digest: &Hash, sig: &[u8]) -> Option<Address> {
    use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
    if sig.len() != 65 {
        return None;
    }
    let recid = RecoveryId::from_byte(sig[64].checked_sub(27)?)?;
    let signature = Signature::from_slice(&sig[..64]).ok()?;
    let vkey = VerifyingKey::recover_from_prehash(digest.as_slice(), &signature, recid).ok()?;
    let pubkey = vkey.to_encoded_point(false);
    let addr_hash = keccak256(&pubkey.as_bytes()[1..]);
    Some(Address::from_slice(&addr_hash[12..]))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consts::PROTOCOL_VERSION;
    use k256::ecdsa::SigningKey;

    fn addr_of(sk: &SigningKey) -> Address {
        let vk = sk.verifying_key();
        let p = vk.to_encoded_point(false);
        let h = keccak256(&p.as_bytes()[1..]);
        Address::from_slice(&h[12..])
    }
    fn sign(sk: &SigningKey, digest: &Hash) -> Vec<u8> {
        let (sig, recid) = sk.sign_prehash_recoverable(digest.as_slice()).unwrap();
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.r().to_bytes());
        out.extend_from_slice(&sig.s().to_bytes());
        out.push(27 + recid.to_byte());
        out
    }

    #[test]
    fn tx_announce_roundtrip_and_id() {
        let raw = vec![0x02u8, 0xaa, 0xbb, 0xcc, 0xdd];
        let tx = TxAnnounce::new(raw.clone());
        let enc = tx.encode();
        let back = TxAnnounce::decode(&enc).unwrap();
        assert_eq!(back, tx);
        assert_eq!(tx.message_id(), keccak256(&raw));
        // Empty / over-large are rejected.
        assert_eq!(TxAnnounce::decode(&[]), Err(WireError::Truncated));
        assert_eq!(
            TxAnnounce::decode(&vec![0u8; MAX_TX_BYTES + 1]),
            Err(WireError::TooLong)
        );
    }

    #[test]
    fn block_roundtrip_hash_and_txs_root() {
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let proposer = addr_of(&sk);
        let txs = vec![vec![1u8, 2, 3], vec![9u8, 9, 9, 9]];
        // Build a block whose txs_root is the canonical root over its txs, then sign the header.
        let mut b = WireBlock {
            number: 5,
            parent_hash: B256::repeat_byte(0x11),
            timestamp: 1_700_000_010,
            txs_root: B256::ZERO,
            state_root: B256::repeat_byte(0x22),
            proposer,
            proposer_sig: vec![],
            txs: txs.clone(),
        };
        b.txs_root = b.recompute_txs_root();
        b.proposer_sig = sign(&sk, &b.hash());

        let enc = b.encode();
        let back = WireBlock::decode(&enc).unwrap();
        assert_eq!(back, b);
        assert_eq!(back.hash(), b.hash());
        assert!(back.shallow_verify(), "valid block must shallow-verify");
        assert_eq!(back.recover_proposer(), Some(proposer));

        // Tamper a tx => txs_root mismatch => shallow_verify fails (a follower would reject).
        let mut tampered = back.clone();
        tampered.txs[0] = vec![0xff];
        assert!(!tampered.shallow_verify());

        // Trailing bytes are non-canonical.
        let mut trailing = enc.clone();
        trailing.push(0);
        assert_eq!(WireBlock::decode(&trailing), Err(WireError::TrailingBytes));
    }

    /// SEC-M5A-1: a forged UNSIGNED block (empty `proposer_sig`) — even one whose `txs_root` is internally
    /// consistent and that claims a huge `number` to drive a sync loop — must NOT shallow-verify. Failing
    /// closed on an absent signature is what stops the network surfacing/forwarding it and the sync driver
    /// trusting its forged tip.
    #[test]
    fn unsigned_block_fails_shallow_verify_even_with_huge_number() {
        let txs: Vec<Vec<u8>> = Vec::new(); // an empty-tx block (the cheapest forgery)
        let mut forged = WireBlock {
            number: u64::MAX,
            parent_hash: B256::ZERO,
            timestamp: 1_700_000_000,
            txs_root: B256::ZERO,
            state_root: B256::ZERO,
            proposer: Address::ZERO,
            proposer_sig: vec![], // UNSIGNED
            txs,
        };
        forged.txs_root = forged.recompute_txs_root(); // internally consistent txs_root
        assert!(
            !forged.shallow_verify(),
            "an unsigned block must fail shallow-verify (SEC-M5A-1) — it cannot be trusted for its number"
        );

        // A signature by the WRONG key (recovers to a different address than `proposer`) also fails.
        let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
        forged.proposer = Address::repeat_byte(0xee); // not the signer's address
        forged.proposer_sig = sign(&sk, &forged.hash());
        assert!(
            !forged.shallow_verify(),
            "a signature that does not recover to `proposer` must fail shallow-verify"
        );
    }

    #[test]
    fn hello_roundtrip_and_binding() {
        let sk = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let validator = addr_of(&sk);
        let genesis = B256::repeat_byte(0xab);
        let peer_id_bytes = b"peer-id-bytes-xyz";
        let proof = sign(&sk, &Hello::proof_digest(peer_id_bytes, &genesis));

        let hello = Hello {
            genesis_hash: genesis,
            chain_id: 0x5542,
            tip: (42, B256::repeat_byte(0xcd)),
            validator: Some(validator),
            peer_proof: proof,
            protocol_ver: PROTOCOL_VERSION,
        };
        let back = Hello::decode(&hello.encode()).unwrap();
        assert_eq!(back, hello);
        assert_eq!(back.verify_binding(peer_id_bytes), Some(validator));
        // Wrong peer-id bytes => binding fails.
        assert_eq!(back.verify_binding(b"other-peer"), None);

        // A non-validator hello (no proof) binds to nothing but still round-trips.
        let plain = Hello {
            genesis_hash: genesis,
            chain_id: 0x5542,
            tip: (0, B256::ZERO),
            validator: None,
            peer_proof: vec![],
            protocol_ver: PROTOCOL_VERSION,
        };
        let back = Hello::decode(&plain.encode()).unwrap();
        assert_eq!(back, plain);
        assert_eq!(back.verify_binding(peer_id_bytes), None);
    }

    #[test]
    fn sync_roundtrip_and_bounds() {
        let get = GetBlocks { from: 1, to: 128 };
        assert_eq!(GetBlocks::decode(&get.encode()).unwrap(), get);

        let mk = |n: u64| {
            let mut b = WireBlock {
                number: n,
                parent_hash: B256::repeat_byte(n as u8),
                timestamp: 1_700_000_000 + n,
                txs_root: B256::ZERO,
                state_root: B256::repeat_byte((n + 1) as u8),
                proposer: Address::ZERO,
                proposer_sig: vec![],
                txs: vec![vec![n as u8; 4]],
            };
            b.txs_root = b.recompute_txs_root();
            b
        };
        let blocks = Blocks {
            blocks: vec![mk(1), mk(2), mk(3)],
        };
        assert_eq!(Blocks::decode(&blocks.encode()).unwrap(), blocks);

        // A response claiming more than SYNC_MAX_BATCH blocks is rejected (AC-F8).
        let mut buf = Vec::new();
        buf.extend_from_slice(&((super::super::consts::SYNC_MAX_BATCH + 1) as u32).to_be_bytes());
        assert_eq!(Blocks::decode(&buf), Err(WireError::TooLong));
    }

    /// The genesis-anchor request/response round-trips through the `SyncRequest`/`SyncResponse`
    /// envelope (spec 07 §3.4 — the `ln-trust-1`/`ln-trust-2` verifiable-anchor messages).
    #[test]
    fn genesis_anchor_roundtrip() {
        // GetGenesis carries no body; an empty body round-trips, a non-empty one is non-canonical.
        let req = SyncRequest::GetGenesis(GetGenesis);
        assert_eq!(SyncRequest::decode(&req.encode()).unwrap(), req);
        assert_eq!(GetGenesis::decode(&[]).unwrap(), GetGenesis);
        assert_eq!(GetGenesis::decode(&[0]), Err(WireError::TrailingBytes));

        let genesis = Genesis {
            genesis_hash: B256::repeat_byte(0xab),
            chain_id: 0x5542,
            state_root: B256::repeat_byte(0xcd),
            genesis_time: 1_700_000_000,
            proposer: Address::repeat_byte(0x3c),
            snapshot: br#"{"version":1,"state":{"accounts":[]}}"#.to_vec(),
        };
        let resp = SyncResponse::Genesis(genesis.clone());
        let back = SyncResponse::decode(&resp.encode()).unwrap();
        assert_eq!(back, resp);
        if let SyncResponse::Genesis(g) = back {
            assert_eq!(g, genesis);
        } else {
            panic!("expected Genesis response");
        }
    }
}
