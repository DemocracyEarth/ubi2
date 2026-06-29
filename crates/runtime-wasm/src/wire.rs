//! The canonical `WireBlock` (the `ubi2/sync/1` block payload, spec 05 §2.2/§4.2) — a small,
//! self-contained decode depending ONLY on `alloy-primitives` + `k256`, so it compiles to
//! `wasm32-unknown-unknown` (unlike `crates/network`, which carries the full libp2p stack).
//!
//! ## Why a copy here, and why it is NOT a fork (spec 07 §2.3, ADR-0006 Decision 2)
//! The browser follower must re-execute and verify **exactly** the bytes a server follower verifies. The
//! canonical definition lives in `crates/network::wire::WireBlock`, but that crate's libp2p dependency
//! (yamux → rand → getrandom 0.3, prost, snow, hickory-dns) does not build to wasm and bloats a browser
//! blob. The spec is explicit that the wire types depend only on `alloy-primitives` + `k256`. So this
//! module is a **byte-for-byte port** of that `WireBlock` (same field order, same length-prefix rules,
//! same `header_preimage`/`hash`/`recompute_txs_root`/`shallow_verify`/ecrecover), and the parity gate
//! (`tests/parity.rs`, AC-WB) asserts it decodes the SAME bytes to the SAME fields + hash +
//! `shallow_verify` result as `ubi2_network::wire::WireBlock`. It is therefore *provably* the canonical
//! format, not a drifting second serialization.

use alloy_primitives::{keccak256, Address, B256};

/// A 32-byte hash (block hash / tx hash / state root).
pub type Hash = B256;

/// Bound on a single block's encoded size (mirrors `crates/network::consts::MAX_BLOCK_BYTES`). Bounds a
/// browser's per-message allocation against a flooding gateway (spec §7, AC-F8).
const MAX_BLOCK_BYTES: usize = 4 * 1024 * 1024;
/// Bound on a single raw tx (mirrors `crates/network::consts::MAX_TX_BYTES`).
const MAX_TX_BYTES: usize = 128 * 1024;

/// Errors decoding a wire payload. The light client drops the message and surfaces a verification stop;
/// it never panics on attacker-controlled bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireError {
    /// The buffer ended before a field finished.
    Truncated,
    /// A length prefix exceeds the message's stated/maximum bound.
    TooLong,
    /// Trailing bytes after the message (non-canonical).
    TrailingBytes,
}

impl core::fmt::Display for WireError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WireError::Truncated => write!(f, "wire: truncated"),
            WireError::TooLong => write!(f, "wire: length prefix too long"),
            WireError::TrailingBytes => write!(f, "wire: trailing bytes"),
        }
    }
}

impl std::error::Error for WireError {}

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

/// A block on the wire (spec §2.2 header + ordered raw txs). Field-for-field identical to
/// `crates/network::wire::WireBlock`. `txs` are the raw EIP-155 tx bytes (verbatim RLP) in block order.
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
    /// (spec §2.2) — byte-identical to `crates/network`/`rpc::Block::header_preimage`.
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

    /// The block hash = `keccak256(header_preimage)` (spec §2.2).
    pub fn hash(&self) -> Hash {
        keccak256(self.header_preimage())
    }

    /// Recompute `txs_root` from the carried raw txs: `keccak256(count ‖ each tx hash)` where each tx
    /// hash is `keccak256(raw)` (spec §5.3).
    pub fn recompute_txs_root(&self) -> Hash {
        let mut buf = Vec::with_capacity(8 + self.txs.len() * 32);
        buf.extend_from_slice(&(self.txs.len() as u64).to_be_bytes());
        for raw in &self.txs {
            buf.extend_from_slice(keccak256(raw).as_slice());
        }
        keccak256(&buf)
    }

    /// Canonical encoding: header fields (§2.2 order), then `txs.len()` (`u32`), then each raw tx as a
    /// length-prefixed blob. Exactly one encoding per block.
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

    /// Decode a single canonically-encoded block (bounded by `MAX_BLOCK_BYTES`).
    pub fn decode(buf: &[u8]) -> Result<Self, WireError> {
        if buf.len() > MAX_BLOCK_BYTES {
            return Err(WireError::TooLong);
        }
        let mut r = Reader::new(buf);
        let number = r.u64()?;
        let parent_hash = r.b256()?;
        let timestamp = r.u64()?;
        let txs_root = r.b256()?;
        let state_root = r.b256()?;
        let proposer = r.address()?;
        let proposer_sig = r.bytes(65)?;
        let count = r.u32()? as usize;
        if count > (MAX_BLOCK_BYTES / 4) {
            return Err(WireError::TooLong);
        }
        let mut txs = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            txs.push(r.bytes(MAX_TX_BYTES)?);
        }
        r.finish()?;
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

    /// Recover the proposer address from `proposer_sig` over the header hash, if a signature is present.
    pub fn recover_proposer(&self) -> Option<Address> {
        recover_secp256k1(&self.hash(), &self.proposer_sig)
    }

    /// The "verify what we can" check (spec §3.1, fail-closed): the carried `txs_root` matches the txs
    /// **and** the block carries a valid proposer signature recovering to `proposer`. An unsigned/empty
    /// signature is **never** trusted (SEC-M5A-1) — an unsigned block claiming any height fails closed.
    /// Byte-identical to `crates/network::wire::WireBlock::shallow_verify`.
    pub fn shallow_verify(&self) -> bool {
        if self.recompute_txs_root() != self.txs_root {
            return false;
        }
        if self.proposer_sig.is_empty() {
            return false;
        }
        match self.recover_proposer() {
            Some(addr) => addr == self.proposer,
            None => false,
        }
    }
}

/// Recover an EVM address from a 65-byte `r‖s‖v` secp256k1 signature over a 32-byte digest. Returns
/// `None` on a malformed signature. Byte-for-byte compatible with `crates/network::wire::
/// recover_secp256k1` / `rpc::recover_proposer` (`v = 27 + recid`).
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
