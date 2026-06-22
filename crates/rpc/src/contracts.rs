//! M4 prompt contracts: ContractHub calldata ABI + canonical effect (ops blob) wire codec.
//!
//! Spec: `docs/specs/04-prompt-contracts.md` (§"RPC / interfaces"). This module is the pure
//! (state-free) ABI layer for the prompt-contract write surface, mirroring [`crate::humanity`] (the
//! HumanityHub) and [`crate::streams`] (the StreamHub). The stateful dispatch — recovering the signer,
//! queuing ops, applying them at block time against the node's [`ubi2_runtime::ContractInterpreter`],
//! emitting receipt logs, and the `ubi_*` reads — lives in `lib.rs`.
//!
//! ## The ContractHub system address (`0x…5043`)
//! Prompt-contract write ops are EVM txs to the reserved [`CONTRACT_HUB`] system address, exactly the
//! way stream ops target the StreamHub (`0x…5742`) and proof-of-humanity ops target the HumanityHub
//! (`0x…5048`). `0x5043` is ASCII `"PC"` (Prompt-Contract) — picked so the three hubs never collide.
//! MetaMask / viem / ethers encode the calls below identically because the Solidity-style signatures
//! match keccak selectors. The constant is re-exported from the runtime so the escrow address space
//! (see [`ubi2_runtime::contract_address`]) and the RPC hub stay one source of truth.
//!
//! ## Write ops (calldata to ContractHub, via `eth_sendRawTransaction`)
//!   * `deployContract(bytes32 textRef, address[] parties)` — register an `Active` contract.
//!   * `fundContract(uint256 id)` — fund the contract's escrow with the tx's `value` (a value-bearing
//!     tx to the hub; the runtime moves it from the signer into the escrow account).
//!   * `invokeContract(uint256 id, bytes32 triggerRef)` — open an `ExecCase`; the node runs the
//!     interpreter quorum at block time and commits/aborts the agreed effect.
//!   * `submitEffect(uint256 caseId, bytes ops)` — an interpreter's signed canonical effect (the
//!     deferred juror-daemon path). `ops` is the canonical effect encoding (see [`encode_effect`]).
//!
//! The natural-language contract text and trigger input are **not** on the wire (I6 — no prose/PII
//! on-chain): the txs commit only `textRef`/`triggerRef`. For the M4 devnet the node derives the
//! deterministic stand-in text/trigger bytes from those refs (see [`derive_text`]/[`derive_trigger`])
//! so the deterministic `MockInterpreter` can interpret the contract end-to-end without an off-chain
//! channel — the same seam M3 uses for liveness (`humanity::derive_liveness`). The live node swaps a
//! real interpreter + a real text/trigger fetch behind the same boundary.

use alloy_primitives::{Address as AlloyAddr, B256, U256};
use alloy_sol_types::{sol, SolCall};

use ubi2_runtime::{CanonicalEffect, Hash, Op, StreamId, CONTRACT_HUB as RT_CONTRACT_HUB};

/// The reserved ContractHub system address (`0x…5043`) — prompt-contract write ops target it. Re-uses
/// the runtime constant so the RPC hub and the escrow address space share one source of truth.
/// `0x5043` is ASCII `"PC"` (Prompt-Contract); distinct from HumanityHub (`0x…5048`)/StreamHub
/// (`0x…5742`).
pub const CONTRACT_HUB: AlloyAddr = AlloyAddr::new(RT_CONTRACT_HUB);

// ---------------------------------------------------------------------------------------------
// ABI: ContractHub calldata (writes). `sol!` derives the 4-byte selectors so wallets encode them
// identically to a real Solidity interface.
// ---------------------------------------------------------------------------------------------

sol! {
    /// ContractHub prompt-contract write ops (via `eth_sendRawTransaction`). Solidity-style signatures
    /// so MetaMask / viem / ethers encode them byte-identically to the on-chain selectors.
    interface IContractHub {
        /// Deploy a NL prompt contract committing `textRef`, with the declared `parties` (I6 — only a
        /// commitment on-chain; the prose lives off-chain / in calldata).
        function deployContract(bytes32 textRef, address[] parties) external;
        /// Fund contract `id`'s escrow with the tx's `value` (a value-bearing tx to the hub).
        function fundContract(uint256 id) external payable;
        /// Invoke contract `id` with a content-addressed `triggerRef`, opening an ExecCase.
        function invokeContract(uint256 id, bytes32 triggerRef) external;
        /// An interpreter's signed canonical effect on `caseId`. `ops` is the canonical effect encoding
        /// (see `encode_effect`) — the quorum compares the effect, never any off-chain reason (I1).
        function submitEffect(uint256 caseId, bytes ops) external;
    }
}

/// Re-export the generated call types so `lib.rs` can match on selectors without re-deriving them.
pub use IContractHub::{
    deployContractCall, fundContractCall, invokeContractCall, submitEffectCall,
};

/// A decoded ContractHub *write* op, parsed from a tx's calldata. The signer (recovered from the tx)
/// is supplied separately as `from`/`caller` by the dispatcher in `lib.rs`. The `value` for
/// `FundContract` is the tx's `msg.value`, also threaded by the dispatcher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContractOp {
    /// `deployContract(textRef, parties)` — register an `Active` contract for the tx signer.
    DeployContract {
        text_ref: Hash,
        parties: Vec<AlloyAddr>,
    },
    /// `fundContract(id)` — fund the escrow with the tx's value (carried separately).
    FundContract { id: u64 },
    /// `invokeContract(id, triggerRef)` — open an ExecCase under interpretation.
    InvokeContract { id: u64, trigger_ref: Hash },
    /// `submitEffect(caseId, ops)` — an interpreter's canonical effect (decoded from the ops blob).
    SubmitEffect {
        case_id: u64,
        effect: CanonicalEffect,
    },
}

/// Why a ContractHub calldata blob could not be turned into a [`ContractOp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CalldataError {
    /// Calldata shorter than a 4-byte selector.
    TooShort,
    /// Selector did not match any known ContractHub write op.
    UnknownSelector([u8; 4]),
    /// Selector matched but the argument tail failed to ABI-decode.
    BadArgs(String),
    /// A `uint256` id/case-id argument exceeded the runtime's `u64` range.
    Overflow(&'static str),
    /// `submitEffect`'s ops blob failed to decode into a canonical effect.
    BadEffect(&'static str),
}

impl std::fmt::Display for CalldataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalldataError::TooShort => write!(f, "calldata too short for a selector"),
            CalldataError::UnknownSelector(s) => {
                let hex: String = s.iter().map(|b| format!("{b:02x}")).collect();
                write!(f, "unknown ContractHub selector 0x{hex}")
            }
            CalldataError::BadArgs(e) => write!(f, "bad ContractHub calldata args: {e}"),
            CalldataError::Overflow(which) => write!(f, "{which} exceeds the runtime range"),
            CalldataError::BadEffect(which) => write!(f, "ops blob: {which}"),
        }
    }
}

/// Parse ContractHub calldata (selector + ABI args) into a [`ContractOp`]. Unknown selectors and
/// malformed args are surfaced distinctly so the RPC can return a precise error.
pub fn parse_calldata(data: &[u8]) -> Result<ContractOp, CalldataError> {
    if data.len() < 4 {
        return Err(CalldataError::TooShort);
    }
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    match selector {
        s if s == deployContractCall::SELECTOR => {
            let call = deployContractCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(ContractOp::DeployContract {
                text_ref: call.textRef.0,
                parties: call.parties,
            })
        }
        s if s == fundContractCall::SELECTOR => {
            let call = fundContractCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            let id = to_u64(call.id, "id")?;
            Ok(ContractOp::FundContract { id })
        }
        s if s == invokeContractCall::SELECTOR => {
            let call = invokeContractCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            let id = to_u64(call.id, "id")?;
            Ok(ContractOp::InvokeContract {
                id,
                trigger_ref: call.triggerRef.0,
            })
        }
        s if s == submitEffectCall::SELECTOR => {
            let call = submitEffectCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            let case_id = to_u64(call.caseId, "caseId")?;
            let effect = decode_effect(&call.ops)?;
            Ok(ContractOp::SubmitEffect { case_id, effect })
        }
        other => Err(CalldataError::UnknownSelector(other)),
    }
}

/// Narrow a `uint256` ABI argument to the runtime's `u64` id range (fail closed on overflow).
fn to_u64(v: U256, which: &'static str) -> Result<u64, CalldataError> {
    if v > U256::from(u64::MAX) {
        return Err(CalldataError::Overflow(which));
    }
    Ok(v.to::<u64>())
}

// ---------------------------------------------------------------------------------------------
// Canonical effect (ops blob) wire codec.
//
// `submitEffect(caseId, bytes ops)` carries the canonical effect as an opaque `bytes` blob. The blob
// is the runtime's own canonical effect encoding ([`CanonicalEffect::encode`]) — byte-for-byte the
// same layout an honest interpreter's `effect_hash` is taken over (4-byte BE op count, then per op a
// 1-byte tag + fixed-width BE fields: Transfer=0, Refund=1, OpenStream=2, StopStream=3, SetVar=4,
// Abort=5; Address=20B, u128=16B BE, u64=8B BE, hash=32B). Re-encoding here and recomputing the hash
// via `CanonicalEffect::new` guarantees a submitted effect groups in the quorum tally with a mock /
// live interpreter that emitted the same ops (I1). We do NOT trust a hash on the wire — we recompute
// it from the decoded ops, so two interpreters submitting the same ops always agree.
// ---------------------------------------------------------------------------------------------

/// Op tags — must match [`ubi2_runtime::Op`]'s canonical `tag()` (see `runtime::contracts`).
const TAG_TRANSFER: u8 = 0;
const TAG_REFUND: u8 = 1;
const TAG_OPEN_STREAM: u8 = 2;
const TAG_STOP_STREAM: u8 = 3;
const TAG_SET_VAR: u8 = 4;
const TAG_ABORT: u8 = 5;

/// Encode a [`CanonicalEffect`] into the wire `ops` blob (re-exports the runtime's canonical encoding
/// so a wallet/SDK builds a `submitEffect` calldata that groups with the same ops from another node).
pub fn encode_effect(effect: &CanonicalEffect) -> Vec<u8> {
    effect.encode()
}

/// Decode a wire `ops` blob into a [`CanonicalEffect`], recomputing the `effect_hash` from the decoded
/// ops (never trusting a hash on the wire — I1). Fail-closed: any malformed blob is rejected with a
/// precise [`CalldataError::BadEffect`] so the tx reverts rather than committing a half-parsed effect.
pub fn decode_effect(blob: &[u8]) -> Result<CanonicalEffect, CalldataError> {
    let mut c = Cursor::new(blob);
    let count = c.u32()? as usize;
    // Bound the op count to the remaining bytes (a 1-byte tag minimum each) so a huge count can't be
    // used to force a large allocation before the bytes are even present.
    if count > blob.len() {
        return Err(CalldataError::BadEffect("op count exceeds blob length"));
    }
    let mut ops = Vec::with_capacity(count);
    for _ in 0..count {
        let tag = c.u8()?;
        let op = match tag {
            TAG_TRANSFER => Op::Transfer {
                to: c.addr()?,
                amount: c.u128()?,
            },
            TAG_REFUND => Op::Refund {
                party: c.addr()?,
                amount: c.u128()?,
            },
            TAG_OPEN_STREAM => Op::OpenStream {
                to: c.addr()?,
                rate: c.u128()?,
                deposit: c.u128()?,
            },
            TAG_STOP_STREAM => Op::StopStream {
                id: c.u64()? as StreamId,
            },
            TAG_SET_VAR => Op::SetVar {
                key: c.hash()?,
                value: c.hash()?,
            },
            TAG_ABORT => Op::Abort {
                reason_hash: c.hash()?,
            },
            _ => return Err(CalldataError::BadEffect("unknown op tag")),
        };
        ops.push(op);
    }
    if !c.is_empty() {
        return Err(CalldataError::BadEffect("trailing bytes after ops"));
    }
    // Recompute the hash from the decoded ops (consensus-internal grouping key — I1).
    Ok(CanonicalEffect::new(ops))
}

/// A minimal big-endian byte cursor for [`decode_effect`] (no external crate; fail-closed on short
/// reads so a truncated blob reverts rather than committing a partial effect).
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], CalldataError> {
        if self.pos + n > self.buf.len() {
            return Err(CalldataError::BadEffect("unexpected end of ops blob"));
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8, CalldataError> {
        Ok(self.take(1)?[0])
    }
    fn u32(&mut self) -> Result<u32, CalldataError> {
        let s = self.take(4)?;
        Ok(u32::from_be_bytes([s[0], s[1], s[2], s[3]]))
    }
    fn u64(&mut self) -> Result<u64, CalldataError> {
        let s = self.take(8)?;
        let mut b = [0u8; 8];
        b.copy_from_slice(s);
        Ok(u64::from_be_bytes(b))
    }
    fn u128(&mut self) -> Result<u128, CalldataError> {
        let s = self.take(16)?;
        let mut b = [0u8; 16];
        b.copy_from_slice(s);
        Ok(u128::from_be_bytes(b))
    }
    fn addr(&mut self) -> Result<[u8; 20], CalldataError> {
        let s = self.take(20)?;
        let mut b = [0u8; 20];
        b.copy_from_slice(s);
        Ok(b)
    }
    fn hash(&mut self) -> Result<Hash, CalldataError> {
        let s = self.take(32)?;
        let mut b = [0u8; 32];
        b.copy_from_slice(s);
        Ok(b)
    }
}

// ---------------------------------------------------------------------------------------------
// Off-chain text / trigger derivation (the devnet seam — no prose/PII on-chain, I6).
// ---------------------------------------------------------------------------------------------

/// Derive deterministic stand-in NL **contract text** bytes from the on-chain `textRef` commitment
/// (the seam to a real off-chain text fetch — M4 scope cut, mirrors `humanity::derive_liveness`).
///
/// For the devnet the deployer commits a `textRef` on-chain and the node reconstructs the text bytes
/// the `MockInterpreter` keys off from it: `keccak("ubi2-contract-text" || ref)`. Pure function of the
/// committed ref, so every node derives identical bytes and the deterministic interpreter converges
/// reproducibly (I1/I5). A real node swaps this for the actual text fetched by `text_ref`.
pub fn derive_text(text_ref: &Hash) -> Vec<u8> {
    use alloy_primitives::keccak256;
    let mut t = Vec::with_capacity(18 + 32);
    t.extend_from_slice(b"ubi2-contract-text");
    t.extend_from_slice(text_ref);
    keccak256(&t).as_slice().to_vec()
}

/// Derive deterministic stand-in **trigger** bytes from the on-chain `triggerRef` commitment (the seam
/// to a real off-chain trigger fetch — M4 scope cut). `keccak("ubi2-contract-trigger" || ref)`. Pure
/// function of the committed ref (I1/I5).
pub fn derive_trigger(trigger_ref: &Hash) -> Vec<u8> {
    use alloy_primitives::keccak256;
    let mut t = Vec::with_capacity(21 + 32);
    t.extend_from_slice(b"ubi2-contract-trigger");
    t.extend_from_slice(trigger_ref);
    keccak256(&t).as_slice().to_vec()
}

// ---------------------------------------------------------------------------------------------
// Receipt-log topic helpers (shared shape with the HumanityHub/StreamHub event logs).
// ---------------------------------------------------------------------------------------------

/// 32-byte big-endian topic for a `u64` (left-padded) — indexed contract/case ids in receipt logs.
pub fn u64_topic(v: u64) -> B256 {
    B256::from(U256::from(v))
}

/// 32-byte topic for an address (left-padded to 32 bytes, EVM-style).
pub fn addr_topic(a: &AlloyAddr) -> B256 {
    let mut b = [0u8; 32];
    b[12..].copy_from_slice(a.as_slice());
    B256::from(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;
    use ubi2_runtime::UBI;

    #[test]
    fn selectors_match_solidity() {
        assert_eq!(
            &deployContractCall::SELECTOR,
            &keccak256(b"deployContract(bytes32,address[])")[..4]
        );
        assert_eq!(
            &fundContractCall::SELECTOR,
            &keccak256(b"fundContract(uint256)")[..4]
        );
        assert_eq!(
            &invokeContractCall::SELECTOR,
            &keccak256(b"invokeContract(uint256,bytes32)")[..4]
        );
        assert_eq!(
            &submitEffectCall::SELECTOR,
            &keccak256(b"submitEffect(uint256,bytes)")[..4]
        );
    }

    #[test]
    fn hub_address_is_5043() {
        // ASCII "PC" in the low two bytes; distinct from HumanityHub 0x…5048 / StreamHub 0x…5742.
        assert_eq!(CONTRACT_HUB.as_slice()[18], 0x50);
        assert_eq!(CONTRACT_HUB.as_slice()[19], 0x43);
        assert_ne!(CONTRACT_HUB, crate::humanity::HUMANITY_HUB);
        assert_ne!(CONTRACT_HUB, crate::streams::STREAM_HUB);
    }

    #[test]
    fn parse_deploy_round_trips() {
        let text_ref: Hash = [0xab; 32];
        let parties = vec![AlloyAddr::from([0x11; 20]), AlloyAddr::from([0x22; 20])];
        let data = deployContractCall {
            textRef: text_ref.into(),
            parties: parties.clone(),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            ContractOp::DeployContract { text_ref, parties }
        );
    }

    #[test]
    fn parse_fund_and_invoke() {
        let data = fundContractCall {
            id: U256::from(7u8),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            ContractOp::FundContract { id: 7 }
        );

        let trigger_ref: Hash = [0xcd; 32];
        let data = invokeContractCall {
            id: U256::from(3u8),
            triggerRef: trigger_ref.into(),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            ContractOp::InvokeContract { id: 3, trigger_ref }
        );
    }

    #[test]
    fn id_overflow_is_rejected() {
        let data = fundContractCall {
            id: U256::from(u64::MAX) + U256::from(1u8),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap_err(),
            CalldataError::Overflow("id")
        );
    }

    #[test]
    fn unknown_selector_is_distinct() {
        let data = vec![0xde, 0xad, 0xbe, 0xef, 0x00];
        assert_eq!(
            parse_calldata(&data).unwrap_err(),
            CalldataError::UnknownSelector([0xde, 0xad, 0xbe, 0xef])
        );
    }

    #[test]
    fn effect_blob_round_trips_every_op() {
        // A blob with one of every op variant decodes back to the same effect_hash the runtime would
        // compute — so a submitted effect groups with a mock/live interpreter's identical ops (I1).
        let effect = CanonicalEffect::new(vec![
            Op::Transfer {
                to: [0x02; 20],
                amount: 5 * UBI,
            },
            Op::Refund {
                party: [0x01; 20],
                amount: UBI,
            },
            Op::OpenStream {
                to: [0x03; 20],
                rate: 1,
                deposit: 100,
            },
            Op::StopStream { id: 9 },
            Op::SetVar {
                key: [0x07; 32],
                value: [0x08; 32],
            },
            Op::Abort {
                reason_hash: [0x09; 32],
            },
        ]);
        let blob = encode_effect(&effect);
        let decoded = decode_effect(&blob).unwrap();
        assert_eq!(decoded, effect);
        assert_eq!(decoded.effect_hash, effect.effect_hash);
    }

    #[test]
    fn submit_effect_calldata_round_trips() {
        let effect = CanonicalEffect::new(vec![Op::Transfer {
            to: [0x02; 20],
            amount: 5 * UBI,
        }]);
        let data = submitEffectCall {
            caseId: U256::from(4u8),
            ops: encode_effect(&effect).into(),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            ContractOp::SubmitEffect { case_id: 4, effect }
        );
    }

    #[test]
    fn empty_ops_blob_is_a_noop_effect() {
        let noop = CanonicalEffect::noop();
        let blob = encode_effect(&noop);
        assert_eq!(decode_effect(&blob).unwrap(), noop);
    }

    #[test]
    fn truncated_and_trailing_blobs_fail_closed() {
        // A claimed 1-op blob that ends before the op body → reverts.
        let mut short = 1u32.to_be_bytes().to_vec();
        short.push(TAG_TRANSFER); // tag only, no address/amount
        assert!(matches!(
            decode_effect(&short),
            Err(CalldataError::BadEffect(_))
        ));

        // A valid effect with trailing junk → reverts (no half-parse).
        let mut trailing = encode_effect(&CanonicalEffect::noop());
        trailing.push(0xff);
        assert!(matches!(
            decode_effect(&trailing),
            Err(CalldataError::BadEffect(_))
        ));

        // An absurd op count (larger than the blob) → reverts before allocating.
        let huge = u32::MAX.to_be_bytes().to_vec();
        assert!(matches!(
            decode_effect(&huge),
            Err(CalldataError::BadEffect(_))
        ));
    }

    #[test]
    fn derive_text_and_trigger_are_deterministic() {
        let r: Hash = [0x07; 32];
        assert_eq!(derive_text(&r), derive_text(&r));
        assert_eq!(derive_trigger(&r), derive_trigger(&r));
        // Text and trigger derivations differ, and differ per ref.
        assert_ne!(derive_text(&r), derive_trigger(&r));
        assert_ne!(derive_text(&r), derive_text(&[0x08; 32]));
    }
}
