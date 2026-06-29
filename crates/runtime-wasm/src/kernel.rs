//! `LightCore` — the browser follower's block re-execution kernel (spec 07 §2.3, ADR-0006 Decision 3).
//!
//! This is the pure, async-free, networking-free re-execution path the browser light node runs to
//! **verify** a `WireBlock`: decode each raw EIP-155 tx, re-execute it against a `MemState` at
//! `block.timestamp`, recompute `txs_root` + `state_root`, and accept the block only if those roots
//! match the header **byte-for-byte**. It is the same trust guarantee a server follower
//! (`crates/rpc::Chain::validate_and_apply_block`) has — a lying gateway is *caught*, not trusted.
//!
//! ## No logic fork (the load-bearing rule, ADR-0006 Decision 3)
//! Every state transition here is the runtime's **own** function — `charge_fee`, `apply_transfer`,
//! `open_stream`, `stop_stream`, `state_root` — called with `block.timestamp` as the only clock. The tx
//! decode (`alloy` `TxEnvelope::decode_2718` + EIP-155 chain-id bind + signer recovery + StreamHub
//! calldata shape) and the per-kind gas/fee are decoded **identically** to the server follower's
//! `decode_pending_tx` / `execute_block`, so a block re-executes to the SAME post-state on both. The
//! parity gate (`tests/parity.rs`, AC-WB) asserts byte-identical `state_root` at every height against
//! the real `crates/rpc` follower, so the two kernels are *provably* the same.
//!
//! ## Phase 1 scope (de-risk the boundary first)
//! Phase 1 verifies the **value-flow** tx kinds — plain transfers and the two StreamHub ops
//! (`openStream` / `stopStream`) — plus empty blocks. These are the kinds whose re-execution is a pure
//! function of `(state, timestamp)` with **no** AI seam: they need no `HumanityOracle` / `Contract-
//! Interpreter` and trigger none of the M3/M4 sybil/finalize/effect sweeps. The HumanityHub /
//! ContractHub kinds (which DO drive the AI quorum + sweeps) are handed off to the sync phase once the
//! shared `crates/exec` kernel the spec calls for is factored out of `crates/rpc` — until then a block
//! carrying one is reported as an unsupported-kind verification stop (fail-closed, never a wrong
//! balance). The corpus the parity gate exercises is exactly these supported kinds.

use ubi2_runtime::{
    apply_transfer, charge_fee, fee_for_gas, open_stream, state_root as runtime_state_root,
    stop_stream, Account, MemState, State, GAS_STREAM, GAS_TRANSFER,
};

use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{keccak256, B256, U256};
use alloy_sol_types::SolCall;

use crate::wire::WireBlock;

/// The reserved StreamHub system address (`0x…5742`, spec D2) — byte-identical to
/// `crates/rpc::streams::STREAM_HUB`. Stream ops are EVM txs whose `to` is this address.
pub const STREAM_HUB: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x57, 0x42,
];
/// The reserved HumanityHub system address (`0x…5048`). A tx to it is an AI-seam op (M3) not yet
/// re-executed by the Phase-1 browser kernel.
pub const HUMANITY_HUB: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x48,
];
/// The reserved ContractHub system address (`0x…5043`). A tx to it is an AI-seam op (M4) not yet
/// re-executed by the Phase-1 browser kernel.
pub const CONTRACT_HUB: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x43,
];

// The StreamHub write selectors, declared exactly as `crates/rpc::streams` does so `abi_decode`
// produces byte-identical args. `sol!` derives the 4-byte selectors from the canonical signatures.
alloy_sol_types::sol! {
    function openStream(address to, uint256 ratePerSec, uint256 deposit) external returns (uint256 id);
    function stopStream(uint256 id) external;
}

/// Why a `WireBlock` failed verification. Every variant is **fail-closed**: the block is NOT applied to
/// the verified state and the tip does not advance (I4 on the client; spec §3.2 step 3 / AC-F-LN1/3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The block did not decode from its canonical wire bytes.
    BadWire(String),
    /// `shallow_verify` failed: `txs_root` inconsistent OR an unsigned/forged-proposer block
    /// (SEC-M5A-1) — an unsigned block is never trusted for its height.
    ShallowVerify,
    /// The block's height is not exactly `tip + 1` (out of order — the driver must fill the gap).
    NonContiguous { have: u64, got: u64 },
    /// `parent_hash` does not link to the verified tip (a different chain / fork).
    WrongParent,
    /// `timestamp` is not strictly greater than the parent's.
    BadTimestamp,
    /// `proposer` is not the expected (scheduled) proposer, when one was supplied.
    WrongProposer,
    /// A raw tx in the block did not decode (malformed/forged block).
    UndecodableTx(String),
    /// The block carries a tx kind the Phase-1 browser kernel does not yet re-execute (a HumanityHub /
    /// ContractHub AI-seam op). Fail-closed: surfaced as a verification stop, never a wrong balance.
    UnsupportedKind(&'static str),
    /// Re-execution produced a different `state_root` than the header claims — the I1/I2 cross-node
    /// check failed (AC-LC2 / AC-F-LN1). The lying server is **caught**; the verified state is unchanged.
    StateRootMismatch { expected: [u8; 32], got: [u8; 32] },
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::BadWire(e) => write!(f, "bad wire block: {e}"),
            VerifyError::ShallowVerify => write!(
                f,
                "shallow-verify failed (txs_root mismatch or unsigned/forged proposer)"
            ),
            VerifyError::NonContiguous { have, got } => {
                write!(f, "non-contiguous block: tip={have}, got={got}")
            }
            VerifyError::WrongParent => write!(f, "parent_hash does not link to verified tip"),
            VerifyError::BadTimestamp => write!(f, "timestamp not greater than parent"),
            VerifyError::WrongProposer => write!(f, "proposer is not the expected proposer"),
            VerifyError::UndecodableTx(e) => write!(f, "undecodable tx: {e}"),
            VerifyError::UnsupportedKind(k) => {
                write!(f, "unsupported tx kind for the Phase-1 browser kernel: {k}")
            }
            VerifyError::StateRootMismatch { expected, got } => write!(
                f,
                "state_root mismatch: header 0x{} re-executed 0x{}",
                hex32(expected),
                hex32(got)
            ),
        }
    }
}

impl std::error::Error for VerifyError {}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A decoded tx ready to re-execute. Mirrors the subset of `crates/rpc::PendingTx` the Phase-1 kernel
/// handles, decoded by the SAME `alloy` path so a block decodes byte-identically on both followers.
struct DecodedTx {
    from: [u8; 20],
    nonce: u64,
    kind: DecodedKind,
}

enum DecodedKind {
    Transfer {
        to: [u8; 20],
        value: u128,
    },
    OpenStream {
        to: [u8; 20],
        rate: u128,
        deposit: u128,
    },
    StopStream {
        id: u64,
    },
}

impl DecodedKind {
    /// Gas this kind charges — byte-identical to `crates/rpc::gas_for_kind` for the supported subset.
    fn gas(&self) -> u64 {
        match self {
            DecodedKind::Transfer { .. } => GAS_TRANSFER,
            DecodedKind::OpenStream { .. } | DecodedKind::StopStream { .. } => GAS_STREAM,
        }
    }
}

/// Decode + structurally-validate a raw EIP-155 tx into a [`DecodedTx`] for the supported subset.
///
/// This is the SAME structural decode `crates/rpc::decode_pending_tx` runs (alloy `decode_2718`,
/// EIP-155 chain-id bind, signer recovery, `to` requirement, StreamHub calldata shape), so a tx the
/// proposer included decodes byte-identically here. A HumanityHub/ContractHub op (or non-empty
/// calldata to a plain address) is reported as an unsupported/undecodable kind — fail-closed.
fn decode_tx(chain_id: u64, raw: &[u8]) -> Result<DecodedTx, VerifyError> {
    let mut slice = raw;
    let env = TxEnvelope::decode_2718(&mut slice)
        .map_err(|e| VerifyError::UndecodableTx(format!("rlp decode failed: {e}")))?;

    // EIP-155 chain-id binding (replay protection): require explicit binding to our chain.
    match env.chain_id() {
        Some(id) if id == chain_id => {}
        Some(other) => {
            return Err(VerifyError::UndecodableTx(format!(
                "wrong chainId: tx is for {other}, chain is {chain_id}"
            )))
        }
        None => {
            return Err(VerifyError::UndecodableTx(
                "tx must be EIP-155 (chainId-bound)".into(),
            ))
        }
    }

    let from = env
        .recover_signer()
        .map_err(|e| VerifyError::UndecodableTx(format!("signature recovery failed: {e}")))?
        .into_array();
    let to = env
        .to()
        .ok_or_else(|| VerifyError::UndecodableTx("contract creation not supported".into()))?;
    let nonce = env.nonce();
    let input = env.input().to_vec();
    let value_u256 = env.value();

    let to_bytes = to.into_array();
    let kind = if to_bytes == STREAM_HUB {
        match parse_stream_calldata(&input)? {
            StreamOp::Open { to, rate, deposit } => DecodedKind::OpenStream { to, rate, deposit },
            StreamOp::Stop { id } => DecodedKind::StopStream { id },
        }
    } else if to_bytes == HUMANITY_HUB {
        return Err(VerifyError::UnsupportedKind(
            "HumanityHub (AI proof-of-humanity)",
        ));
    } else if to_bytes == CONTRACT_HUB {
        return Err(VerifyError::UnsupportedKind(
            "ContractHub (AI prompt-contract)",
        ));
    } else {
        if !input.is_empty() {
            return Err(VerifyError::UndecodableTx(
                "calldata only supported for StreamHub (value transfers otherwise)".into(),
            ));
        }
        let value: u128 = value_u256
            .try_into()
            .map_err(|_| VerifyError::UndecodableTx("value exceeds u128 base-unit range".into()))?;
        DecodedKind::Transfer {
            to: to_bytes,
            value,
        }
    };

    Ok(DecodedTx { from, nonce, kind })
}

enum StreamOp {
    Open {
        to: [u8; 20],
        rate: u128,
        deposit: u128,
    },
    Stop {
        id: u64,
    },
}

/// Parse StreamHub calldata (selector + ABI args) into a [`StreamOp`] — byte-identical to
/// `crates/rpc::streams::parse_calldata` for the two write ops. Any other selector (a soulbound
/// transfer/approve, or an unknown one) is reported as undecodable so the block fails closed.
fn parse_stream_calldata(data: &[u8]) -> Result<StreamOp, VerifyError> {
    if data.len() < 4 {
        return Err(VerifyError::UndecodableTx(
            "StreamHub calldata too short".into(),
        ));
    }
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];
    match selector {
        s if s == openStreamCall::SELECTOR => {
            let call = openStreamCall::abi_decode(data, true)
                .map_err(|e| VerifyError::UndecodableTx(format!("bad openStream args: {e}")))?;
            let rate: u128 = call.ratePerSec.try_into().map_err(|_| {
                VerifyError::UndecodableTx("ratePerSec exceeds u128 base-unit range".into())
            })?;
            let deposit: u128 = call.deposit.try_into().map_err(|_| {
                VerifyError::UndecodableTx("deposit exceeds u128 base-unit range".into())
            })?;
            Ok(StreamOp::Open {
                to: call.to.into_array(),
                rate,
                deposit,
            })
        }
        s if s == stopStreamCall::SELECTOR => {
            let call = stopStreamCall::abi_decode(data, true)
                .map_err(|e| VerifyError::UndecodableTx(format!("bad stopStream args: {e}")))?;
            if call.id > U256::from(u64::MAX) {
                return Err(VerifyError::UndecodableTx("stream id exceeds u64".into()));
            }
            Ok(StreamOp::Stop {
                id: call.id.to::<u64>(),
            })
        }
        other => Err(VerifyError::UndecodableTx(format!(
            "unknown StreamHub selector 0x{}",
            other.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))),
    }
}

/// Consume + bump a sender's nonce for a stream op, mirroring `crates/rpc::consume_nonce`: settle the
/// sender first so `last_settled_at` advances consistently, require the tx nonce matches, then bump.
/// On a mismatch the state is left untouched (the op is never reached). Returns the post-bump value on
/// success so the caller can recover from an op error with the SAME idempotent nonce handling the
/// server follower uses.
fn consume_nonce(
    state: &mut dyn State,
    from: &[u8; 20],
    nonce: u64,
    now: u64,
) -> Result<(), String> {
    let mut acct = state.get(from).unwrap_or(Account {
        address: *from,
        ..Default::default()
    });
    acct.settle(now);
    if nonce != acct.nonce {
        return Err(format!(
            "invalid nonce: expected {}, got {nonce}",
            acct.nonce
        ));
    }
    acct.nonce += 1;
    state.put(acct);
    Ok(())
}

/// Recompute the canonical `txs_root` over the carried raw user txs — byte-identical to
/// `WireBlock::recompute_txs_root` and `crates/rpc::Block::compute_txs_root`. (We re-derive it here so
/// the kernel does not depend on a mutable wire helper; the value matches the wire one bit-for-bit.)
fn compute_txs_root(raw_txs: &[Vec<u8>]) -> B256 {
    let mut buf = Vec::with_capacity(8 + raw_txs.len() * 32);
    buf.extend_from_slice(&(raw_txs.len() as u64).to_be_bytes());
    for raw in raw_txs {
        buf.extend_from_slice(keccak256(raw).as_slice());
    }
    keccak256(&buf)
}

/// The verified post-state of a successfully-applied block — what `applyBlock` returns to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockOutcome {
    pub number: u64,
    pub hash: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp: u64,
}

/// The verified light-client state: the `MemState` plus the verified chain tip. This is the in-memory
/// equivalent of what `crates/rpc::Chain` holds, minus the server's mempool/tx-index/networking — a
/// light node only needs the verified state + tip to read balances and verify the next block.
pub struct LightCore {
    chain_id: u64,
    state: MemState,
    tip_number: u64,
    tip_hash: [u8; 32],
    tip_state_root: [u8; 32],
    tip_timestamp: u64,
}

impl LightCore {
    /// The chain id this core verifies against.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Construct an empty verified state anchored at the gateway's advertised genesis (spec §2.2
    /// `LightState.genesis`). `genesis_hash` is the block-0 hash the gateway advertised in its `Hello`;
    /// `genesis_time` is genesis unix time, `genesis_state_root` block-0's committed root. The state is
    /// empty (genesis seeds no accounts on this chain — the dev account is seeded post-genesis on the
    /// server, and a light node re-derives every later account by replaying blocks). Verified state is
    /// always grown by `apply_block` from here.
    pub fn genesis(
        chain_id: u64,
        genesis_hash: [u8; 32],
        genesis_state_root: [u8; 32],
        genesis_time: u64,
    ) -> Self {
        LightCore {
            chain_id,
            state: MemState::new(),
            tip_number: 0,
            tip_hash: genesis_hash,
            tip_state_root: genesis_state_root,
            tip_timestamp: genesis_time,
        }
    }

    /// The verified tip `(number, hash, state_root, timestamp)`.
    pub fn tip(&self) -> BlockOutcome {
        BlockOutcome {
            number: self.tip_number,
            hash: self.tip_hash,
            state_root: self.tip_state_root,
            timestamp: self.tip_timestamp,
        }
    }

    /// The 32-byte deterministic `state_root` over the current verified state — `ubi2_runtime::
    /// state_root`, the SAME commitment consensus uses. Pure read.
    pub fn state_root(&self) -> [u8; 32] {
        runtime_state_root(&self.state)
    }

    /// The streaming balance of `addr` at unix-second `now` (settled + emission + Σ incoming streams) —
    /// `State::balance`, an exact-integer function of `(state, now)` (I2). Returned as base units; the
    /// wasm layer crosses it to JS as a **decimal string**, never a float.
    pub fn balance_of(&self, addr: &[u8; 20], now: u64) -> u128 {
        self.state.balance(addr, now)
    }

    /// The current nonce of `addr` (0 if unknown) — for composing the next tx.
    pub fn nonce_of(&self, addr: &[u8; 20]) -> u64 {
        self.state.nonce(addr)
    }

    /// The PoH status tag of `addr` (`0`=Unverified .. `4`=Revoked), matching `state_root`'s
    /// `human_status_tag`. `None`/Unverified ⇒ 0.
    pub fn human_status(&self, addr: &[u8; 20]) -> u8 {
        match self.state.get_human(addr).map(|h| h.status) {
            None | Some(ubi2_runtime::HumanStatus::Unverified) => 0,
            Some(ubi2_runtime::HumanStatus::Pending) => 1,
            Some(ubi2_runtime::HumanStatus::Verified) => 2,
            Some(ubi2_runtime::HumanStatus::Challenged) => 3,
            Some(ubi2_runtime::HumanStatus::Revoked) => 4,
        }
    }

    /// Decode + re-execute + root-verify a `WireBlock` against the verified tip (spec §3.2 step 3). On
    /// success the verified state advances to this block and `BlockOutcome` is returned; on ANY failure
    /// the verified state is left **unchanged** (fail-closed — the tip never advances on a bad block,
    /// LC-2/LC-5/AC-LC2). `expected_proposer`, when supplied, pins the scheduled proposer.
    pub fn apply_block(
        &mut self,
        wire: &[u8],
        expected_proposer: Option<[u8; 20]>,
    ) -> Result<BlockOutcome, VerifyError> {
        let block = WireBlock::decode(wire).map_err(|e| VerifyError::BadWire(e.to_string()))?;
        self.apply_decoded(&block, expected_proposer)
    }

    /// As [`apply_block`], but over an already-decoded `WireBlock` (used by the parity test, which
    /// drives the kernel directly from in-memory blocks).
    pub fn apply_decoded(
        &mut self,
        block: &WireBlock,
        expected_proposer: Option<[u8; 20]>,
    ) -> Result<BlockOutcome, VerifyError> {
        // 1. shallow_verify: txs_root consistent + a NON-EMPTY proposer signature recovering to
        //    `proposer` (SEC-M5A-1 — an unsigned block is never trusted for its height, AC-F-LN3).
        if !block.shallow_verify() {
            return Err(VerifyError::ShallowVerify);
        }

        // 2. Cheap header checks against the verified tip (fail-fast, before re-execution).
        if block.number != self.tip_number + 1 {
            return Err(VerifyError::NonContiguous {
                have: self.tip_number,
                got: block.number,
            });
        }
        if block.parent_hash.0 != self.tip_hash {
            return Err(VerifyError::WrongParent);
        }
        if block.timestamp <= self.tip_timestamp {
            return Err(VerifyError::BadTimestamp);
        }
        if let Some(exp) = expected_proposer {
            if block.proposer.into_array() != exp {
                return Err(VerifyError::WrongProposer);
            }
        }

        // 3. Decode the ordered raw user txs (same structural decode the proposer/server follower ran).
        let mut decoded = Vec::with_capacity(block.txs.len());
        for raw in &block.txs {
            decoded.push(decode_tx(self.chain_id, raw)?);
        }

        // 4. Re-execute against a TRIAL copy of the verified state at block.timestamp. We commit it only
        //    if the recomputed roots match the header byte-for-byte — a bad block applies no change.
        let mut trial = self.state.clone();
        let timestamp = block.timestamp;
        for tx in &decoded {
            // Real UBI gas fee, charged to the sender BEFORE the op (crediting TREASURY) — exactly as
            // `crates/rpc::execute_block`. A sender who cannot afford even the fee has its tx dropped
            // (the server drops it too; a follower never reaches this for a well-formed block).
            let gas = tx.kind.gas();
            if charge_fee(&mut trial, &tx.from, gas, timestamp).is_err() {
                continue;
            }

            // Apply the op. On an op error we MINE A FAILED tx EVM-style — keep the fee, consume the
            // sender nonce exactly once (set to `nonce + 1`, the one idempotent post-state the server
            // also writes), apply no op state change — so the post-state matches the server byte-for-byte.
            let applied: Result<(), String> = match &tx.kind {
                DecodedKind::Transfer { to, value } => {
                    apply_transfer(&mut trial, &tx.from, to, *value, tx.nonce, timestamp)
                        .map_err(|e| e.to_string())
                }
                DecodedKind::OpenStream { to, rate, deposit } => {
                    consume_nonce(&mut trial, &tx.from, tx.nonce, timestamp).and_then(|()| {
                        open_stream(&mut trial, &tx.from, to, *rate, *deposit, timestamp)
                            .map(|_id| ())
                            .map_err(|e| e.to_string())
                    })
                }
                DecodedKind::StopStream { id } => {
                    consume_nonce(&mut trial, &tx.from, tx.nonce, timestamp).and_then(|()| {
                        stop_stream(&mut trial, *id, &tx.from, timestamp)
                            .map(|_refund| ())
                            .map_err(|e| e.to_string())
                    })
                }
            };

            if applied.is_err() {
                // Failed tx: keep the charged fee, set the nonce to its correct post-tx value. The FIFO
                // mempool + submit gate guarantee `tx.nonce` is the sender's current nonce, so this is
                // the one true deterministic post-state (matches `execute_block`'s failed-tx branch).
                let mut acct = trial.get(&tx.from).unwrap_or(Account {
                    address: tx.from,
                    ..Default::default()
                });
                acct.settle(timestamp);
                acct.nonce = tx.nonce + 1;
                trial.put(acct);
            }
        }

        // 5. Recompute the consensus roots over the FINAL trial state and assert byte-identical to the
        //    header (the I1/I2 cross-node check — AC-LC2 / AC-F-LN1). A mismatch ⇒ reject, state unchanged.
        let got_txs_root = compute_txs_root(&block.txs);
        if got_txs_root != block.txs_root {
            // (shallow_verify already checked this, but assert it on the re-derived value too.)
            return Err(VerifyError::StateRootMismatch {
                expected: block.state_root.0,
                got: runtime_state_root(&trial),
            });
        }
        let got_state_root = runtime_state_root(&trial);
        if got_state_root != block.state_root.0 {
            return Err(VerifyError::StateRootMismatch {
                expected: block.state_root.0,
                got: got_state_root,
            });
        }

        // 6. Commit: the trial state becomes the verified state; advance the tip.
        self.state = trial;
        self.tip_number = block.number;
        self.tip_hash = block.hash().0;
        self.tip_state_root = got_state_root;
        self.tip_timestamp = timestamp;

        Ok(self.tip())
    }

    /// Canonical snapshot of the verified state + tip, for IndexedDB persistence (spec §3.3). The bytes
    /// round-trip through [`LightCore::deserialize`] to a byte-identical state (same `state_root`).
    pub fn serialize(&self) -> Vec<u8> {
        crate::snapshot::encode(self)
    }

    /// Restore a verified state + tip from a [`LightCore::serialize`] snapshot. The caller (the TS light
    /// client) MUST re-verify the restored `state_root` against the stored tip header on load and
    /// discard + re-sync on mismatch (spec §3.3 — a poisoned IndexedDB entry is not trusted).
    pub fn deserialize(bytes: &[u8]) -> Result<Self, VerifyError> {
        crate::snapshot::decode(bytes).map_err(VerifyError::BadWire)
    }

    /// Construct a `LightCore` directly from parts (used by the snapshot decoder).
    pub(crate) fn from_parts(
        chain_id: u64,
        state: MemState,
        tip_number: u64,
        tip_hash: [u8; 32],
        tip_state_root: [u8; 32],
        tip_timestamp: u64,
    ) -> Self {
        LightCore {
            chain_id,
            state,
            tip_number,
            tip_hash,
            tip_state_root,
            tip_timestamp,
        }
    }

    // --- accessors for the snapshot encoder (read-only; no mutation) ---
    pub(crate) fn state_ref(&self) -> &MemState {
        &self.state
    }
    pub(crate) fn tip_parts(&self) -> (u64, [u8; 32], [u8; 32], u64) {
        (
            self.tip_number,
            self.tip_hash,
            self.tip_state_root,
            self.tip_timestamp,
        )
    }
}

/// The fee a kind of `gas` costs, re-exported for the wasm layer's tx-composition helpers.
pub fn fee_for_kind_gas(gas: u64) -> u128 {
    fee_for_gas(gas)
}

// Reference the hub addresses in a const-eval so an accidental edit that desyncs them from the runtime
// fails the build (they must equal the runtime's reserved addresses byte-for-byte).
const _: () = {
    assert!(STREAM_HUB[18] == 0x57 && STREAM_HUB[19] == 0x42);
    assert!(HUMANITY_HUB[18] == 0x50 && HUMANITY_HUB[19] == 0x48);
    assert!(CONTRACT_HUB[18] == 0x50 && CONTRACT_HUB[19] == 0x43);
};
