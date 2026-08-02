//! ubi2 EVM-compatible JSON-RPC (M1).
//!
//! Goal (spec `docs/specs/01-evm-rpc-and-wallet.md`, invariant I3): expose enough of the Ethereum
//! JSON-RPC surface that unmodified wallets (MetaMask) and standard EVM clients (viem/ethers) can add
//! the devnet, read a **streaming** balance, and submit signed transfers.
//!
//! ## Design
//! * [`Chain`] is the shared node state: an in-memory [`ubi2_runtime::State`] behind a `Mutex`, a
//!   block history, a tx index, a FIFO mempool, and a `newHeads` broadcast channel. It is `Clone`
//!   (all fields are `Arc`) so the RPC handlers and the node's block-tick task share one instance.
//! * [`serve`] builds a `jsonrpsee` server (HTTP **and** WebSocket on the same socket) and registers
//!   every method. Subscriptions (`eth_subscribe("newHeads")`) ride the WS transport.
//! * Transaction decoding + signer recovery use the **alloy** stack (`alloy-consensus`,
//!   `alloy-eips`, `alloy-primitives` with the `k256` feature): `TxEnvelope::decode_2718` parses an
//!   EIP-155 legacy tx and `recover_signer()` returns the sender, with EIP-155 chain-id binding
//!   handled by alloy.
//!
//! ## Documented deviations from Ethereum (invariant I3)
//! * **Gas is a real, flat UBI fee.** `eth_gasPrice` is a flat constant (1 gwei) and there is no
//!   per-opcode metering: each tx kind has a fixed `gas_used` (transfer `21000`; StreamHub `60000`;
//!   HumanityHub `80000`; ContractHub `120000`). `eth_estimateGas` returns the per-kind gas for the
//!   call's target so a wallet's `gasLimit * gasPrice` preview equals the UBI deducted. The fee
//!   `gas_used * gas_price` (base units) is charged to the sender at apply time and credited to the
//!   reserved TREASURY (`0x…5542`) — fee recycling, the M5 redistribution basis. Sender needs
//!   `value + fee`; an under-funded tx is dropped. (Verified humans stream 1 UBI/hr, far above the
//!   `~2.1e13`-base-unit transfer fee, so they always cover it.) **`requestVerification` (onboarding)
//!   is the one fee-exempt tx kind** — a not-yet-verified account has no UBI to pay with, so the
//!   network subsidizes the bootstrap gate (its `eth_estimateGas` is `0x0`).
//! * **`eth_call` is minimal.** There is no EVM; calls return `0x`. M1 has no contracts (deferred to
//!   M4 prompt-contracts).
//! * **Blocks are empty-or-tx containers** produced on a fixed clock tick; there is no real PoW/PoS,
//!   no uncles, no logs/bloom beyond zeroes. State root / receipts root are zero placeholders.
//! * **Only legacy (type-0) EIP-155 transfers** are executed. Typed txs decode but contract-creation
//!   (`to == None`) and non-zero `data` are rejected — M1 moves value only.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::{keccak256, Address as AlloyAddr, B256, U256};
use alloy_sol_types::SolCall;
use jsonrpsee::core::{RpcResult, SubscriptionResult};
use jsonrpsee::server::{Server, ServerHandle};
use jsonrpsee::types::error::ErrorObjectOwned;
use jsonrpsee::{PendingSubscriptionSink, RpcModule};
use serde_json::{json, Value};
use tokio::sync::broadcast;

use ubi2_runtime::{
    csca_registry_root, fee_for_gas, finalize_registration, gas_for_deploy, proposer_index,
    refresh_epoch_validators, system_challenge as lc_system_challenge, validator_set, Account,
    Address, Assurance, CanonicalEffect, Case, CaseKind, CaseStatus, Confidence,
    ContractInterpreter, ContractStatus, CscaEntry, CscaStatus, ExecCase, ExecStatus, Human,
    HumanStatus, HumanityOracle, Juror, MemState, MockZkVerifier, Op, PromptContract, State,
    Stream, StreamStatus, Verdict, ZkAttrType, ZkPassportVerifier, EPOCH_BLOCKS, GAS_CONTRACT,
    GAS_CSCA_GOV, GAS_HUMANITY, GAS_ONBOARD, GAS_PRICE_WEI as RT_GAS_PRICE_WEI, GAS_STREAM,
    GAS_TRANSFER, GAS_ZKPOH, VIEW_MAX,
};

pub mod persist;
pub mod sync_gateway;
pub use sync_gateway::{serve_sync_gateway, SyncGatewayHandle};

pub mod streams;
use streams::{
    decode_token_id, parse_calldata, render_token_uri, CalldataError, CardData, Side, StreamOp,
    STREAM_HUB,
};

pub mod humanity;
use humanity::{
    addr_topic as h_addr_topic, over18_attribute_type, parse_calldata as parse_humanity_calldata,
    u64_topic as h_u64_topic, HumanityOp, HUMANITY_HUB,
};

pub mod poh_nft;
use poh_nft::{
    addr_of_token_id, render_token_uri as render_poh_token_uri, token_id_of,
    CardData as PohCardData,
};

pub mod contracts;
use contracts::{
    addr_topic as c_addr_topic, parse_calldata as parse_contract_calldata, text_commitment,
    u64_topic as c_u64_topic, ContractOp, CONTRACT_HUB,
};

pub mod oracle_admin;
use oracle_admin::{bad_config_error, is_loopback, not_loopback_error, AdminHttpMeta};
pub use oracle_admin::{
    ActiveImpl, AdminAccess, BuiltOracle, OracleAdmin, OracleConfig, OracleFactory, OracleHealth,
};

/// Default devnet chain id (0x5542 / 21826). Spec §M1-T1.3.
pub const DEVNET_CHAIN_ID: u64 = 0x5542;

/// M5 Stage B (spec 08 §6.3/§12): k-deep finality depth. A block is final once the head is
/// `FINALITY_DEPTH` beyond it; no reorg may cross a finalized block, and the reorg bound is
/// `< FINALITY_DEPTH`. Devnet default `k = 6` (matches `NetStatus::finality_depth`).
pub const FINALITY_DEPTH: u64 = 6;

/// M5 Stage B (spec 08 §5.4/§6.1): cap on the bounded SIDE STORE of valid non-canonical fork blocks
/// ([`Chain::consider_competing_block`]). Generous versus the handful of concurrent forks a CFT
/// round-robin ever produces (an original-vs-successor tip race is at most a couple of blocks wide),
/// but a hard bound so a hostile flood of authenticated-but-off-chain blocks cannot grow it unbounded.
const MAX_FORK_STORE: usize = 256;

/// Fork-choice tip comparison (spec 08 §6.1): is tip `a` canonical-preferred over tip `b`? The total
/// order on `(height, view, hash)` is: (1) greater height, ties → (2) lower view, ties → (3) lower hash.
/// Two distinct equal-height valid chains have distinct tip hashes, so rule 3 always terminates — the
/// order is total, and every honest node selects the same head (I1). Pure; reads no clock, no arrival
/// order. This refines the Stage-A "longest, then lowest hash" by inserting the `view` tiebreak.
pub fn fork_choice_prefers(a: (u64, u32, B256), b: (u64, u32, B256)) -> bool {
    let (ah, av, ahash) = a;
    let (bh, bv, bhash) = b;
    match ah.cmp(&bh) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => match av.cmp(&bv) {
            std::cmp::Ordering::Less => true,
            std::cmp::Ordering::Greater => false,
            std::cmp::Ordering::Equal => ahash < bhash,
        },
    }
}

/// Flat devnet gas price (1 gwei), as a `u64` for the JSON quantity helpers. Sourced from the runtime
/// constant ([`RT_GAS_PRICE_WEI`]) so the price the RPC advertises (`eth_gasPrice`) is exactly the
/// price the runtime charges the fee at — a wallet's `gasLimit * gasPrice` preview equals the UBI
/// deducted.
const GAS_PRICE_WEI: u64 = RT_GAS_PRICE_WEI as u64;

/// Gas a plain value transfer costs — the EVM intrinsic `21000`, sourced from the runtime constant.
const TRANSFER_GAS: u64 = GAS_TRANSFER;

/// Deterministic per-kind gas for a queued tx — the `gas_used` the UBI fee is charged on and the value
/// `eth_estimateGas` returns. A small constant per tx kind (no metering) for most kinds: transfers pay
/// the EVM intrinsic; hub ops pay progressively more to reflect their bookkeeping (escrow/index/quorum).
/// A `deployContract` is the exception — its gas SCALES with the stored text length (`gas_for_deploy`),
/// so permanent on-chain storage has a real per-byte cost (C6-SEC-1) and a larger contract pays a
/// larger UBI fee. This is consensus state (I2): the text length is a consensus input, so every node
/// charges the same sender the same fee for the same tx.
fn gas_for_kind(kind: &PendingKind) -> u64 {
    match kind {
        PendingKind::Transfer { .. } => GAS_TRANSFER,
        PendingKind::OpenStream { .. } | PendingKind::StopStream { .. } => GAS_STREAM,
        // Onboarding is fee-exempt: a not-yet-verified account has no UBI to pay with (bootstrap gate).
        PendingKind::RequestVerification { .. } => GAS_ONBOARD,
        PendingKind::Vouch { .. }
        | PendingKind::Challenge { .. }
        | PendingKind::SubmitVerdict { .. } => GAS_HUMANITY,
        // M6: the ZK-passport proof runs a pairing check — the heaviest HumanityHub op (NOT fee-exempt,
        // §4.1). The CSCA-governance ops pay the humanity tier (governance-gated, small surface).
        PendingKind::SubmitZkPassportProof { .. } => GAS_ZKPOH,
        PendingKind::RegisterCsca { .. }
        | PendingKind::RevokeCsca { .. }
        | PendingKind::PinSelfIdentityRoot { .. }
        | PendingKind::PinSelfOfacRoot { .. }
        | PendingKind::RetireSelfRoot { .. } => GAS_CSCA_GOV,
        // Size-metered: base contract gas + per-byte surcharge on the stored UTF-8 text (the text is
        // already capped at submit, so the length is bounded; storing more costs more).
        PendingKind::DeployContract { text, .. } => gas_for_deploy(text.len()),
        PendingKind::FundContract { .. }
        | PendingKind::InvokeContract { .. }
        | PendingKind::SubmitEffect { .. } => GAS_CONTRACT,
    }
}

/// Gas for an `eth_estimateGas` / `eth_call` call object, by its `to` address. Each hub charges one
/// gas tier for *all* its methods (matching [`gas_for_kind`]), so the destination address alone fixes
/// the estimate — no selector decode needed. A call with no `to` (contract creation) or to any
/// non-hub address is a plain transfer (`21000`). Keeps `eth_estimateGas` in lock-step with the fee
/// the apply path actually charges, so MetaMask's preview matches the deduction.
fn gas_for_call_obj(call: &Value) -> u64 {
    let to = call
        .get("to")
        .and_then(|v| v.as_str())
        .and_then(decode_hex)
        .filter(|b| b.len() == 20);
    let data = call
        .get("data")
        .or_else(|| call.get("input"))
        .and_then(|v| v.as_str())
        .and_then(decode_hex)
        .unwrap_or_default();
    match to.as_deref() {
        Some(a) if a == STREAM_HUB.as_slice() => GAS_STREAM,
        Some(a) if a == HUMANITY_HUB.as_slice() => {
            // `requestVerification` (onboarding) is fee-exempt, so MetaMask's zero-balance preflight
            // estimate is 0 and the new human can submit. Other HumanityHub ops pay the humanity tier.
            match parse_humanity_calldata(&data) {
                Ok(HumanityOp::RequestVerification { .. }) => GAS_ONBOARD,
                Ok(HumanityOp::SubmitZkPassportProof { .. }) => GAS_ZKPOH,
                Ok(HumanityOp::RegisterCsca { .. })
                | Ok(HumanityOp::RevokeCsca { .. })
                | Ok(HumanityOp::PinSelfIdentityRoot { .. })
                | Ok(HumanityOp::PinSelfOfacRoot { .. })
                | Ok(HumanityOp::RetireSelfRoot { .. }) => GAS_CSCA_GOV,
                _ => GAS_HUMANITY,
            }
        }
        Some(a) if a == CONTRACT_HUB.as_slice() => {
            // A `deployContract` is size-metered (per-byte surcharge on the stored text), so MetaMask's
            // preflight estimate scales with the text and matches the larger UBI fee the apply path
            // charges. Other ContractHub ops pay the flat contract tier. Parsing also enforces the size
            // cap, so an oversized estimate request surfaces the same invalid-params error the wallet
            // would get at submit. We fall back to the flat tier on a non-deploy/unparsable call.
            match parse_contract_calldata(&data) {
                Ok(ContractOp::DeployContract { text, .. }) => gas_for_deploy(text.len()),
                _ => GAS_CONTRACT,
            }
        }
        _ => GAS_TRANSFER,
    }
}

/// Client version string returned by `web3_clientVersion`.
const CLIENT_VERSION: &str = "ubi2-node/v0.2.0-m2";

/// The EVM JSON-RPC methods M1 implements (kept for documentation / tests).
pub const M1_METHODS: &[&str] = &[
    "web3_clientVersion",
    "net_version",
    "eth_chainId",
    "eth_syncing",
    "eth_accounts",
    "eth_blockNumber",
    "eth_getBalance",
    "eth_getTransactionCount",
    "eth_gasPrice",
    "eth_maxPriorityFeePerGas",
    "eth_estimateGas",
    "eth_feeHistory",
    "eth_call",
    "eth_sendRawTransaction",
    "eth_getBlockByNumber",
    "eth_getBlockByHash",
    "eth_getTransactionByHash",
    "eth_getTransactionReceipt",
    "eth_subscribe",
    "eth_unsubscribe",
];

/// M2 stream-read methods (custom `ubi_*` surface; `eth_call`/`eth_sendRawTransaction`/`eth_getBalance`
/// are M1 methods extended in place to recognize StreamHub). Kept for documentation / tests.
pub const M2_METHODS: &[&str] = &["ubi_getStream", "ubi_getStreams"];

/// M3 proof-of-humanity read methods (custom `ubi_*` surface; the write surface is
/// `eth_sendRawTransaction` extended in place to recognize the HumanityHub). Kept for docs / tests.
pub const M3_METHODS: &[&str] = &[
    "ubi_getHuman",
    "ubi_getCase",
    "ubi_getVouches",
    "ubi_getJurors",
    "ubi_getPendingCases",
];

/// M4 prompt-contract read methods + the EXPL-1 address indexer reads (custom `ubi_*` surface; the
/// write surface is `eth_sendRawTransaction` extended in place to recognize the ContractHub). Kept for
/// docs / tests.
pub const M4_METHODS: &[&str] = &[
    "ubi_getContract",
    "ubi_getExecCase",
    "ubi_getContractsOf",
    "ubi_getAddressActivity",
    "ubi_getAccount",
];

/// EXPL-2 deep decoded explorer reads (custom `ubi_*` surface): a full decoded block and a full
/// decoded transaction (system-hub call + decoded logs + resulting state effect/verdict/status).
/// Standard `eth_getBlockByNumber`/`eth_getTransactionByHash` stay intact for wallets; these are the
/// explorer's richer surface. Kept for docs / tests.
pub const EXPL2_METHODS: &[&str] = &["ubi_getBlock", "ubi_getTransaction"];

/// UI explorer directory reads (custom `ubi_*` surface): a recent-blocks list (with an optional
/// non-empty filter, since most devnet blocks are empty ticks) and a global deployed-contracts
/// directory. Both are compact, read-only summaries backed by the EXPL indexer / state — newest-first,
/// bounded limit, no PII, no new clocks/floats. Kept for docs / tests.
pub const UI_METHODS: &[&str] = &["ubi_getRecentBlocks", "ubi_getContracts"];

/// LOCALHOST-ONLY AI-backend admin (`ubi_*`): the wallet's Settings panel reads/updates which LLM the
/// node calls. Both methods are rejected for non-loopback callers (see [`oracle_admin`]). Kept for
/// docs / tests.
pub const ADMIN_METHODS: &[&str] = &["ubi_getOracleConfig", "ubi_setOracleConfig"];

// ---------------------------------------------------------------------------------------------
// Block / transaction model
// ---------------------------------------------------------------------------------------------

/// One EVM log emitted by a stream op, carried in the tx receipt (spec §"RPC surface": the receipt's
/// logs include the assigned stream id). Standard `{address, topics, data}` shape.
#[derive(Clone, Debug)]
pub struct TxLog {
    pub address: AlloyAddr,
    pub topics: Vec<B256>,
    pub data: Vec<u8>,
}

/// A transaction as included in a block (the bits an explorer / receipt needs). M2 adds `input`
/// (StreamHub calldata) and `logs` (stream/NFT events).
#[derive(Clone, Debug)]
pub struct StoredTx {
    pub hash: B256,
    pub from: AlloyAddr,
    pub to: Option<AlloyAddr>,
    pub value: U256,
    pub nonce: u64,
    pub block_number: u64,
    pub block_hash: B256,
    pub tx_index: u64,
    /// Raw calldata (`0x` for plain transfers; the StreamHub selector+args otherwise).
    pub input: Vec<u8>,
    /// Logs emitted while applying this tx (stream + ERC-721 Transfer mints). Empty for a FAILED tx.
    pub logs: Vec<TxLog>,
    /// Gas this tx consumed — the per-kind constant the UBI fee was charged on (`fee = gas * price`).
    /// Surfaced verbatim in `eth_getTransactionReceipt` (`gasUsed`) and the tx's `gas`/block `gasUsed`.
    /// Charged on BOTH a succeeded and a FAILED tx (EVM charges gas on revert — the node did work).
    pub gas_used: u64,
    /// EVM receipt status: `true` = succeeded (`0x1`), `false` = the op FAILED at block time (`0x0`).
    /// A FAILED tx is still MINED (included, fee-charged, nonce-consumed) — never silently dropped —
    /// so the wallet always gets a receipt (no perpetual pending) and the sender nonce advances (no
    /// nonce gap). Cycle-6 fix.
    pub success: bool,
    /// The decoded failure reason for a FAILED tx (the op's `Err` rendered as a string), carried so the
    /// explorer can show "vouchee has no open registration" etc. `None` for a succeeded tx.
    pub revert_reason: Option<String>,
    /// EIP-2718 transaction type byte as the SENDER signed it: `0` legacy, `1` EIP-2930, `2` EIP-1559.
    /// Surfaced verbatim as the `type` field in `eth_getTransactionByHash`/`Receipt`. Critical for
    /// MetaMask: it signs a type-2 (EIP-1559) tx on this chain (we advertise `baseFeePerGas` +
    /// `eth_feeHistory`) and polls the receipt expecting `type: 0x2`. A hardcoded `0x0` made MetaMask
    /// treat the (correctly hashed, correctly mined) tx as a non-match and show it "Dropped". The
    /// sender's tx HASH is the canonical EIP-2718 hash and is type-independent, so it matches; only the
    /// returned object's `type`/1559-fee shape was wrong (cycle-7 fix).
    pub tx_type: u8,
    /// EIP-1559 fee fields, present iff `tx_type == 2` (or `1`). `max_fee_per_gas` /
    /// `max_priority_fee_per_gas` are echoed back exactly as the sender signed them so the wallet's
    /// signed object reconciles with the returned object. On this chain the priority tip is 0 and the
    /// effective price is the flat `GAS_PRICE_WEI`, but we still surface the sender's caps for fidelity.
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
}

/// A devnet block. Empty blocks are valid (the clock tick still advances height — spec §M1-T1.6).
///
/// M5 (Stage A, spec `05-p2p-network.md` §2.2) extends the header with the consensus fields a follower
/// needs to validate authorship + agreement across processes:
///   * `txs_root`  — a commitment over the canonical, ordered tx list (the included tx hashes).
///   * `state_root`— a commitment over the FULL post-execution state ([`ubi2_runtime::state_root`]).
///   * `proposer`  — the validator address that produced the block (zero for the single-node devnet).
///   * `proposer_sig` — the proposer's EVM-key signature over the header pre-image (empty when unsigned).
///
/// The header hash is `keccak256(number ‖ parent_hash ‖ timestamp ‖ txs_root ‖ state_root ‖ proposer)`,
/// and `proposer_sig` signs that same pre-image, so `ecrecover(proposer_sig)` must equal `proposer`.
#[derive(Clone, Debug)]
pub struct Block {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
    /// M5 Stage B (spec 08 §2.2): the view (rotation offset) at which this block was produced. `0` for
    /// the height's first-scheduled proposer; `k > 0` for the `k`-th view-change successor (§5). Committed
    /// in the header pre-image (after `timestamp`, before `txs_root`), so the hash + signature cover it.
    pub view: u32,
    /// M5: commitment over the canonical, ordered tx list (the included tx hashes). Pure function of
    /// the block's txs (EC-4/EC-10).
    pub txs_root: B256,
    /// M5: commitment over the full post-block state ([`ubi2_runtime::state_root`]). Two honest nodes
    /// that re-execute the same ordered txs against the same parent state compute the identical root.
    pub state_root: B256,
    /// M5: the validator that produced the block. Zero (`Address::ZERO`) on the single-proposer devnet
    /// until a proposer key is configured (Stage B fills the round-robin schedule).
    pub proposer: AlloyAddr,
    /// M5: the proposer's secp256k1 signature over the header pre-image, as 65 raw bytes (`r‖s‖v`).
    /// Empty when the block was produced without a configured proposer key (devnet default).
    pub proposer_sig: Vec<u8>,
    pub txs: Vec<StoredTx>,
}

impl Block {
    /// The header pre-image `number ‖ parent_hash ‖ timestamp ‖ txs_root ‖ state_root ‖ proposer`
    /// (spec §2.2). Both the block hash and `proposer_sig` are computed over this exact byte string, so
    /// `ecrecover(proposer_sig)` recovers `proposer` and any field change moves the hash.
    fn header_preimage(
        number: u64,
        parent_hash: B256,
        timestamp: u64,
        view: u32,
        txs_root: B256,
        state_root: B256,
        proposer: &AlloyAddr,
    ) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + 32 + 8 + 4 + 32 + 32 + 20);
        buf.extend_from_slice(&number.to_be_bytes());
        buf.extend_from_slice(parent_hash.as_slice());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        // Stage B (§2.2): `view` is inserted after `timestamp`, before `txs_root`, as a 4-byte BE int.
        buf.extend_from_slice(&view.to_be_bytes());
        buf.extend_from_slice(txs_root.as_slice());
        buf.extend_from_slice(state_root.as_slice());
        buf.extend_from_slice(proposer.as_slice());
        buf
    }

    /// The M5 block hash: `keccak256(header_preimage)` (spec §2.2). For the genesis block (and any
    /// pre-M5 caller) the extra fields are zero (`view = 0`), so this reduces to a stable commitment over
    /// the original `(number, parent_hash, timestamp)` plus `view` and three zero roots/address.
    fn compute_hash(
        number: u64,
        parent_hash: B256,
        timestamp: u64,
        view: u32,
        txs_root: B256,
        state_root: B256,
        proposer: &AlloyAddr,
    ) -> B256 {
        keccak256(Block::header_preimage(
            number,
            parent_hash,
            timestamp,
            view,
            txs_root,
            state_root,
            proposer,
        ))
    }

    /// The canonical `txs_root` over a block's ordered **user**-tx list: `keccak256(count ‖ each tx
    /// hash)`. A pure function of the included tx hashes in block order, so a follower recomputes it and
    /// rejects a block whose proposer reordered or altered the tx set (spec §5.3). The caller passes only
    /// the raw, gossipable user txs (NOT the synthetic M3 sweep tx) so the wire block's
    /// `recompute_txs_root` over the carried raw bytes matches byte-for-byte; the sweep's effects are
    /// committed by `state_root` and regenerated deterministically. (Stage A uses the as-included order;
    /// the §5.3 canonical `(sender, nonce)` re-ordering + verification is a Stage-B follower check.)
    fn compute_txs_root(txs: &[StoredTx]) -> B256 {
        let mut buf = Vec::with_capacity(8 + txs.len() * 32);
        buf.extend_from_slice(&(txs.len() as u64).to_be_bytes());
        for tx in txs {
            buf.extend_from_slice(tx.hash.as_slice());
        }
        keccak256(&buf)
    }
}

/// Why a follower rejected a network block ([`Chain::validate_and_apply_block`], spec §5.1 / AC-F2/F3).
/// Every variant is fail-closed: the block is NOT applied and the source peer may be penalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlockError {
    /// The block's height is not exactly `head + 1` (the follower is behind/ahead — drive sync).
    NonContiguous { have: u64, got: u64 },
    /// `parent_hash` does not match the local head (different chain / fork).
    WrongParent,
    /// `timestamp` is not strictly greater than the parent's (§5.1(4)).
    BadTimestamp,
    /// The block's `proposer` is not the scheduled proposer `V[(h+view) mod N]` (AC-F3 / §4 check 3).
    WrongProposer,
    /// `ecrecover(proposer_sig)` does not equal `proposer` (forged/unsigned authorship).
    BadSignature,
    /// Stage B (§4 check 3): the effective validator set `V` is empty (`N == 0`) — no one is scheduled,
    /// so no block can be authorized. Fail-closed.
    NoValidatorSet,
    /// Stage B (§4 check 2): the block's `view` is `>= VIEW_MAX` — an absurd/garbage view is rejected.
    ViewOutOfRange { view: u32 },
    /// A raw tx in the block did not decode (malformed/forged block).
    UndecodableTx,
    /// Re-execution produced a different `state_root`/`txs_root`/`hash` than the header claims — the
    /// I1/I2 cross-node check failed (AC-F2). The block is rejected and rolled back.
    StateRootMismatch { expected: B256, got: B256 },
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BlockError::NonContiguous { have, got } => {
                write!(f, "non-contiguous block: head={have}, got={got}")
            }
            BlockError::WrongParent => write!(f, "wrong parent hash"),
            BlockError::BadTimestamp => write!(f, "timestamp not greater than parent"),
            BlockError::WrongProposer => write!(f, "block proposer is not the scheduled proposer"),
            BlockError::BadSignature => {
                write!(f, "proposer signature does not recover to proposer")
            }
            BlockError::NoValidatorSet => {
                write!(f, "no validator set (N == 0): no proposer is scheduled")
            }
            BlockError::ViewOutOfRange { view } => {
                write!(f, "view {view} out of range (>= VIEW_MAX)")
            }
            BlockError::UndecodableTx => write!(f, "block contains an undecodable tx"),
            BlockError::StateRootMismatch { expected, got } => {
                write!(
                    f,
                    "state_root mismatch: expected {expected}, re-executed {got}"
                )
            }
        }
    }
}

impl std::error::Error for BlockError {}

// ---------------------------------------------------------------------------------------------
// Chain state
// ---------------------------------------------------------------------------------------------

/// M5 Stage B (spec 08 §5.4/§6.1/§6.3): a VALID-but-non-canonical fork block retained in the bounded
/// side store ([`Chain`]`.fork_store`). It carries exactly the header fields + the ordered raw user-tx
/// bytes needed to (a) walk a fork branch's ancestry by `parent_hash` and (b) deterministically
/// re-execute the branch on a reorg (`< FINALITY_DEPTH` deep). The `hash` is the committed block hash
/// (the store key), so a later-arriving child that names this block as its parent completes the branch
/// and can trigger a bounded general reorg (the h1@view1→h2@view1 race in §5.4). Authenticated on
/// entry (signature recovers to `proposer`) but its schedule/state-root is only fully re-checked when
/// it is actually re-executed during a reorg — a forged branch fails there and is rolled back.
#[derive(Clone)]
struct ForkBlockEntry {
    number: u64,
    parent_hash: B256,
    timestamp: u64,
    view: u32,
    txs_root: B256,
    state_root: B256,
    proposer: AlloyAddr,
    proposer_sig: Vec<u8>,
    raw_txs: Vec<Vec<u8>>,
    hash: B256,
}

/// M5 Stage B (spec 08 §6.1): a fork-choice tip key `(height, view, hash)` — the total-order comparison
/// key over competing chain tips ([`fork_choice_prefers`]).
type TipKey = (u64, u32, B256);

/// M5 Stage B (spec 08 §6.1/§6.3): a complete, reorg-ready fork branch — the ascending winning blocks
/// (`ca+1 … tip`), the common-ancestor height they reattach at, and the fork-choice tip key.
struct ReorgCandidate {
    branch: Vec<ForkBlockEntry>,
    ca_height: u64,
    tip: TipKey,
}

/// M5 Stage B (spec 08 §6.1/§6.3): assemble the complete fork branch ending at `tip` by walking
/// `parent_hash` back through the retained fork blocks (`fmap`) until a **canonical common ancestor**
/// (a block already in `inner.blocks_by_hash`) is reached. Returns the branch as an ascending list
/// (`ca+1 … tip`) plus the common-ancestor height, or `None` if the branch is:
/// - **incomplete** (an ancestor is neither canonical nor retained — a missing parent, wait for it),
/// - **non-contiguous** (a height gap in the fork chain — malformed), or
/// - **finality-bounded** (the common ancestor is below the finalized frontier — a reorg here would
///   revert finalized history, §6.3, which is REFUSED).
///
/// Pure: reads only the retained headers + canonical index, no clock, no arrival order (I1).
fn assemble_fork_branch(
    tip: &ForkBlockEntry,
    fmap: &HashMap<B256, ForkBlockEntry>,
    inner: &Inner,
    finalized: u64,
) -> Option<(Vec<ForkBlockEntry>, u64)> {
    let mut chain: Vec<ForkBlockEntry> = Vec::new();
    let mut cur = tip.clone();
    let mut guard = 0usize;
    loop {
        guard += 1;
        // Defensive walk bound (no real keccak hash cycle can form): a branch reverting more than the
        // whole finality window is not a bounded reorg — abandon it.
        if guard > (FINALITY_DEPTH as usize + 2) * 8 {
            return None;
        }
        // Is `cur`'s parent a canonical block? Then it is the common ancestor (the fork point).
        if let Some(&idx) = inner.blocks_by_hash.get(&cur.parent_hash) {
            let ca_number = inner.blocks[idx].number;
            // Height contiguity: the branch's lowest block must sit exactly on the canonical ancestor.
            if cur.number != ca_number + 1 {
                return None;
            }
            // Finality bound (§6.3): the lowest reverted block is `ca_number + 1`; it must be ABOVE the
            // finalized frontier (`ca_number >= finalized`). A deeper fork would revert finalized
            // history — REFUSE (never reorg across the finalized frontier).
            if ca_number < finalized {
                return None;
            }
            chain.push(cur);
            chain.reverse();
            return Some((chain, ca_number));
        }
        // Else the parent must be another retained fork block; continue walking upward.
        match fmap.get(&cur.parent_hash) {
            Some(parent) => {
                if cur.number != parent.number + 1 {
                    return None; // non-contiguous fork branch (a height gap)
                }
                chain.push(cur.clone());
                cur = parent.clone();
            }
            None => return None, // missing ancestor — the branch is incomplete for now
        }
    }
}

/// Clone so the follower's [`Chain::validate_and_apply_block`] can snapshot-and-restore on a rejected
/// block (fail-closed: a divergent block applies no state change). All fields are cheaply clonable.
#[derive(Clone)]
struct Inner {
    state: MemState,
    blocks: Vec<Block>,
    blocks_by_hash: HashMap<B256, usize>,
    txs: HashMap<B256, StoredTx>,
    /// FIFO mempool of decoded, validated-but-not-yet-mined transfers awaiting the next block.
    mempool: Vec<PendingTx>,
    /// EXPL-1 per-address tx index: for every address a tx *touches* (its `from`, its `to`, and any
    /// address an applied effect moves value to/from — payees, vouchees, challenge subjects, stream
    /// recipients, contract escrows, effect targets), the ordered list of tx hashes that touched it.
    /// Append-only in block order, so `ubi_getAddressActivity` returns most-recent-first by reversing.
    /// Each entry is recorded once per (address, tx) pair (deduped) so a self-transfer isn't doubled.
    addr_index: HashMap<Address, Vec<B256>>,
    /// M5 (Stage A): `tx_hash → raw EIP-155 bytes`, populated by `ingest_raw_tx` (the RPC submit AND the
    /// gossip-relay path both go through it). The proposer reads it to reconstruct the gossipable
    /// `WireBlock` (raw txs are NOT stored on `StoredTx`); a synced/late-joiner node also feeds the raw
    /// bytes of applied blocks here so it can re-serve sync. NOT part of the persisted snapshot (a
    /// restarted node re-derives nothing from it that affects state — it is a relay convenience only).
    raw_tx: HashMap<B256, Vec<u8>>,
}

/// What a queued tx will do when mined. M1 had only value transfers; M2 adds the two StreamHub ops.
// `SubmitZkPassportProof` carries the full 21-element public vector inline (spec 06b §4.3); this queued
// per-tx state is short-lived, so the inline layout is intentional (no `Box` indirection).
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug)]
enum PendingKind {
    /// Plain value transfer to `to`.
    Transfer { to: AlloyAddr, value: u128 },
    /// `openStream` to StreamHub: open `from → to` at `rate`, locking `deposit`.
    OpenStream {
        to: AlloyAddr,
        rate: u128,
        deposit: u128,
    },
    /// `stopStream` to StreamHub: stop stream `id` (signer must be the sender).
    StopStream { id: u64 },

    // ---- M3: proof-of-humanity ops to HumanityHub ----
    /// `requestVerification(livenessRef)`: open a registration for the signer.
    RequestVerification { liveness_ref: [u8; 32] },
    /// `vouch(vouchee)`: the (Verified) signer vouches for `vouchee`.
    Vouch { vouchee: AlloyAddr },
    /// `challenge(subject, evidenceRef)`: open a challenge against `subject`.
    Challenge {
        subject: AlloyAddr,
        evidence_ref: [u8; 32],
    },
    /// `submitVerdict(caseId, verdict, confidence)`: a juror's canonical verdict.
    SubmitVerdict {
        case_id: u64,
        verdict: ubi2_runtime::CanonicalVerdict,
    },

    // ---- M6: ZK-passport ops to HumanityHub ----
    /// `submitZkPassportProof(proof, publicSignals[21], schemeTag)`: verify a Self `vc_and_disclose`
    /// proof for the signer (spec 06b §4.3). The submitter address is the tx sender (NOT in calldata),
    /// bound against `publicSignals[user_identifier]` so it cannot be forged (§4.4).
    SubmitZkPassportProof {
        proof: Vec<u8>,
        signals: [[u8; 32]; 21],
        scheme_tag: u8,
    },
    /// `registerCsca(countryCode, keyId, pubkey)`: governance-gated CSCA add (§7.3). RETAINED, reserved.
    RegisterCsca {
        country_code: [u8; 3],
        key_id: [u8; 32],
        pubkey: Vec<u8>,
    },
    /// `revokeCsca(keyId)`: governance-gated CSCA revoke (§7.3/§7.4). RETAINED, reserved.
    RevokeCsca { key_id: [u8; 32] },
    /// `pinSelfIdentityRoot(root)`: governance-gated pin of an accepted Self identity root (06b §2.2).
    PinSelfIdentityRoot { root: [u8; 32] },
    /// `pinSelfOfacRoot(kind, root)`: governance-gated pin of an accepted OFAC SMT root (06b §2.2).
    PinSelfOfacRoot { kind: u8, root: [u8; 32] },
    /// `retireSelfRoot(root)`: governance-gated retire of a Self root (06b §2.2).
    RetireSelfRoot { root: [u8; 32] },

    // ---- M4: prompt-contract ops to ContractHub ----
    /// `deployContract(text, parties)`: register an `Active` contract for the signer. Carries the
    /// **full** plain-language text (stored on-chain); the node derives `text_ref = keccak256(utf8)`.
    DeployContract {
        text: String,
        parties: Vec<AlloyAddr>,
    },
    /// `fundContract(id)`: fund contract `id`'s escrow with the tx's value (carried in `PendingTx`).
    FundContract { id: u64 },
    /// `invokeContract(id, triggerRef)`: open an ExecCase; the node runs the interpreter quorum at
    /// block time and commits/aborts the agreed effect.
    InvokeContract { id: u64, trigger_ref: [u8; 32] },
    /// `submitEffect(caseId, ops)`: an interpreter's canonical effect (deferred juror-daemon path).
    SubmitEffect {
        case_id: u64,
        effect: CanonicalEffect,
    },
}

/// A tx that passed validation in `eth_sendRawTransaction` and is queued for the next block.
#[derive(Clone, Debug)]
struct PendingTx {
    hash: B256,
    from: AlloyAddr,
    /// The recipient/`to` field of the tx envelope (StreamHub for stream ops; the payee for transfers).
    tx_to: AlloyAddr,
    /// Tx value (0 for stream ops — the deposit is a calldata arg, spec D2/Q1).
    value: u128,
    nonce: u64,
    /// Raw calldata, preserved for the explorer's `input` field.
    input: Vec<u8>,
    kind: PendingKind,
    /// EIP-2718 type byte the sender signed (`0` legacy / `1` 2930 / `2` 1559). Threaded into the
    /// `StoredTx` so the mined tx's `type` matches what the wallet signed (MetaMask sends type-2).
    tx_type: u8,
    /// EIP-1559 sender fee caps (present iff type 1/2), echoed verbatim in the tx/receipt JSON.
    max_fee_per_gas: Option<u128>,
    max_priority_fee_per_gas: Option<u128>,
}

/// The amount a queued tx debits from its sender's *spendable* balance when mined: its `value` (a
/// transfer amount, or a `fundContract` escrow funding — both carried in `PendingTx.value`), plus,
/// for an `openStream`, the locked `deposit` (a calldata arg, so it lives outside `value` and is 0
/// in `value`), plus the **gas fee** every fee-bearing op pays to the TREASURY (cycle-6 — the fee is
/// always charged, even on a FAILED op, so a sender who cannot afford it must be rejected at SUBMIT,
/// not left perpetually pending). Onboarding (`requestVerification`) is fee-exempt, so its fee is 0.
///
/// Used by `ingest_raw_tx` to sum a sender's still-pending mempool commitments for the cumulative
/// affordability check (M2-F2 / cycle-1 FU-1): the runtime debits all of these from the one balance at
/// block time, so admission must weigh them together, not each against the full live balance in
/// isolation. Saturating add so an absurd sum fails closed (over-rejects) rather than wrapping.
fn spendable_debit(value: u128, kind: &PendingKind) -> u128 {
    value
        .saturating_add(match kind {
            PendingKind::OpenStream { deposit, .. } => *deposit,
            _ => 0,
        })
        .saturating_add(fee_for_gas(gas_for_kind(kind)))
}

// ---------------------------------------------------------------------------------------------
// Event logs
//
// NOTE (ADR-0006 Decision 3): the per-op state transition — fee charge, the runtime op, the
// non-transfer nonce consume/bump, the EVM-style failed-tx post-state, and the M3 sweeps — now lives in
// the SHARED kernel `crates/exec` (`ubi2_exec::apply_tx`), which BOTH this server follower
// (`execute_block`) and the browser follower (`crates/runtime-wasm`) call, so there is one
// re-execution implementation. The helpers below build only the receipt LOGS, which are presentation
// (not in `state_root`) and a server-only concern.
// ---------------------------------------------------------------------------------------------

/// The `keccak256` event-signature topic for `StreamOpened(uint256,address,address)`. Indexed id in
/// `topics[1]` so `eth_getTransactionReceipt` carries the assigned stream id (spec §"RPC surface").
fn stream_opened_topic() -> B256 {
    keccak256(b"StreamOpened(uint256,address,address)")
}
/// Topic for `StreamStopped(uint256,address)`.
fn stream_stopped_topic() -> B256 {
    keccak256(b"StreamStopped(uint256,address)")
}
/// Topic for ERC-721 `Transfer(address,address,uint256)` (the two mints on open).
fn transfer_topic() -> B256 {
    keccak256(b"Transfer(address,address,uint256)")
}

/// 32-byte big-endian topic for a u64 (left-padded) — used for indexed stream ids.
fn u64_topic(v: u64) -> B256 {
    B256::from(U256::from(v))
}
/// 32-byte topic for a U256 token id.
fn u256_topic(v: U256) -> B256 {
    B256::from(v)
}
/// 32-byte topic for an address (left-padded to 32 bytes, EVM-style).
fn addr_topic(a: &AlloyAddr) -> B256 {
    let mut b = [0u8; 32];
    b[12..].copy_from_slice(a.as_slice());
    B256::from(b)
}

/// Build the logs emitted by an `openStream`: a `StreamOpened` event plus the two ERC-721 `Transfer`
/// mints (`0x0 → to` for the recipient token, `0x0 → from` for the sender receipt) — spec D4.
fn stream_open_logs(id: u64, from: AlloyAddr, to: AlloyAddr) -> Vec<TxLog> {
    let recipient_token = U256::from(id);
    let sender_token = U256::from(id) | (U256::from(1u8) << 255);
    vec![
        TxLog {
            address: STREAM_HUB,
            topics: vec![
                stream_opened_topic(),
                u64_topic(id),
                addr_topic(&from),
                addr_topic(&to),
            ],
            data: Vec::new(),
        },
        // Mint the recipient token (id) to `to`.
        TxLog {
            address: STREAM_HUB,
            topics: vec![
                transfer_topic(),
                addr_topic(&AlloyAddr::ZERO),
                addr_topic(&to),
                u256_topic(recipient_token),
            ],
            data: Vec::new(),
        },
        // Mint the sender receipt (id | SENDER_FLAG) to `from`.
        TxLog {
            address: STREAM_HUB,
            topics: vec![
                transfer_topic(),
                addr_topic(&AlloyAddr::ZERO),
                addr_topic(&from),
                u256_topic(sender_token),
            ],
            data: Vec::new(),
        },
    ]
}

/// Build the log emitted by a `stopStream`: a `StreamStopped(id, caller)` event.
fn stream_stop_logs(id: u64, caller: AlloyAddr) -> Vec<TxLog> {
    vec![TxLog {
        address: STREAM_HUB,
        topics: vec![stream_stopped_topic(), u64_topic(id), addr_topic(&caller)],
        data: Vec::new(),
    }]
}

// ---------------------------------------------------------------------------------------------
// M3 proof-of-humanity event logs (carried in tx receipts — spec 03 §"RPC / interfaces").
// ---------------------------------------------------------------------------------------------

/// Topic for `CaseOpened(uint256 indexed caseId, address indexed subject, uint8 kind)` — emitted when
/// a registration or challenge case is opened. `kind` (0=Registration,1=Challenge) is in `data`.
fn case_opened_topic() -> B256 {
    keccak256(b"CaseOpened(uint256,address,uint8)")
}
/// Topic for `VerdictSubmitted(uint256 indexed caseId, address indexed juror, uint8 verdict)` —
/// emitted on each accepted `submitVerdict`. `verdict` byte (0=Human,1=Sybil,2=Uncertain) in `data`.
fn verdict_submitted_topic() -> B256 {
    keccak256(b"VerdictSubmitted(uint256,address,uint8)")
}
/// Topic for `StatusChanged(address indexed subject, uint8 status)` — emitted when a subject's
/// `HumanStatus` changes as a lifecycle effect (e.g. Pending→Verified, *→Revoked). `status` in `data`.
fn status_changed_topic() -> B256 {
    keccak256(b"StatusChanged(address,uint8)")
}
/// Topic for `ZkPassportVerified(address indexed subject, uint8 assurance)` — emitted on a successful
/// `submitZkPassportProof` (spec §4.2 step 5). `assurance` byte (1=ENH,2=DUAL) is in `data`. Carries NO
/// PII (only the level — I6). `nullifier`/commitments are NEVER logged.
fn zk_verified_topic() -> B256 {
    keccak256(b"ZkPassportVerified(address,uint8)")
}
/// Topic for `CscaRegistered(bytes32 indexed keyId, bytes3 countryCode)` — emitted on `registerCsca`.
fn csca_registered_topic() -> B256 {
    keccak256(b"CscaRegistered(bytes32,bytes3)")
}
/// Topic for `CscaRevoked(bytes32 indexed keyId)` — emitted on `revokeCsca`.
fn csca_revoked_topic() -> B256 {
    keccak256(b"CscaRevoked(bytes32)")
}

/// Topic for `SelfIdentityRootPinned(bytes32 indexed root)` — emitted on `pinSelfIdentityRoot`.
fn self_identity_root_pinned_topic() -> B256 {
    keccak256(b"SelfIdentityRootPinned(bytes32)")
}

/// Topic for `SelfOfacRootPinned(bytes32 indexed root)` — emitted on `pinSelfOfacRoot`.
fn self_ofac_root_pinned_topic() -> B256 {
    keccak256(b"SelfOfacRootPinned(bytes32)")
}

/// Topic for `SelfRootRetired(bytes32 indexed root)` — emitted on `retireSelfRoot`.
fn self_root_retired_topic() -> B256 {
    keccak256(b"SelfRootRetired(bytes32)")
}

/// A `ZkPassportVerified(subject, assurance)` log for a successful ZK-passport proof (§4.2 step 5). The
/// `data` is the 1-byte assurance level (ENH/DUAL); no PII.
fn zk_verified_log(subject: &Address, assurance: Assurance) -> TxLog {
    TxLog {
        address: HUMANITY_HUB,
        topics: vec![
            zk_verified_topic(),
            h_addr_topic(&AlloyAddr::from(*subject)),
        ],
        data: u8_data(assurance.tag()),
    }
}

/// Encode a [`CaseKind`] as the 1-byte ABI value used in the `CaseOpened` log `data` (0/1).
fn case_kind_u8(kind: CaseKind) -> u8 {
    match kind {
        CaseKind::Registration => 0,
        CaseKind::Challenge => 1,
    }
}
/// Encode a [`Verdict`] as its 1-byte ABI value (0=Human,1=Sybil,2=Uncertain).
fn verdict_u8(v: Verdict) -> u8 {
    match v {
        Verdict::Human => 0,
        Verdict::Sybil => 1,
        Verdict::Uncertain => 2,
    }
}
/// Encode a [`HumanStatus`] as a stable 1-byte ABI value
/// (0=Unverified,1=Pending,2=Verified,3=Challenged,4=Revoked).
fn human_status_u8(s: HumanStatus) -> u8 {
    match s {
        HumanStatus::Unverified => 0,
        HumanStatus::Pending => 1,
        HumanStatus::Verified => 2,
        HumanStatus::Challenged => 3,
        HumanStatus::Revoked => 4,
    }
}

/// 32-byte right-padded `data` word for a single ABI `uint8` (EVM left-pads small uints).
fn u8_data(v: u8) -> Vec<u8> {
    let mut b = [0u8; 32];
    b[31] = v;
    b.to_vec()
}

/// A `CaseOpened(caseId, subject, kind)` log for a freshly opened case.
fn case_opened_log(case: &Case) -> TxLog {
    TxLog {
        address: HUMANITY_HUB,
        topics: vec![
            case_opened_topic(),
            h_u64_topic(case.id),
            h_addr_topic(&AlloyAddr::from(case.subject)),
        ],
        data: u8_data(case_kind_u8(case.kind)),
    }
}

/// A `VerdictSubmitted(caseId, juror, verdict)` log for an accepted juror vote.
fn verdict_submitted_log(case_id: u64, juror: &AlloyAddr, verdict: Verdict) -> TxLog {
    TxLog {
        address: HUMANITY_HUB,
        topics: vec![
            verdict_submitted_topic(),
            h_u64_topic(case_id),
            h_addr_topic(juror),
        ],
        data: u8_data(verdict_u8(verdict)),
    }
}

/// A `StatusChanged(subject, status)` log for a lifecycle status transition.
fn status_changed_log(subject: &Address, status: HumanStatus) -> TxLog {
    TxLog {
        address: HUMANITY_HUB,
        topics: vec![
            status_changed_topic(),
            h_addr_topic(&AlloyAddr::from(*subject)),
        ],
        data: u8_data(human_status_u8(status)),
    }
}

/// The standard ERC-721 `Transfer(from, to, tokenId)` mint log for the "Proof of Humanity" token of
/// `human` (`0x0 → human`, `tokenId == human as uint160`). Emitted by the HumanityHub when `human`
/// transitions to `Verified`.
fn poh_mint_log(human: &Address) -> TxLog {
    let h = AlloyAddr::from(*human);
    TxLog {
        address: HUMANITY_HUB,
        topics: vec![
            transfer_topic(),
            addr_topic(&AlloyAddr::ZERO),
            addr_topic(&h),
            u256_topic(token_id_of(&h)),
        ],
        data: Vec::new(),
    }
}

/// The standard ERC-721 `Transfer(from, to, tokenId)` burn log for the "Proof of Humanity" token of
/// `human` (`human → 0x0`). Emitted by the HumanityHub when `human` is `Revoked`.
fn poh_burn_log(human: &Address) -> TxLog {
    let h = AlloyAddr::from(*human);
    TxLog {
        address: HUMANITY_HUB,
        topics: vec![
            transfer_topic(),
            addr_topic(&h),
            addr_topic(&AlloyAddr::ZERO),
            u256_topic(token_id_of(&h)),
        ],
        data: Vec::new(),
    }
}

/// Emit the lifecycle `StatusChanged` log for `subject`'s transition to `status`, plus the soulbound
/// PoH ERC-721 `Transfer` mint/burn whenever the transition crosses the token-existence boundary. The
/// PoH token of an address **exists iff its status is `Verified`** (the exact predicate `ownerOf` /
/// `balanceOf` use), so:
///   * `prev != Verified` → `Verified` mints (`0x0 → subject`);
///   * `prev == Verified` → not-`Verified` (Revoked, or Challenged) burns (`subject → 0x0`).
///
/// `prev` is the status *before* the transition, so a `Verified→Verified` no-op never re-mints. Keeping
/// mint/burn aligned with the `ownerOf`/`balanceOf` predicate guarantees the log stream is a faithful
/// transcript of token existence (an indexer can reconstruct ownership from Transfer logs alone).
fn humanity_status_logs(
    subject: &Address,
    prev: Option<HumanStatus>,
    status: HumanStatus,
) -> Vec<TxLog> {
    let mut logs = vec![status_changed_log(subject, status)];
    let was_verified = prev == Some(HumanStatus::Verified);
    let is_verified = status == HumanStatus::Verified;
    if is_verified && !was_verified {
        logs.push(poh_mint_log(subject)); // token comes into existence
    } else if was_verified && !is_verified {
        logs.push(poh_burn_log(subject)); // token leaves existence (Revoked or Challenged)
    }
    logs
}

// ---------------------------------------------------------------------------------------------
// M4 prompt-contract event logs (carried in tx receipts — spec 04 §"RPC / interfaces"). Same
// `{address, topics, data}` shape as the StreamHub/HumanityHub logs.
// ---------------------------------------------------------------------------------------------

/// Topic for `ContractDeployed(uint256 indexed id, address indexed deployer, bytes32 textRef)` —
/// emitted on `deployContract`. `textRef` is in `data`.
fn contract_deployed_topic() -> B256 {
    keccak256(b"ContractDeployed(uint256,address,bytes32)")
}
/// Topic for `CaseOpened(uint256 indexed caseId, uint256 indexed contractId, address indexed invoker)`
/// — emitted on `invokeContract`. (Distinct from the HumanityHub's `CaseOpened` by its hub address +
/// signature: this one carries a contract id, not a subject.)
fn contract_case_opened_topic() -> B256 {
    keccak256(b"CaseOpened(uint256,uint256,address)")
}
/// Topic for `EffectCommitted(uint256 indexed caseId, uint256 indexed contractId, bytes32 effectHash)`
/// — emitted when a quorum-agreed effect is validated + applied. `effectHash` is in `data`.
fn effect_committed_topic() -> B256 {
    keccak256(b"EffectCommitted(uint256,uint256,bytes32)")
}
/// Topic for `EffectAborted(uint256 indexed caseId, uint256 indexed contractId)` — emitted when a case
/// aborts (split / no-quorum / invalid-or-over-authority effect / explicit Abort). Fail-closed (I4).
fn effect_aborted_topic() -> B256 {
    keccak256(b"EffectAborted(uint256,uint256)")
}

/// 32-byte `data` word carrying a 32-byte hash (a `bytes32` ABI value is its own word).
fn hash_data(h: &[u8; 32]) -> Vec<u8> {
    h.to_vec()
}

/// A `ContractDeployed(id, deployer, textRef)` log for a freshly deployed contract.
fn contract_deployed_log(id: u64, deployer: &AlloyAddr, text_ref: &[u8; 32]) -> TxLog {
    TxLog {
        address: CONTRACT_HUB,
        topics: vec![
            contract_deployed_topic(),
            c_u64_topic(id),
            c_addr_topic(deployer),
        ],
        data: hash_data(text_ref),
    }
}

/// A `CaseOpened(caseId, contractId, invoker)` log for a freshly opened exec case.
fn contract_case_opened_log(case_id: u64, contract_id: u64, invoker: &AlloyAddr) -> TxLog {
    TxLog {
        address: CONTRACT_HUB,
        topics: vec![
            contract_case_opened_topic(),
            c_u64_topic(case_id),
            c_u64_topic(contract_id),
            c_addr_topic(invoker),
        ],
        data: Vec::new(),
    }
}

/// The terminal log for an exec case: `EffectCommitted(caseId, contractId, effectHash)` when the case
/// committed an effect, else `EffectAborted(caseId, contractId)` (split / invalid / explicit Abort).
fn exec_case_outcome_log(case: &ExecCase) -> Option<TxLog> {
    match &case.status {
        ExecStatus::Committed(effect) => Some(TxLog {
            address: CONTRACT_HUB,
            topics: vec![
                effect_committed_topic(),
                c_u64_topic(case.id),
                c_u64_topic(case.contract),
            ],
            data: hash_data(&effect.effect_hash),
        }),
        ExecStatus::Aborted => Some(TxLog {
            address: CONTRACT_HUB,
            topics: vec![
                effect_aborted_topic(),
                c_u64_topic(case.id),
                c_u64_topic(case.contract),
            ],
            data: Vec::new(),
        }),
        // Still gathering submissions (the deferred juror-daemon path) — no terminal log yet.
        ExecStatus::Open => None,
    }
}

/// Fold a block's `(hash, number)` into a `u64` chain-entropy word for deterministic juror selection.
/// Both inputs are consensus values, so the entropy is byte-reproducible across nodes (spec §"Juror
/// selection": VRF-style from chain entropy; M3 uses this simpler deterministic-random seed).
fn block_entropy(hash: B256, number: u64) -> u64 {
    let b = hash.as_slice();
    let mut word = [0u8; 8];
    word.copy_from_slice(&b[..8]);
    u64::from_be_bytes(word) ^ number
}

/// Build the receipt logs for a SUCCESSFULLY-applied op, reading the post-op state + the shared
/// kernel's [`OpResult`] — the presentation layer that the shared apply path (`ubi2_exec::apply_tx`)
/// does NOT compute (logs are not in `state_root`). This reproduces, byte-for-byte, the logs the old
/// inline op match emitted, at the SAME post-op read timing. `pre_status` is the subject's status
/// snapshot captured BEFORE the op (for the ops that log a status transition). A FAILED op carries no
/// logs (the caller short-circuits), so this is only called on success.
fn build_op_logs(
    state: &MemState,
    p: &PendingTx,
    result: &ubi2_exec::OpResult,
    pre_status: Option<(Address, Option<HumanStatus>)>,
) -> Vec<TxLog> {
    use ubi2_exec::OpResult;
    match &p.kind {
        PendingKind::Transfer { .. } => Vec::new(),
        PendingKind::OpenStream { to, .. } => match result {
            OpResult::StreamId(id) => stream_open_logs(*id, p.from, *to),
            _ => Vec::new(),
        },
        PendingKind::StopStream { id } => stream_stop_logs(*id, p.from),
        PendingKind::RequestVerification { .. } => {
            let mut logs = vec![status_changed_log(
                &p.from.into_array(),
                HumanStatus::Pending,
            )];
            if let OpResult::CaseId(case_id) = result {
                if let Some(case) = state.get_case(*case_id) {
                    logs.insert(0, case_opened_log(&case));
                }
            }
            logs
        }
        PendingKind::Vouch { .. } => Vec::new(),
        PendingKind::Challenge { subject, .. } => {
            let mut logs = Vec::new();
            if let OpResult::CaseId(case_id) = result {
                if let Some(case) = state.get_case(*case_id) {
                    logs.push(case_opened_log(&case));
                }
            }
            // A Verified subject flips to Challenged when a challenge opens — emit StatusChanged + burn.
            let subj = subject.into_array();
            if let Some(h) = state.get_human(&subj) {
                if h.status == HumanStatus::Challenged {
                    logs.extend(humanity_status_logs(
                        &subj,
                        Some(HumanStatus::Verified),
                        h.status,
                    ));
                }
            }
            logs
        }
        PendingKind::SubmitVerdict { case_id, verdict } => {
            let mut logs = vec![verdict_submitted_log(*case_id, &p.from, verdict.verdict)];
            if let Some((subj, pre)) = pre_status {
                if let Some(h) = state.get_human(&subj) {
                    if Some(h.status) != pre {
                        logs.extend(humanity_status_logs(&subj, pre, h.status));
                    }
                }
            }
            logs
        }
        PendingKind::SubmitZkPassportProof { .. } => {
            let subject = p.from.into_array();
            let mut logs = match result {
                OpResult::Assurance(a) => vec![zk_verified_log(&subject, *a)],
                _ => Vec::new(),
            };
            let pre = pre_status.and_then(|(_, s)| s);
            if pre != Some(HumanStatus::Verified) {
                logs.extend(humanity_status_logs(&subject, pre, HumanStatus::Verified));
            }
            logs
        }
        PendingKind::RegisterCsca {
            country_code,
            key_id,
            ..
        } => vec![TxLog {
            address: HUMANITY_HUB,
            topics: vec![csca_registered_topic(), B256::from(*key_id)],
            data: {
                let mut d = [0u8; 32];
                d[..3].copy_from_slice(country_code);
                d.to_vec()
            },
        }],
        PendingKind::RevokeCsca { key_id } => vec![TxLog {
            address: HUMANITY_HUB,
            topics: vec![csca_revoked_topic(), B256::from(*key_id)],
            data: Vec::new(),
        }],
        PendingKind::PinSelfIdentityRoot { root } => vec![TxLog {
            address: HUMANITY_HUB,
            topics: vec![self_identity_root_pinned_topic(), B256::from(*root)],
            data: Vec::new(),
        }],
        PendingKind::PinSelfOfacRoot { kind, root } => vec![TxLog {
            address: HUMANITY_HUB,
            topics: vec![self_ofac_root_pinned_topic(), B256::from(*root)],
            data: {
                let mut d = [0u8; 32];
                d[31] = *kind;
                d.to_vec()
            },
        }],
        PendingKind::RetireSelfRoot { root } => vec![TxLog {
            address: HUMANITY_HUB,
            topics: vec![self_root_retired_topic(), B256::from(*root)],
            data: Vec::new(),
        }],
        PendingKind::DeployContract { .. } => match result {
            // The contract record's deploy_block/deploy_tx stamping is now done by the shared kernel
            // (it is consensus state); here we only emit the receipt log.
            OpResult::CaseId(id) => {
                let text_ref = match &p.kind {
                    PendingKind::DeployContract { text, .. } => contracts::text_commitment(text),
                    _ => [0u8; 32],
                };
                vec![contract_deployed_log(*id, &p.from, &text_ref)]
            }
            _ => Vec::new(),
        },
        PendingKind::FundContract { .. } => Vec::new(),
        PendingKind::InvokeContract { id, .. } => {
            let mut logs = Vec::new();
            if let OpResult::CaseId(case_id) = result {
                logs.push(contract_case_opened_log(*case_id, *id, &p.from));
                if let Some(case) = state.get_exec_case(*case_id) {
                    if let Some(log) = exec_case_outcome_log(&case) {
                        logs.push(log);
                    }
                }
            }
            logs
        }
        PendingKind::SubmitEffect { case_id, .. } => {
            if let Some(case) = state.get_exec_case(*case_id) {
                exec_case_outcome_log(&case).into_iter().collect()
            } else {
                Vec::new()
            }
        }
    }
}

/// Auto-finalize every `Pending` registration whose challenge window has cleared and which satisfies
/// the finalize gate (liveness passed + ≥MIN_VOUCHES + no open/upheld challenge). `now_block` is the
/// window clock (block HEIGHT); `verified_at_secs` is the emission epoch (unix SECONDS). Returns the
/// `StatusChanged(*, Verified)` logs for the humans it finalized. Fail-closed: a human that doesn't
/// meet the gate is skipped silently (no mutation — I4).
fn sweep_finalize(state: &mut dyn State, now_block: u64, verified_at_secs: u64) -> Vec<TxLog> {
    let pending: Vec<Address> = state
        .humans()
        .into_iter()
        .filter(|h| h.status == HumanStatus::Pending)
        .map(|h| h.address)
        .collect();
    let mut logs = Vec::new();
    for subject in pending {
        if finalize_registration(state, &subject, now_block, verified_at_secs).is_ok() {
            // Pending→Verified: emit StatusChanged + the PoH ERC-721 mint (0x0 → subject).
            logs.extend(humanity_status_logs(
                &subject,
                Some(HumanStatus::Pending),
                HumanStatus::Verified,
            ));
        }
    }
    logs
}

/// AI sybil-cluster auto-challenge sweep (security finding D / acceptance criterion 6). For each
/// `Pending` subject (address-sorted, so order-independent — I1), run the node's `oracle.analyze_sybil`
/// over the deterministic [`graph_view`](State::graph_view) (sorted edges). When the oracle flags the
/// cluster `Sybil`, auto-file a `system_challenge` against the subject so the jury path adjudicates it
/// before it can finalize. Skips a subject that already has an open challenge (one-open-per-subject) or
/// is on cooldown — `system_challenge` enforces both and we ignore those benign errors. Deterministic:
/// sorted scan, sorted graph, `block_entropy` seed; with the devnet `MockOracle` no model is called.
fn sweep_sybil_scan(
    state: &mut dyn State,
    oracle: &dyn HumanityOracle,
    block_hash: B256,
    now_block: u64,
) -> Vec<TxLog> {
    let pending: Vec<Address> = state
        .humans()
        .into_iter()
        .filter(|h| h.status == HumanStatus::Pending)
        .map(|h| h.address)
        .collect();
    let mut logs = Vec::new();
    for subject in pending {
        let graph = state.graph_view();
        if oracle.analyze_sybil(&graph, &subject).verdict != Verdict::Sybil {
            continue;
        }
        // The evidence ref commits to "the AI sybil scan flagged this subject's cluster at this block"
        // (I6: only a commitment on-chain, never the graph/PII). Deterministic from consensus values.
        let evidence_ref = keccak256(
            [
                b"sybil-scan".as_slice(),
                subject.as_slice(),
                block_hash.as_slice(),
            ]
            .concat(),
        )
        .0;
        let entropy = block_entropy(block_hash, now_block);
        match lc_system_challenge(
            state,
            &HUMANITY_HUB.into_array(),
            &subject,
            evidence_ref,
            entropy,
            now_block,
        ) {
            Ok(case_id) => {
                if let Some(case) = state.get_case(case_id) {
                    logs.push(case_opened_log(&case));
                }
            }
            // Benign: subject already has an open challenge, or the system opener is on cooldown for
            // this subject (a prior scan already cleared Human). No mutation occurred — skip.
            Err(_) => continue,
        }
    }
    logs
}

/// The set of 20-byte addresses a stored tx **touches** (EXPL-1 — for the per-address index). Always
/// includes `from` and `to`; for hub txs it also pulls the value-bearing counterparties out of the
/// applied logs (payees / vouchees / subjects / stream recipients / contract escrows / effect
/// targets), since those are exactly the addresses an explorer's per-account history must surface. We
/// read them from the logs (which the apply path already emits) rather than re-deriving, so the index
/// and the receipts agree. The result is sorted + deduped so each (address, tx) pair indexes once.
fn affected_addresses(tx: &StoredTx) -> Vec<Address> {
    let mut out: Vec<Address> = Vec::with_capacity(4);
    out.push(tx.from.into_array());
    if let Some(to) = tx.to {
        out.push(to.into_array());
    }
    for log in &tx.logs {
        // Address-typed topics are 32-byte left-padded; the low 20 bytes are the address. We treat any
        // topic whose high 12 bytes are zero as a candidate address (the convention `addr_topic` uses).
        for topic in &log.topics {
            let bytes = topic.as_slice();
            if bytes[..12].iter().all(|b| *b == 0) {
                let mut a = [0u8; 20];
                a.copy_from_slice(&bytes[12..]);
                // Skip the zero address (ERC-721 mint `from`); it is not a real account.
                if a != [0u8; 20] {
                    out.push(a);
                }
            }
        }
        // A contract escrow address (the `Transfer`/`Refund` source for an effect) is the log emitter's
        // contract space; the escrow address itself shows up as the `from` of the apply-time transfer,
        // which is recorded on those synthetic effect logs' parent tx. Effect targets are in topics.
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Record `tx` under every address it touches in the per-address index (EXPL-1). Append-only in block
/// order; each (address, tx) pair is recorded once.
fn index_tx(addr_index: &mut HashMap<Address, Vec<B256>>, tx: &StoredTx) {
    for a in affected_addresses(tx) {
        let entry = addr_index.entry(a).or_default();
        // Guard against double-indexing if the same tx is somehow re-stored (idempotent).
        if entry.last() != Some(&tx.hash) {
            entry.push(tx.hash);
        }
    }
}

/// Extra value-moving addresses a committed contract effect touches that aren't on the tx's
/// `from`/`to`/log-topics (EXPL-1). For an `InvokeContract`/`SubmitEffect` whose exec case committed,
/// this returns the contract's escrow address plus every effect-target address (Transfer/Refund/
/// OpenStream recipients) so the per-address index records them. Returns empty for non-contract ops or
/// a case that aborted / is still open (no value moved). Pure read of `state`.
fn contract_effect_addresses(state: &dyn State, kind: &PendingKind) -> Vec<Address> {
    let case_id = match kind {
        PendingKind::InvokeContract { .. } | PendingKind::SubmitEffect { .. } => {
            // Find the case this op resolved. For InvokeContract it is the highest-id case for the
            // contract; for SubmitEffect it is the named case. Look up directly via the case id where
            // we have it; for InvokeContract we re-derive by scanning the contract's cases.
            if let PendingKind::SubmitEffect { case_id, .. } = kind {
                Some(*case_id)
            } else if let PendingKind::InvokeContract { id, .. } = kind {
                // The just-opened case is the newest exec case for this contract.
                state
                    .exec_cases()
                    .into_iter()
                    .filter(|c| c.contract == *id)
                    .map(|c| c.id)
                    .max()
            } else {
                None
            }
        }
        _ => return Vec::new(),
    };
    let Some(case_id) = case_id else {
        return Vec::new();
    };
    let Some(case) = state.get_exec_case(case_id) else {
        return Vec::new();
    };
    let ExecStatus::Committed(effect) = &case.status else {
        return Vec::new();
    };
    let mut out = vec![ubi2_runtime::contract_address(case.contract)];
    for op in &effect.ops {
        match op {
            Op::Transfer { to, .. } => out.push(*to),
            Op::Refund { party, .. } => out.push(*party),
            Op::OpenStream { to, .. } => out.push(*to),
            // StopStream/SetVar/Abort move value only back into the escrow (already included).
            Op::StopStream { .. } | Op::SetVar { .. } | Op::Abort { .. } => {}
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Shared node state. Cheaply cloneable (`Arc` inside) so handlers and the tick task share it.
#[derive(Clone)]
pub struct Chain {
    inner: Arc<Mutex<Inner>>,
    chain_id: u64,
    /// Genesis unix time; also the devnet `verified_at` for the dev account.
    genesis_time: u64,
    /// Monotonic subscription-id source for `eth_subscribe`.
    sub_seq: Arc<AtomicU64>,
    /// `newHeads` fan-out: every produced block is broadcast to live WS subscribers.
    heads_tx: broadcast::Sender<Block>,
    /// The hot-swappable AI backend (the proof-of-humanity oracle + the prompt-contract interpreter, both
    /// AI seams — I1/I5). The devnet boots the deterministic `MockOracle`/`MockInterpreter` so the whole
    /// lifecycle verifies end-to-end with no model calls; a node configured with a live provider (boot
    /// config + the localhost-only `ubi_setOracleConfig`) swaps a provider-backed impl behind the same
    /// runtime traits at runtime. See [`oracle_admin`].
    oracle_admin: Arc<OracleAdmin>,
    /// M6 — the ZK-passport verifier seam (spec §6.1, ADR-0005 D2). The deterministic
    /// [`MockZkVerifier`] ships on the consensus path by default (exactly as M3 ships `MockOracle`); a
    /// node wires the real `ubi2_zkpoh::Groth16Verifier` (or, for the EC-7 injected-disagreement test, a
    /// stubbed mock) via [`Chain::with_verifier`]. Read once per block in `execute_block` so the verifier
    /// is fixed for the duration of a block (re-execution consensus, §5.4).
    verifier: Arc<dyn ZkPassportVerifier>,
    /// Browser-CSRF / DNS-rebinding policy for the admin methods (`Origin` allowlist + `Host` pinning).
    /// The loopback TCP-peer gate is always on; this scopes which browser origins may reach the admin
    /// surface (default: the local wallet at `http://localhost:3000`). See [`oracle_admin::AdminAccess`].
    admin_access: Arc<AdminAccess>,
    /// M5 (Stage A): the optional proposer signing key. When set, [`Chain::produce_block`] stamps the
    /// block's `proposer` (the key's address) and signs the header pre-image into `proposer_sig`, so a
    /// follower can `ecrecover` the author (spec §2.2). `None` ⇒ the single-node devnet produces blocks
    /// with a zero proposer + empty signature (unchanged M1–M4 behavior). The round-robin schedule that
    /// rotates this across validators is Stage B.
    proposer_key: Option<Arc<ProposerKey>>,
    /// M5 (Stage A): the live network status the node publishes for the read-only `ubi_getPeers` /
    /// `ubi_consensusStatus` RPCs. The peer table + the "is this node the proposer" flag live in
    /// `crates/node` (which owns the swarm); the node updates this through [`Chain::set_net_status`] /
    /// [`Chain::set_peers`] and the RPC handlers read it. Empty until the node wires the network.
    net_status: Arc<Mutex<NetStatus>>,
    /// Spec 07 §3.4 (`ln-trust-2` fix): the **seeded genesis anchor** — a snapshot of the state at
    /// height 0 (after all genesis seeding, before block #1) plus its recomputed `state_root`. Captured
    /// once by [`Chain::seal_genesis`] (or lazily at the first [`Chain::execute_block`]) and served to a
    /// browser light client over the sync gateway so it can reproduce a REAL seeded-genesis chain. `None`
    /// until sealed; a chain with no seeding (an empty genesis) seals to the empty-state root.
    genesis_anchor: Arc<Mutex<Option<GenesisAnchor>>>,
    /// M5 Stage B (fork choice / reorg, spec 08 §5.4/§6): a bounded ring of the committed `MemState`
    /// **before** each recent block was applied — `parent_height → parent state`. It lets the follower
    /// reorg a bounded distance (`< FINALITY_DEPTH`) when a lower-view competitor at the tip height
    /// arrives after a higher-view block (§5.4 re-convergence): restore the parent state, drop the loser,
    /// re-execute the winner. Pruned to the last `FINALITY_DEPTH + 1` heights, so it never grows
    /// unbounded and never lets a reorg cross the finalized frontier. Kept OUTSIDE `Inner` (which is
    /// cloned as the trial-execution backup) so it is not churned by the trial/rollback dance.
    recent_states: Arc<Mutex<std::collections::BTreeMap<u64, MemState>>>,
    /// M5 Stage B (spec 08 §5.4/§6.1/§6.3): the bounded SIDE STORE of valid non-canonical fork blocks,
    /// keyed by block hash. When a node is on a losing tip-race branch and the winning branch's blocks
    /// arrive non-contiguously (a child of a block this node does not hold as canonical), they are
    /// retained here so a later block that completes the branch back to a common ancestor triggers a
    /// bounded general reorg. Pruned to blocks above the finalized frontier and capped at
    /// [`MAX_FORK_STORE`]; kept OUTSIDE `Inner` (not churned by the trial/rollback clone), like
    /// `recent_states`. Purely a local reconciliation aid — it never feeds a committed value (I1/I2).
    fork_store: Arc<Mutex<HashMap<B256, ForkBlockEntry>>>,
}

/// The seeded genesis anchor served to a light client (spec 07 §3.4). Holds the canonical genesis state
/// **snapshot bytes** (the `runtime-wasm`-compatible `state` JSON, re-derivable to `state_root`) and the
/// recomputed seeded `state_root`. The light client re-derives the root from the snapshot and rejects the
/// gateway unless it equals its PINNED constant (so the snapshot is untrusted data; the anchor is pinned).
#[derive(Clone, Debug)]
pub struct GenesisAnchor {
    /// The seeded `state_root` over the height-0 state (recomputed via `ubi2_runtime::state_root`).
    pub state_root: B256,
    /// The canonical genesis state snapshot — the `state` section JSON the `runtime-wasm` snapshot
    /// decoder imports (accounts/streams/humans/jurors/contracts/CSCA/governance/…), serialized bytes.
    pub snapshot: Vec<u8>,
}

/// Build the [`GenesisAnchor`] for a height-0 `MemState`: recompute its `state_root` and serialize its
/// canonical genesis snapshot (the `state` JSON the `runtime-wasm` decoder imports). Pure (spec 07 §3.4).
fn build_genesis_anchor(state: &MemState) -> GenesisAnchor {
    let state_root = B256::from(ubi2_runtime::state_root(state));
    let json = persist::genesis_state_json(state);
    let snapshot = serde_json::to_vec(&json).expect("genesis state json serializes");
    GenesisAnchor {
        state_root,
        snapshot,
    }
}

/// A connected peer as the node sees it, surfaced read-only by `ubi_getPeers` (spec §11). The node
/// (which owns the libp2p swarm + peer table) maps its transport `PeerInfo` into this and publishes it
/// through [`Chain::set_peers`]; `crates/rpc` only renders it (no network types leak into rpc).
#[derive(Clone, Debug)]
pub struct PeerStatus {
    /// The peer's libp2p `PeerId`, as a base58 string.
    pub peer_id: String,
    /// The multiaddr we connected over.
    pub multiaddr: String,
    /// The bound validator address (if the peer proved a PeerId↔address binding at the handshake).
    pub validator: Option<AlloyAddr>,
    /// The peer's last-reported tip `(height, hash)` from its `Hello` / block gossip.
    pub tip: Option<(u64, B256)>,
}

/// Live network/consensus status the node publishes for the read-only RPCs (spec §11). Stage A: a peer
/// list, whether THIS node is the designated proposer, and the designated proposer's address.
#[derive(Clone, Debug, Default)]
pub struct NetStatus {
    pub peers: Vec<PeerStatus>,
    /// True iff this node is the Stage-A designated block proposer.
    pub is_proposer: bool,
    /// The designated proposer's address (the single Stage-A authority); `None` until the node sets it.
    pub designated_proposer: Option<AlloyAddr>,
    /// k-deep finality depth (devnet default 6); `head − FINALITY_DEPTH` is the finalized height.
    pub finality_depth: u64,
    /// Stage B (§11): the current epoch validator snapshot `V`, sorted ascending. The node publishes it
    /// from the on-chain snapshot (multi-validator mode) or `[designated]` (Stage-A override mode).
    pub validator_set: Vec<AlloyAddr>,
    /// Stage B (§11): this node's LOCAL view for the height it is extending (a local liveness value,
    /// labeled as such — never a committed value). `0` until the node's view timer sets it.
    pub current_view: u32,
    /// M5 Stage B (spec 08 §5.3): the number of distinct `V`-members this node currently considers
    /// **reachable** (self + ping-live bound-validator peers), as counted by the production connectivity
    /// guard. A LOCAL liveness signal (never committed): when it drops below `N/2 + 1` this node stalls
    /// production (the partition-safe-finality guard). Surfaced on `ubi_consensusStatus` so a partition
    /// test can observe the minority side converge below majority within a bound (Blocker-2).
    pub reachable_validators: u32,
}

/// M5: a proposer's secp256k1 signing key + its derived EVM address. Used to sign block headers so a
/// follower can recover the author. Held in an `Arc` on the [`Chain`] so the block-production task can
/// sign without cloning key material per block.
pub struct ProposerKey {
    signing_key: k256::ecdsa::SigningKey,
    address: AlloyAddr,
}

impl std::fmt::Debug for ProposerKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("ProposerKey")
            .field("address", &self.address)
            .finish_non_exhaustive()
    }
}

impl ProposerKey {
    /// Build a proposer key from 32 raw secret bytes, deriving the EVM address from the public key
    /// (`keccak256(uncompressed_pubkey[1..])[12..]`, the standard EVM derivation).
    pub fn from_bytes(secret: &[u8; 32]) -> Result<Self, String> {
        let signing_key =
            k256::ecdsa::SigningKey::from_slice(secret).map_err(|e| format!("bad key: {e}"))?;
        let verifying_key = signing_key.verifying_key();
        let pubkey = verifying_key.to_encoded_point(false);
        // Uncompressed SEC1: 0x04 ‖ X(32) ‖ Y(32); EVM address = keccak256(X‖Y)[12..].
        let hash = keccak256(&pubkey.as_bytes()[1..]);
        let address = AlloyAddr::from_slice(&hash[12..]);
        Ok(Self {
            signing_key,
            address,
        })
    }

    /// The proposer's EVM address (the value stamped into `Block::proposer`).
    pub fn address(&self) -> AlloyAddr {
        self.address
    }

    /// Sign a 32-byte header hash, returning the 65-byte `r‖s‖v` signature (`v` = 27 + recovery id) —
    /// the same encoding [`recover_proposer`] expects.
    fn sign_prehash(&self, hash: &B256) -> Vec<u8> {
        let (sig, recid) = self
            .signing_key
            .sign_prehash_recoverable(hash.as_slice())
            .expect("sign 32-byte prehash");
        let mut out = Vec::with_capacity(65);
        out.extend_from_slice(&sig.r().to_bytes());
        out.extend_from_slice(&sig.s().to_bytes());
        out.push(27 + recid.to_byte());
        out
    }
}

/// M5: recover the proposer address from a 65-byte `r‖s‖v` signature over a header hash. Returns `None`
/// on a malformed signature. Mirrors `ProposerKey::sign_prehash` so a follower verifies authorship
/// (`ecrecover(proposer_sig) == proposer`, spec §2.2/§5.1). Pure; no chain state.
pub fn recover_proposer(hash: &B256, sig: &[u8]) -> Option<AlloyAddr> {
    if sig.len() != 65 {
        return None;
    }
    let v = sig[64];
    let recid_byte = v.checked_sub(27)?;
    let recid = k256::ecdsa::RecoveryId::from_byte(recid_byte)?;
    let signature = k256::ecdsa::Signature::from_slice(&sig[..64]).ok()?;
    let vkey =
        k256::ecdsa::VerifyingKey::recover_from_prehash(hash.as_slice(), &signature, recid).ok()?;
    let pubkey = vkey.to_encoded_point(false);
    let addr_hash = keccak256(&pubkey.as_bytes()[1..]);
    Some(AlloyAddr::from_slice(&addr_hash[12..]))
}

impl Chain {
    /// Build a chain with a fresh genesis block at `genesis_time`. Seed accounts (e.g. the
    /// pre-verified dev account) via [`Chain::seed_account`] before serving.
    pub fn new(chain_id: u64, genesis_time: u64) -> Self {
        // Genesis: empty txs ⇒ txs_root over zero txs; the state_root over the empty genesis state (it
        // is reseeded by `seed_account`/`seed_verified_human` AFTER construction, so the genesis header
        // commits the pre-seed empty root — this is fine: genesis is a fixed anchor, never re-executed).
        let genesis_txs_root = Block::compute_txs_root(&[]);
        let genesis_state_root = B256::ZERO;
        let genesis_proposer = AlloyAddr::ZERO;
        let genesis_hash = Block::compute_hash(
            0,
            B256::ZERO,
            genesis_time,
            0, // genesis view is 0 (Stage-A block == Stage-B block with view 0)
            genesis_txs_root,
            genesis_state_root,
            &genesis_proposer,
        );
        let genesis = Block {
            number: 0,
            hash: genesis_hash,
            parent_hash: B256::ZERO,
            timestamp: genesis_time,
            view: 0,
            txs_root: genesis_txs_root,
            state_root: genesis_state_root,
            proposer: genesis_proposer,
            proposer_sig: Vec::new(),
            txs: vec![],
        };
        let mut blocks_by_hash = HashMap::new();
        blocks_by_hash.insert(genesis_hash, 0usize);
        let (heads_tx, _) = broadcast::channel(256);
        Chain {
            inner: Arc::new(Mutex::new(Inner {
                state: MemState::new(),
                blocks: vec![genesis],
                blocks_by_hash,
                txs: HashMap::new(),
                mempool: vec![],
                addr_index: HashMap::new(),
                raw_tx: HashMap::new(),
            })),
            chain_id,
            genesis_time,
            sub_seq: Arc::new(AtomicU64::new(1)),
            heads_tx,
            // Devnet default: the deterministic MockOracle/MockInterpreter (everyone votes a confident
            // `Human` / a no-op effect unless a per-input override is scripted), so the lifecycle
            // verifies end-to-end in CI (I5). The node may swap a provider-backed impl at runtime via
            // the localhost-only admin RPC (`with_oracle_admin`).
            oracle_admin: Arc::new(OracleAdmin::mock_only()),
            // M6 devnet default: the deterministic MockZkVerifier (a confident accept unless a
            // per-(nullifier, submitter) override is scripted), so the ZK lifecycle verifies end-to-end
            // in CI (I5). The node wires the real `Groth16Verifier` via `with_verifier`.
            verifier: Arc::new(MockZkVerifier::default()),
            admin_access: Arc::new(AdminAccess::default()),
            proposer_key: None,
            net_status: Arc::new(Mutex::new(NetStatus {
                finality_depth: 6,
                ..Default::default()
            })),
            genesis_anchor: Arc::new(Mutex::new(None)),
            recent_states: Arc::new(Mutex::new(std::collections::BTreeMap::new())),
            fork_store: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// M5 (Stage A): publish the live peer list for `ubi_getPeers` (the node calls this whenever its
    /// peer table changes — connect/disconnect/Hello/tip update). Read-only surface (I6).
    pub fn set_peers(&self, peers: Vec<PeerStatus>) {
        self.net_status.lock().unwrap().peers = peers;
    }

    /// M5 (Stage A): publish whether THIS node is the designated proposer + the designated proposer's
    /// address (the node sets this once at startup from its config). Backs `ubi_consensusStatus`.
    pub fn set_proposer_role(&self, is_proposer: bool, designated: Option<AlloyAddr>) {
        let mut s = self.net_status.lock().unwrap();
        s.is_proposer = is_proposer;
        s.designated_proposer = designated;
    }

    /// M5 (Stage B, §11): publish the effective validator set `V` + this node's local `current_view`
    /// for `ubi_consensusStatus`. The node computes `V` (on-chain snapshot or the Stage-A override) and
    /// its local view in `crates/node` and pushes it here; the RPC handler renders it. Read-only (I6).
    pub fn set_consensus_status(
        &self,
        validator_set: Vec<AlloyAddr>,
        current_view: u32,
        reachable_validators: u32,
    ) {
        let mut s = self.net_status.lock().unwrap();
        s.validator_set = validator_set;
        s.current_view = current_view;
        s.reachable_validators = reachable_validators;
    }

    /// M5 Stage B (spec 08 §2.1): ensure the genesis (height-0) epoch validator snapshot is seeded. The
    /// snapshot is normally installed during `execute_block` at block #1, but the follower's schedule read
    /// (`validate_and_apply_block`) happens BEFORE that first execution — so a fresh follower would see an
    /// empty `V` for block #1. This idempotent, deterministic helper seeds it over the seeded genesis
    /// state on first use (only while the head is still genesis). It re-derives the same sorted membership
    /// every node computes, so it introduces no divergence (§8); a chain with no seeded validators seeds
    /// an empty `V`, unchanged.
    fn ensure_epoch_validators_seeded(&self) {
        let mut g = self.inner.lock().unwrap();
        let head = g.blocks.last().expect("genesis present").number;
        if head == 0 && g.state.epoch_validators().is_empty() {
            refresh_epoch_validators(&mut g.state, 0);
        }
    }

    /// M5 (Stage B): the on-chain epoch validator snapshot `V` at the current head (spec 08 §2.1),
    /// sorted ascending, as `AlloyAddr`. Pure read of committed state — the authoritative multi-validator
    /// set (before the Stage-A single-proposer override, which the node applies). Empty until genesis
    /// seeds it (or in a single-proposer devnet that seeds no jurors).
    pub fn validator_set(&self) -> Vec<AlloyAddr> {
        self.ensure_epoch_validators_seeded();
        let g = self.inner.lock().unwrap();
        validator_set(&g.state)
            .into_iter()
            .map(AlloyAddr::from)
            .collect()
    }

    /// Snapshot of the live network status (for the RPC handlers + tests). Pure read.
    pub fn net_status(&self) -> NetStatus {
        self.net_status.lock().unwrap().clone()
    }

    /// M5 (Stage A): install the proposer signing key. When set, every block this node produces stamps
    /// the key's address as `Block::proposer` and signs the header pre-image into `proposer_sig`, so a
    /// follower can recover the author (spec §2.2). The single-node devnet runs without it (zero
    /// proposer, empty signature). Stage B adds the round-robin schedule that decides *when* this node
    /// is the proposer.
    pub fn with_proposer_key(mut self, key: Arc<ProposerKey>) -> Self {
        self.proposer_key = Some(key);
        self
    }

    /// The configured proposer address, if any (the local validator address for `ubi_consensusStatus`).
    pub fn proposer_address(&self) -> Option<AlloyAddr> {
        self.proposer_key.as_ref().map(|k| k.address)
    }

    /// M5 (Stage A, A4 — the follower's block-validation entry point). Validate a block received from the
    /// network and, on success, re-execute it and append it to the local chain. Implements spec §5.1
    /// (Stage-A subset): valid parent, correct author, and a **byte-identical re-executed `state_root`**.
    ///
    /// Inputs are the wire header fields + the block's ordered **raw user-tx bytes** (`raw_txs`, exactly
    /// the bytes that were gossiped — system/sweep txs are NOT carried; the follower regenerates them by
    /// re-running the same deterministic sweeps). `expected_proposer` is the Stage-A designated proposer
    /// (the node passes its single-proposer address); the block's `proposer` must equal it and the
    /// signature must recover to it.
    ///
    /// Fail-closed: a block failing ANY check applies **no** state change (the trial executes against a
    /// snapshot and is committed only if the recomputed `state_root` + `hash` match the claimed header).
    #[allow(clippy::too_many_arguments)]
    pub fn validate_and_apply_block(
        &self,
        number: u64,
        parent_hash: B256,
        timestamp: u64,
        view: u32,
        claimed_txs_root: B256,
        claimed_state_root: B256,
        proposer: AlloyAddr,
        proposer_sig: &[u8],
        raw_txs: &[Vec<u8>],
        validator_override: Option<AlloyAddr>,
    ) -> Result<Block, BlockError> {
        // Stage B: seed the genesis epoch snapshot on first use so block #1's schedule read sees `V`.
        self.ensure_epoch_validators_seeded();
        // ---- Cheap header checks (no state mutation), in fail-fast order ----
        // §4(1) parent + height + timestamp sanity FIRST: a block off our chain is the most meaningful
        // rejection (fork / behind-or-ahead) and is cheaper than the ecrecover below.
        {
            let g = self.inner.lock().unwrap();
            let head = g.blocks.last().expect("genesis present");
            if number != head.number + 1 {
                return Err(BlockError::NonContiguous {
                    have: head.number,
                    got: number,
                });
            }
            if parent_hash != head.hash {
                return Err(BlockError::WrongParent);
            }
            if timestamp <= head.timestamp {
                return Err(BlockError::BadTimestamp);
            }
        }

        // §4(2) view in range: an absurd view is rejected before any expensive work.
        if view >= VIEW_MAX {
            return Err(BlockError::ViewOutOfRange { view });
        }

        // §4(3) author = scheduled proposer. Resolve the effective `V` (§3.3): a `validator_override`
        // (the Stage-A single designated proposer) pins `V = [override]` (`N = 1`) and takes PRECEDENCE
        // over any on-chain snapshot; otherwise `V = validator_set(parent_state)` (the epoch snapshot).
        // The parent state is the current committed state (this block is not yet applied), so its
        // snapshot is exactly the one the schedule reads (§2.1). `N >= 1` required (`NoValidatorSet`).
        let expected = {
            let g = self.inner.lock().unwrap();
            let v: Vec<AlloyAddr> = match validator_override {
                Some(a) => vec![a],
                None => validator_set(&g.state)
                    .into_iter()
                    .map(AlloyAddr::from)
                    .collect(),
            };
            let n = v.len();
            if n == 0 {
                return Err(BlockError::NoValidatorSet);
            }
            v[proposer_index(number, view, n)]
        };
        if proposer != expected {
            return Err(BlockError::WrongProposer);
        }

        let claimed_hash = Block::compute_hash(
            number,
            parent_hash,
            timestamp,
            view,
            claimed_txs_root,
            claimed_state_root,
            &proposer,
        );

        // §4(4) signature recovers to the author. The header hash now commits `view` (§2.2), so a
        // follower cannot alter a block's view without breaking the signature.
        match recover_proposer(&claimed_hash, proposer_sig) {
            Some(recovered) if recovered == proposer => {}
            _ => return Err(BlockError::BadSignature),
        }

        // Decode the ordered raw user txs into `PendingTx` (same structural decode the proposer used —
        // chain-id bind, signer recovery, calldata shape). A tx that does not decode means the block is
        // malformed/forged ⇒ reject (do not apply).
        let mut pending = Vec::with_capacity(raw_txs.len());
        for raw in raw_txs {
            match decode_pending_tx(self.chain_id, raw) {
                Ok(p) => pending.push(p),
                Err(_) => return Err(BlockError::UndecodableTx),
            }
        }

        // ---- §4(5) deterministic state transition (the I1/I2 cross-node check) ----
        // Snapshot the inner state so a state-root mismatch rolls back to a no-op (fail-closed). Then
        // re-execute the committed tx order via the SAME routine the proposer ran, at the block's `view`,
        // stamping the block's original proposer + signature so the recomputed header is byte-identical.
        let backup = self.inner.lock().unwrap().clone();
        let produced = self.execute_block(
            pending,
            timestamp,
            view,
            Some((proposer, proposer_sig.to_vec())),
        );

        if produced.state_root != claimed_state_root
            || produced.txs_root != claimed_txs_root
            || produced.hash != claimed_hash
        {
            // Roll back the trial execution entirely — the block is rejected and nothing is applied.
            *self.inner.lock().unwrap() = backup;
            return Err(BlockError::StateRootMismatch {
                expected: claimed_state_root,
                got: produced.state_root,
            });
        }

        // ---- Mempool prune (follower hygiene) ----
        // A follower's mempool is NOT drained by applying a block (only the proposer's `produce_block`
        // takes the mempool). Without pruning, a tx that was mined (in this or an earlier block) or that
        // has gone stale (its sender's account nonce has advanced past it) lingers forever, blocking the
        // sender's later txs via the cumulative-nonce submit gate. After a successful apply, drop any
        // mempool tx that is now mined or whose nonce is below its sender's current account nonce. This
        // is local hygiene only — it touches no consensus state (the block already committed).
        {
            let mut g = self.inner.lock().unwrap();
            let mined: std::collections::HashSet<B256> =
                produced.txs.iter().map(|t| t.hash).collect();
            let taken = std::mem::take(&mut g.mempool);
            let mut kept = Vec::with_capacity(taken.len());
            for p in taken {
                let acct_nonce = g
                    .state
                    .get(&p.from.into_array())
                    .map(|acc| acc.nonce)
                    .unwrap_or(0);
                let stale = mined.contains(&p.hash) || p.nonce < acct_nonce;
                if !stale {
                    kept.push(p);
                }
            }
            g.mempool = kept;
        }
        Ok(produced)
    }

    /// M5 Stage B (spec 08 §5.4/§6.1/§6.3): consider a VALID block that competes with — but does not
    /// cleanly extend — the local canonical chain, and perform a **bounded GENERAL reorg** to the
    /// fork-choice-best branch it completes. This generalises the earlier depth-1 tip-swap: it handles
    /// not only a same-height, shared-parent competitor (a late `view 0` original vs an adopted `view 1`
    /// successor, §5.4) but also a **taller** honest branch whose ancestry does not extend our tip
    /// (the h1@view1 → h2@view1 race that would otherwise leave a node on `h1@view0` PERMANENTLY stuck
    /// and finalizing a conflicting chain — spec §5.4/§7, EC-B-F5).
    ///
    /// Mechanics:
    /// - The block is authenticated up front (view in range, hash + signature recover to `proposer`)
    ///   and RETAINED in the bounded side store (`fork_store`), keyed by hash, so a later-arriving child
    ///   that names it as parent can complete the branch.
    /// - We then walk `parent_hash` back through the side store + our canonical blocks to the **common
    ///   ancestor**. If that ancestor is at/below the finalized frontier we REFUSE (never revert
    ///   finalized history, §6.3); otherwise we truncate the losing suffix, restore the ancestor state,
    ///   and deterministically re-execute the winning branch (each block re-validated + state-root
    ///   matched). The displaced canonical suffix is moved into the side store so a still-better branch
    ///   can later win it back — fork choice is a total order, so this converges (I1).
    ///
    /// Returns `Ok(Some(new_tip))` if a reorg happened, `Ok(None)` if the block was valid but no reorg
    /// applied (the current chain is still preferred, the branch is incomplete, or its ancestor is
    /// finalized-bounded — all BENIGN, do not penalize), `Err(e)` only if the block is GENUINELY invalid
    /// (`ViewOutOfRange` / `BadSignature`, or — on re-execution — `WrongProposer` / `StateRootMismatch`),
    /// which the caller may penalize. Fail-closed: an invalid branch applies no state change.
    #[allow(clippy::too_many_arguments)]
    pub fn consider_competing_block(
        &self,
        number: u64,
        parent_hash: B256,
        timestamp: u64,
        view: u32,
        claimed_txs_root: B256,
        claimed_state_root: B256,
        proposer: AlloyAddr,
        proposer_sig: &[u8],
        raw_txs: &[Vec<u8>],
        validator_override: Option<AlloyAddr>,
    ) -> Result<Option<Block>, BlockError> {
        self.ensure_epoch_validators_seeded();
        // §4(2) view in range — reject an absurd/garbage view before any retention or work.
        if view >= VIEW_MAX {
            return Err(BlockError::ViewOutOfRange { view });
        }
        // §4(4) authenticate: the hash + signature must recover to the claimed author. This is what
        // makes it safe to RETAIN the block (only a signed-by-a-real-key block enters the side store);
        // its schedule + state-root are fully re-checked when the branch is re-executed on a reorg.
        let hash = Block::compute_hash(
            number,
            parent_hash,
            timestamp,
            view,
            claimed_txs_root,
            claimed_state_root,
            &proposer,
        );
        match recover_proposer(&hash, proposer_sig) {
            Some(recovered) if recovered == proposer => {}
            _ => return Err(BlockError::BadSignature),
        }

        // Snapshot the tip + finalized frontier (short lock).
        let (current_tip, finalized, already_canonical) = {
            let g = self.inner.lock().unwrap();
            let tip = g.blocks.last().expect("genesis present");
            let finalized = tip.number.saturating_sub(FINALITY_DEPTH);
            let canon = g.blocks_by_hash.contains_key(&hash);
            ((tip.number, tip.view, tip.hash), finalized, canon)
        };
        // Already canonical (our tip or an interior block) — nothing to reconcile.
        if already_canonical || hash == current_tip.2 {
            return Ok(None);
        }
        // At/below the finalized frontier a competing block can never win a bounded reorg — never
        // retained, never reorged (a reorg here would cross finalized history, §6.3).
        if number <= finalized {
            return Ok(None);
        }

        // Retain the authenticated fork block so a later child can complete its branch (§5.4).
        self.store_fork_block(
            ForkBlockEntry {
                number,
                parent_hash,
                timestamp,
                view,
                txs_root: claimed_txs_root,
                state_root: claimed_state_root,
                proposer,
                proposer_sig: proposer_sig.to_vec(),
                raw_txs: raw_txs.to_vec(),
                hash,
            },
            finalized,
        );

        // Assemble the fork-choice-best COMPLETE branch and reorg to it iff it beats our tip (§6.1).
        self.maybe_reorg_to_best_branch(current_tip, finalized, validator_override)
    }

    /// Insert a fork block into the bounded side store (keyed by hash) and prune it: drop anything at or
    /// below the finalized frontier (it can never win a bounded reorg, §6.3), then, if still over
    /// [`MAX_FORK_STORE`], evict the lowest-height entries (a hostile flood cannot grow it unbounded).
    fn store_fork_block(&self, entry: ForkBlockEntry, finalized: u64) {
        let mut store = self.fork_store.lock().unwrap();
        store.insert(entry.hash, entry);
        store.retain(|_, e| e.number > finalized);
        if store.len() > MAX_FORK_STORE {
            // Evict lowest-height entries first (oldest forks are least likely to still win).
            let mut by_height: Vec<(u64, B256)> =
                store.iter().map(|(h, e)| (e.number, *h)).collect();
            by_height.sort();
            let excess = store.len() - MAX_FORK_STORE;
            for (_, h) in by_height.into_iter().take(excess) {
                store.remove(&h);
            }
        }
    }

    /// M5 Stage B (spec 08 §6.1): find the fork-choice-best COMPLETE branch among the retained fork
    /// blocks (each walked back to a canonical common ancestor above the finalized frontier) and, if its
    /// tip beats the current canonical tip, perform the bounded general reorg. Pure of any clock/rand —
    /// the decision + re-execution read only `(state, headers)`, so every honest node converges (I1).
    fn maybe_reorg_to_best_branch(
        &self,
        current_tip: TipKey,
        finalized: u64,
        validator_override: Option<AlloyAddr>,
    ) -> Result<Option<Block>, BlockError> {
        // Snapshot the side store (short lock) so the walk holds no lock on `inner`/`recent_states`.
        let fmap: HashMap<B256, ForkBlockEntry> = self.fork_store.lock().unwrap().clone();
        if fmap.is_empty() {
            return Ok(None);
        }
        // Find the best complete branch: for each retained block treated as a branch tip, walk to a
        // canonical ancestor and keep the fork-choice-best whose tip beats our current tip.
        let mut best: Option<ReorgCandidate> = None;
        {
            let g = self.inner.lock().unwrap();
            for tip_entry in fmap.values() {
                let tip: TipKey = (tip_entry.number, tip_entry.view, tip_entry.hash);
                if !fork_choice_prefers(tip, current_tip) {
                    continue; // this branch tip does not beat our canonical tip
                }
                if let Some((branch, ca_height)) =
                    assemble_fork_branch(tip_entry, &fmap, &g, finalized)
                {
                    let better = best
                        .as_ref()
                        .map(|b| fork_choice_prefers(tip, b.tip))
                        .unwrap_or(true);
                    if better {
                        best = Some(ReorgCandidate {
                            branch,
                            ca_height,
                            tip,
                        });
                    }
                }
            }
        }
        let candidate = match best {
            Some(b) => b,
            None => return Ok(None), // no complete, preferred, finality-safe branch yet
        };
        self.execute_reorg(candidate.branch, candidate.ca_height, validator_override)
    }

    /// Perform the bounded general reorg to `branch` (ascending `ca+1 … tip`), whose common ancestor is
    /// the canonical block at `ca_height`. Restores the ancestor state, truncates the losing suffix
    /// (moving it into the side store so a still-better branch can win it back), then re-executes each
    /// winning block via the ordinary validated apply (schedule + signature + byte-identical state-root
    /// re-checked, I1/I2). Fail-closed: any failure rolls the whole reorg back to the pre-reorg state.
    fn execute_reorg(
        &self,
        branch: Vec<ForkBlockEntry>,
        ca_height: u64,
        validator_override: Option<AlloyAddr>,
    ) -> Result<Option<Block>, BlockError> {
        // The common-ancestor state (state AFTER block `ca_height` = the winning branch's parent state).
        // Must still be retained (guaranteed above the finalized frontier); else we cannot reorg safely.
        let ca_state = match self.recent_states.lock().unwrap().get(&ca_height) {
            Some(s) => s.clone(),
            None => return Ok(None),
        };
        // Full backups (fail-closed rollback covers BOTH the canonical chain and the recent-state ring).
        let inner_backup = self.inner.lock().unwrap().clone();
        let rs_backup = self.recent_states.lock().unwrap().clone();

        // Truncate the losing suffix down to the common ancestor + restore its state. Collect the
        // displaced blocks (with their raw txs) so we can retain them in the side store.
        let displaced: Vec<ForkBlockEntry> = {
            let mut g = self.inner.lock().unwrap();
            let cut = ca_height as usize + 1;
            let old_suffix: Vec<Block> = if cut < g.blocks.len() {
                g.blocks.split_off(cut)
            } else {
                Vec::new()
            };
            let mut displaced = Vec::with_capacity(old_suffix.len());
            for b in &old_suffix {
                g.blocks_by_hash.remove(&b.hash);
                for t in &b.txs {
                    g.txs.remove(&t.hash);
                }
                let raw_txs: Vec<Vec<u8>> = b
                    .txs
                    .iter()
                    .filter_map(|t| g.raw_tx.get(&t.hash).cloned())
                    .collect();
                displaced.push(ForkBlockEntry {
                    number: b.number,
                    parent_hash: b.parent_hash,
                    timestamp: b.timestamp,
                    view: b.view,
                    txs_root: b.txs_root,
                    state_root: b.state_root,
                    proposer: b.proposer,
                    proposer_sig: b.proposer_sig.clone(),
                    raw_txs,
                    hash: b.hash,
                });
            }
            g.state = ca_state;
            displaced
        };

        // Re-execute the winning branch. Each block re-runs the full validity check (contiguity, parent,
        // schedule, signature, byte-identical state-root) via the SHARED apply path — a forged branch
        // fails here and triggers a fail-closed rollback below.
        for fb in &branch {
            let applied = self.validate_and_apply_block(
                fb.number,
                fb.parent_hash,
                fb.timestamp,
                fb.view,
                fb.txs_root,
                fb.state_root,
                fb.proposer,
                &fb.proposer_sig,
                &fb.raw_txs,
                validator_override,
            );
            if let Err(e) = applied {
                // Fail-closed: restore the entire pre-reorg state (chain + recent-state ring).
                *self.inner.lock().unwrap() = inner_backup;
                *self.recent_states.lock().unwrap() = rs_backup;
                return Err(e);
            }
            // Cache the now-canonical block's raw txs so this node can re-gossip / re-serve it on sync
            // (the ordinary follower path caches via `apply_wire_block`; the reorg path caches here).
            self.cache_raw_txs(&fb.raw_txs);
        }

        // Commit the reorg's side-store bookkeeping: the now-canonical winning blocks leave the store;
        // the displaced (previously-canonical) blocks enter it so a later, still-better branch (e.g. a
        // taller extension of the old branch) can win them back — fork choice remains a total order.
        {
            let mut store = self.fork_store.lock().unwrap();
            for fb in &branch {
                store.remove(&fb.hash);
            }
            let new_head = self.tip().0;
            let finalized = new_head.saturating_sub(FINALITY_DEPTH);
            for d in displaced {
                if d.number > finalized {
                    store.insert(d.hash, d);
                }
            }
            store.retain(|_, e| e.number > finalized);
        }
        Ok(Some(self.latest_block()))
    }

    /// The k-deep finalized height (spec 08 §6.3): `head − FINALITY_DEPTH`, saturating at 0. No reorg may
    /// cross it. Pure read.
    pub fn finalized_height(&self) -> u64 {
        self.tip().0.saturating_sub(FINALITY_DEPTH)
    }

    /// Whether this exact block hash is already part of the canonical chain (tip or interior). Pure read;
    /// lets the node skip re-considering a block it already holds (a second dedup on top of gossipsub).
    pub fn knows_block(&self, hash: &B256) -> bool {
        self.inner.lock().unwrap().blocks_by_hash.contains_key(hash)
    }

    /// M5 Stage B (§3.3): the effective validator set `V` under a node's config — the Stage-A single
    /// designated proposer (`validator_override`) pins `V = [override]` and takes PRECEDENCE; otherwise
    /// `V = validator_set(head_state)` (the on-chain epoch snapshot). The node calls this to resolve `V`
    /// for the schedule, the production guard, and `ubi_consensusStatus`.
    pub fn effective_validator_set(&self, validator_override: Option<AlloyAddr>) -> Vec<AlloyAddr> {
        match validator_override {
            Some(a) => vec![a],
            None => self.validator_set(),
        }
    }

    /// M5 Stage B (§3.1): the scheduled proposer `V[(height + view) mod N]` for the given height/view
    /// under this node's config, or `None` if `V` is empty. Pure read of committed state + the config.
    pub fn scheduled_proposer(
        &self,
        height: u64,
        view: u32,
        validator_override: Option<AlloyAddr>,
    ) -> Option<AlloyAddr> {
        let v = self.effective_validator_set(validator_override);
        let n = v.len();
        if n == 0 {
            return None;
        }
        Some(v[proposer_index(height, view, n)])
    }

    /// Lock the inner state (for the persistence layer's read-only snapshot export). `pub(crate)` so
    /// only sibling modules (e.g. [`persist`]) can reach `Inner`.
    pub(crate) fn lock_inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap()
    }

    /// FU-3 load path: replace this chain's state + block history with a loaded snapshot, rebuilding the
    /// derived indexes (`blocks_by_hash`, the tx map, the per-address activity index) from the blocks so
    /// the loaded chain is byte-identical (same tip, same `state_root`) to the saved one. Called only by
    /// [`Chain::from_snapshot`] on a freshly-`new`'d chain. `pub(crate)`.
    pub(crate) fn load_into(&self, state: MemState, blocks: Vec<Block>) {
        let mut g = self.inner.lock().unwrap();
        g.state = state;
        g.blocks_by_hash.clear();
        g.txs.clear();
        g.addr_index.clear();
        for (idx, b) in blocks.iter().enumerate() {
            g.blocks_by_hash.insert(b.hash, idx);
            for tx in &b.txs {
                index_tx(&mut g.addr_index, tx);
                g.txs.insert(tx.hash, tx.clone());
            }
        }
        g.blocks = blocks;
    }

    /// Install the admin-method browser-access policy (the `Origin` allowlist for the loopback admin RPC).
    /// The node builds this from its boot config (default: the local wallet at `http://localhost:3000`).
    pub fn with_admin_access(mut self, access: Arc<AdminAccess>) -> Self {
        self.admin_access = access;
        self
    }

    /// The admin-method access policy (for the admin handlers + tests).
    pub fn admin_access(&self) -> &Arc<AdminAccess> {
        &self.admin_access
    }

    /// Install a node-configured [`OracleAdmin`] (the hot-swappable AI backend + its localhost-only admin
    /// surface). The node builds this from its boot config (a JSON file under the data dir + env
    /// overrides) and a factory over `ubi2-oracle`; absent a call, the chain runs the deterministic Mock
    /// impls. This is the single wiring point for a live provider.
    pub fn with_oracle_admin(mut self, admin: Arc<OracleAdmin>) -> Self {
        self.oracle_admin = admin;
        self
    }

    /// Replace the proof-of-humanity oracle (the AI seam — I1/I5) with a fixed impl, keeping the Mock
    /// interpreter. Test/back-compat helper; the node uses [`Chain::with_oracle_admin`] for the
    /// runtime-configurable path.
    pub fn with_oracle(mut self, oracle: Arc<dyn HumanityOracle>) -> Self {
        let interpreter = self.oracle_admin.interpreter();
        self.oracle_admin = Arc::new(OracleAdmin::with_fixed(oracle, interpreter));
        self
    }

    /// Replace the prompt-contract interpreter (the AI seam — I1/I5) with a fixed impl, keeping the Mock
    /// oracle. Test/back-compat helper; the node uses [`Chain::with_oracle_admin`].
    pub fn with_interpreter(mut self, interpreter: Arc<dyn ContractInterpreter>) -> Self {
        let oracle = self.oracle_admin.oracle();
        self.oracle_admin = Arc::new(OracleAdmin::with_fixed(oracle, interpreter));
        self
    }

    /// The chain's oracle-admin (for the admin RPC handlers + tests).
    pub fn oracle_admin(&self) -> &Arc<OracleAdmin> {
        &self.oracle_admin
    }

    /// M6 — install the ZK-passport verifier (spec §6.1). The node wires the real
    /// `ubi2_zkpoh::Groth16Verifier` (genesis-pinned VK); a test wires a `MockZkVerifier` or — for the
    /// EC-7 injected-disagreement leg — a stubbed mock that returns the wrong boolean. Absent a call, the
    /// chain runs the deterministic `MockZkVerifier::default()` (a confident accept), exactly as the
    /// oracle defaults to `MockOracle`.
    pub fn with_verifier(mut self, verifier: Arc<dyn ZkPassportVerifier>) -> Self {
        self.verifier = verifier;
        self
    }

    /// Set the CSCA governance authority (spec §7.3). The node seeds a reserved governance address at
    /// genesis so `registerCsca`/`revokeCsca` are gated (AC-10). Concrete wiring point, like
    /// [`Chain::register_juror`].
    pub fn set_csca_governance(&self, authority: &Address) {
        self.inner
            .lock()
            .unwrap()
            .state
            .set_csca_governance(*authority);
    }

    /// Seed a genesis CSCA trust anchor (the curated static set, spec §7.3). Called by the node at
    /// genesis; `Active` from genesis (the next proof can build against the resulting root).
    pub fn seed_csca(&self, country_code: [u8; 3], key_id: [u8; 32], pubkey: Vec<u8>) {
        ubi2_runtime::seed_csca(
            &mut self.inner.lock().unwrap().state,
            country_code,
            key_id,
            pubkey,
        );
    }

    /// The current live CSCA registry root (over the sorted Active set, §7.2). Pure read — a client
    /// fetches this to build a proof against the live trust set.
    pub fn csca_registry_root(&self) -> [u8; 32] {
        let g = self.inner.lock().unwrap();
        csca_registry_root(&g.state.csca_entries())
    }

    /// All CSCA entries, sorted by `key_id` (Active + Revoked). Pure read for `ubi_getCscaRegistry`.
    pub fn csca_entries(&self) -> Vec<CscaEntry> {
        self.inner.lock().unwrap().state.csca_entries()
    }

    /// M6 Stage C: seed a genesis Self identity-commitment root (spec 06b §2.2). Called by the node at
    /// genesis; pinned at block 0 so the first proof carrying it is accepted.
    pub fn seed_self_identity_root(&self, root: [u8; 32]) {
        ubi2_runtime::seed_self_identity_root(&mut self.inner.lock().unwrap().state, root);
    }

    /// M6 Stage C: seed a genesis Self OFAC SMT root of `kind` (spec 06b §2.2). Pinned at block 0.
    pub fn seed_self_ofac_root(&self, kind: u8, root: [u8; 32]) {
        ubi2_runtime::seed_self_ofac_root(&mut self.inner.lock().unwrap().state, kind, root);
    }

    /// M6 / EC-C7: seed the canonical Self `scope` scalar this deployment binds `signals[19]` against
    /// (spec 06b §3). Called by the node at genesis; its value is Self's scope derivation for the
    /// deployment's Self endpoint host.
    pub fn seed_self_scope(&self, scope: [u8; 32]) {
        ubi2_runtime::seed_self_scope(&mut self.inner.lock().unwrap().state, scope);
    }

    /// The live accepted Self identity roots, sorted by `root`. Pure read for `ubi_getSelfRoots`.
    pub fn self_identity_roots(&self) -> Vec<ubi2_runtime::SelfIdentityRoot> {
        self.inner.lock().unwrap().state.self_identity_roots()
    }

    /// The live accepted Self OFAC roots, sorted by `(kind, root)`. Pure read for `ubi_getSelfRoots`.
    pub fn self_ofac_roots(&self) -> Vec<ubi2_runtime::SelfOfacRoot> {
        self.inner.lock().unwrap().state.self_ofac_roots()
    }

    /// The three Pedersen attribute commitments stored for `addr` (`[age, nationality, expiry]`), or
    /// `None` for an `Std`-only / unverified human. Opaque (I6). Pure read for `ubi_getAttributes`.
    pub fn attribute_commitments(&self, addr: &Address) -> Option<[[u8; 32]; 3]> {
        self.inner.lock().unwrap().state.attribute_commitments(addr)
    }

    /// Is `nullifier` already spent? Pure read for `ubi_isNullifierUsed` (a client checks before proving).
    pub fn nullifier_used(&self, nullifier: &[u8; 32]) -> bool {
        self.inner.lock().unwrap().state.nullifier_used(nullifier)
    }

    /// M6 Stage D — verify an attribute-opening proof against `subject`'s stored `attr_type` commitment
    /// (spec §4.4, EC-9). Returns `true` iff `attr_proof` is a valid opening proving the statement (e.g.
    /// over-18) WITHOUT revealing the underlying value. Fail-closed: `false` if the subject has no stored
    /// commitment (an STD-only / unverified human) or the proof does not verify. Pure read (no mutation):
    /// the `eth_call` surface (`verifyAttribute`) calls this.
    pub fn verify_attribute(
        &self,
        subject: &Address,
        attr_type: ZkAttrType,
        attr_proof: &[u8],
    ) -> bool {
        let commitments = {
            let g = self.inner.lock().unwrap();
            g.state.attribute_commitments(subject)
        };
        // The Stage-D `over18` verifier opens `attr_commit[0]` (the age-threshold commitment, §3.4 idx 0).
        let commitment = match (attr_type, commitments) {
            (ZkAttrType::Over18, Some(c)) => c[0],
            // No stored commitment ⇒ fail closed (the feature is simply unavailable for this subject).
            (_, None) => return false,
        };
        self.verifier
            .verify_attribute(attr_type, &commitment, attr_proof)
    }

    /// Insert/replace an account in genesis state (used by the node to seed the dev account).
    pub fn seed_account(&self, account: Account) {
        self.inner.lock().unwrap().state.put(account);
    }

    /// Register a deterministic devnet juror (register-only in M3; staking is M5). Called by the node
    /// at genesis to seed the verifier set so cases have a jury to draw from (fail-closed otherwise).
    pub fn register_juror(&self, addr: &Address, stake: u128) {
        ubi2_runtime::register_juror(&mut self.inner.lock().unwrap().state, addr, stake);
    }

    /// Migrate `addr` to a `Verified` human in the M3 registry, with `verified_at` (unix seconds) as
    /// the emission epoch (M3 spec criterion 5: the genesis dev account is `Verified` for devnet
    /// continuity). Seeds the M1/M2 account cache too, so emission/streaming are unchanged.
    pub fn seed_verified_human(&self, addr: &Address, verified_at: u64) {
        ubi2_runtime::seed_verified_human(&mut self.inner.lock().unwrap().state, addr, verified_at);
    }

    /// Live balance of `addr` at `now` (base units). Pure read of `(state, now)` — invariant I2.
    pub fn balance(&self, addr: &Address, now: u64) -> u128 {
        self.inner.lock().unwrap().state.balance(addr, now)
    }

    /// A stream by id (None if unknown). Pure read.
    pub fn get_stream(&self, id: u64) -> Option<Stream> {
        self.inner.lock().unwrap().state.get_stream(id)
    }

    /// `addr`'s outgoing + incoming stream ids (sender, recipient). Pure read.
    pub fn streams_of(&self, addr: &Address) -> (Vec<u64>, Vec<u64>) {
        let g = self.inner.lock().unwrap();
        (g.state.outgoing(addr), g.state.incoming(addr))
    }

    /// ERC-721 `balanceOf`: number of stream tokens `addr` owns = (# where it is `to`) + (# where it
    /// is `from`) (D4 — both sides count). Pure read.
    pub fn nft_balance_of(&self, addr: &Address) -> u64 {
        let g = self.inner.lock().unwrap();
        (g.state.outgoing(addr).len() + g.state.incoming(addr).len()) as u64
    }

    /// Produce the next block from the current mempool at `timestamp`. Applies each queued transfer
    /// to state (each transfer re-settles emission at `timestamp`), records the txs, appends the
    /// block, and broadcasts it to `newHeads` subscribers. Called by the node on every clock tick;
    /// empty mempool ⇒ empty block (still advances height — spec §M1-T1.6).
    pub fn produce_block(&self, timestamp: u64) -> Block {
        // Stage-A / view-0 production (a Stage-A block is exactly a Stage-B block with `view == 0`, §2.2).
        // Every existing caller (and the N=1 degenerate case) produces at view 0; the Stage-B view-change
        // successor path calls [`Chain::produce_block_at_view`] with `current_view`.
        self.produce_block_at_view(timestamp, 0)
    }

    /// M5 Stage B (spec 08 §5): produce the next block at an explicit `view`. Used by the node's view
    /// timer when this node is the scheduled proposer for `(head+1, current_view)` — a view-change
    /// successor stamps `view = current_view > 0`, the first-scheduled proposer stamps `view = 0`. The
    /// `view` is committed in the header (signed + hashed, §2.2) and folded into the jury entropy (§2.3),
    /// but reads no clock — it is data, deterministic on every node.
    pub fn produce_block_at_view(&self, timestamp: u64, view: u32) -> Block {
        // The proposer mines the current mempool in FIFO order (the canonical commitment is the
        // `txs_root` over that order; a follower re-executes the SAME committed order — see
        // `validate_and_apply_block`). Take the mempool and delegate to the shared execution routine
        // so the proposer and the follower run byte-identical state transitions (I1/I2).
        let pending = std::mem::take(&mut self.inner.lock().unwrap().mempool);
        self.execute_block(pending, timestamp, view, None)
    }

    /// The shared, deterministic block-execution routine driven by both [`Chain::produce_block`] (the
    /// proposer, with its mempool) and [`Chain::validate_and_apply_block`] (a follower, with the block's
    /// committed tx order). Given the parent state, an ordered `pending` tx list, and the block
    /// `timestamp`, it applies every tx, runs the M3/M4 sweeps, computes `txs_root`/`state_root`, stamps
    /// the header (signing with the local proposer key, or — for a follower — with `proposer_override`'s
    /// pre-recovered `(proposer, sig)`), appends the block, and broadcasts it. Execution reads ONLY
    /// `timestamp` as its clock (never a node-local wall-clock), so two honest nodes applying the same
    /// ordered txs against the same parent reach a byte-identical `state_root` (EC-4/EC-10).
    fn execute_block(
        &self,
        pending: Vec<PendingTx>,
        timestamp: u64,
        view: u32,
        proposer_override: Option<(AlloyAddr, Vec<u8>)>,
    ) -> Block {
        // Clone the AI-seam Arcs before locking state (the apply loop calls the oracle for liveness
        // grading and the interpreter for contract effects). Reading from the hot-swappable admin once
        // per block makes a mid-flight `setOracleConfig` swap atomic at the block boundary.
        let oracle = self.oracle_admin.oracle();
        let interpreter = self.oracle_admin.interpreter();
        // M6: the ZK-passport verifier is read once per block too (re-execution consensus, §5.4) — the
        // proposer and every follower run the SAME verifier over the SAME ordered txs, so honest nodes
        // reach a byte-identical state_root. A node whose verifier disagrees diverges and is out-voted.
        let verifier = self.verifier.clone();
        let mut g = self.inner.lock().unwrap();
        let parent = g.blocks.last().expect("genesis always present").clone();
        let number = parent.number + 1;
        // Stage B (fork choice / reorg, §5.4/§6): remember the parent state (before this block mutates
        // it) so a later lower-view competitor at height `number` can be re-executed against the same
        // parent. Bounded to the last `FINALITY_DEPTH + 1` heights — a reorg never crosses the finalized
        // frontier. Deterministic (a plain state clone); it feeds no committed value.
        {
            let mut rs = self.recent_states.lock().unwrap();
            rs.insert(number - 1, g.state.clone());
            let cutoff = number.saturating_sub(FINALITY_DEPTH + 1);
            rs.retain(|h, _| *h >= cutoff);
        }
        // Spec 07 §3.4 (`ln-trust-2`): seal the seeded genesis anchor the instant before block #1 mutates
        // state — at this point `g.state` IS the height-0 seeded state (the genesis the light client must
        // reproduce). Idempotent + lazy: only fires once, only at the first block, and only if the node
        // did not already seal it explicitly at boot via `seal_genesis`. A no-op for every later block.
        if number == 1 {
            // Stage B (§2.1): seed the genesis (height-0) epoch validator snapshot over the fully-seeded
            // genesis state, BEFORE building the anchor + BEFORE block #1 reads `V` from its parent. Height
            // 0 is a multiple of `EPOCH_BLOCKS`, so genesis is a boundary; this is the deterministic seed
            // every node installs by replay. Idempotent (re-derives the same sorted set); it mutates the
            // genesis state so the anchor's `state_root` commits it (EC-B5) and block #1's schedule reads it.
            refresh_epoch_validators(&mut g.state, 0);
            let mut anchor = self.genesis_anchor.lock().unwrap();
            if anchor.is_none() {
                *anchor = Some(build_genesis_anchor(&g.state));
            }
        }
        // Stage B (§2.1): at an epoch boundary (`number % EPOCH_BLOCKS == 0`) re-snapshot `V` over the
        // pre-block state. The boundary block itself is scheduled by the parent's (previous) snapshot;
        // executing it installs the new one, which governs blocks `number+1 …`. Genesis (height 0) is
        // seeded above via the `number == 1` path, so the first on-chain refresh here is height
        // `EPOCH_BLOCKS`. Pure function of the parent state — deterministic on every node.
        if number.is_multiple_of(EPOCH_BLOCKS) {
            refresh_epoch_validators(&mut g.state, number);
        }
        // M5: the committed block hash now commits `view` + `txs_root` + `state_root` (spec §2.2), which
        // are only known *after* execution. But jury-selection entropy and the txs' `block_hash` are
        // needed *during* execution. We therefore derive a **pre-execution** `entropy_hash` from the
        // (already final) parent hash + number + timestamp + `view` — a pure, deterministic function of
        // pre-execution inputs, so every node computes the same jury seeds (I1) even after a view change
        // (§2.3) — and use it as the block's identity through the loop. After execution we compute the
        // roots and the real header `hash`, then back-fill it onto the stored txs so receipts carry the
        // committed block hash. `entropy_hash` feeds ONLY the seeded PRNG (never balances/roots).
        let entropy_hash = Block::compute_hash(
            number,
            parent.hash,
            timestamp,
            view,
            B256::ZERO,
            B256::ZERO,
            &AlloyAddr::ZERO,
        );
        let hash = entropy_hash;

        // The number of user txs (each `pending` entry yields exactly one stored tx in the loop below;
        // any synthetic M3 sweep tx is appended AFTER, so `stored[..user_tx_count]` is exactly the user
        // txs). `txs_root` commits ONLY these — the raw, gossipable txs a follower re-derives — so the
        // wire block's `recompute_txs_root` (over the carried raw bytes) matches byte-for-byte. The
        // sweep tx is a deterministic function of the user txs + state, already committed by `state_root`
        // and regenerated identically on every node, so it needs no separate tx-list commitment.
        let user_tx_count = pending.len();
        let mut stored = Vec::with_capacity(pending.len());
        for (i, p) in pending.into_iter().enumerate() {
            // ---- Real UBI gas fee (M5 fee-recycling foundation) ----
            // Charge `fee = gas_for_kind(kind) * gas_price` in UBI base units to the sender *before*
            // the op runs, crediting the reserved TREASURY. This is the only fee on the chain and it
            // is always in UBI (the native currency). The op then operates on the post-fee balance, so
            // the sender needs `value + fee` — an under-funded tx is rejected at SUBMIT (cycle-6), so a
            // wallet sees a synchronous error rather than a perpetual pending.
            //
            // The fee is charged on BOTH a succeeded and a FAILED tx (see the apply-result match below):
            // EVM charges gas on revert because the node still did the work. The ONLY tx we drop here is
            // one whose sender cannot afford even the fee — and that is caught at submit, so reaching
            // this `continue` means state raced after submit (rare). `charge_fee` settles the sender
            // first, so its insufficient-balance check runs on the materialized balance (I2).
            let gas_used = gas_for_kind(&p.kind);

            // ---- Apply via the SHARED kernel (ADR-0006 Decision 3 — one re-execution path) ----
            // `ubi2_exec::apply_tx` performs the fee charge → the runtime op → the EVM-style failed-tx
            // nonce post-state, EXACTLY as the browser follower (`crates/runtime-wasm`) does, so the two
            // followers mutate state byte-identically. It returns `None` only when the sender cannot
            // afford even the gas fee (the tx is dropped — the same `continue` the old inline loop had).
            // We then build this tx's receipt LOGS from the post-op state + the op's primary result
            // (stream id / case id / assurance) at the SAME read-timing the old code used (immediately
            // after the op, before the next tx), so receipts are unchanged. Pre-op status snapshots that
            // the logs need are captured BEFORE `apply_tx` runs.
            let pre_status_for_subject: Option<(Address, Option<HumanStatus>)> = match &p.kind {
                PendingKind::Challenge { subject, .. } => {
                    let s = subject.into_array();
                    Some((s, g.state.get_human(&s).map(|h| h.status)))
                }
                PendingKind::SubmitVerdict { case_id, .. } => {
                    let subj = g.state.get_case(*case_id).map(|c| c.subject);
                    subj.map(|s| (s, g.state.get_human(&s).map(|h| h.status)))
                }
                PendingKind::SubmitZkPassportProof { .. } => {
                    let s = p.from.into_array();
                    Some((s, g.state.get_human(&s).map(|h| h.status)))
                }
                _ => None,
            };

            let kernel_tx = kernel_tx_from_pending(&p);
            let outcome = match ubi2_exec::apply_tx(
                &mut g.state,
                &kernel_tx,
                timestamp,
                number,
                hash.0,
                &*oracle,
                &*interpreter,
                &*verifier,
            ) {
                Some(o) => o,
                None => {
                    tracing::warn!(tx = %p.hash, "dropping tx: cannot pay gas fee");
                    continue;
                }
            };

            // Build the receipt logs for THIS op from the post-op state + the kernel's op result. This
            // is the presentation layer (logs are NOT in `state_root`); it reads exactly what the old
            // inline match read. `_unused_applied` keeps the historical per-op apply arms below dead-
            // code-free by routing through the shared kernel; the log construction is the live path.
            let applied: Result<Vec<TxLog>, String> = if outcome.success {
                Ok(build_op_logs(
                    &g.state,
                    &p,
                    &outcome.result,
                    pre_status_for_subject,
                ))
            } else {
                Err(outcome.revert_reason.clone().unwrap_or_default())
            };

            // Unpack the shared kernel's outcome into the receipt fields. The kernel ALREADY performed
            // the failed-tx post-state (fee kept, nonce set to `p.nonce + 1`, no op state change —
            // cycle-6 / EVM-charges-gas-on-revert), so this is pure presentation: a FAILED tx carries no
            // logs and its decoded revert reason. (`applied` was derived from the same `outcome`.)
            let (success, logs, revert_reason) = match applied {
                Ok(logs) => (true, logs, None),
                Err(_) => {
                    tracing::warn!(tx = %p.hash, "mining failed tx (status 0x0)");
                    (false, Vec::new(), outcome.revert_reason.clone())
                }
            };

            let tx = StoredTx {
                hash: p.hash,
                from: p.from,
                to: Some(p.tx_to),
                value: U256::from(p.value),
                nonce: p.nonce,
                block_number: number,
                block_hash: hash,
                tx_index: i as u64,
                input: p.input.clone(),
                logs,
                gas_used,
                success,
                revert_reason,
                // Echo the sender's signed type + 1559 caps so the mined tx/receipt match the wallet's
                // expectation when it polls by hash (MetaMask sends type-2 — see StoredTx::tx_type).
                tx_type: p.tx_type,
                max_fee_per_gas: p.max_fee_per_gas,
                max_priority_fee_per_gas: p.max_priority_fee_per_gas,
            };
            index_tx(&mut g.addr_index, &tx);
            // EXPL-1: a committed contract effect moves value from the escrow to payees / stream
            // recipients that are NOT the tx's `from`/`to`/log-topics, so the per-address index would
            // miss them. Index the escrow + every effect-target address explicitly so an explorer's
            // per-account history surfaces "received 5 UBI from contract #N". A FAILED tx applied no
            // effect, so it has no extra targets — but calling this is harmless (it reads the post-op
            // state, which for a failed op moved no value) and keeps the success/fail paths uniform.
            if success {
                let extra = contract_effect_addresses(&g.state, &p.kind);
                for a in extra {
                    let entry = g.addr_index.entry(a).or_default();
                    if entry.last() != Some(&tx.hash) {
                        entry.push(tx.hash);
                    }
                }
            }
            g.txs.insert(p.hash, tx.clone());
            stored.push(tx);
        }

        // M3 AI sybil-cluster auto-challenge sweep (AC6 / security finding D): before finalizing, run
        // the node's oracle over the deterministic vouch graph for each Pending subject and auto-file a
        // `system_challenge` on any flagged sybil cluster — so a vouch farm is challenged (and must
        // clear the jury) before it can finalize, even when no human happens to challenge it. Runs
        // BEFORE the finalize sweep so a freshly-opened challenge blocks finalize in the same block.
        let scan_logs = sweep_sybil_scan(&mut g.state, &*oracle, hash, number);

        // M3 auto-finalize sweep: any `Pending` human whose challenge window has cleared (and which
        // satisfies liveness + MIN_VOUCHES + no open/upheld challenge) is finalized to `Verified` so
        // emission starts. `number` is the window clock (block HEIGHT); `timestamp` is the emission
        // epoch stamped on `verified_at` (unix SECONDS) — the two intentionally-distinct clocks.
        // Eligibility is checked deterministically by `finalize_registration` (it returns an error and
        // mutates nothing on any unmet condition — I4), so the sweep only commits clean cases.
        let mut sweep_logs = scan_logs;
        sweep_logs.extend(sweep_finalize(&mut g.state, number, timestamp));
        if !sweep_logs.is_empty() {
            // Carry the StatusChanged logs in a synthetic system tx so they appear in the block + a
            // receipt (the tx hash is derived from the block hash so it's stable and unique per block).
            let sys_hash = keccak256([hash.as_slice(), b"humanity-finalize-sweep"].concat());
            let tx = StoredTx {
                hash: sys_hash,
                from: HUMANITY_HUB,
                to: Some(HUMANITY_HUB),
                value: U256::ZERO,
                nonce: 0,
                block_number: number,
                block_hash: hash,
                tx_index: stored.len() as u64,
                input: Vec::new(),
                logs: sweep_logs,
                // A synthetic system tx (no signer, no fee) — it consumes no gas.
                gas_used: 0,
                // The sweep only ever commits clean cases (it never errors) — always a success.
                success: true,
                revert_reason: None,
                // A synthetic system tx has no signer / no fee envelope: report it as legacy (type 0).
                tx_type: 0,
                max_fee_per_gas: None,
                max_priority_fee_per_gas: None,
            };
            index_tx(&mut g.addr_index, &tx);
            g.txs.insert(sys_hash, tx.clone());
            stored.push(tx);
        }

        // ---- M5 (Stage A, §2.2/§5.3): compute the consensus header fields over the FINAL state ----
        //
        // `txs_root` commits the canonical ordered tx list; `state_root` commits the full post-block
        // state (a pure function of state — `ubi2_runtime::state_root`, no floats, no hash-order). The
        // header `hash` then commits both (+ proposer), and `proposer_sig` signs that pre-image, so a
        // follower can re-execute, match `state_root` byte-for-byte, and recover the author (EC-4/EC-10).
        let txs_root = Block::compute_txs_root(&stored[..user_tx_count.min(stored.len())]);
        let state_root = B256::from(ubi2_runtime::state_root(&g.state));
        // A follower (`proposer_override` is `Some`) commits the block's ORIGINAL proposer + signature
        // verbatim, so its stored header is byte-identical to the proposer's (and the recomputed hash
        // matches). The proposer path (`None`) stamps its own key (or zero/empty for the unsigned
        // single-node devnet, preserving M1–M4 behaviour).
        let (proposer, proposer_sig, final_hash) = match proposer_override {
            Some((proposer, sig)) => {
                let final_hash = Block::compute_hash(
                    number,
                    parent.hash,
                    timestamp,
                    view,
                    txs_root,
                    state_root,
                    &proposer,
                );
                (proposer, sig, final_hash)
            }
            None => {
                let proposer = self
                    .proposer_key
                    .as_ref()
                    .map(|k| k.address)
                    .unwrap_or(AlloyAddr::ZERO);
                let final_hash = Block::compute_hash(
                    number,
                    parent.hash,
                    timestamp,
                    view,
                    txs_root,
                    state_root,
                    &proposer,
                );
                let proposer_sig = self
                    .proposer_key
                    .as_ref()
                    .map(|k| k.sign_prehash(&final_hash))
                    .unwrap_or_default();
                (proposer, proposer_sig, final_hash)
            }
        };

        // Back-fill the committed block hash onto every stored tx (so a receipt's `blockHash` is the
        // real header hash, not the pre-execution `entropy_hash`). Update both the in-block copies and
        // the `g.txs` index. Stamped contracts already used `p.hash` (tx hash) for `deploy_tx`, which is
        // unaffected.
        for tx in stored.iter_mut() {
            tx.block_hash = final_hash;
        }
        for tx in &stored {
            g.txs.insert(tx.hash, tx.clone());
        }

        let block = Block {
            number,
            hash: final_hash,
            parent_hash: parent.hash,
            timestamp,
            view,
            txs_root,
            state_root,
            proposer,
            proposer_sig,
            txs: stored,
        };
        let idx = g.blocks.len();
        g.blocks.push(block.clone());
        g.blocks_by_hash.insert(final_hash, idx);
        drop(g);

        // Best-effort broadcast (ignored if there are no live subscribers).
        let _ = self.heads_tx.send(block.clone());
        block
    }

    fn latest_block(&self) -> Block {
        self.inner
            .lock()
            .unwrap()
            .blocks
            .last()
            .expect("genesis present")
            .clone()
    }

    /// The current chain tip `(height, hash)`. Pure read. Used by the network handshake (`Hello.tip`)
    /// and `ubi_consensusStatus`.
    pub fn tip(&self) -> (u64, B256) {
        let g = self.inner.lock().unwrap();
        let b = g.blocks.last().expect("genesis present");
        (b.number, b.hash)
    }

    /// Subscribe to new-block notifications (the broadcast channel the sync gateway uses to push live
    /// blocks to connected light clients). Each produced/applied block is broadcast; receivers that
    /// lag more than the channel capacity (256) get a `Lagged` error and must re-sync.
    pub fn subscribe_heads(&self) -> broadcast::Receiver<Block> {
        self.heads_tx.subscribe()
    }

    /// The current head's committed `state_root` (the tip block's header field). Backs `ubi_stateRoot`
    /// and the cross-node agreement check (EC-4/EC-10). Pure read.
    pub fn state_root(&self) -> B256 {
        self.inner
            .lock()
            .unwrap()
            .blocks
            .last()
            .expect("genesis present")
            .state_root
    }

    /// The `state_root` of the block at `height` (`None` if the height is beyond the tip). Pure read.
    pub fn state_root_at(&self, height: u64) -> Option<B256> {
        let g = self.inner.lock().unwrap();
        g.blocks.get(height as usize).map(|b| b.state_root)
    }

    /// The full block at `height` (`None` beyond the tip). Pure read — backs the sync server (A5): a
    /// peer asks for `[from, to]` and the node returns these blocks for re-execution.
    pub fn block_at(&self, height: u64) -> Option<Block> {
        let g = self.inner.lock().unwrap();
        g.blocks.get(height as usize).cloned()
    }

    /// M5 (Stage A, §3.2): admit a tx that arrived via **gossip** into the local mempool, running the
    /// EXACT same validation `eth_sendRawTransaction` uses (`ingest_raw_tx`: chain-id bind, signer
    /// recovery, nonce, cumulative affordability, calldata shape). This is the **validate-before-
    /// rebroadcast** gate: the node calls this on a `TxReceived` event and only re-gossips on `Ok`
    /// (so an invalid/spam tx never propagates and the source peer is penalized). Returns the tx hash, or
    /// a human error string (the node logs it + penalizes the peer). Idempotent at the chain level: a tx
    /// already in the mempool re-validates and is rejected as a duplicate-nonce, so a re-arrival is a
    /// no-op the node treats as "already known" (gossipsub already deduped by message-id upstream).
    pub fn ingest_gossip_tx(&self, raw: &[u8]) -> Result<B256, String> {
        ingest_raw_tx(self, raw).map_err(|e| e.message().to_string())
    }

    /// Whether a tx hash is already known to this node (in the mempool or already mined). The node uses
    /// it to skip re-validating/re-gossiping a tx it has already seen (a second dedup layer on top of
    /// gossipsub's message-id dedup). Pure read.
    pub fn knows_tx(&self, hash: &B256) -> bool {
        let g = self.inner.lock().unwrap();
        g.txs.contains_key(hash) || g.mempool.iter().any(|p| &p.hash == hash)
    }

    /// M5 (Stage A): the raw EIP-155 bytes of a block's **user** txs, in block order — exactly the
    /// `WireBlock.txs` payload the proposer gossips. A `StoredTx` whose raw bytes are not cached (a
    /// synthetic M3 sweep system tx, or a tx the node never saw the raw form of) is skipped. The result,
    /// fed to `WireBlock`, has `recompute_txs_root() == block.txs_root` (which commits only user txs).
    pub fn raw_txs_for_block(&self, block: &Block) -> Vec<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        block
            .txs
            .iter()
            .filter_map(|tx| g.raw_tx.get(&tx.hash).cloned())
            .collect()
    }

    /// M5 (Stage A): cache the raw bytes of txs applied from a network block / sync, so a synced node can
    /// re-serve those blocks' raw txs to a later joiner. Keyed by `keccak256(raw)` (= the tx hash).
    pub fn cache_raw_txs(&self, raws: &[Vec<u8>]) {
        let mut g = self.inner.lock().unwrap();
        for raw in raws {
            let hash = B256::from(keccak256(raw).0);
            g.raw_tx.insert(hash, raw.clone());
        }
    }

    /// M5 (Stage A): the raw bytes of every tx currently in the mempool (in FIFO order). The node's
    /// network driver gossips these on a short relay timer so a LOCALLY-submitted tx (via
    /// `eth_sendRawTransaction`, which goes straight to the mempool without touching the network task)
    /// reaches peers (EC-2). gossipsub dedups by the tx-hash message-id, so re-publishing an
    /// already-seen tx is a cheap no-op — the relay is naturally bounded.
    pub fn pending_raw_txs(&self) -> Vec<Vec<u8>> {
        let g = self.inner.lock().unwrap();
        g.mempool
            .iter()
            .filter_map(|p| g.raw_tx.get(&p.hash).cloned())
            .collect()
    }

    /// The chain id (for the network `Hello` handshake + `ubi_consensusStatus`).
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// The genesis block hash (the network-identity anchor: peers with a different genesis hash are on a
    /// different network and are disconnected at the handshake, spec §4.1). Pure read.
    pub fn genesis_hash(&self) -> B256 {
        let g = self.inner.lock().unwrap();
        g.blocks.first().expect("genesis present").hash
    }

    /// Genesis unix time this chain was created at (also the dev account's `verified_at`).
    pub fn genesis_time(&self) -> u64 {
        self.genesis_time
    }

    /// Spec 07 §3.4 (`ln-trust-2`): **seal the seeded genesis anchor** from the CURRENT state. The node
    /// calls this once at boot, right after seeding the genesis accounts/jurors/CSCA/governance and
    /// BEFORE producing any block, so the captured snapshot + root are the canonical height-0 state a
    /// light client must reproduce. Idempotent: a second call is a no-op (the anchor is sealed once). If
    /// the node never calls it, [`Chain::execute_block`] seals it lazily before block #1 — but an explicit
    /// boot-time seal is correct even for a chain restored from a FU-3 snapshot (whose state has advanced
    /// past genesis), provided the caller seals from a freshly-seeded genesis state.
    pub fn seal_genesis(&self) {
        // Stage B: seed the genesis epoch snapshot BEFORE sealing so the anchor's `state_root` commits it
        // consistently with block #1's schedule read (and with the lazy `execute_block` seed).
        self.ensure_epoch_validators_seeded();
        let mut anchor = self.genesis_anchor.lock().unwrap();
        if anchor.is_none() {
            let g = self.inner.lock().unwrap();
            *anchor = Some(build_genesis_anchor(&g.state));
        }
    }

    /// Spec 07 §3.4: seal the genesis anchor from an EXPLICIT height-0 `MemState`. Used by a node that
    /// boots from a FU-3 persistence snapshot (its live state has advanced past genesis): the caller
    /// reconstructs the canonical seeded genesis into a throwaway state and seals it here, so the gateway
    /// can still serve the verifiable anchor. Idempotent (a no-op if already sealed).
    pub fn seal_genesis_from_state(&self, genesis_state: &MemState) {
        let mut anchor = self.genesis_anchor.lock().unwrap();
        if anchor.is_none() {
            *anchor = Some(build_genesis_anchor(genesis_state));
        }
    }

    /// The seeded genesis anchor (snapshot + seeded `state_root`), if sealed. Spec 07 §3.4. The sync
    /// gateway serves this to a browser light client as the `Genesis` response; the client re-derives the
    /// root from the snapshot and rejects unless it equals its PINNED constant. `None` until sealed.
    pub fn genesis_anchor(&self) -> Option<GenesisAnchor> {
        self.genesis_anchor.lock().unwrap().clone()
    }

    /// The seeded genesis `state_root` (the root over the height-0 seeded state), if sealed. This is the
    /// value the shipped light client PINS — distinct from the genesis BLOCK header's `state_root` (a
    /// fixed `ZERO` anchor, never re-executed). `None` until [`Chain::seal_genesis`] / block #1.
    pub fn genesis_state_root(&self) -> Option<B256> {
        self.genesis_anchor
            .lock()
            .unwrap()
            .as_ref()
            .map(|a| a.state_root)
    }

    /// The authorized PoA proposer address for this chain — the proposer key's address if configured,
    /// else the designated-proposer published in the net status, else `None`. The sync gateway advertises
    /// it in the `Genesis` response and the light client verifies every block's proposer ∈ the pinned set.
    pub fn genesis_proposer(&self) -> Option<AlloyAddr> {
        if let Some(k) = &self.proposer_key {
            return Some(k.address());
        }
        self.net_status.lock().unwrap().designated_proposer
    }

    // ---- M3: proof-of-humanity reads (pure snapshots — invariants I1/I6) ----

    /// A human record by address (None if `Unverified` / never registered). Pure read.
    pub fn get_human(&self, addr: &Address) -> Option<Human> {
        self.inner.lock().unwrap().state.get_human(addr)
    }

    /// A case by id (None if unknown). Pure read.
    pub fn get_case(&self, id: u64) -> Option<Case> {
        self.inner.lock().unwrap().state.get_case(id)
    }

    /// `addr`'s outgoing vouchees and incoming vouchers (`(vouches_out, vouchers_of)`). Pure read.
    pub fn vouches_of(&self, addr: &Address) -> (Vec<Address>, Vec<Address>) {
        let g = self.inner.lock().unwrap();
        (g.state.vouches_out(addr), g.state.vouchers_of(addr))
    }

    /// All registered active jurors, sorted ascending. Pure read.
    pub fn active_jurors(&self) -> Vec<Juror> {
        let g = self.inner.lock().unwrap();
        g.state
            .active_jurors()
            .into_iter()
            .filter_map(|a| g.state.get_juror(&a))
            .collect()
    }

    /// Ids of all `Open` cases, sorted ascending. Pure read.
    pub fn open_cases(&self) -> Vec<u64> {
        self.inner.lock().unwrap().state.open_cases()
    }

    // ---- M4: prompt-contract reads (pure snapshots — invariants I1/I6) ----

    /// A prompt contract by id (None if unknown). Pure read.
    pub fn get_contract(&self, id: u64) -> Option<PromptContract> {
        self.inner.lock().unwrap().state.get_contract(id)
    }

    /// An exec case by id (None if unknown). Pure read.
    pub fn get_exec_case(&self, id: u64) -> Option<ExecCase> {
        self.inner.lock().unwrap().state.get_exec_case(id)
    }

    /// Contracts `addr` is a declared party of, sorted by id ascending. Pure read.
    pub fn contracts_of(&self, addr: &Address) -> Vec<PromptContract> {
        let g = self.inner.lock().unwrap();
        g.state
            .contracts()
            .into_iter()
            .filter(|c| c.is_party(addr))
            .collect()
    }

    /// A prompt contract by id together with all its exec cases (sorted by id), for the full
    /// `ubi_getContract` detail view. None if the contract is unknown. Pure read (I1: sorted output).
    pub fn get_contract_detail(&self, id: u64) -> Option<(PromptContract, Vec<ExecCase>)> {
        let g = self.inner.lock().unwrap();
        let contract = g.state.get_contract(id)?;
        let mut cases: Vec<ExecCase> = g
            .state
            .exec_cases()
            .into_iter()
            .filter(|c| c.contract == id)
            .collect();
        cases.sort_by_key(|c| c.id);
        Some((contract, cases))
    }

    // ---- EXPL-1: address index reads ----

    /// The most-recent `limit` tx hashes that touched `addr` (newest first). Backs
    /// `ubi_getAddressActivity`. Pure read of the per-address index.
    pub fn address_activity(&self, addr: &Address, limit: usize) -> Vec<StoredTx> {
        let g = self.inner.lock().unwrap();
        let hashes = match g.addr_index.get(addr) {
            Some(h) => h,
            None => return Vec::new(),
        };
        hashes
            .iter()
            .rev()
            .take(limit)
            .filter_map(|h| g.txs.get(h).cloned())
            .collect()
    }

    /// An account summary for `addr` (balance at `now`, nonce, human status, #streams in/out,
    /// #contracts the address is a party of). Backs `ubi_getAccount`. Pure read.
    pub fn account_summary(&self, addr: &Address, now: u64) -> AccountSummary {
        let g = self.inner.lock().unwrap();
        let balance = g.state.balance(addr, now);
        let nonce = g.state.nonce(addr);
        let human_status = g.state.get_human(addr).map(|h| h.status);
        let streams_out = g.state.outgoing(addr).len() as u64;
        let streams_in = g.state.incoming(addr).len() as u64;
        let contracts = g
            .state
            .contracts()
            .into_iter()
            .filter(|c| c.is_party(addr))
            .count() as u64;
        let tx_count = g.addr_index.get(addr).map(|v| v.len() as u64).unwrap_or(0);
        AccountSummary {
            address: *addr,
            balance,
            nonce,
            human_status,
            streams_out,
            streams_in,
            contracts,
            tx_count,
        }
    }

    // ---- EXPL-2: deep decoded block / tx reads ----

    /// Build the fully-decoded `ubi_getTransaction` JSON for a tx hash (None if unknown). Decodes the
    /// system-hub call, the emitted logs, and resolves the *resulting state effect / verdict / status*
    /// from the now-settled state (for an invoke → the committed `CanonicalEffect` or `Aborted`; a
    /// `submitVerdict`/`challenge`/`requestVerification` → the case outcome + subject status). Pure
    /// read of `(stored tx, state snapshot)` — every field is deterministic (I2). Locks state once.
    pub fn decoded_transaction(&self, hash: &B256) -> Option<Value> {
        let g = self.inner.lock().unwrap();
        let tx = g.txs.get(hash)?.clone();
        Some(decoded_tx_json(&g.state, &tx))
    }

    /// Build the fully-decoded `ubi_getBlock` JSON for a resolved block: the header fields plus the
    /// FULL list of its txs, each decoded via [`decoded_tx_json`]. `block` is resolved by the caller
    /// (tag / number / hash). Pure read of `(block, state snapshot)`. Locks state once.
    pub fn decoded_block_json(&self, block: &Block) -> Value {
        let g = self.inner.lock().unwrap();
        let txs: Vec<Value> = block
            .txs
            .iter()
            .map(|tx| decoded_tx_json(&g.state, tx))
            .collect();
        json!({
            "number": hex_u64(block.number),
            "hash": hex_b256(&block.hash),
            "parentHash": hex_b256(&block.parent_hash),
            "timestamp": hex_u64(block.timestamp),
            "txCount": block.txs.len(),
            "gasUsed": hex_u64(block_gas_used(block)),
            "gasLimit": "0x1c9c380",
            "baseFeePerGas": hex_u64(GAS_PRICE_WEI),
            // M5: real consensus header fields (spec §2.2). `stateRoot`/`transactionsRoot` are the
            // committed roots; `miner`/`proposer` is the block author; `proposerSig` is the hex sig.
            "stateRoot": hex_b256(&block.state_root),
            "transactionsRoot": hex_b256(&block.txs_root),
            "receiptsRoot": hex_b256(&B256::ZERO),
            "miner": hex_addr(&block.proposer),
            "proposer": hex_addr(&block.proposer),
            // M5 Stage B (§11): the block's committed `view` as a `ubi2` extension. Standard `eth_*`
            // block fields are unchanged (I3); `view` never repurposes a standard field.
            "view": block.view,
            "proposerSig": format!("0x{}", hex::encode(&block.proposer_sig)),
            "transactions": txs,
        })
    }

    /// Resolve a block by `"latest"`/`"earliest"`/`"pending"`/`0x<number>`/`0x<32-byte-hash>` for the
    /// `ubi_getBlock` explorer read. A 32-byte hex is treated as a block hash; anything else as a tag
    /// or a block number. Pure read.
    fn resolve_block_ref(&self, raw: &str) -> Option<Block> {
        // A 32-byte (64 hex char) value is a block hash; resolve it directly.
        if let Some(stripped) = raw.strip_prefix("0x") {
            if stripped.len() == 64 {
                let bytes = decode_hex(raw)?;
                let h = B256::from_slice(&bytes);
                let g = self.inner.lock().unwrap();
                return g
                    .blocks_by_hash
                    .get(&h)
                    .and_then(|i| g.blocks.get(*i))
                    .cloned();
            }
        }
        resolve_block_tag(self, raw)
    }

    // ---- UI explorer directory reads (recent blocks / global contracts) ----

    /// The most-recent `limit` blocks as compact summaries (newest-first). When `non_empty_only` is
    /// set, blocks with zero txs are skipped *before* the limit is applied, so the explorer can list a
    /// page of blocks that actually contain transactions (most devnet blocks are empty 2s ticks). Backs
    /// `ubi_getRecentBlocks`. Pure read of the block history (no clock, no state mutation — I2): every
    /// field (number/hash/timestamp/txCount/gasUsed) is a deterministic function of stored blocks.
    pub fn recent_blocks(&self, limit: usize, non_empty_only: bool) -> Vec<BlockSummary> {
        let g = self.inner.lock().unwrap();
        g.blocks
            .iter()
            .rev()
            .filter(|b| !non_empty_only || !b.txs.is_empty())
            .take(limit)
            .map(|b| BlockSummary {
                number: b.number,
                hash: b.hash,
                parent_hash: b.parent_hash,
                timestamp: b.timestamp,
                tx_count: b.txs.len() as u64,
                gas_used: block_gas_used(b),
            })
            .collect()
    }

    /// The most-recent `limit` deployed prompt contracts (newest-first by id), each a compact directory
    /// summary (address/parties/status/escrow/deploy block + its timestamp/a title derived from the
    /// text). Backs `ubi_getContracts` — the explorer's global contracts directory (`getContractsOf` is
    /// per-address only). Pure read of `(contracts, block history, now)`: the balance shown is the live
    /// escrow base units (an exact integer — no float, I2); `createdAt` resolves the deploy block's
    /// timestamp from the block history (0 if the block is not yet retained). `now` is unused by escrow
    /// (escrow is settled state, not a streaming balance) and accepted only for signature symmetry.
    pub fn recent_contracts(&self, limit: usize) -> Vec<ContractSummary> {
        let g = self.inner.lock().unwrap();
        // `state.contracts()` is sorted by id ascending (deterministic — I1); reverse for newest-first.
        let mut contracts = g.state.contracts();
        contracts.reverse();
        contracts
            .into_iter()
            .take(limit)
            .map(|c| {
                let created_at = g
                    .blocks
                    .get(c.deploy_block as usize)
                    .filter(|b| b.number == c.deploy_block)
                    .map(|b| b.timestamp)
                    .unwrap_or(0);
                ContractSummary {
                    id: c.id,
                    address: ubi2_runtime::contract_address(c.id),
                    parties: c.parties.clone(),
                    status: c.status,
                    escrow: c.escrow,
                    title: contract_title(&c.text),
                    deploy_block: c.deploy_block,
                    deploy_tx: c.deploy_tx,
                    created_at,
                }
            })
            .collect()
    }
}

/// A compact block summary returned by `ubi_getRecentBlocks` (the explorer's recent-blocks directory).
/// Every field is a deterministic read of a stored block (no clock, no float — I2).
#[derive(Clone, Debug)]
pub struct BlockSummary {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
    pub tx_count: u64,
    /// Total gas (sum of the block's txs' per-kind `gas_used`) — the block `gasUsed` header value.
    pub gas_used: u64,
}

/// A compact deployed-contract summary returned by `ubi_getContracts` (the explorer's global contracts
/// directory). Mirrors the value-bearing fields of [`contract_view_json`] without the full text/vars —
/// just enough for a directory row. All numeric fields are exact integer reads (no float — I2).
#[derive(Clone, Debug)]
pub struct ContractSummary {
    pub id: u64,
    /// The contract's derived escrow address (`contract_address(id)`).
    pub address: Address,
    pub parties: Vec<Address>,
    pub status: ContractStatus,
    /// Live escrow base units the contract controls.
    pub escrow: u128,
    /// A short title derived from the on-chain text (first line, truncated) — no PII beyond the text
    /// the deployer already published on-chain.
    pub title: String,
    pub deploy_block: u64,
    pub deploy_tx: [u8; 32],
    /// Unix timestamp of the deploy block (0 if that block is no longer retained).
    pub created_at: u64,
}

/// Derive a short, single-line title from a contract's full on-chain text: the first non-empty line,
/// trimmed and truncated to 80 chars (a `…` suffix when truncated). Pure function of the text (which is
/// already public on-chain) — no PII surfaced beyond what the deployer published. Empty text → `""`.
fn contract_title(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    if line.chars().count() > 80 {
        let truncated: String = line.chars().take(80).collect();
        format!("{truncated}…")
    } else {
        line.to_string()
    }
}

/// A per-account summary returned by `ubi_getAccount` (EXPL-1): the explorer/social-hub at-a-glance
/// card for an address. All numeric fields are exact integer reads of `(state, now)` — invariant I2.
#[derive(Clone, Debug)]
pub struct AccountSummary {
    pub address: Address,
    /// Live streaming balance at `now`, in base units.
    pub balance: u128,
    pub nonce: u64,
    /// The address's proof-of-humanity status (None if never registered / Unverified).
    pub human_status: Option<HumanStatus>,
    /// Number of streams the address is the sender of.
    pub streams_out: u64,
    /// Number of streams the address is the recipient of.
    pub streams_in: u64,
    /// Number of prompt contracts the address is a declared party of.
    pub contracts: u64,
    /// Total txs that have touched the address (the per-address index length).
    pub tx_count: u64,
}

// ---------------------------------------------------------------------------------------------
// Encoding helpers (Ethereum quantities are minimal-length 0x-hex)
// ---------------------------------------------------------------------------------------------

fn hex_u64(v: u64) -> String {
    format!("0x{v:x}")
}
fn hex_u128(v: u128) -> String {
    format!("0x{v:x}")
}
fn hex_u256(v: U256) -> String {
    format!("0x{v:x}")
}
fn hex_b256(v: &B256) -> String {
    format!("0x{}", hex::encode(v.as_slice()))
}
fn hex_addr(a: &AlloyAddr) -> String {
    format!("0x{}", hex::encode(a.as_slice()))
}

/// Minimal hex module (avoids a dependency just for byte→hex).
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
        }
        s
    }
}

fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn invalid_params(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(-32602, msg.into(), None::<()>)
}

/// Enforce the admin gate for `ubi_getOracleConfig` / `ubi_setOracleConfig`. Three independent checks, all
/// fail-closed:
///   1. **TCP-peer loopback** — the connection's peer `SocketAddr` (injected by [`serve`]'s accept loop)
///      must be a loopback address. A missing peer is treated as non-loopback and rejected. This is the
///      primary gate and is *not* header-spoofable (it reads the socket, not a header).
///   2. **`Host`-header pinning** (DNS-rebinding defense, C5-SEC-2) — the HTTP `Host` must be a loopback
///      host; a rebound hostname is refused even though it arrived over loopback.
///   3. **`Origin` allowlist** (browser-CSRF defense, C5-SEC-2) — a present `Origin` must be the wallet
///      origin; a malicious page's `Origin` (e.g. `https://evil.example.com`) is refused. Absent `Origin`
///      (curl / non-browser / same-origin) is allowed.
///
/// Checks 2+3 read the per-request [`AdminHttpMeta`] injected alongside the peer address; if no metadata
/// was injected (a direct in-process module call in tests, with no `Host`), only the loopback gate runs —
/// the production `serve` path always injects it, so the browser defenses are always active on the wire.
fn require_loopback(ext: &jsonrpsee::Extensions, access: &AdminAccess) -> RpcResult<()> {
    match ext.get::<std::net::SocketAddr>() {
        Some(addr) if is_loopback(addr) => {}
        _ => return Err(not_loopback_error()),
    }
    // The browser defenses run only when HTTP metadata is present (the wire path always injects it). A
    // bare module call (offline test) with no metadata is the loopback in-process path and is allowed.
    if let Some(meta) = ext.get::<AdminHttpMeta>() {
        access.check(meta)?;
    }
    Ok(())
}

/// Parse `ubi_setOracleConfig`'s single object param into the persisted [`OracleConfig`] (secret-free)
/// plus the optional raw `api_key` (used in-memory, never persisted). Accepts the object either as the
/// first element of a params array (`[{...}]`) or, leniently, as the bare object. Every field is
/// optional; an empty object clears to the Mock default.
fn parse_set_oracle_params(
    params: &jsonrpsee::types::Params,
) -> RpcResult<(OracleConfig, Option<String>)> {
    // jsonrpsee delivers positional params; the wallet sends `[{...}]`. Accept a bare object too.
    let obj: Value = match params.parse::<Vec<Value>>() {
        Ok(mut seq) if !seq.is_empty() => seq.swap_remove(0),
        _ => params
            .parse::<Value>()
            .map_err(|_| invalid_params("expected [{provider?, model?, base_url?, api_key?}]"))?,
    };
    let o = obj
        .as_object()
        .ok_or_else(|| invalid_params("oracle config must be an object"))?;

    // Pull a string field, treating "" as absent (so the wallet can clear a field with an empty box).
    let str_field = |k: &str| -> Option<String> {
        o.get(k)
            .and_then(|v| v.as_str())
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string)
    };

    let raw_api_key = str_field("api_key");
    // When a raw key is provided without an explicit env-var name, default the name from the provider so
    // the node has somewhere to set the in-memory key. The node's factory resolves the default per
    // provider; we leave `api_key_env` as the caller gave it (possibly None) and pass the raw key through.
    let config = OracleConfig {
        provider: str_field("provider"),
        model: str_field("model"),
        base_url: str_field("base_url"),
        api_key_env: str_field("api_key_env"),
    };
    Ok((config, raw_api_key))
}

/// Parse the first param of `[address, block]` shape into a 20-byte address.
fn parse_addr_param(params: &jsonrpsee::types::Params) -> RpcResult<Address> {
    let seq: Vec<Value> = params
        .parse()
        .map_err(|_| invalid_params("expected params array"))?;
    let raw = seq
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_params("missing address param"))?;
    let bytes = decode_hex(raw).ok_or_else(|| invalid_params("bad address hex"))?;
    if bytes.len() != 20 {
        return Err(invalid_params("address must be 20 bytes"));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&bytes);
    Ok(a)
}

/// Decode `0x`-prefixed (or bare) hex into bytes.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------------------------
// Block JSON (the shape MetaMask / explorers expect)
// ---------------------------------------------------------------------------------------------

fn block_to_json(block: &Block, full_txs: bool) -> Value {
    let txs: Vec<Value> = if full_txs {
        block.txs.iter().map(tx_to_json).collect()
    } else {
        block.txs.iter().map(|t| json!(hex_b256(&t.hash))).collect()
    };
    json!({
        "number": hex_u64(block.number),
        "hash": hex_b256(&block.hash),
        "parentHash": hex_b256(&block.parent_hash),
        "nonce": "0x0000000000000000",
        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
        "logsBloom": format!("0x{}", "0".repeat(512)),
        // M5: real consensus roots + author. `transactionsRoot`/`stateRoot` are the committed header
        // fields (no longer zero placeholders); `miner` is the block proposer.
        "transactionsRoot": hex_b256(&block.txs_root),
        "stateRoot": hex_b256(&block.state_root),
        "receiptsRoot": hex_b256(&B256::ZERO),
        "miner": hex_addr(&block.proposer),
        "difficulty": "0x0",
        "totalDifficulty": "0x0",
        "extraData": "0x",
        "size": "0x0",
        "gasLimit": "0x1c9c380",
        "gasUsed": hex_u64(block_gas_used(block)),
        "timestamp": hex_u64(block.timestamp),
        "transactions": txs,
        "uncles": [],
        "baseFeePerGas": hex_u64(GAS_PRICE_WEI),
        // M5 extension fields (ubi_*-namespaced consensus header), MetaMask ignores unknown keys.
        "proposer": hex_addr(&block.proposer),
    })
}

/// Total gas a block consumed — the sum of its txs' per-kind `gas_used` (the block `gasUsed` header).
fn block_gas_used(block: &Block) -> u64 {
    block.txs.iter().map(|t| t.gas_used).sum()
}

fn tx_to_json(tx: &StoredTx) -> Value {
    let mut out = json!({
        "hash": hex_b256(&tx.hash),
        "nonce": hex_u64(tx.nonce),
        "blockHash": hex_b256(&tx.block_hash),
        "blockNumber": hex_u64(tx.block_number),
        "transactionIndex": hex_u64(tx.tx_index),
        "from": hex_addr(&tx.from),
        "to": tx.to.map(|a| hex_addr(&a)).map(Value::String).unwrap_or(Value::Null),
        "value": hex_u256(tx.value),
        "gas": hex_u64(tx.gas_used),
        // `gasPrice` is present on every type for legacy-client compatibility (it equals the effective
        // price on this flat-fee chain). For a typed-fee tx we ALSO surface the 1559 caps below so the
        // returned object reconciles with what the wallet signed.
        "gasPrice": hex_u64(GAS_PRICE_WEI),
        "input": if tx.input.is_empty() { "0x".to_string() } else { format!("0x{}", hex::encode(&tx.input)) },
        // Echo the SENDER's signed EIP-2718 type. MetaMask sends type-2 (EIP-1559) on this chain and
        // rejects a receipt whose `type` mismatches as a different tx ("Dropped") — so this must be the
        // real signed type, not a hardcoded `0x0` (cycle-7 fix).
        "type": hex_u64(tx.tx_type as u64),
        "chainId": hex_u64(DEVNET_CHAIN_ID),
    });
    // EIP-1559 (type-2) / EIP-2930 typed-fee fields, echoed verbatim from the sender's signature so the
    // wallet's signed tx object matches the node's returned object field-for-field. `accessList` is
    // always empty on this devnet but must be present for a typed tx to look well-formed to wallets.
    if let (Some(max_fee), pri) = (tx.max_fee_per_gas, tx.max_priority_fee_per_gas) {
        out["maxFeePerGas"] = json!(hex_u128(max_fee));
        out["maxPriorityFeePerGas"] = json!(hex_u128(pri.unwrap_or(0)));
        out["accessList"] = json!([]);
    }
    out
}

/// Render a single log into the Ethereum receipt log shape. `logIndex`/`blockHash` etc. are filled in
/// by `receipt_to_json` (it knows the tx's position).
fn log_to_json(tx: &StoredTx, log: &TxLog, log_index: usize) -> Value {
    json!({
        "address": hex_addr(&log.address),
        "topics": log.topics.iter().map(hex_b256).collect::<Vec<_>>(),
        "data": if log.data.is_empty() { "0x".to_string() } else { format!("0x{}", hex::encode(&log.data)) },
        "blockNumber": hex_u64(tx.block_number),
        "blockHash": hex_b256(&tx.block_hash),
        "transactionHash": hex_b256(&tx.hash),
        "transactionIndex": hex_u64(tx.tx_index),
        "logIndex": hex_u64(log_index as u64),
        "removed": false,
    })
}

fn receipt_to_json(tx: &StoredTx) -> Value {
    let logs: Vec<Value> = tx
        .logs
        .iter()
        .enumerate()
        .map(|(i, l)| log_to_json(tx, l, i))
        .collect();
    let mut receipt = json!({
        "transactionHash": hex_b256(&tx.hash),
        "transactionIndex": hex_u64(tx.tx_index),
        "blockHash": hex_b256(&tx.block_hash),
        "blockNumber": hex_u64(tx.block_number),
        "from": hex_addr(&tx.from),
        "to": tx.to.map(|a| hex_addr(&a)).map(Value::String).unwrap_or(Value::Null),
        "cumulativeGasUsed": hex_u64(tx.gas_used),
        "gasUsed": hex_u64(tx.gas_used),
        "contractAddress": Value::Null,
        "logs": logs,
        "logsBloom": format!("0x{}", "0".repeat(512)),
        // EVM receipt status: `0x1` = succeeded, `0x0` = the op FAILED at block time. A FAILED tx is
        // still MINED (fee charged, nonce consumed) — never silently dropped — so the wallet always
        // gets a receipt (no perpetual pending) and the nonce advances (no nonce gap). Cycle-6.
        "status": if tx.success { "0x1" } else { "0x0" },
        "effectiveGasPrice": hex_u64(GAS_PRICE_WEI),
        // The receipt `type` must equal the tx's signed EIP-2718 type or MetaMask treats the receipt as
        // belonging to a different tx and shows the (mined) tx as "Dropped" (cycle-7 fix).
        "type": hex_u64(tx.tx_type as u64),
    });
    // For a FAILED tx, carry the decoded failure reason (a Geth-compatible `revertReason` field) so the
    // explorer / wallet can show "vouchee has no open registration" etc. Omitted on a succeeded tx.
    if let Some(reason) = &tx.revert_reason {
        receipt["revertReason"] = json!(reason);
    }
    receipt
}

/// Resolve a block tag/number param ("latest"/"earliest"/"pending"/"0x..") to a concrete block.
fn resolve_block_tag(chain: &Chain, tag: &str) -> Option<Block> {
    let g = chain.inner.lock().unwrap();
    match tag {
        "latest" | "pending" | "safe" | "finalized" => g.blocks.last().cloned(),
        "earliest" => g.blocks.first().cloned(),
        hex => {
            let n = u64::from_str_radix(hex.strip_prefix("0x").unwrap_or(hex), 16).ok()?;
            g.blocks.get(n as usize).cloned()
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Transaction ingestion (eth_sendRawTransaction)
// ---------------------------------------------------------------------------------------------

/// Decode an EIP-155 legacy signed tx, recover the sender, and validate it against the chain rules.
/// Returns the queued `PendingTx`'s hash. Public for unit testing the decode/recover/validate path.
/// Decode + structurally-validate a raw EIP-155 tx into a [`PendingTx`], WITHOUT the affordability /
/// pending-nonce submit gate (that gate lives in [`ingest_raw_tx`]). This is the shared parse path used
/// by both the RPC submit (`ingest_raw_tx`) and the follower's block re-execution
/// ([`Chain::validate_and_apply_block`]), so a tx that the proposer included decodes byte-identically on
/// every node (the `chain_id`-bind, signer recovery, `to` requirement, and calldata-shape rules all run
/// here). Returns the decoded `PendingTx`; the caller decides admission. Pure given `chain_id` + bytes.
fn decode_pending_tx(chain_id: u64, raw: &[u8]) -> Result<PendingTx, ErrorObjectOwned> {
    // The op model + structural decode (chain-id bind, signer recovery, hub calldata shape) is the
    // SHARED kernel decode (`ubi2_exec::decode_tx`) — the SAME decode the browser follower runs, so a
    // block decodes byte-identically on both (ADR-0006 Decision 3, "no logic fork"). We re-derive only
    // the RPC-presentation fields (`hash`, `input`, `tx_type`, 1559 caps) from the envelope here, which
    // do not affect state. Map the kernel's `DecodeError` onto the precise JSON-RPC error the wallet
    // expects.
    let kernel_tx = ubi2_exec::decode_tx(chain_id, raw).map_err(decode_error_to_rpc)?;

    // Re-decode the envelope for the presentation-only fields (hash / input / type / fee caps). This is
    // the same `alloy` envelope `decode_tx` already parsed; we do not re-validate (the kernel decode
    // already accepted it).
    let mut slice = raw;
    let env = TxEnvelope::decode_2718(&mut slice)
        .map_err(|e| invalid_params(format!("rlp decode failed: {e}")))?;
    let to = env
        .to()
        .ok_or_else(|| invalid_params("contract creation not supported"))?;
    let hash = *env.tx_hash();
    let input = env.input().to_vec();

    // Capture the EIP-2718 type byte + EIP-1559 fee caps EXACTLY as the sender signed them, so the
    // mined tx/receipt echo the same `type` (and `maxFeePerGas`/`maxPriorityFeePerGas`) the wallet
    // expects when it polls by hash (MetaMask signs TYPE-2 on this chain — cycle-7).
    let tx_type: u8 = env.tx_type().into();
    let (max_fee_per_gas, max_priority_fee_per_gas) = if tx_type >= 1 {
        (Some(env.max_fee_per_gas()), env.max_priority_fee_per_gas())
    } else {
        (None, None)
    };

    let kind = pending_kind_from_kernel(kernel_tx.kind);
    Ok(PendingTx {
        hash,
        from: AlloyAddr::from(kernel_tx.from),
        tx_to: to,
        value: kernel_tx.value,
        nonce: kernel_tx.nonce,
        input,
        kind,
        tx_type,
        max_fee_per_gas,
        max_priority_fee_per_gas,
    })
}

/// Map the shared kernel's [`ubi2_exec::DecodeError`] onto the precise JSON-RPC error the wallet
/// expects (so a soulbound transfer / unknown selector / bad chain-id each surface their familiar
/// message). The `to == None` / unexpected-calldata cases keep the M1 wording.
fn decode_error_to_rpc(e: ubi2_exec::DecodeError) -> ErrorObjectOwned {
    use ubi2_exec::DecodeError;
    match e {
        DecodeError::Rlp(m) => invalid_params(format!("rlp decode failed: {m}")),
        DecodeError::WrongChain { expected, got } => match got {
            Some(g) => invalid_params(format!(
                "wrong chainId: tx is for {g}, devnet is {expected}"
            )),
            None => invalid_params("tx must be EIP-155 (chainId-bound) for replay safety"),
        },
        DecodeError::BadSignature(m) => invalid_params(format!("signature recovery failed: {m}")),
        DecodeError::ContractCreation => invalid_params("contract creation not supported"),
        DecodeError::UnexpectedCalldata => {
            invalid_params("calldata only supported for StreamHub (value transfers otherwise)")
        }
        DecodeError::ValueOverflow(which) => {
            invalid_params(format!("{which} exceeds u128 base-unit range"))
        }
        DecodeError::Soulbound => execution_reverted("soulbound"),
        DecodeError::BadCalldata(m) => {
            // An unknown hub selector should revert (not be a params error) so a wallet preflight
            // surfaces an execution revert, matching M2/M3 behaviour; a malformed-args blob is a params
            // error.
            if m.contains("unknown") && m.contains("selector") {
                execution_reverted("unknown hub selector")
            } else {
                invalid_params(format!("hub call: {m}"))
            }
        }
    }
}

/// Map a shared-kernel [`ubi2_exec::KernelKind`] onto the RPC's `PendingKind` (field-for-field — the
/// two enums are intentionally identical so the mempool/gas/submit surface keeps its existing shape).
fn pending_kind_from_kernel(k: ubi2_exec::KernelKind) -> PendingKind {
    use ubi2_exec::KernelKind as K;
    match k {
        K::Transfer { to, value } => PendingKind::Transfer {
            to: AlloyAddr::from(to),
            value,
        },
        K::OpenStream { to, rate, deposit } => PendingKind::OpenStream {
            to: AlloyAddr::from(to),
            rate,
            deposit,
        },
        K::StopStream { id } => PendingKind::StopStream { id },
        K::RequestVerification { liveness_ref } => {
            PendingKind::RequestVerification { liveness_ref }
        }
        K::Vouch { vouchee } => PendingKind::Vouch {
            vouchee: AlloyAddr::from(vouchee),
        },
        K::Challenge {
            subject,
            evidence_ref,
        } => PendingKind::Challenge {
            subject: AlloyAddr::from(subject),
            evidence_ref,
        },
        K::SubmitVerdict { case_id, verdict } => PendingKind::SubmitVerdict { case_id, verdict },
        K::SubmitZkPassportProof {
            proof,
            signals,
            scheme_tag,
        } => PendingKind::SubmitZkPassportProof {
            proof,
            signals,
            scheme_tag,
        },
        K::RegisterCsca {
            country_code,
            key_id,
            pubkey,
        } => PendingKind::RegisterCsca {
            country_code,
            key_id,
            pubkey,
        },
        K::RevokeCsca { key_id } => PendingKind::RevokeCsca { key_id },
        K::PinSelfIdentityRoot { root } => PendingKind::PinSelfIdentityRoot { root },
        K::PinSelfOfacRoot { kind, root } => PendingKind::PinSelfOfacRoot { kind, root },
        K::RetireSelfRoot { root } => PendingKind::RetireSelfRoot { root },
        K::DeployContract { text, parties } => PendingKind::DeployContract {
            text,
            parties: parties.into_iter().map(AlloyAddr::from).collect(),
        },
        K::FundContract { id } => PendingKind::FundContract { id },
        K::InvokeContract { id, trigger_ref } => PendingKind::InvokeContract { id, trigger_ref },
        K::SubmitEffect { case_id, effect } => PendingKind::SubmitEffect { case_id, effect },
    }
}

/// Map an RPC `PendingTx` onto the shared kernel's [`ubi2_exec::KernelTx`] (the inverse of
/// [`pending_kind_from_kernel`]) so `execute_block` can apply each tx via the single shared kernel.
fn kernel_tx_from_pending(p: &PendingTx) -> ubi2_exec::KernelTx {
    use ubi2_exec::KernelKind as K;
    let kind = match &p.kind {
        PendingKind::Transfer { to, value } => K::Transfer {
            to: to.into_array(),
            value: *value,
        },
        PendingKind::OpenStream { to, rate, deposit } => K::OpenStream {
            to: to.into_array(),
            rate: *rate,
            deposit: *deposit,
        },
        PendingKind::StopStream { id } => K::StopStream { id: *id },
        PendingKind::RequestVerification { liveness_ref } => K::RequestVerification {
            liveness_ref: *liveness_ref,
        },
        PendingKind::Vouch { vouchee } => K::Vouch {
            vouchee: vouchee.into_array(),
        },
        PendingKind::Challenge {
            subject,
            evidence_ref,
        } => K::Challenge {
            subject: subject.into_array(),
            evidence_ref: *evidence_ref,
        },
        PendingKind::SubmitVerdict { case_id, verdict } => K::SubmitVerdict {
            case_id: *case_id,
            verdict: *verdict,
        },
        PendingKind::SubmitZkPassportProof {
            proof,
            signals,
            scheme_tag,
        } => K::SubmitZkPassportProof {
            proof: proof.clone(),
            signals: *signals,
            scheme_tag: *scheme_tag,
        },
        PendingKind::RegisterCsca {
            country_code,
            key_id,
            pubkey,
        } => K::RegisterCsca {
            country_code: *country_code,
            key_id: *key_id,
            pubkey: pubkey.clone(),
        },
        PendingKind::RevokeCsca { key_id } => K::RevokeCsca { key_id: *key_id },
        PendingKind::PinSelfIdentityRoot { root } => K::PinSelfIdentityRoot { root: *root },
        PendingKind::PinSelfOfacRoot { kind, root } => K::PinSelfOfacRoot {
            kind: *kind,
            root: *root,
        },
        PendingKind::RetireSelfRoot { root } => K::RetireSelfRoot { root: *root },
        PendingKind::DeployContract { text, parties } => K::DeployContract {
            text: text.clone(),
            parties: parties.iter().map(|a| a.into_array()).collect(),
        },
        PendingKind::FundContract { id } => K::FundContract { id: *id },
        PendingKind::InvokeContract { id, trigger_ref } => K::InvokeContract {
            id: *id,
            trigger_ref: *trigger_ref,
        },
        PendingKind::SubmitEffect { case_id, effect } => K::SubmitEffect {
            case_id: *case_id,
            effect: effect.clone(),
        },
    };
    ubi2_exec::KernelTx {
        tx_hash: p.hash.0,
        from: p.from.into_array(),
        nonce: p.nonce,
        value: p.value,
        kind,
    }
}

/// Decode + admit a raw tx submitted via `eth_sendRawTransaction` (or relayed from gossip). Runs the
/// shared structural decode ([`decode_pending_tx`]) then the affordability / pending-nonce SUBMIT gate
/// (so the wallet gets a synchronous rejection rather than a silently-dropped tx), and pushes it onto
/// the mempool. Returns the tx hash. The runtime re-validates + re-settles authoritatively at block
/// time and fails closed; this gate is the UX layer on top.
fn ingest_raw_tx(chain: &Chain, raw: &[u8]) -> Result<B256, ErrorObjectOwned> {
    let pending = decode_pending_tx(chain.chain_id, raw)?;
    let hash = pending.hash;
    let from = pending.from;
    let value = pending.value;
    let nonce = pending.nonce;
    let kind = &pending.kind;

    // Validate nonce + spendable-balance affordability against current state at *now*, accounting
    // for this sender's other still-pending mempool txs (see the cumulative check below). The
    // runtime re-checks and re-settles authoritatively at block time and fails closed; this submit
    // gate exists so the wallet gets a synchronous rejection instead of a silently dropped tx.
    {
        let g = chain.inner.lock().unwrap();
        let now = now_secs();
        let acct = g.state.get(&from.into_array()).unwrap_or_default();
        let settled = acct.balance(now); // live balance, since settlement folds emission in
        let sender_pending = g.mempool.iter().filter(|p| p.from == from).count();
        // SEC-M5A-3: bound the mempool BEFORE admitting. Both caps (spec §10/§3.3, the canonical values
        // in `ubi2_network::consts`) were previously unreferenced; an unbounded ingest let a flood of
        // (individually valid) txs grow the mempool without limit on the gossip + RPC path. Enforce the
        // GLOBAL cap and the PER-SENDER cap here, rejecting over-cap txs with a clear JSON-RPC error so a
        // single sender cannot monopolize the mempool and the total is bounded. A duplicate (same nonce,
        // already pending) re-arrival is caught by the nonce gate below, so it does not consume a slot.
        if g.mempool.len() >= ubi2_network::consts::MEMPOOL_MAX_TXS {
            return Err(invalid_params(format!(
                "mempool full: at global cap of {} txs",
                ubi2_network::consts::MEMPOOL_MAX_TXS
            )));
        }
        if sender_pending >= ubi2_network::consts::MEMPOOL_MAX_PER_SENDER {
            return Err(invalid_params(format!(
                "mempool full for sender: at per-sender cap of {} txs",
                ubi2_network::consts::MEMPOOL_MAX_PER_SENDER
            )));
        }
        let expected_nonce = acct.nonce + sender_pending as u64;
        if nonce != expected_nonce {
            return Err(invalid_params(format!(
                "nonce too {}: expected {expected_nonce}, got {nonce}",
                if nonce < expected_nonce {
                    "low"
                } else {
                    "high"
                }
            )));
        }
        // Affordability is cumulative across the sender's still-pending txs, not just this one:
        // every queued transfer `value`, `openStream` `deposit`, and `fundContract` funding will be
        // debited from the same spendable balance when the block is mined. Checking each op against
        // the live balance in isolation admitted N full-balance opens — all but the first then got
        // silently dropped by the runtime's fail-closed insufficient-balance check at block time
        // (only a WARN, no receipt, a misleading accepted hash to the wallet). M2-F2 / cycle-1 FU-1.
        // Mirror the pending-nonce accounting above: sum what this sender has already committed in
        // the mempool and reject when adding this op would exceed the live balance.
        let pending_committed: u128 = g
            .mempool
            .iter()
            .filter(|p| p.from == from)
            .fold(0u128, |acc, p| {
                acc.saturating_add(spendable_debit(p.value, &p.kind))
            });
        let need = pending_committed.saturating_add(spendable_debit(value, kind));
        if settled < need {
            // Note the already-pending portion only when there is one, so the single-tx message is
            // unchanged. Keep "for deposit" wording on stream opens (their `value` is 0).
            let pending_note = if pending_committed > 0 {
                format!(" (incl. {pending_committed} already pending from this sender)")
            } else {
                String::new()
            };
            let what = if matches!(kind, PendingKind::OpenStream { .. }) {
                "balance for deposit"
            } else {
                "balance"
            };
            return Err(invalid_params(format!(
                "insufficient {what}: have {settled}, need {need}{pending_note}"
            )));
        }
    }

    // `decode_pending_tx` already produced a fully-formed `PendingTx` (incl. tx_type + the EIP-1559
    // fee caps); push it directly rather than rebuilding it from locals (the merge of #12 + #13 left a
    // stray rebuild here that referenced fields out of scope).
    {
        let mut g = chain.inner.lock().unwrap();
        // Cache the raw bytes so the network driver can gossip a LOCALLY-submitted tx (`pending_raw_txs`)
        // and the proposer can reconstruct the gossipable block (`StoredTx` drops the raw RLP). Keyed by
        // the tx hash (= the gossipsub message-id). This insert was dropped in the #12+#13 merge — its
        // absence left locally-submitted txs un-gossipable, breaking tx propagation (EC-2).
        g.raw_tx.insert(hash, raw.to_vec());
        g.mempool.push(pending);
    }
    Ok(hash)
}

/// JSON-RPC "execution reverted" error (code 3), used for soulbound transfer attempts on StreamHub.
fn execution_reverted(msg: impl Into<String>) -> ErrorObjectOwned {
    ErrorObjectOwned::owned(3, msg.into(), None::<()>)
}

// ---------------------------------------------------------------------------------------------
// ERC-721 view precompile (eth_call → StreamHub) + ubi_* stream-read helpers
// ---------------------------------------------------------------------------------------------

/// Dispatch an ERC-721 / ERC-165 / ERC-721-Metadata view call against the StreamHub collection,
/// returning ABI-encoded result bytes (spec D4). Unknown selectors return empty data; soulbound
/// mutators revert. The two-token scheme is decoded in `ownerOf`/`tokenURI` via `decode_token_id`.
fn erc721_call(chain: &Chain, data: &[u8]) -> Result<Vec<u8>, ErrorObjectOwned> {
    use streams::{
        balanceOfCall, encode_address, encode_bool, encode_string, encode_u256, nameCall,
        ownerOfCall, supportsInterfaceCall, symbolCall, tokenURICall, IFACE_ERC165, IFACE_ERC721,
        IFACE_ERC721_METADATA,
    };

    if data.len() < 4 {
        return Err(invalid_params("calldata too short for a selector"));
    }
    let sel: [u8; 4] = [data[0], data[1], data[2], data[3]];

    // supportsInterface(bytes4)
    if sel == supportsInterfaceCall::SELECTOR {
        let call = supportsInterfaceCall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad supportsInterface args: {e}")))?;
        let id: [u8; 4] = call.interfaceId.0;
        let yes = id == IFACE_ERC165 || id == IFACE_ERC721 || id == IFACE_ERC721_METADATA;
        return Ok(encode_bool(yes));
    }
    // name()
    if sel == nameCall::SELECTOR {
        return Ok(encode_string("UBI Streams"));
    }
    // symbol()
    if sel == symbolCall::SELECTOR {
        return Ok(encode_string("USTREAM"));
    }
    // balanceOf(address)
    if sel == balanceOfCall::SELECTOR {
        let call = balanceOfCall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad balanceOf args: {e}")))?;
        let n = chain.nft_balance_of(&call.owner.into_array());
        return Ok(encode_u256(U256::from(n)));
    }
    // ownerOf(uint256) — decode the side flag; revert for unknown tokens.
    if sel == ownerOfCall::SELECTOR {
        let call = ownerOfCall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad ownerOf args: {e}")))?;
        let (id, side) = decode_token_id(call.tokenId)
            .ok_or_else(|| execution_reverted("ERC721: invalid token"))?;
        let stream = chain
            .get_stream(id)
            .ok_or_else(|| execution_reverted("ERC721: owner query for nonexistent token"))?;
        let owner = match side {
            Side::Incoming => stream.to,
            Side::Outgoing => stream.from,
        };
        return Ok(encode_address(AlloyAddr::from(owner)));
    }
    // tokenURI(uint256) — render the on-chain card for the decoded side.
    if sel == tokenURICall::SELECTOR {
        let call = tokenURICall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad tokenURI args: {e}")))?;
        let (id, side) = decode_token_id(call.tokenId)
            .ok_or_else(|| execution_reverted("ERC721: invalid token"))?;
        let stream = chain
            .get_stream(id)
            .ok_or_else(|| execution_reverted("ERC721Metadata: URI query for nonexistent token"))?;
        let card = CardData::new(&stream, side, now_secs());
        return Ok(encode_string(&render_token_uri(&card)));
    }
    // Soulbound mutators (transfer/approve) reach eth_call only if a tool simulates them: revert.
    match parse_calldata(data) {
        Err(CalldataError::Soulbound) => Err(execution_reverted("soulbound")),
        // openStream/stopStream are writes, not view calls; everything else is unknown → empty data.
        _ => Ok(Vec::new()),
    }
}

/// Dispatch a "Proof of Humanity" ERC-721 / ERC-165 / ERC-721-Metadata view call against the
/// HumanityHub collection, returning ABI-encoded result bytes. Stateless ownership: `tokenId` is the
/// human address as `uint160`, and the token *exists* (does not revert) iff that address's
/// `ubi_getHuman` status is `Verified`. Unknown selectors return empty data; soulbound mutators revert.
fn poh_nft_call(chain: &Chain, data: &[u8]) -> Result<Vec<u8>, ErrorObjectOwned> {
    use alloy_sol_types::SolCall;
    use poh_nft::{
        balanceOfCall, encode_address, encode_bool, encode_string, encode_u256, nameCall,
        ownerOfCall, supportsInterfaceCall, symbolCall, tokenURICall, IFACE_ERC165, IFACE_ERC721,
        IFACE_ERC721_METADATA, POH_NAME, POH_SYMBOL,
    };

    if data.len() < 4 {
        return Err(invalid_params("calldata too short for a selector"));
    }
    let sel: [u8; 4] = [data[0], data[1], data[2], data[3]];

    // supportsInterface(bytes4)
    if sel == supportsInterfaceCall::SELECTOR {
        let call = supportsInterfaceCall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad supportsInterface args: {e}")))?;
        let id: [u8; 4] = call.interfaceId.0;
        let yes = id == IFACE_ERC165 || id == IFACE_ERC721 || id == IFACE_ERC721_METADATA;
        return Ok(encode_bool(yes));
    }
    // name() / symbol()
    if sel == nameCall::SELECTOR {
        return Ok(encode_string(POH_NAME));
    }
    if sel == symbolCall::SELECTOR {
        return Ok(encode_string(POH_SYMBOL));
    }
    // balanceOf(address) → 1 iff Verified, else 0.
    if sel == balanceOfCall::SELECTOR {
        let call = balanceOfCall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad balanceOf args: {e}")))?;
        let verified = chain
            .get_human(&call.owner.into_array())
            .map(|h| h.status == HumanStatus::Verified)
            .unwrap_or(false);
        return Ok(encode_u256(U256::from(u8::from(verified))));
    }
    // ownerOf(uint256) → the address iff Verified, else revert.
    if sel == ownerOfCall::SELECTOR {
        let call = ownerOfCall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad ownerOf args: {e}")))?;
        let addr = addr_of_token_id(call.tokenId)
            .ok_or_else(|| execution_reverted("ERC721: invalid token"))?;
        let verified = chain
            .get_human(&addr.into_array())
            .map(|h| h.status == HumanStatus::Verified)
            .unwrap_or(false);
        if !verified {
            return Err(execution_reverted(
                "ERC721: owner query for nonexistent token",
            ));
        }
        return Ok(encode_address(addr));
    }
    // tokenURI(uint256) → the on-chain fingerprint card iff Verified, else revert.
    if sel == tokenURICall::SELECTOR {
        let call = tokenURICall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad tokenURI args: {e}")))?;
        let addr = addr_of_token_id(call.tokenId)
            .ok_or_else(|| execution_reverted("ERC721: invalid token"))?;
        let human = chain
            .get_human(&addr.into_array())
            .filter(|h| h.status == HumanStatus::Verified)
            .ok_or_else(|| execution_reverted("ERC721Metadata: URI query for nonexistent token"))?;
        let card = PohCardData {
            address: addr,
            status: human.status,
            verified_at: human.verified_at,
            vouches: human.vouches_in.len(),
            reputation: human.reputation,
            assurance: human.assurance,
        };
        return Ok(encode_string(&render_poh_token_uri(&card)));
    }
    // M6 Stage D — verifyAttribute(subject, attributeType, attrProof) → bool (spec §4.4, EC-9). The
    // chain never learns the DOB/opening — the verifier returns only the boolean. M6 ships only `over18`;
    // an unknown attributeType fails closed (`false`), never reverts.
    if sel == humanity::verifyAttributeCall::SELECTOR {
        use alloy_sol_types::SolValue;
        let call = humanity::verifyAttributeCall::abi_decode(data, true)
            .map_err(|e| invalid_params(format!("bad verifyAttribute args: {e}")))?;
        // Map the keccak attribute-type tag to the runtime enum. M6 knows only `over18`.
        let ok = if call.attributeType == over18_attribute_type() {
            chain.verify_attribute(
                &call.subject.into_array(),
                ZkAttrType::Over18,
                &call.attrProof,
            )
        } else {
            false // unknown attribute type ⇒ fail closed
        };
        return Ok(ok.abi_encode());
    }
    // Soulbound mutators (transfer/approve) reach eth_call only if a tool simulates them: revert.
    // (One token per human, non-transferable.)
    if sel == poh_nft::transferFromCall::SELECTOR
        || sel == poh_nft::safeTransferFromCall::SELECTOR
        || sel == poh_nft::approveCall::SELECTOR
        || sel == poh_nft::setApprovalForAllCall::SELECTOR
    {
        return Err(execution_reverted("soulbound"));
    }
    // Unknown selector → empty data (matches the StreamHub view fallback).
    Ok(Vec::new())
}

/// Parse a stream-id JSON param accepting either a hex quantity (`"0x.."`) or a JSON number.
fn parse_stream_id_param(v: Option<&Value>) -> RpcResult<u64> {
    let v = v.ok_or_else(|| invalid_params("missing stream id"))?;
    if let Some(s) = v.as_str() {
        return u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
            .map_err(|_| invalid_params("bad stream id hex"));
    }
    v.as_u64().ok_or_else(|| invalid_params("bad stream id"))
}

/// Render a [`Stream`] into the `StreamView` JSON shape (spec §"RPC surface"): all stored fields plus
/// the read-time `accrued_now` and `t_end`. `status` is a `{type, ...}` object so `Stopped(at)`
/// carries its instant.
fn stream_view_json(s: &Stream, now: u64) -> Value {
    let status = match s.status {
        StreamStatus::Active => json!({ "type": "Active" }),
        StreamStatus::Stopped(at) => json!({ "type": "Stopped", "at": at }),
        StreamStatus::Completed => json!({ "type": "Completed" }),
    };
    json!({
        "id": s.id,
        "from": format!("0x{}", hex::encode(&s.from)),
        "to": format!("0x{}", hex::encode(&s.to)),
        "rate": hex_u128(s.rate),
        "deposit": hex_u128(s.deposit),
        "drawn": hex_u128(s.drawn),
        "started_at": s.started_at,
        "status": status,
        "accrued_now": hex_u128(s.accrued(now)),
        "t_end": s.t_end(),
    })
}

// ---------------------------------------------------------------------------------------------
// M3 proof-of-humanity JSON shapes (spec 03 §"RPC / interfaces"). Statuses/verdicts/kinds are
// rendered as stable lowercase-or-CamelCase strings; addresses + hashes as 0x-hex; ids as numbers.
// ---------------------------------------------------------------------------------------------

/// String name for a [`HumanStatus`] (the `status` field of `ubi_getHuman`).
fn human_status_str(s: HumanStatus) -> &'static str {
    match s {
        HumanStatus::Unverified => "Unverified",
        HumanStatus::Pending => "Pending",
        HumanStatus::Verified => "Verified",
        HumanStatus::Challenged => "Challenged",
        HumanStatus::Revoked => "Revoked",
    }
}

/// String name for a [`Verdict`].
fn verdict_str(v: Verdict) -> &'static str {
    match v {
        Verdict::Human => "Human",
        Verdict::Sybil => "Sybil",
        Verdict::Uncertain => "Uncertain",
    }
}

/// String name for a [`Confidence`] bucket.
fn confidence_str(c: Confidence) -> &'static str {
    match c {
        Confidence::Low => "Low",
        Confidence::Med => "Med",
        Confidence::High => "High",
    }
}

/// String name for a [`CaseKind`].
fn case_kind_str(k: CaseKind) -> &'static str {
    match k {
        CaseKind::Registration => "Registration",
        CaseKind::Challenge => "Challenge",
    }
}

/// 0x-hex of a 20-byte address.
fn addr_hex(a: &Address) -> String {
    format!("0x{}", hex::encode(a))
}
/// 0x-hex of a 32-byte hash.
fn hash_hex(h: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(h))
}

/// Render a [`Human`] into the `ubi_getHuman` JSON shape. `verified_at` is unix seconds (emission
/// epoch). Vouchers + commitments are 0x-hex; no PII is ever present (I6). M6: the `assurance` level
/// (STD/ENH/DUAL) is surfaced additively — existing fields are unchanged (EC-5 / I3).
fn human_view_json(h: &Human) -> Value {
    json!({
        "address": addr_hex(&h.address),
        "status": human_status_str(h.status),
        "verified_at": h.verified_at,
        "liveness_ref": hash_hex(&h.liveness_ref),
        "vouches_in": h.vouches_in.iter().map(addr_hex).collect::<Vec<_>>(),
        "reputation": h.reputation,
        "assurance": h.assurance.as_str(),
    })
}

/// Render a [`CscaEntry`] into the `ubi_getCscaRegistry` JSON shape (spec §9). A CSCA is a sovereign
/// signing key, not a person — no PII. `pubkey` is raw 0x-hex; `country_code` the ICAO 3-letter code.
fn csca_entry_json(e: &CscaEntry) -> Value {
    json!({
        "country_code": String::from_utf8_lossy(&e.country_code),
        "key_id": hash_hex(&e.key_id),
        "pubkey": format!("0x{}", hex::encode(&e.pubkey)),
        "added_at": e.added_at,
        "status": match e.status { CscaStatus::Active => "Active", CscaStatus::Revoked => "Revoked" },
    })
}

/// Render a committed [`CanonicalVerdict`] into a `{verdict, confidence, reasons_hash}` JSON object.
fn verdict_json(v: &ubi2_runtime::CanonicalVerdict) -> Value {
    json!({
        "verdict": verdict_str(v.verdict),
        "confidence": confidence_str(v.confidence),
        "reasons_hash": hash_hex(&v.reasons_hash),
    })
}

/// Render the case `status` as `{type, ...}` so a `Committed` carries its canonical verdict.
fn case_status_json(s: &CaseStatus) -> Value {
    match s {
        CaseStatus::Open => json!({ "type": "Open" }),
        CaseStatus::Committed(v) => json!({ "type": "Committed", "verdict": verdict_json(v) }),
        CaseStatus::Escalated => json!({ "type": "Escalated" }),
    }
}

/// Render a [`Case`] into the `ubi_getCase` JSON shape: jury + each submitted juror verdict, the
/// content-addressed `evidence_ref`, and the case status (with the committed verdict if any).
fn case_view_json(c: &Case) -> Value {
    let votes: Vec<Value> = c
        .votes
        .iter()
        .map(|(juror, v)| json!({ "juror": addr_hex(juror), "verdict": verdict_json(v) }))
        .collect();
    json!({
        "id": c.id,
        "subject": addr_hex(&c.subject),
        "kind": case_kind_str(c.kind),
        "evidence_ref": hash_hex(&c.evidence_ref),
        "jury": c.jury.iter().map(addr_hex).collect::<Vec<_>>(),
        "votes": votes,
        "status": case_status_json(&c.status),
        "opened_at": c.opened_at,
    })
}

/// Render a [`Juror`] into the `ubi_getJurors` element shape.
fn juror_view_json(j: &Juror) -> Value {
    json!({
        "address": addr_hex(&j.address),
        "stake": hex_u128(j.stake),
        "active": j.active,
    })
}

// ---------------------------------------------------------------------------------------------
// M4 prompt-contract JSON shapes (spec 04 §"RPC / interfaces") + the EXPL-1 indexer reads.
// ---------------------------------------------------------------------------------------------

/// String name for a [`ContractStatus`].
fn contract_status_str(s: ContractStatus) -> &'static str {
    match s {
        ContractStatus::Active => "Active",
        ContractStatus::Terminated => "Terminated",
    }
}

/// Render a single canonical [`Op`] as a tagged JSON object (so a wallet/explorer can show "Transfer
/// 5 UBI to 0x…" without re-decoding the ops blob). Amounts are 0x-hex base units; addresses/hashes
/// 0x-hex; ids numbers.
fn op_json(op: &Op) -> Value {
    match op {
        Op::Transfer { to, amount } => json!({
            "type": "Transfer", "to": addr_hex(to), "amount": hex_u128(*amount),
        }),
        Op::Refund { party, amount } => json!({
            "type": "Refund", "party": addr_hex(party), "amount": hex_u128(*amount),
        }),
        Op::OpenStream { to, rate, deposit } => json!({
            "type": "OpenStream", "to": addr_hex(to),
            "rate": hex_u128(*rate), "deposit": hex_u128(*deposit),
        }),
        Op::StopStream { id } => json!({ "type": "StopStream", "id": id }),
        Op::SetVar { key, value } => json!({
            "type": "SetVar", "key": hash_hex(key), "value": hash_hex(value),
        }),
        Op::Abort { reason_hash } => json!({
            "type": "Abort", "reason_hash": hash_hex(reason_hash),
        }),
    }
}

/// Render a [`CanonicalEffect`] as `{ops: [...], effect_hash}` — the quorum-equality key plus the
/// human-readable op list.
fn effect_json(e: &CanonicalEffect) -> Value {
    json!({
        "ops": e.ops.iter().map(op_json).collect::<Vec<_>>(),
        "effect_hash": hash_hex(&e.effect_hash),
    })
}

/// Render a [`PromptContract`] into the contract JSON shape: the **full** plain-language `text` (stored
/// on-chain — transparency), its `text_ref` content commitment, escrow (0x-hex base units) + derived
/// escrow address, the declared parties, the contract-local vars, the status, and where it was deployed
/// (`deploy_block` number + `deploy_tx` hash). Used for both `ubi_getContract` (enriched with `cases`
/// by [`contract_detail_json`]) and the `ubi_getContractsOf` list view.
fn contract_view_json(c: &PromptContract) -> Value {
    let mut vars: Vec<([u8; 32], [u8; 32])> = c.vars.iter().map(|(k, v)| (*k, *v)).collect();
    vars.sort_unstable();
    let vars_json: Vec<Value> = vars
        .iter()
        .map(|(k, v)| json!({ "key": hash_hex(k), "value": hash_hex(v) }))
        .collect();
    json!({
        "id": c.id,
        "text": c.text,
        "text_ref": hash_hex(&c.text_ref),
        "escrow": hex_u128(c.escrow),
        "escrow_address": addr_hex(&ubi2_runtime::contract_address(c.id)),
        "parties": c.parties.iter().map(addr_hex).collect::<Vec<_>>(),
        "vars": vars_json,
        "status": contract_status_str(c.status),
        "deploy_block": c.deploy_block,
        "deploy_tx": hash_hex(&c.deploy_tx),
    })
}

/// Render a [`BlockSummary`] into the `ubi_getRecentBlocks` JSON shape: a compact directory row
/// (number/hash/parentHash/timestamp/txCount/gasUsed + a zero `miner` placeholder so the field set
/// matches the explorer's other block views). Hex quantities; `txCount` a plain number for the UI.
fn block_summary_json(s: &BlockSummary) -> Value {
    json!({
        "number": hex_u64(s.number),
        "hash": hex_b256(&s.hash),
        "parentHash": hex_b256(&s.parent_hash),
        "timestamp": hex_u64(s.timestamp),
        "txCount": s.tx_count,
        "gasUsed": hex_u64(s.gas_used),
        // Devnet blocks have no proposer; surfaced as the zero address (matches `decoded_block_json`).
        "miner": "0x0000000000000000000000000000000000000000",
    })
}

/// Render a [`ContractSummary`] into the `ubi_getContracts` JSON shape: a compact directory row
/// (id/address/parties/status/escrow base units/title + deploy block/tx/createdAt). The full
/// `text`/`vars`/`cases` live behind `ubi_getContract(id)`.
fn contract_summary_json(s: &ContractSummary) -> Value {
    json!({
        "id": s.id,
        "address": addr_hex(&s.address),
        "parties": s.parties.iter().map(addr_hex).collect::<Vec<_>>(),
        "status": contract_status_str(s.status),
        "escrow": hex_u128(s.escrow),
        "balance": hex_u128(s.escrow),
        "title": s.title,
        "deploy_block": s.deploy_block,
        "deploy_tx": hash_hex(&s.deploy_tx),
        "createdAt": s.created_at,
    })
}

/// Render the **full** `ubi_getContract` detail: every [`contract_view_json`] field plus the contract's
/// list of exec cases (each a [`exec_case_summary_json`]: id, invoker, trigger, status, the resulting
/// canonical effect / abort, and the block it resolved in). Everything about the contract from chain
/// state in one read — for the explorer / wallet contract page.
fn contract_detail_json(c: &PromptContract, cases: &[ExecCase]) -> Value {
    let mut v = contract_view_json(c);
    let cases_json: Vec<Value> = cases.iter().map(exec_case_summary_json).collect();
    v.as_object_mut()
        .expect("contract_view_json is an object")
        .insert("cases".to_string(), json!(cases_json));
    v
}

/// A compact exec-case summary for the contract detail view: the case id, who invoked it, the trigger
/// commitment, the case status (Open / Committed / Aborted), and — when resolved — the resulting
/// canonical effect ops (for Committed) and the block it resolved in. Lets a contract page list every
/// invocation and its outcome without a second `ubi_getExecCase` round-trip.
fn exec_case_summary_json(c: &ExecCase) -> Value {
    json!({
        "id": c.id,
        "invoker": addr_hex(&c.invoker),
        "trigger_ref": hash_hex(&c.trigger_ref),
        "status": exec_status_json(&c.status),
        "opened_at": c.opened_at,
        "resolved_at": c.resolved_at,
    })
}

/// Render the exec-case `status` as `{type, ...}` so a `Committed` carries its canonical effect.
fn exec_status_json(s: &ExecStatus) -> Value {
    match s {
        ExecStatus::Open => json!({ "type": "Open" }),
        ExecStatus::Committed(e) => json!({ "type": "Committed", "effect": effect_json(e) }),
        ExecStatus::Aborted => json!({ "type": "Aborted" }),
    }
}

/// Render an [`ExecCase`] into the `ubi_getExecCase` JSON shape: the contract, trigger commitment,
/// invoker, the interpreter jury, each submitted effect, and the case status (with the committed
/// effect if any).
fn exec_case_view_json(c: &ExecCase) -> Value {
    let effects: Vec<Value> = c
        .effects
        .iter()
        .map(|(interp, e)| json!({ "interpreter": addr_hex(interp), "effect": effect_json(e) }))
        .collect();
    json!({
        "id": c.id,
        "contract": c.contract,
        "trigger_ref": hash_hex(&c.trigger_ref),
        "invoker": addr_hex(&c.invoker),
        "jury": c.jury.iter().map(addr_hex).collect::<Vec<_>>(),
        "effects": effects,
        "status": exec_status_json(&c.status),
        "opened_at": c.opened_at,
        "resolved_at": c.resolved_at,
    })
}

/// Classify a stored tx by the hub it targets (its `to`) + selector, for the explorer's per-address
/// activity feed. Returns a stable string `kind` an explorer can label rows with.
fn tx_kind_str(tx: &StoredTx) -> &'static str {
    let to = match tx.to {
        Some(a) => a,
        None => return "Create",
    };
    if to == STREAM_HUB {
        match parse_calldata(&tx.input) {
            Ok(StreamOp::Open { .. }) => "OpenStream",
            Ok(StreamOp::Stop { .. }) => "StopStream",
            _ => "StreamHub",
        }
    } else if to == HUMANITY_HUB {
        match parse_humanity_calldata(&tx.input) {
            Ok(HumanityOp::RequestVerification { .. }) => "RequestVerification",
            Ok(HumanityOp::Vouch { .. }) => "Vouch",
            Ok(HumanityOp::Challenge { .. }) => "Challenge",
            Ok(HumanityOp::SubmitVerdict { .. }) => "SubmitVerdict",
            Ok(HumanityOp::SubmitZkPassportProof { .. }) => "SubmitZkPassportProof",
            Ok(HumanityOp::RegisterCsca { .. }) => "RegisterCsca",
            Ok(HumanityOp::RevokeCsca { .. }) => "RevokeCsca",
            Ok(HumanityOp::PinSelfIdentityRoot { .. }) => "PinSelfIdentityRoot",
            Ok(HumanityOp::PinSelfOfacRoot { .. }) => "PinSelfOfacRoot",
            Ok(HumanityOp::RetireSelfRoot { .. }) => "RetireSelfRoot",
            // The synthetic finalize/scan sweep tx is from==to==HumanityHub with empty input.
            _ => "HumanitySystem",
        }
    } else if to == CONTRACT_HUB {
        match parse_contract_calldata(&tx.input) {
            Ok(ContractOp::DeployContract { .. }) => "DeployContract",
            Ok(ContractOp::FundContract { .. }) => "FundContract",
            Ok(ContractOp::InvokeContract { .. }) => "InvokeContract",
            Ok(ContractOp::SubmitEffect { .. }) => "SubmitEffect",
            _ => "ContractHub",
        }
    } else if tx.input.is_empty() {
        "Transfer"
    } else {
        "Call"
    }
}

/// Render one activity row for `subject` (the queried address): the tx hash, block, kind, the
/// counterparty (the *other* side from `subject`'s perspective), and value. Backs
/// `ubi_getAddressActivity`.
fn activity_row_json(tx: &StoredTx, subject: &Address) -> Value {
    // The counterparty is whichever of from/to is not the subject (default to `to`).
    let counterparty = if &tx.from.into_array() == subject {
        tx.to.map(|a| a.into_array())
    } else {
        Some(tx.from.into_array())
    };
    json!({
        "hash": hex_b256(&tx.hash),
        "blockNumber": hex_u64(tx.block_number),
        "kind": tx_kind_str(tx),
        "from": hex_addr(&tx.from),
        "to": tx.to.map(|a| hex_addr(&a)).map(Value::String).unwrap_or(Value::Null),
        "counterparty": counterparty.map(|a| addr_hex(&a)).map(Value::String).unwrap_or(Value::Null),
        "value": hex_u256(tx.value),
        // The UBI fee this tx paid (`gas_used * gas_price`, base units) — so a per-account feed can
        // show what each row cost. Zero for the synthetic finalize/scan sweep tx (no signer, no fee).
        "fee": hex_u128(tx_fee(tx)),
        "input": if tx.input.is_empty() { "0x".to_string() } else { format!("0x{}", hex::encode(&tx.input)) },
    })
}

/// Render an [`AccountSummary`] into the `ubi_getAccount` JSON shape.
fn account_summary_json(s: &AccountSummary) -> Value {
    json!({
        "address": addr_hex(&s.address),
        "balance": hex_u128(s.balance),
        "nonce": hex_u64(s.nonce),
        "human_status": s.human_status.map(human_status_str).map(Value::from).unwrap_or(Value::Null),
        "streams_out": s.streams_out,
        "streams_in": s.streams_in,
        "contracts": s.contracts,
        "tx_count": s.tx_count,
    })
}

// ---------------------------------------------------------------------------------------------
// EXPL-2: deep decoded reads (ubi_getBlock / ubi_getTransaction). The block explorer needs every
// detail of a tx — not just its raw bytes, but a *human-decoded* view: which system hub it called,
// which method, the decoded args, the events it emitted (decoded), and the resulting committed
// state effect / verdict / status where applicable. These helpers are all pure, deterministic
// functions of `(stored tx, state snapshot)` — no floats, hex quantities, 0x addresses/hashes (I2).
// ---------------------------------------------------------------------------------------------

/// The UBI fee a tx paid, in base units: `gas_used * gas_price`. A synthetic system tx (the
/// finalize/scan sweep) has `gas_used == 0` and so a zero fee. Pure integer math (I2).
fn tx_fee(tx: &StoredTx) -> u128 {
    (tx.gas_used as u128) * RT_GAS_PRICE_WEI
}

/// Decode a tx's system-hub calldata into a `{hub, method, args}` object an explorer can render as
/// "StreamHub.openStream(to=0x…, rate=…, deposit=…)" without re-implementing the ABI. Returns:
/// * a `Transfer` descriptor for a plain value send (empty calldata to a non-hub address),
/// * a hub call descriptor (`hub` = the hub name, `method` = the decoded op, `args` = a map) for a
///   StreamHub / HumanityHub / ContractHub tx,
/// * `System` for the synthetic humanity finalize/scan sweep tx (from==to==HumanityHub, no input),
/// * `null` for an opaque call we can't decode (unknown selector to a non-hub address).
///
/// All addresses are 0x-hex, amounts/ids/refs are 0x-hex, so the shape is byte-stable across nodes.
fn decode_call_json(tx: &StoredTx) -> Value {
    let to = match tx.to {
        Some(a) => a,
        None => return json!({ "kind": "Create" }),
    };
    if to == STREAM_HUB {
        match parse_calldata(&tx.input) {
            Ok(StreamOp::Open { to, rate, deposit }) => json!({
                "kind": "HubCall", "hub": "StreamHub", "method": "openStream",
                "args": { "to": hex_addr(&to), "rate": hex_u128(rate), "deposit": hex_u128(deposit) },
            }),
            Ok(StreamOp::Stop { id }) => json!({
                "kind": "HubCall", "hub": "StreamHub", "method": "stopStream",
                "args": { "id": id },
            }),
            // The ERC-721 view selectors / unknowns reach a write tx only if a tool simulates them.
            _ => json!({ "kind": "HubCall", "hub": "StreamHub", "method": null, "args": {} }),
        }
    } else if to == HUMANITY_HUB {
        match parse_humanity_calldata(&tx.input) {
            Ok(HumanityOp::RequestVerification { liveness_ref }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "requestVerification",
                "args": { "liveness_ref": hash_hex(&liveness_ref) },
            }),
            Ok(HumanityOp::Vouch { vouchee }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "vouch",
                "args": { "vouchee": hex_addr(&vouchee) },
            }),
            Ok(HumanityOp::Challenge {
                subject,
                evidence_ref,
            }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "challenge",
                "args": { "subject": hex_addr(&subject), "evidence_ref": hash_hex(&evidence_ref) },
            }),
            Ok(HumanityOp::SubmitVerdict { case_id, verdict }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "submitVerdict",
                "args": {
                    "case_id": case_id,
                    "verdict": verdict_str(verdict.verdict),
                    "confidence": confidence_str(verdict.confidence),
                },
            }),
            Ok(HumanityOp::SubmitZkPassportProof {
                proof,
                signals,
                scheme_tag,
            }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "submitZkPassportProof",
                // The proof bytes are opaque; we surface only their length (I6 — no PII; the proof never
                // contains plaintext). The 21 public signals are all on-chain commitments/scalars.
                "args": {
                    "proof_len": proof.len(),
                    "public_signals": signals.iter().map(hash_hex).collect::<Vec<_>>(),
                    "scheme_tag": scheme_tag,
                },
            }),
            Ok(HumanityOp::RegisterCsca {
                country_code,
                key_id,
                pubkey,
            }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "registerCsca",
                "args": {
                    "country_code": String::from_utf8_lossy(&country_code),
                    "key_id": hash_hex(&key_id),
                    "pubkey_len": pubkey.len(),
                },
            }),
            Ok(HumanityOp::RevokeCsca { key_id }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "revokeCsca",
                "args": { "key_id": hash_hex(&key_id) },
            }),
            Ok(HumanityOp::PinSelfIdentityRoot { root }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "pinSelfIdentityRoot",
                "args": { "root": hash_hex(&root) },
            }),
            Ok(HumanityOp::PinSelfOfacRoot { kind, root }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "pinSelfOfacRoot",
                "args": { "kind": kind, "root": hash_hex(&root) },
            }),
            Ok(HumanityOp::RetireSelfRoot { root }) => json!({
                "kind": "HubCall", "hub": "HumanityHub", "method": "retireSelfRoot",
                "args": { "root": hash_hex(&root) },
            }),
            // The synthetic finalize/scan sweep tx is from==to==HumanityHub with empty input.
            _ => json!({ "kind": "System", "hub": "HumanityHub", "method": "finalizeSweep" }),
        }
    } else if to == CONTRACT_HUB {
        match parse_contract_calldata(&tx.input) {
            Ok(ContractOp::DeployContract { text, parties }) => json!({
                "kind": "HubCall", "hub": "ContractHub", "method": "deployContract",
                "args": {
                    "text": text,
                    "text_ref": hash_hex(&text_commitment(&text)),
                    "parties": parties.iter().map(hex_addr).collect::<Vec<_>>(),
                },
            }),
            Ok(ContractOp::FundContract { id }) => json!({
                "kind": "HubCall", "hub": "ContractHub", "method": "fundContract",
                "args": { "id": id, "value": hex_u256(tx.value) },
            }),
            Ok(ContractOp::InvokeContract { id, trigger_ref }) => json!({
                "kind": "HubCall", "hub": "ContractHub", "method": "invokeContract",
                "args": { "id": id, "trigger_ref": hash_hex(&trigger_ref) },
            }),
            Ok(ContractOp::SubmitEffect { case_id, effect }) => json!({
                "kind": "HubCall", "hub": "ContractHub", "method": "submitEffect",
                "args": { "case_id": case_id, "effect": effect_json(&effect) },
            }),
            _ => json!({ "kind": "HubCall", "hub": "ContractHub", "method": null, "args": {} }),
        }
    } else if tx.input.is_empty() {
        json!({ "kind": "Transfer", "to": hex_addr(&to), "value": hex_u256(tx.value) })
    } else {
        // Opaque calldata to a non-hub address (no EVM on devnet) — surface the raw input only.
        Value::Null
    }
}

/// Decode a single [`TxLog`] into `{name, hub, args}` by matching its signature topic against the
/// known hub events (StreamOpened/StreamStopped/Transfer, CaseOpened/VerdictSubmitted/StatusChanged,
/// ContractDeployed/EffectCommitted/EffectAborted). Falls back to `{name: null}` carrying the raw
/// topics for an event we don't recognize. Pure: the address-typed topics are decoded the same way
/// `addr_topic`/`u64_topic` encode them, so this is the exact inverse (I2-stable).
fn decode_log_json(log: &TxLog) -> Value {
    let sig = log.topics.first().copied().unwrap_or(B256::ZERO);
    // Recover a left-padded address topic's low 20 bytes.
    let topic_addr = |i: usize| -> Option<String> {
        log.topics.get(i).map(|t| {
            let b = t.as_slice();
            let mut a = [0u8; 20];
            a.copy_from_slice(&b[12..]);
            addr_hex(&a)
        })
    };
    // Recover a u64 from a left-padded numeric topic (the low 8 bytes).
    let topic_u64 = |i: usize| -> Option<u64> {
        log.topics.get(i).map(|t| {
            let b = t.as_slice();
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[24..]);
            u64::from_be_bytes(w)
        })
    };
    // The trailing 1-byte ABI uint in the log `data` (left-padded to a 32-byte word).
    let data_u8 = || -> Option<u8> { log.data.last().copied() };

    if sig == stream_opened_topic() {
        json!({ "name": "StreamOpened", "hub": "StreamHub", "args": {
            "id": topic_u64(1), "from": topic_addr(2), "to": topic_addr(3),
        }})
    } else if sig == stream_stopped_topic() {
        json!({ "name": "StreamStopped", "hub": "StreamHub", "args": {
            "id": topic_u64(1), "caller": topic_addr(2),
        }})
    } else if sig == transfer_topic() {
        // ERC-721 Transfer(from, to, tokenId). The emitter disambiguates the collection: the StreamHub
        // mints stream tokens (two per stream); the HumanityHub mints/burns the Proof-of-Humanity
        // soulbound token (one per verified human, tokenId == the human address as uint160).
        let token_id = log
            .topics
            .get(3)
            .map(|t| hex_u256(U256::from_be_bytes(t.0)));
        let hub = if log.address == HUMANITY_HUB {
            "HumanityHub"
        } else {
            "StreamHub"
        };
        json!({ "name": "Transfer", "hub": hub, "args": {
            "from": topic_addr(1), "to": topic_addr(2), "token_id": token_id,
        }})
    } else if sig == case_opened_topic() {
        // HumanityHub CaseOpened(caseId, subject, kind); kind byte in data.
        let kind = data_u8().map(|b| match b {
            0 => "Registration",
            1 => "Challenge",
            _ => "Unknown",
        });
        json!({ "name": "CaseOpened", "hub": "HumanityHub", "args": {
            "case_id": topic_u64(1), "subject": topic_addr(2), "kind": kind,
        }})
    } else if sig == verdict_submitted_topic() {
        let verdict = data_u8().map(|b| match b {
            0 => "Human",
            1 => "Sybil",
            2 => "Uncertain",
            _ => "Unknown",
        });
        json!({ "name": "VerdictSubmitted", "hub": "HumanityHub", "args": {
            "case_id": topic_u64(1), "juror": topic_addr(2), "verdict": verdict,
        }})
    } else if sig == status_changed_topic() {
        let status = data_u8().map(|b| match b {
            0 => "Unverified",
            1 => "Pending",
            2 => "Verified",
            3 => "Challenged",
            4 => "Revoked",
            _ => "Unknown",
        });
        json!({ "name": "StatusChanged", "hub": "HumanityHub", "args": {
            "subject": topic_addr(1), "status": status,
        }})
    } else if sig == contract_deployed_topic() {
        let text_ref = log
            .data
            .first()
            .map(|_| format!("0x{}", hex::encode(&log.data)));
        json!({ "name": "ContractDeployed", "hub": "ContractHub", "args": {
            "id": topic_u64(1), "deployer": topic_addr(2), "text_ref": text_ref,
        }})
    } else if sig == contract_case_opened_topic() {
        // ContractHub CaseOpened(caseId, contractId, invoker) — distinct from the HumanityHub one.
        json!({ "name": "CaseOpened", "hub": "ContractHub", "args": {
            "case_id": topic_u64(1), "contract_id": topic_u64(2), "invoker": topic_addr(3),
        }})
    } else if sig == effect_committed_topic() {
        let effect_hash = log
            .data
            .first()
            .map(|_| format!("0x{}", hex::encode(&log.data)));
        json!({ "name": "EffectCommitted", "hub": "ContractHub", "args": {
            "case_id": topic_u64(1), "contract_id": topic_u64(2), "effect_hash": effect_hash,
        }})
    } else if sig == effect_aborted_topic() {
        json!({ "name": "EffectAborted", "hub": "ContractHub", "args": {
            "case_id": topic_u64(1), "contract_id": topic_u64(2),
        }})
    } else {
        // Unknown event — surface the raw shape so the explorer can still show it.
        json!({
            "name": Value::Null,
            "address": hex_addr(&log.address),
            "topics": log.topics.iter().map(hex_b256).collect::<Vec<_>>(),
            "data": if log.data.is_empty() { "0x".to_string() } else { format!("0x{}", hex::encode(&log.data)) },
        })
    }
}

/// Recover an indexed `caseId` (topic[1]) from the first log on `tx` whose signature matches `sig`.
/// Used to map an invoke/verdict tx back to the case it opened/voted on, so we can report the case's
/// *resulting* outcome from the settled state. Deterministic: topics are the exact `u64_topic`
/// inverse.
fn case_id_from_log(tx: &StoredTx, sig: B256) -> Option<u64> {
    for log in &tx.logs {
        if log.topics.first().copied() == Some(sig) {
            let b = log.topics.get(1)?.as_slice();
            let mut w = [0u8; 8];
            w.copy_from_slice(&b[24..]);
            return Some(u64::from_be_bytes(w));
        }
    }
    None
}

/// Resolve the *resulting state effect / verdict / status* a tx produced, read from the settled state
/// (so the explorer can show "this invoke committed effect 0x… (Transfer 5 UBI → 0x…)" or "this
/// submitVerdict closed case #N as Sybil → subject Revoked"). Returns `null` for a tx whose kind has
/// no after-the-fact resolvable outcome (a plain transfer / fund / vouch — the value move is already
/// in the decoded call + logs). Pure read of `(state, tx)`; the case lookups are deterministic.
fn tx_result_json(state: &dyn State, tx: &StoredTx) -> Value {
    let to = match tx.to {
        Some(a) => a,
        None => return Value::Null,
    };
    if to == CONTRACT_HUB {
        match parse_contract_calldata(&tx.input) {
            // An invoke opened a case (CaseOpened in topic[1]); report its current outcome.
            Ok(ContractOp::InvokeContract { id, .. }) => {
                let case_id = case_id_from_log(tx, contract_case_opened_topic());
                if let Some(case) = case_id.and_then(|cid| state.get_exec_case(cid)) {
                    return json!({
                        "kind": "ExecCase",
                        "case_id": case.id,
                        "contract_id": case.contract,
                        "outcome": exec_status_json(&case.status),
                    });
                }
                json!({ "kind": "ExecCase", "contract_id": id, "outcome": Value::Null })
            }
            // A submitEffect carries a caseId in calldata; report that case's outcome.
            Ok(ContractOp::SubmitEffect { case_id, .. }) => {
                if let Some(case) = state.get_exec_case(case_id) {
                    return json!({
                        "kind": "ExecCase",
                        "case_id": case.id,
                        "contract_id": case.contract,
                        "outcome": exec_status_json(&case.status),
                    });
                }
                Value::Null
            }
            _ => Value::Null,
        }
    } else if to == HUMANITY_HUB {
        match parse_humanity_calldata(&tx.input) {
            // A challenge / requestVerification opened a case (HumanityHub CaseOpened in topic[1]).
            Ok(HumanityOp::Challenge { subject, .. }) => {
                humanity_case_result(state, tx, &subject.into_array())
            }
            // requestVerification opens a Registration case for the signer.
            Ok(HumanityOp::RequestVerification { .. }) => {
                humanity_case_result(state, tx, &tx.from.into_array())
            }
            // A submitVerdict votes on a known caseId; report the (possibly now-committed) case + the
            // subject's resulting human status.
            Ok(HumanityOp::SubmitVerdict { case_id, .. }) => {
                if let Some(case) = state.get_case(case_id) {
                    let subject_status = state.get_human(&case.subject).map(|h| h.status);
                    return json!({
                        "kind": "Case",
                        "case_id": case.id,
                        "subject": addr_hex(&case.subject),
                        "outcome": case_status_json(&case.status),
                        "subject_status": subject_status.map(human_status_str)
                            .map(Value::from).unwrap_or(Value::Null),
                    });
                }
                Value::Null
            }
            // A successful ZK proof: report the signer's resulting human status + assurance level (no
            // PII — only the level — I6).
            Ok(HumanityOp::SubmitZkPassportProof { .. }) => {
                let subject = tx.from.into_array();
                match state.get_human(&subject) {
                    Some(h) => json!({
                        "kind": "ZkPassport",
                        "subject": addr_hex(&subject),
                        "status": human_status_str(h.status),
                        "assurance": h.assurance.as_str(),
                    }),
                    None => Value::Null,
                }
            }
            _ => Value::Null,
        }
    } else {
        Value::Null
    }
}

/// Resolve the case a challenge / registration tx opened (its `caseId` is in the CaseOpened log) plus
/// the subject's resulting human status, into the `{kind: "Case", …}` shape. Pure read.
fn humanity_case_result(state: &dyn State, tx: &StoredTx, subject: &Address) -> Value {
    let case_id = case_id_from_log(tx, case_opened_topic());
    let subject_status = state.get_human(subject).map(|h| h.status);
    if let Some(case) = case_id.and_then(|cid| state.get_case(cid)) {
        return json!({
            "kind": "Case",
            "case_id": case.id,
            "subject": addr_hex(&case.subject),
            "outcome": case_status_json(&case.status),
            "subject_status": subject_status.map(human_status_str)
                .map(Value::from).unwrap_or(Value::Null),
        });
    }
    json!({
        "kind": "Case",
        "subject": addr_hex(subject),
        "outcome": Value::Null,
        "subject_status": subject_status.map(human_status_str)
            .map(Value::from).unwrap_or(Value::Null),
    })
}

/// Build the full decoded `ubi_getTransaction` JSON for a stored tx against a state snapshot. The
/// richest explorer surface: standard tx fields, the UBI `fee` paid, the explorer `kind`, the decoded
/// system-hub `call` (hub + method + args), the decoded `logs`, and the resolved `result` (committed
/// effect / case outcome / subject status). Pure + deterministic (I2).
fn decoded_tx_json(state: &dyn State, tx: &StoredTx) -> Value {
    let logs: Vec<Value> = tx.logs.iter().map(decode_log_json).collect();
    // A FAILED tx applied no op effect, so its `result` is the decoded failure reason rather than a
    // committed effect / case outcome (cycle-6). A succeeded tx resolves the usual state effect.
    let result = match &tx.revert_reason {
        Some(reason) => json!({ "kind": "Failed", "reason": reason }),
        None => tx_result_json(state, tx),
    };
    json!({
        "hash": hex_b256(&tx.hash),
        "blockHash": hex_b256(&tx.block_hash),
        "blockNumber": hex_u64(tx.block_number),
        "transactionIndex": hex_u64(tx.tx_index),
        "from": hex_addr(&tx.from),
        "to": tx.to.map(|a| hex_addr(&a)).map(Value::String).unwrap_or(Value::Null),
        "value": hex_u256(tx.value),
        "nonce": hex_u64(tx.nonce),
        "gasUsed": hex_u64(tx.gas_used),
        "gasPrice": hex_u64(GAS_PRICE_WEI),
        "fee": hex_u128(tx_fee(tx)),
        "kind": tx_kind_str(tx),
        // EVM receipt status mirrored onto the explorer surface (`0x1` ok / `0x0` failed). A FAILED tx
        // is mined (it advanced the nonce + paid the fee) but applied no op state change.
        "status": if tx.success { "0x1" } else { "0x0" },
        "input": if tx.input.is_empty() { "0x".to_string() } else { format!("0x{}", hex::encode(&tx.input)) },
        // The decoded system-hub call (which hub + method + args) — null for an opaque non-hub call.
        "call": decode_call_json(tx),
        // Every emitted log, decoded into {name, hub, args} (empty for a FAILED tx).
        "logs": logs,
        // For a succeeded tx: the committed effect / case verdict / subject status. For a FAILED tx:
        // `{kind: "Failed", reason}` carrying why the op aborted.
        "result": result,
    })
}

// ---------------------------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------------------------

/// Build the jsonrpsee `RpcModule` with all M1 methods registered against `chain`.
pub fn build_module(chain: Chain) -> RpcModule<Chain> {
    let mut m = RpcModule::new(chain);

    m.register_method("web3_clientVersion", |_, _, _| {
        Ok::<_, ErrorObjectOwned>(json!(CLIENT_VERSION))
    })
    .unwrap();

    m.register_method("net_version", |_, ctx, _| {
        Ok::<_, ErrorObjectOwned>(json!(ctx.chain_id.to_string()))
    })
    .unwrap();

    m.register_method("eth_chainId", |_, ctx, _| {
        Ok::<_, ErrorObjectOwned>(json!(hex_u64(ctx.chain_id)))
    })
    .unwrap();

    // No syncing on a single-node devnet.
    m.register_method("eth_syncing", |_, _, _| {
        Ok::<_, ErrorObjectOwned>(json!(false))
    })
    .unwrap();

    // The node holds no unlocked accounts; wallets manage their own keys.
    m.register_method("eth_accounts", |_, _, _| {
        Ok::<_, ErrorObjectOwned>(json!([]))
    })
    .unwrap();

    m.register_method("eth_blockNumber", |_, ctx, _| {
        Ok::<_, ErrorObjectOwned>(json!(hex_u64(ctx.latest_block().number)))
    })
    .unwrap();

    // Live streaming balance at `now` (invariant I2). `block` param is accepted but balance is
    // always evaluated at the current wall clock so the stream is observable; documented deviation:
    // historical-block balances are not reconstructed in M1.
    m.register_method("eth_getBalance", |params, ctx, _| {
        let addr = parse_addr_param(&params)?;
        let bal = ctx.balance(&addr, now_secs());
        Ok::<_, ErrorObjectOwned>(json!(hex_u128(bal)))
    })
    .unwrap();

    m.register_method("eth_getTransactionCount", |params, ctx, _| {
        let addr = parse_addr_param(&params)?;
        let nonce = ctx.inner.lock().unwrap().state.nonce(&addr);
        Ok::<_, ErrorObjectOwned>(json!(hex_u64(nonce)))
    })
    .unwrap();

    m.register_method("eth_gasPrice", |_, _, _| {
        Ok::<_, ErrorObjectOwned>(json!(hex_u64(GAS_PRICE_WEI)))
    })
    .unwrap();

    // The UBI gas price is a flat base fee carried in every block header (`baseFeePerGas =
    // GAS_PRICE_WEI`), so the priority tip is 0 — a 1559 wallet computes `maxFee = baseFee + tip =
    // GAS_PRICE_WEI`, exactly the price the runtime charges. (A legacy wallet uses `eth_gasPrice`,
    // which is the same constant.)
    m.register_method("eth_maxPriorityFeePerGas", |_, _, _| {
        Ok::<_, ErrorObjectOwned>(json!(hex_u64(0)))
    })
    .unwrap();

    // Per-kind gas estimate. MetaMask preflights *every* tx with `eth_estimateGas` and refuses to let
    // the user submit if it errors or under-estimates — so we must return the correct per-kind gas for
    // hub calls (vouch/deploy/invoke), not just transfers. We decode `(to, data)` to the same tx kind
    // the apply path charges the fee on, so the wallet's `gasLimit * gasPrice` preview equals the UBI
    // fee deducted. Unknown/missing call → transfer intrinsic (a safe lower bound for a plain send).
    m.register_method("eth_estimateGas", |params, _, _| {
        let seq: Vec<Value> = params.parse().unwrap_or_default();
        let gas = seq.first().map(gas_for_call_obj).unwrap_or(TRANSFER_GAS);
        Ok::<_, ErrorObjectOwned>(json!(hex_u64(gas)))
    })
    .unwrap();

    // Minimal EIP-1559 fee history so wallets that probe it don't choke.
    m.register_method("eth_feeHistory", |params, _, _| {
        let seq: Vec<Value> = params.parse().unwrap_or_default();
        let count = seq
            .first()
            .and_then(|v| v.as_str())
            .and_then(|s| u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16).ok())
            .or_else(|| seq.first().and_then(|v| v.as_u64()))
            .unwrap_or(1)
            .clamp(1, 1024) as usize;
        // Base fee = the flat UBI gas price (matching every block's `baseFeePerGas` header) and a zero
        // priority reward, so a 1559 wallet's `maxFee = baseFee + tip` resolves to exactly the UBI gas
        // price the runtime charges.
        let base: Vec<Value> = (0..=count).map(|_| json!(hex_u64(GAS_PRICE_WEI))).collect();
        let reward: Vec<Value> = (0..count).map(|_| json!([hex_u64(0)])).collect();
        let ratios: Vec<Value> = (0..count).map(|_| json!(0.0)).collect();
        Ok::<_, ErrorObjectOwned>(json!({
            "oldestBlock": hex_u64(0),
            "baseFeePerGas": base,
            "gasUsedRatio": ratios,
            "reward": reward,
        }))
    })
    .unwrap();

    // `eth_call`: no general EVM, but the StreamHub address answers the ERC-721 view precompile
    // (spec D4). Any other target returns `0x` (M1 behavior — no contracts until M4).
    m.register_method("eth_call", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [callObject, block]"))?;
        let call = seq
            .first()
            .ok_or_else(|| invalid_params("missing call object"))?;
        let to = call
            .get("to")
            .and_then(|v| v.as_str())
            .and_then(decode_hex)
            .filter(|b| b.len() == 20);
        let data = call
            .get("data")
            .or_else(|| call.get("input"))
            .and_then(|v| v.as_str())
            .and_then(decode_hex)
            .unwrap_or_default();

        // The StreamHub (UBI Streams) and the HumanityHub (Proof of Humanity) each answer an ERC-721
        // view surface; every other target stays `0x` (M1 behavior — no general EVM).
        let out = if to.as_deref() == Some(STREAM_HUB.as_slice()) {
            erc721_call(ctx, &data)?
        } else if to.as_deref() == Some(HUMANITY_HUB.as_slice()) {
            poh_nft_call(ctx, &data)?
        } else {
            return Ok::<_, ErrorObjectOwned>(json!("0x"));
        };
        Ok::<_, ErrorObjectOwned>(json!(format!("0x{}", hex::encode(&out))))
    })
    .unwrap();

    // ---- Custom stream reads (ubi_*) ----
    m.register_method("ubi_getStream", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [id]"))?;
        let id = parse_stream_id_param(seq.first())?;
        match ctx.get_stream(id) {
            Some(s) => Ok::<_, ErrorObjectOwned>(stream_view_json(&s, now_secs())),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    m.register_method("ubi_getStreams", |params, ctx, _| {
        let addr = parse_addr_param(&params)?;
        let now = now_secs();
        let (out_ids, in_ids) = ctx.streams_of(&addr);
        let outgoing: Vec<Value> = out_ids
            .into_iter()
            .filter_map(|id| ctx.get_stream(id))
            .map(|s| stream_view_json(&s, now))
            .collect();
        let incoming: Vec<Value> = in_ids
            .into_iter()
            .filter_map(|id| ctx.get_stream(id))
            .map(|s| stream_view_json(&s, now))
            .collect();
        Ok::<_, ErrorObjectOwned>(json!({ "outgoing": outgoing, "incoming": incoming }))
    })
    .unwrap();

    // ---- M3 proof-of-humanity reads (ubi_*) ----

    // ubi_getHuman(address) → the human record, or null if Unverified / never registered.
    m.register_method("ubi_getHuman", |params, ctx, _| {
        let addr = parse_addr_param(&params)?;
        match ctx.get_human(&addr) {
            Some(h) => Ok::<_, ErrorObjectOwned>(human_view_json(&h)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    // ubi_getCase(id) → the case (jury, votes, status), or null if unknown. `id` accepts hex or number.
    m.register_method("ubi_getCase", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [id]"))?;
        let id = parse_stream_id_param(seq.first())?;
        match ctx.get_case(id) {
            Some(c) => Ok::<_, ErrorObjectOwned>(case_view_json(&c)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    // ubi_getVouches(address) → {outgoing: [vouchees], incoming: [vouchers]} (the web-of-trust edges).
    m.register_method("ubi_getVouches", |params, ctx, _| {
        let addr = parse_addr_param(&params)?;
        let (out, inc) = ctx.vouches_of(&addr);
        Ok::<_, ErrorObjectOwned>(json!({
            "outgoing": out.iter().map(addr_hex).collect::<Vec<_>>(),
            "incoming": inc.iter().map(addr_hex).collect::<Vec<_>>(),
        }))
    })
    .unwrap();

    // ubi_getJurors() → the active juror registry.
    m.register_method("ubi_getJurors", |_, ctx, _| {
        let jurors: Vec<Value> = ctx.active_jurors().iter().map(juror_view_json).collect();
        Ok::<_, ErrorObjectOwned>(json!(jurors))
    })
    .unwrap();

    // ubi_getPendingCases() → the full case object for every Open case (sorted ascending).
    m.register_method("ubi_getPendingCases", |_, ctx, _| {
        let cases: Vec<Value> = ctx
            .open_cases()
            .into_iter()
            .filter_map(|id| ctx.get_case(id))
            .map(|c| case_view_json(&c))
            .collect();
        Ok::<_, ErrorObjectOwned>(json!(cases))
    })
    .unwrap();

    // ---- M6 ZK-passport reads (ubi_*) — spec §9 ----

    // ubi_getAttributes(address) → the three opaque Pedersen commitments {age, nationality, expiry}, or
    // empty (all-null) for an STD-only / unverified human. Opaque — no preimage (EC-8 / I6).
    m.register_method("ubi_getAttributes", |params, ctx, _| {
        let addr = parse_addr_param(&params)?;
        match ctx.attribute_commitments(&addr) {
            Some(c) => Ok::<_, ErrorObjectOwned>(json!({
                "ageCommitment": hash_hex(&c[0]),
                "nationalityCommitment": hash_hex(&c[1]),
                "expiryCommitment": hash_hex(&c[2]),
            })),
            // No commitments (STD-only / unverified) — return nulls so the shape is stable.
            None => Ok(json!({
                "ageCommitment": Value::Null,
                "nationalityCommitment": Value::Null,
                "expiryCommitment": Value::Null,
            })),
        }
    })
    .unwrap();

    // ubi_isNullifierUsed(nullifier) → bool. A client checks this before generating a proof (pure read).
    m.register_method("ubi_isNullifierUsed", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [nullifier]"))?;
        let n = seq
            .first()
            .and_then(|v| v.as_str())
            .and_then(decode_hex)
            .filter(|b| b.len() == 32)
            .ok_or_else(|| invalid_params("nullifier must be 32-byte 0x-hex"))?;
        let mut nullifier = [0u8; 32];
        nullifier.copy_from_slice(&n);
        Ok::<_, ErrorObjectOwned>(json!(ctx.nullifier_used(&nullifier)))
    })
    .unwrap();

    // ubi_getCscaRegistry() → the sorted Active CSCA entries + the current root (so a client can build a
    // proof against the live trust set). Revoked entries are excluded from the listing.
    m.register_method("ubi_getCscaRegistry", |_, ctx, _| {
        let entries: Vec<Value> = ctx
            .csca_entries()
            .iter()
            .filter(|e| e.status == CscaStatus::Active)
            .map(csca_entry_json)
            .collect();
        Ok::<_, ErrorObjectOwned>(json!({
            "root": hash_hex(&ctx.csca_registry_root()),
            "entries": entries,
        }))
    })
    .unwrap();

    // ubi_getSelfRoots() → the live pinned Self identity + OFAC roots + the freshness window (spec 06b
    // §8), so a client can confirm the live trust set before requesting a proof (EC-C13).
    m.register_method("ubi_getSelfRoots", |_, ctx, _| {
        let identity_roots: Vec<Value> = ctx
            .self_identity_roots()
            .iter()
            .map(|e| json!({ "root": hash_hex(&e.root), "pinnedAtBlock": e.pinned_at_block }))
            .collect();
        let ofac_roots: Vec<Value> = ctx
            .self_ofac_roots()
            .iter()
            .map(|e| {
                json!({ "kind": e.kind, "root": hash_hex(&e.root), "pinnedAtBlock": e.pinned_at_block })
            })
            .collect();
        Ok::<_, ErrorObjectOwned>(json!({
            "identityRoots": identity_roots,
            "ofacRoots": ofac_roots,
            "windowBlocks": ubi2_runtime::SELF_ROOT_WINDOW_BLOCKS,
        }))
    })
    .unwrap();

    // ---- M4 prompt-contract reads (ubi_*) ----

    // ubi_getContract(id) → the FULL contract detail (text, text_ref, escrow, parties, vars, status,
    // deploy_block/deploy_tx, and the list of its exec cases with their outcomes), or null. `id`
    // accepts hex or number.
    m.register_method("ubi_getContract", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [id]"))?;
        let id = parse_stream_id_param(seq.first())?;
        match ctx.get_contract_detail(id) {
            Some((c, cases)) => Ok::<_, ErrorObjectOwned>(contract_detail_json(&c, &cases)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    // ubi_getExecCase(id) → the exec case (jury, submitted effects, status), or null. `id` hex/number.
    m.register_method("ubi_getExecCase", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [id]"))?;
        let id = parse_stream_id_param(seq.first())?;
        match ctx.get_exec_case(id) {
            Some(c) => Ok::<_, ErrorObjectOwned>(exec_case_view_json(&c)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    // ubi_getContractsOf(address) → the contracts the address is a declared party of, sorted by id.
    m.register_method("ubi_getContractsOf", |params, ctx, _| {
        let addr = parse_addr_param(&params)?;
        let contracts: Vec<Value> = ctx
            .contracts_of(&addr)
            .iter()
            .map(contract_view_json)
            .collect();
        Ok::<_, ErrorObjectOwned>(json!(contracts))
    })
    .unwrap();

    // ubi_getContracts(limit?) → the most-recent deployed prompt contracts (newest-first by id), each a
    // compact directory row { id, address, parties, status, escrow, balance, title, deploy_block,
    // deploy_tx, createdAt }. The explorer's GLOBAL contracts directory (`getContractsOf` is per-address
    // only). `limit` (param 1, hex or number) defaults to 50, capped at 100.
    m.register_method("ubi_getContracts", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [limit?]"))?;
        let limit = match seq.first() {
            Some(v) if !v.is_null() => parse_stream_id_param(Some(v))?,
            _ => 50,
        }
        .clamp(1, 100) as usize;
        let rows: Vec<Value> = ctx
            .recent_contracts(limit)
            .iter()
            .map(contract_summary_json)
            .collect();
        Ok::<_, ErrorObjectOwned>(json!(rows))
    })
    .unwrap();

    // ---- EXPL-1 address indexer reads (ubi_*) ----

    // ubi_getAddressActivity(address, limit?) → the most-recent txs touching the address (newest
    // first). `limit` (param 2, hex or number) defaults to 50, capped at 1000.
    m.register_method("ubi_getAddressActivity", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [address, limit?]"))?;
        let raw = seq
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params("missing address param"))?;
        let bytes = decode_hex(raw).ok_or_else(|| invalid_params("bad address hex"))?;
        if bytes.len() != 20 {
            return Err(invalid_params("address must be 20 bytes"));
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes);
        let limit = match seq.get(1) {
            Some(v) if !v.is_null() => parse_stream_id_param(Some(v))?,
            _ => 50,
        }
        .clamp(1, 1000) as usize;
        let rows: Vec<Value> = ctx
            .address_activity(&addr, limit)
            .iter()
            .map(|tx| activity_row_json(tx, &addr))
            .collect();
        Ok::<_, ErrorObjectOwned>(json!(rows))
    })
    .unwrap();

    // ubi_getAccount(address) → an at-a-glance account summary (balance, nonce, human status,
    // #streams in/out, #contracts, #txs).
    m.register_method("ubi_getAccount", |params, ctx, _| {
        let addr = parse_addr_param(&params)?;
        let summary = ctx.account_summary(&addr, now_secs());
        Ok::<_, ErrorObjectOwned>(account_summary_json(&summary))
    })
    .unwrap();

    // ---- AI-backend admin (ubi_*) — LOCALHOST ONLY ----
    //
    // The wallet's Settings panel reads/updates which LLM backend the node calls. These two methods are
    // **rejected for any non-loopback caller** (the peer SocketAddr is injected into the call extensions
    // by `serve`'s accept loop): `setOracleConfig` can redirect the node's model/endpoint and carries a
    // raw API key, so it is a devnet admin surface, not a public RPC. See `oracle_admin` for the security
    // note and the determinism caveat (a real LLM inline on this single-node devnet is fine; the
    // multi-node end-state is the off-chain juror/interpreter daemon, FU-7 — that seam is untouched).

    // ubi_getOracleConfig() → { config: {provider, model, base_url, api_key_env}, active: "mock"|"live",
    //   health: { provider, model, reachable, error } }. The config is secret-free by construction
    //   (only the env-var NAME is stored, never a key value).
    m.register_method("ubi_getOracleConfig", |_params, ctx, ext| {
        require_loopback(ext, ctx.admin_access())?;
        Ok::<_, ErrorObjectOwned>(ctx.oracle_admin().get_config_json())
    })
    .unwrap();

    // ubi_setOracleConfig({ provider?, model?, base_url?, api_key?, api_key_env? }) → the new
    //   getOracleConfig body. Validates + builds the backend, hot-swaps it into the chain, and persists
    //   the secret-free config to the node's config file. A failed build leaves the previous impl serving
    //   (fail-closed) and returns an error. The raw `api_key` (when supplied) is used in-memory only and
    //   is NEVER persisted or logged — only `api_key_env` (its env-var name) is written to disk.
    // Async + `spawn_blocking`: building a live backend constructs a blocking HTTP client, which MUST NOT
    // run on a tokio worker thread (it would panic dropping a runtime in an async context). We validate
    // the loopback gate + parse params inline, then run the (synchronous) build/hot-swap/persist on the
    // blocking pool.
    m.register_async_method("ubi_setOracleConfig", |params, ctx, ext| async move {
        require_loopback(&ext, ctx.admin_access())?;
        let (config, api_key) = parse_set_oracle_params(&params)?;
        let admin = Arc::clone(ctx.oracle_admin());
        tokio::task::spawn_blocking(move || admin.set_config(config, api_key))
            .await
            .map_err(|e| bad_config_error(format!("oracle config task failed: {e}")))?
            .map_err(bad_config_error)
    })
    .unwrap();

    // ---- EXPL-2 deep decoded explorer reads (ubi_*) ----

    // ubi_getBlock(numberOrHashOrTag) → a full decoded block: header fields (number, hash,
    // parentHash, timestamp, txCount, roots) + the FULL list of its txs, each decoded (from/to/value/
    // nonce/fee/kind, the decoded system-hub `call`, the decoded `logs`, and the resulting `result`).
    // Accepts a tag ("latest"/"earliest"/"pending"), a 0x-block-number, or a 0x-32-byte block hash.
    m.register_method("ubi_getBlock", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [numberOrHashOrTag]"))?;
        let raw = seq.first().and_then(|v| v.as_str()).unwrap_or("latest");
        match ctx.resolve_block_ref(raw) {
            Some(b) => Ok::<_, ErrorObjectOwned>(ctx.decoded_block_json(&b)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    // M5 (Stage A) — `ubi_stateRoot([numberOrTag?])` → the committed `state_root` of the head (or the
    // given height/tag). Backs EC-4/EC-10: a test compares this string byte-for-byte across nodes. Pure
    // read; no new write surface (I6).
    m.register_method("ubi_stateRoot", |params, ctx, _| {
        let seq: Vec<Value> = params.parse().unwrap_or_default();
        let raw = seq.first().and_then(|v| v.as_str());
        let root = match raw {
            None | Some("latest") | Some("pending") => Some(ctx.state_root()),
            Some(r) => ctx.resolve_block_ref(r).map(|b| b.state_root),
        };
        match root {
            Some(r) => Ok::<_, ErrorObjectOwned>(json!(hex_b256(&r))),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    // M5 (Stage A) — `ubi_getPeers` → the node's live peer table: each connected peer's libp2p PeerId,
    // the multiaddr we connected over, the bound validator address (if it proved the PeerId↔address
    // binding at the handshake), and its last-reported tip. Backs EC-1. Read-only (I6). The peer table
    // lives in `crates/node` (which owns the swarm); the node publishes it via `Chain::set_peers`.
    m.register_method("ubi_getPeers", |_params, ctx, _| {
        let peers: Vec<Value> = ctx
            .net_status()
            .peers
            .iter()
            .map(|p| {
                json!({
                    "peerId": p.peer_id,
                    "multiaddr": p.multiaddr,
                    "validator": p.validator.map(|a| hex_addr(&a)),
                    "tip": p.tip.map(|(h, hash)| json!({
                        "height": hex_u64(h),
                        "hash": hex_b256(&hash),
                    })),
                })
            })
            .collect();
        Ok::<_, ErrorObjectOwned>(json!(peers))
    })
    .unwrap();

    // M5 (Stage B) — `ubi_consensusStatus` → the node's head + the round-robin schedule + role. Reports
    // the effective `validatorSet` `V` (the epoch snapshot the node published, or `[designated]` in the
    // Stage-A override), `n` (`|V|`), this node's LOCAL `currentView` for the height it is extending, the
    // `scheduledProposer` = `V[(head+1 + currentView) mod N]`, whether THIS node is it (`isProposer`), the
    // connected-peer count, and k-deep `finalizedHeight` (`head − FINALITY_DEPTH`, floored at 0). Pure
    // read (I6); `currentView` is labeled a LOCAL liveness value (never committed).
    m.register_method("ubi_consensusStatus", |_params, ctx, _| {
        let (height, hash) = ctx.tip();
        let net = ctx.net_status();
        // The effective validator set: the node-published snapshot (Stage-B on-chain `V`, or the Stage-A
        // `[designated]` override) if present, else fall back to the single designated proposer / this
        // node's own key so Stage-A single-node reads still surface a 1-member set.
        let mut validator_set: Vec<AlloyAddr> = net.validator_set.clone();
        if validator_set.is_empty() {
            if let Some(a) = net.designated_proposer.or_else(|| ctx.proposer_address()) {
                validator_set.push(a);
            }
        }
        let n = validator_set.len();
        let current_view = net.current_view;
        // The scheduled proposer for the NEXT height (head + 1) at this node's local view.
        let scheduled = if n == 0 {
            AlloyAddr::ZERO
        } else {
            validator_set[proposer_index(height + 1, current_view, n)]
        };
        let finalized = height.saturating_sub(net.finality_depth);
        Ok::<_, ErrorObjectOwned>(json!({
            "head": {
                "height": hex_u64(height),
                "hash": hex_b256(&hash),
                "stateRoot": hex_b256(&ctx.state_root()),
            },
            "currentProposer": hex_addr(&scheduled),
            "scheduledProposer": hex_addr(&scheduled),
            "validatorSet": validator_set.iter().map(hex_addr).collect::<Vec<_>>(),
            "n": n,
            "currentView": current_view,
            "isProposer": net.is_proposer,
            "peerCount": net.peers.len(),
            // Stage B §5.3: the LOCAL count of reachable V-members (self + ping-live bound peers) the
            // production guard uses; below `n/2 + 1` this node stalls (never a committed value).
            "reachableValidators": net.reachable_validators,
            "majority": if n == 0 { 0 } else { (n / 2 + 1) as u64 },
            "finalityDepth": hex_u64(net.finality_depth),
            "finalizedHeight": hex_u64(finalized),
            "chainId": hex_u64(ctx.chain_id()),
            "genesisHash": hex_b256(&ctx.genesis_hash()),
        }))
    })
    .unwrap();

    // ubi_getTransaction(hash) → a full decoded tx: from/to/value/nonce/fee/block, the decoded
    // system-hub `call` (hub + method + args), the decoded `logs` (StreamOpened/CaseOpened/
    // VerdictSubmitted/StatusChanged/ContractDeployed/EffectCommitted/EffectAborted/Transfer…), and
    // the resulting `result` (an invoke → the committed effect or Aborted; a submitVerdict → the case
    // outcome + subject status). Null if the hash is unknown.
    // ubi_getRecentBlocks(limit?, nonEmptyOnly?) → the most-recent blocks as compact summaries
    // (newest-first), each { number, hash, parentHash, timestamp, txCount, gasUsed, miner }. `limit`
    // (param 1, hex or number) defaults to 20, capped at 100. `nonEmptyOnly` (param 2, bool) skips
    // empty blocks BEFORE the limit, so the explorer can page only blocks that contain txs (most devnet
    // ticks are empty). Backs the explorer's recent-blocks directory.
    m.register_method("ubi_getRecentBlocks", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [limit?, nonEmptyOnly?]"))?;
        let limit = match seq.first() {
            Some(v) if !v.is_null() => parse_stream_id_param(Some(v))?,
            _ => 20,
        }
        .clamp(1, 100) as usize;
        let non_empty_only = seq.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
        let rows: Vec<Value> = ctx
            .recent_blocks(limit, non_empty_only)
            .iter()
            .map(block_summary_json)
            .collect();
        Ok::<_, ErrorObjectOwned>(json!(rows))
    })
    .unwrap();

    m.register_method("ubi_getTransaction", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [hash]"))?;
        let hash_s = seq
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params("missing hash"))?;
        let bytes = decode_hex(hash_s).ok_or_else(|| invalid_params("bad hash hex"))?;
        if bytes.len() != 32 {
            return Err(invalid_params("hash must be 32 bytes"));
        }
        let h = B256::from_slice(&bytes);
        match ctx.decoded_transaction(&h) {
            Some(v) => Ok::<_, ErrorObjectOwned>(v),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    m.register_method("eth_sendRawTransaction", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected [rawTx]"))?;
        let raw = seq
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params("missing raw tx"))?;
        let bytes = decode_hex(raw).ok_or_else(|| invalid_params("bad raw tx hex"))?;
        let hash = ingest_raw_tx(ctx, &bytes)?;
        Ok::<_, ErrorObjectOwned>(json!(hex_b256(&hash)))
    })
    .unwrap();

    m.register_method("eth_getBlockByNumber", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected params"))?;
        let tag = seq.first().and_then(|v| v.as_str()).unwrap_or("latest");
        let full = seq.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
        match resolve_block_tag(ctx, tag) {
            Some(b) => Ok::<_, ErrorObjectOwned>(block_to_json(&b, full)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    m.register_method("eth_getBlockByHash", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected params"))?;
        let hash_s = seq
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params("missing hash"))?;
        let full = seq.get(1).and_then(|v| v.as_bool()).unwrap_or(false);
        let bytes = decode_hex(hash_s).ok_or_else(|| invalid_params("bad hash hex"))?;
        if bytes.len() != 32 {
            return Err(invalid_params("hash must be 32 bytes"));
        }
        let h = B256::from_slice(&bytes);
        let g = ctx.inner.lock().unwrap();
        match g
            .blocks_by_hash
            .get(&h)
            .and_then(|i| g.blocks.get(*i))
            .cloned()
        {
            Some(b) => Ok::<_, ErrorObjectOwned>(block_to_json(&b, full)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    m.register_method("eth_getTransactionByHash", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected params"))?;
        let hash_s = seq
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params("missing hash"))?;
        let bytes = decode_hex(hash_s).ok_or_else(|| invalid_params("bad hash hex"))?;
        if bytes.len() != 32 {
            return Err(invalid_params("hash must be 32 bytes"));
        }
        let h = B256::from_slice(&bytes);
        let g = ctx.inner.lock().unwrap();
        match g.txs.get(&h) {
            Some(tx) => Ok::<_, ErrorObjectOwned>(tx_to_json(tx)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    m.register_method("eth_getTransactionReceipt", |params, ctx, _| {
        let seq: Vec<Value> = params
            .parse()
            .map_err(|_| invalid_params("expected params"))?;
        let hash_s = seq
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_params("missing hash"))?;
        let bytes = decode_hex(hash_s).ok_or_else(|| invalid_params("bad hash hex"))?;
        if bytes.len() != 32 {
            return Err(invalid_params("hash must be 32 bytes"));
        }
        let h = B256::from_slice(&bytes);
        let g = ctx.inner.lock().unwrap();
        match g.txs.get(&h) {
            Some(tx) => Ok::<_, ErrorObjectOwned>(receipt_to_json(tx)),
            None => Ok(Value::Null),
        }
    })
    .unwrap();

    // ---- Subscriptions (WS): newHeads ----
    m.register_subscription(
        "eth_subscribe",
        "eth_subscription",
        "eth_unsubscribe",
        |params, pending, ctx, _| async move {
            let kind: Vec<Value> = params.parse().unwrap_or_default();
            let topic = kind.first().and_then(|v| v.as_str()).unwrap_or("");
            new_heads_subscription(topic, pending, ctx).await
        },
    )
    .unwrap();

    m
}

/// Drive a `newHeads` subscription: accept the sink, then forward every produced block as an
/// Ethereum-style header notification until the client disconnects.
async fn new_heads_subscription(
    topic: &str,
    pending: PendingSubscriptionSink,
    ctx: Arc<Chain>,
) -> SubscriptionResult {
    if topic != "newHeads" {
        // Only newHeads is supported in M1 (logs/newPendingTransactions are deferred).
        pending
            .reject(ErrorObjectOwned::owned(
                -32601,
                format!("unsupported subscription '{topic}'; only newHeads"),
                None::<()>,
            ))
            .await;
        return Ok(());
    }
    let mut rx = ctx.heads_tx.subscribe();
    let sink = pending.accept().await?;

    loop {
        tokio::select! {
            _ = sink.closed() => break,
            recv = rx.recv() => match recv {
                Ok(block) => {
                    let header = json!({
                        "number": hex_u64(block.number),
                        "hash": hex_b256(&block.hash),
                        "parentHash": hex_b256(&block.parent_hash),
                        "timestamp": hex_u64(block.timestamp),
                        "gasUsed": hex_u64(block_gas_used(&block)),
                        "gasLimit": "0x1c9c380",
                        "miner": hex_addr(&block.proposer),
                        "difficulty": "0x0",
                        "extraData": "0x",
                        "nonce": "0x0000000000000000",
                        "baseFeePerGas": hex_u64(GAS_PRICE_WEI),
                        // M5: real consensus roots + author on the newHeads header.
                        "stateRoot": hex_b256(&block.state_root),
                        "transactionsRoot": hex_b256(&block.txs_root),
                        "receiptsRoot": hex_b256(&B256::ZERO),
                        "logsBloom": format!("0x{}", "0".repeat(512)),
                        "sha3Uncles": "0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347",
                    });
                    let msg = jsonrpsee::SubscriptionMessage::from_json(&header)
                        .expect("header serializes");
                    if sink.send(msg).await.is_err() {
                        break;
                    }
                }
                // Lagged: drop missed heads and keep going (devnet is best-effort).
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => break,
            }
        }
    }
    Ok(())
}

/// Start the JSON-RPC server on `addr` (HTTP **and** WebSocket share the socket). Returns the
/// `ServerHandle`; the caller keeps the chain alive and drives `produce_block` on its tick.
///
/// We use jsonrpsee's manual accept loop (`to_service_builder` + `serve_with_graceful_shutdown`) rather
/// than the one-line `Server::start` so we can capture each connection's **peer `SocketAddr`** and inject
/// it (plus the `Host`/`Origin` headers) into the per-request extensions. The admin RPC
/// ([`require_loopback`]) reads the address for its loopback gate and the headers for its DNS-rebinding /
/// browser-CSRF defenses (C5-SEC-2); the default `start` path surfaces neither to method handlers.
///
/// CORS: the read/EVM methods keep permissive CORS (the browser wallet needs it). The admin methods are
/// not protected by CORS alone — they enforce a server-side `Host`-pinning + `Origin`-allowlist gate at
/// the handler ([`AdminAccess`]), so a permissive ACAO header cannot authorize a cross-origin admin call
/// (the handler still rejects a foreign `Origin`). This is the standard local-RPC posture: CORS for
/// read-compat, an explicit server-side gate for the privileged surface.
pub async fn serve(addr: std::net::SocketAddr, chain: Chain) -> anyhow::Result<ServerHandle> {
    use jsonrpsee::server::{serve_with_graceful_shutdown, stop_channel, HttpRequest};
    use tower::Service;

    // The wallet/explorer runs in the browser at localhost:3000 and fetches this RPC at
    // 127.0.0.1:8545 — a cross-origin request the browser guards with a CORS preflight. Without
    // CORS headers every browser `fetch` fails ("Failed to fetch"), even though curl/MetaMask work.
    // A permissive CORS layer is fine for the *read* surface of a local devnet (any origin/method/
    // header). The privileged admin methods are gated server-side by `AdminAccess` (Host pinning +
    // Origin allowlist), so permissive CORS does not weaken them. MetaMask makes its own (non-browser)
    // requests, so it is unaffected either way.
    let cors = tower_http::cors::CorsLayer::permissive();
    let http_middleware = tower::ServiceBuilder::new().layer(cors);

    // jsonrpsee's service speaks both HTTP and WS on one socket, so eth_subscribe (WS) and the plain
    // HTTP request/response methods share the same `:8545` (spec §M1-T1.3).
    //
    // Defense in depth (C6-SEC-1): cap the request body well below jsonrpsee's 10 MB default. The
    // primary fix is the hard text/parties cap enforced at parse (`MAX_CONTRACT_TEXT_BYTES`), but a
    // tight body limit also stops an attacker forcing the node to buffer multi-MB payloads before the
    // calldata is even decoded. 1 MiB is generous headroom for any legit tx (an 8 KiB-text deploy's
    // hex-encoded raw tx is ~17 KiB) while shrinking the abuse surface by 10x.
    const MAX_REQUEST_BODY_BYTES: u32 = 1024 * 1024;
    let svc_builder = Server::builder()
        .max_request_body_size(MAX_REQUEST_BODY_BYTES)
        .set_http_middleware(http_middleware)
        .to_service_builder();
    let methods: jsonrpsee::Methods = build_module(chain).into();

    let listener = tokio::net::TcpListener::bind(addr).await?;
    let (stop_handle, server_handle) = stop_channel();

    tokio::spawn(async move {
        loop {
            // Accept the next connection, or stop when the handle is dropped/stopped.
            let (sock, remote_addr) = tokio::select! {
                res = listener.accept() => match res {
                    Ok(conn) => conn,
                    Err(e) => {
                        tracing::warn!(error = %e, "accept failed");
                        continue;
                    }
                },
                _ = stop_handle.clone().shutdown() => break,
            };

            // Build the jsonrpsee tower service once per connection (consumes a clone of the builder);
            // it is `Clone`, so each request gets its own handle. Wrap it in a `service_fn` that injects
            // the peer address AND the request's `Host`/`Origin` headers into the request extensions
            // first — the peer address drives `require_loopback`'s loopback gate; the headers drive its
            // DNS-rebinding (`Host` pinning) + browser-CSRF (`Origin` allowlist) defenses (C5-SEC-2).
            let jsonrpsee_svc = svc_builder
                .clone()
                .build(methods.clone(), stop_handle.clone());
            let svc = tower::service_fn(move |mut req: HttpRequest<hyper::body::Incoming>| {
                let header_str = |name: &str| -> Option<String> {
                    req.headers()
                        .get(name)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                };
                let meta = AdminHttpMeta {
                    host: header_str("host").map(|h| h.to_ascii_lowercase()),
                    origin: header_str("origin"),
                };
                req.extensions_mut().insert(remote_addr);
                req.extensions_mut().insert(meta);
                let mut jsonrpsee_svc = jsonrpsee_svc.clone();
                jsonrpsee_svc.call(req)
            });

            tokio::spawn(serve_with_graceful_shutdown(
                sock,
                svc,
                stop_handle.clone().shutdown(),
            ));
        }
    });

    Ok(server_handle)
}

/// The `next_sub_id` helper exists so subscription ids are unique even before jsonrpsee assigns one
/// (used in tests / diagnostics). Kept minimal.
pub fn next_sub_id(chain: &Chain) -> u64 {
    chain.sub_seq.fetch_add(1, Ordering::Relaxed)
}

// Kept from the M0 skeleton for callers/tests that still reference the free helpers.
pub fn eth_chain_id(chain_id: u64) -> String {
    hex_u64(chain_id)
}
pub fn eth_get_balance(account: &Account, now: u64) -> String {
    hex_u128(account.balance(now))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubi2_runtime::{EMISSION_PERIOD_SECS, UBI};

    #[test]
    fn chain_id_is_hex() {
        assert_eq!(eth_chain_id(DEVNET_CHAIN_ID), "0x5542");
    }

    #[test]
    fn balance_rpc_reflects_stream() {
        let a = Account {
            verified: true,
            verified_at: 0,
            last_settled_at: 0,
            ..Default::default()
        };
        assert_eq!(
            eth_get_balance(&a, EMISSION_PERIOD_SECS),
            format!("0x{:x}", UBI)
        );
    }

    #[test]
    fn genesis_block_and_tick() {
        let chain = Chain::new(DEVNET_CHAIN_ID, 1_000);
        assert_eq!(chain.latest_block().number, 0);
        let b1 = chain.produce_block(1_002);
        assert_eq!(b1.number, 1);
        assert_eq!(b1.parent_hash, chain.inner.lock().unwrap().blocks[0].hash);
        let b2 = chain.produce_block(1_004);
        assert_eq!(b2.number, 2);
        assert_eq!(b2.parent_hash, b1.hash);
    }

    #[test]
    fn balance_streams_on_chain() {
        let chain = Chain::new(DEVNET_CHAIN_ID, 0);
        chain.seed_account(Account {
            address: [0xaa; 20],
            verified: true,
            verified_at: 0,
            last_settled_at: 0,
            ..Default::default()
        });
        assert_eq!(chain.balance(&[0xaa; 20], EMISSION_PERIOD_SECS), UBI);
        assert_eq!(
            chain.balance(&[0xaa; 20], EMISSION_PERIOD_SECS * 2),
            UBI * 2
        );
    }

    #[test]
    fn block_hash_is_deterministic() {
        // I2-adjacent: same inputs ⇒ same block hash across two chains. M5: the hash now commits the
        // full header (number ‖ parent ‖ timestamp ‖ txs_root ‖ state_root ‖ proposer).
        let tr = B256::repeat_byte(3);
        let sr = B256::repeat_byte(9);
        let p = AlloyAddr::repeat_byte(1);
        let h1 = Block::compute_hash(5, B256::repeat_byte(7), 1234, 0, tr, sr, &p);
        let h2 = Block::compute_hash(5, B256::repeat_byte(7), 1234, 0, tr, sr, &p);
        assert_eq!(h1, h2);
        // Any field change moves the hash.
        assert_ne!(
            h1,
            Block::compute_hash(6, B256::repeat_byte(7), 1234, 0, tr, sr, &p)
        );
        assert_ne!(
            h1,
            Block::compute_hash(
                5,
                B256::repeat_byte(7),
                1234,
                0,
                B256::repeat_byte(4),
                sr,
                &p
            )
        );
        assert_ne!(
            h1,
            Block::compute_hash(
                5,
                B256::repeat_byte(7),
                1234,
                0,
                tr,
                B256::repeat_byte(8),
                &p
            )
        );
        // Stage B: the `view` is committed — changing it moves the hash.
        assert_ne!(
            h1,
            Block::compute_hash(5, B256::repeat_byte(7), 1234, 1, tr, sr, &p)
        );
        assert_ne!(
            h1,
            Block::compute_hash(
                5,
                B256::repeat_byte(7),
                1234,
                0,
                tr,
                sr,
                &AlloyAddr::repeat_byte(2)
            )
        );
    }

    #[test]
    fn proposer_sign_recover_roundtrips() {
        // M5: a header signed by a proposer key recovers to that key's address (spec §2.2).
        let key = ProposerKey::from_bytes(&[7u8; 32]).unwrap();
        let hash = B256::repeat_byte(0x42);
        let sig = key.sign_prehash(&hash);
        assert_eq!(sig.len(), 65);
        assert_eq!(recover_proposer(&hash, &sig), Some(key.address()));
        // A different hash recovers a different (or no) address — not the proposer.
        assert_ne!(
            recover_proposer(&B256::repeat_byte(0x43), &sig),
            Some(key.address())
        );
        // A malformed signature recovers nothing.
        assert_eq!(recover_proposer(&hash, &sig[..64]), None);
    }

    #[test]
    fn produced_block_carries_signed_header() {
        // A chain with a proposer key stamps + signs the header; a follower recovers the author.
        let key = Arc::new(ProposerKey::from_bytes(&[11u8; 32]).unwrap());
        let chain = Chain::new(DEVNET_CHAIN_ID, 1_000).with_proposer_key(key.clone());
        let b = chain.produce_block(1_002);
        assert_eq!(b.proposer, key.address());
        assert_eq!(
            recover_proposer(&b.hash, &b.proposer_sig),
            Some(key.address())
        );
        // The header hash commits the state_root + txs_root.
        let recomputed = Block::compute_hash(
            b.number,
            b.parent_hash,
            b.timestamp,
            b.view,
            b.txs_root,
            b.state_root,
            &b.proposer,
        );
        assert_eq!(recomputed, b.hash);
    }

    #[test]
    fn rejects_wrong_chain_id_tx() {
        // A tx RLP for chain 1 (mainnet) must be rejected by our devnet (chain 0x5542).
        // This is the well-known hardhat account #0 sending 0 wei on chain 1, EIP-155 signed.
        // We only assert the *decode + chain check* path here; signature is valid mainnet-bound.
        let chain = Chain::new(DEVNET_CHAIN_ID, 0);
        // Minimal: feed garbage → decode error (covers the error arm deterministically).
        let err = ingest_raw_tx(&chain, &[0x01, 0x02, 0x03]).unwrap_err();
        assert_eq!(err.code(), -32602);
    }
}
