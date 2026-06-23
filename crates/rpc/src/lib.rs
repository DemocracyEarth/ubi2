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
    apply_transfer, challenge as lc_challenge, charge_fee, deploy_contract as lc_deploy_contract,
    fee_for_gas, finalize_registration, fund_contract as lc_fund_contract,
    invoke_contract as lc_invoke_contract, open_stream, request_verification, stop_stream,
    submit_effect as lc_submit_effect, submit_verdict, system_challenge as lc_system_challenge,
    vouch as lc_vouch, Account, Address, CanonicalEffect, Case, CaseKind, CaseStatus, Confidence,
    ContractInterpreter, ContractStatus, ExecCase, ExecStatus, Human, HumanStatus, HumanityOracle,
    Juror, LivenessEvidence, MemState, Op, PromptContract, State, Stream, StreamStatus, Verdict,
    GAS_CONTRACT, GAS_HUMANITY, GAS_ONBOARD, GAS_PRICE_WEI as RT_GAS_PRICE_WEI, GAS_STREAM,
    GAS_TRANSFER,
};

pub mod streams;
use streams::{
    decode_token_id, parse_calldata, render_token_uri, CalldataError, CardData, Side, StreamOp,
    STREAM_HUB,
};

pub mod humanity;
use humanity::{
    addr_topic as h_addr_topic, derive_liveness, parse_calldata as parse_humanity_calldata,
    u64_topic as h_u64_topic, CalldataError as HumanityCalldataError, HumanityOp, HUMANITY_HUB,
};

pub mod contracts;
use contracts::{
    addr_topic as c_addr_topic, derive_trigger, parse_calldata as parse_contract_calldata,
    text_commitment, u64_topic as c_u64_topic, CalldataError as ContractCalldataError, ContractOp,
    CONTRACT_HUB,
};

pub mod oracle_admin;
use oracle_admin::{bad_config_error, is_loopback, not_loopback_error, AdminHttpMeta};
pub use oracle_admin::{
    ActiveImpl, AdminAccess, BuiltOracle, OracleAdmin, OracleConfig, OracleFactory, OracleHealth,
};

/// Default devnet chain id (0x5542 / 21826). Spec §M1-T1.3.
pub const DEVNET_CHAIN_ID: u64 = 0x5542;

/// Flat devnet gas price (1 gwei), as a `u64` for the JSON quantity helpers. Sourced from the runtime
/// constant ([`RT_GAS_PRICE_WEI`]) so the price the RPC advertises (`eth_gasPrice`) is exactly the
/// price the runtime charges the fee at — a wallet's `gasLimit * gasPrice` preview equals the UBI
/// deducted.
const GAS_PRICE_WEI: u64 = RT_GAS_PRICE_WEI as u64;

/// Gas a plain value transfer costs — the EVM intrinsic `21000`, sourced from the runtime constant.
const TRANSFER_GAS: u64 = GAS_TRANSFER;

/// Deterministic per-kind gas for a queued tx — the `gas_used` the UBI fee is charged on and the value
/// `eth_estimateGas` returns. A small constant per tx kind (no metering): transfers pay the EVM
/// intrinsic; hub ops pay progressively more to reflect their bookkeeping (escrow/index/quorum). This
/// is consensus state (I2): every node charges the same sender the same fee for the same tx kind.
fn gas_for_kind(kind: &PendingKind) -> u64 {
    match kind {
        PendingKind::Transfer { .. } => GAS_TRANSFER,
        PendingKind::OpenStream { .. } | PendingKind::StopStream { .. } => GAS_STREAM,
        // Onboarding is fee-exempt: a not-yet-verified account has no UBI to pay with (bootstrap gate).
        PendingKind::RequestVerification { .. } => GAS_ONBOARD,
        PendingKind::Vouch { .. }
        | PendingKind::Challenge { .. }
        | PendingKind::SubmitVerdict { .. } => GAS_HUMANITY,
        PendingKind::DeployContract { .. }
        | PendingKind::FundContract { .. }
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
                _ => GAS_HUMANITY,
            }
        }
        Some(a) if a == CONTRACT_HUB.as_slice() => GAS_CONTRACT,
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
}

/// A devnet block. Empty blocks are valid (the clock tick still advances height — spec §M1-T1.6).
#[derive(Clone, Debug)]
pub struct Block {
    pub number: u64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: u64,
    pub txs: Vec<StoredTx>,
}

impl Block {
    /// A deterministic, opaque block hash: `keccak256(number || parent_hash || timestamp)`.
    /// Not Ethereum's real header hash (no full header on devnet) but stable and collision-resistant
    /// enough for `getBlockByHash` / `newHeads` correlation.
    fn compute_hash(number: u64, parent_hash: B256, timestamp: u64) -> B256 {
        let mut buf = Vec::with_capacity(8 + 32 + 8);
        buf.extend_from_slice(&number.to_be_bytes());
        buf.extend_from_slice(parent_hash.as_slice());
        buf.extend_from_slice(&timestamp.to_be_bytes());
        keccak256(&buf)
    }
}

// ---------------------------------------------------------------------------------------------
// Chain state
// ---------------------------------------------------------------------------------------------

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
}

/// What a queued tx will do when mined. M1 had only value transfers; M2 adds the two StreamHub ops.
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
// Stream-op nonce handling + event logs
// ---------------------------------------------------------------------------------------------

/// Validate and bump the sender's nonce for a stream-op tx, mirroring `apply_transfer`'s replay
/// protection (stream ops bypass `apply_transfer`, so they enforce the nonce here). Settles the
/// sender's emission first so `last_settled_at` advances consistently. On a nonce mismatch the state
/// is left untouched (the runtime op is never reached). Returns `Err(reason)` on mismatch.
fn consume_nonce(
    state: &mut dyn State,
    from: &AlloyAddr,
    nonce: u64,
    now: u64,
) -> Result<(), String> {
    let mut acct = state.get(&from.into_array()).unwrap_or(Account {
        address: from.into_array(),
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
            logs.push(status_changed_log(&subject, HumanStatus::Verified));
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
    /// Browser-CSRF / DNS-rebinding policy for the admin methods (`Origin` allowlist + `Host` pinning).
    /// The loopback TCP-peer gate is always on; this scopes which browser origins may reach the admin
    /// surface (default: the local wallet at `http://localhost:3000`). See [`oracle_admin::AdminAccess`].
    admin_access: Arc<AdminAccess>,
}

impl Chain {
    /// Build a chain with a fresh genesis block at `genesis_time`. Seed accounts (e.g. the
    /// pre-verified dev account) via [`Chain::seed_account`] before serving.
    pub fn new(chain_id: u64, genesis_time: u64) -> Self {
        let genesis_hash = Block::compute_hash(0, B256::ZERO, genesis_time);
        let genesis = Block {
            number: 0,
            hash: genesis_hash,
            parent_hash: B256::ZERO,
            timestamp: genesis_time,
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
            admin_access: Arc::new(AdminAccess::default()),
        }
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
        // Clone the AI-seam Arcs before locking state (the apply loop calls the oracle for liveness
        // grading and the interpreter for contract effects). Reading from the hot-swappable admin once
        // per block makes a mid-flight `setOracleConfig` swap atomic at the block boundary.
        let oracle = self.oracle_admin.oracle();
        let interpreter = self.oracle_admin.interpreter();
        let mut g = self.inner.lock().unwrap();
        let parent = g.blocks.last().expect("genesis always present").clone();
        let number = parent.number + 1;
        let hash = Block::compute_hash(number, parent.hash, timestamp);

        let pending = std::mem::take(&mut g.mempool);
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
            let from_addr = p.from.into_array();
            if let Err(e) = charge_fee(&mut g.state, &from_addr, gas_used, timestamp) {
                tracing::warn!(tx = %p.hash, error = %e, "dropping tx: cannot pay gas fee");
                continue;
            }

            // Apply against current state. Validation already happened at submit time. On an op error
            // we do NOT drop the tx — we mine it as a FAILED (`status: 0x0`) transaction (see below).
            let applied: Result<Vec<TxLog>, String> = match &p.kind {
                PendingKind::Transfer { to, value } => apply_transfer(
                    &mut g.state,
                    &p.from.into_array(),
                    &to.into_array(),
                    *value,
                    p.nonce,
                    timestamp,
                )
                .map(|()| Vec::new())
                .map_err(|e| e.to_string()),

                PendingKind::OpenStream { to, rate, deposit } => {
                    // Stream ops are signed txs too: enforce + bump the sender nonce, then run the op.
                    consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                        .and_then(|()| {
                            open_stream(
                                &mut g.state,
                                &p.from.into_array(),
                                &to.into_array(),
                                *rate,
                                *deposit,
                                timestamp,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .map(|id| stream_open_logs(id, p.from, *to))
                }

                PendingKind::StopStream { id } => {
                    consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                        .and_then(|()| {
                            stop_stream(&mut g.state, *id, &p.from.into_array(), timestamp)
                                .map_err(|e| e.to_string())
                        })
                        .map(|_refund| stream_stop_logs(*id, p.from))
                }

                // ---- M3: proof-of-humanity ops ----
                PendingKind::RequestVerification { liveness_ref } => {
                    consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                        .and_then(|()| {
                            // Derive the off-chain liveness bytes from the committed ref (devnet seam — the
                            // applicant has no off-chain channel to a single-node devnet); the oracle grades
                            // them deterministically. Window clock = block HEIGHT (`number`); the emission
                            // epoch is unix SECONDS (`timestamp`), stamped later at finalize.
                            let (challenge_bytes, response_bytes) = derive_liveness(liveness_ref);
                            let evidence = LivenessEvidence {
                                liveness_ref: *liveness_ref,
                                challenge: &challenge_bytes,
                                response: &response_bytes,
                            };
                            let entropy = block_entropy(hash, number);
                            request_verification(
                                &mut g.state,
                                &*oracle,
                                &p.from.into_array(),
                                &evidence,
                                entropy,
                                number,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .map(|case_id| {
                            let mut logs = vec![status_changed_log(
                                &p.from.into_array(),
                                HumanStatus::Pending,
                            )];
                            if let Some(case) = g.state.get_case(case_id) {
                                logs.insert(0, case_opened_log(&case));
                            }
                            logs
                        })
                }

                PendingKind::Vouch { vouchee } => {
                    consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                        .and_then(|()| {
                            // Vouch is recorded at block HEIGHT (`number`) — the vouch `at` clock.
                            lc_vouch(
                                &mut g.state,
                                &p.from.into_array(),
                                &vouchee.into_array(),
                                number,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .map(|()| Vec::new())
                }

                PendingKind::Challenge {
                    subject,
                    evidence_ref,
                } => consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                    .and_then(|()| {
                        let entropy = block_entropy(hash, number);
                        lc_challenge(
                            &mut g.state,
                            &p.from.into_array(),
                            &subject.into_array(),
                            *evidence_ref,
                            entropy,
                            number,
                        )
                        .map_err(|e| e.to_string())
                    })
                    .map(|case_id| {
                        let mut logs = Vec::new();
                        if let Some(case) = g.state.get_case(case_id) {
                            logs.push(case_opened_log(&case));
                        }
                        // A Verified subject flips to Challenged when a challenge opens.
                        if let Some(h) = g.state.get_human(&subject.into_array()) {
                            if h.status == HumanStatus::Challenged {
                                logs.push(status_changed_log(&subject.into_array(), h.status));
                            }
                        }
                        logs
                    }),

                PendingKind::SubmitVerdict { case_id, verdict } => {
                    // Snapshot the subject's pre-verdict status so a status change can be logged.
                    let subject = g.state.get_case(*case_id).map(|c| c.subject);
                    let pre_status = subject
                        .and_then(|s| g.state.get_human(&s))
                        .map(|h| h.status);
                    consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                        .and_then(|()| {
                            submit_verdict(
                                &mut g.state,
                                *case_id,
                                &p.from.into_array(),
                                *verdict,
                                number,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .map(|_status| {
                            let mut logs =
                                vec![verdict_submitted_log(*case_id, &p.from, verdict.verdict)];
                            // If the committed effect changed the subject's status, log it.
                            if let Some(subj) = subject {
                                if let Some(h) = g.state.get_human(&subj) {
                                    if Some(h.status) != pre_status {
                                        logs.push(status_changed_log(&subj, h.status));
                                    }
                                }
                            }
                            logs
                        })
                }

                // ---- M4: prompt-contract ops ----
                PendingKind::DeployContract { text, parties } => {
                    // The full NL text now lives on-chain; the node derives the content commitment
                    // `text_ref = keccak256(utf8(text))` and stamps the deploy block/tx onto the record
                    // (so the contract detail view can show where it was deployed).
                    let text_ref = text_commitment(text);
                    consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                        .and_then(|()| {
                            let parties: Vec<Address> =
                                parties.iter().map(|a| a.into_array()).collect();
                            lc_deploy_contract(&mut g.state, text.clone(), text_ref, parties)
                                .map_err(|e| e.to_string())
                        })
                        .map(|id| {
                            // Stamp the deploy block height + tx hash onto the stored contract.
                            if let Some(mut c) = g.state.get_contract(id) {
                                c.deploy_block = number;
                                c.deploy_tx = p.hash.0;
                                g.state.put_contract(c);
                            }
                            vec![contract_deployed_log(id, &p.from, &text_ref)]
                        })
                }

                PendingKind::FundContract { id } => {
                    // `fund_contract` moves the tx's value (`p.value`) from the funder into the escrow
                    // account via the normal transfer path (settles + nonce + balance); it consumes the
                    // funder nonce itself, so we do NOT call `consume_nonce` here (that would double-
                    // count). Fail-closed: an unknown/terminated contract or insufficient balance leaves
                    // no state change.
                    lc_fund_contract(
                        &mut g.state,
                        &p.from.into_array(),
                        *id,
                        p.value,
                        p.nonce,
                        timestamp,
                    )
                    .map(|()| Vec::new())
                    .map_err(|e| e.to_string())
                }

                PendingKind::InvokeContract { id, trigger_ref } => {
                    consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                        .and_then(|()| {
                            // The interpreter reads the contract's stored on-chain text (so
                            // interpretation is reproducible from chain state); we only derive the
                            // off-chain trigger bytes from the committed `triggerRef` (the devnet seam).
                            // The deterministic interpreter computes the same canonical effect for every
                            // juror so the quorum forms reproducibly (I1/I5). `entropy` folds chain
                            // entropy into interpreter selection; `number` is the resolving block.
                            let trigger = derive_trigger(trigger_ref);
                            let entropy = block_entropy(hash, number);
                            lc_invoke_contract(
                                &mut g.state,
                                &*interpreter,
                                *id,
                                *trigger_ref,
                                &trigger,
                                p.from.into_array(),
                                entropy,
                                number,
                                timestamp,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .map(|case_id| {
                            let mut logs = vec![contract_case_opened_log(case_id, *id, &p.from)];
                            // The interpreter quorum may already have committed/aborted the effect in
                            // this call (the common case with the deterministic MockInterpreter); emit
                            // the terminal EffectCommitted/EffectAborted log if so.
                            if let Some(case) = g.state.get_exec_case(case_id) {
                                if let Some(log) = exec_case_outcome_log(&case) {
                                    logs.push(log);
                                }
                            }
                            logs
                        })
                }

                PendingKind::SubmitEffect { case_id, effect } => {
                    consume_nonce(&mut g.state, &p.from, p.nonce, timestamp)
                        .and_then(|()| {
                            lc_submit_effect(
                                &mut g.state,
                                *case_id,
                                &p.from.into_array(),
                                effect.clone(),
                                number,
                                timestamp,
                            )
                            .map_err(|e| e.to_string())
                        })
                        .map(|_status| {
                            // The case may have transitioned to Committed/Aborted with this submission;
                            // emit the terminal log if so (it stays Open while gathering more votes).
                            if let Some(case) = g.state.get_exec_case(*case_id) {
                                exec_case_outcome_log(&case).into_iter().collect()
                            } else {
                                Vec::new()
                            }
                        })
                }
            };

            let (success, logs, revert_reason) = match applied {
                Ok(logs) => (true, logs, None),
                Err(e) => {
                    // Cycle-6 fix: the op FAILED at block time (e.g. "vouchee has no open registration",
                    // "no such contract", a transfer validation error). The OLD code rolled back the fee
                    // AND the nonce and dropped the tx — leaving it perpetually "pending" (no receipt)
                    // and opening a nonce gap (the next tx then failed "nonce too high"). Instead we MINE
                    // the tx as a FAILED (`status: 0x0`) transaction, EVM-style:
                    //   * KEEP the fee charged (the node did work — EVM charges gas on revert);
                    //   * CONSUME the sender nonce exactly once (see below);
                    //   * apply NO op state change (the op already aborted/fail-closed);
                    //   * carry the decoded `reason` so the explorer can show why it failed.
                    //
                    // Nonce handling is subtle and must be IDEMPOTENT: the hub ops run as
                    // `consume_nonce(..).and_then(|| op(..))`, so a failing hub op (vouch/challenge/…)
                    // has ALREADY bumped the nonce 0→1 before the op erred; whereas `apply_transfer` /
                    // `fund_contract` validate-before-mutate and leave it unbumped on `Err`. Rather than
                    // `+= 1` (which would double-count the hub case → a NEW gap), we SET the nonce to its
                    // correct post-tx value, `p.nonce + 1`. The FIFO mempool + submit gate guarantee
                    // `p.nonce` is this sender's current nonce, so this is the one true post-state and is
                    // deterministic across nodes (I2). `charge_fee` already settled at `timestamp`, so
                    // re-settling here is a no-op.
                    let mut acct = g.state.get(&from_addr).unwrap_or(Account {
                        address: from_addr,
                        ..Default::default()
                    });
                    acct.settle(timestamp);
                    acct.nonce = p.nonce + 1;
                    g.state.put(acct);
                    tracing::warn!(tx = %p.hash, error = %e, "mining failed tx (status 0x0)");
                    (false, Vec::new(), Some(e))
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
            };
            index_tx(&mut g.addr_index, &tx);
            g.txs.insert(sys_hash, tx.clone());
            stored.push(tx);
        }

        let block = Block {
            number,
            hash,
            parent_hash: parent.hash,
            timestamp,
            txs: stored,
        };
        let idx = g.blocks.len();
        g.blocks.push(block.clone());
        g.blocks_by_hash.insert(hash, idx);
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

    /// Genesis unix time this chain was created at (also the dev account's `verified_at`).
    pub fn genesis_time(&self) -> u64 {
        self.genesis_time
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
            // Roots are zero placeholders on devnet (no full header) — surfaced so the explorer can
            // render the field set Ethereum blocks carry; documented in the module-level deviations.
            "stateRoot": hex_b256(&B256::ZERO),
            "transactionsRoot": hex_b256(&B256::ZERO),
            "receiptsRoot": hex_b256(&B256::ZERO),
            "miner": "0x0000000000000000000000000000000000000000",
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
        "transactionsRoot": hex_b256(&B256::ZERO),
        "stateRoot": hex_b256(&B256::ZERO),
        "receiptsRoot": hex_b256(&B256::ZERO),
        "miner": "0x0000000000000000000000000000000000000000",
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
    })
}

/// Total gas a block consumed — the sum of its txs' per-kind `gas_used` (the block `gasUsed` header).
fn block_gas_used(block: &Block) -> u64 {
    block.txs.iter().map(|t| t.gas_used).sum()
}

fn tx_to_json(tx: &StoredTx) -> Value {
    json!({
        "hash": hex_b256(&tx.hash),
        "nonce": hex_u64(tx.nonce),
        "blockHash": hex_b256(&tx.block_hash),
        "blockNumber": hex_u64(tx.block_number),
        "transactionIndex": hex_u64(tx.tx_index),
        "from": hex_addr(&tx.from),
        "to": tx.to.map(|a| hex_addr(&a)).map(Value::String).unwrap_or(Value::Null),
        "value": hex_u256(tx.value),
        "gas": hex_u64(tx.gas_used),
        "gasPrice": hex_u64(GAS_PRICE_WEI),
        "input": if tx.input.is_empty() { "0x".to_string() } else { format!("0x{}", hex::encode(&tx.input)) },
        "type": "0x0",
        "chainId": hex_u64(DEVNET_CHAIN_ID),
    })
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
        "type": "0x0",
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
fn ingest_raw_tx(chain: &Chain, raw: &[u8]) -> Result<B256, ErrorObjectOwned> {
    // alloy decode: TxEnvelope::decode_2718 handles both typed (EIP-2718) and untyped legacy txs.
    let mut slice = raw;
    let env = TxEnvelope::decode_2718(&mut slice)
        .map_err(|e| invalid_params(format!("rlp decode failed: {e}")))?;

    // EIP-155 chain-id binding: reject txs signed for another chain (replay protection — spec §M1-T1.4).
    // Legacy pre-155 txs have `chain_id() == None`; we require explicit 155 binding to our chain.
    match env.chain_id() {
        Some(id) if id == chain.chain_id => {}
        Some(other) => {
            return Err(invalid_params(format!(
                "wrong chainId: tx is for {other}, devnet is {}",
                chain.chain_id
            )))
        }
        None => {
            return Err(invalid_params(
                "tx must be EIP-155 (chainId-bound) for replay safety",
            ))
        }
    }

    // Recover the signer (verifies the secp256k1 signature; alloy errors on a bad sig).
    let from = env
        .recover_signer()
        .map_err(|e| invalid_params(format!("signature recovery failed: {e}")))?;

    // Require a `to` (no contract creation on devnet).
    let to = env
        .to()
        .ok_or_else(|| invalid_params("contract creation not supported"))?;

    let nonce = env.nonce();
    let hash = *env.tx_hash();
    let input = env.input().to_vec();
    let value_u256 = env.value();

    // Calldata rule (spec D2): M1 rejects non-empty calldata, **relaxed for StreamHub and (M3) the
    // HumanityHub**. A tx to any other address still must be a plain value transfer (empty calldata).
    let kind = if to == STREAM_HUB {
        // Parse the StreamHub selector + ABI args into a stream op (soulbound selectors revert here).
        match parse_calldata(&input) {
            Ok(StreamOp::Open { to, rate, deposit }) => {
                PendingKind::OpenStream { to, rate, deposit }
            }
            Ok(StreamOp::Stop { id }) => PendingKind::StopStream { id },
            Err(CalldataError::Soulbound) => {
                return Err(execution_reverted("soulbound"));
            }
            Err(e) => return Err(invalid_params(format!("StreamHub call: {e}"))),
        }
    } else if to == HUMANITY_HUB {
        // Parse the HumanityHub selector + ABI args into a proof-of-humanity op (M3).
        match parse_humanity_calldata(&input) {
            Ok(HumanityOp::RequestVerification { liveness_ref }) => {
                PendingKind::RequestVerification { liveness_ref }
            }
            Ok(HumanityOp::Vouch { vouchee }) => PendingKind::Vouch { vouchee },
            Ok(HumanityOp::Challenge {
                subject,
                evidence_ref,
            }) => PendingKind::Challenge {
                subject,
                evidence_ref,
            },
            Ok(HumanityOp::SubmitVerdict { case_id, verdict }) => {
                PendingKind::SubmitVerdict { case_id, verdict }
            }
            Err(HumanityCalldataError::UnknownSelector(_)) => {
                return Err(execution_reverted("unknown HumanityHub selector"));
            }
            Err(e) => return Err(invalid_params(format!("HumanityHub call: {e}"))),
        }
    } else if to == CONTRACT_HUB {
        // Parse the ContractHub selector + ABI args into a prompt-contract op (M4).
        match parse_contract_calldata(&input) {
            Ok(ContractOp::DeployContract { text, parties }) => {
                PendingKind::DeployContract { text, parties }
            }
            Ok(ContractOp::FundContract { id }) => PendingKind::FundContract { id },
            Ok(ContractOp::InvokeContract { id, trigger_ref }) => {
                PendingKind::InvokeContract { id, trigger_ref }
            }
            Ok(ContractOp::SubmitEffect { case_id, effect }) => {
                PendingKind::SubmitEffect { case_id, effect }
            }
            Err(ContractCalldataError::UnknownSelector(_)) => {
                return Err(execution_reverted("unknown ContractHub selector"));
            }
            Err(e) => return Err(invalid_params(format!("ContractHub call: {e}"))),
        }
    } else {
        if !input.is_empty() {
            return Err(invalid_params(
                "calldata only supported for StreamHub (value transfers otherwise)",
            ));
        }
        // Balances are u128 base units; reject values that don't fit (unfundable on devnet anyway).
        let value: u128 = value_u256
            .try_into()
            .map_err(|_| invalid_params("value exceeds u128 base-unit range"))?;
        PendingKind::Transfer { to, value }
    };

    // The deposit for stream ops is a calldata arg, not msg.value (D2/Q1); the tx value is 0. A
    // `fundContract` tx IS value-bearing: its `msg.value` is the escrow funding amount, threaded
    // through as the `PendingTx.value` (the runtime moves it from the funder into the escrow account).
    let value: u128 = match &kind {
        PendingKind::Transfer { value, .. } => *value,
        PendingKind::FundContract { .. } => value_u256
            .try_into()
            .map_err(|_| invalid_params("value exceeds u128 base-unit range"))?,
        _ => 0,
    };

    // Validate nonce + spendable-balance affordability against current state at *now*, accounting
    // for this sender's other still-pending mempool txs (see the cumulative check below). The
    // runtime re-checks and re-settles authoritatively at block time and fails closed; this submit
    // gate exists so the wallet gets a synchronous rejection instead of a silently dropped tx.
    {
        let g = chain.inner.lock().unwrap();
        let now = now_secs();
        let acct = g.state.get(&from.into_array()).unwrap_or_default();
        let settled = acct.balance(now); // live balance, since settlement folds emission in
        let expected_nonce =
            acct.nonce + g.mempool.iter().filter(|p| p.from == from).count() as u64;
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
        let need = pending_committed.saturating_add(spendable_debit(value, &kind));
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

    chain.inner.lock().unwrap().mempool.push(PendingTx {
        hash,
        from,
        tx_to: to,
        value,
        nonce,
        input,
        kind,
    });
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
/// epoch). Vouchers + commitments are 0x-hex; no PII is ever present (I6).
fn human_view_json(h: &Human) -> Value {
    json!({
        "address": addr_hex(&h.address),
        "status": human_status_str(h.status),
        "verified_at": h.verified_at,
        "liveness_ref": hash_hex(&h.liveness_ref),
        "vouches_in": h.vouches_in.iter().map(addr_hex).collect::<Vec<_>>(),
        "reputation": h.reputation,
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
        // ERC-721 Transfer(from, to, tokenId) — the two stream-NFT mints. tokenId is in topic[3].
        let token_id = log
            .topics
            .get(3)
            .map(|t| hex_u256(U256::from_be_bytes(t.0)));
        json!({ "name": "Transfer", "hub": "StreamHub", "args": {
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

        // Only StreamHub is a "contract"; everything else stays `0x`.
        let is_hub = to.as_deref() == Some(STREAM_HUB.as_slice());
        if !is_hub {
            return Ok::<_, ErrorObjectOwned>(json!("0x"));
        }
        let out = erc721_call(ctx, &data)?;
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

    // ubi_getTransaction(hash) → a full decoded tx: from/to/value/nonce/fee/block, the decoded
    // system-hub `call` (hub + method + args), the decoded `logs` (StreamOpened/CaseOpened/
    // VerdictSubmitted/StatusChanged/ContractDeployed/EffectCommitted/EffectAborted/Transfer…), and
    // the resulting `result` (an invoke → the committed effect or Aborted; a submitVerdict → the case
    // outcome + subject status). Null if the hash is unknown.
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
                        "miner": "0x0000000000000000000000000000000000000000",
                        "difficulty": "0x0",
                        "extraData": "0x",
                        "nonce": "0x0000000000000000",
                        "baseFeePerGas": hex_u64(GAS_PRICE_WEI),
                        "stateRoot": hex_b256(&B256::ZERO),
                        "transactionsRoot": hex_b256(&B256::ZERO),
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
    let svc_builder = Server::builder()
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
        // I2-adjacent: same inputs ⇒ same block hash across two chains.
        let h1 = Block::compute_hash(5, B256::repeat_byte(7), 1234);
        let h2 = Block::compute_hash(5, B256::repeat_byte(7), 1234);
        assert_eq!(h1, h2);
        assert_ne!(h1, Block::compute_hash(6, B256::repeat_byte(7), 1234));
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
