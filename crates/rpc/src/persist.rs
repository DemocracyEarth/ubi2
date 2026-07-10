//! M5 (Stage A, FU-3) — **chain persistence** behind the existing `State` trait.
//!
//! A node must be able to stop and restart from a data dir and come back up at the **same tip with the
//! same `state_root`** (the Phase-1 acceptance bar), and a joining node must be replayable from genesis
//! (Stage A sync, later phase). This module serializes the full chain — every block header (incl. the
//! M5 `txs_root`/`state_root`/`proposer`/`proposer_sig` fields) and ordered tx, plus the **entire**
//! canonicalized `MemState` (accounts, streams, the PoH registry, the prompt-contract registry, and the
//! id counters) — to a single JSON snapshot, and reloads it deterministically.
//!
//! ## Why a full snapshot (not a re-execute-from-genesis on restart)
//! The runtime state transition is deterministic, so the persisted `(blocks, state)` pair *is* the
//! canonical state; loading it directly is sound (a node trusts its own on-disk data) and avoids re-
//! running the AI seam on restart. Re-execution from genesis is reserved for the **sync** path (a
//! joining node that does not yet trust a snapshot), which re-validates each block to a byte-identical
//! `state_root` (spec §4.2) — a later Stage-A phase.
//!
//! ## Determinism + atomicity
//! - Every collection is serialized in its **canonical sorted order** (the same `State` accessors the
//!   `state_root` uses), so the on-disk bytes are themselves deterministic and a snapshot taken on two
//!   equal states is byte-identical.
//! - The write is **atomic**: the snapshot is written to a temp file in the same dir and `rename`d over
//!   the target, so a crash mid-write never leaves a torn snapshot (the old one survives).
//! - Round-trip is **lossless**: `save(load(x)) == x` and `state_root(load(save(s))) == state_root(s)`.
//!
//! This module owns only (de)serialization + atomic file IO; the node ([`crates/node`]) decides *when*
//! to snapshot (on each block / on shutdown) and *where* the data dir is.

use std::io::Write;
use std::path::{Path, PathBuf};

use alloy_primitives::{Address as AlloyAddr, B256, U256};
use serde::{Deserialize, Serialize};

use ubi2_runtime::{
    Account, Assurance, CanonicalEffect, CanonicalVerdict, Case, CaseKind, CaseStatus, Confidence,
    ContractStatus, CscaEntry, CscaStatus, ExecCase, ExecStatus, Human, HumanStatus, Juror,
    MemState, Op, PromptContract, State, Stream, StreamStatus, Verdict,
};

use crate::{Block, Chain, StoredTx, TxLog};

/// The on-disk snapshot version. Bumped if the schema changes (a future load can refuse / migrate).
const SNAPSHOT_VERSION: u32 = 1;

/// The snapshot file name within the data dir.
pub const SNAPSHOT_FILE: &str = "chain.json";

// ---------------------------------------------------------------------------------------------
// Serde DTOs — runtime/rpc types are not `serde`, so we map them to plain, hex-encoded DTOs. Byte
// arrays are lowercase hex (no `0x`); integers are decimal strings for `u128`/`U256` (JSON numbers
// can't hold > 2^53) and plain numbers for `u64`.
// ---------------------------------------------------------------------------------------------

fn hex20(a: &[u8; 20]) -> String {
    hex_encode(a)
}
fn hex32(h: &[u8; 32]) -> String {
    hex_encode(h)
}
fn unhex20(s: &str) -> [u8; 20] {
    let mut out = [0u8; 20];
    hex_decode_into(s, &mut out);
    out
}
fn unhex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex_decode_into(s, &mut out);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap());
    }
    s
}
fn hex_decode_into(s: &str, out: &mut [u8]) {
    let bytes = s.as_bytes();
    for (i, slot) in out.iter_mut().enumerate() {
        let hi = (bytes[i * 2] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (bytes[i * 2 + 1] as char).to_digit(16).unwrap_or(0) as u8;
        *slot = (hi << 4) | lo;
    }
}
fn hex_decode_vec(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    let mut i = 0;
    while i + 1 < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16).unwrap_or(0) as u8;
        let lo = (bytes[i + 1] as char).to_digit(16).unwrap_or(0) as u8;
        out.push((hi << 4) | lo);
        i += 2;
    }
    out
}

#[derive(Serialize, Deserialize)]
struct AccountDto {
    address: String,
    verified: bool,
    verified_at: u64,
    settled_balance: String,
    last_settled_at: u64,
    nonce: u64,
}

#[derive(Serialize, Deserialize)]
struct StreamDto {
    id: u64,
    from: String,
    to: String,
    rate: String,
    deposit: String,
    drawn: String,
    started_at: u64,
    /// 0 = Active, 1 = Stopped(at), 2 = Completed.
    status: u8,
    stopped_at: u64,
}

#[derive(Serialize, Deserialize)]
struct VerdictDto {
    /// 0 Human, 1 Sybil, 2 Uncertain.
    verdict: u8,
    /// 0 Low, 1 Med, 2 High.
    confidence: u8,
    reasons_hash: String,
}

#[derive(Serialize, Deserialize)]
struct HumanDto {
    address: String,
    /// 0 Unverified, 1 Pending, 2 Verified, 3 Challenged, 4 Revoked.
    status: u8,
    verified_at: u64,
    liveness_ref: String,
    vouches_in: Vec<String>,
    reputation: i64,
    /// M6: 0 STD, 1 ENH, 2 DUAL. `#[serde(default)]` keeps pre-M6 snapshots loadable — they default to
    /// STD (the additive-field migration, spec §5.6).
    #[serde(default)]
    assurance: u8,
}

/// M6: a CSCA trust-anchor entry on disk (spec §7.2).
#[derive(Serialize, Deserialize)]
struct CscaDto {
    country_code: String,
    key_id: String,
    pubkey: String,
    added_at: u64,
    /// 0 Active, 1 Revoked.
    status: u8,
}

/// M6 Stage C: an accepted Self identity root on disk (spec 06b §2.2).
#[derive(Serialize, Deserialize)]
struct SelfIdentityRootDto {
    root: String,
    pinned_at_block: u64,
}

/// M6 Stage C: an accepted Self OFAC SMT root on disk (spec 06b §2.2).
#[derive(Serialize, Deserialize)]
struct SelfOfacRootDto {
    kind: u8,
    root: String,
    pinned_at_block: u64,
}

#[derive(Serialize, Deserialize)]
struct CaseDto {
    id: u64,
    subject: String,
    challenger: String,
    /// 0 Registration, 1 Challenge.
    kind: u8,
    evidence_ref: String,
    jury: Vec<String>,
    votes: Vec<(String, VerdictDto)>,
    /// 0 Open, 1 Committed(verdict), 2 Escalated.
    status: u8,
    committed: Option<VerdictDto>,
    opened_at: u64,
}

#[derive(Serialize, Deserialize)]
struct JurorDto {
    address: String,
    stake: String,
    active: bool,
}

#[derive(Serialize, Deserialize)]
struct OpDto {
    /// matches `Op` discriminants (see [`encode_op`]).
    tag: u8,
    addr: Option<String>,
    amount: Option<String>,
    rate: Option<String>,
    deposit: Option<String>,
    id: Option<u64>,
    key: Option<String>,
    value: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct EffectDto {
    ops: Vec<OpDto>,
    effect_hash: String,
}

#[derive(Serialize, Deserialize)]
struct ContractDto {
    id: u64,
    escrow: String,
    parties: Vec<String>,
    text: String,
    text_ref: String,
    vars: Vec<(String, String)>,
    /// 0 Active, 1 Terminated.
    status: u8,
    deploy_block: u64,
    deploy_tx: String,
}

#[derive(Serialize, Deserialize)]
struct ExecCaseDto {
    id: u64,
    contract: u64,
    trigger_ref: String,
    invoker: String,
    jury: Vec<String>,
    effects: Vec<(String, EffectDto)>,
    /// 0 Open, 1 Committed(effect), 2 Aborted.
    status: u8,
    committed: Option<EffectDto>,
    opened_at: u64,
    resolved_at: Option<u64>,
}

#[derive(Serialize, Deserialize)]
struct TxLogDto {
    address: String,
    topics: Vec<String>,
    data: String,
}

#[derive(Serialize, Deserialize)]
struct StoredTxDto {
    hash: String,
    from: String,
    to: Option<String>,
    value: String,
    nonce: u64,
    block_number: u64,
    block_hash: String,
    tx_index: u64,
    input: String,
    logs: Vec<TxLogDto>,
    gas_used: u64,
    success: bool,
    revert_reason: Option<String>,
    // EIP-2718 type byte + EIP-1559 sender fee caps (cycle-7). `#[serde(default)]` keeps snapshots
    // written before these fields loadable — they default to a legacy type-0 tx.
    #[serde(default)]
    tx_type: u8,
    #[serde(default)]
    max_fee_per_gas: Option<u128>,
    #[serde(default)]
    max_priority_fee_per_gas: Option<u128>,
}

#[derive(Serialize, Deserialize)]
struct BlockDto {
    number: u64,
    hash: String,
    parent_hash: String,
    timestamp: u64,
    // M5 Stage B (spec 08 §2.2): the block's view. `#[serde(default)]` keeps a pre-Stage-B snapshot
    // loadable (it restores `view = 0`, exactly a Stage-A block).
    #[serde(default)]
    view: u32,
    txs_root: String,
    state_root: String,
    proposer: String,
    proposer_sig: String,
    txs: Vec<StoredTxDto>,
}

#[derive(Serialize, Deserialize)]
struct StateDto {
    accounts: Vec<AccountDto>,
    streams: Vec<StreamDto>,
    humans: Vec<HumanDto>,
    vouch_edges: Vec<(String, String)>,
    cleared_challenges: Vec<(String, String)>,
    cases: Vec<CaseDto>,
    jurors: Vec<JurorDto>,
    contracts: Vec<ContractDto>,
    exec_cases: Vec<ExecCaseDto>,
    next_stream_id: u64,
    next_case_id: u64,
    next_contract_id: u64,
    next_exec_case_id: u64,
    // ---- M6: ZK-passport registries (spec §5.1/§5.3). `#[serde(default)]` keeps pre-M6 snapshots
    //         loadable — they restore empty registries + no governance authority. ----
    #[serde(default)]
    nullifiers: Vec<String>,
    #[serde(default)]
    attribute_store: Vec<(String, [String; 3])>,
    #[serde(default)]
    csca: Vec<CscaDto>,
    #[serde(default)]
    csca_governance: Option<String>,
    // ---- M6 Stage C: the Self-root anchor registry (spec 06b §2.2). `#[serde(default)]` keeps
    //      pre-Stage-C snapshots loadable (empty sets). ----
    #[serde(default)]
    self_identity_roots: Vec<SelfIdentityRootDto>,
    #[serde(default)]
    self_ofac_roots: Vec<SelfOfacRootDto>,
    // ---- M5 Stage B: the committed epoch validator snapshot (spec 08 §2.1). `#[serde(default)]` keeps
    //      pre-Stage-B snapshots loadable (empty `V`, re-seeded at the next boundary / block #1). ----
    #[serde(default)]
    epoch_validators: Vec<String>,
}

/// The full on-disk chain snapshot.
#[derive(Serialize, Deserialize)]
pub struct ChainSnapshot {
    version: u32,
    chain_id: u64,
    genesis_time: u64,
    blocks: Vec<BlockDto>,
    state: StateDto,
}

// ---- mapping helpers ----

fn verdict_to_dto(v: &CanonicalVerdict) -> VerdictDto {
    VerdictDto {
        verdict: match v.verdict {
            Verdict::Human => 0,
            Verdict::Sybil => 1,
            Verdict::Uncertain => 2,
        },
        confidence: match v.confidence {
            Confidence::Low => 0,
            Confidence::Med => 1,
            Confidence::High => 2,
        },
        reasons_hash: hex32(&v.reasons_hash),
    }
}
fn dto_to_verdict(d: &VerdictDto) -> CanonicalVerdict {
    let verdict = match d.verdict {
        0 => Verdict::Human,
        1 => Verdict::Sybil,
        _ => Verdict::Uncertain,
    };
    let confidence = match d.confidence {
        0 => Confidence::Low,
        1 => Confidence::Med,
        _ => Confidence::High,
    };
    let mut cv = CanonicalVerdict::new(verdict, confidence);
    cv.reasons_hash = unhex32(&d.reasons_hash);
    cv
}

fn encode_op(op: &Op) -> OpDto {
    let mut d = OpDto {
        tag: 0,
        addr: None,
        amount: None,
        rate: None,
        deposit: None,
        id: None,
        key: None,
        value: None,
    };
    match op {
        Op::Transfer { to, amount } => {
            d.tag = 0;
            d.addr = Some(hex20(to));
            d.amount = Some(amount.to_string());
        }
        Op::Refund { party, amount } => {
            d.tag = 1;
            d.addr = Some(hex20(party));
            d.amount = Some(amount.to_string());
        }
        Op::OpenStream { to, rate, deposit } => {
            d.tag = 2;
            d.addr = Some(hex20(to));
            d.rate = Some(rate.to_string());
            d.deposit = Some(deposit.to_string());
        }
        Op::StopStream { id } => {
            d.tag = 3;
            d.id = Some(*id);
        }
        Op::SetVar { key, value } => {
            d.tag = 4;
            d.key = Some(hex32(key));
            d.value = Some(hex32(value));
        }
        Op::Abort { reason_hash } => {
            d.tag = 5;
            d.key = Some(hex32(reason_hash));
        }
    }
    d
}
fn decode_op(d: &OpDto) -> Op {
    match d.tag {
        0 => Op::Transfer {
            to: unhex20(d.addr.as_deref().unwrap_or("")),
            amount: parse_u128(d.amount.as_deref()),
        },
        1 => Op::Refund {
            party: unhex20(d.addr.as_deref().unwrap_or("")),
            amount: parse_u128(d.amount.as_deref()),
        },
        2 => Op::OpenStream {
            to: unhex20(d.addr.as_deref().unwrap_or("")),
            rate: parse_u128(d.rate.as_deref()),
            deposit: parse_u128(d.deposit.as_deref()),
        },
        3 => Op::StopStream {
            id: d.id.unwrap_or(0),
        },
        4 => Op::SetVar {
            key: unhex32(d.key.as_deref().unwrap_or("")),
            value: unhex32(d.value.as_deref().unwrap_or("")),
        },
        _ => Op::Abort {
            reason_hash: unhex32(d.key.as_deref().unwrap_or("")),
        },
    }
}
fn effect_to_dto(e: &CanonicalEffect) -> EffectDto {
    EffectDto {
        ops: e.ops.iter().map(encode_op).collect(),
        effect_hash: hex32(&e.effect_hash),
    }
}
fn dto_to_effect(d: &EffectDto) -> CanonicalEffect {
    // Rebuild from ops so `effect_hash` is recomputed canonically (the stored hash is a checksum).
    CanonicalEffect::new(d.ops.iter().map(decode_op).collect())
}

fn parse_u128(s: Option<&str>) -> u128 {
    s.and_then(|x| x.parse().ok()).unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------------------------

fn export_state(state: &MemState) -> StateDto {
    let mut accounts: Vec<Account> = state.accounts();
    accounts.sort_by_key(|a| a.address);
    let mut streams: Vec<Stream> = state.streams();
    streams.sort_by_key(|s| s.id);

    StateDto {
        accounts: accounts
            .iter()
            .map(|a| AccountDto {
                address: hex20(&a.address),
                verified: a.verified,
                verified_at: a.verified_at,
                settled_balance: a.settled_balance.to_string(),
                last_settled_at: a.last_settled_at,
                nonce: a.nonce,
            })
            .collect(),
        streams: streams
            .iter()
            .map(|s| {
                let (status, stopped_at) = match s.status {
                    StreamStatus::Active => (0u8, 0u64),
                    StreamStatus::Stopped(at) => (1, at),
                    StreamStatus::Completed => (2, 0),
                };
                StreamDto {
                    id: s.id,
                    from: hex20(&s.from),
                    to: hex20(&s.to),
                    rate: s.rate.to_string(),
                    deposit: s.deposit.to_string(),
                    drawn: s.drawn.to_string(),
                    started_at: s.started_at,
                    status,
                    stopped_at,
                }
            })
            .collect(),
        humans: state
            .humans()
            .iter()
            .map(|h| HumanDto {
                address: hex20(&h.address),
                status: match h.status {
                    HumanStatus::Unverified => 0,
                    HumanStatus::Pending => 1,
                    HumanStatus::Verified => 2,
                    HumanStatus::Challenged => 3,
                    HumanStatus::Revoked => 4,
                },
                verified_at: h.verified_at,
                liveness_ref: hex32(&h.liveness_ref),
                vouches_in: h.vouches_in.iter().map(hex20).collect(),
                reputation: h.reputation,
                assurance: h.assurance.tag(),
            })
            .collect(),
        vouch_edges: state
            .vouch_edges()
            .iter()
            .map(|(a, b)| (hex20(a), hex20(b)))
            .collect(),
        cleared_challenges: state
            .cleared_challenges_sorted()
            .iter()
            .map(|(a, b)| (hex20(a), hex20(b)))
            .collect(),
        cases: state
            .cases()
            .iter()
            .map(|c| CaseDto {
                id: c.id,
                subject: hex20(&c.subject),
                challenger: hex20(&c.challenger),
                kind: match c.kind {
                    CaseKind::Registration => 0,
                    CaseKind::Challenge => 1,
                },
                evidence_ref: hex32(&c.evidence_ref),
                jury: c.jury.iter().map(hex20).collect(),
                votes: c
                    .votes
                    .iter()
                    .map(|(a, v)| (hex20(a), verdict_to_dto(v)))
                    .collect(),
                status: match c.status {
                    CaseStatus::Open => 0,
                    CaseStatus::Committed(_) => 1,
                    CaseStatus::Escalated => 2,
                },
                committed: match &c.status {
                    CaseStatus::Committed(v) => Some(verdict_to_dto(v)),
                    _ => None,
                },
                opened_at: c.opened_at,
            })
            .collect(),
        jurors: {
            let mut jurors: Vec<Juror> = state
                .active_jurors()
                .into_iter()
                .filter_map(|a| state.get_juror(&a))
                .collect();
            jurors.sort_by_key(|j| j.address);
            jurors
                .iter()
                .map(|j| JurorDto {
                    address: hex20(&j.address),
                    stake: j.stake.to_string(),
                    active: j.active,
                })
                .collect()
        },
        contracts: state
            .contracts()
            .iter()
            .map(|c| ContractDto {
                id: c.id,
                escrow: c.escrow.to_string(),
                parties: c.parties.iter().map(hex20).collect(),
                text: c.text.clone(),
                text_ref: hex32(&c.text_ref),
                vars: c
                    .sorted_vars()
                    .iter()
                    .map(|(k, v)| (hex32(k), hex32(v)))
                    .collect(),
                status: match c.status {
                    ContractStatus::Active => 0,
                    ContractStatus::Terminated => 1,
                },
                deploy_block: c.deploy_block,
                deploy_tx: hex32(&c.deploy_tx),
            })
            .collect(),
        exec_cases: state
            .exec_cases()
            .iter()
            .map(|ec| ExecCaseDto {
                id: ec.id,
                contract: ec.contract,
                trigger_ref: hex32(&ec.trigger_ref),
                invoker: hex20(&ec.invoker),
                jury: ec.jury.iter().map(hex20).collect(),
                effects: ec
                    .effects
                    .iter()
                    .map(|(a, e)| (hex20(a), effect_to_dto(e)))
                    .collect(),
                status: match ec.status {
                    ExecStatus::Open => 0,
                    ExecStatus::Committed(_) => 1,
                    ExecStatus::Aborted => 2,
                },
                committed: match &ec.status {
                    ExecStatus::Committed(e) => Some(effect_to_dto(e)),
                    _ => None,
                },
                opened_at: ec.opened_at,
                resolved_at: ec.resolved_at,
            })
            .collect(),
        next_stream_id: state.peek_next_stream_id(),
        next_case_id: state.peek_next_case_id(),
        next_contract_id: state.peek_next_contract_id(),
        next_exec_case_id: state.peek_next_exec_case_id(),
        // ---- M6: ZK-passport registries (sorted by the State accessors — deterministic order). ----
        nullifiers: state.nullifiers().iter().map(hex32).collect(),
        attribute_store: state
            .attribute_store()
            .iter()
            .map(|(addr, commitments)| {
                (
                    hex20(addr),
                    [
                        hex32(&commitments[0]),
                        hex32(&commitments[1]),
                        hex32(&commitments[2]),
                    ],
                )
            })
            .collect(),
        csca: state
            .csca_entries()
            .iter()
            .map(|e| CscaDto {
                country_code: hex_encode(&e.country_code),
                key_id: hex32(&e.key_id),
                pubkey: hex_encode(&e.pubkey),
                added_at: e.added_at,
                status: e.status.tag(),
            })
            .collect(),
        csca_governance: state.csca_governance().map(|a| hex20(&a)),
        // M6 Stage C: the Self-root anchor registry (sorted by the runtime accessors).
        self_identity_roots: state
            .self_identity_roots()
            .iter()
            .map(|e| SelfIdentityRootDto {
                root: hex32(&e.root),
                pinned_at_block: e.pinned_at_block,
            })
            .collect(),
        self_ofac_roots: state
            .self_ofac_roots()
            .iter()
            .map(|e| SelfOfacRootDto {
                kind: e.kind,
                root: hex32(&e.root),
                pinned_at_block: e.pinned_at_block,
            })
            .collect(),
        // Stage B: the epoch validator snapshot, already sorted by the runtime accessor.
        epoch_validators: state.epoch_validators().iter().map(hex20).collect(),
    }
}

fn export_tx(tx: &StoredTx) -> StoredTxDto {
    StoredTxDto {
        hash: hex32(&tx.hash.0),
        from: hex20(&tx.from.into_array()),
        to: tx.to.map(|a| hex20(&a.into_array())),
        value: tx.value.to_string(),
        nonce: tx.nonce,
        block_number: tx.block_number,
        block_hash: hex32(&tx.block_hash.0),
        tx_index: tx.tx_index,
        input: hex_encode(&tx.input),
        logs: tx
            .logs
            .iter()
            .map(|l| TxLogDto {
                address: hex20(&l.address.into_array()),
                topics: l.topics.iter().map(|t| hex32(&t.0)).collect(),
                data: hex_encode(&l.data),
            })
            .collect(),
        gas_used: tx.gas_used,
        success: tx.success,
        revert_reason: tx.revert_reason.clone(),
        tx_type: tx.tx_type,
        max_fee_per_gas: tx.max_fee_per_gas,
        max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
    }
}

fn export_block(b: &Block) -> BlockDto {
    BlockDto {
        number: b.number,
        hash: hex32(&b.hash.0),
        parent_hash: hex32(&b.parent_hash.0),
        timestamp: b.timestamp,
        view: b.view,
        txs_root: hex32(&b.txs_root.0),
        state_root: hex32(&b.state_root.0),
        proposer: hex20(&b.proposer.into_array()),
        proposer_sig: hex_encode(&b.proposer_sig),
        txs: b.txs.iter().map(export_tx).collect(),
    }
}

// ---------------------------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------------------------

fn import_state(dto: &StateDto) -> MemState {
    let mut s = MemState::new();
    for a in &dto.accounts {
        s.put(Account {
            address: unhex20(&a.address),
            verified: a.verified,
            verified_at: a.verified_at,
            settled_balance: parse_u128(Some(&a.settled_balance)),
            last_settled_at: a.last_settled_at,
            nonce: a.nonce,
        });
    }
    for st in &dto.streams {
        s.put_stream(Stream {
            id: st.id,
            from: unhex20(&st.from),
            to: unhex20(&st.to),
            rate: parse_u128(Some(&st.rate)),
            deposit: parse_u128(Some(&st.deposit)),
            drawn: parse_u128(Some(&st.drawn)),
            started_at: st.started_at,
            status: match st.status {
                0 => StreamStatus::Active,
                1 => StreamStatus::Stopped(st.stopped_at),
                _ => StreamStatus::Completed,
            },
        });
    }
    for h in &dto.humans {
        s.put_human(Human {
            address: unhex20(&h.address),
            status: match h.status {
                0 => HumanStatus::Unverified,
                1 => HumanStatus::Pending,
                2 => HumanStatus::Verified,
                3 => HumanStatus::Challenged,
                _ => HumanStatus::Revoked,
            },
            verified_at: h.verified_at,
            liveness_ref: unhex32(&h.liveness_ref),
            vouches_in: h.vouches_in.iter().map(|a| unhex20(a)).collect(),
            reputation: h.reputation,
            assurance: match h.assurance {
                1 => Assurance::Enh,
                2 => Assurance::Dual,
                _ => Assurance::Std,
            },
        });
    }
    for (voucher, vouchee) in &dto.vouch_edges {
        s.put_vouch(ubi2_runtime::Vouch {
            voucher: unhex20(voucher),
            vouchee: unhex20(vouchee),
            at: 0,
        });
    }
    for (challenger, subject) in &dto.cleared_challenges {
        s.record_challenge_cleared(&unhex20(challenger), &unhex20(subject));
    }
    for c in &dto.cases {
        s.put_case(Case {
            id: c.id,
            subject: unhex20(&c.subject),
            challenger: unhex20(&c.challenger),
            kind: match c.kind {
                0 => CaseKind::Registration,
                _ => CaseKind::Challenge,
            },
            evidence_ref: unhex32(&c.evidence_ref),
            jury: c.jury.iter().map(|a| unhex20(a)).collect(),
            votes: c
                .votes
                .iter()
                .map(|(a, v)| (unhex20(a), dto_to_verdict(v)))
                .collect(),
            status: match c.status {
                1 => CaseStatus::Committed(dto_to_verdict(
                    c.committed.as_ref().expect("committed verdict"),
                )),
                2 => CaseStatus::Escalated,
                _ => CaseStatus::Open,
            },
            opened_at: c.opened_at,
        });
    }
    for j in &dto.jurors {
        s.put_juror(Juror {
            address: unhex20(&j.address),
            stake: parse_u128(Some(&j.stake)),
            active: j.active,
        });
    }
    for c in &dto.contracts {
        let mut pc = PromptContract::new(c.id, c.text.clone(), unhex32(&c.text_ref), {
            c.parties.iter().map(|a| unhex20(a)).collect()
        });
        pc.escrow = parse_u128(Some(&c.escrow));
        pc.status = match c.status {
            1 => ContractStatus::Terminated,
            _ => ContractStatus::Active,
        };
        pc.deploy_block = c.deploy_block;
        pc.deploy_tx = unhex32(&c.deploy_tx);
        for (k, v) in &c.vars {
            pc.vars.insert(unhex32(k), unhex32(v));
        }
        s.put_contract(pc);
    }
    for ec in &dto.exec_cases {
        s.put_exec_case(ExecCase {
            id: ec.id,
            contract: ec.contract,
            trigger_ref: unhex32(&ec.trigger_ref),
            invoker: unhex20(&ec.invoker),
            jury: ec.jury.iter().map(|a| unhex20(a)).collect(),
            effects: ec
                .effects
                .iter()
                .map(|(a, e)| (unhex20(a), dto_to_effect(e)))
                .collect(),
            status: match ec.status {
                1 => ExecStatus::Committed(dto_to_effect(
                    ec.committed.as_ref().expect("committed effect"),
                )),
                2 => ExecStatus::Aborted,
                _ => ExecStatus::Open,
            },
            opened_at: ec.opened_at,
            resolved_at: ec.resolved_at,
        });
    }
    s.set_next_stream_id(dto.next_stream_id);
    s.set_next_case_id(dto.next_case_id);
    s.set_next_contract_id(dto.next_contract_id);
    s.set_next_exec_case_id(dto.next_exec_case_id);
    // ---- M6: ZK-passport registries ----
    for n in &dto.nullifiers {
        s.put_nullifier(unhex32(n));
    }
    for (addr, commitments) in &dto.attribute_store {
        s.put_attribute_commitments(
            &unhex20(addr),
            [
                unhex32(&commitments[0]),
                unhex32(&commitments[1]),
                unhex32(&commitments[2]),
            ],
        );
    }
    for e in &dto.csca {
        let cc = hex_decode_vec(&e.country_code);
        let mut country_code = [0u8; 3];
        country_code.copy_from_slice(&cc[..3.min(cc.len())]);
        let mut entry = CscaEntry::active(
            country_code,
            unhex32(&e.key_id),
            hex_decode_vec(&e.pubkey),
            e.added_at,
        );
        entry.status = match e.status {
            1 => CscaStatus::Revoked,
            _ => CscaStatus::Active,
        };
        s.put_csca(entry);
    }
    if let Some(gov) = &dto.csca_governance {
        s.set_csca_governance(unhex20(gov));
    }
    // M6 Stage C: restore the Self-root anchor registry (spec 06b §2.2).
    for e in &dto.self_identity_roots {
        s.put_self_identity_root(ubi2_runtime::SelfIdentityRoot {
            root: unhex32(&e.root),
            pinned_at_block: e.pinned_at_block,
        });
    }
    for e in &dto.self_ofac_roots {
        s.put_self_ofac_root(ubi2_runtime::SelfOfacRoot {
            kind: e.kind,
            root: unhex32(&e.root),
            pinned_at_block: e.pinned_at_block,
        });
    }
    // Stage B: restore the epoch validator snapshot (the setter re-sorts + dedups, so a hand-rolled
    // snapshot cannot install a non-canonical order).
    s.set_epoch_validators(dto.epoch_validators.iter().map(|a| unhex20(a)).collect());
    s
}

fn import_tx(dto: &StoredTxDto) -> StoredTx {
    StoredTx {
        hash: B256::from(unhex32(&dto.hash)),
        from: AlloyAddr::from(unhex20(&dto.from)),
        to: dto.to.as_ref().map(|a| AlloyAddr::from(unhex20(a))),
        value: dto.value.parse::<U256>().unwrap_or(U256::ZERO),
        nonce: dto.nonce,
        block_number: dto.block_number,
        block_hash: B256::from(unhex32(&dto.block_hash)),
        tx_index: dto.tx_index,
        input: hex_decode_vec(&dto.input),
        logs: dto
            .logs
            .iter()
            .map(|l| TxLog {
                address: AlloyAddr::from(unhex20(&l.address)),
                topics: l.topics.iter().map(|t| B256::from(unhex32(t))).collect(),
                data: hex_decode_vec(&l.data),
            })
            .collect(),
        gas_used: dto.gas_used,
        success: dto.success,
        revert_reason: dto.revert_reason.clone(),
        tx_type: dto.tx_type,
        max_fee_per_gas: dto.max_fee_per_gas,
        max_priority_fee_per_gas: dto.max_priority_fee_per_gas,
    }
}

fn import_block(dto: &BlockDto) -> Block {
    Block {
        number: dto.number,
        hash: B256::from(unhex32(&dto.hash)),
        parent_hash: B256::from(unhex32(&dto.parent_hash)),
        timestamp: dto.timestamp,
        view: dto.view,
        txs_root: B256::from(unhex32(&dto.txs_root)),
        state_root: B256::from(unhex32(&dto.state_root)),
        proposer: AlloyAddr::from(unhex20(&dto.proposer)),
        proposer_sig: hex_decode_vec(&dto.proposer_sig),
        txs: dto.txs.iter().map(import_tx).collect(),
    }
}

// ---------------------------------------------------------------------------------------------
// Public API on `Chain`
// ---------------------------------------------------------------------------------------------

/// Serialize a `MemState`'s `state` section to the canonical JSON the `runtime-wasm` snapshot decoder
/// imports (spec 07 §3.4). The field shapes are byte-for-byte the `StateDto` the light client reads (the
/// AC-WB parity gate proves the two `StateDto`s round-trip), so a light client decoding these bytes
/// rebuilds a state with the SAME `state_root`. Used to serve the seeded genesis anchor over the gateway.
pub(crate) fn genesis_state_json(state: &MemState) -> serde_json::Value {
    serde_json::to_value(export_state(state)).expect("StateDto serializes")
}

impl Chain {
    /// Build a full, deterministic [`ChainSnapshot`] of the current chain (blocks + state). Pure read.
    pub fn export_snapshot(&self) -> ChainSnapshot {
        let g = self.lock_inner();
        ChainSnapshot {
            version: SNAPSHOT_VERSION,
            chain_id: self.chain_id(),
            genesis_time: self.genesis_time(),
            blocks: g.blocks.iter().map(export_block).collect(),
            state: export_state(&g.state),
        }
    }

    /// Rebuild a [`Chain`] from a snapshot (the FU-3 restart path). The oracle/admin/proposer wiring is
    /// NOT part of the snapshot (it is node config), so the caller re-attaches it via the `with_*`
    /// builders. The derived indexes (`blocks_by_hash`, the tx map, the per-address activity index) are
    /// rebuilt from the persisted blocks, so a loaded chain is byte-identical (same `state_root`, same
    /// tip) to the one that was saved.
    pub fn from_snapshot(snap: &ChainSnapshot) -> Self {
        let chain = Chain::new(snap.chain_id, snap.genesis_time);
        let state = import_state(&snap.state);
        let blocks: Vec<Block> = snap.blocks.iter().map(import_block).collect();
        chain.load_into(state, blocks);
        chain
    }
}

impl ChainSnapshot {
    /// The persisted chain id (so the node can sanity-check the data dir matches its config).
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
    /// The persisted tip height (the highest block number).
    pub fn tip_height(&self) -> u64 {
        self.blocks.last().map(|b| b.number).unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------------------------
// Atomic file IO (deterministic, crash-safe)
// ---------------------------------------------------------------------------------------------

/// The snapshot path within a data dir.
pub fn snapshot_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SNAPSHOT_FILE)
}

/// Save `snap` to `<data_dir>/chain.json` **atomically**: serialize to a temp file in the same
/// directory and `rename` it over the target, so a crash mid-write never corrupts the live snapshot.
/// Creates `data_dir` if absent. Pretty JSON for human inspection of the devnet data dir.
pub fn save(data_dir: &Path, snap: &ChainSnapshot) -> std::io::Result<()> {
    std::fs::create_dir_all(data_dir)?;
    let target = snapshot_path(data_dir);
    let tmp = data_dir.join(format!(".{SNAPSHOT_FILE}.tmp"));
    let bytes = serde_json::to_vec_pretty(snap)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?; // flush to disk before the rename so the rename publishes complete bytes
    }
    std::fs::rename(&tmp, &target)?;
    Ok(())
}

/// Load the snapshot from `<data_dir>/chain.json`, or `Ok(None)` if no snapshot exists (a fresh node).
pub fn load(data_dir: &Path) -> std::io::Result<Option<ChainSnapshot>> {
    let target = snapshot_path(data_dir);
    if !target.exists() {
        return Ok(None);
    }
    let bytes = std::fs::read(&target)?;
    let snap: ChainSnapshot = serde_json::from_slice(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
    Ok(Some(snap))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Chain, ProposerKey, DEVNET_CHAIN_ID};
    use std::sync::Arc;

    fn dev_addr() -> [u8; 20] {
        // A fixed test address (exact value is not load-bearing for the persistence round-trip).
        [0xab; 20]
    }

    /// Build a chain with some state + a few produced blocks (incl. signed headers).
    fn populated_chain() -> Chain {
        let key = Arc::new(ProposerKey::from_bytes(&[5u8; 32]).unwrap());
        let chain = Chain::new(DEVNET_CHAIN_ID, 1_700_000_000).with_proposer_key(key);
        chain.seed_verified_human(&dev_addr(), 1_700_000_000);
        chain.seed_account(ubi2_runtime::Account {
            address: dev_addr(),
            verified: true,
            verified_at: 1_700_000_000,
            last_settled_at: 1_700_000_000,
            settled_balance: 0,
            nonce: 0,
        });
        chain.register_juror(&[7u8; 20], 0);
        // Produce a couple of (empty) blocks so the block history + signed headers are non-trivial.
        chain.produce_block(1_700_000_002);
        chain.produce_block(1_700_000_004);
        chain
    }

    /// FU-3 round-trip: save → load → identical state_root, identical tip, identical block hashes.
    #[test]
    fn snapshot_roundtrip_preserves_state_root_and_tip() {
        let chain = populated_chain();
        let pre_root = chain.state_root();
        let pre_tip = chain.tip();

        let snap = chain.export_snapshot();
        let restored = Chain::from_snapshot(&snap);

        assert_eq!(
            restored.state_root(),
            pre_root,
            "restart must preserve the state_root byte-for-byte"
        );
        assert_eq!(restored.tip(), pre_tip, "restart must preserve the tip");

        // Block-by-block hash agreement.
        let a = chain.lock_inner();
        let b = restored.lock_inner();
        assert_eq!(a.blocks.len(), b.blocks.len());
        for (x, y) in a.blocks.iter().zip(b.blocks.iter()) {
            assert_eq!(
                x.hash, y.hash,
                "block {} hash diverged on restore",
                x.number
            );
            assert_eq!(x.state_root, y.state_root);
            assert_eq!(x.proposer, y.proposer);
            assert_eq!(x.proposer_sig, y.proposer_sig);
        }
    }

    /// Atomic file round-trip: save to a temp dir → load → identical state_root + tip.
    #[test]
    fn file_roundtrip_atomic() {
        let chain = populated_chain();
        let pre_root = chain.state_root();
        let dir = std::env::temp_dir().join(format!("ubi2-persist-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        save(&dir, &chain.export_snapshot()).unwrap();
        let loaded = load(&dir).unwrap().expect("snapshot present after save");
        let restored = Chain::from_snapshot(&loaded);
        assert_eq!(restored.state_root(), pre_root);
        assert_eq!(restored.tip(), chain.tip());

        // Loading a fresh (empty) dir returns None.
        let empty = std::env::temp_dir().join(format!("ubi2-persist-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&empty);
        assert!(load(&empty).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A node that keeps producing after a restart extends the SAME chain (parent links hold) — i.e. a
    /// restart is transparent to block production.
    #[test]
    fn restart_then_continue_extends_same_chain() {
        let chain = populated_chain();
        let snap = chain.export_snapshot();
        let restored = Chain::from_snapshot(&snap);
        let tip_before = restored.tip();

        let next = restored.produce_block(1_700_000_006);
        assert_eq!(next.number, tip_before.0 + 1);
        assert_eq!(
            next.parent_hash, tip_before.1,
            "new block must link to the restored tip"
        );
    }
}
