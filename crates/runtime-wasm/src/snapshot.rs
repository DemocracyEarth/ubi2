//! Canonical snapshot of the verified `LightCore` (the `MemState` + verified tip) for IndexedDB
//! persistence (spec 07 §3.3). Round-trip is **lossless**: `state_root(decode(encode(c)))` equals
//! `state_root(c)` and the tip is preserved byte-for-byte, so a browser reload resumes from the last
//! verified height instead of re-syncing from genesis.
//!
//! The `MemState` serialization mirrors `crates/rpc::persist::export_state`/`import_state` **field for
//! field** (same DTOs, same sorted accessors), so a snapshot the browser writes is structurally the
//! same shape a server writes — and re-imports to a state with the same `state_root`. The light node
//! re-verifies the restored root against the stored tip on load (the TS client does this; a poisoned
//! IndexedDB entry whose root != tip is discarded and re-synced, §3.3).

use serde::{Deserialize, Serialize};

use ubi2_runtime::{
    Account, Assurance, CanonicalEffect, CanonicalVerdict, Case, CaseKind, CaseStatus, Confidence,
    ContractStatus, CscaEntry, CscaStatus, ExecCase, ExecStatus, Human, HumanStatus, Juror,
    MemState, Op, PromptContract, State, Stream, StreamStatus, Verdict, Vouch,
};

use crate::kernel::LightCore;

/// The snapshot schema version. A future schema change bumps this so an old snapshot is refused (and
/// the client re-syncs) rather than silently misread.
const SNAPSHOT_VERSION: u32 = 1;

// ---- hex helpers (lowercase, no 0x) — byte-identical to the rpc persist module ----

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
        let hi = (*bytes.get(i * 2).unwrap_or(&b'0') as char)
            .to_digit(16)
            .unwrap_or(0) as u8;
        let lo = (*bytes.get(i * 2 + 1).unwrap_or(&b'0') as char)
            .to_digit(16)
            .unwrap_or(0) as u8;
        *slot = (hi << 4) | lo;
    }
}
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
fn parse_u128(s: &str) -> u128 {
    s.parse().unwrap_or(0)
}
/// Decode a lowercase, no-`0x` hex string into a `Vec<u8>` of arbitrary length (CSCA `country_code` /
/// `pubkey`). Mirrors `rpc::persist::hex_decode_vec` so a server-served entry round-trips byte-identical.
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

// ---- DTOs (mirror rpc::persist) ----

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
    status: u8,
    stopped_at: u64,
}

#[derive(Serialize, Deserialize)]
struct VerdictDto {
    verdict: u8,
    confidence: u8,
    reasons_hash: String,
}

#[derive(Serialize, Deserialize)]
struct HumanDto {
    address: String,
    status: u8,
    verified_at: u64,
    liveness_ref: String,
    vouches_in: Vec<String>,
    reputation: i64,
    // M6 §5.3: the assurance level (0 STD / 1 ENH / 2 DUAL). `#[serde(default)]` keeps a pre-M6
    // light-client snapshot loadable (it restores `Std`, the default), matching `rpc::persist`.
    #[serde(default)]
    assurance: u8,
}

/// M6: a CSCA trust-anchor entry (spec §7.2) — mirrors `rpc::persist::CscaDto` field-for-field so a
/// genesis snapshot the server serves imports to a state with the SAME `state_root` (which folds the
/// CSCA registry, §5.3).
#[derive(Serialize, Deserialize)]
struct CscaDto {
    country_code: String,
    key_id: String,
    pubkey: String,
    added_at: u64,
    /// 0 Active, 1 Revoked.
    status: u8,
}

/// M6 Stage C: an accepted Self identity root (spec 06b §2.2) — mirrors `rpc::persist::SelfIdentityRootDto`
/// so a server-served snapshot re-derives to the SAME `state_root` (which folds the Self-root registry).
#[derive(Serialize, Deserialize)]
struct SelfIdentityRootDto {
    root: String,
    pinned_at_block: u64,
}

/// M6 Stage C: an accepted Self OFAC SMT root (spec 06b §2.2) — mirrors `rpc::persist::SelfOfacRootDto`.
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
    kind: u8,
    evidence_ref: String,
    jury: Vec<String>,
    votes: Vec<(String, VerdictDto)>,
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
    status: u8,
    committed: Option<EffectDto>,
    opened_at: u64,
    resolved_at: Option<u64>,
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
    // ---- M6: ZK-passport registries (sorted by the State accessors — the deterministic order the
    //         `state_root` folds, §5.3). All `#[serde(default)]` so a pre-M6 snapshot loads (empty
    //         registries / no governance). These are what make a seeded genesis snapshot (which carries
    //         a curated CSCA + governance) re-derive to the SAME root the honest gateway pins. ----
    #[serde(default)]
    nullifiers: Vec<String>,
    #[serde(default)]
    attribute_store: Vec<(String, [String; 3])>,
    #[serde(default)]
    csca: Vec<CscaDto>,
    #[serde(default)]
    csca_governance: Option<String>,
    // ---- M6 Stage C: the Self-root anchor registry (spec 06b §2.2), folded into `state_root`. ----
    #[serde(default)]
    self_identity_roots: Vec<SelfIdentityRootDto>,
    #[serde(default)]
    self_ofac_roots: Vec<SelfOfacRootDto>,
    // ---- M5 Stage B: the committed epoch validator snapshot (spec 08 §2.1), folded into `state_root`
    //      (§8). Mirrors `rpc::persist::StateDto` so a server-served snapshot re-derives to the SAME
    //      root the light client verifies. `#[serde(default)]` keeps a pre-Stage-B snapshot loadable. ----
    #[serde(default)]
    epoch_validators: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct TipDto {
    number: u64,
    hash: String,
    state_root: String,
    timestamp: u64,
}

#[derive(Serialize, Deserialize)]
struct LightSnapshot {
    version: u32,
    chain_id: u64,
    tip: TipDto,
    state: StateDto,
}

// ---- verdict / op mapping (mirror rpc::persist) ----

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
            amount: parse_u128(d.amount.as_deref().unwrap_or("0")),
        },
        1 => Op::Refund {
            party: unhex20(d.addr.as_deref().unwrap_or("")),
            amount: parse_u128(d.amount.as_deref().unwrap_or("0")),
        },
        2 => Op::OpenStream {
            to: unhex20(d.addr.as_deref().unwrap_or("")),
            rate: parse_u128(d.rate.as_deref().unwrap_or("0")),
            deposit: parse_u128(d.deposit.as_deref().unwrap_or("0")),
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
    CanonicalEffect::new(d.ops.iter().map(decode_op).collect())
}

// ---- export / import state (mirror rpc::persist, same sorted accessors) ----

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
        // ---- M6 registries (mirror rpc::persist::export_state, same sorted State accessors). ----
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
        // Stage B: the epoch validator snapshot (sorted by the runtime accessor).
        epoch_validators: state.epoch_validators().iter().map(hex20).collect(),
    }
}

fn import_state(dto: &StateDto) -> MemState {
    let mut s = MemState::new();
    for a in &dto.accounts {
        s.put(Account {
            address: unhex20(&a.address),
            verified: a.verified,
            verified_at: a.verified_at,
            settled_balance: parse_u128(&a.settled_balance),
            last_settled_at: a.last_settled_at,
            nonce: a.nonce,
        });
    }
    for st in &dto.streams {
        s.put_stream(Stream {
            id: st.id,
            from: unhex20(&st.from),
            to: unhex20(&st.to),
            rate: parse_u128(&st.rate),
            deposit: parse_u128(&st.deposit),
            drawn: parse_u128(&st.drawn),
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
            // M6 §5.3: restore the assurance level the snapshot carried (0 STD / 1 ENH / 2 DUAL). A
            // ZK-passport block re-executed by the light client moves an existing human to Enh/Dual, and
            // a verified genesis snapshot must round-trip that exactly so `state_root` matches (the root
            // folds the 1-byte assurance tag in the humans section).
            assurance: match h.assurance {
                1 => Assurance::Enh,
                2 => Assurance::Dual,
                _ => Assurance::Std,
            },
        });
    }
    for (voucher, vouchee) in &dto.vouch_edges {
        s.put_vouch(Vouch {
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
            stake: parse_u128(&j.stake),
            active: j.active,
        });
    }
    for c in &dto.contracts {
        let mut pc = PromptContract::new(
            c.id,
            c.text.clone(),
            unhex32(&c.text_ref),
            c.parties.iter().map(|a| unhex20(a)).collect(),
        );
        pc.escrow = parse_u128(&c.escrow);
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
    // ---- M6 registries (mirror rpc::persist::import_state, same order + mappings). ----
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
    // Stage B: restore the epoch validator snapshot (the setter re-sorts + dedups).
    s.set_epoch_validators(dto.epoch_validators.iter().map(|a| unhex20(a)).collect());
    s
}

/// Encode a verified [`LightCore`] to canonical snapshot bytes (JSON). Deterministic: a snapshot taken
/// on two byte-equal cores is byte-identical.
pub fn encode(core: &LightCore) -> Vec<u8> {
    let (number, hash, state_root, timestamp) = core.tip_parts();
    let snap = LightSnapshot {
        version: SNAPSHOT_VERSION,
        chain_id: core.chain_id(),
        tip: TipDto {
            number,
            hash: hex32(&hash),
            state_root: hex32(&state_root),
            timestamp,
        },
        state: export_state(core.state_ref()),
    };
    serde_json::to_vec(&snap).expect("snapshot serializes")
}

/// Decode a bare `state` section (the `StateDto` JSON the sync gateway serves as the genesis snapshot,
/// spec 07 §3.4) into a `MemState`. This is the SAME `StateDto` the full snapshot's `state` field uses —
/// the seeded accounts/humans/jurors/CSCA/governance — so re-deriving `ubi2_runtime::state_root` over the
/// result reproduces the seeded genesis root the honest gateway pins (the AC-WB parity gate proves the
/// rpc-vs-wasm `StateDto` round-trip). Returns an error string on malformed bytes.
pub fn decode_state(bytes: &[u8]) -> Result<MemState, String> {
    let dto: StateDto =
        serde_json::from_slice(bytes).map_err(|e| format!("genesis state decode failed: {e}"))?;
    Ok(import_state(&dto))
}

/// Decode snapshot bytes back to a verified [`LightCore`]. Returns an error string on malformed bytes
/// or a version mismatch. The caller MUST re-verify `state_root()` against the restored tip on load
/// (spec §3.3 — a poisoned IndexedDB snapshot is discarded + re-synced).
pub fn decode(bytes: &[u8]) -> Result<LightCore, String> {
    let snap: LightSnapshot =
        serde_json::from_slice(bytes).map_err(|e| format!("snapshot decode failed: {e}"))?;
    if snap.version != SNAPSHOT_VERSION {
        return Err(format!(
            "snapshot version {} != supported {SNAPSHOT_VERSION}",
            snap.version
        ));
    }
    let state = import_state(&snap.state);
    Ok(LightCore::from_parts(
        snap.chain_id,
        state,
        snap.tip.number,
        unhex32(&snap.tip.hash),
        unhex32(&snap.tip.state_root),
        snap.tip.timestamp,
    ))
}
