//! M4 — Natural-language prompt contracts (intent-as-law). See `docs/specs/04-prompt-contracts.md`.
//!
//! This module is the **deterministic** on-chain part of M4: the prompt-contract registry, the
//! escrow/authority model, the canonical effect language, and the pure fail-closed lifecycle that ties
//! them together. It is the contract-execution analogue of M3's proof-of-humanity machinery
//! (`crate::humanity` + `crate::lifecycle`), and it **reuses the same consensus substrate**:
//!
//!   * juror selection + the active-juror registry ([`crate::humanity::select_jury`]) pick the
//!     **interpreter quorum** exactly the way M3 picks a jury;
//!   * the **generic** [`crate::humanity::quorum_tally`] (shared with M3's verdict tally) tallies
//!     submitted [`CanonicalEffect`]s — one audited consensus path for both milestones (I1).
//!
//! The probabilistic AI work lives entirely behind the [`ContractInterpreter`] trait (I1/I5): the
//! runtime only ever commits a [`CanonicalEffect`] (a bounded, typed state delta), never prose, and
//! only when a quorum of interpreters produced the *same* effect (by [`CanonicalEffect::effect_hash`]).
//! On disagreement / split / no-quorum, or on an effect that violates escrow/authority, the whole
//! invocation **Aborts deterministically** — no partial state, ever (I4 fail-closed).
//!
//! Least authority (I6): a contract can move **only its own escrow**, and a `Refund` may only target a
//! declared party. Every op is validated against escrow/authority **in the runtime** (not the LLM)
//! before anything is applied, and the whole effect is applied **atomically** (all-or-nothing).
//!
//! Determinism: integer-only, no floats, no hash-iteration on any consensus path. The canonical effect
//! encoding is a fixed little-/big-endian byte layout (see [`CanonicalEffect::encode`]) and the
//! `effect_hash` is a FNV-1a digest over it — two interpreters that emit the same ops produce the same
//! hash, so the tally groups them deterministically.

use crate::humanity::{
    quorum_tally, select_jury, Hash, QuorumEq, QuorumOutcome, JURY_SIZE, QUORUM,
};
use crate::{open_stream, stop_stream, Address, State, StreamError, StreamId, TransferError};
use std::collections::HashMap;

/// A sequential prompt-contract identifier.
pub type ContractId = u64;
/// A sequential execution-case identifier (one per invocation under interpretation).
pub type ExecCaseId = u64;

/// The reserved ContractHub system address (`0x…5043`) — prompt-contract write ops target it, and it
/// is the base of the contract escrow address space (see [`contract_address`]). `0x5043` is ASCII
/// `"PC"` (Prompt-Contract); distinct from the HumanityHub (`0x…5048`) and StreamHub (`0x…5742`).
pub const CONTRACT_HUB: Address = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x43,
];

/// Derive a contract's **escrow account address** from its id. A contract's escrow lives in the normal
/// account model at a reserved, collision-free address derived deterministically from its id, so the
/// existing transfer/stream paths fund and move it with no special-casing (spec M4-T1 open question:
/// "reuse the account model with a contract-id→address map" — we use a pure derivation, not a map, so
/// it needs no extra state and is reproducible across nodes).
///
/// Layout: the first 12 bytes are the ContractHub prefix tag `0x…5043`'s high bytes (so escrow
/// addresses are visibly in the ContractHub space and never collide with EOA/derived hub addresses),
/// the last 8 bytes are the contract id big-endian. Id `0` ⇒ `0x0000…00005043_0000000000000000`.
pub fn contract_address(id: ContractId) -> Address {
    let mut a = [0u8; 20];
    // Tag the high 12 bytes with the ContractHub marker so the address space is unambiguous.
    a[..12].copy_from_slice(&CONTRACT_HUB[..12]);
    a[10] = 0x50; // 'P'
    a[11] = 0x43; // 'C'
    a[12..20].copy_from_slice(&id.to_be_bytes());
    a
}

// ---------------------------------------------------------------------------------------------
// Canonical effect language (spec D1) — bounded, typed, deterministic. The interpreter emits an
// ordered list of these ops; the runtime applies them atomically.
// ---------------------------------------------------------------------------------------------

/// A single typed op in the canonical effect language (spec D1). All amounts are integer base units
/// (I2). The op set is intentionally small (no loops, no cross-contract calls); expressiveness comes
/// from the NL + the interpreter, not a VM. Extends only by ADR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Op {
    /// Move `amount` base units **from the contract's escrow** to `to`.
    Transfer { to: Address, amount: u128 },
    /// Return `amount` base units of escrow to a **declared party** `party`.
    Refund { party: Address, amount: u128 },
    /// Open an M2 stream `rate` base units/sec to `to`, locking `deposit` **from escrow** (reuses M2).
    OpenStream {
        to: Address,
        rate: u128,
        deposit: u128,
    },
    /// Stop a stream the contract owns (its escrow is the stream's `from`), refunding the remainder.
    StopStream { id: StreamId },
    /// Set a contract-local key/value (stateful contracts).
    SetVar { key: Hash, value: Hash },
    /// Explicit deterministic abort with a reason commitment. Reaching quorum on an `Abort` op set
    /// commits the *decision to abort*; the runtime then makes no state change (I4).
    Abort { reason_hash: Hash },
}

impl Op {
    /// A 1-byte canonical tag, fixing the discriminant for the wire encoding (stable across versions).
    fn tag(&self) -> u8 {
        match self {
            Op::Transfer { .. } => 0,
            Op::Refund { .. } => 1,
            Op::OpenStream { .. } => 2,
            Op::StopStream { .. } => 3,
            Op::SetVar { .. } => 4,
            Op::Abort { .. } => 5,
        }
    }

    /// Append this op's canonical byte encoding to `buf`. Fixed-width, big-endian integers, fixed
    /// field order — so two interpreters that emit the same op produce identical bytes (and thus the
    /// same `effect_hash`). The 1-byte `tag` prefixes every op so variants never alias.
    fn encode_into(&self, buf: &mut Vec<u8>) {
        buf.push(self.tag());
        match self {
            Op::Transfer { to, amount } => {
                buf.extend_from_slice(to);
                buf.extend_from_slice(&amount.to_be_bytes());
            }
            Op::Refund { party, amount } => {
                buf.extend_from_slice(party);
                buf.extend_from_slice(&amount.to_be_bytes());
            }
            Op::OpenStream { to, rate, deposit } => {
                buf.extend_from_slice(to);
                buf.extend_from_slice(&rate.to_be_bytes());
                buf.extend_from_slice(&deposit.to_be_bytes());
            }
            Op::StopStream { id } => {
                buf.extend_from_slice(&id.to_be_bytes());
            }
            Op::SetVar { key, value } => {
                buf.extend_from_slice(key);
                buf.extend_from_slice(value);
            }
            Op::Abort { reason_hash } => {
                buf.extend_from_slice(reason_hash);
            }
        }
    }
}

/// The canonical, structured output every interpreter signs and the chain tallies (spec D1). Two
/// effects are *equal for quorum purposes* iff their `effect_hash` matches — i.e. their canonical-
/// encoded ops are byte-identical. Any off-chain reasoning/explanation is **not** part of the effect
/// and never affects quorum equality (I1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CanonicalEffect {
    /// The ordered ops, applied atomically (empty = no-op).
    pub ops: Vec<Op>,
    /// FNV-1a digest over [`CanonicalEffect::encode`] — the quorum-equality key.
    pub effect_hash: Hash,
}

impl CanonicalEffect {
    /// Build a canonical effect from an ordered op list, computing its `effect_hash`.
    pub fn new(ops: Vec<Op>) -> Self {
        let effect_hash = effect_hash(&ops);
        Self { ops, effect_hash }
    }

    /// The empty (no-op) effect. Commits a quorum-agreed *no change*.
    pub fn noop() -> Self {
        Self::new(Vec::new())
    }

    /// An explicit single-`Abort` effect with the given reason commitment.
    pub fn abort(reason_hash: Hash) -> Self {
        Self::new(vec![Op::Abort { reason_hash }])
    }

    /// The canonical byte encoding of the ops: a 4-byte big-endian op count, then each op's
    /// [`Op::encode_into`] in order. Deterministic and self-delimiting; the hash is taken over this.
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(self.ops.len() as u32).to_be_bytes());
        for op in &self.ops {
            op.encode_into(&mut buf);
        }
        buf
    }

    /// Whether this effect is a pure abort decision (a single `Abort` op). A quorum on such an effect
    /// commits the *decision to abort*, which the runtime applies as no state change.
    pub fn is_abort(&self) -> bool {
        matches!(self.ops.as_slice(), [Op::Abort { .. }])
    }
}

/// Compute the canonical `effect_hash` for an op list (FNV-1a over the canonical encoding). FNV-1a is
/// used (not keccak) to keep the runtime dependency-free and the hash fully deterministic in-crate;
/// it is a *consensus-internal* commitment used only for quorum grouping (not an external/security
/// hash), so collision-resistance against an adversary is not required — two honest interpreters
/// emitting the same ops must agree, which a stable encoding + any deterministic digest guarantees.
fn effect_hash(ops: &[Op]) -> Hash {
    let tmp = CanonicalEffect {
        ops: ops.to_vec(),
        effect_hash: [0u8; 32],
    };
    let bytes = tmp.encode();
    fnv1a_256(&bytes)
}

/// A 256-bit FNV-1a-style digest: eight independent FNV-1a lanes over the input with distinct offset
/// bases, concatenated. Deterministic, integer-only, no external crate. (Consensus-internal grouping
/// hash; see [`effect_hash`].)
fn fnv1a_256(data: &[u8]) -> Hash {
    const PRIME: u64 = 0x0000_0100_0000_01B3;
    // Eight distinct offset bases so the lanes diverge (FNV offset basis + 7 perturbations).
    const BASES: [u64; 4] = [
        0xcbf2_9ce4_8422_2325,
        0x84222325cbf29ce4u64.wrapping_mul(PRIME),
        0x1000_0000_0000_01B3,
        0xff00_ff00_ff00_ff00,
    ];
    let mut out = [0u8; 32];
    for (lane, base) in BASES.iter().enumerate() {
        let mut h = *base;
        // Mix the lane index so the two halves of each 8-byte word differ even for short inputs.
        h ^= (lane as u64).wrapping_add(1).wrapping_mul(PRIME);
        for &b in data {
            h ^= b as u64;
            h = h.wrapping_mul(PRIME);
        }
        // Final avalanche (SplitMix64 finalizer) so small input changes spread across the lane.
        h = (h ^ (h >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        h = (h ^ (h >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        h ^= h >> 31;
        out[lane * 8..lane * 8 + 8].copy_from_slice(&h.to_be_bytes());
    }
    out
}

// Tallying a [`CanonicalEffect`] shares the generic [`quorum_tally`] with M3's verdict tally. The
// grouping key is the `effect_hash` (so quorum compares the canonical-encoded ops, never any
// off-chain reason). **Every** effect — including an `Abort` — is committable at the tally level:
// reaching quorum commits the agreed effect, and the runtime then validates + applies it (an `Abort`
// applies as no state change). This differs from M3, where an `Uncertain` verdict is non-committable;
// here "fail closed" is enforced one layer down, at op validation, not at the tally (spec 04).
//
// `CanonicalEffect` is not `Copy` (it owns a `Vec<Op>`), but `quorum_tally` requires `T: Copy` via
// `QuorumEq: Copy`. So we tally over a `Copy` token that carries only the `effect_hash`, then resolve
// the committed token back to the full effect by hash (see [`tally_effects`]).

/// A `Copy` tally token carrying only an effect's quorum key (`effect_hash`). Lets the non-`Copy`
/// [`CanonicalEffect`] reuse the generic [`quorum_tally`] without cloning op vectors into the tally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EffectToken(Hash);

impl QuorumEq for EffectToken {
    type Key = Hash;
    fn quorum_key(&self) -> Self::Key {
        self.0
    }
    fn is_committable(&self) -> bool {
        // An effect is always committable at the tally layer; escrow/authority validation (and the
        // explicit-Abort no-op) happen one layer down in `resolve_case`/`apply_effect` (I4).
        true
    }
}

/// The outcome of tallying an exec case's submitted effects.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EffectTally {
    /// Still gathering submissions; quorum is still reachable.
    Pending,
    /// `>= QUORUM` interpreters produced the same canonical effect (by `effect_hash`).
    Committed(CanonicalEffect),
    /// Quorum can no longer be reached (a split) — abort deterministically.
    NoQuorum,
}

/// Tally an exec case's submitted effects against `quorum` over a jury of `jury_size`. Reuses the
/// generic [`quorum_tally`] via [`EffectToken`] (effect_hash only), then resolves the committed token
/// back to the full [`CanonicalEffect`]. Deterministic and order-independent.
fn tally_effects(
    submissions: &[(Address, CanonicalEffect)],
    jury_size: usize,
    quorum: usize,
) -> EffectTally {
    let tokens: Vec<(Address, EffectToken)> = submissions
        .iter()
        .map(|(a, e)| (*a, EffectToken(e.effect_hash)))
        .collect();
    match quorum_tally(&tokens, jury_size, quorum) {
        QuorumOutcome::Pending => EffectTally::Pending,
        QuorumOutcome::NoQuorum => EffectTally::NoQuorum,
        QuorumOutcome::Committed(tok) => {
            // Resolve the winning hash to a full effect (the first submission with that hash; all
            // submissions sharing a hash are byte-identical by construction).
            let effect = submissions
                .iter()
                .find(|(_, e)| e.effect_hash == tok.0)
                .map(|(_, e)| e.clone())
                .expect("committed token must have a backing submission");
            EffectTally::Committed(effect)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The interpreter oracle seam (spec §"The interpreter oracle"). Off-chain; each interpreter node
// runs it. Mirrors `HumanityOracle`'s place in the runtime.
// ---------------------------------------------------------------------------------------------

/// A read-only view of the state an interpreter may read for a contract (spec §"state snapshot").
/// Content-addressed inputs all honest interpreters see identically (I1/I6): only the contract's own
/// escrow balance, its declared parties, its local vars, and its owned streams — never arbitrary
/// chain state, never PII.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContractStateView {
    /// The contract id.
    pub contract_id: ContractId,
    /// The contract's escrow balance at the snapshot time, in base units.
    pub escrow: u128,
    /// The contract's declared parties (sorted — deterministic input).
    pub parties: Vec<Address>,
    /// The contract's local key/value vars (sorted by key — deterministic input).
    pub vars: Vec<(Hash, Hash)>,
    /// Stream ids the contract's escrow owns (sorted — deterministic input).
    pub streams: Vec<StreamId>,
    /// The snapshot timestamp (unix seconds).
    pub now: u64,
}

/// The off-chain AI interpreter (spec §"The interpreter oracle"). Each interpreter node runs an
/// implementation, signs the [`CanonicalEffect`], and submits it; the runtime tallies the signed
/// effects deterministically and commits only on quorum.
///
/// Determinism (I1): a real impl (the `ClaudeInterpreter`, M4-T3, a separate crate) pins the model,
/// seed, and temperature 0 and emits the canonical effect schema only — the contract text **and** the
/// trigger are *untrusted data* (prompt-injection-resistant: fenced; the model may emit only the
/// schema, never free actions). The runtime treats the interpreter as a black box: it consumes only
/// the [`CanonicalEffect`] and validates every op against escrow/authority itself (I6).
pub trait ContractInterpreter: Send + Sync {
    /// Map `(contract text, state snapshot, trigger input)` → a canonical effect. Honest interpreters
    /// seeing identical inputs converge on the same effect (so the quorum forms).
    fn interpret(
        &self,
        contract_text: &[u8],
        state: &ContractStateView,
        trigger: &[u8],
    ) -> CanonicalEffect;
}

/// A scripted, fully-deterministic interpreter for CI / the whole-lifecycle tests (I5 — no live
/// calls). Resolution order:
///   1. an exact override keyed off `(contract_text, trigger)`, if scripted;
///   2. an override keyed off `trigger` alone, if scripted;
///   3. otherwise the configured `default` effect (a no-op by default).
///
/// This makes every lifecycle test reproducible and offline: a fixed `(text, trigger)` always yields
/// the same `CanonicalEffect`, so all honest interpreters agree and the quorum/tally path is exercised
/// without any model. The live node swaps in the Claude-backed impl behind the same trait (M4-T3).
#[derive(Clone, Debug)]
pub struct MockInterpreter {
    default: CanonicalEffect,
    by_text_trigger: HashMap<(Vec<u8>, Vec<u8>), CanonicalEffect>,
    by_trigger: HashMap<Vec<u8>, CanonicalEffect>,
}

impl Default for MockInterpreter {
    fn default() -> Self {
        Self::new(CanonicalEffect::noop())
    }
}

impl MockInterpreter {
    /// A mock whose default effect is `default` (used when no override matches an input).
    pub fn new(default: CanonicalEffect) -> Self {
        Self {
            default,
            by_text_trigger: HashMap::new(),
            by_trigger: HashMap::new(),
        }
    }

    /// Always return `effect` regardless of input.
    pub fn always(effect: CanonicalEffect) -> Self {
        Self::new(effect)
    }

    /// Script an effect for a specific `(contract_text, trigger)` pair (builder style).
    pub fn with(mut self, contract_text: &[u8], trigger: &[u8], effect: CanonicalEffect) -> Self {
        self.by_text_trigger
            .insert((contract_text.to_vec(), trigger.to_vec()), effect);
        self
    }

    /// Script an effect for a specific `trigger` blob, any contract text (builder style).
    pub fn with_trigger(mut self, trigger: &[u8], effect: CanonicalEffect) -> Self {
        self.by_trigger.insert(trigger.to_vec(), effect);
        self
    }
}

impl ContractInterpreter for MockInterpreter {
    fn interpret(
        &self,
        contract_text: &[u8],
        _state: &ContractStateView,
        trigger: &[u8],
    ) -> CanonicalEffect {
        if let Some(e) = self
            .by_text_trigger
            .get(&(contract_text.to_vec(), trigger.to_vec()))
        {
            return e.clone();
        }
        if let Some(e) = self.by_trigger.get(trigger) {
            return e.clone();
        }
        self.default.clone()
    }
}

// ---------------------------------------------------------------------------------------------
// On-chain state types (spec §"Data model").
// ---------------------------------------------------------------------------------------------

/// Lifecycle status of a [`PromptContract`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ContractStatus {
    /// Deployed and live; can be funded and invoked.
    #[default]
    Active,
    /// Terminated (e.g. a committed effect fully refunded the escrow). No longer invocable.
    Terminated,
}

/// A deployed natural-language prompt contract (spec §"Data model"). The **full** NL text now lives
/// on-chain (in the deploy tx calldata and in this record) — transparency is the whole point: the
/// explorer can show the agreement, and interpretation is fully reproducible from chain state (no
/// off-chain text fetch). `text_ref = keccak256(utf8(text))` is kept as a stable content commitment.
/// `escrow` is the **only** value the contract can move (least authority — I6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PromptContract {
    pub id: ContractId,
    /// Escrowed base units the contract controls (mirrors the escrow account at [`contract_address`]).
    pub escrow: u128,
    /// Declared parties — the only addresses a `Refund` may target (sorted, deduped).
    pub parties: Vec<Address>,
    /// The **full** natural-language contract text (stored on-chain — transparency). The interpreter
    /// reads this at invoke time, so interpretation is reproducible from chain state alone.
    pub text: String,
    /// Content commitment `keccak256(utf8(text))` (a stable id for the text; kept for compatibility).
    pub text_ref: Hash,
    /// Contract-local key/value state, set by `SetVar` ops.
    pub vars: HashMap<Hash, Hash>,
    pub status: ContractStatus,
    /// Block height the contract was deployed at (for the explorer / contract detail view).
    pub deploy_block: u64,
    /// Hash of the deploy tx (for the explorer / contract detail view). Zero until stamped by the node.
    pub deploy_tx: Hash,
}

impl PromptContract {
    /// A fresh `Active` contract with zero escrow, the given parties, the full NL `text`, and its
    /// content commitment `text_ref` (the node computes `text_ref = keccak256(utf8(text))` — the
    /// runtime stays dependency-free, so the hash is supplied by the caller). Deploy block/tx are
    /// stamped to zero here and set by the node when the deploy tx is mined (see the RPC
    /// `DeployContract` apply arm).
    pub fn new(id: ContractId, text: String, text_ref: Hash, mut parties: Vec<Address>) -> Self {
        parties.sort_unstable();
        parties.dedup();
        Self {
            id,
            escrow: 0,
            parties,
            text,
            text_ref,
            vars: HashMap::new(),
            status: ContractStatus::Active,
            deploy_block: 0,
            deploy_tx: [0u8; 32],
        }
    }

    /// Is `addr` a declared party of this contract? (`Refund` authority check — I6.)
    pub fn is_party(&self, addr: &Address) -> bool {
        self.parties.binary_search(addr).is_ok()
    }

    /// Contract-local vars as a deterministic, sorted `(key, value)` list (for [`ContractStateView`]).
    pub fn sorted_vars(&self) -> Vec<(Hash, Hash)> {
        let mut v: Vec<(Hash, Hash)> = self.vars.iter().map(|(k, val)| (*k, *val)).collect();
        v.sort_unstable();
        v
    }
}

/// Lifecycle of an [`ExecCase`] (one invocation under interpretation; parallels M3's `Case`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecStatus {
    /// Collecting interpreter effect submissions.
    Open,
    /// A quorum agreed on a canonical effect, validated, and applied atomically.
    Committed(CanonicalEffect),
    /// Disagreement / split / invalid-or-over-authority effect — aborted, no state change (I4).
    Aborted,
}

/// One invocation of a contract under interpretation (spec §"Data model"). Parallels M3's `Case`: an
/// interpreter quorum is selected like a jury; each interpreter submits a [`CanonicalEffect`]; the
/// runtime tallies and commits/aborts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecCase {
    pub id: ExecCaseId,
    pub contract: ContractId,
    /// Commitment to the off-chain trigger input that drove this invocation.
    pub trigger_ref: Hash,
    /// Who invoked the contract.
    pub invoker: Address,
    /// The interpreter quorum (selected from the active juror registry like an M3 jury).
    pub jury: Vec<Address>,
    /// Submitted effects keyed by interpreter, stored as a sorted-by-submission `Vec` (not a map) so
    /// tallying never depends on hash-iteration order (I1).
    pub effects: Vec<(Address, CanonicalEffect)>,
    pub status: ExecStatus,
    /// Block height the case opened at (for explorer / future timeout policy).
    pub opened_at: u64,
    /// Block height the case **resolved** in (committed or aborted), if it has resolved. `None` while
    /// the case is still `Open`. Set by the node when the resolving block is mined.
    pub resolved_at: Option<u64>,
}

impl ExecCase {
    /// Look up an interpreter's submitted effect, if any.
    pub fn effect_of(&self, interpreter: &Address) -> Option<&CanonicalEffect> {
        self.effects
            .iter()
            .find(|(a, _)| a == interpreter)
            .map(|(_, e)| e)
    }
}

// ---------------------------------------------------------------------------------------------
// Errors (deterministic so two nodes reject identically — I1/I4).
// ---------------------------------------------------------------------------------------------

/// Why a contract lifecycle op was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractError {
    /// `deploy_contract` with an empty parties list (a contract must have at least one party so a
    /// `Refund` always has a valid target — fail-closed).
    NoParties,
    /// `deploy_contract` whose on-chain UTF-8 `text` exceeds [`crate::MAX_CONTRACT_TEXT_BYTES`]. The
    /// text is permanent state, so an unbounded blob is a state-bloat DoS (C6-SEC-1); reject it. Carries
    /// the offending length and the cap.
    TextTooLarge { len: usize, max: usize },
    /// `deploy_contract` whose declared `parties` exceed [`crate::MAX_CONTRACT_PARTIES`] (C6-SEC-1).
    /// Carries the offending count and the cap.
    TooManyParties { count: usize, max: usize },
    /// An op references an unknown contract id.
    NoSuchContract(ContractId),
    /// An op targets a contract that is `Terminated`.
    ContractTerminated(ContractId),
    /// `invoke_contract` when no active interpreters are registered (fail closed — I4).
    NoInterpreters,
    /// An op references an unknown exec-case id.
    NoSuchCase(ExecCaseId),
    /// `submit_effect` from an address not on the case's interpreter jury.
    NotOnJury,
    /// `submit_effect` to a case that is already `Committed`/`Aborted` (not `Open`).
    CaseClosed,
    /// `submit_effect` from an interpreter that already submitted on this case.
    AlreadySubmitted,
    /// `fund_contract`'s underlying value transfer (funder → escrow) failed (bad nonce / insufficient
    /// balance). Carries the precise [`TransferError`] for the RPC layer. Fail-closed: no state change.
    Transfer(TransferError),
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ContractError::*;
        match self {
            NoParties => write!(f, "a contract must declare at least one party"),
            TextTooLarge { len, max } => {
                write!(
                    f,
                    "contract text is {len} bytes, exceeds the {max}-byte cap"
                )
            }
            TooManyParties { count, max } => {
                write!(
                    f,
                    "contract declares {count} parties, exceeds the {max} cap"
                )
            }
            NoSuchContract(id) => write!(f, "no such contract: {id}"),
            ContractTerminated(id) => write!(f, "contract {id} is terminated"),
            NoInterpreters => write!(f, "no active interpreters to interpret the contract"),
            NoSuchCase(id) => write!(f, "no such exec case: {id}"),
            NotOnJury => write!(f, "submitter is not on this case's interpreter jury"),
            CaseClosed => write!(f, "exec case is already committed or aborted"),
            AlreadySubmitted => write!(f, "interpreter already submitted on this case"),
            Transfer(e) => write!(f, "contract funding transfer failed: {e}"),
        }
    }
}

impl std::error::Error for ContractError {}

// ---------------------------------------------------------------------------------------------
// Lifecycle (pure, deterministic, fail-closed) — the contract-execution state machine.
// ---------------------------------------------------------------------------------------------

/// Deploy a natural-language prompt contract: register it `Active` with zero escrow, the **full** NL
/// `text` stored on-chain, its content commitment `text_ref` (the node passes
/// `keccak256(utf8(text))`), and the declared `parties`. Returns the new contract id. Fail-closed: at
/// least one party is required (so a `Refund` always has a valid target).
///
/// The escrow account at [`contract_address`] is left at zero balance; funding raises it (see
/// [`fund_contract`]).
pub fn deploy_contract(
    state: &mut dyn State,
    text: String,
    text_ref: Hash,
    parties: Vec<Address>,
) -> Result<ContractId, ContractError> {
    if parties.is_empty() {
        return Err(ContractError::NoParties);
    }
    // Defense in depth (C6-SEC-1): the RPC submit gate rejects an oversized text/parties before the tx
    // ever enters the mempool, but the runtime is the consensus authority — re-check here so the bound
    // holds regardless of how the op reached `deploy_contract`. `String` is UTF-8, so `len()` is the
    // exact on-chain byte count. Fail-closed: no contract is created.
    if text.len() > crate::MAX_CONTRACT_TEXT_BYTES {
        return Err(ContractError::TextTooLarge {
            len: text.len(),
            max: crate::MAX_CONTRACT_TEXT_BYTES,
        });
    }
    if parties.len() > crate::MAX_CONTRACT_PARTIES {
        return Err(ContractError::TooManyParties {
            count: parties.len(),
            max: crate::MAX_CONTRACT_PARTIES,
        });
    }
    let id = state.next_contract_id();
    state.put_contract(PromptContract::new(id, text, text_ref, parties));
    Ok(id)
}

/// Fund a contract's escrow with `amount` base units from `funder` (a normal value transfer into the
/// contract's escrow account), at unix second `now`. The funder is settled and debited like any
/// transfer; the contract's `escrow` field is raised and kept in lock-step with the escrow account
/// balance. Fail-closed: unknown/terminated contract or insufficient funder balance ⇒ no state change.
///
/// `nonce` is the funder's EIP-155 nonce (the funding tx). This reuses [`crate::apply_transfer`]'s
/// settlement + nonce + balance semantics by performing the same checks here against the escrow
/// account, so funding is a normal on-chain transfer to [`contract_address(id)`].
pub fn fund_contract(
    state: &mut dyn State,
    funder: &Address,
    id: ContractId,
    amount: u128,
    nonce: u64,
    now: u64,
) -> Result<(), ContractError> {
    let mut contract = state
        .get_contract(id)
        .ok_or(ContractError::NoSuchContract(id))?;
    if contract.status == ContractStatus::Terminated {
        return Err(ContractError::ContractTerminated(id));
    }
    // Move value funder -> escrow account via the standard transfer path (settles + nonce + balance;
    // fail-closed on any error — no partial writes). The precise `TransferError` is surfaced for the
    // RPC layer; on error nothing was written, so the contract's escrow field stays in lock-step.
    let escrow_addr = contract_address(id);
    crate::apply_transfer(state, funder, &escrow_addr, amount, nonce, now)
        .map_err(ContractError::Transfer)?;
    contract.escrow = contract.escrow.saturating_add(amount);
    state.put_contract(contract);
    Ok(())
}

/// Mix an exec-case id with chain entropy into an interpreter-selection seed (mirrors M3's
/// `jury_seed`). Both inputs are consensus values, so the seed is byte-reproducible across nodes.
fn interpreter_seed(case_id: ExecCaseId, entropy: u64) -> u64 {
    let mut z = case_id.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ entropy;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Build the deterministic [`ContractStateView`] an interpreter sees for `contract` at `now` (I1/I6:
/// only the contract's own escrow, parties, vars, and owned streams — nothing else).
fn state_view(state: &dyn State, contract: &PromptContract, now: u64) -> ContractStateView {
    let escrow_addr = contract_address(contract.id);
    let mut streams = state.outgoing(&escrow_addr);
    streams.sort_unstable();
    ContractStateView {
        contract_id: contract.id,
        escrow: contract.escrow,
        parties: contract.parties.clone(),
        vars: contract.sorted_vars(),
        streams,
        now,
    }
}

/// Invoke a contract: open an [`ExecCase`], select an interpreter quorum (deterministic, like an M3
/// jury), and have each selected interpreter compute its [`CanonicalEffect`] from
/// `(text, state_snapshot, trigger)`. The submitted effects are recorded and tallied immediately; if a
/// quorum already agrees (the common case with honest, deterministic interpreters) the effect is
/// validated + applied atomically and the case `Committed`/`Aborted` in this call. Otherwise the case
/// stays `Open` for later [`submit_effect`] submissions.
///
/// The interpreter reads the contract's **stored on-chain text** (`contract.text`) — interpretation is
/// reproducible from chain state alone (no off-chain text fetch). `trigger` is the off-chain trigger
/// bytes (committed by `trigger_ref`). `entropy` folds chain entropy into interpreter selection; `now`
/// is the unix second of invocation.
///
/// Fail-closed: no active interpreters ⇒ `NoInterpreters` and no case is opened (I4). An unknown or
/// terminated contract is rejected with no state change.
#[allow(clippy::too_many_arguments)]
pub fn invoke_contract(
    state: &mut dyn State,
    interpreter: &dyn ContractInterpreter,
    id: ContractId,
    trigger_ref: Hash,
    trigger: &[u8],
    invoker: Address,
    entropy: u64,
    block: u64,
    now: u64,
) -> Result<ExecCaseId, ContractError> {
    let contract = state
        .get_contract(id)
        .ok_or(ContractError::NoSuchContract(id))?;
    if contract.status == ContractStatus::Terminated {
        return Err(ContractError::ContractTerminated(id));
    }

    let candidates = state.active_jurors();
    if candidates.is_empty() {
        return Err(ContractError::NoInterpreters);
    }

    let case_id = state.next_exec_case_id();
    let jury = select_jury(candidates, JURY_SIZE, interpreter_seed(case_id, entropy));

    // Each interpreter computes its effect from the same content-addressed inputs (I1): the contract's
    // own stored text + the deterministic state view + the trigger. Reading `contract.text` from chain
    // state (not an off-chain ref) makes interpretation fully reproducible across nodes.
    let contract_text = contract.text.as_bytes();
    let view = state_view(state, &contract, now);
    let mut effects: Vec<(Address, CanonicalEffect)> = Vec::with_capacity(jury.len());
    for interp_addr in &jury {
        let effect = interpreter.interpret(contract_text, &view, trigger);
        effects.push((*interp_addr, effect));
    }

    let mut case = ExecCase {
        id: case_id,
        contract: id,
        trigger_ref,
        invoker,
        jury,
        effects,
        status: ExecStatus::Open,
        opened_at: block,
        resolved_at: None,
    };

    resolve_case(state, &mut case, block, now);
    state.put_exec_case(case);
    Ok(case_id)
}

/// Record an interpreter's submitted effect on `case_id` and re-tally (the deferred-submission path:
/// for an off-chain juror daemon that submits effects as separate txs). Only an interpreter on the
/// case's jury may submit, once. When a quorum forms the effect is validated + applied atomically and
/// the case transitions to `Committed`/`Aborted`; a split aborts deterministically. Returns the
/// resulting [`ExecStatus`].
pub fn submit_effect(
    state: &mut dyn State,
    case_id: ExecCaseId,
    interpreter: &Address,
    effect: CanonicalEffect,
    block: u64,
    now: u64,
) -> Result<ExecStatus, ContractError> {
    let mut case = state
        .get_exec_case(case_id)
        .ok_or(ContractError::NoSuchCase(case_id))?;
    if !matches!(case.status, ExecStatus::Open) {
        return Err(ContractError::CaseClosed);
    }
    if !case.jury.contains(interpreter) {
        return Err(ContractError::NotOnJury);
    }
    if case.effect_of(interpreter).is_some() {
        return Err(ContractError::AlreadySubmitted);
    }

    case.effects.push((*interpreter, effect));
    resolve_case(state, &mut case, block, now);
    let status = case.status.clone();
    state.put_exec_case(case);
    Ok(status)
}

/// Tally a case's submitted effects and, on quorum, validate + apply the agreed effect atomically.
/// Sets the case's status. Pure on `state` + `case`:
///   * `Pending` ⇒ leave `Open`;
///   * `NoQuorum` (split) ⇒ `Aborted`, no state change;
///   * `Committed(effect)` ⇒ validate every op against escrow/authority; if all valid, apply
///     atomically and set `Committed(effect)`; if any op is invalid (over-escrow / non-party refund /
///     a pure `Abort`), set `Aborted` and make no state change (I4 fail-closed).
fn resolve_case(state: &mut dyn State, case: &mut ExecCase, block: u64, now: u64) {
    match tally_effects(&case.effects, JURY_SIZE, QUORUM) {
        // Still gathering submissions — the case stays Open and unresolved.
        EffectTally::Pending => case.status = ExecStatus::Open,
        EffectTally::NoQuorum => {
            case.status = ExecStatus::Aborted;
            case.resolved_at = Some(block);
        }
        EffectTally::Committed(effect) => {
            // An explicit single-Abort effect: a quorum agreed to abort — no state change (I4).
            if effect.is_abort() {
                case.status = ExecStatus::Aborted;
                case.resolved_at = Some(block);
                return;
            }
            match apply_effect(state, case.contract, &effect, now) {
                Ok(()) => case.status = ExecStatus::Committed(effect),
                // Any validation/apply failure ⇒ fail closed, no state change (apply_effect is
                // all-or-nothing: it only commits to `state` after validating the whole effect).
                Err(_) => case.status = ExecStatus::Aborted,
            }
            case.resolved_at = Some(block);
        }
    }
}

/// Why applying a committed effect failed (validation against escrow/authority — done in the runtime,
/// not the LLM; I6). Any of these aborts the **whole** effect with no state change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EffectError {
    /// The effect's escrow draws (Transfer + Refund + OpenStream deposits) exceed the contract escrow.
    Insolvent { need: u128, escrow: u128 },
    /// A `Refund` targets an address that is not a declared party of the contract (I6).
    RefundToNonParty(Address),
    /// An `OpenStream`/`StopStream` op failed the M2 stream layer (e.g. rate too high, not owned).
    Stream(StreamError),
    /// A `StopStream` targets a stream the contract's escrow does not own (least authority — I6).
    NotOwnedStream(StreamId),
    /// The committed effect was a pure `Abort` (handled as a no-op abort by the caller).
    AbortOp,
}

impl std::fmt::Display for EffectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EffectError::Insolvent { need, escrow } => {
                write!(f, "effect draws {need} but escrow holds only {escrow}")
            }
            EffectError::RefundToNonParty(_) => write!(f, "refund to a non-party address"),
            EffectError::Stream(e) => write!(f, "stream op failed: {e}"),
            EffectError::NotOwnedStream(id) => {
                write!(f, "stop of stream {id} the contract does not own")
            }
            EffectError::AbortOp => write!(f, "explicit abort effect"),
        }
    }
}

impl std::error::Error for EffectError {}

/// Validate **and** apply a committed effect atomically (all-or-nothing). Validation runs first
/// **entirely** (escrow solvency, party authority, and stream ownership), against a copy of the
/// contract and the escrow's owned-stream set; only if the *whole* effect validates do we touch
/// `state` (I4 fail-closed: no partial application). Least authority (I6): every value-moving op draws
/// from the contract's own escrow and a `Refund` may only target a declared party; a `StopStream` may
/// only stop a stream the escrow owns.
///
/// Determinism (I2): integer-only; the escrow draw is summed exactly; stream ops reuse the M2
/// integer math.
fn apply_effect(
    state: &mut dyn State,
    contract_id: ContractId,
    effect: &CanonicalEffect,
    now: u64,
) -> Result<(), EffectError> {
    let contract = state
        .get_contract(contract_id)
        // A committed effect always has a backing contract (the case was opened for it); treat a
        // missing contract as a fail-closed abort.
        .ok_or(EffectError::Insolvent { need: 0, escrow: 0 })?;
    let escrow_addr = contract_address(contract_id);
    let owned_streams: std::collections::HashSet<StreamId> =
        state.outgoing(&escrow_addr).into_iter().collect();

    // ---- Phase 1: validate the WHOLE effect (no mutation) ----
    // Sum the escrow *draws* (Transfer + Refund + OpenStream deposit) and check solvency against the
    // escrow once, so a multi-op effect can never partially over-draw. StopStream releases escrow back
    // (a refund), so it does not count against the draw budget.
    let mut draw: u128 = 0;
    for op in &effect.ops {
        match op {
            Op::Transfer { amount, .. } => draw = draw.saturating_add(*amount),
            Op::Refund { party, amount } => {
                if !contract.is_party(party) {
                    return Err(EffectError::RefundToNonParty(*party));
                }
                draw = draw.saturating_add(*amount);
            }
            Op::OpenStream { rate, deposit, .. } => {
                // Validate the stream params up front (rate bound etc.) so an invalid stream aborts
                // the whole effect before any mutation. `deposit` counts against the escrow draw.
                if *rate == 0 {
                    return Err(EffectError::Stream(StreamError::ZeroRate));
                }
                if *deposit == 0 {
                    return Err(EffectError::Stream(StreamError::ZeroDeposit));
                }
                if *rate > crate::MAX_RATE {
                    return Err(EffectError::Stream(StreamError::RateTooHigh {
                        rate: *rate,
                        max: crate::MAX_RATE,
                    }));
                }
                draw = draw.saturating_add(*deposit);
            }
            Op::StopStream { id } => {
                if !owned_streams.contains(id) {
                    return Err(EffectError::NotOwnedStream(*id));
                }
            }
            Op::SetVar { .. } => {}
            Op::Abort { .. } => return Err(EffectError::AbortOp),
        }
    }
    if draw > contract.escrow {
        return Err(EffectError::Insolvent {
            need: draw,
            escrow: contract.escrow,
        });
    }

    // ---- Phase 2: apply (only reached if the WHOLE effect validated) ----
    // The escrow account must be able to fund the draw; its balance is kept in lock-step with
    // `contract.escrow`, and we validated draw <= escrow, so the transfers below cannot fail on
    // balance. We thread the escrow account's nonce through the value-moving ops.
    let mut contract = contract; // owned, mutated then written back once.
    let mut escrow_acct = state.get(&escrow_addr).unwrap_or(crate::Account {
        address: escrow_addr,
        ..Default::default()
    });
    // Settle the escrow account so its balance is materialized before we move value.
    escrow_acct.settle(now);
    let mut escrow_nonce = escrow_acct.nonce;
    state.put(escrow_acct);

    for op in &effect.ops {
        match op {
            Op::Transfer { to, amount } => {
                crate::apply_transfer(state, &escrow_addr, to, *amount, escrow_nonce, now)
                    .expect("validated transfer must succeed (escrow >= draw)");
                escrow_nonce += 1;
                contract.escrow = contract.escrow.saturating_sub(*amount);
            }
            Op::Refund { party, amount } => {
                crate::apply_transfer(state, &escrow_addr, party, *amount, escrow_nonce, now)
                    .expect("validated refund must succeed (escrow >= draw, party checked)");
                escrow_nonce += 1;
                contract.escrow = contract.escrow.saturating_sub(*amount);
            }
            Op::OpenStream { to, rate, deposit } => {
                open_stream(state, &escrow_addr, to, *rate, *deposit, now)
                    .expect("validated stream open must succeed (escrow >= draw, params checked)");
                contract.escrow = contract.escrow.saturating_sub(*deposit);
            }
            Op::StopStream { id } => {
                // Stopping returns the unused deposit to the escrow account; fold it back into the
                // contract's escrow field so the two stay in lock-step.
                let refund = stop_stream(state, *id, &escrow_addr, now)
                    .map_err(EffectError::Stream)
                    .expect("validated stop must succeed (ownership checked)");
                contract.escrow = contract.escrow.saturating_add(refund);
            }
            Op::SetVar { key, value } => {
                contract.vars.insert(*key, *value);
            }
            // Abort is rejected in phase 1; unreachable here.
            Op::Abort { .. } => unreachable!("Abort op rejected during validation"),
        }
    }

    // The contract stays `Active` after a committed effect (it may be invoked again — e.g. a multi-
    // stage agreement, or a refund that only partly drains escrow). Auto-termination on a fully-
    // drained escrow is intentionally NOT done here: it is a policy decision deferred to the RPC/
    // wallet layer (M4-T4), keeping this apply path purely about the escrow/var deltas.
    state.put_contract(contract);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{lifecycle::register_juror, MemState, UBI};

    fn addr(b: u8) -> Address {
        [b; 20]
    }

    /// Register `n` jurors (interpreters) `addr(100+i)` so a quorum can form.
    fn register_interpreters(state: &mut MemState, n: u8) -> Vec<Address> {
        let mut v = Vec::new();
        for i in 0..n {
            let a = addr(100 + i);
            register_juror(state, &a, 0);
            v.push(a);
        }
        v
    }

    /// Seed `addr` as a funded verified account so it can fund an escrow.
    fn seed_funded(state: &mut MemState, a: Address, settled: u128) {
        state.put(crate::Account {
            address: a,
            verified: true,
            verified_at: 0,
            last_settled_at: 0,
            settled_balance: settled,
            nonce: 0,
        });
    }

    /// A deterministic stand-in text commitment for tests (the node uses keccak; the runtime only
    /// stores whatever ref it is handed). Distinct per text so two contracts don't alias.
    fn tref(text: &str) -> Hash {
        let mut h = [0u8; 32];
        for (i, b) in text.bytes().enumerate() {
            h[i % 32] ^= b;
        }
        h[31] ^= text.len() as u8;
        h
    }

    /// Deploy a contract with the given plain-language `text`, deriving its `text_ref` via [`tref`].
    fn deploy(state: &mut MemState, text: &str, parties: Vec<Address>) -> ContractId {
        deploy_contract(state, text.to_string(), tref(text), parties).unwrap()
    }

    // -----------------------------------------------------------------------------------------
    // Canonical encoding / hashing.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn effect_hash_is_deterministic_and_distinguishes_ops() {
        let e1 = CanonicalEffect::new(vec![Op::Transfer {
            to: addr(2),
            amount: UBI,
        }]);
        let e2 = CanonicalEffect::new(vec![Op::Transfer {
            to: addr(2),
            amount: UBI,
        }]);
        // Same ops ⇒ same hash (so honest interpreters' effects group together — I1).
        assert_eq!(e1.effect_hash, e2.effect_hash);

        // A different amount, recipient, or op order changes the hash.
        let e3 = CanonicalEffect::new(vec![Op::Transfer {
            to: addr(2),
            amount: UBI + 1,
        }]);
        let e4 = CanonicalEffect::new(vec![Op::Transfer {
            to: addr(3),
            amount: UBI,
        }]);
        let e5 = CanonicalEffect::new(vec![
            Op::Transfer {
                to: addr(2),
                amount: UBI,
            },
            Op::SetVar {
                key: [1u8; 32],
                value: [2u8; 32],
            },
        ]);
        assert_ne!(e1.effect_hash, e3.effect_hash);
        assert_ne!(e1.effect_hash, e4.effect_hash);
        assert_ne!(e1.effect_hash, e5.effect_hash);
        // Distinct op variants with the same trailing bytes don't alias (tag prefix).
        let t = CanonicalEffect::new(vec![Op::Transfer {
            to: addr(7),
            amount: 5,
        }]);
        let r = CanonicalEffect::new(vec![Op::Refund {
            party: addr(7),
            amount: 5,
        }]);
        assert_ne!(t.effect_hash, r.effect_hash);
    }

    // -----------------------------------------------------------------------------------------
    // AC1 — deploy → fund → invoke → Transfer from escrow.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn ac1_deploy_fund_invoke_transfers_from_escrow() {
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        let payee = addr(2);
        seed_funded(&mut s, funder, 100 * UBI);

        // Deploy a contract whose plain-language intent is "pay 5 UBI to the payee".
        let text = "pay 5 UBI to the payee on signal";
        let parties = vec![funder, payee];
        let id = deploy(&mut s, text, parties);
        let escrow_addr = contract_address(id);
        // The full text is stored on-chain verbatim.
        assert_eq!(s.get_contract(id).unwrap().text, text);

        // Fund the escrow with 10 UBI.
        fund_contract(&mut s, &funder, id, 10 * UBI, 0, 0).unwrap();
        assert_eq!(s.get_contract(id).unwrap().escrow, 10 * UBI);
        assert_eq!(s.balance(&escrow_addr, 0), 10 * UBI);

        // The interpreter keys off the *stored* contract text + the trigger ⇒ "Transfer 5 UBI to
        // payee". (If the interpreter read anything but `contract.text`, this override would miss and
        // the no-op default would commit instead.)
        let trigger = b"signal";
        let interp = MockInterpreter::default().with(
            text.as_bytes(),
            trigger,
            CanonicalEffect::new(vec![Op::Transfer {
                to: payee,
                amount: 5 * UBI,
            }]),
        );

        let case_id = invoke_contract(
            &mut s, &interp, id, [7u8; 32], trigger, funder, 0xABCD, 1, 0,
        )
        .unwrap();

        // Committed: the agreed effect transferred from escrow to the payee.
        let case = s.get_exec_case(case_id).unwrap();
        assert!(matches!(case.status, ExecStatus::Committed(_)));
        assert_eq!(s.balance(&payee, 0), 5 * UBI);
        // Escrow drained by exactly 5 UBI (both the account and the contract field).
        assert_eq!(s.balance(&escrow_addr, 0), 5 * UBI);
        assert_eq!(s.get_contract(id).unwrap().escrow, 5 * UBI);
    }

    // -----------------------------------------------------------------------------------------
    // AC2 — over-escrow / non-party effect → Abort, no state change.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn ac2_over_escrow_aborts_no_state_change() {
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        let payee = addr(2);
        seed_funded(&mut s, funder, 100 * UBI);
        let id = deploy(&mut s, "pay the payee from escrow", vec![funder, payee]);
        fund_contract(&mut s, &funder, id, 3 * UBI, 0, 0).unwrap();
        let escrow_addr = contract_address(id);

        // Effect tries to move 5 UBI but escrow holds only 3 ⇒ whole effect aborts.
        let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Transfer {
            to: payee,
            amount: 5 * UBI,
        }]));
        let case_id =
            invoke_contract(&mut s, &interp, id, [0u8; 32], b"x", funder, 1, 1, 0).unwrap();

        assert_eq!(
            s.get_exec_case(case_id).unwrap().status,
            ExecStatus::Aborted
        );
        // No state change: escrow intact, payee untouched.
        assert_eq!(s.get_contract(id).unwrap().escrow, 3 * UBI);
        assert_eq!(s.balance(&escrow_addr, 0), 3 * UBI);
        assert_eq!(s.balance(&payee, 0), 0);
    }

    #[test]
    fn ac2_refund_to_non_party_aborts_no_state_change() {
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        let stranger = addr(50); // NOT a declared party
        seed_funded(&mut s, funder, 100 * UBI);
        let id = deploy(&mut s, "single-party escrow agreement", vec![funder]);
        fund_contract(&mut s, &funder, id, 8 * UBI, 0, 0).unwrap();

        // Refund to a non-party ⇒ authority violation ⇒ abort (I6).
        let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Refund {
            party: stranger,
            amount: UBI,
        }]));
        let case_id =
            invoke_contract(&mut s, &interp, id, [0u8; 32], b"x", funder, 1, 1, 0).unwrap();

        assert_eq!(
            s.get_exec_case(case_id).unwrap().status,
            ExecStatus::Aborted
        );
        assert_eq!(s.get_contract(id).unwrap().escrow, 8 * UBI);
        assert_eq!(s.balance(&stranger, 0), 0);
    }

    #[test]
    fn ac2_multi_op_partial_over_escrow_aborts_atomically() {
        // A two-op effect: a valid 2 UBI transfer + a 5 UBI transfer; combined 7 > escrow 6 ⇒ the
        // WHOLE effect aborts, including the otherwise-valid first op (atomicity, I4).
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        let a = addr(2);
        let b = addr(3);
        seed_funded(&mut s, funder, 100 * UBI);
        let id = deploy(&mut s, "split escrow to a and b", vec![funder, a, b]);
        fund_contract(&mut s, &funder, id, 6 * UBI, 0, 0).unwrap();

        let interp = MockInterpreter::always(CanonicalEffect::new(vec![
            Op::Transfer {
                to: a,
                amount: 2 * UBI,
            },
            Op::Transfer {
                to: b,
                amount: 5 * UBI,
            },
        ]));
        let case_id =
            invoke_contract(&mut s, &interp, id, [0u8; 32], b"x", funder, 1, 1, 0).unwrap();

        assert_eq!(
            s.get_exec_case(case_id).unwrap().status,
            ExecStatus::Aborted
        );
        // Neither op applied.
        assert_eq!(s.get_contract(id).unwrap().escrow, 6 * UBI);
        assert_eq!(s.balance(&a, 0), 0);
        assert_eq!(s.balance(&b, 0), 0);
    }

    // -----------------------------------------------------------------------------------------
    // AC3 — quorum determinism + split → Abort.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn ac3_split_aborts_deterministically() {
        // A unanimous (all-agree) invocation commits; a genuine 3-way split aborts deterministically.
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        seed_funded(&mut s, funder, 100 * UBI);
        let id = deploy(&mut s, "two-party escrow agreement", vec![funder, addr(2)]);
        fund_contract(&mut s, &funder, id, 10 * UBI, 0, 0).unwrap();

        // All three jurors run the same MockInterpreter (no-op default) ⇒ unanimous ⇒ Committed.
        let interp = MockInterpreter::default();
        let case_id =
            invoke_contract(&mut s, &interp, id, [0u8; 32], b"x", funder, 7, 1, 0).unwrap();
        assert!(matches!(
            s.get_exec_case(case_id).unwrap().status,
            ExecStatus::Committed(_)
        ));

        // A genuine split: three jurors each submit a *different* effect ⇒ no group reaches QUORUM ⇒
        // NoQuorum ⇒ the case aborts deterministically (I4). We assert it directly on the tally (the
        // consensus core) since `invoke_contract` runs one MockInterpreter for the whole jury.
        let jurors = s.active_jurors();
        let split = vec![
            (
                jurors[0],
                CanonicalEffect::new(vec![Op::Transfer {
                    to: addr(2),
                    amount: UBI,
                }]),
            ),
            (
                jurors[1],
                CanonicalEffect::new(vec![Op::Transfer {
                    to: addr(2),
                    amount: 2 * UBI,
                }]),
            ),
            (
                jurors[2],
                CanonicalEffect::new(vec![Op::Transfer {
                    to: addr(2),
                    amount: 3 * UBI,
                }]),
            ),
        ];
        assert_eq!(
            tally_effects(&split, JURY_SIZE, QUORUM),
            EffectTally::NoQuorum
        );
    }

    #[test]
    fn ac3_quorum_determinism_two_nodes_agree() {
        // I1: identical (text, state, trigger) + MockInterpreter ⇒ identical CanonicalEffect across
        // interpreters; the same op sequence on two independent states commits byte-identically.
        let build = || -> (MemState, ExecCaseId) {
            let mut s = MemState::new();
            register_interpreters(&mut s, 3);
            let funder = addr(1);
            let payee = addr(2);
            seed_funded(&mut s, funder, 100 * UBI);
            let id = deploy(&mut s, "pay the payee from escrow", vec![funder, payee]);
            fund_contract(&mut s, &funder, id, 10 * UBI, 0, 0).unwrap();
            let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Transfer {
                to: payee,
                amount: 4 * UBI,
            }]));
            let case_id =
                invoke_contract(&mut s, &interp, id, [1u8; 32], b"go", funder, 99, 1, 0).unwrap();
            (s, case_id)
        };
        let (sa, ca) = build();
        let (sb, cb) = build();
        assert_eq!(ca, cb);
        // Both nodes committed the same effect and reached the same escrow + payee balances.
        let ea = sa.get_exec_case(ca).unwrap();
        let eb = sb.get_exec_case(cb).unwrap();
        assert_eq!(ea.status, eb.status);
        assert_eq!(sa.balance(&addr(2), 0), sb.balance(&addr(2), 0));
        assert_eq!(sa.balance(&addr(2), 0), 4 * UBI);
        // The interpreter jury selection is identical too (same seed).
        assert_eq!(ea.jury, eb.jury);
    }

    // -----------------------------------------------------------------------------------------
    // AC3 property test — random effects: tally is order-independent + deterministic.
    // -----------------------------------------------------------------------------------------

    struct Rng(u64);
    impl Rng {
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next_u64() % n
        }
    }

    #[test]
    fn ac3_property_tally_order_independent_and_deterministic() {
        let mut rng = Rng(0xC0FFEE);
        for _ in 0..5_000 {
            // Three interpreters each emit one of a few candidate effects (some equal, some not).
            let candidates = [
                CanonicalEffect::new(vec![Op::Transfer {
                    to: addr(2),
                    amount: 1,
                }]),
                CanonicalEffect::new(vec![Op::Transfer {
                    to: addr(2),
                    amount: 2,
                }]),
                CanonicalEffect::new(vec![Op::Refund {
                    party: addr(1),
                    amount: 1,
                }]),
            ];
            let pick = |r: &mut Rng| candidates[r.below(3) as usize].clone();
            let subs = vec![
                (addr(101), pick(&mut rng)),
                (addr(102), pick(&mut rng)),
                (addr(103), pick(&mut rng)),
            ];

            // Quorum forms iff >= 2 of the 3 picked the same effect_hash.
            let mut counts: std::collections::HashMap<Hash, usize> =
                std::collections::HashMap::new();
            for (_, e) in &subs {
                *counts.entry(e.effect_hash).or_default() += 1;
            }
            let max = counts.values().copied().max().unwrap_or(0);
            let expect_quorum = max >= QUORUM;

            let out = tally_effects(&subs, JURY_SIZE, QUORUM);
            match &out {
                EffectTally::Committed(e) => {
                    assert!(expect_quorum, "committed without a 2/3 majority");
                    assert_eq!(counts[&e.effect_hash], max);
                }
                EffectTally::NoQuorum => assert!(!expect_quorum, "aborted despite a 2/3 majority"),
                EffectTally::Pending => panic!("a full 3-jury must not be Pending"),
            }

            // Order independence: shuffle the submissions, the outcome is identical.
            let mut shuffled = subs.clone();
            shuffled.reverse();
            assert_eq!(tally_effects(&shuffled, JURY_SIZE, QUORUM), out);
        }
    }

    // -----------------------------------------------------------------------------------------
    // AC5 — streaming contract opens an M2 stream from escrow; stop/refund conserves.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn ac5_streaming_contract_opens_stream_from_escrow() {
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        let bob = addr(2);
        seed_funded(&mut s, funder, 1_000 * UBI);
        let id = deploy(&mut s, "stream to bob from escrow", vec![funder, bob]);
        let escrow_addr = contract_address(id);

        // "stream to Bob for 10 hours from escrow". We use an exact 1-base-unit/sec rate so the
        // assertions are exact: the M2 layer truncates `UBI / 3600`, which is an emission-rounding
        // artifact (documented F1), not a streaming-from-escrow concern — the latter is what's tested
        // here. `deposit = 10h` of flow at 1 base unit/sec.
        let hour = crate::EMISSION_PERIOD_SECS as u128;
        let rate: u128 = 1;
        let deposit = 10 * hour; // 10 hours of flow
        fund_contract(&mut s, &funder, id, deposit, 0, 0).unwrap();

        let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::OpenStream {
            to: bob,
            rate,
            deposit,
        }]));
        let case_id =
            invoke_contract(&mut s, &interp, id, [0u8; 32], b"go", funder, 1, 1, 0).unwrap();
        assert!(matches!(
            s.get_exec_case(case_id).unwrap().status,
            ExecStatus::Committed(_)
        ));

        // The escrow funded the stream: escrow field drained to 0; a stream from the escrow exists.
        assert_eq!(s.get_contract(id).unwrap().escrow, 0);
        let stream_id = s.outgoing(&escrow_addr)[0];
        let st = s.get_stream(stream_id).unwrap();
        assert_eq!(st.from, escrow_addr);
        assert_eq!(st.to, bob);
        assert_eq!(st.deposit, deposit);

        // After 4 hours Bob has accrued exactly 4 hours of flow (from escrow, not the funder).
        let four_h = 4 * crate::EMISSION_PERIOD_SECS;
        assert_eq!(s.balance(&bob, four_h), 4 * hour);
    }

    #[test]
    fn ac5_stop_stream_refunds_escrow_conserved() {
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        let bob = addr(2);
        seed_funded(&mut s, funder, 1_000 * UBI);
        let id = deploy(&mut s, "stream to bob from escrow", vec![funder, bob]);
        let escrow_addr = contract_address(id);

        // Exact 1-base-unit/sec rate so the stop/refund split is exact (see the open test for why).
        let hour = crate::EMISSION_PERIOD_SECS as u128;
        let rate: u128 = 1;
        let deposit = 10 * hour;
        fund_contract(&mut s, &funder, id, deposit, 0, 0).unwrap();

        // Open the stream at t=0.
        let open_interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::OpenStream {
            to: bob,
            rate,
            deposit,
        }]));
        invoke_contract(
            &mut s,
            &open_interp,
            id,
            [0u8; 32],
            b"open",
            funder,
            1,
            1,
            0,
        )
        .unwrap();
        let stream_id = s.outgoing(&escrow_addr)[0];

        // Stop it 3 hours in: Bob keeps 3h of flow, 7h refunds back into escrow.
        let stop_at = 3 * crate::EMISSION_PERIOD_SECS;
        let stop_interp =
            MockInterpreter::always(CanonicalEffect::new(vec![Op::StopStream { id: stream_id }]));
        let case_id = invoke_contract(
            &mut s,
            &stop_interp,
            id,
            [0u8; 32],
            b"stop",
            funder,
            2,
            1,
            stop_at,
        )
        .unwrap();
        assert!(matches!(
            s.get_exec_case(case_id).unwrap().status,
            ExecStatus::Committed(_)
        ));

        // Bob keeps 3h; escrow regained the unused 7h (conservation of the 10h deposit).
        assert_eq!(s.balance(&bob, stop_at), 3 * hour);
        assert_eq!(s.get_contract(id).unwrap().escrow, 7 * hour);
        assert_eq!(s.balance(&escrow_addr, stop_at), 7 * hour);
        // Total conserved: bob + escrow == the original 10h deposit.
        assert_eq!(
            s.balance(&bob, stop_at) + s.get_contract(id).unwrap().escrow,
            deposit
        );

        // Then a Refund returns the remaining escrow to the funder (a declared party) — conserved.
        let refund_interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Refund {
            party: funder,
            amount: 7 * hour,
        }]));
        let pre_funder = s.balance(&funder, stop_at);
        invoke_contract(
            &mut s,
            &refund_interp,
            id,
            [0u8; 32],
            b"refund",
            funder,
            3,
            1,
            stop_at,
        )
        .unwrap();
        assert_eq!(s.get_contract(id).unwrap().escrow, 0);
        assert_eq!(s.balance(&funder, stop_at), pre_funder + 7 * hour);
    }

    // -----------------------------------------------------------------------------------------
    // SetVar + lifecycle plumbing.
    // -----------------------------------------------------------------------------------------

    #[test]
    fn setvar_effect_updates_contract_vars() {
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        seed_funded(&mut s, funder, 10 * UBI);
        let id = deploy(&mut s, "single-party escrow agreement", vec![funder]);

        let key = [3u8; 32];
        let value = [4u8; 32];
        let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::SetVar { key, value }]));
        invoke_contract(&mut s, &interp, id, [0u8; 32], b"x", funder, 1, 1, 0).unwrap();

        assert_eq!(s.get_contract(id).unwrap().vars.get(&key), Some(&value));
    }

    #[test]
    fn explicit_abort_effect_makes_no_state_change() {
        let mut s = MemState::new();
        register_interpreters(&mut s, 3);
        let funder = addr(1);
        seed_funded(&mut s, funder, 10 * UBI);
        let id = deploy(&mut s, "two-party escrow agreement", vec![funder, addr(2)]);
        fund_contract(&mut s, &funder, id, 5 * UBI, 0, 0).unwrap();

        let interp = MockInterpreter::always(CanonicalEffect::abort([1u8; 32]));
        let case_id =
            invoke_contract(&mut s, &interp, id, [0u8; 32], b"x", funder, 1, 1, 0).unwrap();
        assert_eq!(
            s.get_exec_case(case_id).unwrap().status,
            ExecStatus::Aborted
        );
        assert_eq!(s.get_contract(id).unwrap().escrow, 5 * UBI);
    }

    #[test]
    fn deploy_requires_at_least_one_party() {
        let mut s = MemState::new();
        assert_eq!(
            deploy_contract(&mut s, "no parties".to_string(), [0u8; 32], vec![]).unwrap_err(),
            ContractError::NoParties
        );
    }

    #[test]
    fn deploy_rejects_oversized_text_fail_closed() {
        // C6-SEC-1: a text exactly at the cap deploys; one byte over is rejected with no state change.
        let mut s = MemState::new();
        let at_cap = "x".repeat(crate::MAX_CONTRACT_TEXT_BYTES);
        let id = deploy_contract(&mut s, at_cap, [1u8; 32], vec![addr(1)]).unwrap();
        assert_eq!(id, 0);

        let mut s2 = MemState::new();
        let over = "y".repeat(crate::MAX_CONTRACT_TEXT_BYTES + 1);
        assert_eq!(
            deploy_contract(&mut s2, over, [2u8; 32], vec![addr(1)]).unwrap_err(),
            ContractError::TextTooLarge {
                len: crate::MAX_CONTRACT_TEXT_BYTES + 1,
                max: crate::MAX_CONTRACT_TEXT_BYTES,
            }
        );
        // No contract was created on the rejected deploy (fail-closed, I4).
        assert!(s2.get_contract(0).is_none());
    }

    #[test]
    fn deploy_rejects_too_many_parties_fail_closed() {
        // C6-SEC-1: `MAX_CONTRACT_PARTIES` distinct parties deploy; one more is rejected, no state.
        let mut s = MemState::new();
        let at_cap: Vec<Address> = (0..crate::MAX_CONTRACT_PARTIES as u8).map(addr).collect();
        deploy_contract(&mut s, "ok".to_string(), [3u8; 32], at_cap).unwrap();

        let mut s2 = MemState::new();
        let over: Vec<Address> = (0..(crate::MAX_CONTRACT_PARTIES as u8 + 1))
            .map(addr)
            .collect();
        let count = over.len();
        assert_eq!(
            deploy_contract(&mut s2, "too many".to_string(), [4u8; 32], over).unwrap_err(),
            ContractError::TooManyParties {
                count,
                max: crate::MAX_CONTRACT_PARTIES,
            }
        );
        assert!(s2.get_contract(0).is_none());
    }

    #[test]
    fn deploy_gas_scales_with_text_length() {
        // The size-metered gas grows linearly with text length (storing more costs more — I2).
        use crate::{gas_for_deploy, GAS_CONTRACT, GAS_PER_TEXT_BYTE};
        assert_eq!(gas_for_deploy(0), GAS_CONTRACT);
        assert_eq!(gas_for_deploy(100), GAS_CONTRACT + 100 * GAS_PER_TEXT_BYTE);
        // Larger text ⇒ strictly larger gas (and thus fee).
        assert!(gas_for_deploy(8192) > gas_for_deploy(10));
    }

    #[test]
    fn invoke_with_no_interpreters_fails_closed() {
        let mut s = MemState::new();
        let funder = addr(1);
        seed_funded(&mut s, funder, 10 * UBI);
        let id = deploy(&mut s, "single-party escrow agreement", vec![funder]);
        let interp = MockInterpreter::default();
        assert_eq!(
            invoke_contract(&mut s, &interp, id, [0u8; 32], b"x", funder, 1, 1, 0).unwrap_err(),
            ContractError::NoInterpreters
        );
    }

    #[test]
    fn submit_effect_authority_and_dedup() {
        // Build a case via single-interpreter pool so it stays Open after invoke (1 sub < QUORUM 2).
        let mut s = MemState::new();
        register_juror(&mut s, &addr(101), 0);
        let funder = addr(1);
        seed_funded(&mut s, funder, 10 * UBI);
        let id = deploy(&mut s, "two-party escrow agreement", vec![funder, addr(2)]);
        fund_contract(&mut s, &funder, id, 5 * UBI, 0, 0).unwrap();
        let interp = MockInterpreter::always(CanonicalEffect::new(vec![Op::Transfer {
            to: addr(2),
            amount: UBI,
        }]));
        // Only one interpreter ⇒ one submission ⇒ Pending (needs QUORUM=2).
        let case_id =
            invoke_contract(&mut s, &interp, id, [0u8; 32], b"x", funder, 1, 1, 0).unwrap();
        assert_eq!(s.get_exec_case(case_id).unwrap().status, ExecStatus::Open);

        // A non-juror cannot submit.
        assert_eq!(
            submit_effect(&mut s, case_id, &addr(200), CanonicalEffect::noop(), 1, 0).unwrap_err(),
            ContractError::NotOnJury
        );
        // The juror already submitted during invoke ⇒ AlreadySubmitted.
        assert_eq!(
            submit_effect(&mut s, case_id, &addr(101), CanonicalEffect::noop(), 1, 0).unwrap_err(),
            ContractError::AlreadySubmitted
        );
    }
}
