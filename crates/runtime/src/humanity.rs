//! M3 — AI Proof-of-Humanity substrate (see `docs/specs/03-proof-of-humanity.md`).
//!
//! This module is the **deterministic** on-chain part of M3: the human registry, the vouch graph,
//! verification/challenge cases, the juror registry, and the pure lifecycle state machine that ties
//! them together. The probabilistic AI work lives entirely behind the [`HumanityOracle`] trait
//! (invariant I1/I5): the runtime only ever commits a [`CanonicalVerdict`] (a structured *effect*),
//! never prose, and only when a quorum of jurors produced the *same* verdict.
//!
//! Everything here is integer-only and free of non-deterministic iteration (no `HashMap` ordering on
//! any consensus path): juror selection sorts candidates and walks a seeded PRNG; tallies count
//! over an explicit, ordered juror list. Given the same op sequence two nodes reach byte-identical
//! state (invariants I1/I2).
//!
//! The AI oracle implementation (M3-T3) and the RPC wiring (M3-T4) build against the trait + types
//! exported here; the [`MockOracle`] lets the whole lifecycle run in CI with no model/network calls.

use crate::Address;
use std::collections::HashMap;

/// A 32-byte content-addressed commitment (e.g. `liveness_ref`, `evidence_ref`, `reasons_hash`).
/// Privacy (I6): only commitments — never the underlying PII/biometric — live on-chain.
pub type Hash = [u8; 32];

// ---------------------------------------------------------------------------------------------
// Constants (devnet starting values — tunable; see spec §Constants + M3-T1 open questions).
// ---------------------------------------------------------------------------------------------

/// Distinct `Verified` vouchers an applicant must collect before it can finalize (spec `MIN_VOUCHES`).
pub const MIN_VOUCHES: usize = 2;

/// Max outstanding vouches a single voucher may issue (spec `VOUCH_CAPACITY`) — anti-grief / anti-farm.
pub const VOUCH_CAPACITY: usize = 10;

/// Jurors selected per case (spec `JURY_SIZE = N`). Deterministic-random subset of active jurors.
pub const JURY_SIZE: usize = 3;

/// Matching verdicts required to commit a case (spec `QUORUM = ⌈2N/3⌉`; for `N=3` that is `2`).
pub const QUORUM: usize = 2;

/// Length of the challenge window, in blocks. The applicant can only finalize once this many blocks
/// have elapsed since registration with no upheld challenge (spec `CHALLENGE_WINDOW`).
pub const CHALLENGE_WINDOW: u64 = 5;

/// Reputation penalty applied to each voucher of a subject proven `Sybil` (spec §"slash vouchers'
/// reputation"). Integer; `reputation` is `i64` so it may go negative.
pub const SYBIL_SLASH: i64 = 100;

// ---------------------------------------------------------------------------------------------
// Canonical verdict — the only thing the chain ever commits from the AI layer (I1).
// ---------------------------------------------------------------------------------------------

/// The classification an oracle returns. `Uncertain` (or a split) deterministically escalates — the
/// chain never coin-flips (I4: fail closed).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Verdict {
    /// A unique, live human.
    Human,
    /// A duplicate / bot / sybil.
    Sybil,
    /// Not enough signal to decide — escalate.
    Uncertain,
}

/// Confidence bucket — part of the canonical effect, so it must match for a quorum to form (spec:
/// "verdict + confidence bucket must match; `reasons_hash` is informational"). Bucketed (not a float)
/// precisely so two nodes can agree exactly (I1/I2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Confidence {
    Low,
    Med,
    High,
}

/// The canonical, structured output every juror signs and the chain tallies. Two verdicts are
/// *equal for quorum purposes* iff `verdict` **and** `confidence` match; `reasons_hash` is a
/// commitment to the human-readable rationale and is **informational only** (spec I1).
#[derive(Clone, Copy, Debug)]
pub struct CanonicalVerdict {
    pub verdict: Verdict,
    pub confidence: Confidence,
    /// Commitment to the off-chain rationale. Informational — does NOT affect quorum equality (I6:
    /// no prose on-chain, only the hash).
    pub reasons_hash: Hash,
}

impl CanonicalVerdict {
    /// Construct a verdict with a zeroed `reasons_hash` (tests / mock convenience).
    pub fn new(verdict: Verdict, confidence: Confidence) -> Self {
        Self {
            verdict,
            confidence,
            reasons_hash: [0u8; 32],
        }
    }

    /// Quorum equality: `verdict` + `confidence` must match. `reasons_hash` is ignored (spec I1).
    /// This is the *only* notion of "same verdict" used in tallying — not `PartialEq` — so the
    /// informational hash can never split an otherwise-agreeing quorum.
    pub fn quorum_eq(&self, other: &CanonicalVerdict) -> bool {
        self.verdict == other.verdict && self.confidence == other.confidence
    }

    /// A stable, order-independent key for tallying identical verdicts (verdict + confidence only).
    pub fn quorum_key(&self) -> (Verdict, Confidence) {
        (self.verdict, self.confidence)
    }
}

// PartialEq deliberately compares the full struct (incl. reasons_hash) for test ergonomics; quorum
// tallying uses `quorum_eq`/`quorum_key` and never this impl.
impl PartialEq for CanonicalVerdict {
    fn eq(&self, other: &Self) -> bool {
        self.verdict == other.verdict
            && self.confidence == other.confidence
            && self.reasons_hash == other.reasons_hash
    }
}
impl Eq for CanonicalVerdict {}

// ---------------------------------------------------------------------------------------------
// The AI Oracle seam (spec §"Verdicts & the AI Oracle seam"). Off-chain; each juror node runs it.
// ---------------------------------------------------------------------------------------------

/// A read-only view of the vouch graph handed to [`HumanityOracle::analyze_sybil`]. Deterministic
/// shape (sorted edges) so two nodes see byte-identical input — the oracle impl (M3-T3) must not
/// depend on any other ordering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct GraphView {
    /// `(voucher, vouchee)` edges, sorted ascending. Content-addressed input all jurors see identically.
    pub edges: Vec<(Address, Address)>,
}

/// The off-chain AI oracle. Each juror node runs an implementation, signs the [`CanonicalVerdict`],
/// and submits it as a transaction; the runtime tallies the signed verdicts deterministically.
///
/// Determinism (I1): a real impl pins model + seed + temperature 0 and emits canonical structured
/// output, so honest jurors converge on the same verdict. The runtime treats the oracle as a black
/// box — it only consumes the [`CanonicalVerdict`] and never the prose behind `reasons_hash`.
pub trait HumanityOracle: Send + Sync {
    /// Grade an interactive liveness challenge/response (presence). `Human` ⇒ a live human responded.
    fn grade_liveness(&self, challenge: &[u8], response: &[u8]) -> CanonicalVerdict;

    /// Analyze the vouch graph around `subject` for sybil clusters (uniqueness). `Sybil` flags an
    /// improbable cluster (e.g. a vouch farm) and the runtime auto-files a challenge.
    fn analyze_sybil(&self, graph: &GraphView, subject: &Address) -> CanonicalVerdict;

    /// Adjudicate a dispute from its content-addressed evidence (the jury path).
    fn adjudicate(&self, evidence: &[u8]) -> CanonicalVerdict;
}

/// A scripted, fully-deterministic oracle for CI / the whole-lifecycle tests (I5 — no live calls).
///
/// Resolution order for every method:
///   1. an exact override keyed off the relevant input bytes (`liveness`, `sybil` keyed by subject,
///      `evidence`), if one was scripted;
///   2. otherwise the configured `default` verdict.
///
/// This makes every lifecycle test reproducible and offline: a fixed evidence blob always yields the
/// same `CanonicalVerdict`, so all honest jurors agree and the quorum/tally logic is exercised without
/// any model. The live node swaps in a Claude-backed impl behind the same trait (M3-T3).
#[derive(Clone, Debug)]
pub struct MockOracle {
    /// Returned when no override matches.
    default: CanonicalVerdict,
    /// Override keyed by liveness `response` bytes.
    liveness: HashMap<Vec<u8>, CanonicalVerdict>,
    /// Override keyed by the sybil-analysis `subject`.
    sybil: HashMap<Address, CanonicalVerdict>,
    /// Override keyed by adjudication `evidence` bytes.
    evidence: HashMap<Vec<u8>, CanonicalVerdict>,
}

impl Default for MockOracle {
    fn default() -> Self {
        // Default = a confident `Human` pass, so the happy path needs no scripting.
        Self::new(CanonicalVerdict::new(Verdict::Human, Confidence::High))
    }
}

impl MockOracle {
    /// A mock whose default verdict is `default` (used when no override matches an input).
    pub fn new(default: CanonicalVerdict) -> Self {
        Self {
            default,
            liveness: HashMap::new(),
            sybil: HashMap::new(),
            evidence: HashMap::new(),
        }
    }

    /// Always return `verdict` regardless of input. Handy for "everyone votes Sybil" tests.
    pub fn always(verdict: CanonicalVerdict) -> Self {
        Self::new(verdict)
    }

    /// Script a liveness verdict for a specific `response` blob (builder style).
    pub fn with_liveness(mut self, response: &[u8], v: CanonicalVerdict) -> Self {
        self.liveness.insert(response.to_vec(), v);
        self
    }

    /// Script a sybil-analysis verdict for a specific `subject` (builder style).
    pub fn with_sybil(mut self, subject: Address, v: CanonicalVerdict) -> Self {
        self.sybil.insert(subject, v);
        self
    }

    /// Script an adjudication verdict for a specific `evidence` blob (builder style).
    pub fn with_evidence(mut self, evidence: &[u8], v: CanonicalVerdict) -> Self {
        self.evidence.insert(evidence.to_vec(), v);
        self
    }
}

impl HumanityOracle for MockOracle {
    fn grade_liveness(&self, _challenge: &[u8], response: &[u8]) -> CanonicalVerdict {
        self.liveness.get(response).copied().unwrap_or(self.default)
    }

    fn analyze_sybil(&self, _graph: &GraphView, subject: &Address) -> CanonicalVerdict {
        self.sybil.get(subject).copied().unwrap_or(self.default)
    }

    fn adjudicate(&self, evidence: &[u8]) -> CanonicalVerdict {
        self.evidence.get(evidence).copied().unwrap_or(self.default)
    }
}

// ---------------------------------------------------------------------------------------------
// On-chain state types (spec §"On-chain state").
// ---------------------------------------------------------------------------------------------

/// Lifecycle status of a human claim (spec). `Unverified` is the implicit state of an address with no
/// `Human` record; the others are explicit.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum HumanStatus {
    /// No claim, or a claim that has not begun. Accrues no UBI.
    #[default]
    Unverified,
    /// Registration opened; liveness graded, gathering vouches / in the challenge window.
    Pending,
    /// A verified unique human — and the **only** status that accrues UBI (I2 gating).
    Verified,
    /// A `Verified` human currently under an open challenge (re-adjudication). Still emits until/unless
    /// the challenge is upheld (a verified human is innocent until a quorum proves otherwise — I4).
    Challenged,
    /// Rejected/revoked by a `Sybil` quorum. Accrues no UBI; `verified_at` is cleared.
    Revoked,
}

/// A human record (spec §"On-chain state"). No PII ever lives here — only the `liveness_ref`
/// commitment, the vouch set, and reputation (I6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Human {
    pub address: Address,
    pub status: HumanStatus,
    /// Unix seconds when this human became `Verified` (0 if never). Drives emission (replaces the M1
    /// genesis flag).
    pub verified_at: u64,
    /// Commitment to the off-chain liveness evidence (no PII on-chain — I6).
    pub liveness_ref: Hash,
    /// Distinct `Verified` vouchers that have vouched *for* this human (sorted, deduped).
    pub vouches_in: Vec<Address>,
    /// Voucher reputation; slashed for vouching a proven sybil. `i64` (may go negative).
    pub reputation: i64,
}

impl Human {
    /// A fresh `Pending` registration with the given liveness commitment.
    pub fn pending(address: Address, liveness_ref: Hash) -> Self {
        Self {
            address,
            status: HumanStatus::Pending,
            verified_at: 0,
            liveness_ref,
            vouches_in: Vec::new(),
            reputation: 0,
        }
    }
}

/// A single vouch edge (spec). The voucher must be `Verified`; capacity-limited; no self/duplicate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Vouch {
    pub voucher: Address,
    pub vouchee: Address,
    /// Block height the vouch was recorded at.
    pub at: u64,
}

/// What a [`Case`] is adjudicating.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseKind {
    /// A new-account verification (grade liveness, then the challenge window).
    Registration,
    /// A challenge against a subject (registration applicant or an already-`Verified` human).
    Challenge,
}

/// Lifecycle of a [`Case`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaseStatus {
    /// Collecting juror verdicts.
    Open,
    /// A quorum agreed; the committed canonical effect.
    Committed(CanonicalVerdict),
    /// Disagreement / `Uncertain` — escalate (never a coin-flip; I4).
    Escalated,
}

/// A sequential case identifier.
pub type CaseId = u64;

/// A verification or challenge under adjudication (spec §"On-chain state").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Case {
    pub id: CaseId,
    pub subject: Address,
    pub kind: CaseKind,
    /// Content-addressed evidence all jurors see identically (I1). For a `Registration` case this is
    /// the liveness commitment; for a `Challenge`, the challenger's evidence.
    pub evidence_ref: Hash,
    /// The quorum selected for this case (deterministic-random from the active juror registry).
    pub jury: Vec<Address>,
    /// Submitted verdicts keyed by juror. Stored as a sorted `Vec` (not a map) so tallying never
    /// depends on hash-iteration order (I1).
    pub votes: Vec<(Address, CanonicalVerdict)>,
    pub status: CaseStatus,
    /// Block height the case opened at (the registration challenge-window clock).
    pub opened_at: u64,
}

impl Case {
    /// Look up a juror's submitted verdict, if any.
    pub fn vote_of(&self, juror: &Address) -> Option<CanonicalVerdict> {
        self.votes.iter().find(|(a, _)| a == juror).map(|(_, v)| *v)
    }
}

/// A registered juror (spec §"On-chain state"). M3 is register-only; staking depth is M5 (spec
/// open question — recommended register-only). `stake` is carried for forward-compat.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Juror {
    pub address: Address,
    pub stake: u128,
    pub active: bool,
}

// ---------------------------------------------------------------------------------------------
// Deterministic juror selection (spec §"Juror selection") — VRF-style, simplified for M3.
// ---------------------------------------------------------------------------------------------

/// Select a deterministic-pseudorandom `size`-subset of `candidates`, seeded from `seed`
/// (`case_id` xored with a chain-entropy input the caller picks). Reproducible across nodes: the
/// candidate list is **sorted** first (so input ordering is irrelevant), then a seeded Fisher–Yates
/// partial shuffle picks the jury. No floats, no hash iteration.
///
/// If `candidates.len() <= size`, all candidates are returned (sorted) — the jury is the whole pool.
/// The returned vector is the selected jury in selection order (not necessarily sorted).
pub fn select_jury(mut candidates: Vec<Address>, size: usize, seed: u64) -> Vec<Address> {
    candidates.sort_unstable();
    candidates.dedup();
    if candidates.len() <= size {
        return candidates;
    }
    let mut rng = SplitMix64::new(seed);
    let n = candidates.len();
    // Partial Fisher–Yates: for i in 0..size pick j in [i, n) and swap; take the first `size`.
    for i in 0..size {
        let j = i + (rng.next_u64() as usize % (n - i));
        candidates.swap(i, j);
    }
    candidates.truncate(size);
    candidates
}

/// SplitMix64 — the same deterministic PRNG the runtime/tests already use elsewhere. Seeded juror
/// selection must be byte-reproducible across nodes, so this lives in the consensus path.
struct SplitMix64(u64);
impl SplitMix64 {
    fn new(seed: u64) -> Self {
        SplitMix64(seed)
    }
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ---------------------------------------------------------------------------------------------
// Tally — the deterministic quorum logic (spec I1). Pure function, no state, fully testable.
// ---------------------------------------------------------------------------------------------

/// The outcome of tallying a case's submitted verdicts against `quorum`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tally {
    /// Fewer than `quorum` votes for any single verdict so far, and it's still possible to reach
    /// quorum with the remaining jurors — keep waiting.
    Pending,
    /// `>= quorum` jurors produced the *same* canonical verdict (verdict + confidence) — commit it.
    Committed(CanonicalVerdict),
    /// Quorum can no longer be reached for any verdict (a split), or the leading verdict is
    /// `Uncertain` at quorum — escalate (I4: fail closed, never a coin-flip).
    Escalated,
}

/// Tally `votes` over a jury of size `jury_size`, requiring `quorum` matching verdicts.
///
/// Deterministic: groups verdicts by `(verdict, confidence)` (ignoring the informational
/// `reasons_hash`), and:
///   * if any group reaches `quorum` **and** is `Human`/`Sybil` ⇒ `Committed` (the first such group
///     by canonical key order — but quorum is exclusive for `size=3, quorum=2`, so at most one group
///     can ever reach it; for larger juries ties are impossible past quorum on a fixed jury);
///   * if a group reaches `quorum` but is `Uncertain` ⇒ `Escalated`;
///   * else if no group *can still* reach `quorum` given the unused jurors ⇒ `Escalated` (split);
///   * else ⇒ `Pending`.
pub fn tally(votes: &[(Address, CanonicalVerdict)], jury_size: usize, quorum: usize) -> Tally {
    // Count identical canonical verdicts (verdict + confidence) deterministically: build an ordered
    // list of (key, count, exemplar) — no hash-iteration ordering on the consensus path.
    let mut groups: Vec<((Verdict, Confidence), usize, CanonicalVerdict)> = Vec::new();
    for (_, v) in votes {
        let key = v.quorum_key();
        if let Some(g) = groups.iter_mut().find(|(k, _, _)| *k == key) {
            g.1 += 1;
        } else {
            groups.push((key, 1, *v));
        }
    }

    // A group at quorum: commit (Human/Sybil) or escalate (Uncertain).
    if let Some((_, _, exemplar)) = groups.iter().find(|(_, c, _)| *c >= quorum) {
        return match exemplar.verdict {
            Verdict::Uncertain => Tally::Escalated,
            Verdict::Human | Verdict::Sybil => Tally::Committed(*exemplar),
        };
    }

    // No group at quorum yet. Can any still reach it? `unused` jurors haven't voted.
    let cast = votes.len();
    let unused = jury_size.saturating_sub(cast);
    let best = groups.iter().map(|(_, c, _)| *c).max().unwrap_or(0);
    if best + unused < quorum {
        // Even handing every remaining juror to the current leader can't reach quorum ⇒ split.
        Tally::Escalated
    } else {
        Tally::Pending
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> Address {
        [b; 20]
    }
    fn human() -> CanonicalVerdict {
        CanonicalVerdict::new(Verdict::Human, Confidence::High)
    }
    fn sybil() -> CanonicalVerdict {
        CanonicalVerdict::new(Verdict::Sybil, Confidence::High)
    }
    fn uncertain() -> CanonicalVerdict {
        CanonicalVerdict::new(Verdict::Uncertain, Confidence::Low)
    }

    #[test]
    fn mock_oracle_is_scripted_and_deterministic() {
        let oracle = MockOracle::new(human())
            .with_evidence(b"sybil-evidence", sybil())
            .with_sybil(addr(9), sybil());
        // Same input ⇒ same verdict, every call (I5).
        for _ in 0..5 {
            assert_eq!(oracle.adjudicate(b"sybil-evidence"), sybil());
            assert_eq!(oracle.adjudicate(b"anything-else"), human()); // default
            let g = GraphView::default();
            assert_eq!(oracle.analyze_sybil(&g, &addr(9)), sybil());
            assert_eq!(oracle.analyze_sybil(&g, &addr(1)), human());
        }
    }

    #[test]
    fn quorum_eq_ignores_reasons_hash() {
        let a = CanonicalVerdict {
            verdict: Verdict::Human,
            confidence: Confidence::High,
            reasons_hash: [1u8; 32],
        };
        let b = CanonicalVerdict {
            verdict: Verdict::Human,
            confidence: Confidence::High,
            reasons_hash: [2u8; 32], // different rationale, same effect
        };
        assert!(a.quorum_eq(&b), "reasons_hash must not split a quorum (I1)");
        assert_ne!(a, b, "full PartialEq still distinguishes the hash");
    }

    #[test]
    fn quorum_requires_matching_confidence() {
        // Two Human votes but different confidence buckets ⇒ no quorum (must match exactly).
        let votes = vec![
            (
                addr(1),
                CanonicalVerdict::new(Verdict::Human, Confidence::High),
            ),
            (
                addr(2),
                CanonicalVerdict::new(Verdict::Human, Confidence::Med),
            ),
            (
                addr(3),
                CanonicalVerdict::new(Verdict::Human, Confidence::Low),
            ),
        ];
        // jury 3, quorum 2: three singleton groups, all jurors voted, none reaches 2 ⇒ split.
        assert_eq!(tally(&votes, JURY_SIZE, QUORUM), Tally::Escalated);
    }

    #[test]
    fn tally_commits_at_quorum() {
        let votes = vec![(addr(1), human()), (addr(2), human())];
        assert_eq!(tally(&votes, JURY_SIZE, QUORUM), Tally::Committed(human()));
    }

    #[test]
    fn tally_pending_then_escalates_on_split() {
        // One vote, two jurors left: still reachable ⇒ Pending.
        let v1 = vec![(addr(1), human())];
        assert_eq!(tally(&v1, JURY_SIZE, QUORUM), Tally::Pending);
        // Human, Sybil, Uncertain — all three jurors voted, no pair agrees ⇒ split ⇒ Escalated.
        let split = vec![
            (addr(1), human()),
            (addr(2), sybil()),
            (addr(3), uncertain()),
        ];
        assert_eq!(tally(&split, JURY_SIZE, QUORUM), Tally::Escalated);
    }

    #[test]
    fn tally_uncertain_quorum_escalates() {
        let votes = vec![(addr(1), uncertain()), (addr(2), uncertain())];
        assert_eq!(tally(&votes, JURY_SIZE, QUORUM), Tally::Escalated);
    }

    #[test]
    fn jury_selection_is_deterministic_and_sized() {
        let pool: Vec<Address> = (1..=10u8).map(addr).collect();
        let j1 = select_jury(pool.clone(), JURY_SIZE, 42);
        // Same seed + pool ⇒ identical jury (reproducible across nodes).
        let j2 = select_jury(pool.clone(), JURY_SIZE, 42);
        assert_eq!(j1, j2);
        assert_eq!(j1.len(), JURY_SIZE);
        // Input order must not matter: a shuffled pool yields the same jury (as a set).
        let mut rev = pool.clone();
        rev.reverse();
        let j3 = select_jury(rev, JURY_SIZE, 42);
        let mut a = j1.clone();
        let mut b = j3.clone();
        a.sort_unstable();
        b.sort_unstable();
        assert_eq!(a, b, "jury must be independent of candidate input order");
        // A different seed generally yields a different jury.
        let j4 = select_jury(pool.clone(), JURY_SIZE, 99);
        assert_ne!(j1, j4);
    }

    #[test]
    fn jury_selection_small_pool_returns_all() {
        let pool: Vec<Address> = vec![addr(1), addr(2)];
        let j = select_jury(pool.clone(), JURY_SIZE, 7);
        assert_eq!(j, vec![addr(1), addr(2)]); // whole pool, sorted
    }
}
