//! Juror-side glue: turning an open case into a signed `submitVerdict` transaction.
//!
//! # How a juror process works (the watch → grade → submit loop)
//!
//! A juror node runs a small daemon alongside the chain node. The loop is deliberately thin — all the
//! consensus-relevant determinism lives in the runtime tally and in [`crate::ClaudeOracle`]; the
//! daemon is just plumbing:
//!
//! ```text
//!   ┌── poll ────────────────────────────────────────────────────────────────┐
//!   │ 1. ubi_getPendingCases()           -> [CaseId]        (RPC read)         │
//!   │ 2. for each open case this juror is on the jury of and has NOT voted:    │
//!   │    a. ubi_getCase(id)              -> Case            (subject, kind,    │
//!   │                                                        evidence_ref)     │
//!   │    b. fetch the content-addressed evidence by evidence_ref from the      │
//!   │       evidence store (same bytes every juror sees — I1)                  │
//!   │    c. verdict = juror_verdict(&oracle, case.kind, &evidence)             │
//!   │       (one pinned, temperature-0, structured Claude call)                │
//!   │    d. build submitVerdict(caseId, verdict) calldata, sign with the       │
//!   │       juror key (EIP-155), submit via eth_sendRawTransaction             │
//!   │ 3. sleep(poll_interval); repeat                                          │
//!   └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! Properties that matter:
//!   * **Idempotent.** A juror submits at most one verdict per case (the runtime rejects a second).
//!     The daemon tracks locally-submitted case ids and also re-checks `votes` on chain before sending,
//!     so a restart never double-votes.
//!   * **Deterministic input.** Every juror grades the *same* evidence bytes (content-addressed by
//!     `evidence_ref`) with the *same* pinned model at temperature 0, so honest jurors converge; the
//!     runtime commits only on ≥QUORUM matching `CanonicalVerdict`s and otherwise escalates (I1/I4).
//!   * **Fail-closed.** If the oracle aborts (missing key, transport/decode failure) it yields
//!     `Uncertain/Low`; submitting that is honest — it pushes the case toward escalation, never a
//!     fabricated `Human`. A juror MAY instead choose not to submit on a hard infra failure and let
//!     the challenge window / re-selection handle it; both paths are safe (never auto-grant).
//!
//! The full daemon (RPC client, key management, evidence store, submission backoff) is integration
//! work owned by the node/protocol side; this module ships the pure decision function
//! ([`juror_verdict`]) plus a typed [`SubmitVerdictTx`] **design stub** describing exactly what the
//! daemon must build, so the seam is unambiguous. We deliberately do NOT reach into `crates/node` or
//! `crates/rpc` (file ownership): the stub documents the boundary instead.

use ubi2_runtime::{Address, CanonicalVerdict, CaseId, CaseKind, HumanityOracle};

/// Compute a juror's verdict for a case of `case_kind` from its content-addressed `evidence`.
///
/// This is the single entry point a juror daemon calls per open case. It routes to the right oracle
/// method by case kind:
///   * [`CaseKind::Registration`] → [`HumanityOracle::adjudicate`] over the registration evidence
///     (which bundles the liveness artifacts + any auto-sybil context the runtime committed under
///     `evidence_ref`). Registration uses the general adjudication path so a juror grades the *whole*
///     committed evidence blob, not just a single sub-artifact.
///   * [`CaseKind::Challenge`] → [`HumanityOracle::adjudicate`] over the challenger's evidence.
///
/// Liveness-only and sybil-only grading remain available as the dedicated trait methods
/// ([`HumanityOracle::grade_liveness`] / [`analyze_sybil`](HumanityOracle::analyze_sybil)) for the
/// runtime's pre-case scans (e.g. the auto-sybil-cluster filing); a *case* always adjudicates the
/// committed evidence so every juror grades byte-identical input.
///
/// Deterministic + offline-testable: with a fixture-backed oracle this is a pure function of
/// `(case_kind, evidence)` (I5).
pub fn juror_verdict(
    oracle: &dyn HumanityOracle,
    case_kind: CaseKind,
    evidence: &[u8],
) -> CanonicalVerdict {
    match case_kind {
        CaseKind::Registration | CaseKind::Challenge => oracle.adjudicate(evidence),
    }
}

/// A typed description of the transaction a juror daemon must build and sign — the **design stub** for
/// the submission seam. The daemon ABI-encodes `submitVerdict(caseId, verdict)` from these fields,
/// signs EIP-155 with the juror key, and sends via `eth_sendRawTransaction`. We model the intent here
/// (without depending on the rpc/node crates) so the boundary is explicit and testable.
///
/// The on-chain `submitVerdict` encodes the `CanonicalVerdict` as `(verdict_tag, confidence_tag)` (the
/// `reasons_hash` is informational and MAY be included as a third arg for the audit log, but does not
/// affect quorum equality — see the runtime `quorum_eq`). The exact ABI is owned by `crates/rpc`'s
/// `HumanityHub`; this stub names the inputs the daemon feeds it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitVerdictTx {
    /// The case being voted on.
    pub case_id: CaseId,
    /// The juror submitting (recovered signer must be on the case's `jury`).
    pub juror: Address,
    /// The canonical effect this juror commits to.
    pub verdict: CanonicalVerdict,
}

impl SubmitVerdictTx {
    /// Assemble the submission intent from a graded case. The daemon then encodes + signs + sends it.
    pub fn new(case_id: CaseId, juror: Address, verdict: CanonicalVerdict) -> Self {
        Self {
            case_id,
            juror,
            verdict,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ContentBlock, MessagesRequest, MessagesResponse, OracleError, Transport};
    use crate::ClaudeOracle;
    use ubi2_runtime::{Confidence, Verdict};

    struct Stub(MessagesResponse);
    impl Transport for Stub {
        fn send(&self, _: &MessagesRequest) -> Result<MessagesResponse, OracleError> {
            Ok(self.0.clone())
        }
    }
    fn stub(json: &str) -> ClaudeOracle<Stub> {
        ClaudeOracle::with_transport(
            "claude-opus-4-8",
            Stub(MessagesResponse {
                content: vec![ContentBlock {
                    kind: "text".into(),
                    text: Some(json.into()),
                    input: None,
                }],
            }),
        )
    }

    #[test]
    fn juror_verdict_routes_challenge_through_adjudicate() {
        let oracle = stub(r#"{"verdict":"Sybil","confidence":"High","reasons":"dup"}"#);
        let v = juror_verdict(&oracle, CaseKind::Challenge, b"evidence-blob");
        assert_eq!(v.verdict, Verdict::Sybil);
        assert_eq!(v.confidence, Confidence::High);
    }

    #[test]
    fn juror_verdict_registration_grades_committed_evidence() {
        let oracle = stub(r#"{"verdict":"Human","confidence":"High","reasons":"live"}"#);
        let v = juror_verdict(&oracle, CaseKind::Registration, b"reg-evidence");
        assert_eq!(v.verdict, Verdict::Human);
    }

    #[test]
    fn two_jurors_same_evidence_agree_quorum() {
        // I1: independent jurors, same pinned oracle + same evidence ⇒ quorum-equal verdicts.
        let j1 = stub(r#"{"verdict":"Sybil","confidence":"Med","reasons":"ring"}"#);
        let j2 = stub(r#"{"verdict":"Sybil","confidence":"Med","reasons":"clique"}"#);
        let v1 = juror_verdict(&j1, CaseKind::Challenge, b"ev");
        let v2 = juror_verdict(&j2, CaseKind::Challenge, b"ev");
        assert!(v1.quorum_eq(&v2), "same effect despite different prose");
    }

    #[test]
    fn submit_tx_carries_the_canonical_effect() {
        let oracle = stub(r#"{"verdict":"Human","confidence":"High","reasons":"ok"}"#);
        let v = juror_verdict(&oracle, CaseKind::Registration, b"e");
        let tx = SubmitVerdictTx::new(7, [9u8; 20], v);
        assert_eq!(tx.case_id, 7);
        assert_eq!(tx.verdict.verdict, Verdict::Human);
    }
}
