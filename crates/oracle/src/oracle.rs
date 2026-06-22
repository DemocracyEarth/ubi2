//! [`ClaudeOracle`] — the live Claude-backed [`HumanityOracle`] implementation (M3-T3).
//!
//! It is generic over a [`Transport`] so the exact same grading logic runs in CI against recorded
//! fixtures and in production against the Anthropic API (I5). The runtime trait methods are
//! *infallible* (they return a `CanonicalVerdict`, not a `Result`), so every internal error path
//! (missing key, transport failure, undecodable response) maps to a **deterministic abort verdict**
//! `{ Uncertain, Low }` — which the on-chain tally turns into an `Escalate`, never a coin-flip (I4).

use crate::client::{ClaudeConfig, HttpTransport, MessagesRequest, OracleError, Transport};
use crate::prompt;
use ubi2_runtime::{Address, CanonicalVerdict, Confidence, GraphView, HumanityOracle, Verdict};

/// The deterministic abort verdict: returned whenever the model layer cannot produce a trustworthy
/// structured verdict. `Uncertain`/`Low` is the fail-closed value (I4) — the tally escalates it.
pub fn abort_verdict() -> CanonicalVerdict {
    CanonicalVerdict::new(Verdict::Uncertain, Confidence::Low)
}

/// A Claude-backed humanity oracle. Holds the pinned model id and a [`Transport`]. The `Transport`
/// abstraction is the whole determinism-testing story: production uses [`HttpTransport`], tests use a
/// fixture transport, and the grading code in between is identical.
pub struct ClaudeOracle<T: Transport> {
    model: String,
    transport: T,
}

impl ClaudeOracle<HttpTransport> {
    /// Construct the **live** oracle from the environment. Requires `ANTHROPIC_API_KEY`; if it is
    /// unset, returns [`OracleError::MissingApiKey`] so the node can fall back to `MockOracle`.
    /// This is the only constructor that touches the network, and it is never called in tests.
    pub fn from_env() -> Result<Self, OracleError> {
        let cfg = ClaudeConfig::from_env()?;
        Ok(Self {
            transport: HttpTransport::new(cfg.api_key),
            model: cfg.model,
        })
    }
}

impl<T: Transport> ClaudeOracle<T> {
    /// Construct with an explicit transport + model id. Used by tests (fixture transport) and by any
    /// caller that wants to inject a custom transport. The model id is pinned by the caller.
    pub fn with_transport(model: impl Into<String>, transport: T) -> Self {
        Self {
            model: model.into(),
            transport,
        }
    }

    /// The pinned model id this oracle calls. Exposed so a juror can record/compare it (two jurors
    /// must run the same id to agree).
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Borrow the underlying transport. Used by offline tests to inspect the recorded request (the
    /// fixture transport stores the last `MessagesRequest`); harmless in production.
    pub fn transport_ref(&self) -> &T {
        &self.transport
    }

    /// Run one pinned, structured, temperature-0 model call and map the result to a `CanonicalVerdict`.
    /// Any error becomes the deterministic [`abort_verdict`] (I4: fail closed, escalate not guess).
    fn grade(&self, system: String, user: String) -> CanonicalVerdict {
        let req = MessagesRequest::build(&self.model, system, user);
        match self.transport.send(&req) {
            Ok(resp) => match resp.structured_verdict() {
                Ok(sv) => sv.to_canonical(),
                Err(_) => abort_verdict(),
            },
            Err(_) => abort_verdict(),
        }
    }
}

impl<T: Transport> HumanityOracle for ClaudeOracle<T> {
    fn grade_liveness(&self, challenge: &[u8], response: &[u8]) -> CanonicalVerdict {
        let (system, user) = prompt::liveness(challenge, response);
        self.grade(system, user)
    }

    fn analyze_sybil(&self, graph: &GraphView, subject: &Address) -> CanonicalVerdict {
        let graph_repr = render_graph(graph);
        let subject_repr = hex20(subject);
        let (system, user) = prompt::sybil(graph_repr.as_bytes(), &subject_repr);
        self.grade(system, user)
    }

    fn adjudicate(&self, evidence: &[u8]) -> CanonicalVerdict {
        let (system, user) = prompt::adjudicate(evidence);
        self.grade(system, user)
    }
}

/// Render a [`GraphView`] deterministically as sorted `voucher -> vouchee` lines. The runtime already
/// hands us sorted edges (consensus path), but we sort defensively so the textual rendering — and
/// therefore the prompt, and therefore the model input — is byte-identical across jurors regardless of
/// how the `GraphView` was constructed.
pub fn render_graph(graph: &GraphView) -> String {
    let mut edges = graph.edges.clone();
    edges.sort_unstable();
    edges.dedup();
    let mut out = String::new();
    for (voucher, vouchee) in &edges {
        out.push_str(&hex20(voucher));
        out.push_str(" -> ");
        out.push_str(&hex20(vouchee));
        out.push('\n');
    }
    out
}

/// Lowercase `0x`-prefixed hex for a 20-byte address. Deterministic, allocation-light.
fn hex20(a: &Address) -> String {
    let mut s = String::with_capacity(42);
    s.push_str("0x");
    for b in a {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{ContentBlock, MessagesResponse};
    use crate::schema;
    use std::sync::Mutex;

    /// An in-test transport returning a canned response (no network). Records the last request so
    /// tests can assert the pinned request shape.
    struct StubTransport {
        response: MessagesResponse,
        last: Mutex<Option<MessagesRequest>>,
    }
    impl StubTransport {
        fn new(response: MessagesResponse) -> Self {
            Self {
                response,
                last: Mutex::new(None),
            }
        }
    }
    impl Transport for StubTransport {
        fn send(&self, req: &MessagesRequest) -> Result<MessagesResponse, OracleError> {
            *self.last.lock().unwrap() = Some(req.clone());
            Ok(self.response.clone())
        }
    }

    fn resp(verdict: &str, confidence: &str, reasons: &str) -> MessagesResponse {
        MessagesResponse {
            content: vec![ContentBlock {
                kind: "text".into(),
                text: Some(format!(
                    r#"{{"verdict":"{verdict}","confidence":"{confidence}","reasons":"{reasons}"}}"#
                )),
                input: None,
            }],
        }
    }

    #[test]
    fn liveness_maps_structured_output_to_canonical() {
        let oracle = ClaudeOracle::with_transport(
            "claude-opus-4-8",
            StubTransport::new(resp("Human", "High", "ok")),
        );
        let v = oracle.grade_liveness(b"challenge", b"response");
        assert_eq!(v.verdict, Verdict::Human);
        assert_eq!(v.confidence, Confidence::High);
        assert_eq!(v.reasons_hash, schema::reasons_hash("ok"));
    }

    #[test]
    fn transport_receives_pinned_temperature_zero_request() {
        let stub = StubTransport::new(resp("Sybil", "Med", "farm"));
        // Re-create the recording stub by hand so we can read `last`.
        let recorded = {
            let oracle = ClaudeOracle::with_transport("claude-opus-4-8", stub);
            let _ = oracle.adjudicate(b"evidence");
            let r = oracle.transport.last.lock().unwrap().clone().unwrap();
            r
        };
        assert_eq!(recorded.temperature, 0.0);
        assert_eq!(recorded.model, "claude-opus-4-8");
        assert_eq!(recorded.output_config.format.kind, "json_schema");
        // The framed, untrusted-evidence fence is present in the sent user content.
        assert!(recorded.messages[0].content.contains("UNTRUSTED"));
    }

    #[test]
    fn decode_failure_aborts_to_uncertain_low() {
        let bad = MessagesResponse {
            content: vec![ContentBlock {
                kind: "text".into(),
                text: Some("garbage not json".into()),
                input: None,
            }],
        };
        let oracle = ClaudeOracle::with_transport("claude-opus-4-8", StubTransport::new(bad));
        let v = oracle.adjudicate(b"evidence");
        assert_eq!(v, abort_verdict());
        assert_eq!(v.verdict, Verdict::Uncertain);
        assert_eq!(v.confidence, Confidence::Low);
    }

    #[test]
    fn transport_error_aborts_to_uncertain_low() {
        struct FailTransport;
        impl Transport for FailTransport {
            fn send(&self, _: &MessagesRequest) -> Result<MessagesResponse, OracleError> {
                Err(OracleError::Transport("boom".into()))
            }
        }
        let oracle = ClaudeOracle::with_transport("claude-opus-4-8", FailTransport);
        assert_eq!(oracle.adjudicate(b"x"), abort_verdict());
    }

    #[test]
    fn render_graph_is_sorted_and_stable() {
        let a = [1u8; 20];
        let b = [2u8; 20];
        let c = [3u8; 20];
        let g1 = GraphView {
            edges: vec![(c, a), (a, b), (a, b)], // unsorted + duplicate
        };
        let g2 = GraphView {
            edges: vec![(a, b), (c, a)],
        };
        assert_eq!(
            render_graph(&g1),
            render_graph(&g2),
            "rendering is canonical"
        );
        assert!(render_graph(&g1).contains("0x0101"));
    }

    #[test]
    fn same_input_same_verdict_determinism() {
        // The whole point (I1/I5): identical input through identical transport ⇒ identical effect.
        let mk = || {
            ClaudeOracle::with_transport(
                "claude-opus-4-8",
                StubTransport::new(resp("Human", "Med", "r")),
            )
        };
        let v1 = mk().grade_liveness(b"c", b"r");
        let v2 = mk().grade_liveness(b"c", b"r");
        assert_eq!(v1, v2);
        assert!(v1.quorum_eq(&v2));
    }
}
