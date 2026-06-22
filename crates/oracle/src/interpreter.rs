//! [`ClaudeInterpreter`] — the live Claude-backed [`ContractInterpreter`] implementation (M4-T3).
//!
//! It is the M4 analogue of [`crate::ClaudeOracle`]: the same model-invocation layer (pinned model,
//! temperature 0, structured output, the swappable [`Transport`] seam) — but it interprets a
//! natural-language **prompt contract** into a [`CanonicalEffect`] instead of grading humanity. The
//! trait method is *infallible* (the runtime tallies effects, it does not handle interpreter errors),
//! so every internal failure path — missing key, transport failure, an undecodable response, or a
//! response that decodes to an out-of-range op — maps to a **deterministic abort effect** (a single
//! `Abort` op), which the runtime applies as no state change (I4 fail-closed). The interpreter never
//! guesses an effect on failure.
//!
//! Determinism (I1): the request is temperature 0, the pinned model id, and the closed canonical
//! *effect* schema; two honest interpreters seeing identical `(text, state, trigger)` send byte-
//! identical requests and (at temperature 0, constrained output) converge on the same effect, so the
//! quorum forms. Off-chain reasoning never enters the effect (only the op list does), so even differing
//! rationales never split the quorum.
//!
//! Least authority (I6): the interpreter is handed only the contract text, the content-addressed state
//! view (the contract's own escrow / parties / vars / owned streams — no arbitrary chain state, no
//! PII), and the trigger. It has no tools, no network beyond the pinned model call, and no chain/state
//! access. The runtime independently re-validates every emitted op against escrow/authority, so a
//! fooled interpreter is still bounded to a fail-closed abort.

use crate::client::{
    ClaudeConfig, HttpTransport, MessagesRequest, MessagesResponse, OracleError, Transport,
};
use crate::contract_prompt;
use crate::effect_schema::{effect_json_schema, StructuredEffect};
use ubi2_runtime::{CanonicalEffect, ContractInterpreter, ContractStateView, Hash};

/// The deterministic abort effect: a single `Abort` op carrying a fixed reason commitment. Returned
/// whenever the model layer cannot produce a trustworthy canonical effect (missing key, transport,
/// undecodable / out-of-range response). The runtime commits no state change on an abort (I4).
///
/// The reason hash is a fixed, content-free marker (`keccak256("ubi2:interpreter-abort")`-style is
/// overkill for a consensus-internal marker, so we use a stable sentinel): two honest interpreters that
/// both abort on the same failure mode produce the *same* abort effect and therefore agree, so an
/// infrastructure-wide failure aborts deterministically rather than splitting the quorum.
pub fn abort_effect() -> CanonicalEffect {
    CanonicalEffect::abort(ABORT_REASON)
}

/// A stable, content-free reason commitment for a deterministic interpreter abort. Pinned so every
/// aborting interpreter emits a byte-identical abort effect (they group in the tally).
pub const ABORT_REASON: Hash = *b"ubi2:contract-interpreter-abort.";

/// A Claude-backed contract interpreter. Holds the pinned model id and a [`Transport`]. Generic over
/// the transport so the identical interpretation logic runs in CI against recorded fixtures and in
/// production against the Anthropic API (I5).
pub struct ClaudeInterpreter<T: Transport> {
    model: String,
    transport: T,
}

impl ClaudeInterpreter<HttpTransport> {
    /// Construct the **live** interpreter from the environment. Requires `ANTHROPIC_API_KEY`; if unset,
    /// returns [`OracleError::MissingApiKey`] so the node can fall back to the runtime
    /// `MockInterpreter`. The only constructor that touches the network; never called in tests.
    pub fn from_env() -> Result<Self, OracleError> {
        let cfg = ClaudeConfig::from_env()?;
        Ok(Self {
            transport: HttpTransport::new(cfg.api_key),
            model: cfg.model,
        })
    }
}

impl<T: Transport> ClaudeInterpreter<T> {
    /// Construct with an explicit transport + model id. Used by tests (fixture transport) and by any
    /// caller injecting a custom transport. The model id is pinned by the caller.
    pub fn with_transport(model: impl Into<String>, transport: T) -> Self {
        Self {
            model: model.into(),
            transport,
        }
    }

    /// The pinned model id this interpreter calls. Two interpreters MUST run the same id to agree.
    pub fn model(&self) -> &str {
        &self.model
    }

    /// Borrow the underlying transport (offline tests inspect the recorded request).
    pub fn transport_ref(&self) -> &T {
        &self.transport
    }

    /// Run one pinned, structured, temperature-0 model call and map the result to a `CanonicalEffect`.
    /// Any error — transport, undecodable response, or a structurally-valid response whose fields are
    /// out of range — becomes the deterministic [`abort_effect`] (I4: fail closed, never guess).
    fn run(&self, system: String, user: String) -> CanonicalEffect {
        let req =
            MessagesRequest::build_with_schema(&self.model, system, user, effect_json_schema());
        match self.transport.send(&req) {
            Ok(resp) => match structured_effect(&resp) {
                // A well-formed structured effect whose every op is in range ⇒ the canonical effect.
                Ok(se) => match se.to_canonical() {
                    Ok(effect) => effect,
                    // Decoded shape but an out-of-range / malformed field ⇒ deterministic abort.
                    Err(_) => abort_effect(),
                },
                Err(_) => abort_effect(),
            },
            Err(_) => abort_effect(),
        }
    }
}

impl<T: Transport> ContractInterpreter for ClaudeInterpreter<T> {
    fn interpret(
        &self,
        contract_text: &[u8],
        state: &ContractStateView,
        trigger: &[u8],
    ) -> CanonicalEffect {
        let (system, user) = contract_prompt::interpret(contract_text, state, trigger);
        self.run(system, user)
    }
}

/// Extract a [`StructuredEffect`] from a Messages-API response, deterministically. Mirrors the verdict
/// path in [`crate::client::MessagesResponse::structured_verdict`]: try a structured `input` object
/// first (strict tool-use forward-compat), then a `text` block parsed as JSON. Any miss is an
/// [`OracleError::Decode`] — a deterministic abort, never a guess.
fn structured_effect(resp: &MessagesResponse) -> Result<StructuredEffect, OracleError> {
    for block in &resp.content {
        if let Some(obj) = &block.input {
            if let Ok(se) = serde_json::from_value::<StructuredEffect>(obj.clone()) {
                return Ok(se);
            }
        }
        if block.kind == "text" {
            if let Some(t) = &block.text {
                if let Ok(se) = serde_json::from_str::<StructuredEffect>(t.trim()) {
                    return Ok(se);
                }
            }
        }
    }
    Err(OracleError::Decode(
        "no content block matched the canonical effect schema".to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::ContentBlock;
    use std::sync::Mutex;
    use ubi2_runtime::Op;

    /// An in-test transport returning a canned response. Records the last request.
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

    fn text_resp(json: &str) -> MessagesResponse {
        MessagesResponse {
            content: vec![ContentBlock {
                kind: "text".into(),
                text: Some(json.into()),
                input: None,
            }],
        }
    }

    fn view(escrow: u128) -> ContractStateView {
        ContractStateView {
            contract_id: 1,
            escrow,
            parties: vec![[1u8; 20], [2u8; 20]],
            vars: vec![],
            streams: vec![],
            now: 0,
        }
    }

    #[test]
    fn interprets_transfer_effect_matching_runtime_ops() {
        let payee = format!("0x{}", "02".repeat(20));
        let json = format!(
            r#"{{"ops":[{{"op":"transfer","to":"{payee}","amount":"5000000000000000000"}}]}}"#
        );
        let interp = ClaudeInterpreter::with_transport(
            "claude-opus-4-8",
            StubTransport::new(text_resp(&json)),
        );
        let effect = interp.interpret(b"pay 5 UBI to the payee", &view(10u128.pow(19)), b"signal");
        // Byte-for-byte identical to the MockInterpreter / runtime building the same op (they group).
        let expected = CanonicalEffect::new(vec![Op::Transfer {
            to: [2u8; 20],
            amount: 5_000_000_000_000_000_000u128,
        }]);
        assert_eq!(effect, expected);
    }

    #[test]
    fn request_is_pinned_temperature_zero_effect_schema_and_fenced() {
        let interp = ClaudeInterpreter::with_transport(
            "claude-opus-4-8",
            StubTransport::new(text_resp(r#"{"ops":[]}"#)),
        );
        let _ = interp.interpret(b"some contract", &view(1000), b"trigger");
        let req = interp.transport_ref().last.lock().unwrap().clone().unwrap();
        assert_eq!(req.temperature, 0.0);
        assert_eq!(req.model, "claude-opus-4-8");
        assert_eq!(req.output_config.format.kind, "json_schema");
        // The effect schema (not the verdict schema): top-level `ops` array of 6 op variants.
        assert!(req.output_config.format.schema["properties"]["ops"].is_object());
        assert_eq!(
            req.output_config.format.schema["properties"]["ops"]["items"]["oneOf"]
                .as_array()
                .unwrap()
                .len(),
            6
        );
        // Contract + trigger fenced as untrusted; the authority envelope (escrow) is present.
        assert!(req.messages[0].content.contains("UNTRUSTED"));
        assert!(req.messages[0].content.contains("escrow_balance"));
        assert!(req.system.contains("FAIL CLOSED"));
    }

    #[test]
    fn empty_ops_response_is_the_noop_effect() {
        let interp = ClaudeInterpreter::with_transport(
            "claude-opus-4-8",
            StubTransport::new(text_resp(r#"{"ops":[]}"#)),
        );
        let effect = interp.interpret(b"do nothing on this trigger", &view(1000), b"x");
        assert_eq!(effect, CanonicalEffect::noop());
    }

    #[test]
    fn transport_error_aborts_deterministically() {
        struct FailTransport;
        impl Transport for FailTransport {
            fn send(&self, _: &MessagesRequest) -> Result<MessagesResponse, OracleError> {
                Err(OracleError::Transport("boom".into()))
            }
        }
        let interp = ClaudeInterpreter::with_transport("claude-opus-4-8", FailTransport);
        let effect = interp.interpret(b"c", &view(1000), b"t");
        assert_eq!(effect, abort_effect());
        assert!(effect.is_abort());
    }

    #[test]
    fn undecodable_response_aborts_deterministically() {
        let interp = ClaudeInterpreter::with_transport(
            "claude-opus-4-8",
            StubTransport::new(text_resp("not json at all")),
        );
        let effect = interp.interpret(b"c", &view(1000), b"t");
        assert_eq!(effect, abort_effect());
    }

    #[test]
    fn out_of_range_op_aborts_deterministically() {
        // Structurally a valid effect, but the amount overflows u128 ⇒ fail closed to an abort.
        let payee = format!("0x{}", "02".repeat(20));
        let big = "340282366920938463463374607431768211456"; // u128::MAX + 1
        let json = format!(r#"{{"ops":[{{"op":"transfer","to":"{payee}","amount":"{big}"}}]}}"#);
        let interp = ClaudeInterpreter::with_transport(
            "claude-opus-4-8",
            StubTransport::new(text_resp(&json)),
        );
        let effect = interp.interpret(b"c", &view(u128::MAX), b"t");
        assert_eq!(effect, abort_effect());
    }

    #[test]
    fn same_input_same_effect_determinism() {
        // I1/I5: identical input through identical transport ⇒ identical effect (incl. effect_hash).
        let payee = format!("0x{}", "0a".repeat(20));
        let json = format!(r#"{{"ops":[{{"op":"transfer","to":"{payee}","amount":"7"}}]}}"#);
        let mk = || {
            ClaudeInterpreter::with_transport(
                "claude-opus-4-8",
                StubTransport::new(text_resp(&json)),
            )
        };
        let e1 = mk().interpret(b"c", &view(100), b"t");
        let e2 = mk().interpret(b"c", &view(100), b"t");
        assert_eq!(e1, e2);
        assert_eq!(e1.effect_hash, e2.effect_hash);
    }

    #[test]
    fn structured_input_block_is_supported() {
        // Forward-compat: a response delivered as a structured `input` object (strict tool use) maps.
        let resp = MessagesResponse {
            content: vec![ContentBlock {
                kind: "tool_use".into(),
                text: None,
                input: Some(serde_json::json!({ "ops": [] })),
            }],
        };
        let interp = ClaudeInterpreter::with_transport("claude-opus-4-8", StubTransport::new(resp));
        assert_eq!(
            interp.interpret(b"c", &view(1), b"t"),
            CanonicalEffect::noop()
        );
    }

    #[test]
    fn abort_effect_is_a_single_abort_op() {
        let e = abort_effect();
        assert!(e.is_abort());
        assert_eq!(e.ops.len(), 1);
        assert_eq!(e, CanonicalEffect::abort(ABORT_REASON));
    }
}
