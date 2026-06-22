//! The model-invocation layer: the pinned Anthropic Messages-API request, a swappable [`Transport`]
//! seam, the live HTTP transport, and an offline fixture transport for tests/CI (I5).
//!
//! Determinism (I1): every request is built with **temperature 0**, the **pinned model id**, and a
//! **structured-output schema** that grammar-constrains the model to the closed verdict shape. The
//! Anthropic API exposes no `seed` parameter, so determinism in the *consensus* sense is delivered by
//! three layers that do not depend on a seed: (a) temperature 0 + grammar-constrained output collapse
//! the model's choices to a small closed domain; (b) deterministic confidence bucketing + canonical
//! mapping (see [`crate::schema`]) leave no post-processing freedom; and (c) the **interpreter quorum**
//! is the actual consensus primitive — the chain commits only when ≥QUORUM jurors independently
//! produce the *same* `CanonicalVerdict`, and any residual model nondeterminism deterministically
//! *escalates* rather than coin-flips (I4). We pin the model id + version explicitly and never resolve
//! an evergreen alias loosely.

use crate::schema::{self, StructuredVerdict};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Anthropic Messages API endpoint (pinned).
pub const ANTHROPIC_URL: &str = "https://api.anthropic.com/v1/messages";

/// The Anthropic API version header value (pinned; see Anthropic versioning docs).
pub const ANTHROPIC_VERSION: &str = "2023-06-01";

/// **Pinned model id** for every consensus-path call. `claude-opus-4-8` is a pinned snapshot (dateless
/// IDs from the 4.6 generation on are snapshots, not evergreen pointers — per Anthropic's model-ID
/// docs), Anthropic's most capable Opus-tier model, with a Jan-2026 knowledge cutoff. Pinned here, but
/// overridable via [`ClaudeConfig`] / the `UBI2_ORACLE_MODEL` env var so the node operator can roll it
/// forward deliberately (never an implicit upgrade). Two jurors MUST run the same id to agree.
pub const DEFAULT_MODEL: &str = "claude-opus-4-8";

/// Max tokens for the verdict completion. The output is a tiny JSON object, so this is generous.
pub const MAX_TOKENS: u32 = 1024;

/// Configuration for the live [`ClaudeOracle`](crate::ClaudeOracle). The API key is read from the
/// environment and **never** stored in logs or artifacts (I6: secrets never enter code/logs).
#[derive(Clone)]
pub struct ClaudeConfig {
    /// Pinned model id. Defaults to [`DEFAULT_MODEL`]; override deliberately.
    pub model: String,
    /// The Anthropic API key. Loaded from `ANTHROPIC_API_KEY`.
    pub api_key: String,
}

impl fmt::Debug for ClaudeConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the key (I6).
        f.debug_struct("ClaudeConfig")
            .field("model", &self.model)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl ClaudeConfig {
    /// Build config from the environment. `ANTHROPIC_API_KEY` is **required** — if it is unset the
    /// node falls back to the runtime `MockOracle` (the caller handles that), so we return a clear
    /// error here rather than constructing a useless oracle.
    pub fn from_env() -> Result<Self, OracleError> {
        let api_key = std::env::var("ANTHROPIC_API_KEY")
            .map_err(|_| OracleError::MissingApiKey)?
            .trim()
            .to_string();
        if api_key.is_empty() {
            return Err(OracleError::MissingApiKey);
        }
        let model = std::env::var("UBI2_ORACLE_MODEL")
            .ok()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODEL.to_string());
        Ok(Self { model, api_key })
    }
}

/// Errors from the model-invocation layer. Every variant is a *deterministic abort* signal — the
/// oracle never guesses on failure (I4). The caller (`ClaudeOracle`) maps any abort to an
/// `Uncertain`/`Low` canonical verdict so the case escalates rather than coin-flips.
#[derive(Debug)]
pub enum OracleError {
    /// `ANTHROPIC_API_KEY` is unset/empty — the node should use `MockOracle` instead.
    MissingApiKey,
    /// The configured `base_url` was refused by the per-provider URL policy (SSRF / key-exfiltration
    /// defense, C5-SEC-1). Carries a secret-free, operator-facing reason (the offending URL/host only).
    BadConfig(String),
    /// The HTTP transport failed (network, timeout, non-2xx). Carries a short, key-free description.
    Transport(String),
    /// The response could not be parsed into the pinned structured schema (deterministic abort).
    Decode(String),
}

impl fmt::Display for OracleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OracleError::MissingApiKey => write!(
                f,
                "ANTHROPIC_API_KEY is not set; node should fall back to MockOracle"
            ),
            OracleError::BadConfig(m) => write!(f, "oracle config rejected: {m}"),
            OracleError::Transport(m) => write!(f, "oracle transport error: {m}"),
            OracleError::Decode(m) => write!(f, "oracle response decode error: {m}"),
        }
    }
}

impl std::error::Error for OracleError {}

/// A model-invocation request, fully built and pinned. Serialized as the Anthropic Messages-API body.
///
/// Forces structured output via `output_config.format = { type: "json_schema", schema: <closed> }`
/// (the GA structured-outputs mechanism: the schema is compiled to a grammar that constrains token
/// generation, so the response is guaranteed to match — no "please return JSON" fragility).
#[derive(Debug, Clone, Serialize)]
pub struct MessagesRequest {
    pub model: String,
    pub max_tokens: u32,
    /// Pinned to 0 for determinism (I1).
    pub temperature: f32,
    pub system: String,
    pub messages: Vec<Message>,
    pub output_config: OutputConfig,
}

#[derive(Debug, Clone, Serialize)]
pub struct Message {
    pub role: &'static str,
    pub content: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputConfig {
    pub format: OutputFormat,
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputFormat {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub schema: serde_json::Value,
}

impl MessagesRequest {
    /// Build the pinned request for a given system prompt + framed user content, using the
    /// proof-of-humanity verdict schema. Equivalent to [`MessagesRequest::build_with_schema`] with
    /// [`schema::json_schema`].
    pub fn build(model: &str, system: String, user: String) -> Self {
        Self::build_with_schema(model, system, user, schema::json_schema())
    }

    /// Build the pinned request for a given system prompt + framed user content with an **explicit**
    /// structured-output JSON-schema. Used by the M4 [`ClaudeInterpreter`](crate::ClaudeInterpreter),
    /// which constrains generation to the canonical *effect* schema (the closed `Op` list) rather than
    /// the verdict schema — same temperature-0, pinned-model, closed-shape determinism, different
    /// closed shape. Both consensus paths share this one builder so the request invariants (temperature
    /// 0, `json_schema` format, `additionalProperties:false`) are guaranteed identical.
    pub fn build_with_schema(
        model: &str,
        system: String,
        user: String,
        schema: serde_json::Value,
    ) -> Self {
        Self {
            model: model.to_string(),
            max_tokens: MAX_TOKENS,
            temperature: 0.0,
            system,
            messages: vec![Message {
                role: "user",
                content: user,
            }],
            output_config: OutputConfig {
                format: OutputFormat {
                    kind: "json_schema",
                    schema,
                },
            },
        }
    }
}

/// The relevant slice of an Anthropic Messages-API response: the structured output is delivered as a
/// `content` block. With `output_config.format` the model returns the JSON object as text in a single
/// content block; we extract and parse it against the pinned schema.
#[derive(Debug, Clone, Deserialize)]
pub struct MessagesResponse {
    pub content: Vec<ContentBlock>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ContentBlock {
    #[serde(rename = "type")]
    pub kind: String,
    /// Present on `text` blocks — the JSON document constrained to our schema.
    #[serde(default)]
    pub text: Option<String>,
    /// Present on `tool_use` / structured blocks as a parsed object (forward-compat with the
    /// strict-tool-use mechanism). Either path yields the same `StructuredVerdict`.
    #[serde(default)]
    pub input: Option<serde_json::Value>,
}

impl MessagesResponse {
    /// Wrap a single structured-output JSON document (delivered as text by a non-Anthropic backend's
    /// reply envelope — Ollama `message.content`, OpenAI `choices[0].message.content`) as a one-block
    /// `text` response, so the existing schema decoders ([`structured_verdict`](Self::structured_verdict)
    /// / `crate::interpreter`'s effect decoder) parse it unchanged. This is the single normalization
    /// point: every provider funnels its reply through here, so all backends share one decode path and
    /// therefore produce byte-identical canonical outputs (I1/I5).
    pub fn from_text(text: impl Into<String>) -> Self {
        Self {
            content: vec![ContentBlock {
                kind: "text".to_string(),
                text: Some(text.into()),
                input: None,
            }],
        }
    }

    /// Extract the [`StructuredVerdict`] from the response, deterministically. Tries a structured
    /// `input` object first, then a `text` block parsed as JSON. Any miss is a [`OracleError::Decode`]
    /// — a deterministic abort, never a guess.
    pub fn structured_verdict(&self) -> Result<StructuredVerdict, OracleError> {
        for block in &self.content {
            if let Some(obj) = &block.input {
                if let Ok(sv) = serde_json::from_value::<StructuredVerdict>(obj.clone()) {
                    return Ok(sv);
                }
            }
            if block.kind == "text" {
                if let Some(t) = &block.text {
                    if let Ok(sv) = serde_json::from_str::<StructuredVerdict>(t.trim()) {
                        return Ok(sv);
                    }
                }
            }
        }
        Err(OracleError::Decode(
            "no content block matched the pinned verdict schema".to_string(),
        ))
    }
}

/// The model-call seam. The live transport hits the Anthropic API; the test transport replays recorded
/// fixtures. Decoupling here is what makes determinism **testable offline** (I5): CI never touches the
/// network — it asserts the request→fixture→`CanonicalVerdict` mapping with a [`FixtureTransport`].
pub trait Transport: Send + Sync {
    /// Send a pinned request and return the parsed response. Errors are deterministic aborts.
    fn send(&self, req: &MessagesRequest) -> Result<MessagesResponse, OracleError>;
}

/// A boxed transport is itself a transport. This lets the backend constructor select a provider at
/// runtime (`Box<dyn Transport>`) while [`ClaudeOracle`](crate::ClaudeOracle) /
/// [`ClaudeInterpreter`](crate::ClaudeInterpreter) stay generic over `T: Transport` — the same grading
/// code runs over a static fixture transport (tests) or a dynamic provider transport (node).
impl Transport for Box<dyn Transport> {
    fn send(&self, req: &MessagesRequest) -> Result<MessagesResponse, OracleError> {
        (**self).send(req)
    }
}

/// Live transport: a blocking `reqwest` client against the Anthropic Messages API. Constructed only on
/// the live path (gated behind `ANTHROPIC_API_KEY`); **never** instantiated in tests/CI.
pub struct HttpTransport {
    client: reqwest::blocking::Client,
    api_key: String,
}

impl HttpTransport {
    pub fn new(api_key: String) -> Self {
        Self {
            // Disable HTTP redirects: a `3xx` must never be able to bounce the request — and the
            // `x-api-key` header — to a different host (cross-host credential leak, C5-SEC-1).
            client: reqwest::blocking::Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            api_key,
        }
    }
}

impl Transport for HttpTransport {
    fn send(&self, req: &MessagesRequest) -> Result<MessagesResponse, OracleError> {
        let resp = self
            .client
            .post(ANTHROPIC_URL)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .header("content-type", "application/json")
            .json(req)
            .send()
            .map_err(|e| OracleError::Transport(scrub(&e.to_string(), &self.api_key)))?;
        let status = resp.status();
        if !status.is_success() {
            // Body may echo request fragments; scrub the key defensively before surfacing.
            let body = resp.text().unwrap_or_default();
            return Err(OracleError::Transport(format!(
                "status {status}: {}",
                scrub(&body, &self.api_key)
            )));
        }
        resp.json::<MessagesResponse>()
            .map_err(|e| OracleError::Decode(scrub(&e.to_string(), &self.api_key)))
    }
}

/// Remove any accidental occurrence of the API key from an error string before it can be logged (I6).
fn scrub(s: &str, key: &str) -> String {
    if key.is_empty() {
        s.to_string()
    } else {
        s.replace(key, "<redacted>")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_is_pinned_temperature_zero_and_schema_constrained() {
        let req = MessagesRequest::build(DEFAULT_MODEL, "sys".into(), "user".into());
        assert_eq!(req.temperature, 0.0, "consensus path must be temperature 0");
        assert_eq!(req.model, "claude-opus-4-8");
        assert_eq!(req.output_config.format.kind, "json_schema");
        assert_eq!(
            req.output_config.format.schema["additionalProperties"],
            serde_json::json!(false)
        );
        // Serialization carries the structured-output field names the API expects.
        let v = serde_json::to_value(&req).unwrap();
        assert_eq!(v["temperature"], serde_json::json!(0.0));
        assert!(v["output_config"]["format"]["schema"].is_object());
    }

    #[test]
    fn response_parses_text_block_into_structured_verdict() {
        let resp = MessagesResponse {
            content: vec![ContentBlock {
                kind: "text".into(),
                text: Some(
                    r#"{"verdict":"Human","confidence":"High","reasons":"coherent"}"#.into(),
                ),
                input: None,
            }],
        };
        let sv = resp.structured_verdict().unwrap();
        assert_eq!(sv.verdict, schema::VerdictTag::Human);
        assert_eq!(sv.confidence, schema::ConfidenceTag::High);
    }

    #[test]
    fn response_parses_structured_input_block() {
        let resp = MessagesResponse {
            content: vec![ContentBlock {
                kind: "tool_use".into(),
                text: None,
                input: Some(
                    serde_json::json!({"verdict":"Sybil","confidence":"Med","reasons":"farm"}),
                ),
            }],
        };
        let sv = resp.structured_verdict().unwrap();
        assert_eq!(sv.verdict, schema::VerdictTag::Sybil);
    }

    #[test]
    fn unparseable_response_is_a_deterministic_decode_abort() {
        let resp = MessagesResponse {
            content: vec![ContentBlock {
                kind: "text".into(),
                text: Some("not json".into()),
                input: None,
            }],
        };
        assert!(matches!(
            resp.structured_verdict(),
            Err(OracleError::Decode(_))
        ));
    }

    #[test]
    fn scrub_removes_key() {
        assert_eq!(
            scrub("oops sk-abc leaked", "sk-abc"),
            "oops <redacted> leaked"
        );
    }

    #[test]
    fn config_debug_redacts_key() {
        let c = ClaudeConfig {
            model: DEFAULT_MODEL.into(),
            api_key: "sk-secret".into(),
        };
        let dbg = format!("{c:?}");
        assert!(!dbg.contains("sk-secret"));
        assert!(dbg.contains("redacted"));
    }
}
