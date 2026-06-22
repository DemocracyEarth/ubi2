//! Pluggable model backends: **Anthropic** (cloud), **Ollama** (local), and **OpenAI-compatible**
//! (cloud / OpenRouter / Groq / local servers). One config enum selects the provider; one constructor
//! returns boxed [`HumanityOracle`] + [`ContractInterpreter`] trait objects wired to it.
//!
//! # Why this is safe to generalize (the determinism discipline is provider-independent)
//! The whole consensus-relevant story lives **above** the transport: the pinned, provider-neutral
//! [`MessagesRequest`](crate::client::MessagesRequest) (temperature 0, pinned model id, the closed
//! structured-output JSON-schema), the injection-fenced prompts ([`crate::prompt`] /
//! [`crate::contract_prompt`]), and the total, pure mapping of the structured output to a
//! [`CanonicalVerdict`] / [`CanonicalEffect`] ([`crate::schema`] / [`crate::effect_schema`]). A backend
//! is **only** a [`Transport`](crate::client::Transport): it translates that one neutral request into
//! its own wire format, forces JSON/structured output, posts it, and translates the reply back into the
//! neutral [`MessagesResponse`](crate::client::MessagesResponse). So all three providers produce the
//! **same** `CanonicalVerdict` / `CanonicalEffect` from the same input, under the same fail-closed rules
//! (I1/I4/I5/I6). Two jurors MUST run the *same provider + model* to agree (the model id is pinned and
//! recorded; cross-provider mixing on one case is an operator error, not a coin-flip — disagreement
//! still aborts deterministically).
//!
//! # What each backend forces
//! * **Anthropic** — Messages API, `output_config.format = json_schema` (existing [`HttpTransport`]).
//! * **Ollama** — local `POST {base}/api/chat`, `format: <json-schema>` + `options.temperature = 0`,
//!   `stream:false`. No API key. The schema is passed as Ollama's structured-output `format`.
//! * **OpenAI-compatible** — `POST {base}/v1/chat/completions`, `temperature:0` +
//!   `response_format: { type: "json_schema", json_schema: { name, strict, schema } }`, Bearer key.
//!
//! All three are gated for live use behind config/env; **tests never construct the live transports**
//! (I5): the request-construction + response-parsing logic is unit-tested against recorded fixtures.

use crate::client::{
    HttpTransport, MessagesRequest, MessagesResponse, OracleError, Transport, DEFAULT_MODEL,
};
use crate::{ClaudeInterpreter, ClaudeOracle};
use serde::{Deserialize, Serialize};
use std::fmt;
use ubi2_runtime::{ContractInterpreter, HumanityOracle};

/// Default model ids per provider. Anthropic reuses the pinned [`DEFAULT_MODEL`]; the others have no
/// universally-correct default, so we pick a sensible, overridable one and require the operator to pin
/// it deliberately (two jurors MUST run the same id).
pub const DEFAULT_OLLAMA_MODEL: &str = "llama3.1";
pub const DEFAULT_OPENAI_MODEL: &str = "gpt-4o";

/// Default base URLs.
pub const DEFAULT_OLLAMA_BASE_URL: &str = "http://localhost:11434";
pub const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com";

/// The selectable model provider. Determinism discipline is identical across all three; only the wire
/// format and auth differ (see [`Backend::transport`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Provider {
    /// Anthropic Messages API (cloud). The original, pinned path.
    Anthropic,
    /// A local Ollama server (`/api/chat`). No API key; forces JSON via the `format` option.
    Ollama,
    /// Any OpenAI-compatible `/v1/chat/completions` endpoint (OpenAI, OpenRouter, Groq, local servers).
    Openai,
}

impl Provider {
    /// The provider's default model id (overridable in [`Backend::model`]).
    pub fn default_model(self) -> &'static str {
        match self {
            Provider::Anthropic => DEFAULT_MODEL,
            Provider::Ollama => DEFAULT_OLLAMA_MODEL,
            Provider::Openai => DEFAULT_OPENAI_MODEL,
        }
    }

    /// The provider's default base URL (Anthropic's is pinned in [`crate::client`], so `None`).
    pub fn default_base_url(self) -> Option<&'static str> {
        match self {
            Provider::Anthropic => None,
            Provider::Ollama => Some(DEFAULT_OLLAMA_BASE_URL),
            Provider::Openai => Some(DEFAULT_OPENAI_BASE_URL),
        }
    }
}

/// Backend configuration: the provider, the pinned model id, an optional base URL override, and the
/// **name of the environment variable** the API key is read from (never the key itself — secrets never
/// enter config structs/logs/artifacts, I6). Deserializable from node config (TOML/JSON/env).
///
/// Field defaults make the common cases terse:
///   * `{ provider = "anthropic" }` → pinned Claude model, key from `ANTHROPIC_API_KEY`.
///   * `{ provider = "ollama" }` → `llama3.1` at `http://localhost:11434`, no key.
///   * `{ provider = "openai", model = "gpt-4o" }` → OpenAI, key from `OPENAI_API_KEY`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Backend {
    /// Which provider to call.
    pub provider: Provider,
    /// The pinned model id. `None` ⇒ the provider's [`Provider::default_model`].
    #[serde(default)]
    pub model: Option<String>,
    /// Base URL override. `None` ⇒ the provider's [`Provider::default_base_url`] (Anthropic ignores it).
    #[serde(default)]
    pub base_url: Option<String>,
    /// The **name** of the env var holding the API key (e.g. `"ANTHROPIC_API_KEY"`, `"OPENAI_API_KEY"`,
    /// `"OPENROUTER_API_KEY"`). `None` ⇒ the provider default; Ollama needs none.
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// An **in-memory** raw API key passed directly from the admin RPC (`setOracleConfig`'s `api_key`
    /// param). When `Some`, it is used verbatim instead of reading the env var — so the node never has to
    /// write the secret into its process env (C5-SEC-4). `#[serde(skip)]`: it is never serialized to the
    /// persisted config (only `api_key_env`, a *name*, is — I6). `Debug` omits it (see manual impl).
    #[serde(skip)]
    pub api_key: Option<String>,
}

impl fmt::Debug for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the raw key value (I6); show only whether one is present.
        f.debug_struct("Backend")
            .field("provider", &self.provider)
            .field("model", &self.model)
            .field("base_url", &self.base_url)
            .field("api_key_env", &self.api_key_env)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl Backend {
    /// A backend for `provider` with all-default model/base/key-env. Terse constructor for tests + the
    /// common path.
    pub fn new(provider: Provider) -> Self {
        Self {
            provider,
            model: None,
            base_url: None,
            api_key_env: None,
            api_key: None,
        }
    }

    /// Attach a raw API key in-memory (from the admin RPC). Used verbatim by the transport instead of an
    /// env var, so the node never writes the secret into its process env (C5-SEC-4).
    pub fn with_api_key(mut self, api_key: Option<String>) -> Self {
        self.api_key = api_key.filter(|k| !k.trim().is_empty());
        self
    }

    /// The resolved, pinned model id (config override or provider default).
    pub fn resolved_model(&self) -> String {
        self.model
            .clone()
            .filter(|m| !m.trim().is_empty())
            .unwrap_or_else(|| self.provider.default_model().to_string())
    }

    /// The resolved base URL (config override or provider default). Anthropic's endpoint is pinned in
    /// [`crate::client`], so `None` there means "use the pinned URL".
    pub fn resolved_base_url(&self) -> Option<String> {
        self.base_url
            .clone()
            .filter(|u| !u.trim().is_empty())
            .or_else(|| self.provider.default_base_url().map(str::to_string))
    }

    /// The env-var name the API key is read from (config override or provider default). `None` for
    /// providers that need no key (Ollama).
    pub fn resolved_api_key_env(&self) -> Option<String> {
        if let Some(name) = self.api_key_env.clone().filter(|n| !n.trim().is_empty()) {
            return Some(name);
        }
        match self.provider {
            Provider::Anthropic => Some("ANTHROPIC_API_KEY".to_string()),
            Provider::Openai => Some("OPENAI_API_KEY".to_string()),
            Provider::Ollama => None,
        }
    }

    /// Read the API key for this backend from its configured env var, if one is required. Returns
    /// `Ok(None)` for keyless providers (Ollama). Errors (with the env-var **name**, never a value) when
    /// a required key is unset/empty so the node can fall back to the deterministic Mock impls.
    fn read_api_key(&self) -> Result<Option<String>, OracleError> {
        // An in-memory key (passed directly from the admin RPC) wins over the env var — the node never
        // has to set a process env var for the secret (C5-SEC-4).
        if let Some(direct) = self
            .api_key
            .as_deref()
            .map(str::trim)
            .filter(|k| !k.is_empty())
        {
            return Ok(Some(direct.to_string()));
        }
        match self.resolved_api_key_env() {
            None => Ok(None),
            Some(name) => {
                let key = std::env::var(&name)
                    .map_err(|_| OracleError::MissingApiKey)?
                    .trim()
                    .to_string();
                if key.is_empty() {
                    return Err(OracleError::MissingApiKey);
                }
                Ok(Some(key))
            }
        }
    }

    /// Build the live [`Transport`] for this backend, reading the API key from its env var. The only
    /// place a live HTTP client is constructed; **never** called in tests/CI (I5). Returns
    /// [`OracleError::MissingApiKey`] when a required key is absent so the node falls back to Mock.
    pub fn transport(&self) -> Result<Box<dyn Transport>, OracleError> {
        // Defense-at-dial (C5-SEC-1): validate the configured `base_url` against the per-provider URL
        // policy BEFORE constructing any client. This refuses SSRF/internal/metadata targets (and the
        // wrong-host/scheme cases) so a repointed `base_url` can never be reached — the key is attached
        // only after this passes. The node's admin RPC also validates earlier (so a bad `setOracleConfig`
        // is rejected without a hot-swap); this is the second, mandatory gate on the actual dial path.
        crate::url_policy::validate_base_url(self.provider, self.base_url.as_deref())
            .map_err(|e| OracleError::BadConfig(e.0))?;
        let key = self.read_api_key()?;
        match self.provider {
            Provider::Anthropic => {
                // Reuse the existing, pinned Anthropic transport unchanged.
                let api_key = key.ok_or(OracleError::MissingApiKey)?;
                Ok(Box::new(HttpTransport::new(api_key)))
            }
            Provider::Ollama => {
                let base = self
                    .resolved_base_url()
                    .unwrap_or_else(|| DEFAULT_OLLAMA_BASE_URL.to_string());
                // Ollama never carries a key.
                Ok(Box::new(OllamaTransport::new(base)))
            }
            Provider::Openai => {
                let base = self
                    .resolved_base_url()
                    .unwrap_or_else(|| DEFAULT_OPENAI_BASE_URL.to_string());
                // The key rides the Bearer header — but only to a `base_url` that just passed the policy
                // above (a public https host), so it can never be exfiltrated to an internal/attacker host.
                let api_key = key.unwrap_or_default();
                Ok(Box::new(OpenAiTransport::new(base, api_key)))
            }
        }
    }

    /// Construct the live [`HumanityOracle`] for this backend, boxed behind the runtime trait. The node
    /// uses this for proof-of-humanity. The pinned model id is recorded in the returned oracle.
    pub fn humanity_oracle(&self) -> Result<Box<dyn HumanityOracle>, OracleError> {
        let model = self.resolved_model();
        let transport = self.transport()?;
        Ok(Box::new(ClaudeOracle::with_transport(model, transport)))
    }

    /// Construct the live [`ContractInterpreter`] for this backend, boxed behind the runtime trait. The
    /// node uses this for prompt-contract interpretation. The pinned model id is recorded.
    pub fn contract_interpreter(&self) -> Result<Box<dyn ContractInterpreter>, OracleError> {
        let model = self.resolved_model();
        let transport = self.transport()?;
        Ok(Box::new(ClaudeInterpreter::with_transport(
            model, transport,
        )))
    }
}

impl Default for Backend {
    /// The pinned Anthropic backend — the protocol's original, audited path.
    fn default() -> Self {
        Self::new(Provider::Anthropic)
    }
}

// ---------------------------------------------------------------------------------------------------
// Ollama transport: local `POST {base}/api/chat`, JSON-forced via `format`, temperature 0.
// ---------------------------------------------------------------------------------------------------

/// Live transport for a local Ollama server. Translates the neutral [`MessagesRequest`] into Ollama's
/// `/api/chat` body, forces structured JSON output via the `format` option (Ollama accepts a JSON-schema
/// there), pins `options.temperature = 0`, and disables streaming. Constructed only on the live path;
/// never instantiated in tests.
pub struct OllamaTransport {
    client: reqwest::blocking::Client,
    base_url: String,
}

impl OllamaTransport {
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            client: build_no_redirect_client(),
            base_url: normalize_base(base_url.into()),
        }
    }

    /// The chat endpoint URL.
    fn endpoint(&self) -> String {
        format!("{}/api/chat", self.base_url)
    }
}

impl Transport for OllamaTransport {
    fn send(&self, req: &MessagesRequest) -> Result<MessagesResponse, OracleError> {
        let body = ollama_request_body(req);
        let resp = self
            .client
            .post(self.endpoint())
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| OracleError::Transport(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(OracleError::Transport(format!("status {status}: {text}")));
        }
        let raw: serde_json::Value = resp
            .json()
            .map_err(|e| OracleError::Decode(e.to_string()))?;
        ollama_parse_response(&raw)
    }
}

/// Build the Ollama `/api/chat` request body from the neutral request. The system prompt and the user
/// content map to the two-message chat shape; `format` carries the closed structured-output schema so
/// Ollama constrains generation to valid JSON; `options.temperature = 0` and `stream:false` pin
/// determinism. Pure: identical neutral request ⇒ identical body (so two jurors send identical bytes).
pub fn ollama_request_body(req: &MessagesRequest) -> serde_json::Value {
    serde_json::json!({
        "model": req.model,
        "stream": false,
        "format": req.output_config.format.schema,
        "options": {
            "temperature": req.temperature,
            // Bound the reply like the Anthropic path; the structured output is a small JSON object.
            "num_predict": req.max_tokens,
        },
        "messages": [
            { "role": "system", "content": req.system },
            { "role": "user", "content": req.messages.first().map(|m| m.content.as_str()).unwrap_or("") },
        ],
    })
}

/// Map an Ollama `/api/chat` reply onto the neutral [`MessagesResponse`]. Ollama returns
/// `{ message: { role, content }, ... }`; `content` is the JSON document constrained by `format`. We
/// wrap it as a single `text` content block so the existing schema decoders parse it unchanged. A reply
/// with no assistant content is a deterministic [`OracleError::Decode`] (fail-closed, never a guess).
pub fn ollama_parse_response(raw: &serde_json::Value) -> Result<MessagesResponse, OracleError> {
    let content = raw
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| OracleError::Decode("ollama reply missing message.content".to_string()))?;
    Ok(MessagesResponse::from_text(content))
}

// ---------------------------------------------------------------------------------------------------
// OpenAI-compatible transport: `POST {base}/v1/chat/completions`, json_schema response_format, temp 0.
// ---------------------------------------------------------------------------------------------------

/// Live transport for any OpenAI-compatible chat-completions endpoint (OpenAI, OpenRouter, Groq, local
/// servers). Translates the neutral [`MessagesRequest`] into the `/v1/chat/completions` body, forces
/// structured JSON via `response_format: { type: "json_schema", ... , strict: true }`, pins
/// `temperature: 0`, and authenticates with a Bearer key. Constructed only on the live path.
pub struct OpenAiTransport {
    client: reqwest::blocking::Client,
    base_url: String,
    api_key: String,
}

impl OpenAiTransport {
    pub fn new(base_url: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            client: build_no_redirect_client(),
            base_url: normalize_base(base_url.into()),
            api_key: api_key.into(),
        }
    }

    /// The chat-completions endpoint URL.
    fn endpoint(&self) -> String {
        format!("{}/v1/chat/completions", self.base_url)
    }
}

impl Transport for OpenAiTransport {
    fn send(&self, req: &MessagesRequest) -> Result<MessagesResponse, OracleError> {
        let body = openai_request_body(req);
        let resp = self
            .client
            .post(self.endpoint())
            .header("authorization", format!("Bearer {}", self.api_key))
            .header("content-type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| OracleError::Transport(scrub(&e.to_string(), &self.api_key)))?;
        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(OracleError::Transport(format!(
                "status {status}: {}",
                scrub(&text, &self.api_key)
            )));
        }
        let raw: serde_json::Value = resp
            .json()
            .map_err(|e| OracleError::Decode(scrub(&e.to_string(), &self.api_key)))?;
        openai_parse_response(&raw)
    }
}

/// Build the OpenAI-compatible `/v1/chat/completions` body from the neutral request. The structured
/// output is forced via `response_format.json_schema` (strict), `temperature` is pinned to 0, and the
/// schema name is the stable structured-output key. Pure: identical neutral request ⇒ identical body.
pub fn openai_request_body(req: &MessagesRequest) -> serde_json::Value {
    serde_json::json!({
        "model": req.model,
        "temperature": req.temperature,
        "max_tokens": req.max_tokens,
        "response_format": {
            "type": "json_schema",
            "json_schema": {
                "name": "ubi2_structured_output",
                "strict": true,
                "schema": req.output_config.format.schema,
            }
        },
        "messages": [
            { "role": "system", "content": req.system },
            { "role": "user", "content": req.messages.first().map(|m| m.content.as_str()).unwrap_or("") },
        ],
    })
}

/// Map an OpenAI-compatible reply onto the neutral [`MessagesResponse`]. The body is
/// `{ choices: [ { message: { role, content } } ], ... }`; `content` is the JSON document constrained by
/// `response_format`. We wrap it as a single `text` content block so the existing schema decoders parse
/// it unchanged. A reply with no first-choice content is a deterministic [`OracleError::Decode`].
pub fn openai_parse_response(raw: &serde_json::Value) -> Result<MessagesResponse, OracleError> {
    let content = raw
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .ok_or_else(|| {
            OracleError::Decode("openai reply missing choices[0].message.content".to_string())
        })?;
    Ok(MessagesResponse::from_text(content))
}

/// Strip a single trailing slash so `{base}/v1/...` / `{base}/api/...` never double up.
fn normalize_base(s: String) -> String {
    s.trim_end_matches('/').to_string()
}

/// Build a blocking client with HTTP redirects **disabled** (C5-SEC-1): a `3xx` must never bounce the
/// request — and any auth header — to a different host (cross-host credential leak). All live transports
/// use this; the destination is already validated by [`crate::url_policy::validate_base_url`].
fn build_no_redirect_client() -> reqwest::blocking::Client {
    reqwest::blocking::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

/// Remove any accidental occurrence of the API key from an error string before it can be logged (I6).
/// Mirrors [`crate::client`]'s scrub for the OpenAI-compatible path.
fn scrub(s: &str, key: &str) -> String {
    if key.is_empty() {
        s.to_string()
    } else {
        s.replace(key, "<redacted>")
    }
}

impl fmt::Display for Provider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Provider::Anthropic => "anthropic",
            Provider::Ollama => "ollama",
            Provider::Openai => "openai",
        };
        f.write_str(s)
    }
}

/// Re-exported for symmetry with the Anthropic config; the node may build a [`ClaudeConfig`] directly
/// for the Anthropic path, or use [`Backend`] uniformly for all three.
pub use crate::client::ClaudeConfig as AnthropicConfig;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::MessagesRequest;
    use ubi2_runtime::{CanonicalVerdict, Confidence, Verdict};

    fn neutral_req() -> MessagesRequest {
        MessagesRequest::build(
            "test-model",
            "SYSTEM RULES".to_string(),
            "UNTRUSTED user content".to_string(),
        )
    }

    // ----- config resolution -----

    #[test]
    fn defaults_resolve_per_provider() {
        let a = Backend::new(Provider::Anthropic);
        assert_eq!(a.resolved_model(), DEFAULT_MODEL);
        assert_eq!(a.resolved_base_url(), None);
        assert_eq!(
            a.resolved_api_key_env().as_deref(),
            Some("ANTHROPIC_API_KEY")
        );

        let o = Backend::new(Provider::Ollama);
        assert_eq!(o.resolved_model(), DEFAULT_OLLAMA_MODEL);
        assert_eq!(
            o.resolved_base_url().as_deref(),
            Some(DEFAULT_OLLAMA_BASE_URL)
        );
        assert_eq!(o.resolved_api_key_env(), None, "ollama needs no key");

        let g = Backend::new(Provider::Openai);
        assert_eq!(g.resolved_model(), DEFAULT_OPENAI_MODEL);
        assert_eq!(
            g.resolved_base_url().as_deref(),
            Some(DEFAULT_OPENAI_BASE_URL)
        );
        assert_eq!(g.resolved_api_key_env().as_deref(), Some("OPENAI_API_KEY"));
    }

    #[test]
    fn overrides_win_over_defaults() {
        let b = Backend {
            provider: Provider::Openai,
            model: Some("llama-3.1-70b".to_string()),
            base_url: Some("https://openrouter.ai/api/".to_string()),
            api_key_env: Some("OPENROUTER_API_KEY".to_string()),
            api_key: None,
        };
        assert_eq!(b.resolved_model(), "llama-3.1-70b");
        // Trailing slash is normalized only at transport build; resolved keeps the override verbatim.
        assert_eq!(
            b.resolved_base_url().as_deref(),
            Some("https://openrouter.ai/api/")
        );
        assert_eq!(
            b.resolved_api_key_env().as_deref(),
            Some("OPENROUTER_API_KEY")
        );
    }

    #[test]
    fn config_round_trips_through_json() {
        let b = Backend {
            provider: Provider::Ollama,
            model: Some("qwen2.5".to_string()),
            base_url: Some("http://10.0.0.5:11434".to_string()),
            api_key_env: None,
            api_key: None,
        };
        let json = serde_json::to_string(&b).unwrap();
        let back: Backend = serde_json::from_str(&json).unwrap();
        assert_eq!(b, back);
    }

    #[test]
    fn minimal_config_deserializes_with_defaults() {
        // Only `provider` is required; the rest default to None (provider defaults kick in).
        let b: Backend = serde_json::from_str(r#"{"provider":"ollama"}"#).unwrap();
        assert_eq!(b.provider, Provider::Ollama);
        assert_eq!(b.model, None);
        assert_eq!(b.resolved_model(), DEFAULT_OLLAMA_MODEL);
    }

    #[test]
    fn provider_lowercase_tokens() {
        assert_eq!(
            serde_json::to_string(&Provider::Anthropic).unwrap(),
            r#""anthropic""#
        );
        assert_eq!(
            serde_json::to_string(&Provider::Ollama).unwrap(),
            r#""ollama""#
        );
        assert_eq!(
            serde_json::to_string(&Provider::Openai).unwrap(),
            r#""openai""#
        );
    }

    // ----- Ollama request construction + response parsing (offline) -----

    #[test]
    fn ollama_request_body_is_temperature_zero_json_forced_and_non_streaming() {
        let body = ollama_request_body(&neutral_req());
        assert_eq!(body["model"], "test-model");
        assert_eq!(body["stream"], serde_json::json!(false));
        assert_eq!(body["options"]["temperature"], serde_json::json!(0.0));
        // The closed structured-output schema is passed through as Ollama's `format`.
        assert_eq!(
            body["format"]["additionalProperties"],
            serde_json::json!(false)
        );
        // System rules + fenced user content map to the chat messages.
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][0]["content"], "SYSTEM RULES");
        assert_eq!(body["messages"][1]["role"], "user");
        assert!(body["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("UNTRUSTED"));
    }

    #[test]
    fn ollama_response_parses_into_canonical_verdict() {
        let raw = serde_json::json!({
            "model": "test-model",
            "message": {
                "role": "assistant",
                "content": "{\"verdict\":\"Human\",\"confidence\":\"High\",\"reasons\":\"ok\"}"
            },
            "done": true
        });
        let resp = ollama_parse_response(&raw).unwrap();
        let sv = resp.structured_verdict().unwrap();
        assert_eq!(sv.verdict, crate::VerdictTag::Human);
        assert_eq!(sv.confidence, crate::ConfidenceTag::High);
    }

    #[test]
    fn ollama_missing_content_is_a_deterministic_decode_abort() {
        let raw = serde_json::json!({ "done": true });
        assert!(matches!(
            ollama_parse_response(&raw),
            Err(OracleError::Decode(_))
        ));
    }

    // ----- OpenAI-compatible request construction + response parsing (offline) -----

    #[test]
    fn openai_request_body_is_temperature_zero_strict_json_schema() {
        let body = openai_request_body(&neutral_req());
        assert_eq!(body["model"], "test-model");
        assert_eq!(body["temperature"], serde_json::json!(0.0));
        assert_eq!(body["response_format"]["type"], "json_schema");
        assert_eq!(
            body["response_format"]["json_schema"]["strict"],
            serde_json::json!(true)
        );
        assert_eq!(
            body["response_format"]["json_schema"]["schema"]["additionalProperties"],
            serde_json::json!(false)
        );
        assert_eq!(body["messages"][0]["role"], "system");
        assert_eq!(body["messages"][1]["role"], "user");
    }

    #[test]
    fn openai_response_parses_into_canonical_verdict() {
        let raw = serde_json::json!({
            "choices": [{
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": "{\"verdict\":\"Sybil\",\"confidence\":\"Med\",\"reasons\":\"farm\"}"
                }
            }]
        });
        let resp = openai_parse_response(&raw).unwrap();
        let sv = resp.structured_verdict().unwrap();
        assert_eq!(sv.verdict, crate::VerdictTag::Sybil);
    }

    #[test]
    fn openai_missing_choice_content_is_a_deterministic_decode_abort() {
        let raw = serde_json::json!({ "choices": [] });
        assert!(matches!(
            openai_parse_response(&raw),
            Err(OracleError::Decode(_))
        ));
    }

    // ----- the three backends produce the SAME canonical verdict from the same reply -----

    #[test]
    fn all_three_backends_yield_identical_canonical_verdict() {
        // Same structured JSON delivered in each provider's reply envelope ⇒ identical CanonicalVerdict
        // (the determinism discipline is provider-independent; only the envelope differs).
        let json = "{\"verdict\":\"Human\",\"confidence\":\"High\",\"reasons\":\"coherent\"}";

        let anthropic = MessagesResponse::from_text(json)
            .structured_verdict()
            .unwrap()
            .to_canonical();
        let ollama = ollama_parse_response(&serde_json::json!({
            "message": { "role": "assistant", "content": json }
        }))
        .unwrap()
        .structured_verdict()
        .unwrap()
        .to_canonical();
        let openai = openai_parse_response(&serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": json } }]
        }))
        .unwrap()
        .structured_verdict()
        .unwrap()
        .to_canonical();

        let expected = CanonicalVerdict {
            verdict: Verdict::Human,
            confidence: Confidence::High,
            reasons_hash: crate::schema::reasons_hash("coherent"),
        };
        assert_eq!(anthropic, expected);
        assert_eq!(ollama, expected);
        assert_eq!(openai, expected);
        // And they group in a quorum across providers (same effect_hash semantics).
        assert!(anthropic.quorum_eq(&ollama));
        assert!(ollama.quorum_eq(&openai));
    }

    #[test]
    fn construct_oracle_and_interpreter_for_each_provider_without_network() {
        // Ollama / OpenAI transports are constructible without env (key optional / unused); Anthropic
        // requires a key, so we only assert that the missing-key path is a clean fallback signal.
        // We never call `.send()` here — no network is touched.
        let ollama = Backend::new(Provider::Ollama);
        assert!(ollama.humanity_oracle().is_ok());
        assert!(ollama.contract_interpreter().is_ok());

        // Anthropic with no key set ⇒ MissingApiKey (the node falls back to Mock).
        std::env::remove_var("ANTHROPIC_API_KEY");
        let anthropic = Backend::new(Provider::Anthropic);
        assert!(matches!(
            anthropic.humanity_oracle().err(),
            Some(OracleError::MissingApiKey)
        ));
    }
}
