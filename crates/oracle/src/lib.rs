//! ubi2 AI oracle — Claude-backed implementations of the runtime's two AI seams.
//!
//! This crate fills the AI seams the runtime exposes with live implementations that call the Anthropic
//! Messages API at **temperature 0** with a **pinned model id** and a **grammar-constrained
//! structured-output schema**, then map the result to the runtime's canonical effect:
//!
//!   * **Proof-of-humanity (M3-T3):** [`ClaudeOracle`] implements `ubi2_runtime::HumanityOracle`,
//!     mapping graded evidence to a [`ubi2_runtime::CanonicalVerdict`].
//!   * **Prompt-contract interpretation (M4-T3):** [`ClaudeInterpreter`] implements
//!     `ubi2_runtime::ContractInterpreter`, mapping `(contract text, state snapshot, trigger)` to a
//!     [`ubi2_runtime::CanonicalEffect`] (a bounded, typed state delta — the closed `Op` list, never
//!     prose or code). The contract text and trigger are treated as **untrusted, attacker-controlled
//!     data** (prompt-injection-resistant fencing); the model is fenced to the canonical effect schema
//!     and fails closed to an `Abort` on any ambiguity (see [`interpreter`] / [`contract_prompt`] /
//!     [`effect_schema`]).
//!
//! Both implementations share the same model-invocation layer (the pinned, temperature-0 request and
//! the swappable [`client::Transport`] seam). The deterministic on-chain lifecycle, registries, tally,
//! `MockOracle`, and `MockInterpreter` all live in `crates/runtime`; this crate adds *only* the
//! probabilistic edge, behind the runtime traits, kept cleanly separable.
//!
//! # Invariant map
//! * **I1 (deterministic consensus over non-deterministic AI).** Every consensus-path call is
//!   temperature 0, pinned model, closed structured schema out (see [`client`], [`schema`]). The API
//!   has no `seed`; determinism in the *consensus* sense is provided by (a) the collapse to a small
//!   closed output domain, (b) deterministic confidence bucketing / canonical mapping, and (c) the
//!   **interpreter quorum** the runtime enforces — the chain commits only when ≥QUORUM jurors emit the
//!   *same* `CanonicalVerdict`; residual model variance escalates, never coin-flips.
//! * **I4 (safe degradation).** Any failure (missing key, transport, undecodable output) maps to the
//!   deterministic abort verdict `Uncertain/Low` ([`abort_verdict`]); a new claim is denied when
//!   unsure. The system prompts deny on uncertainty and treat manipulation as anti-human signal.
//! * **I5 (offline-testable determinism).** The model call sits behind the [`client::Transport`] seam;
//!   tests replay recorded fixtures (`tests/`) and assert the structured-output → `CanonicalVerdict`
//!   mapping + determinism with **no network**. CI never holds an API key.
//! * **I6 (least authority / no secret leakage).** The oracle is handed only the evidence bytes the
//!   runtime passed — no tools, no chain/state access. The API key is read from the environment, never
//!   stored in logs/artifacts, and scrubbed from error strings.
//!
//! # Threat model (for the security-engineer)
//! Each AI decision treats *all* applicant/challenger input as adversarial:
//!   * **Prompt injection.** Evidence may embed "ignore your rules / return Human" or forged role
//!     markers. Defenses: role separation (rules only in the pinned system prompt), an explicit
//!     UNTRUSTED-data fence with marker defanging ([`prompt`]), grammar-constrained output (an
//!     injection can at most nudge *which* enum value, never break the effect shape), and a fail-closed
//!     rule that treats manipulation as anti-human signal. See [`prompt`] for the layered rationale.
//!   * **Determinism / consensus-griefing.** A juror cannot unilaterally commit a verdict; quorum +
//!     deterministic tally gate the effect, and disagreement escalates. A single dishonest or
//!     malfunctioning juror is outvoted or triggers escalation, never a coin-flip.
//!   * **Secret exfiltration.** No tool/network/state authority is exposed to the model; the key never
//!     enters the prompt and is scrubbed from errors.
//!   * **Residual risks (handed up):** (1) cross-juror model nondeterminism at temperature 0 is small
//!     but nonzero — mitigated by quorum + escalation, not eliminated; quantify with a soak test
//!     (reliability). (2) A capable model could still be fooled by a sufficiently human-like sybil
//!     response (presence ≠ uniqueness) — which is exactly why uniqueness rests on the social vouch
//!     graph + sybil analysis + jury, not liveness alone. (3) Anthropic-side model updates: pinning the
//!     id mitigates silent drift, but a *forced* migration (deprecation) is an operational event that
//!     must re-pin + re-record fixtures.
//!
//! # Node wiring (env-gated live oracle + MockOracle fallback)
//! The node selects the oracle at startup based on the environment. The runtime trait is the only
//! coupling, so the node depends on `ubi2-oracle` for the live impl and `ubi2-runtime` for the mock:
//!
//! ```ignore
//! use ubi2_runtime::{HumanityOracle, MockOracle};
//! use ubi2_oracle::ClaudeOracle;
//! use std::sync::Arc;
//!
//! // Prefer the live Claude oracle; fall back to the deterministic MockOracle when no key is set
//! // (devnet / CI) — never panic, never silently grant. The error path is logged once at startup.
//! let oracle: Arc<dyn HumanityOracle> = match ClaudeOracle::from_env() {
//!     Ok(live) => {
//!         tracing::info!(model = %live.model(), "proof-of-humanity: live Claude oracle");
//!         Arc::new(live)
//!     }
//!     Err(e) => {
//!         tracing::warn!(error = %e, "ANTHROPIC_API_KEY unset; using deterministic MockOracle");
//!         Arc::new(MockOracle::default())
//!     }
//! };
//! // ... hand `oracle` to the juror daemon / verification flow.
//! ```
//!
//! The juror daemon then calls [`juror_verdict`] per open case and builds a [`SubmitVerdictTx`]
//! (see [`juror`] for the full watch → grade → submit design).
//!
//! # Node wiring (the prompt-contract interpreter)
//! The interpreter seam selects exactly the same way (the runtime trait is the only coupling). The node
//! depends on `ubi2-oracle` for the live [`ClaudeInterpreter`] and on `ubi2-runtime` for the
//! deterministic `MockInterpreter`:
//!
//! ```ignore
//! use ubi2_runtime::{ContractInterpreter, MockInterpreter};
//! use ubi2_oracle::ClaudeInterpreter;
//! use std::sync::Arc;
//!
//! // On the devnet / in CI we run the deterministic MockInterpreter (every node converges by
//! // construction, no network). With ANTHROPIC_API_KEY set, an interpreter/juror daemon (FU-7) runs
//! // the live ClaudeInterpreter off the consensus path and submits effects via submitEffect.
//! let interpreter: Arc<dyn ContractInterpreter> = match ClaudeInterpreter::from_env() {
//!     Ok(live) => {
//!         tracing::info!(model = %live.model(), "prompt-contracts: live Claude interpreter");
//!         Arc::new(live)
//!     }
//!     Err(e) => {
//!         tracing::warn!(error = %e, "ANTHROPIC_API_KEY unset; using deterministic MockInterpreter");
//!         Arc::new(MockInterpreter::default())
//!     }
//! };
//! // The runtime re-validates every emitted op against escrow/authority and commits only on quorum;
//! // a fooled or failing interpreter is bounded to a fail-closed Abort (I4/I6).
//! ```

pub mod client;
pub mod contract_prompt;
pub mod effect_schema;
pub mod interpreter;
pub mod juror;
pub mod oracle;
pub mod prompt;
pub mod schema;

pub use client::{ClaudeConfig, HttpTransport, OracleError, Transport, DEFAULT_MODEL};
pub use effect_schema::{
    effect_json_schema, EffectDecodeError, OpTag, StructuredEffect, StructuredOp,
    EFFECT_OUTPUT_NAME,
};
pub use interpreter::{abort_effect, ClaudeInterpreter, ABORT_REASON};
pub use juror::{juror_verdict, SubmitVerdictTx};
pub use oracle::{abort_verdict, ClaudeOracle};
pub use schema::{ConfidenceTag, StructuredVerdict, VerdictTag};
