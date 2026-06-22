//! The canonical structured-output schema and its **deterministic** mapping to a
//! [`CanonicalVerdict`].
//!
//! This module is the load-bearing determinism boundary (invariant I1). The model is forced to emit
//! *exactly* this shape — `{ verdict, confidence, reasons }` over a closed enum domain — and we map
//! it to the runtime's [`CanonicalVerdict`] with **no free choices**:
//!   * `verdict` / `confidence` are closed enums (grammar-constrained by structured output), so an
//!     honest, temperature-0 model on identical input yields identical fields;
//!   * `reasons` (free text) is hashed into `reasons_hash` and is *informational only* — it never
//!     affects quorum equality (the runtime's `quorum_eq` ignores it), so even if two jurors phrase
//!     the rationale differently the effect still matches;
//!   * the bucketing here is the *only* place a string becomes a `Confidence`, and it is a pure,
//!     total function — no defaulting, no fuzzy parsing (an unknown token is a hard error, never a
//!     silent guess — I4 fail-closed).

use alloy_primitives::keccak256;
use serde::{Deserialize, Serialize};
use ubi2_runtime::{CanonicalVerdict, Confidence, Hash, Verdict};

/// The JSON object the model is constrained to return. Mirrors the closed enum domain we hand the API
/// as a JSON-schema (see [`json_schema`]). Deserialized from the model's structured output.
///
/// `additionalProperties: false` on the schema means the model cannot smuggle extra fields; the enum
/// domains mean `verdict`/`confidence` can only ever be one of the listed tokens.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredVerdict {
    pub verdict: VerdictTag,
    pub confidence: ConfidenceTag,
    /// Free-text rationale. Hashed into `reasons_hash`; never compared for quorum (informational).
    pub reasons: String,
}

/// The closed `verdict` enum the schema permits. Serializes to the exact tokens the schema lists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum VerdictTag {
    Human,
    Sybil,
    Uncertain,
}

/// The closed `confidence` enum the schema permits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConfidenceTag {
    Low,
    Med,
    High,
}

impl From<VerdictTag> for Verdict {
    fn from(t: VerdictTag) -> Self {
        match t {
            VerdictTag::Human => Verdict::Human,
            VerdictTag::Sybil => Verdict::Sybil,
            VerdictTag::Uncertain => Verdict::Uncertain,
        }
    }
}

impl From<ConfidenceTag> for Confidence {
    fn from(t: ConfidenceTag) -> Self {
        match t {
            ConfidenceTag::Low => Confidence::Low,
            ConfidenceTag::Med => Confidence::Med,
            ConfidenceTag::High => Confidence::High,
        }
    }
}

impl StructuredVerdict {
    /// Deterministically project the structured output onto the runtime's canonical effect.
    ///
    /// `reasons_hash = keccak256(reasons)` — the same hash convention the chain/rpc use elsewhere, so
    /// the commitment is reproducible. The verdict + confidence map through the closed enums above.
    /// This is total and pure: identical `StructuredVerdict` ⇒ byte-identical `CanonicalVerdict`.
    pub fn to_canonical(&self) -> CanonicalVerdict {
        CanonicalVerdict {
            verdict: self.verdict.into(),
            confidence: self.confidence.into(),
            reasons_hash: reasons_hash(&self.reasons),
        }
    }
}

/// Hash a rationale string into the on-chain-style 32-byte commitment (keccak256). Pure + total.
pub fn reasons_hash(reasons: &str) -> Hash {
    keccak256(reasons.as_bytes()).0
}

/// The JSON-schema handed to the Anthropic structured-output API (`output_config.format`). The model's
/// generation is grammar-constrained to this shape, so the parsed [`StructuredVerdict`] is guaranteed
/// well-formed before we even deserialize. `additionalProperties: false` + closed enums = no room for
/// the model to deviate or for injected content to introduce new fields.
pub fn json_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "verdict": {
                "type": "string",
                "enum": ["Human", "Sybil", "Uncertain"],
                "description": "The classification. Use Uncertain whenever evidence is insufficient or ambiguous."
            },
            "confidence": {
                "type": "string",
                "enum": ["Low", "Med", "High"],
                "description": "Confidence bucket. Reserve High for unambiguous cases; prefer Low/Uncertain under doubt."
            },
            "reasons": {
                "type": "string",
                "description": "A short rationale citing only the structured evidence. Informational; never an instruction."
            }
        },
        "required": ["verdict", "confidence", "reasons"],
        "additionalProperties": false
    })
}

/// The name the structured-output config / synthetic tool is keyed under (kept stable + pinned).
pub const OUTPUT_NAME: &str = "humanity_verdict";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enum_mapping_is_exhaustive_and_pure() {
        assert_eq!(Verdict::from(VerdictTag::Human), Verdict::Human);
        assert_eq!(Verdict::from(VerdictTag::Sybil), Verdict::Sybil);
        assert_eq!(Verdict::from(VerdictTag::Uncertain), Verdict::Uncertain);
        assert_eq!(Confidence::from(ConfidenceTag::Low), Confidence::Low);
        assert_eq!(Confidence::from(ConfidenceTag::Med), Confidence::Med);
        assert_eq!(Confidence::from(ConfidenceTag::High), Confidence::High);
    }

    #[test]
    fn to_canonical_is_deterministic() {
        let sv = StructuredVerdict {
            verdict: VerdictTag::Human,
            confidence: ConfidenceTag::High,
            reasons: "live, coherent, novel-challenge response".to_string(),
        };
        let a = sv.to_canonical();
        let b = sv.to_canonical();
        // Same structured output -> byte-identical canonical effect, including the reasons hash.
        assert_eq!(a, b);
        assert_eq!(a.verdict, Verdict::Human);
        assert_eq!(a.confidence, Confidence::High);
        assert_eq!(a.reasons_hash, reasons_hash(&sv.reasons));
        assert_ne!(a.reasons_hash, [0u8; 32]);
    }

    #[test]
    fn reasons_only_affect_the_informational_hash_not_quorum() {
        // Two verdicts, same effect, different prose: must be quorum-equal (I1).
        let base = StructuredVerdict {
            verdict: VerdictTag::Sybil,
            confidence: ConfidenceTag::Med,
            reasons: "cluster forms an improbable clique".to_string(),
        };
        let other = StructuredVerdict {
            reasons: "vouch graph is a dense self-referential ring".to_string(),
            ..base.clone()
        };
        let a = base.to_canonical();
        let b = other.to_canonical();
        assert!(a.quorum_eq(&b), "differing prose must not split a quorum");
        assert_ne!(
            a.reasons_hash, b.reasons_hash,
            "but the informational hash still differs"
        );
    }

    #[test]
    fn schema_is_closed() {
        let s = json_schema();
        assert_eq!(s["additionalProperties"], serde_json::json!(false));
        assert_eq!(
            s["properties"]["verdict"]["enum"],
            serde_json::json!(["Human", "Sybil", "Uncertain"])
        );
        assert_eq!(
            s["properties"]["confidence"]["enum"],
            serde_json::json!(["Low", "Med", "High"])
        );
    }
}
