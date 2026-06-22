//! The canonical **effect** structured-output schema (M4) and its **deterministic, total** mapping to
//! the runtime [`CanonicalEffect`].
//!
//! This is the M4 analogue of [`crate::schema`]: the load-bearing determinism boundary (invariant I1)
//! for prompt-contract interpretation. The model is grammar-constrained to emit *exactly* a closed
//! ordered list of typed ops — never prose, never code, never a free action — and we map that list to
//! the runtime's [`CanonicalEffect`] (whose `effect_hash` is the quorum-equality key) with **no free
//! choices**:
//!
//!   * the op set is a **closed enum** (`op` discriminator over the 6 canonical variants); the model
//!     cannot invent a 7th op or smuggle a field (`additionalProperties:false` everywhere);
//!   * every numeric field is parsed by a **pure, total** decoder (decimal `u128`/`u64`, `0x`-hex
//!     20-byte address, `0x`-hex 32-byte word). An unparseable / out-of-range / wrong-length value is a
//!     **hard error**, never a silent guess — which the interpreter turns into a deterministic `Abort`
//!     (I4 fail-closed). No defaulting, no truncation, no fuzzy parsing;
//!   * **op order is preserved** exactly as emitted: the canonical encoding (and thus `effect_hash`) is
//!     order-sensitive, so two honest, temperature-0 interpreters on identical input emit the identical
//!     ordered list and therefore the identical effect — they group in the quorum tally.
//!
//! The result is byte-for-byte compatible with the runtime's own canonical encoding
//! ([`CanonicalEffect::encode`] / its FNV-1a `effect_hash`): we build runtime [`Op`] values and call
//! [`CanonicalEffect::new`], so live-interpreter effects group with a `MockInterpreter`'s identical ops.

use serde::{Deserialize, Serialize};
use ubi2_runtime::{Address, CanonicalEffect, Op};

/// Why decoding a single structured op into a runtime [`Op`] failed. Every variant is a **deterministic
/// abort** signal — the interpreter maps any of these to an `Abort` effect (I4), never a guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EffectDecodeError {
    /// A `u128` amount field was not a base-10 integer in range.
    BadAmount(String),
    /// A `u64` stream-id field was not a base-10 integer in range.
    BadStreamId(String),
    /// A `0x`-hex address was malformed or not exactly 20 bytes.
    BadAddress(String),
    /// A `0x`-hex 32-byte word (key/value/reason_hash) was malformed or not exactly 32 bytes.
    BadWord(String),
}

impl std::fmt::Display for EffectDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EffectDecodeError::BadAmount(s) => write!(f, "malformed u128 amount: {s}"),
            EffectDecodeError::BadStreamId(s) => write!(f, "malformed u64 stream id: {s}"),
            EffectDecodeError::BadAddress(s) => write!(f, "malformed 20-byte address: {s}"),
            EffectDecodeError::BadWord(s) => write!(f, "malformed 32-byte word: {s}"),
        }
    }
}

impl std::error::Error for EffectDecodeError {}

/// The closed `op` discriminator — exactly the 6 canonical effect ops (spec D1). Serializes to the
/// stable lowercase token the schema lists, so the model picks one of a fixed set.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpTag {
    Transfer,
    Refund,
    OpenStream,
    StopStream,
    SetVar,
    Abort,
}

/// One structured op as the model emits it: a discriminated record. Numeric fields are **strings**
/// (decimal) so `u128`/`u64` survive JSON without precision loss; addresses/words are `0x`-hex strings.
/// All payload fields are optional in the wire shape (only the ones the `op` needs are read); a missing
/// required field for the chosen `op` is a decode error (fail-closed), never a default value.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredOp {
    /// Which canonical op this is.
    pub op: OpTag,
    /// `Transfer.to` / `OpenStream.to` recipient (`0x`-hex 20-byte).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to: Option<String>,
    /// `Refund.party` — must be a declared party (authority enforced by the runtime, not here).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub party: Option<String>,
    /// `Transfer.amount` / `Refund.amount` — base units, decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    /// `OpenStream.rate` — base units/sec, decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<String>,
    /// `OpenStream.deposit` — base units, decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deposit: Option<String>,
    /// `StopStream.id` — stream id, decimal string.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// `SetVar.key` — `0x`-hex 32-byte word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    /// `SetVar.value` — `0x`-hex 32-byte word.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// `Abort.reason_hash` — `0x`-hex 32-byte commitment to the off-chain abort reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_hash: Option<String>,
}

/// The top-level structured output the model is constrained to: an **ordered** list of canonical ops.
/// Empty = a quorum-agreed no-op. There is no free-text field on the wire shape — reasoning, if any,
/// lives off-chain and never enters the effect (I1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StructuredEffect {
    /// The ordered ops (order is preserved into the canonical encoding).
    pub ops: Vec<StructuredOp>,
}

impl StructuredEffect {
    /// Deterministically project the structured effect onto the runtime [`CanonicalEffect`], preserving
    /// op order. Total + pure: identical `StructuredEffect` ⇒ byte-identical `CanonicalEffect` (incl.
    /// `effect_hash`). Any malformed/missing field is a hard [`EffectDecodeError`] (the interpreter then
    /// fails closed to an `Abort`) — never a default or a guess.
    pub fn to_canonical(&self) -> Result<CanonicalEffect, EffectDecodeError> {
        let mut ops = Vec::with_capacity(self.ops.len());
        for so in &self.ops {
            ops.push(so.to_op()?);
        }
        Ok(CanonicalEffect::new(ops))
    }
}

impl StructuredOp {
    /// Decode one structured op into a runtime [`Op`]. The `op` tag selects which fields are read; a
    /// required field that is absent or malformed is a decode error. Pure + total.
    fn to_op(&self) -> Result<Op, EffectDecodeError> {
        match self.op {
            OpTag::Transfer => Ok(Op::Transfer {
                to: addr(self.to.as_deref())?,
                amount: u128_dec(self.amount.as_deref())?,
            }),
            OpTag::Refund => Ok(Op::Refund {
                party: addr(self.party.as_deref())?,
                amount: u128_dec(self.amount.as_deref())?,
            }),
            OpTag::OpenStream => Ok(Op::OpenStream {
                to: addr(self.to.as_deref())?,
                rate: u128_dec(self.rate.as_deref())?,
                deposit: u128_dec(self.deposit.as_deref())?,
            }),
            OpTag::StopStream => Ok(Op::StopStream {
                id: u64_dec(self.id.as_deref())?,
            }),
            OpTag::SetVar => Ok(Op::SetVar {
                key: word(self.key.as_deref())?,
                value: word(self.value.as_deref())?,
            }),
            OpTag::Abort => Ok(Op::Abort {
                reason_hash: word(self.reason_hash.as_deref())?,
            }),
        }
    }
}

/// Parse a required decimal `u128` (base units). Missing/empty/out-of-range/non-numeric ⇒ error.
fn u128_dec(s: Option<&str>) -> Result<u128, EffectDecodeError> {
    let s = s.unwrap_or("").trim();
    s.parse::<u128>()
        .map_err(|_| EffectDecodeError::BadAmount(s.to_string()))
}

/// Parse a required decimal `u64` (stream id). Missing/empty/out-of-range/non-numeric ⇒ error.
fn u64_dec(s: Option<&str>) -> Result<u64, EffectDecodeError> {
    let s = s.unwrap_or("").trim();
    s.parse::<u64>()
        .map_err(|_| EffectDecodeError::BadStreamId(s.to_string()))
}

/// Parse a required `0x`-prefixed (optional) 20-byte hex address. Exactly 20 bytes required.
fn addr(s: Option<&str>) -> Result<Address, EffectDecodeError> {
    let raw = s.unwrap_or("");
    let bytes = hex_bytes(raw).ok_or_else(|| EffectDecodeError::BadAddress(raw.to_string()))?;
    if bytes.len() != 20 {
        return Err(EffectDecodeError::BadAddress(raw.to_string()));
    }
    let mut a = [0u8; 20];
    a.copy_from_slice(&bytes);
    Ok(a)
}

/// Parse a required `0x`-prefixed (optional) 32-byte hex word (key/value/reason_hash). Exactly 32 bytes.
fn word(s: Option<&str>) -> Result<[u8; 32], EffectDecodeError> {
    let raw = s.unwrap_or("");
    let bytes = hex_bytes(raw).ok_or_else(|| EffectDecodeError::BadWord(raw.to_string()))?;
    if bytes.len() != 32 {
        return Err(EffectDecodeError::BadWord(raw.to_string()));
    }
    let mut w = [0u8; 32];
    w.copy_from_slice(&bytes);
    Ok(w)
}

/// Decode a hex string with an optional `0x`/`0X` prefix into bytes. Returns `None` on any non-hex
/// nibble or an odd length. Pure + total; lowercase/uppercase both accepted (the encoding is
/// case-insensitive, but the *decoded bytes* are canonical, so the effect hash is unaffected).
fn hex_bytes(s: &str) -> Option<Vec<u8>> {
    let h = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    if h.is_empty() || !h.len().is_multiple_of(2) {
        return None;
    }
    let mut out = Vec::with_capacity(h.len() / 2);
    let bytes = h.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = (bytes[i] as char).to_digit(16)?;
        let lo = (bytes[i + 1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
        i += 2;
    }
    Some(out)
}

/// The JSON-schema handed to the Anthropic structured-output API for **effect** interpretation. The
/// model's generation is grammar-constrained to this shape: a top-level `{ ops: [ <op> ] }` where each
/// `<op>` is a closed discriminated record over the 6 canonical variants. `additionalProperties:false`
/// at every level + the closed `op` enum = the model cannot emit a 7th op, an extra field, prose, or a
/// free action. Numeric fields are decimal strings (so `u128`/`u64` survive JSON exactly);
/// addresses/words are `0x`-hex strings with a length-bounded pattern.
///
/// Note: the JSON-schema enforces the *shape*; the strict byte/range checks live in [`StructuredEffect::
/// to_canonical`], so even a schema-lenient backend can never produce an out-of-range effect — it fails
/// closed to an `Abort` instead.
pub fn effect_json_schema() -> serde_json::Value {
    // A `oneOf` of the 6 closed op records. Each requires only its own fields and forbids extras.
    let addr_pat = "^0x[0-9a-fA-F]{40}$";
    let word_pat = "^0x[0-9a-fA-F]{64}$";
    let uint_pat = "^[0-9]+$";
    let op = serde_json::json!({
        "oneOf": [
            {
                "type": "object",
                "properties": {
                    "op": { "const": "transfer" },
                    "to": { "type": "string", "pattern": addr_pat },
                    "amount": { "type": "string", "pattern": uint_pat }
                },
                "required": ["op", "to", "amount"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "op": { "const": "refund" },
                    "party": { "type": "string", "pattern": addr_pat },
                    "amount": { "type": "string", "pattern": uint_pat }
                },
                "required": ["op", "party", "amount"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "op": { "const": "open_stream" },
                    "to": { "type": "string", "pattern": addr_pat },
                    "rate": { "type": "string", "pattern": uint_pat },
                    "deposit": { "type": "string", "pattern": uint_pat }
                },
                "required": ["op", "to", "rate", "deposit"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "op": { "const": "stop_stream" },
                    "id": { "type": "string", "pattern": uint_pat }
                },
                "required": ["op", "id"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "op": { "const": "set_var" },
                    "key": { "type": "string", "pattern": word_pat },
                    "value": { "type": "string", "pattern": word_pat }
                },
                "required": ["op", "key", "value"],
                "additionalProperties": false
            },
            {
                "type": "object",
                "properties": {
                    "op": { "const": "abort" },
                    "reason_hash": { "type": "string", "pattern": word_pat }
                },
                "required": ["op", "reason_hash"],
                "additionalProperties": false
            }
        ]
    });
    serde_json::json!({
        "type": "object",
        "properties": {
            "ops": {
                "type": "array",
                "description": "The ordered canonical effect: a bounded list of typed state-delta ops. Empty = no-op. Emit ONLY ops the contract's plain-language intent authorizes; otherwise emit a single abort op.",
                "items": op
            }
        },
        "required": ["ops"],
        "additionalProperties": false
    })
}

/// The structured-output name the effect schema is keyed under (pinned + stable).
pub const EFFECT_OUTPUT_NAME: &str = "contract_effect";

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: serde_json::Value) -> StructuredEffect {
        serde_json::from_value(v).expect("valid structured effect")
    }

    #[test]
    fn transfer_decodes_to_runtime_op_with_matching_hash() {
        let payee = format!("0x{}", "02".repeat(20));
        let eff = s(serde_json::json!({
            "ops": [{ "op": "transfer", "to": payee, "amount": "5000000000000000000" }]
        }));
        let canon = eff.to_canonical().unwrap();
        // Byte-for-byte identical to the runtime building the same Op (the whole point — they group).
        let expected = CanonicalEffect::new(vec![Op::Transfer {
            to: [2u8; 20],
            amount: 5_000_000_000_000_000_000u128,
        }]);
        assert_eq!(canon, expected);
        assert_eq!(canon.effect_hash, expected.effect_hash);
    }

    #[test]
    fn all_six_ops_round_trip_deterministically() {
        let a = format!("0x{}", "07".repeat(20));
        let w1 = format!("0x{}", "11".repeat(32));
        let w2 = format!("0x{}", "22".repeat(32));
        let rh = format!("0x{}", "ab".repeat(32));
        let eff = s(serde_json::json!({ "ops": [
            { "op": "transfer", "to": a, "amount": "1" },
            { "op": "refund", "party": a, "amount": "2" },
            { "op": "open_stream", "to": a, "rate": "1", "deposit": "3600" },
            { "op": "stop_stream", "id": "9" },
            { "op": "set_var", "key": w1, "value": w2 },
            { "op": "abort", "reason_hash": rh },
        ]}));
        let canon = eff.to_canonical().unwrap();
        assert_eq!(canon.ops.len(), 6);
        assert_eq!(canon, eff.to_canonical().unwrap(), "pure + deterministic");
        // Order is preserved into the hash: reversing changes the effect.
        let mut rev = eff.clone();
        rev.ops.reverse();
        assert_ne!(canon.effect_hash, rev.to_canonical().unwrap().effect_hash);
    }

    #[test]
    fn empty_ops_is_the_noop_effect() {
        let eff = s(serde_json::json!({ "ops": [] }));
        assert_eq!(eff.to_canonical().unwrap(), CanonicalEffect::noop());
    }

    #[test]
    fn malformed_fields_are_hard_errors_not_guesses() {
        // Out-of-range u128.
        let big = "340282366920938463463374607431768211456"; // u128::MAX + 1
        let e = s(
            serde_json::json!({ "ops": [{ "op": "transfer", "to": format!("0x{}", "01".repeat(20)), "amount": big }]}),
        );
        assert!(matches!(
            e.to_canonical(),
            Err(EffectDecodeError::BadAmount(_))
        ));
        // Wrong-length address (19 bytes).
        let e = s(
            serde_json::json!({ "ops": [{ "op": "transfer", "to": format!("0x{}", "01".repeat(19)), "amount": "1" }]}),
        );
        assert!(matches!(
            e.to_canonical(),
            Err(EffectDecodeError::BadAddress(_))
        ));
        // Wrong-length word (31 bytes).
        let e = s(
            serde_json::json!({ "ops": [{ "op": "set_var", "key": format!("0x{}", "01".repeat(31)), "value": format!("0x{}", "02".repeat(32)) }]}),
        );
        assert!(matches!(
            e.to_canonical(),
            Err(EffectDecodeError::BadWord(_))
        ));
        // Non-numeric stream id.
        let e = s(serde_json::json!({ "ops": [{ "op": "stop_stream", "id": "soon" }]}));
        assert!(matches!(
            e.to_canonical(),
            Err(EffectDecodeError::BadStreamId(_))
        ));
    }

    #[test]
    fn hex_is_case_insensitive_but_bytes_are_canonical() {
        let lower = format!("0x{}", "ab".repeat(20));
        let upper = format!("0x{}", "AB".repeat(20));
        let lo = s(serde_json::json!({ "ops": [{ "op": "transfer", "to": lower, "amount": "1" }]}));
        let up = s(serde_json::json!({ "ops": [{ "op": "transfer", "to": upper, "amount": "1" }]}));
        // Same bytes ⇒ same hash regardless of input case (so interpreters never split on casing).
        assert_eq!(
            lo.to_canonical().unwrap().effect_hash,
            up.to_canonical().unwrap().effect_hash
        );
    }

    #[test]
    fn schema_is_closed_at_top_and_per_op() {
        let s = effect_json_schema();
        assert_eq!(s["additionalProperties"], serde_json::json!(false));
        assert_eq!(s["properties"]["ops"]["type"], serde_json::json!("array"));
        let variants = s["properties"]["ops"]["items"]["oneOf"].as_array().unwrap();
        assert_eq!(variants.len(), 6, "exactly the 6 canonical ops");
        for v in variants {
            assert_eq!(v["additionalProperties"], serde_json::json!(false));
        }
    }
}
