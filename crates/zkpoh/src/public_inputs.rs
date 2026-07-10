//! The canonical public-input vector (spec §3.5) — the wire contract between the off-chain prover and
//! the on-chain verifier.
//!
//! The proof's public inputs are pinned in a **fixed canonical order**. Changing the order or contents
//! is a *new circuit + a new verifying key* (and a state-root version bump), never a silent break — the
//! same discipline M5 applies to its wire formats.
//!
//! ```text
//! public_inputs = [
//!   nullifier,                  // 32-byte field element                          (§3.3)
//!   attr_commit[0],             // Pedersen commitment: age threshold             (§3.4 idx 0)
//!   attr_commit[1],             // Pedersen commitment: nationality bucket        (§3.4 idx 1)
//!   attr_commit[2],             // Pedersen commitment: document expiry           (§3.4 idx 2)
//!   csca_registry_root,         // 32-byte commitment to the trusted CSCA set     (§7.2)
//!   submitter_address,          // 20-byte address, zero-extended to 32 — anti-replay binding (§3.3)
//!   now_epoch,                  // chain-supplied "current time" (block ts) the not-expired check used
//!   passport_scheme_tag,        // 1-byte document-type/scheme discriminant — forward-compat (§2.4)
//! ]
//! ```
//!
//! Each entry is a single BN254 scalar-field element. The runtime re-derives `csca_registry_root`,
//! `submitter_address`, and `now_epoch` from on-chain state + the tx + the block and rejects on
//! mismatch (the fail-closed binding that prevents replay and trust-anchor confusion). This crate only
//! *consumes* the assembled vector; it does not know what those values mean — it converts them to field
//! elements in this exact order and feeds them to the pairing check.

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::self_layout::SELF_NPUBLIC;

/// The full Self `vc_and_disclose` public-signal vector as raw 32-byte big-endian values, ready for the
/// single canonical field mapping (spec 06b §4.3). Built from [`ubi2_runtime::ZkPublicInputs`] — the raw
/// 21-signal vector the runtime carries on-chain — and mapped to `[Fr; 21]` by
/// [`PublicInputs::to_field_elements`]. There is exactly one mapping, so two nodes that assemble the same
/// bytes produce the same field vector and therefore the same verify result (I1/I2). **No adapter, no
/// zeroing** (the Stage-A/B mistake): every live signal is consumed verbatim.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    /// The raw 21-element public vector (snarkjs order, §4.1), each a 32-byte big-endian field value.
    pub signals: [[u8; 32]; SELF_NPUBLIC],
}

impl PublicInputs {
    /// Wrap the raw 21-signal vector.
    pub fn new(signals: [[u8; 32]; SELF_NPUBLIC]) -> Self {
        Self { signals }
    }

    /// Build from the runtime's plain-bytes [`ubi2_runtime::ZkPublicInputs`] (the on-chain wire shape).
    /// The runtime owns the *meaning* (it binds the policy slots by index); this crate owns the
    /// *field-element mapping*. The single seam — a pure, field-for-field copy.
    pub fn from_runtime(pi: &ubi2_runtime::ZkPublicInputs) -> Self {
        Self {
            signals: pi.signals,
        }
    }

    /// Convert to the ordered `[Fr; 21]` vector the Groth16 verifier consumes (spec 06b §4.1 order). The
    /// **single canonical mapping** whose determinism makes the whole verify reproducible across nodes.
    ///
    /// `Fr::from_be_bytes_mod_order` reduces each 32-byte value modulo the scalar order `r`; a genuine
    /// proof's public signals are already canonical (< r). The runtime's nullifier canonicality guard
    /// (§4.4) rejects the one slot whose raw bytes double as a registry key, so the `N, N+r, …` family
    /// cannot mint duplicate humans.
    pub fn to_field_elements(&self) -> [Fr; SELF_NPUBLIC] {
        let mut out = [Fr::from(0u64); SELF_NPUBLIC];
        for (o, s) in out.iter_mut().zip(self.signals.iter()) {
            *o = Fr::from_be_bytes_mod_order(s);
        }
        out
    }
}

/// Map a 20-byte address to a BN254 scalar by big-endian zero-extension (spec §3.5: "the 20-byte
/// address (zero-extended)"). `20 * 8 = 160 bits` is far below the ~254-bit field, so the mapping is
/// injective (no modular wrap) — distinct addresses are distinct field elements, preserving the
/// anti-replay binding.
pub fn address_to_field(addr: &[u8; 20]) -> Fr {
    let mut be = [0u8; 32];
    be[12..].copy_from_slice(addr);
    Fr::from_be_bytes_mod_order(&be)
}

/// Map a raw 32-byte value (an on-chain `bytes32`, e.g. a stored attribute commitment) to a BN254
/// scalar by big-endian reduction modulo the field order. The single canonical mapping the attribute
/// verifier uses for its one public input (the stored commitment, §4.4).
pub fn address_to_field32(value: &[u8; 32]) -> Fr {
    Fr::from_be_bytes_mod_order(value)
}

/// The attribute kinds a [`crate::ZkPassportVerifier::verify_attribute`] proof can be about (spec §4.4).
/// M6 ships only `Over18`; the enum is the forward-compatible discriminant M7 extends (nationality
/// bucket, expiry gate) — exactly the `scheme_tag` forward-compat pattern (§2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttrType {
    /// Proves `attr_commit[0]` opens to a `born_before_epoch ≤ now − 18y` (DOB never revealed).
    Over18,
}

impl AttrType {
    /// The on-chain `attributeType` selector (`keccak256("over18")` etc.) — kept as a stable tag so the
    /// `eth_call` surface (`verifyAttribute(subject, attributeType, attrProof)`) decodes to this enum.
    /// M6 only knows `Over18`; an unknown tag fails closed at the call site.
    pub fn as_str(&self) -> &'static str {
        match self {
            AttrType::Over18 => "over18",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_vector_order_is_canonical_and_stable() {
        let mut signals = [[0u8; 32]; SELF_NPUBLIC];
        for (i, s) in signals.iter_mut().enumerate() {
            s[31] = i as u8;
        }
        let pi = PublicInputs::new(signals);
        let a = pi.to_field_elements();
        let b = pi.to_field_elements();
        assert_eq!(a, b, "the field mapping is a pure function");
        assert_eq!(a.len(), SELF_NPUBLIC);
        // Each signal maps to its integer value under the canonical BE reduction.
        for (i, fr) in a.iter().enumerate() {
            assert_eq!(*fr, Fr::from(i as u64));
        }
    }

    #[test]
    fn distinct_addresses_are_distinct_field_elements() {
        let mut a = [0u8; 20];
        let mut b = [0u8; 20];
        a[19] = 1;
        b[19] = 2;
        assert_ne!(address_to_field(&a), address_to_field(&b));
        // Zero-extension: the top 96 bits are zero, so the value equals the low 160 bits — injective.
        assert_eq!(address_to_field(&[0u8; 20]), Fr::from(0u64));
    }

    #[test]
    fn attr_type_tag_is_stable() {
        assert_eq!(AttrType::Over18.as_str(), "over18");
    }
}
