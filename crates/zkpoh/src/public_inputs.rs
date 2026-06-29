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

/// The number of public inputs in the M6 passport-proof statement (spec §3.5). Pinned: the verifying
/// key encodes this arity, so a mismatch is a hard reject.
pub const NUM_PUBLIC_INPUTS: usize = 8;

/// Index of `nullifier` in the canonical vector.
pub const IDX_NULLIFIER: usize = 0;
/// Index of `attr_commit[0]` (age-threshold commitment).
pub const IDX_ATTR_AGE: usize = 1;
/// Index of `attr_commit[1]` (nationality-bucket commitment).
pub const IDX_ATTR_NATIONALITY: usize = 2;
/// Index of `attr_commit[2]` (document-expiry commitment).
pub const IDX_ATTR_EXPIRY: usize = 3;
/// Index of `csca_registry_root`.
pub const IDX_CSCA_ROOT: usize = 4;
/// Index of `submitter_address` (zero-extended).
pub const IDX_SUBMITTER: usize = 5;
/// Index of `now_epoch`.
pub const IDX_NOW_EPOCH: usize = 6;
/// Index of `passport_scheme_tag` (zero-extended).
pub const IDX_SCHEME_TAG: usize = 7;

/// The canonical, ordered public-input vector for `submitZkPassportProof` (spec §3.5).
///
/// Every field is stored as a raw **32-byte big-endian** value (the on-chain `bytes32` / address /
/// `uint64` representation the HumanityHub op carries). Conversion to BN254 field elements is done once,
/// deterministically, in [`PublicInputs::to_field_elements`] — there is exactly one mapping, so two
/// nodes that assemble the same bytes produce the same field vector and therefore the same verify
/// result (I1/I2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicInputs {
    /// `nullifier` — 32-byte field element (§3.3).
    pub nullifier: [u8; 32],
    /// The three Pedersen attribute commitments in fixed order: `[age, nationality, expiry]` (§3.4).
    pub attribute_commitments: [[u8; 32]; 3],
    /// `csca_registry_root` — commitment to the trusted CSCA set the proof verifies against (§7.2).
    pub csca_registry_root: [u8; 32],
    /// `submitter_address` — the 20-byte address, zero-extended to 32, the proof is bound to (§3.3).
    pub submitter_address: [u8; 20],
    /// `now_epoch` — the chain-supplied current time (the block timestamp) the not-expired check used.
    pub now_epoch: u64,
    /// `passport_scheme_tag` — 1-byte document-type/scheme discriminant (§2.4).
    pub scheme_tag: u8,
}

impl PublicInputs {
    /// Assemble the canonical vector from its on-chain components (the shape `crates/runtime` hands the
    /// verifier after re-deriving the bound fields). Pure: no clock, no allocation beyond the struct.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        nullifier: [u8; 32],
        attribute_commitments: [[u8; 32]; 3],
        csca_registry_root: [u8; 32],
        submitter_address: [u8; 20],
        now_epoch: u64,
        scheme_tag: u8,
    ) -> Self {
        Self {
            nullifier,
            attribute_commitments,
            csca_registry_root,
            submitter_address,
            now_epoch,
            scheme_tag,
        }
    }

    /// Build this crate's field-mapping struct from the runtime's plain-bytes
    /// [`ubi2_runtime::ZkPublicInputs`] (the wire shape the runtime assembles + binds, §4.2). A pure,
    /// field-for-field copy: the runtime owns the *meaning* (it re-derives + binds `csca_registry_root`,
    /// `submitter_address`, `now_epoch`); this crate owns the *field-element mapping*. The single seam.
    pub fn from_runtime(pi: &ubi2_runtime::ZkPublicInputs) -> Self {
        Self {
            nullifier: pi.nullifier,
            attribute_commitments: pi.attribute_commitments,
            csca_registry_root: pi.csca_registry_root,
            submitter_address: pi.submitter_address,
            now_epoch: pi.now_epoch,
            scheme_tag: pi.scheme_tag,
        }
    }

    /// Convert to the ordered BN254 scalar-field vector the Groth16 verifier consumes (spec §3.5
    /// order). This is the **single canonical mapping**; it is the function whose determinism makes the
    /// whole verify reproducible across nodes.
    ///
    /// `Fr::from_be_bytes_mod_order` reduces each 32-byte value modulo the scalar field order `r`. A
    /// 32-byte value `≥ r` is folded into the field — the off-chain prover therefore commits to the
    /// *reduced* value, and the runtime must reject any field that does not round-trip (a malleability
    /// guard the caller enforces; documented as a binding obligation here so it is not lost).
    pub fn to_field_elements(&self) -> [Fr; NUM_PUBLIC_INPUTS] {
        let mut out = [Fr::from(0u64); NUM_PUBLIC_INPUTS];
        out[IDX_NULLIFIER] = Fr::from_be_bytes_mod_order(&self.nullifier);
        out[IDX_ATTR_AGE] = Fr::from_be_bytes_mod_order(&self.attribute_commitments[0]);
        out[IDX_ATTR_NATIONALITY] = Fr::from_be_bytes_mod_order(&self.attribute_commitments[1]);
        out[IDX_ATTR_EXPIRY] = Fr::from_be_bytes_mod_order(&self.attribute_commitments[2]);
        out[IDX_CSCA_ROOT] = Fr::from_be_bytes_mod_order(&self.csca_registry_root);
        // The 20-byte address is zero-extended to a field element (big-endian, left-padded by `from`).
        out[IDX_SUBMITTER] = address_to_field(&self.submitter_address);
        out[IDX_NOW_EPOCH] = Fr::from(self.now_epoch);
        out[IDX_SCHEME_TAG] = Fr::from(self.scheme_tag as u64);
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
        let pi = PublicInputs::new(
            [1u8; 32],
            [[2u8; 32], [3u8; 32], [4u8; 32]],
            [5u8; 32],
            [6u8; 20],
            1_700_000_000,
            0,
        );
        let a = pi.to_field_elements();
        let b = pi.to_field_elements();
        assert_eq!(a, b, "the field mapping is a pure function");
        assert_eq!(a.len(), NUM_PUBLIC_INPUTS);
        // now_epoch and scheme_tag map through the integer `From` impls.
        assert_eq!(a[IDX_NOW_EPOCH], Fr::from(1_700_000_000u64));
        assert_eq!(a[IDX_SCHEME_TAG], Fr::from(0u64));
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
