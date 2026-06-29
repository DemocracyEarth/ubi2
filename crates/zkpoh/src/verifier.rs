//! The `ZkPassportVerifier` implementations — the consensus crypto behind the runtime's seam.
//!
//! The [`ZkPassportVerifier`](ubi2_runtime::ZkPassportVerifier) trait now lives in `crates/runtime`
//! (dependency-free, ADR-0005 D2 / spec §6.1); this crate **implements** it — exactly as `ubi2-oracle`
//! implements `ubi2_runtime::HumanityOracle`. The runtime hands the impl a plain-bytes
//! [`ZkPublicInputs`](ubi2_runtime::ZkPublicInputs); this module converts it to the BN254 field-element
//! vector ([`PublicInputs`]) through the single canonical mapping and runs the pairing check.
//!
//! * [`Groth16Verifier`] — the real, pure, deterministic arkworks impl (the consensus crypto). Wired by
//!   `crates/node` from the genesis-pinned VK.
//!
//! * [`MockZkVerifier`] (re-export of `ubi2_runtime::MockZkVerifier`) — the scripted, deterministic
//!   verifier for CI / lifecycle tests (the I5 offline path). It is the impl the consensus path **ships
//!   on** for Stage B; the real `Groth16Verifier` wires by node config later.

use ark_groth16::Groth16;

use ubi2_runtime::{ZkAttrType, ZkPassportVerifier, ZkPublicInputs};

use crate::keys::{proof_from_canonical_bytes, PinnedVerifyingKey};
use crate::public_inputs::{AttrType, PublicInputs, NUM_PUBLIC_INPUTS};
use crate::self_layout::SELF_NPUBLIC;

/// Which public-input layout the pinned passport VK is sized for (chosen by its arity at load).
///
/// Stage 1 pinned the **domain** layout (`NUM_PUBLIC_INPUTS = 8`, spec §3.5). Stage 2 adds the **real**
/// Self / OpenPassport `vc_and_disclose` layout (`SELF_NPUBLIC = 20`): a proof generated against the real
/// circuit verifies with the runtime's domain inputs mapped onto the 20-signal vector by the documented
/// adapter ([`PublicInputs::to_self_field_elements`]). The verifier selects the mapping from the VK's
/// arity so the same code path serves both — fail-closed for any other arity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassportLayout {
    /// Our pinned 8-field domain vector (spec §3.5). [`PublicInputs::to_field_elements`].
    Domain,
    /// The real Self `vc_and_disclose` 20-signal layout. [`PublicInputs::to_self_field_elements`].
    SelfDisclose,
}

/// Convert a runtime `ZkAttrType` to this crate's internal `AttrType` (the field-mapping discriminant).
/// M6 ships only `Over18`; the match is exhaustive so a new runtime variant is a compile error here
/// (the seam stays in lock-step).
fn attr_type_of(t: ZkAttrType) -> AttrType {
    match t {
        ZkAttrType::Over18 => AttrType::Over18,
    }
}

/// The real Groth16/BN254 verifier — pure deterministic cryptography (ADR-0005 D2).
///
/// Holds the genesis-pinned verifying key (and, for Stage D, the attribute-circuit VK). Verification is
/// the fixed Groth16 3-pairing equation + the public-input MSM; arkworks evaluates it deterministically
/// (no `parallel` feature ⇒ no reduction-order nondeterminism) over canonically-decoded group elements.
#[derive(Clone, Debug)]
pub struct Groth16Verifier {
    /// The pinned VK for the passport-proof statement (`verify_passport`).
    passport_vk: PinnedVerifyingKey,
    /// Which public-input layout the pinned passport VK is sized for (selected by its arity at load).
    layout: PassportLayout,
    /// The pinned VK for the `over18` attribute-opening statement (`verify_attribute`). Optional: M6
    /// Stage B ships the passport path; the attribute VK is wired when Stage D lands. `None` ⇒ every
    /// attribute verify fails closed (the feature is simply not enabled yet — never an accidental pass).
    over18_vk: Option<PinnedVerifyingKey>,
}

impl Groth16Verifier {
    /// Construct with the genesis-pinned passport VK and the layout its arity selects. The attribute
    /// (`over18`) VK is absent until wired via [`Groth16Verifier::with_over18_vk`] — until then
    /// `verify_attribute` fails closed.
    pub fn new(passport_vk: PinnedVerifyingKey) -> Self {
        // Default-construct from a VK already known to be a supported arity (the `from_vk_bytes` path
        // guards this). Choose the layout from the arity; default to Domain for the 8-field case.
        let layout = if passport_vk.num_public_inputs() == SELF_NPUBLIC {
            PassportLayout::SelfDisclose
        } else {
            PassportLayout::Domain
        };
        Self {
            passport_vk,
            layout,
            over18_vk: None,
        }
    }

    /// Build directly from the canonical compressed VK bytes (the genesis-pinned form, §5.3), selecting
    /// the public-input layout from the VK's arity. Returns `None` if the bytes are not a canonical VK or
    /// the arity is neither the **domain** (`NUM_PUBLIC_INPUTS = 8`, spec §3.5) nor the **real Self**
    /// (`SELF_NPUBLIC = 20`) layout — the node fails closed at startup rather than running with a VK from
    /// an unrecognized circuit (spec §3.5 / §6.2).
    pub fn from_vk_bytes(vk_bytes: &[u8]) -> Option<Self> {
        let vk = PinnedVerifyingKey::from_canonical_bytes(vk_bytes).ok()?;
        let layout = match vk.num_public_inputs() {
            NUM_PUBLIC_INPUTS => PassportLayout::Domain,
            SELF_NPUBLIC => PassportLayout::SelfDisclose,
            // Any other arity is a foreign circuit — rejected, not silently mis-applied.
            _ => return None,
        };
        Some(Self {
            passport_vk: vk,
            layout,
            over18_vk: None,
        })
    }

    /// The public-input layout the pinned passport VK is sized for.
    pub fn layout(&self) -> PassportLayout {
        self.layout
    }

    /// Construct the verifier from the **genesis-pinned** passport VK (the real Self `vc_and_disclose`
    /// VK, [`crate::pinned_passport_vk`]). Returns `None` if no VK is pinned in this build
    /// ([`crate::HAS_PINNED_PASSPORT_VK`] is `false`) — fail-closed. This is the constructor `crates/node`
    /// uses to wire the real verifier at genesis.
    pub fn from_pinned() -> Option<Self> {
        let vk = crate::pinned_passport_vk()?;
        // The pinned VK's arity must be a recognized layout (it is the real Self 20-signal layout).
        let layout = match vk.num_public_inputs() {
            NUM_PUBLIC_INPUTS => PassportLayout::Domain,
            SELF_NPUBLIC => PassportLayout::SelfDisclose,
            _ => return None,
        };
        Some(Self {
            passport_vk: vk,
            layout,
            over18_vk: None,
        })
    }

    /// Attach the `over18` attribute-circuit VK (Stage D). Pure builder.
    pub fn with_over18_vk(mut self, over18_vk: PinnedVerifyingKey) -> Self {
        self.over18_vk = Some(over18_vk);
        self
    }

    /// The number of public inputs the pinned passport VK is sized for (debugging / wiring assert).
    pub fn passport_arity(&self) -> usize {
        self.passport_vk.num_public_inputs()
    }
}

impl ZkPassportVerifier for Groth16Verifier {
    fn verify_passport(&self, proof: &[u8], public_inputs: &ZkPublicInputs) -> bool {
        // 1. Canonical-decode the proof. Non-canonical / off-curve / wrong-subgroup ⇒ false (F-3).
        let proof = match proof_from_canonical_bytes(proof) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // 2. The runtime's plain-bytes public inputs → this crate's field-mapping struct. The conversion
        //    to the BN254 vector is the single canonical mapping for the VK's layout (selected at load):
        //    the pinned **domain** vector (§3.5, 8 fields) or the **real Self** 20-signal vector via the
        //    documented adapter. The verify equation is otherwise identical.
        let pi = PublicInputs::from_runtime(public_inputs);
        // 3. The Groth16 verify equation against the prepared, genesis-pinned VK. Deterministic; any
        //    internal error (e.g. a pairing failure) maps to false — fail closed.
        match self.layout {
            PassportLayout::Domain => {
                let inputs = pi.to_field_elements();
                Groth16::<ark_bn254::Bn254>::verify_proof(
                    self.passport_vk.prepared(),
                    &proof,
                    &inputs,
                )
                .unwrap_or(false)
            }
            PassportLayout::SelfDisclose => {
                let inputs = pi.to_self_field_elements();
                Groth16::<ark_bn254::Bn254>::verify_proof(
                    self.passport_vk.prepared(),
                    &proof,
                    &inputs,
                )
                .unwrap_or(false)
            }
        }
    }

    fn verify_attribute(
        &self,
        attr_type: ZkAttrType,
        commitment: &[u8; 32],
        attr_proof: &[u8],
    ) -> bool {
        // M6 ships only `over18`. Without the wired attribute VK the feature is OFF (fail closed) — an
        // unwired or unknown attribute never accidentally returns `true`.
        let vk = match attr_type_of(attr_type) {
            AttrType::Over18 => match &self.over18_vk {
                Some(vk) => vk,
                None => return false,
            },
        };
        let proof = match proof_from_canonical_bytes(attr_proof) {
            Ok(p) => p,
            Err(_) => return false,
        };
        // The attribute statement's single public input is the stored commitment (the verifier proves a
        // Pedersen-opening + range statement *about* this commitment, revealing only the boolean — §4.4).
        let inputs = [crate::public_inputs::address_to_field32(commitment)];
        Groth16::<ark_bn254::Bn254>::verify_proof(vk.prepared(), &proof, &inputs).unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ubi2_runtime::MockZkVerifier;

    fn pi(nullifier: u8, submitter: u8) -> ZkPublicInputs {
        ZkPublicInputs::new(
            [nullifier; 32],
            [[0u8; 32]; 3],
            [9u8; 32],
            [submitter; 20],
            1_700_000_000,
            0,
        )
    }

    #[test]
    fn mock_default_passes_and_is_deterministic() {
        let v = MockZkVerifier::default();
        let p = pi(1, 1);
        assert!(v.verify_passport(b"ignored", &p));
        // Same input ⇒ same bool (I1).
        assert_eq!(v.verify_passport(b"x", &p), v.verify_passport(b"x", &p));
    }

    #[test]
    fn mock_scripts_per_nullifier_submitter() {
        let v = MockZkVerifier::new(false).with_passport([7u8; 32], [3u8; 20], true);
        assert!(v.verify_passport(b"", &pi(7, 3)), "scripted accept");
        assert!(
            !v.verify_passport(b"", &pi(7, 4)),
            "different submitter ⇒ default reject"
        );
        assert!(
            !v.verify_passport(b"", &pi(8, 3)),
            "different nullifier ⇒ default reject"
        );
    }

    #[test]
    fn mock_attribute_default_and_override() {
        let v = MockZkVerifier::new(false).with_attribute(ZkAttrType::Over18, [5u8; 32], true);
        assert!(v.verify_attribute(ZkAttrType::Over18, &[5u8; 32], b""));
        assert!(!v.verify_attribute(ZkAttrType::Over18, &[6u8; 32], b""));
    }

    #[test]
    fn injected_disagreement_stub_returns_wrong_bool() {
        // EC-7: one node's verifier stubbed to the wrong answer — the divergence the M5 fork choice
        // out-votes. The honest mock accepts; the stubbed mock rejects the same input.
        let honest = MockZkVerifier::always(true);
        let stubbed = MockZkVerifier::always(false);
        let p = pi(1, 1);
        assert_ne!(
            honest.verify_passport(b"", &p),
            stubbed.verify_passport(b"", &p)
        );
    }
}
