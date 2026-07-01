//! The genesis-pinned verifying-key slot (spec §2.3, ADR-0005 D1 — "pin the resulting verifying key in
//! genesis, hash-committed in `state_root`").
//!
//! ## Real-circuit binding — current status (the honest accounting)
//!
//! **Stage 2 update.** This slot now ships the **real Self / OpenPassport `vc_and_disclose` verifying
//! key** (Groth16 over BN254, `nPublic = 20`), taken verbatim from the Self monorepo (`selfxyz/self`,
//! `common/src/constants/vkey.ts`) — the same artifact fixtured in `tests/fixtures/`. The bytes embedded
//! here are that VK re-serialized through arkworks into its **canonical compressed** form (the exact
//! `state_root`-commit encoding, §5.3), produced from the JSON fixture by [`crate::SnarkjsVk::to_pinned`]
//! then [`crate::PinnedVerifyingKey::to_canonical_bytes`]. [`pinned_passport_vk`] loads them with
//! `Validate::Yes` (on-curve, correct-subgroup, canonical) so a corrupted embed fails closed at startup.
//!
//! The pinned VK loads as a **`SelfDisclose`-layout** passport verifier ([`crate::PassportLayout`]): the
//! runtime's domain public inputs (spec §3.5) are mapped onto the real 20-signal vector by the documented
//! adapter ([`crate::PublicInputs::to_self_field_elements`] — see `crate::self_layout`). This is what
//! closed the Stage-1 gap: Stage 1 only pinned the 8-field domain arity, so the real VK was rejected
//! fail-closed; Stage 2 binds the real arity + layout, and the real VK is the genesis trust anchor.
//!
//! ## The remaining gap to a fully production binding (stated plainly)
//!
//! Pinning the real VK lets the verifier accept a proof generated under Self's **production circuit +
//! their Phase-2 ceremony proving key (`vc_and_disclose_final.zkey`)**. That ceremony `.zkey` is a
//! multi-gigabyte build artifact **not committed to the open repo** (the repo ships only the VK, which we
//! pin here), so this Stage does not also ship a proof verifiable under *this exact* production VK. The
//! real-curve soundness guarantee (a genuine Groth16/BN254 proof verifying at the real 20-input arity
//! through the production seam, with tampered/replayed proofs failing closed) is proven in
//! `tests/real_curve_self_layout.rs` against a self-generated setup of the same arity + layout — the
//! spec §6.3 real-curve fixture path ("a test CSCA→DSC→SOD, never a real document"). Wiring Self's
//! production ceremony proving key to emit a proof under the pinned VK is the remaining production step;
//! it changes no code in this crate (the VK, the layout adapter, and the verifier are all in place).

use crate::keys::PinnedVerifyingKey;

/// The real Self `vc_and_disclose` VK in arkworks canonical-compressed bytes (the `state_root`-commit
/// form, §5.3). Generated from `tests/fixtures/self_vc_and_disclose_vkey.json` via
/// `SnarkjsVk::to_pinned().to_canonical_bytes()`; re-generatable and verified byte-stable by
/// `tests/real_vk.rs` (canonical round-trip) + `tests/pinned_vk.rs` (this embed == the fixture import).
const PINNED_PASSPORT_VK_BYTES: &[u8] =
    include_bytes!("../fixtures/self_vc_and_disclose_vk.canonical.bin");

/// The genesis-pinned passport-proof verifying key — the **real Self `vc_and_disclose` VK** (Stage 2).
///
/// Loads the embedded canonical-compressed bytes with full validation (`Validate::Yes`); returns `None`
/// only if the embed is somehow corrupt (fail-closed: a node with an invalid trust anchor runs no
/// `verify_passport`). The returned key reports `num_public_inputs() == 20` (the real Self arity) and is
/// consumed in the [`crate::PassportLayout::SelfDisclose`] layout.
pub fn pinned_passport_vk() -> Option<PinnedVerifyingKey> {
    PinnedVerifyingKey::from_canonical_bytes(PINNED_PASSPORT_VK_BYTES).ok()
}

/// Whether a real, pinned passport VK is compiled into this build. **`true` in Stage 2**: the real Self
/// `vc_and_disclose` VK is embedded (see [`pinned_passport_vk`]). The consensus default verifier remains
/// the [`crate::MockZkVerifier`] unless a node is explicitly configured with the real
/// [`crate::Groth16Verifier`] + this pinned VK (ADR-0005 D2 — the mock is the Stage-B consensus default).
pub const HAS_PINNED_PASSPORT_VK: bool = true;
