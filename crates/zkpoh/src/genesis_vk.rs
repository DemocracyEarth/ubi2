//! The genesis-pinned verifying-key slot (spec §2.3, ADR-0005 D1 — "pin the resulting verifying key in
//! genesis, hash-committed in `state_root`").
//!
//! ## Stage-C status — a SYNTHETIC 21-signal layout/pipeline lock (NOT Self's production VK)
//!
//! This slot ships a **SYNTHETIC** Groth16/BN254 verifying key over the **CONFIRMED** Self
//! `vc_and_disclose` public-signal layout (`SELF_NPUBLIC = 21`, VK `IC.len() == 22`, spec 06b §4.1). It
//! is generated from `fixtures/self_synthetic_vkey.json` via [`crate::SnarkjsVk::to_pinned`] then
//! [`crate::PinnedVerifyingKey::to_canonical_bytes`] (regenerate with the ignored test
//! `tests/self_arity21.rs::regen_pinned_synthetic_vk`). [`pinned_passport_vk`] loads it with
//! `Validate::Yes` (on-curve, correct-subgroup, canonical) so a corrupted embed fails closed at startup.
//!
//! **Why synthetic, and why the stale VK was dropped (spec 06b §4.1 VK-status).** The VK pinned in
//! Stage A/B was a genuine-but-**STALE 20-signal legacy** artifact (byte-identical to Self's dead
//! `vkey_vc_and_disclose` constant — zero usages in their monorepo); it **cannot verify a real 21-signal
//! proof**, and the current **production 21-signal VK is not obtainable** (Self's S3 returns 403; the
//! ceremony `.zkey` is uncommitted). The arity gate now **rejects** any 20-signal VK, so the stale one no
//! longer loads. The synthetic VK is a **layout/pipeline lock**: it proves the verifier + importer +
//! full-vector carriage all work at the real arity + slot order (`tests/self_arity21.rs`: a genuine proof
//! verifies TRUE at 21 inputs; tampered/wrong-slot fail closed).
//!
//! **The real verifier stays STAGING/OPT-IN.** The `MockZkVerifier` remains the shipped devnet
//! **consensus default** (`crates/node`); a node may wire the real [`crate::Groth16Verifier`] +
//! [`pinned_passport_vk`] via `Chain::with_verifier` as an opt-in staging path. Flipping it to the
//! value-minting default is gated on **EC-C7** — a genuine Self **staging** proof verifying end-to-end
//! (which requires replacing this synthetic VK + [`ubi2_runtime::UBI2_SELF_SCOPE`] with the fixture
//! values captured by the C1 SDK flow).

use crate::keys::PinnedVerifyingKey;

/// The SYNTHETIC 21-signal `vc_and_disclose` VK in arkworks canonical-compressed bytes (the
/// `state_root`-commit form, §5.3). Generated from `fixtures/self_synthetic_vkey.json`; regenerate with
/// `tests/self_arity21.rs::regen_pinned_synthetic_vk`. A layout/pipeline lock — NOT Self's production VK.
const PINNED_PASSPORT_VK_BYTES: &[u8] =
    include_bytes!("../fixtures/self_synthetic_vk.canonical.bin");

/// The genesis-pinned passport-proof verifying key — the **SYNTHETIC 21-signal** layout/pipeline lock
/// (spec 06b §4.1). Loads the embedded canonical-compressed bytes with full validation (`Validate::Yes`);
/// returns `None` only if the embed is corrupt (fail-closed). The returned key reports
/// `num_public_inputs() == 21` (the confirmed Self arity) and is consumed in the
/// [`crate::PassportLayout::SelfDisclose`] layout. Available via `Chain::with_verifier` as a
/// **staging/opt-in** verifier; the `MockZkVerifier` stays the consensus default (EC-C7 gate).
pub fn pinned_passport_vk() -> Option<PinnedVerifyingKey> {
    PinnedVerifyingKey::from_canonical_bytes(PINNED_PASSPORT_VK_BYTES).ok()
}

/// Whether a pinned passport VK is compiled into this build. **`true`**: the synthetic 21-signal
/// layout-lock VK is embedded (see [`pinned_passport_vk`]). The consensus default verifier remains the
/// [`crate::MockZkVerifier`] unless a node explicitly wires the real [`crate::Groth16Verifier`] + this
/// pinned VK via `Chain::with_verifier` (the mock is the Stage-C consensus default — EC-C7 gate).
pub const HAS_PINNED_PASSPORT_VK: bool = true;
