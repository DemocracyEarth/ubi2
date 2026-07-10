//! # ubi2-zkpoh — the pure, deterministic ZK-passport proof-of-humanity verifier (M6, ADR-0005 D1/D2)
//!
//! This crate is the **cleanest PoH path** the project has: pairing/field arithmetic over a fixed
//! `(proof, public_inputs)` pair is a *function*, reproducible to the bit across nodes (invariant **I4**
//! — "the cleanest realization"). There is no AI in the verify path; honest nodes that re-run the
//! verifier get the same boolean, so the op slots into the M5 re-execution consensus more cleanly than
//! the AI jury (spec §5.4).
//!
//! ## What it holds (the crate boundary — spec §6.1, ADR-0005 D2)
//! * The `ZkPassportVerifier` trait + the plain-bytes `ZkPublicInputs`/`ZkAttrType` types now live in
//!   `crates/runtime` (dependency-free); this crate **implements** the trait — exactly as `ubi2-oracle`
//!   implements `ubi2_runtime::HumanityOracle`. They are re-exported here so a caller has a single import
//!   surface (`ubi2_zkpoh::{ZkPassportVerifier, MockZkVerifier, ...}`).
//! * [`Groth16Verifier`] — the real arkworks Groth16/BN254 impl (the consensus crypto).
//! * [`MockZkVerifier`](ubi2_runtime::MockZkVerifier) — the scripted, deterministic verifier for CI /
//!   lifecycle tests (the I5 offline path, the analogue of `MockOracle`). It is the impl the consensus
//!   path ships on for Stage B.
//! * [`PinnedVerifyingKey`] + canonical (de)serialization — the genesis-pinned trust anchor + the
//!   single-encoding-per-element guarantee (spec §6.2 non-malleability).
//! * [`PublicInputs`] — this crate's BN254 field-element mapping of the public-input vector (spec §3.5);
//!   built from `ubi2_runtime::ZkPublicInputs` via [`PublicInputs::from_runtime`].
//!
//! ## Determinism + isolation (the structural rules — spec §6.2, §14)
//! 1. **Pure + deterministic + canonical-encoding.** Same inputs ⇒ same bool on every node: no float,
//!    no clock, no allocation/iteration-order dependence, no randomized verification. Malformed input
//!    fails closed (`false`), never panics. arkworks is built **without** the `parallel` feature, so
//!    there is no reduction-order nondeterminism.
//! 2. **Canonical encodings.** Group elements (de)serialize with `Validate::Yes` — one valid encoding
//!    per element; non-canonical / off-curve / wrong-subgroup bytes are rejected (a malleable encoding
//!    is a soundness/replay risk, F-3/F-4).
//! 3. **wasm32-compilable.** The verify path is `std` + arkworks only (no async/network/clock/float
//!    dep), so the same code compiles to `wasm32-unknown-unknown` and runs in a browser light node
//!    (spec §8). The build-level dependency assertion ([`tests/dependency_clean.rs`]) enforces this.
//! 4. **`crates/runtime` stays dependency-free.** It calls this crate through the trait; no crypto crate
//!    crosses the boundary.
//!
//! ## Trust-setup accounting (the security-gate item — spec §2.3)
//! Groth16 needs a circuit-specific trusted setup; un-destroyed toxic waste forges proofs ⇒ a fake
//! human. The mitigations (reuse a public Phase-1, run an open multi-party Phase-2, **pin the VK in
//! genesis hash-committed in `state_root`**, document the assumption) live in the spec/ADR. This crate
//! holds the VK *slot* ([`genesis_vk`]) and the canonical (de)serialize; the real ceremony VK is wired
//! by `crates/node` at genesis (see [`genesis_vk`] for the real-circuit binding status).

mod genesis_vk;
mod keys;
mod public_inputs;
mod self_layout;
mod snarkjs;
mod verifier;

pub use genesis_vk::{pinned_passport_vk, HAS_PINNED_PASSPORT_VK};
pub use keys::{proof_from_canonical_bytes, proof_to_canonical_bytes, PinnedVerifyingKey};
pub use public_inputs::{address_to_field, address_to_field32, AttrType, PublicInputs};
pub use self_layout::{
    SELF_IDX_ATTESTATION_ID, SELF_IDX_CURRENT_DATE, SELF_IDX_FORBIDDEN_COUNTRIES,
    SELF_IDX_MERKLE_ROOT, SELF_IDX_NULLIFIER, SELF_IDX_OFAC_NAMEDOB, SELF_IDX_OFAC_NAMEYOB,
    SELF_IDX_OFAC_PASSPORTNO, SELF_IDX_REVEALED_DATA, SELF_IDX_SCOPE, SELF_IDX_USER_IDENTIFIER,
    SELF_NPUBLIC, UBI2_SELF_SCOPE, UBI2_SELF_SCOPE_SEED,
};
pub use snarkjs::{SnarkjsImportError, SnarkjsVk};
pub use verifier::{Groth16Verifier, PassportLayout};
// The trait + the plain-bytes types + the mock now live in `crates/runtime` (dependency-free, ADR-0005
// D2); re-export them so `ubi2_zkpoh` stays a single import surface for the verifier seam.
pub use ubi2_runtime::{MockZkVerifier, ZkAttrType, ZkPassportVerifier, ZkPublicInputs};
