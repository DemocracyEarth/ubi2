//! The verifying key + proof byte types, with **canonical** (single-encoding-per-element)
//! (de)serialization (spec §6.2, ADR-0005 D2).
//!
//! Canonical encoding is a soundness/replay guarantee, not a nicety: a malleable encoding (multiple
//! valid byte strings for one group element) would let an attacker produce a *different* proof blob for
//! the *same* proof, defeating the mempool-replay and front-run defenses (F-3/F-4). arkworks'
//! `CanonicalSerialize`/`CanonicalDeserialize` with **validation on** rejects non-canonical and
//! off-curve / wrong-subgroup encodings; we always deserialize with `Validate::Yes`, so a tampered or
//! malformed byte string fails closed (`false`), never silently accepts.
//!
//! ## The genesis-pinned VK
//! The verifying key is produced by the circuit's trusted-setup ceremony (spec §2.3) and **pinned in
//! genesis**, hash-committed in `state_root`. This crate holds the *type* + the canonical (de)serialize;
//! the actual pinned bytes are wired by `crates/node` at genesis (the same way the genesis CSCA set is).
//! [`PinnedVerifyingKey`] is the slot: load real ceremony bytes when available, or a deterministically
//! generated test VK in CI (the real-curve fixture path, spec §6.3).

use ark_bn254::Bn254;
use ark_groth16::{PreparedVerifyingKey, Proof, VerifyingKey};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Validate,
};

/// The Groth16/BN254 verifying key, in the **prepared** form the verify equation consumes (the
/// `e(α,β)` pairing and the `γ⁻¹`, `δ⁻¹` group elements are precomputed once at load). Pinned in genesis.
#[derive(Clone)]
pub struct PinnedVerifyingKey {
    /// The raw verifying key (kept so we can re-serialize it canonically for the `state_root` commit).
    vk: VerifyingKey<Bn254>,
    /// The prepared form actually fed to the verify equation (precomputed; pure function of `vk`).
    prepared: PreparedVerifyingKey<Bn254>,
}

impl PinnedVerifyingKey {
    /// Wrap a raw `VerifyingKey`, precomputing the prepared form. Pure + deterministic.
    pub fn from_vk(vk: VerifyingKey<Bn254>) -> Self {
        let prepared = ark_groth16::prepare_verifying_key(&vk);
        Self { vk, prepared }
    }

    /// Deserialize a verifying key from its **canonical compressed** bytes (the genesis-pinned form),
    /// validating subgroup membership + canonicality. A non-canonical / off-curve / wrong-arity VK is a
    /// hard error — fail closed (I4). This is the only constructor the node uses for the pinned VK.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SerializationError> {
        let vk = VerifyingKey::<Bn254>::deserialize_with_mode(
            bytes,
            Compress::Yes,
            Validate::Yes, // reject non-canonical / off-curve / wrong-subgroup
        )?;
        Ok(Self::from_vk(vk))
    }

    /// Serialize the verifying key to its **canonical compressed** bytes — the exact bytes hash-committed
    /// in `state_root` so all nodes agree on the trust anchor (a VK swap is a consensus change, §5.3).
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, SerializationError> {
        let mut out = Vec::with_capacity(self.vk.serialized_size(Compress::Yes));
        self.vk.serialize_with_mode(&mut out, Compress::Yes)?;
        Ok(out)
    }

    /// The number of public inputs this VK is sized for (`gamma_abc_g1.len() − 1`). The verifier
    /// cross-checks this equals [`crate::NUM_PUBLIC_INPUTS`] so a VK from a different circuit (different
    /// arity) is rejected rather than mis-applied (spec §3.5 pinning).
    pub fn num_public_inputs(&self) -> usize {
        // `gamma_abc_g1` has one extra element (the "1" / constant term) beyond the public inputs.
        self.vk.gamma_abc_g1.len().saturating_sub(1)
    }

    /// Borrow the prepared key for the verify equation.
    pub(crate) fn prepared(&self) -> &PreparedVerifyingKey<Bn254> {
        &self.prepared
    }
}

impl core::fmt::Debug for PinnedVerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PinnedVerifyingKey")
            .field("num_public_inputs", &self.num_public_inputs())
            .finish()
    }
}

/// Deserialize a Groth16 proof (3 BN254 group elements, ~200 bytes compressed) from its **canonical
/// compressed** bytes, validating subgroup membership + canonicality. A tampered / non-canonical /
/// off-curve proof blob is a hard error → the verifier returns `false` (fail-closed, F-3).
pub fn proof_from_canonical_bytes(bytes: &[u8]) -> Result<Proof<Bn254>, SerializationError> {
    Proof::<Bn254>::deserialize_with_mode(bytes, Compress::Yes, Validate::Yes)
}

/// Serialize a Groth16 proof to its canonical compressed bytes (used by the test/CLI prover side and to
/// confirm round-trip stability).
pub fn proof_to_canonical_bytes(proof: &Proof<Bn254>) -> Result<Vec<u8>, SerializationError> {
    let mut out = Vec::with_capacity(proof.serialized_size(Compress::Yes));
    proof.serialize_with_mode(&mut out, Compress::Yes)?;
    Ok(out)
}
