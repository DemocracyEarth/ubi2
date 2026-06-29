//! snarkjs verifying-key importer (the real-VK binding path, spec §2.2 / §6.3).
//!
//! The OpenPassport / Self circuits — and essentially every Circom/snarkjs Groth16 pipeline — publish
//! their verifying key as a **snarkjs `verification_key.json`**: decimal-string field elements in
//! `{ vk_alpha_1, vk_beta_2, vk_gamma_2, vk_delta_2, IC }`. This module converts that canonical snarkjs
//! shape into an arkworks [`VerifyingKey<Bn254>`], validated on-curve, and wraps it as a
//! [`PinnedVerifyingKey`] — so the node can load a **real ceremony VK** (e.g. the Self disclose circuit,
//! `nPublic = 20`) directly, then re-serialize it canonically for the `state_root` commit (§5.3).
//!
//! To keep `crates/zkpoh` dependency-clean (arkworks-only — no `serde_json`), this takes the *already
//! parsed* string arrays via [`SnarkjsVk`]. The caller (the node, or a test) does the JSON parse and
//! hands the strings in. The conversion itself is pure + deterministic + fail-closed: any malformed
//! coordinate, off-curve point, or arity mismatch is a hard [`SnarkjsImportError`].
//!
//! ## Coordinate conventions (snarkjs ⇄ arkworks)
//! * **Field elements** are base-10 decimal strings over `Fq` (G1 coords) / `Fq2` (G2 coords).
//! * **G1 points** are `[x, y, z]`; affine iff `z == "1"` (snarkjs always emits affine VKs).
//! * **G2 points** are `[[x_c0, x_c1], [y_c0, y_c1], [z_c0, z_c1]]` over `Fq2 = Fq[u]/(u²+1)`; affine
//!   iff `z == [1, 0]`. arkworks `Fq2::new(c0, c1)` uses the same `(c0 + c1·u)` basis as snarkjs.
//! * Points are constructed with `G1Affine::new` / `G2Affine::new`, which **validate on-curve + correct
//!   subgroup** — a bogus VK fails here rather than silently producing wrong accepts.

use ark_bn254::{Bn254, Fq, Fq2, G1Affine, G2Affine};
use ark_groth16::VerifyingKey;
use core::str::FromStr;

use crate::keys::PinnedVerifyingKey;

/// A snarkjs Groth16 verifying key as decimal strings (the `verification_key.json` shape), pre-parsed by
/// the caller. Mirrors the field names snarkjs emits so the mapping is obvious.
#[derive(Clone, Debug)]
pub struct SnarkjsVk {
    /// `vk_alpha_1`: G1 point `[x, y, z]` (decimal strings; affine ⇒ `z == "1"`).
    pub vk_alpha_1: [String; 3],
    /// `vk_beta_2`: G2 point `[[x0,x1],[y0,y1],[z0,z1]]`.
    pub vk_beta_2: [[String; 2]; 3],
    /// `vk_gamma_2`: G2 point.
    pub vk_gamma_2: [[String; 2]; 3],
    /// `vk_delta_2`: G2 point.
    pub vk_delta_2: [[String; 2]; 3],
    /// `IC`: the `nPublic + 1` G1 points of the public-input MSM (`gamma_abc_g1` in arkworks).
    pub ic: Vec<[String; 3]>,
}

/// A failure converting a snarkjs VK to the arkworks form. Every variant is fail-closed — the VK is
/// rejected, never partially loaded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SnarkjsImportError {
    /// A coordinate string was not a valid `Fq` element (bad decimal / out of range).
    BadFieldElement,
    /// A point was not affine (its `z` coordinate was not `1` / `[1,0]`) — snarkjs VKs are always affine.
    NonAffinePoint,
    /// A point `(x, y)` was not on the curve or not in the correct subgroup (arkworks validation failed).
    OffCurvePoint,
    /// The `IC` array was empty (a VK must have at least the constant term).
    EmptyIc,
}

fn fq(s: &str) -> Result<Fq, SnarkjsImportError> {
    Fq::from_str(s).map_err(|_| SnarkjsImportError::BadFieldElement)
}

/// Build a validated affine G1 point from a snarkjs `[x, y, z]` triple. Rejects non-affine (`z != 1`)
/// and off-curve points.
fn g1(p: &[String; 3]) -> Result<G1Affine, SnarkjsImportError> {
    if p[2] != "1" {
        return Err(SnarkjsImportError::NonAffinePoint);
    }
    let x = fq(&p[0])?;
    let y = fq(&p[1])?;
    // `new` validates on-curve + subgroup; `new_unchecked` would not — we want the validating path.
    let pt = G1Affine::new_unchecked(x, y);
    if !pt.is_on_curve() || !pt.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SnarkjsImportError::OffCurvePoint);
    }
    Ok(pt)
}

/// Build a validated affine G2 point from a snarkjs `[[x0,x1],[y0,y1],[z0,z1]]`. Rejects non-affine
/// (`z != [1,0]`) and off-curve points.
fn g2(p: &[[String; 2]; 3]) -> Result<G2Affine, SnarkjsImportError> {
    if p[2][0] != "1" || p[2][1] != "0" {
        return Err(SnarkjsImportError::NonAffinePoint);
    }
    let x = Fq2::new(fq(&p[0][0])?, fq(&p[0][1])?);
    let y = Fq2::new(fq(&p[1][0])?, fq(&p[1][1])?);
    let pt = G2Affine::new_unchecked(x, y);
    if !pt.is_on_curve() || !pt.is_in_correct_subgroup_assuming_on_curve() {
        return Err(SnarkjsImportError::OffCurvePoint);
    }
    Ok(pt)
}

impl SnarkjsVk {
    /// Convert this snarkjs VK into a validated [`PinnedVerifyingKey`]. Pure + deterministic + fail-closed.
    ///
    /// The resulting key reports `IC.len() − 1` public inputs via
    /// [`PinnedVerifyingKey::num_public_inputs`] — for the Self disclose circuit (`nPublic = 20`) the
    /// `IC` array has 21 entries, so this reports 20, matching the snarkjs `nPublic`. The
    /// [`crate::Groth16Verifier::from_vk_bytes`] arity pin (8 for our §3.5 layout) then *rejects* this
    /// foreign-arity VK — which is the correct behavior until the circuit's public outputs are adapted to
    /// emit our 8-field vector (the documented next step, [`crate::pinned_passport_vk`]).
    pub fn to_pinned(&self) -> Result<PinnedVerifyingKey, SnarkjsImportError> {
        if self.ic.is_empty() {
            return Err(SnarkjsImportError::EmptyIc);
        }
        let alpha_g1 = g1(&self.vk_alpha_1)?;
        let beta_g2 = g2(&self.vk_beta_2)?;
        let gamma_g2 = g2(&self.vk_gamma_2)?;
        let delta_g2 = g2(&self.vk_delta_2)?;
        let mut gamma_abc_g1 = Vec::with_capacity(self.ic.len());
        for ic_pt in &self.ic {
            gamma_abc_g1.push(g1(ic_pt)?);
        }
        let vk = VerifyingKey::<Bn254> {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            gamma_abc_g1,
        };
        Ok(PinnedVerifyingKey::from_vk(vk))
    }
}
