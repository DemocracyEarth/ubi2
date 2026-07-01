//! The **real** Self / OpenPassport `vc_and_disclose` public-signal **arity** (nPublic = 20) and the
//! adapter that maps our domain public inputs (spec §3.5) onto a real-arity 20-element vector.
//!
//! ## Why this module exists (closing the Stage-1 gap)
//!
//! M6 ZK-PoH Stage 1 fetched the real Self protocol `vc_and_disclose` Groth16/BN254 verifying key
//! (`tests/fixtures/self_vc_and_disclose_vkey.json`, taken verbatim from `selfxyz/self`) and confirmed
//! the **curve** (BN254) and the **proof system** (Groth16). It then found our *pinned* 8-field
//! public-input layout did **not** match their real circuit: the Self disclose VK is **`nPublic = 20`**
//! (`IC.len() == 21`), so the real VK was — correctly — rejected fail-closed by the 8-input arity pin.
//!
//! Stage 2 closes that gap. We read the actual circuit (`circuits/disclose/vc_and_disclose.circom` in the
//! Self monorepo) to pin the real **arity** and the real public-signal **structure**, then map the
//! runtime's domain inputs (spec §3.5) onto a real-arity (20) field vector with a documented,
//! deterministic **adapter** — option (b) of the Stage-2 plan: keep the runtime's `ZkPublicInputs`
//! crypto-free domain shape; own the mapping to the real circuit's arity here in `crates/zkpoh`.
//!
//! ## The real public-signal structure (from `template VC_AND_DISCLOSE(33, 40, 64, 64, 64)`)
//!
//! snarkjs orders public signals as the circuit **outputs** (declaration order) then the **declared
//! public inputs** (`component main { public [...] }` order). For `vc_and_disclose`:
//!
//! Outputs:
//!   * `revealedData_packed[3]`             — packed disclosed DG1 fields (3 signals)
//!   * `forbidden_countries_list_packed[N]` — OFAC forbidden-country list (packed; N field elements)
//!   * `nullifier`                          — `Poseidon(secret, scope)` (scope-bound) (1 signal)
//!
//! Declared public inputs:
//!   * `merkle_root`, `ofac_passportno_smt_root`, `ofac_namedob_smt_root`, `ofac_nameyob_smt_root`,
//!     `scope`, `user_identifier`, `current_date[6]`, `attestation_id`.
//!
//! The **verifying key is authoritative on the count**: its `IC` has 21 points ⇒ exactly **20** public
//! signals (`SELF_NPUBLIC`). [`crate::SnarkjsVk::to_pinned`] reports that 20 directly from the real VK.
//!
//! ## The domain mapping (our §3.5 vector → the real 20-signal vector)
//!
//! The runtime owns the *meaning* of our domain inputs and re-derives/binds the chain-supplied ones
//! (CSCA root, submitter, now, scheme) — exactly as before. This adapter owns the *placement* of those
//! values into the real circuit's signal slots, so a proof generated against the real-arity circuit
//! verifies against our domain vector with no change to the runtime seam:
//!
//!   * **nullifier**           → the circuit `nullifier` slot.
//!   * **attr_commit\[0..3]**  → the three `revealedData_packed` slots (the opaque packed-disclosure
//!     field elements ARE our three attribute commitments — only commitments on-chain, I6).
//!   * **submitter_address**   → the `user_identifier` slot (the bound address, anti-replay §4.3).
//!   * **now_epoch**           → the six `current_date` digit slots (the chain-supplied not-expired "now").
//!   * **csca_registry_root**  → the `merkle_root` slot (the trusted-set root the proof binds to).
//!   * **scheme_tag**          → the `attestation_id` slot (the document/credential discriminant).
//!   * Remaining slots (`forbidden_countries_list_packed`, the three OFAC roots, `scope`) are pinned
//!     **adapter-context** field constants — part of the canonical statement, not free inputs.
//!
//! Changing this mapping — like changing the §3.5 order — is a **new circuit + a new verifying key** (and
//! a state-root version bump), never a silent break.

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::public_inputs::PublicInputs;

/// The number of public signals the real Self `vc_and_disclose` circuit exposes (its VK's `IC.len() - 1`).
/// Pinned from the real VK fixture; [`crate::SnarkjsVk::to_pinned`] reports the same 20.
pub const SELF_NPUBLIC: usize = 20;

// --- Canonical slot indices in the real 20-element public-signal vector (0..=19). The three OFAC roots,
//     the packed forbidden-countries list, and `scope` are adapter-context constants and occupy the
//     remaining slots; only the slots we bind a domain value into are named. ---

/// `revealedData_packed` slots — our three attribute commitments map here (slots 0,1,2).
pub const SELF_IDX_REVEALED_DATA: usize = 0;
/// `nullifier` slot — our nullifier maps here.
pub const SELF_IDX_NULLIFIER: usize = 7;
/// `merkle_root` slot — our CSCA-registry root maps here.
pub const SELF_IDX_MERKLE_ROOT: usize = 8;
/// `scope` slot — a pinned adapter-context constant.
pub const SELF_IDX_SCOPE: usize = 12;
/// `user_identifier` slot — our submitter address maps here (anti-replay binding).
pub const SELF_IDX_USER_IDENTIFIER: usize = 13;
/// `current_date[0..6]` slots — our now-epoch maps here (six YYMMDD digit signals).
pub const SELF_IDX_CURRENT_DATE: usize = 14;
/// `attestation_id` slot — our scheme tag maps here (the last public signal).
pub const SELF_IDX_ATTESTATION_ID: usize = SELF_NPUBLIC - 1;

/// The fixed adapter-context constant for the `scope` slot — a domain-separated tag so the pinned
/// statement commits to *this* chain's scope, not a free input. Deterministic (no clock, no allocation).
pub const SELF_SCOPE_CONST: u64 = 0x7562_6932; // "ubi2" in ASCII big-endian, as a small field constant.

impl PublicInputs {
    /// Map our domain public-input vector (spec §3.5) onto a **real-arity** (`SELF_NPUBLIC = 20`) Self
    /// `vc_and_disclose` public vector. The single canonical adapter (deterministic, pure): two nodes
    /// that assemble the same domain inputs produce the same 20-field vector and therefore the same
    /// verify result (I1/I2). See the module docs for the per-slot mapping rationale.
    pub fn to_self_field_elements(&self) -> [Fr; SELF_NPUBLIC] {
        let mut out = [Fr::from(0u64); SELF_NPUBLIC];

        // Our 3 attribute commitments occupy the 3 packed-disclosure slots (0,1,2).
        out[SELF_IDX_REVEALED_DATA] = Fr::from_be_bytes_mod_order(&self.attribute_commitments[0]);
        out[SELF_IDX_REVEALED_DATA + 1] =
            Fr::from_be_bytes_mod_order(&self.attribute_commitments[1]);
        out[SELF_IDX_REVEALED_DATA + 2] =
            Fr::from_be_bytes_mod_order(&self.attribute_commitments[2]);

        // nullifier.
        out[SELF_IDX_NULLIFIER] = Fr::from_be_bytes_mod_order(&self.nullifier);

        // merkle_root slot carries our CSCA-registry root — the trust-set the proof binds to.
        out[SELF_IDX_MERKLE_ROOT] = Fr::from_be_bytes_mod_order(&self.csca_registry_root);

        // scope: a fixed domain-separated constant.
        out[SELF_IDX_SCOPE] = Fr::from(SELF_SCOPE_CONST);

        // user_identifier carries our submitter address — the anti-replay binding (§4.3).
        out[SELF_IDX_USER_IDENTIFIER] =
            crate::public_inputs::address_to_field(&self.submitter_address);

        // current_date[6] encodes now_epoch (the chain-supplied "now").
        let date = now_epoch_to_date_digits(self.now_epoch);
        for (i, d) in date.iter().enumerate() {
            out[SELF_IDX_CURRENT_DATE + i] = Fr::from(*d as u64);
        }

        // attestation_id carries our scheme tag (the last public signal).
        out[SELF_IDX_ATTESTATION_ID] = Fr::from(self.scheme_tag as u64);

        out
    }
}

/// Deterministically encode a unix `now_epoch` into six `current_date` ASCII-digit field slots
/// (`YYMMDD`). Pure integer arithmetic (no float, no clock, no chrono dep) so it is bit-reproducible
/// across nodes. The runtime binds `now_epoch == block.timestamp`; this maps that single integer into the
/// six circuit signals the in-circuit not-expired check reads.
///
/// Uses Howard Hinnant's well-known integer days-from-civil inverse to get the UTC civil date, then emits
/// the two low year digits, the month, and the day as ASCII codes (`'0'..='9'`) — the byte encoding the
/// circuit's `current_date` uses.
pub fn now_epoch_to_date_digits(now_epoch: u64) -> [u8; 6] {
    let days = (now_epoch / 86_400) as i64;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if m <= 2 { y + 1 } else { y };

    let yy = year.rem_euclid(100) as u8;
    let mm = m as u8;
    let dd = d as u8;
    [
        b'0' + yy / 10,
        b'0' + yy % 10,
        b'0' + mm / 10,
        b'0' + mm % 10,
        b'0' + dd / 10,
        b'0' + dd % 10,
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PublicInputs {
        PublicInputs::new(
            [7u8; 32],
            [[1u8; 32], [2u8; 32], [3u8; 32]],
            [9u8; 32],
            [6u8; 20],
            1_700_000_000,
            0,
        )
    }

    #[test]
    fn self_layout_arity_is_twenty() {
        let pi = sample();
        let v = pi.to_self_field_elements();
        assert_eq!(v.len(), SELF_NPUBLIC);
        assert_eq!(SELF_NPUBLIC, 20);
    }

    #[test]
    fn self_mapping_is_pure_and_places_domain_values() {
        let pi = sample();
        let a = pi.to_self_field_elements();
        let b = pi.to_self_field_elements();
        assert_eq!(a, b, "the adapter is a pure function (I1)");

        assert_eq!(
            a[SELF_IDX_NULLIFIER],
            Fr::from_be_bytes_mod_order(&[7u8; 32])
        );
        assert_eq!(
            a[SELF_IDX_REVEALED_DATA],
            Fr::from_be_bytes_mod_order(&[1u8; 32])
        );
        assert_eq!(
            a[SELF_IDX_REVEALED_DATA + 2],
            Fr::from_be_bytes_mod_order(&[3u8; 32])
        );
        assert_eq!(
            a[SELF_IDX_USER_IDENTIFIER],
            crate::public_inputs::address_to_field(&[6u8; 20])
        );
        assert_eq!(a[SELF_IDX_ATTESTATION_ID], Fr::from(0u64));
    }

    #[test]
    fn now_epoch_date_digits_are_deterministic_and_ascii() {
        // 1_700_000_000 = 2023-11-14 (UTC) ⇒ YY MM DD = 23 11 14.
        let d = now_epoch_to_date_digits(1_700_000_000);
        assert_eq!(d, [b'2', b'3', b'1', b'1', b'1', b'4']);
        assert_eq!(
            now_epoch_to_date_digits(1_700_000_000),
            now_epoch_to_date_digits(1_700_000_000)
        );
        // Epoch 0 = 1970-01-01.
        assert_eq!(
            now_epoch_to_date_digits(0),
            [b'7', b'0', b'0', b'1', b'0', b'1']
        );
    }
}
