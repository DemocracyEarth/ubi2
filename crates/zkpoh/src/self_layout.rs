//! The **CONFIRMED** Self `vc_and_disclose` public-signal layout (nPublic = 21, VK `IC.len() == 22`).
//!
//! ## What this module is (Stage C, spec 06b §4.1)
//!
//! Stage A/B guessed a 20-signal layout that was off-by-one from slot 8 and zeroed the live
//! forbidden-countries / OFAC slots — a real proof could never verify against it. The Stage-C de-risk
//! **confirmed** the real order against six independent Self sources (the circom `main`, the deployed
//! `Verifier_vc_and_disclose.sol` `uint[21]`, `CircuitConstantsV2.getDiscloseIndices(E_PASSPORT)`,
//! `IVcAndDiscloseCircuitVerifier`, the active SDK constants, and an empirically-compiled `.sym` +
//! snarkjs-verified proof). The trap that produced the earlier guess: circom orders public signals as
//! **outputs (declaration order), then public inputs in DECLARATION order** — NOT the `public[...]` list
//! order — and `forbidden_countries_list_packed` is **4** field elements, not 3.
//!
//! ```text
//! slot  signal
//!  0,1,2   revealedData_packed[3]                (opaque attribute commitments — I6)
//!  3,4,5,6 forbidden_countries_list_packed[4]    (pass-through)
//!  7       nullifier            = Poseidon(secret, scope)
//!  8       attestation_id       (== 1 for E-Passport)
//!  9       merkle_root          (∈ accepted Self identity roots — NOT our CSCA root)
//! 10..=15  current_date[6]      (YYMMDD raw digits 0-9)
//! 16       ofac_passportno_smt_root
//! 17       ofac_namedob_smt_root
//! 18       ofac_nameyob_smt_root
//! 19       scope                (== UBI2_SELF_SCOPE)
//! 20       user_identifier      (== submitter address)
//! ```
//!
//! There is **no adapter and no zeroing**: `crates/runtime` carries the raw 21-signal vector on-chain
//! (spec 06b §4.3) and this crate maps each signal to a BN254 field element by the single canonical
//! mapping (`Fr::from_be_bytes_mod_order`). The slot **constants are owned by `crates/runtime`** (so the
//! dependency-free runtime can bind by index) and re-exported here so `crates/zkpoh` and the SDK share
//! one source of truth. Changing the layout is a new circuit + a new VK (a state-root migration), never
//! a silent break.

// The confirmed slot map lives in the dependency-free runtime (it binds the policy fields by index).
// Re-export it here so the crypto crate + the SDK mirror a single source of truth (spec 06b §4.2 GAP-4).
pub use ubi2_runtime::{
    SELF_IDX_ATTESTATION_ID, SELF_IDX_CURRENT_DATE, SELF_IDX_FORBIDDEN_COUNTRIES,
    SELF_IDX_MERKLE_ROOT, SELF_IDX_NULLIFIER, SELF_IDX_OFAC_NAMEDOB, SELF_IDX_OFAC_NAMEYOB,
    SELF_IDX_OFAC_PASSPORTNO, SELF_IDX_REVEALED_DATA, SELF_IDX_SCOPE, SELF_IDX_USER_IDENTIFIER,
    SELF_NPUBLIC, UBI2_SELF_SCOPE, UBI2_SELF_SCOPE_SEED,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confirmed_slot_map() {
        assert_eq!(SELF_NPUBLIC, 21);
        assert_eq!(SELF_IDX_REVEALED_DATA, 0);
        assert_eq!(SELF_IDX_FORBIDDEN_COUNTRIES, 3);
        assert_eq!(SELF_IDX_NULLIFIER, 7);
        assert_eq!(SELF_IDX_ATTESTATION_ID, 8);
        assert_eq!(SELF_IDX_MERKLE_ROOT, 9);
        assert_eq!(SELF_IDX_CURRENT_DATE, 10);
        assert_eq!(SELF_IDX_OFAC_PASSPORTNO, 16);
        assert_eq!(SELF_IDX_OFAC_NAMEDOB, 17);
        assert_eq!(SELF_IDX_OFAC_NAMEYOB, 18);
        assert_eq!(SELF_IDX_SCOPE, 19);
        assert_eq!(SELF_IDX_USER_IDENTIFIER, 20);
    }
}
