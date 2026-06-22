//! M3 proof-of-humanity: HumanityHub calldata ABI + liveness-evidence derivation.
//!
//! Spec: `docs/specs/03-proof-of-humanity.md` (§"RPC / interfaces"). This module is the pure
//! (state-free) ABI layer for the proof-of-humanity write surface, mirroring [`crate::streams`] for
//! the StreamHub. The stateful dispatch — recovering the signer, queuing ops, applying them at block
//! time against the node oracle, emitting receipt logs, and the `ubi_*` reads — lives in `lib.rs`.
//!
//! ## The HumanityHub system address (`0x…5048`)
//! Proof-of-humanity write ops are EVM txs to the reserved [`HUMANITY_HUB`] system address, exactly
//! the way stream ops target the StreamHub (`0x…5742`). The two addresses are distinct documented
//! constants; `0x5048` is ASCII `"PH"` (Proof-of-Humanity), `0x5742` is ASCII `"WB"`-ish — picked so
//! the two hubs never collide. MetaMask / viem / ethers encode the calls below identically because
//! the Solidity-style signatures match keccak selectors.
//!
//! ## Write ops (calldata to HumanityHub, via `eth_sendRawTransaction`)
//!   * `requestVerification(bytes32 livenessRef)` — open a registration for the tx signer.
//!   * `vouch(address vouchee)` — the (Verified) signer vouches for `vouchee`.
//!   * `challenge(address subject, bytes32 evidenceRef)` — open a challenge against `subject`.
//!   * `submitVerdict(uint256 caseId, uint8 verdict, uint8 confidence)` — a juror's signed verdict.
//!
//! The off-chain liveness challenge/response bytes are *not* on the wire (I6 — no PII on-chain): the
//! tx only commits the `livenessRef`. For the M3 devnet the node derives deterministic stub
//! challenge/response bytes from `livenessRef` (see [`derive_liveness`]) so the MockOracle can grade
//! the registration end-to-end without an off-chain channel. The seam to a real liveness exchange is
//! exactly this function.

use alloy_primitives::{Address as AlloyAddr, B256, U256};
use alloy_sol_types::{sol, SolCall};

use ubi2_runtime::{CanonicalVerdict, Confidence, Hash, Verdict};

/// The reserved HumanityHub system address (`0x…5048`) — proof-of-humanity write ops target it.
/// Distinct from the StreamHub (`0x…5742`). `0x5048` is ASCII `"PH"` (Proof-of-Humanity).
pub const HUMANITY_HUB: AlloyAddr = AlloyAddr::new([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x48,
]);

// ---------------------------------------------------------------------------------------------
// ABI: HumanityHub calldata (writes). `sol!` derives the 4-byte selectors so wallets encode them
// identically to a real Solidity interface.
// ---------------------------------------------------------------------------------------------

sol! {
    /// HumanityHub proof-of-humanity write ops (via `eth_sendRawTransaction`). Solidity-style
    /// signatures so MetaMask / viem / ethers encode them byte-identically to the on-chain selectors.
    interface IHumanityHub {
        /// Open a registration for the tx signer, committing `livenessRef` (no PII on-chain — I6).
        function requestVerification(bytes32 livenessRef) external;
        /// The (Verified) signer vouches for `vouchee`.
        function vouch(address vouchee) external;
        /// Open a challenge against `subject` with content-addressed `evidenceRef`.
        function challenge(address subject, bytes32 evidenceRef) external;
        /// A juror's signed canonical verdict on `caseId`. `verdict`: 0=Human,1=Sybil,2=Uncertain.
        /// `confidence`: 0=Low,1=Med,2=High. (`reasons_hash` is off-chain/informational — I1.)
        function submitVerdict(uint256 caseId, uint8 verdict, uint8 confidence) external;
    }
}

/// Re-export the generated call types so `lib.rs` can match on selectors without re-deriving them.
pub use IHumanityHub::{challengeCall, requestVerificationCall, submitVerdictCall, vouchCall};

/// A decoded HumanityHub *write* op, parsed from a tx's calldata. The signer (recovered from the tx)
/// is supplied separately as `from`/`caller` by the dispatcher in `lib.rs`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HumanityOp {
    /// `requestVerification(livenessRef)` — open a registration for the tx signer.
    RequestVerification { liveness_ref: Hash },
    /// `vouch(vouchee)` — the signer vouches for `vouchee`.
    Vouch { vouchee: AlloyAddr },
    /// `challenge(subject, evidenceRef)` — open a challenge against `subject`.
    Challenge {
        subject: AlloyAddr,
        evidence_ref: Hash,
    },
    /// `submitVerdict(caseId, verdict, confidence)` — a juror's canonical verdict.
    SubmitVerdict {
        case_id: u64,
        verdict: CanonicalVerdict,
    },
}

/// Why a HumanityHub calldata blob could not be turned into a [`HumanityOp`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CalldataError {
    /// Calldata shorter than a 4-byte selector.
    TooShort,
    /// Selector did not match any known HumanityHub write op.
    UnknownSelector([u8; 4]),
    /// Selector matched but the argument tail failed to ABI-decode.
    BadArgs(String),
    /// A `uint256` case-id argument exceeded the runtime's `u64` case-id range.
    Overflow(&'static str),
    /// `submitVerdict` carried a `verdict`/`confidence` byte outside the canonical enum range.
    BadVerdict(&'static str),
}

impl std::fmt::Display for CalldataError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CalldataError::TooShort => write!(f, "calldata too short for a selector"),
            CalldataError::UnknownSelector(s) => {
                let hex: String = s.iter().map(|b| format!("{b:02x}")).collect();
                write!(f, "unknown HumanityHub selector 0x{hex}")
            }
            CalldataError::BadArgs(e) => write!(f, "bad HumanityHub calldata args: {e}"),
            CalldataError::Overflow(which) => write!(f, "{which} exceeds the runtime range"),
            CalldataError::BadVerdict(which) => write!(f, "{which} is out of canonical enum range"),
        }
    }
}

/// Map the `uint8 verdict` ABI byte to the canonical [`Verdict`] enum (0=Human,1=Sybil,2=Uncertain).
fn verdict_from_u8(b: u8) -> Result<Verdict, CalldataError> {
    match b {
        0 => Ok(Verdict::Human),
        1 => Ok(Verdict::Sybil),
        2 => Ok(Verdict::Uncertain),
        _ => Err(CalldataError::BadVerdict("verdict")),
    }
}

/// Map the `uint8 confidence` ABI byte to the canonical [`Confidence`] enum (0=Low,1=Med,2=High).
fn confidence_from_u8(b: u8) -> Result<Confidence, CalldataError> {
    match b {
        0 => Ok(Confidence::Low),
        1 => Ok(Confidence::Med),
        2 => Ok(Confidence::High),
        _ => Err(CalldataError::BadVerdict("confidence")),
    }
}

/// Parse HumanityHub calldata (selector + ABI args) into a [`HumanityOp`]. Unknown selectors and
/// malformed args are surfaced distinctly so the RPC can return a precise error.
pub fn parse_calldata(data: &[u8]) -> Result<HumanityOp, CalldataError> {
    if data.len() < 4 {
        return Err(CalldataError::TooShort);
    }
    let selector: [u8; 4] = [data[0], data[1], data[2], data[3]];

    match selector {
        s if s == requestVerificationCall::SELECTOR => {
            let call = requestVerificationCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(HumanityOp::RequestVerification {
                liveness_ref: call.livenessRef.0,
            })
        }
        s if s == vouchCall::SELECTOR => {
            let call = vouchCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(HumanityOp::Vouch {
                vouchee: call.vouchee,
            })
        }
        s if s == challengeCall::SELECTOR => {
            let call = challengeCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(HumanityOp::Challenge {
                subject: call.subject,
                evidence_ref: call.evidenceRef.0,
            })
        }
        s if s == submitVerdictCall::SELECTOR => {
            let call = submitVerdictCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            if call.caseId > U256::from(u64::MAX) {
                return Err(CalldataError::Overflow("caseId"));
            }
            let verdict = verdict_from_u8(call.verdict)?;
            let confidence = confidence_from_u8(call.confidence)?;
            Ok(HumanityOp::SubmitVerdict {
                case_id: call.caseId.to::<u64>(),
                verdict: CanonicalVerdict::new(verdict, confidence),
            })
        }
        other => Err(CalldataError::UnknownSelector(other)),
    }
}

/// Derive deterministic stub liveness `(challenge, response)` bytes from the on-chain `livenessRef`
/// commitment (the seam to a real off-chain liveness exchange — M3 scope cut).
///
/// For the devnet, the applicant commits a `livenessRef` on-chain and the node reconstructs the bytes
/// the MockOracle grades from it: `challenge = keccak("ubi2-liveness-challenge" || ref)` and
/// `response = keccak("ubi2-liveness-response" || ref)`. Both are pure functions of the committed ref,
/// so every node derives identical bytes and the MockOracle's default `Human` verdict passes liveness
/// reproducibly (I1/I5). A real node swaps this for the actual challenge/response transcript behind
/// the same `(challenge, response)` shape.
pub fn derive_liveness(liveness_ref: &Hash) -> (Vec<u8>, Vec<u8>) {
    use alloy_primitives::keccak256;
    let mut c = Vec::with_capacity(23 + 32);
    c.extend_from_slice(b"ubi2-liveness-challenge");
    c.extend_from_slice(liveness_ref);
    let mut r = Vec::with_capacity(22 + 32);
    r.extend_from_slice(b"ubi2-liveness-response");
    r.extend_from_slice(liveness_ref);
    (
        keccak256(&c).as_slice().to_vec(),
        keccak256(&r).as_slice().to_vec(),
    )
}

/// 32-byte big-endian topic for a `u64` (left-padded) — used for indexed case ids in receipt logs.
pub fn u64_topic(v: u64) -> B256 {
    B256::from(U256::from(v))
}

/// 32-byte topic for an address (left-padded to 32 bytes, EVM-style).
pub fn addr_topic(a: &AlloyAddr) -> B256 {
    let mut b = [0u8; 32];
    b[12..].copy_from_slice(a.as_slice());
    B256::from(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    #[test]
    fn selectors_match_solidity() {
        assert_eq!(
            &requestVerificationCall::SELECTOR,
            &keccak256(b"requestVerification(bytes32)")[..4]
        );
        assert_eq!(&vouchCall::SELECTOR, &keccak256(b"vouch(address)")[..4]);
        assert_eq!(
            &challengeCall::SELECTOR,
            &keccak256(b"challenge(address,bytes32)")[..4]
        );
        assert_eq!(
            &submitVerdictCall::SELECTOR,
            &keccak256(b"submitVerdict(uint256,uint8,uint8)")[..4]
        );
    }

    #[test]
    fn hub_address_is_5048() {
        // ASCII "PH" in the low two bytes; distinct from StreamHub 0x…5742.
        assert_eq!(HUMANITY_HUB.as_slice()[18], 0x50);
        assert_eq!(HUMANITY_HUB.as_slice()[19], 0x48);
        assert_ne!(HUMANITY_HUB, crate::streams::STREAM_HUB);
    }

    #[test]
    fn parse_request_verification() {
        let ref_bytes: Hash = [0xab; 32];
        let data = requestVerificationCall {
            livenessRef: ref_bytes.into(),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            HumanityOp::RequestVerification {
                liveness_ref: ref_bytes
            }
        );
    }

    #[test]
    fn parse_vouch_and_challenge() {
        let vouchee = AlloyAddr::from([0x11; 20]);
        let data = vouchCall { vouchee }.abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            HumanityOp::Vouch { vouchee }
        );

        let subject = AlloyAddr::from([0x22; 20]);
        let ev: Hash = [0xcd; 32];
        let data = challengeCall {
            subject,
            evidenceRef: ev.into(),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            HumanityOp::Challenge {
                subject,
                evidence_ref: ev
            }
        );
    }

    #[test]
    fn parse_submit_verdict_maps_enums() {
        let data = submitVerdictCall {
            caseId: U256::from(7u8),
            verdict: 1,    // Sybil
            confidence: 2, // High
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            HumanityOp::SubmitVerdict {
                case_id: 7,
                verdict: CanonicalVerdict::new(Verdict::Sybil, Confidence::High),
            }
        );

        // Out-of-range verdict byte is rejected (fail closed).
        let bad = submitVerdictCall {
            caseId: U256::from(1u8),
            verdict: 9,
            confidence: 0,
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&bad).unwrap_err(),
            CalldataError::BadVerdict("verdict")
        );
    }

    #[test]
    fn derive_liveness_is_deterministic() {
        let r: Hash = [0x07; 32];
        let a = derive_liveness(&r);
        let b = derive_liveness(&r);
        assert_eq!(a, b, "liveness derivation must be reproducible (I1/I5)");
        assert_ne!(a.0, a.1, "challenge and response bytes differ");
        // A different ref yields different bytes.
        let c = derive_liveness(&[0x08; 32]);
        assert_ne!(a, c);
    }
}
