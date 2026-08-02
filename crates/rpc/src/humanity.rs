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

        // ---- M6: ZK-passport proof of humanity (spec 06 §4.1/§7.3) ----

        /// Submit a Self `vc_and_disclose` proof for the tx signer (spec 06b §4.3). Carries the Groth16
        /// `proof` + the **full** 21-signal public vector (snarkjs order, §4.1) + the `schemeTag`. The
        /// submitter address is NOT in calldata — it is `ecrecover(tx.sig)` (the tx sender), bound
        /// against `publicSignals[user_identifier]` so it cannot be forged (§4.4). Every policy slot is
        /// derived + bound on-chain by index.
        function submitZkPassportProof(
            bytes proof,
            bytes32[21] publicSignals,
            uint8 schemeTag,
            bytes userContextData
        ) external;
        /// Register a CSCA trust anchor (governance-gated — spec §7.3). RETAINED, reserved for the
        /// own-stack milestone (O-C1); inactive on the Self verify path.
        function registerCsca(bytes3 countryCode, bytes32 keyId, bytes pubkey) external;
        /// Revoke a CSCA trust anchor (governance-gated — spec §7.3/§7.4). RETAINED, reserved.
        function revokeCsca(bytes32 keyId) external;
        /// Pin an accepted Self identity-commitment root (governance-gated — spec 06b §2.2).
        function pinSelfIdentityRoot(bytes32 root) external;
        /// Pin an accepted Self OFAC SMT root of `kind` (0=passportno,1=namedob,2=nameyob) (§2.2).
        function pinSelfOfacRoot(uint8 kind, bytes32 root) external;
        /// Retire a Self root from the accepted sets (governance-gated — spec 06b §2.2).
        function retireSelfRoot(bytes32 root) external;

        /// Stage-D attribute verifier (read-only, `eth_call` — spec §4.4). Returns `true` iff `attrProof`
        /// is a valid Pedersen-opening + range proof that `subject`'s stored `attributeType` commitment
        /// satisfies the statement (e.g. over-18), WITHOUT revealing the DOB. `attributeType` is a keccak
        /// tag, e.g. `keccak256("over18")`. M6 ships only `over18`.
        function verifyAttribute(address subject, bytes32 attributeType, bytes attrProof) external view returns (bool);
    }
}

/// Re-export the generated call types so `lib.rs` can match on selectors without re-deriving them.
pub use IHumanityHub::{
    challengeCall, pinSelfIdentityRootCall, pinSelfOfacRootCall, registerCscaCall,
    requestVerificationCall, retireSelfRootCall, revokeCscaCall, submitVerdictCall,
    submitZkPassportProofCall, verifyAttributeCall, vouchCall,
};

/// The keccak tag for the `over18` attribute (`keccak256("over18")`) — the `verifyAttribute`
/// `attributeType` selector M6 ships. Computed once via a const-friendly helper at the call site.
pub fn over18_attribute_type() -> alloy_primitives::B256 {
    alloy_primitives::keccak256(b"over18")
}

/// A decoded HumanityHub *write* op, parsed from a tx's calldata. The signer (recovered from the tx)
/// is supplied separately as `from`/`caller` by the dispatcher in `lib.rs`.
// `SubmitZkPassportProof` carries the full 21-element public vector inline (`[Hash;21]`, spec 06b §4.3);
// this decoded-op enum is short-lived per-tx state, so the inline layout is intentional (no `Box`).
#[allow(clippy::large_enum_variant)]
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

    // ---- M6: ZK-passport ops ----
    /// `submitZkPassportProof(proof, publicSignals[21], schemeTag, userContextData)` — a Self
    /// `vc_and_disclose` proof for the tx signer (spec 06b §4.3, EC-C7). The submitter address is the tx
    /// sender (NOT a calldata field) — supplied separately by the dispatcher and bound TWO ways against
    /// `userContextData` (`[32:64]` low-20 == sender, and `hash160(userContextData)` == slot 20).
    SubmitZkPassportProof {
        proof: Vec<u8>,
        signals: [Hash; 21],
        scheme_tag: u8,
        user_context_data: Vec<u8>,
    },
    /// `registerCsca(countryCode, keyId, pubkey)` — governance-gated CSCA add (§7.3). RETAINED, reserved.
    RegisterCsca {
        country_code: [u8; 3],
        key_id: Hash,
        pubkey: Vec<u8>,
    },
    /// `revokeCsca(keyId)` — governance-gated CSCA revoke (§7.3/§7.4). RETAINED, reserved.
    RevokeCsca { key_id: Hash },
    /// `pinSelfIdentityRoot(root)` — governance-gated pin of an accepted Self identity root (06b §2.2).
    PinSelfIdentityRoot { root: Hash },
    /// `pinSelfOfacRoot(kind, root)` — governance-gated pin of an accepted OFAC SMT root (06b §2.2).
    PinSelfOfacRoot { kind: u8, root: Hash },
    /// `retireSelfRoot(root)` — governance-gated retire of a Self root (06b §2.2).
    RetireSelfRoot { root: Hash },
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
    /// A `submitZkPassportProof` proof blob was outside the accepted size bounds (spec §4.2 step 1).
    BadProofLength(usize),
    /// A `submitZkPassportProof` `userContextData` buffer exceeded the accepted size bound (EC-C7).
    BadUserContextLength(usize),
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
            CalldataError::BadProofLength(n) => {
                write!(f, "ZK proof length {n} is outside the accepted bounds")
            }
            CalldataError::BadUserContextLength(n) => {
                write!(f, "userContextData length {n} exceeds the accepted bound")
            }
        }
    }
}

/// Maximum accepted `submitZkPassportProof` proof-blob size (spec §4.2 step 1 bound-check). A Groth16
/// proof is ~200 bytes (3 compressed BN254 group elements); we accept a generous ceiling so a future
/// uncompressed/padded encoding still fits, while rejecting an unbounded blob at decode (DoS guard,
/// §11). The verifier itself fails closed on any malformed bytes within this bound.
pub const MAX_ZK_PROOF_BYTES: usize = 1024;

/// Maximum accepted `submitZkPassportProof` `userContextData` size (spec 06b §4.4, EC-C7) — byte-
/// identical to `ubi2_exec::op::MAX_USER_CONTEXT_DATA_BYTES`. A genuine buffer is ~106 bytes; an
/// unbounded blob is rejected at decode (DoS guard). The `< 64`-byte fail-closed lower bound + the
/// two-way submitter binding are enforced in the runtime, not here.
pub const MAX_USER_CONTEXT_DATA_BYTES: usize = 1024;

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
        s if s == submitZkPassportProofCall::SELECTOR => {
            let call = submitZkPassportProofCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            let proof = call.proof.to_vec();
            // Bound-check the proof length at decode (spec §4.2 step 1) — an unbounded blob never enters
            // the mempool / reaches the pairing check (DoS guard).
            if proof.is_empty() || proof.len() > MAX_ZK_PROOF_BYTES {
                return Err(CalldataError::BadProofLength(proof.len()));
            }
            // `bytes32[21]` decodes to a fixed array of `B256`; copy into `[Hash; 21]`.
            let mut signals = [[0u8; 32]; 21];
            for (i, sig) in call.publicSignals.iter().enumerate() {
                signals[i] = sig.0;
            }
            let user_context_data = call.userContextData.to_vec();
            if user_context_data.len() > MAX_USER_CONTEXT_DATA_BYTES {
                return Err(CalldataError::BadUserContextLength(user_context_data.len()));
            }
            Ok(HumanityOp::SubmitZkPassportProof {
                proof,
                signals,
                scheme_tag: call.schemeTag,
                user_context_data,
            })
        }
        s if s == registerCscaCall::SELECTOR => {
            let call = registerCscaCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(HumanityOp::RegisterCsca {
                country_code: call.countryCode.0,
                key_id: call.keyId.0,
                pubkey: call.pubkey.to_vec(),
            })
        }
        s if s == revokeCscaCall::SELECTOR => {
            let call = revokeCscaCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(HumanityOp::RevokeCsca {
                key_id: call.keyId.0,
            })
        }
        s if s == pinSelfIdentityRootCall::SELECTOR => {
            let call = pinSelfIdentityRootCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(HumanityOp::PinSelfIdentityRoot { root: call.root.0 })
        }
        s if s == pinSelfOfacRootCall::SELECTOR => {
            let call = pinSelfOfacRootCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(HumanityOp::PinSelfOfacRoot {
                kind: call.kind,
                root: call.root.0,
            })
        }
        s if s == retireSelfRootCall::SELECTOR => {
            let call = retireSelfRootCall::abi_decode(data, true)
                .map_err(|e| CalldataError::BadArgs(e.to_string()))?;
            Ok(HumanityOp::RetireSelfRoot { root: call.root.0 })
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
        assert_eq!(
            &submitZkPassportProofCall::SELECTOR,
            &keccak256(b"submitZkPassportProof(bytes,bytes32[21],uint8,bytes)")[..4]
        );
        assert_eq!(
            &registerCscaCall::SELECTOR,
            &keccak256(b"registerCsca(bytes3,bytes32,bytes)")[..4]
        );
        assert_eq!(
            &revokeCscaCall::SELECTOR,
            &keccak256(b"revokeCsca(bytes32)")[..4]
        );
        assert_eq!(
            &pinSelfIdentityRootCall::SELECTOR,
            &keccak256(b"pinSelfIdentityRoot(bytes32)")[..4]
        );
        assert_eq!(
            &pinSelfOfacRootCall::SELECTOR,
            &keccak256(b"pinSelfOfacRoot(uint8,bytes32)")[..4]
        );
        assert_eq!(
            &retireSelfRootCall::SELECTOR,
            &keccak256(b"retireSelfRoot(bytes32)")[..4]
        );
    }

    #[test]
    fn parse_submit_zk_passport_proof_roundtrips() {
        use alloy_primitives::{Bytes, FixedBytes};
        let proof = Bytes::from(vec![0xAB; 192]);
        let mut sig_bytes = [[0u8; 32]; 21];
        let mut fixed = [FixedBytes::<32>::from([0u8; 32]); 21];
        for i in 0..21 {
            let mut b = [0u8; 32];
            b[31] = i as u8;
            sig_bytes[i] = b;
            fixed[i] = FixedBytes::<32>::from(b);
        }
        let ucd = vec![0x11u8; 106];
        let data = submitZkPassportProofCall {
            proof: proof.clone(),
            publicSignals: fixed,
            schemeTag: 0,
            userContextData: Bytes::from(ucd.clone()),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            HumanityOp::SubmitZkPassportProof {
                proof: vec![0xAB; 192],
                signals: sig_bytes,
                scheme_tag: 0,
                user_context_data: ucd,
            }
        );

        // An over-long proof blob is rejected at decode (bound-check, §4.4 step 1).
        let big = submitZkPassportProofCall {
            proof: Bytes::from(vec![0u8; MAX_ZK_PROOF_BYTES + 1]),
            publicSignals: fixed,
            schemeTag: 0,
            userContextData: Bytes::from(vec![0u8; 106]),
        }
        .abi_encode();
        assert!(matches!(
            parse_calldata(&big).unwrap_err(),
            CalldataError::BadProofLength(_)
        ));

        // An over-long userContextData buffer is rejected at decode (EC-C7 DoS bound).
        let big_ucd = submitZkPassportProofCall {
            proof: proof.clone(),
            publicSignals: fixed,
            schemeTag: 0,
            userContextData: Bytes::from(vec![0u8; MAX_USER_CONTEXT_DATA_BYTES + 1]),
        }
        .abi_encode();
        assert!(matches!(
            parse_calldata(&big_ucd).unwrap_err(),
            CalldataError::BadUserContextLength(_)
        ));
    }

    #[test]
    fn parse_csca_governance_ops() {
        use alloy_primitives::{Bytes, FixedBytes};
        let key_id: Hash = [0xD1; 32];
        let data = registerCscaCall {
            countryCode: FixedBytes::<3>::from([b'U', b'S', b'A']),
            keyId: key_id.into(),
            pubkey: Bytes::from(vec![9, 9, 9]),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            HumanityOp::RegisterCsca {
                country_code: [b'U', b'S', b'A'],
                key_id,
                pubkey: vec![9, 9, 9],
            }
        );

        let data = revokeCscaCall {
            keyId: key_id.into(),
        }
        .abi_encode();
        assert_eq!(
            parse_calldata(&data).unwrap(),
            HumanityOp::RevokeCsca { key_id }
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
