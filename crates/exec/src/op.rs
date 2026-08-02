//! The shared decoded-op model (`KernelKind` / `KernelTx`) and the canonical tx decode.
//!
//! This is the SINGLE decode the server follower (`crates/rpc`) and the browser follower
//! (`crates/runtime-wasm`) both run (ADR-0006 Decision 3 — "no logic fork"). A raw EIP-155 tx decodes
//! to a `KernelTx` via the SAME `alloy`/`k256` path (`decode_2718` + EIP-155 chain-id bind + signer
//! recovery + per-hub calldata shape) on both, so a block decodes byte-identically. The hub calldata
//! ABIs are declared with `sol!` so the 4-byte selectors derive from the canonical Solidity-style
//! signatures — identical to the wallet's encoding and to the runtime/rpc selectors.

use alloy_consensus::{Transaction as _, TxEnvelope};
use alloy_eips::eip2718::Decodable2718;
use alloy_primitives::U256;
use alloy_sol_types::SolCall;

use ubi2_runtime::{
    CanonicalEffect, CanonicalVerdict, Confidence, Verdict, CONTRACT_HUB as RT_CONTRACT_HUB,
    MAX_CONTRACT_PARTIES, MAX_CONTRACT_TEXT_BYTES,
};

/// The reserved StreamHub system address (`0x…5742`, spec D2) — byte-identical to
/// `crates/rpc::streams::STREAM_HUB`. Stream ops are EVM txs whose `to` is this address.
pub const STREAM_HUB: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x57, 0x42,
];
/// The reserved HumanityHub system address (`0x…5048`, spec 03/06).
pub const HUMANITY_HUB: [u8; 20] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x50, 0x48,
];
/// The reserved ContractHub system address (`0x…5043`, spec 04). Sourced from the runtime constant.
pub const CONTRACT_HUB: [u8; 20] = RT_CONTRACT_HUB;

/// Maximum accepted `submitZkPassportProof` proof-blob size (spec §4.2 step 1) — byte-identical to
/// `crates/rpc::humanity::MAX_ZK_PROOF_BYTES`. An unbounded blob is rejected at decode (DoS guard).
pub const MAX_ZK_PROOF_BYTES: usize = 1024;

/// Maximum accepted `submitZkPassportProof` `userContextData` size (spec 06b §4.4, EC-C7) — byte-
/// identical to `crates/rpc::humanity::MAX_USER_CONTEXT_DATA_BYTES`. A genuine buffer is ~106 bytes
/// (`destChainId(32) || userId(32) || userDefinedData`); an absurd blob is rejected at decode (DoS
/// guard, mirroring the proof-blob bound). The `< 64`-byte fail-closed lower bound + the two-way
/// submitter binding are enforced in the runtime (`submit_zk_passport_proof`).
pub const MAX_USER_CONTEXT_DATA_BYTES: usize = 1024;

// The hub calldata ABIs. `sol!` derives the 4-byte selectors from the canonical signatures, so they
// equal the wallet's encoding and the rpc/runtime selectors byte-for-byte.
alloy_sol_types::sol! {
    // StreamHub (spec D2).
    function openStream(address to, uint256 ratePerSec, uint256 deposit) external returns (uint256 id);
    function stopStream(uint256 id) external;

    // HumanityHub (spec 03 / 06).
    function requestVerification(bytes32 livenessRef) external;
    function vouch(address vouchee) external;
    function challenge(address subject, bytes32 evidenceRef) external;
    function submitVerdict(uint256 caseId, uint8 verdict, uint8 confidence) external;
    function submitZkPassportProof(
        bytes proof,
        bytes32[21] publicSignals,
        uint8 schemeTag,
        bytes userContextData
    ) external;
    function registerCsca(bytes3 countryCode, bytes32 keyId, bytes pubkey) external;
    function revokeCsca(bytes32 keyId) external;
    function pinSelfIdentityRoot(bytes32 root) external;
    function pinSelfOfacRoot(uint8 kind, bytes32 root) external;
    function retireSelfRoot(bytes32 root) external;

    // ContractHub (spec 04).
    function deployContract(string text, address[] parties) external returns (uint256 id);
    function fundContract(uint256 id) external payable;
    function invokeContract(uint256 id, bytes32 triggerRef) external returns (uint256 caseId);
    function submitEffect(uint256 caseId, bytes ops) external;

    // StreamHub soulbound ERC-721 mutators — these MUST revert (no transfer/approve state, spec D4).
    function transferFrom(address from, address to, uint256 tokenId) external;
    function safeTransferFrom(address from, address to, uint256 tokenId) external;
    function approve(address to, uint256 tokenId) external;
    function setApprovalForAll(address operator, bool approved) external;
}

/// What a decoded tx does when applied — the kernel's op model. Mirrors `crates/rpc::PendingKind`
/// field-for-field (the rpc enum maps 1:1 to this), so the shared apply path is the one source of truth.
// `SubmitZkPassportProof` carries the full 21-element public vector inline (`[[u8;32];21]`, spec 06b
// §4.3 full-vector carriage), making it the dominant variant; the enum is short-lived per-tx decode
// state, so the inline layout is intentional over a `Box` indirection.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KernelKind {
    /// Plain value transfer to `to`.
    Transfer { to: [u8; 20], value: u128 },
    /// `openStream`: open `from → to` at `rate`, locking `deposit`.
    OpenStream {
        to: [u8; 20],
        rate: u128,
        deposit: u128,
    },
    /// `stopStream`: stop stream `id` (signer must be the sender).
    StopStream { id: u64 },

    // ---- M3: proof-of-humanity ops ----
    /// `requestVerification(livenessRef)`: open a registration for the signer.
    RequestVerification { liveness_ref: [u8; 32] },
    /// `vouch(vouchee)`: the (Verified) signer vouches for `vouchee`.
    Vouch { vouchee: [u8; 20] },
    /// `challenge(subject, evidenceRef)`: open a challenge against `subject`.
    Challenge {
        subject: [u8; 20],
        evidence_ref: [u8; 32],
    },
    /// `submitVerdict(caseId, verdict, confidence)`: a juror's canonical verdict.
    SubmitVerdict {
        case_id: u64,
        verdict: CanonicalVerdict,
    },

    // ---- M6: ZK-passport ops ----
    /// `submitZkPassportProof(proof, publicSignals[21], schemeTag, userContextData)`: verify a Self
    /// `vc_and_disclose` proof for the signer, carrying the full 21-signal vector + the raw
    /// `userContextData` buffer the submitter binding recomputes `hash160` over (spec 06b §4.3, EC-C7).
    SubmitZkPassportProof {
        proof: Vec<u8>,
        signals: [[u8; 32]; 21],
        scheme_tag: u8,
        user_context_data: Vec<u8>,
    },
    /// `registerCsca(countryCode, keyId, pubkey)`: governance-gated CSCA add (§7.3). RETAINED, reserved.
    RegisterCsca {
        country_code: [u8; 3],
        key_id: [u8; 32],
        pubkey: Vec<u8>,
    },
    /// `revokeCsca(keyId)`: governance-gated CSCA revoke (§7.3/§7.4). RETAINED, reserved.
    RevokeCsca { key_id: [u8; 32] },
    /// `pinSelfIdentityRoot(root)`: governance-gated pin of an accepted Self identity root (06b §2.2).
    PinSelfIdentityRoot { root: [u8; 32] },
    /// `pinSelfOfacRoot(kind, root)`: governance-gated pin of an accepted OFAC SMT root (06b §2.2).
    PinSelfOfacRoot { kind: u8, root: [u8; 32] },
    /// `retireSelfRoot(root)`: governance-gated retire of a Self root (06b §2.2).
    RetireSelfRoot { root: [u8; 32] },

    // ---- M4: prompt-contract ops ----
    /// `deployContract(text, parties)`: register an `Active` contract for the signer.
    DeployContract {
        text: String,
        parties: Vec<[u8; 20]>,
    },
    /// `fundContract(id)`: fund contract `id`'s escrow with the tx's value.
    FundContract { id: u64 },
    /// `invokeContract(id, triggerRef)`: open an ExecCase; the interpreter quorum runs at block time.
    InvokeContract { id: u64, trigger_ref: [u8; 32] },
    /// `submitEffect(caseId, ops)`: an interpreter's canonical effect (deferred juror-daemon path).
    SubmitEffect {
        case_id: u64,
        effect: CanonicalEffect,
    },
}

impl KernelKind {
    /// The per-kind gas — byte-identical to `crates/rpc::gas_for_kind`. The fee `gas * gas_price` is
    /// charged to the sender before the op (crediting the treasury).
    pub fn gas(&self) -> u64 {
        use ubi2_runtime::{
            gas_for_deploy, GAS_CONTRACT, GAS_CSCA_GOV, GAS_HUMANITY, GAS_ONBOARD, GAS_STREAM,
            GAS_TRANSFER, GAS_ZKPOH,
        };
        match self {
            KernelKind::Transfer { .. } => GAS_TRANSFER,
            KernelKind::OpenStream { .. } | KernelKind::StopStream { .. } => GAS_STREAM,
            KernelKind::RequestVerification { .. } => GAS_ONBOARD,
            KernelKind::Vouch { .. }
            | KernelKind::Challenge { .. }
            | KernelKind::SubmitVerdict { .. } => GAS_HUMANITY,
            KernelKind::SubmitZkPassportProof { .. } => GAS_ZKPOH,
            KernelKind::RegisterCsca { .. }
            | KernelKind::RevokeCsca { .. }
            | KernelKind::PinSelfIdentityRoot { .. }
            | KernelKind::PinSelfOfacRoot { .. }
            | KernelKind::RetireSelfRoot { .. } => GAS_CSCA_GOV,
            KernelKind::DeployContract { text, .. } => gas_for_deploy(text.len()),
            KernelKind::FundContract { .. }
            | KernelKind::InvokeContract { .. }
            | KernelKind::SubmitEffect { .. } => GAS_CONTRACT,
        }
    }
}

/// A decoded tx ready for the apply kernel: the recovered signer, nonce, value, and op kind. The
/// caller (rpc or wasm) decodes the raw bytes once into this and hands an ordered `Vec<KernelTx>` to
/// [`crate::apply::apply_ops`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KernelTx {
    /// The canonical EIP-2718 tx hash (`keccak256(raw)`). Consensus-relevant: a `deployContract` stamps
    /// it onto the stored contract record as `deploy_tx`, which IS committed by `state_root` — so both
    /// followers MUST stamp the same hash. `decode_tx` fills it; a caller building a `KernelTx` by hand
    /// must set the canonical tx hash.
    pub tx_hash: [u8; 32],
    /// The recovered (ecrecover) tx sender.
    pub from: [u8; 20],
    /// The tx nonce.
    pub nonce: u64,
    /// The tx value in base units (0 for stream ops; the escrow funding for `fundContract`).
    pub value: u128,
    /// The decoded op.
    pub kind: KernelKind,
}

/// Why a raw tx did not decode into a [`KernelTx`]. The caller maps this to its own error surface
/// (rpc → a JSON-RPC error; wasm → a `VerifyError`). Fail-closed: an undecodable tx in a block ⇒ the
/// block is rejected, never partially applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The raw bytes did not RLP/2718-decode.
    Rlp(String),
    /// The tx is not EIP-155 chain-id-bound, or is bound to a different chain (replay protection).
    WrongChain { expected: u64, got: Option<u64> },
    /// Signer recovery failed (bad signature).
    BadSignature(String),
    /// Contract creation (`to == None`) is not supported.
    ContractCreation,
    /// Calldata to a plain (non-hub) address — only value transfers are allowed there.
    UnexpectedCalldata,
    /// A value did not fit the runtime's `u128` base-unit range.
    ValueOverflow(&'static str),
    /// A hub calldata blob was malformed (selector/args). Carries a human-readable reason.
    BadCalldata(String),
    /// A soulbound StreamHub ERC-721 mutator (transfer/approve) was sent as a write tx — must revert
    /// ("soulbound", spec D4). Distinct from an unknown selector so the caller can surface the exact
    /// revert message the M2 acceptance suite asserts.
    Soulbound,
}

impl core::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DecodeError::Rlp(e) => write!(f, "rlp decode failed: {e}"),
            DecodeError::WrongChain { expected, got } => match got {
                Some(g) => write!(f, "wrong chainId: tx is for {g}, chain is {expected}"),
                None => write!(f, "tx must be EIP-155 (chainId-bound) for replay safety"),
            },
            DecodeError::BadSignature(e) => write!(f, "signature recovery failed: {e}"),
            DecodeError::ContractCreation => write!(f, "contract creation not supported"),
            DecodeError::UnexpectedCalldata => write!(
                f,
                "calldata only supported for the system hubs (value transfers otherwise)"
            ),
            DecodeError::ValueOverflow(which) => write!(f, "{which} exceeds u128 base-unit range"),
            DecodeError::BadCalldata(e) => write!(f, "bad hub calldata: {e}"),
            DecodeError::Soulbound => write!(f, "soulbound"),
        }
    }
}

impl std::error::Error for DecodeError {}

fn u256_to_u128(v: U256, which: &'static str) -> Result<u128, DecodeError> {
    v.try_into().map_err(|_| DecodeError::ValueOverflow(which))
}

/// Decode + structurally-validate a raw EIP-155 tx into a [`KernelTx`]. This is the SINGLE decode the
/// server follower and the browser follower share (ADR-0006 Decision 3). `value` for a `fundContract`
/// is the tx's `msg.value`; for a transfer it is the transfer amount; for every other op it is 0.
pub fn decode_tx(chain_id: u64, raw: &[u8]) -> Result<KernelTx, DecodeError> {
    let mut slice = raw;
    let env = TxEnvelope::decode_2718(&mut slice).map_err(|e| DecodeError::Rlp(e.to_string()))?;
    let tx_hash = *env.tx_hash();

    // EIP-155 chain-id binding (replay protection): require explicit binding to our chain.
    match env.chain_id() {
        Some(id) if id == chain_id => {}
        other => {
            return Err(DecodeError::WrongChain {
                expected: chain_id,
                got: other,
            })
        }
    }

    let from = env
        .recover_signer()
        .map_err(|e| DecodeError::BadSignature(e.to_string()))?
        .into_array();
    let to = env.to().ok_or(DecodeError::ContractCreation)?.into_array();
    let nonce = env.nonce();
    let input = env.input().to_vec();
    let value_u256 = env.value();

    let kind = if to == STREAM_HUB {
        parse_stream(&input)?
    } else if to == HUMANITY_HUB {
        parse_humanity(&input)?
    } else if to == CONTRACT_HUB {
        parse_contract(&input)?
    } else {
        if !input.is_empty() {
            return Err(DecodeError::UnexpectedCalldata);
        }
        KernelKind::Transfer {
            to,
            value: u256_to_u128(value_u256, "value")?,
        }
    };

    // The deposit for stream ops is a calldata arg (value == 0); `fundContract` is value-bearing.
    let value: u128 = match &kind {
        KernelKind::Transfer { value, .. } => *value,
        KernelKind::FundContract { .. } => u256_to_u128(value_u256, "value")?,
        _ => 0,
    };

    Ok(KernelTx {
        tx_hash: tx_hash.0,
        from,
        nonce,
        value,
        kind,
    })
}

fn parse_stream(data: &[u8]) -> Result<KernelKind, DecodeError> {
    let selector = selector_of(data)?;
    if selector == openStreamCall::SELECTOR {
        let call = openStreamCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("openStream: {e}")))?;
        Ok(KernelKind::OpenStream {
            to: call.to.into_array(),
            rate: u256_to_u128(call.ratePerSec, "ratePerSec")?,
            deposit: u256_to_u128(call.deposit, "deposit")?,
        })
    } else if selector == stopStreamCall::SELECTOR {
        let call = stopStreamCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("stopStream: {e}")))?;
        if call.id > U256::from(u64::MAX) {
            return Err(DecodeError::ValueOverflow("stream id"));
        }
        Ok(KernelKind::StopStream {
            id: call.id.to::<u64>(),
        })
    } else if selector == transferFromCall::SELECTOR
        || selector == safeTransferFromCall::SELECTOR
        || selector == approveCall::SELECTOR
        || selector == setApprovalForAllCall::SELECTOR
    {
        // Soulbound (spec D4): any transfer/approve selector to StreamHub reverts.
        Err(DecodeError::Soulbound)
    } else {
        Err(DecodeError::BadCalldata(format!(
            "unknown StreamHub selector 0x{}",
            hex4(&selector)
        )))
    }
}

fn parse_humanity(data: &[u8]) -> Result<KernelKind, DecodeError> {
    let selector = selector_of(data)?;
    if selector == requestVerificationCall::SELECTOR {
        let call = requestVerificationCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("requestVerification: {e}")))?;
        Ok(KernelKind::RequestVerification {
            liveness_ref: call.livenessRef.0,
        })
    } else if selector == vouchCall::SELECTOR {
        let call = vouchCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("vouch: {e}")))?;
        Ok(KernelKind::Vouch {
            vouchee: call.vouchee.into_array(),
        })
    } else if selector == challengeCall::SELECTOR {
        let call = challengeCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("challenge: {e}")))?;
        Ok(KernelKind::Challenge {
            subject: call.subject.into_array(),
            evidence_ref: call.evidenceRef.0,
        })
    } else if selector == submitVerdictCall::SELECTOR {
        let call = submitVerdictCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("submitVerdict: {e}")))?;
        if call.caseId > U256::from(u64::MAX) {
            return Err(DecodeError::ValueOverflow("caseId"));
        }
        let verdict = verdict_from_u8(call.verdict)?;
        let confidence = confidence_from_u8(call.confidence)?;
        Ok(KernelKind::SubmitVerdict {
            case_id: call.caseId.to::<u64>(),
            verdict: CanonicalVerdict::new(verdict, confidence),
        })
    } else if selector == submitZkPassportProofCall::SELECTOR {
        let call = submitZkPassportProofCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("submitZkPassportProof: {e}")))?;
        let proof = call.proof.to_vec();
        if proof.is_empty() || proof.len() > MAX_ZK_PROOF_BYTES {
            return Err(DecodeError::BadCalldata(format!(
                "ZK proof length {} is outside the accepted bounds",
                proof.len()
            )));
        }
        let mut signals = [[0u8; 32]; 21];
        for (i, s) in call.publicSignals.iter().enumerate() {
            signals[i] = s.0;
        }
        let user_context_data = call.userContextData.to_vec();
        if user_context_data.len() > MAX_USER_CONTEXT_DATA_BYTES {
            return Err(DecodeError::BadCalldata(format!(
                "userContextData length {} exceeds the accepted bound",
                user_context_data.len()
            )));
        }
        Ok(KernelKind::SubmitZkPassportProof {
            proof,
            signals,
            scheme_tag: call.schemeTag,
            user_context_data,
        })
    } else if selector == registerCscaCall::SELECTOR {
        let call = registerCscaCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("registerCsca: {e}")))?;
        Ok(KernelKind::RegisterCsca {
            country_code: call.countryCode.0,
            key_id: call.keyId.0,
            pubkey: call.pubkey.to_vec(),
        })
    } else if selector == revokeCscaCall::SELECTOR {
        let call = revokeCscaCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("revokeCsca: {e}")))?;
        Ok(KernelKind::RevokeCsca {
            key_id: call.keyId.0,
        })
    } else if selector == pinSelfIdentityRootCall::SELECTOR {
        let call = pinSelfIdentityRootCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("pinSelfIdentityRoot: {e}")))?;
        Ok(KernelKind::PinSelfIdentityRoot { root: call.root.0 })
    } else if selector == pinSelfOfacRootCall::SELECTOR {
        let call = pinSelfOfacRootCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("pinSelfOfacRoot: {e}")))?;
        Ok(KernelKind::PinSelfOfacRoot {
            kind: call.kind,
            root: call.root.0,
        })
    } else if selector == retireSelfRootCall::SELECTOR {
        let call = retireSelfRootCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("retireSelfRoot: {e}")))?;
        Ok(KernelKind::RetireSelfRoot { root: call.root.0 })
    } else {
        Err(DecodeError::BadCalldata(format!(
            "unknown HumanityHub selector 0x{}",
            hex4(&selector)
        )))
    }
}

fn parse_contract(data: &[u8]) -> Result<KernelKind, DecodeError> {
    let selector = selector_of(data)?;
    if selector == deployContractCall::SELECTOR {
        let call = deployContractCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("deployContract: {e}")))?;
        if call.text.len() > MAX_CONTRACT_TEXT_BYTES {
            return Err(DecodeError::BadCalldata(format!(
                "contract text length {} exceeds the on-chain storage cap of {} bytes",
                call.text.len(),
                MAX_CONTRACT_TEXT_BYTES
            )));
        }
        if call.parties.len() > MAX_CONTRACT_PARTIES {
            return Err(DecodeError::BadCalldata(format!(
                "parties count {} exceeds the cap of {}",
                call.parties.len(),
                MAX_CONTRACT_PARTIES
            )));
        }
        Ok(KernelKind::DeployContract {
            text: call.text,
            parties: call.parties.into_iter().map(|a| a.into_array()).collect(),
        })
    } else if selector == fundContractCall::SELECTOR {
        let call = fundContractCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("fundContract: {e}")))?;
        if call.id > U256::from(u64::MAX) {
            return Err(DecodeError::ValueOverflow("contract id"));
        }
        Ok(KernelKind::FundContract {
            id: call.id.to::<u64>(),
        })
    } else if selector == invokeContractCall::SELECTOR {
        let call = invokeContractCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("invokeContract: {e}")))?;
        if call.id > U256::from(u64::MAX) {
            return Err(DecodeError::ValueOverflow("contract id"));
        }
        Ok(KernelKind::InvokeContract {
            id: call.id.to::<u64>(),
            trigger_ref: call.triggerRef.0,
        })
    } else if selector == submitEffectCall::SELECTOR {
        let call = submitEffectCall::abi_decode(data, true)
            .map_err(|e| DecodeError::BadCalldata(format!("submitEffect: {e}")))?;
        if call.caseId > U256::from(u64::MAX) {
            return Err(DecodeError::ValueOverflow("caseId"));
        }
        let effect = decode_effect(&call.ops)
            .map_err(|e| DecodeError::BadCalldata(format!("effect ops: {e}")))?;
        Ok(KernelKind::SubmitEffect {
            case_id: call.caseId.to::<u64>(),
            effect,
        })
    } else {
        Err(DecodeError::BadCalldata(format!(
            "unknown ContractHub selector 0x{}",
            hex4(&selector)
        )))
    }
}

fn selector_of(data: &[u8]) -> Result<[u8; 4], DecodeError> {
    if data.len() < 4 {
        return Err(DecodeError::BadCalldata("calldata too short".into()));
    }
    Ok([data[0], data[1], data[2], data[3]])
}

fn hex4(s: &[u8; 4]) -> String {
    s.iter().map(|b| format!("{b:02x}")).collect()
}

fn verdict_from_u8(b: u8) -> Result<Verdict, DecodeError> {
    match b {
        0 => Ok(Verdict::Human),
        1 => Ok(Verdict::Sybil),
        2 => Ok(Verdict::Uncertain),
        _ => Err(DecodeError::BadCalldata("verdict out of range".into())),
    }
}

fn confidence_from_u8(b: u8) -> Result<Confidence, DecodeError> {
    match b {
        0 => Ok(Confidence::Low),
        1 => Ok(Confidence::Med),
        2 => Ok(Confidence::High),
        _ => Err(DecodeError::BadCalldata("confidence out of range".into())),
    }
}

/// Decode a `CanonicalEffect` from its on-chain `ops` blob — byte-identical to
/// `crates/rpc::contracts::decode_effect`. The encoding is `count(u32) ‖ [op]`, each op a tagged
/// `(payer?, payee?, amount(u128 be))` triple. Fail-closed on any malformed/over-long blob.
fn decode_effect(ops: &[u8]) -> Result<CanonicalEffect, String> {
    // Mirror of the rpc codec (`encode_effect`/`decode_effect`). Layout per op:
    //   tag(1): 0 = Pay { from, to, amount }, 1 = OpenStream { from, to, rate, deposit }, etc.
    // To stay the single source of truth WITHOUT duplicating the rpc codec, we re-use the rpc one by
    // shape: a length-prefixed list of canonical ops. See `crate::effect_codec`.
    crate::effect_codec::decode_effect(ops)
}
