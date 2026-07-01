//! The shared, deterministic ordered-op APPLY kernel — the SINGLE source of truth for the state
//! transition of a block (ADR-0006 Decision 3, spec 07 §2.3). Both `crates/rpc::Chain::execute_block`
//! (server follower / proposer) and `crates/runtime-wasm::LightCore` (browser follower) call
//! [`apply_ops`], so they mutate state byte-identically: two honest nodes re-executing the same ordered
//! ops against the same parent state compute the same `state_root` (I1/I2).
//!
//! ## What this owns (and what the caller owns)
//! This kernel owns every **state mutation** a block performs: per-tx gas fee → the runtime op →
//! failed-tx nonce handling (the EVM-style "mine a failed tx" post-state) → the M3 sybil-scan +
//! finalize sweeps. It returns a [`Vec<OpOutcome>`] — one per input op, in order — carrying exactly the
//! result data the caller needs to build receipts/logs (success, revert reason, the op's primary return
//! value: a stream id, a case id, an assurance level). Logs/receipts/indexing/mempool/broadcast are
//! the caller's (server-only) concern — none of them touch `state_root`, so the light client skips them.
//!
//! ## The AI seam is a parameter, never embedded
//! The ops that consult the AI quorum at apply time — `requestVerification` (liveness), `invokeContract`
//! (the in-call interpreter quorum), `submitZkPassportProof` (the pairing check), and the sybil-scan
//! sweep — take the [`HumanityOracle`] / [`ContractInterpreter`] / [`ZkPassportVerifier`] as trait
//! parameters. The full node passes its configured impls (the deterministic Mocks on the consensus
//! path; a live backend when wired). The light client passes the SAME deterministic Mocks the consensus
//! path ships (I5), so it re-executes byte-identical. (`submitVerdict`/`submitEffect` carry the AI
//! verdict/effect IN the tx — applying them is pure, no seam call.)

use alloy_primitives::keccak256;

use ubi2_runtime::{
    apply_transfer, challenge as lc_challenge, charge_fee, deploy_contract as lc_deploy_contract,
    finalize_registration, fund_contract as lc_fund_contract,
    invoke_contract as lc_invoke_contract, open_stream, register_csca as lc_register_csca,
    request_verification, revoke_csca as lc_revoke_csca, stop_stream,
    submit_effect as lc_submit_effect, submit_verdict, submit_zk_passport_proof as lc_submit_zk,
    system_challenge as lc_system_challenge, vouch as lc_vouch, Account, Address, Assurance,
    ContractInterpreter, HumanStatus, HumanityOracle, LivenessEvidence, State, Verdict,
    ZkPassportVerifier, ZkProofSubmission,
};

use crate::op::{KernelKind, KernelTx, HUMANITY_HUB};

/// The per-op result the apply kernel returns to the caller, in block order. The caller (server)
/// uses it to build its `StoredTx`/receipt/logs; the light client ignores it (it only needs the
/// final `state_root`, which the mutations this kernel performed already determine).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpOutcome {
    /// Whether the op committed (`true`) or was MINED AS A FAILED tx (`false`, EVM-style: fee kept,
    /// nonce consumed, no op state change). Matches `crates/rpc`'s receipt `status`.
    pub success: bool,
    /// The decoded failure reason for a failed op (rendered runtime error), or `None` on success.
    pub revert_reason: Option<String>,
    /// The op's primary on-chain return value, for the caller's logs. `None` for ops with no id.
    pub result: OpResult,
}

/// The op-specific return value carried out of a successful op (for the caller's receipt logs).
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub enum OpResult {
    /// No id-bearing result (transfers, fund, csca ops, failed ops).
    #[default]
    None,
    /// `openStream` → the assigned stream id (for `StreamOpened` + the two ERC-721 mints).
    StreamId(u64),
    /// A HumanityHub/ContractHub op → the opened/affected case id (registration / challenge / verdict /
    /// invoke). For `submitVerdict`/`submitEffect` it is the case the op acted on.
    CaseId(u64),
    /// `submitZkPassportProof` → the assurance level the proof reached (no PII — I6).
    Assurance(Assurance),
}

/// Fold a block's `(hash, number)` into a `u64` chain-entropy word for deterministic juror selection —
/// byte-identical to `crates/rpc::block_entropy`. Both inputs are consensus values, so the entropy is
/// byte-reproducible across nodes (used ONLY to seed jury PRNG — never balances/roots).
pub fn block_entropy(block_hash: [u8; 32], number: u64) -> u64 {
    let mut word = [0u8; 8];
    word.copy_from_slice(&block_hash[..8]);
    u64::from_be_bytes(word) ^ number
}

/// Derive deterministic stub liveness `(challenge, response)` bytes from the on-chain `livenessRef` —
/// byte-identical to `crates/rpc::humanity::derive_liveness`.
pub fn derive_liveness(liveness_ref: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
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

/// Derive deterministic stand-in trigger bytes from `triggerRef` — byte-identical to
/// `crates/rpc::contracts::derive_trigger`.
pub fn derive_trigger(trigger_ref: &[u8; 32]) -> Vec<u8> {
    let mut t = Vec::with_capacity(21 + 32);
    t.extend_from_slice(b"ubi2-contract-trigger");
    t.extend_from_slice(trigger_ref);
    keccak256(&t).as_slice().to_vec()
}

/// Compute a contract's on-chain text commitment `keccak256(utf8(text))` — byte-identical to
/// `crates/rpc::contracts::text_commitment`.
pub fn text_commitment(text: &str) -> [u8; 32] {
    keccak256(text.as_bytes()).0
}

/// Consume + bump a sender's nonce for a non-transfer op (transfers enforce the nonce inside
/// `apply_transfer`). Settles emission first so `last_settled_at` advances consistently; on a mismatch
/// the state is untouched and the op is never reached. Byte-identical to `crates/rpc::consume_nonce`.
fn consume_nonce(
    state: &mut dyn State,
    from: &Address,
    nonce: u64,
    now: u64,
) -> Result<(), String> {
    let mut acct = state.get(from).unwrap_or(Account {
        address: *from,
        ..Default::default()
    });
    acct.settle(now);
    if nonce != acct.nonce {
        return Err(format!(
            "invalid nonce: expected {}, got {nonce}",
            acct.nonce
        ));
    }
    acct.nonce += 1;
    state.put(acct);
    Ok(())
}

/// Apply an ordered list of decoded ops to `state` at `timestamp`, running the M3 sweeps after the
/// user ops — the SINGLE deterministic state transition both followers share. `block_hash` is the
/// PRE-execution entropy hash (`number ‖ parent_hash ‖ timestamp ‖ 0 ‖ 0 ‖ 0`) the caller derives;
/// it feeds ONLY jury-selection entropy (never balances/roots), exactly as `execute_block` does.
///
/// Returns one [`OpOutcome`] per input op, in order. The state mutations performed (fees, ops, failed-
/// tx nonce post-states, sweeps) fully determine the post-block `state_root`.
#[allow(clippy::too_many_arguments)]
pub fn apply_ops(
    state: &mut dyn State,
    ops: &[KernelTx],
    timestamp: u64,
    number: u64,
    block_hash: [u8; 32],
    oracle: &dyn HumanityOracle,
    interpreter: &dyn ContractInterpreter,
    verifier: &dyn ZkPassportVerifier,
) -> Vec<OpOutcome> {
    let mut outcomes = Vec::with_capacity(ops.len());
    for tx in ops {
        if let Some(outcome) = apply_tx(
            state,
            tx,
            timestamp,
            number,
            block_hash,
            oracle,
            interpreter,
            verifier,
        ) {
            outcomes.push(outcome);
        }
    }
    run_sweeps(state, oracle, block_hash, number, timestamp);
    outcomes
}

/// Apply a SINGLE decoded tx (fee → op → failed-tx nonce post-state) and return its [`OpOutcome`], or
/// `None` if the sender could not afford even the gas fee (the tx is dropped, exactly as
/// `execute_block`'s `continue`). This is the per-op step both followers run in their tx loop so the
/// caller can build per-op receipts/logs at the SAME state-read timing the original code used; the
/// caller then calls [`run_sweeps`] ONCE after the loop. (The state mutations are identical to
/// [`apply_ops`] applied op-by-op.)
#[allow(clippy::too_many_arguments)]
pub fn apply_tx(
    state: &mut dyn State,
    tx: &KernelTx,
    timestamp: u64,
    number: u64,
    block_hash: [u8; 32],
    oracle: &dyn HumanityOracle,
    interpreter: &dyn ContractInterpreter,
    verifier: &dyn ZkPassportVerifier,
) -> Option<OpOutcome> {
    // ---- Real UBI gas fee, charged to the sender BEFORE the op (crediting the TREASURY) ----
    // A sender who cannot afford even the fee has its tx dropped (the proposer drops it too; a
    // follower never reaches this for a well-formed block).
    let gas = tx.kind.gas();
    if charge_fee(state, &tx.from, gas, timestamp).is_err() {
        return None;
    }

    let applied: Result<OpResult, String> = apply_one(
        state,
        tx,
        timestamp,
        number,
        block_hash,
        oracle,
        interpreter,
        verifier,
    );

    let outcome = match applied {
        Ok(result) => OpOutcome {
            success: true,
            revert_reason: None,
            result,
        },
        Err(e) => {
            // FAILED tx, EVM-style: keep the fee, set the nonce to its correct post-tx value
            // (`tx.nonce + 1` — idempotent across the validate-before-mutate transfer/fund path and the
            // consume-nonce-then-op hub path), apply NO op state change. The FIFO mempool + submit gate
            // guarantee `tx.nonce` is the sender's current nonce, so this is the one true deterministic
            // post-state (matches `execute_block`'s failed-tx branch).
            let mut acct = state.get(&tx.from).unwrap_or(Account {
                address: tx.from,
                ..Default::default()
            });
            acct.settle(timestamp);
            acct.nonce = tx.nonce + 1;
            state.put(acct);
            OpOutcome {
                success: false,
                revert_reason: Some(e),
                result: OpResult::None,
            }
        }
    };
    Some(outcome)
}

/// Run the M3 sweeps (deterministic, after the user ops; commit only clean cases — I4): the AI
/// sybil-scan auto-challenge then the auto-finalize. Both followers call this ONCE after the per-op
/// loop. Byte-identical state effect to `execute_block`'s sweep block (minus the logs).
pub fn run_sweeps(
    state: &mut dyn State,
    oracle: &dyn HumanityOracle,
    block_hash: [u8; 32],
    number: u64,
    timestamp: u64,
) {
    sweep_sybil_scan(state, oracle, block_hash, number);
    sweep_finalize(state, number, timestamp);
}

/// Apply a single op against `state` (the fee is already charged). Returns the op's primary result on
/// success, or a rendered error string on failure. Byte-identical op dispatch to `execute_block`.
#[allow(clippy::too_many_arguments)]
fn apply_one(
    state: &mut dyn State,
    tx: &KernelTx,
    timestamp: u64,
    number: u64,
    block_hash: [u8; 32],
    oracle: &dyn HumanityOracle,
    interpreter: &dyn ContractInterpreter,
    verifier: &dyn ZkPassportVerifier,
) -> Result<OpResult, String> {
    match &tx.kind {
        KernelKind::Transfer { to, value } => {
            apply_transfer(state, &tx.from, to, *value, tx.nonce, timestamp)
                .map(|()| OpResult::None)
                .map_err(|e| e.to_string())
        }

        KernelKind::OpenStream { to, rate, deposit } => {
            consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
                open_stream(state, &tx.from, to, *rate, *deposit, timestamp)
                    .map(OpResult::StreamId)
                    .map_err(|e| e.to_string())
            })
        }

        KernelKind::StopStream { id } => consume_nonce(state, &tx.from, tx.nonce, timestamp)
            .and_then(|()| {
                stop_stream(state, *id, &tx.from, timestamp)
                    .map(|_refund| OpResult::None)
                    .map_err(|e| e.to_string())
            }),

        KernelKind::RequestVerification { liveness_ref } => {
            consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
                let (challenge_bytes, response_bytes) = derive_liveness(liveness_ref);
                let evidence = LivenessEvidence {
                    liveness_ref: *liveness_ref,
                    challenge: &challenge_bytes,
                    response: &response_bytes,
                };
                let entropy = block_entropy(block_hash, number);
                request_verification(state, oracle, &tx.from, &evidence, entropy, number)
                    .map(OpResult::CaseId)
                    .map_err(|e| e.to_string())
            })
        }

        KernelKind::Vouch { vouchee } => consume_nonce(state, &tx.from, tx.nonce, timestamp)
            .and_then(|()| {
                lc_vouch(state, &tx.from, vouchee, number)
                    .map(|()| OpResult::None)
                    .map_err(|e| e.to_string())
            }),

        KernelKind::Challenge {
            subject,
            evidence_ref,
        } => consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
            let entropy = block_entropy(block_hash, number);
            lc_challenge(state, &tx.from, subject, *evidence_ref, entropy, number)
                .map(OpResult::CaseId)
                .map_err(|e| e.to_string())
        }),

        KernelKind::SubmitVerdict { case_id, verdict } => {
            consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
                submit_verdict(state, *case_id, &tx.from, *verdict, number)
                    .map(|_status| OpResult::CaseId(*case_id))
                    .map_err(|e| e.to_string())
            })
        }

        KernelKind::SubmitZkPassportProof {
            proof,
            nullifier,
            attribute_commitments,
            csca_registry_root,
            scheme_tag,
            now_epoch,
        } => consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
            let submission = ZkProofSubmission {
                proof: proof.clone(),
                nullifier: *nullifier,
                attribute_commitments: *attribute_commitments,
                csca_registry_root: *csca_registry_root,
                scheme_tag: *scheme_tag,
                now_epoch: *now_epoch,
            };
            lc_submit_zk(state, verifier, &tx.from, &submission, timestamp)
                .map(OpResult::Assurance)
                .map_err(|e| e.to_string())
        }),

        KernelKind::RegisterCsca {
            country_code,
            key_id,
            pubkey,
        } => consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
            lc_register_csca(
                state,
                &tx.from,
                *country_code,
                *key_id,
                pubkey.clone(),
                number,
            )
            .map(|()| OpResult::None)
            .map_err(|e| e.to_string())
        }),

        KernelKind::RevokeCsca { key_id } => consume_nonce(state, &tx.from, tx.nonce, timestamp)
            .and_then(|()| {
                lc_revoke_csca(state, &tx.from, key_id)
                    .map(|()| OpResult::None)
                    .map_err(|e| e.to_string())
            }),

        KernelKind::DeployContract { text, parties } => {
            let text_ref = text_commitment(text);
            consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
                lc_deploy_contract(state, text.clone(), text_ref, parties.clone())
                    .map(|id| {
                        // Stamp the deploy block height + tx hash onto the stored contract. Both fields
                        // are committed by `state_root` (see `runtime::state_root`), so this mutation is
                        // consensus-relevant and MUST be performed by the shared kernel on BOTH followers
                        // (it was previously hidden in the rpc log-builder). `tx.tx_hash` is the canonical
                        // EIP-2718 hash, identical on the proposer and a re-executing light node.
                        if let Some(mut c) = state.get_contract(id) {
                            c.deploy_block = number;
                            c.deploy_tx = tx.tx_hash;
                            state.put_contract(c);
                        }
                        OpResult::CaseId(id)
                    })
                    .map_err(|e| e.to_string())
            })
        }

        // `fund_contract` consumes the funder nonce itself (via the transfer path) — do NOT
        // `consume_nonce` here (that would double-count).
        KernelKind::FundContract { id } => {
            lc_fund_contract(state, &tx.from, *id, tx.value, tx.nonce, timestamp)
                .map(|()| OpResult::None)
                .map_err(|e| e.to_string())
        }

        KernelKind::InvokeContract { id, trigger_ref } => {
            consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
                let trigger = derive_trigger(trigger_ref);
                let entropy = block_entropy(block_hash, number);
                lc_invoke_contract(
                    state,
                    interpreter,
                    *id,
                    *trigger_ref,
                    &trigger,
                    tx.from,
                    entropy,
                    number,
                    timestamp,
                )
                .map(OpResult::CaseId)
                .map_err(|e| e.to_string())
            })
        }

        KernelKind::SubmitEffect { case_id, effect } => {
            consume_nonce(state, &tx.from, tx.nonce, timestamp).and_then(|()| {
                lc_submit_effect(state, *case_id, &tx.from, effect.clone(), number, timestamp)
                    .map(|_status| OpResult::CaseId(*case_id))
                    .map_err(|e| e.to_string())
            })
        }
    }
}

/// Auto-finalize every `Pending` registration whose challenge window has cleared and which satisfies
/// the finalize gate — byte-identical to `crates/rpc::sweep_finalize` (minus the logs, which do not
/// affect state). `now_block` is the window clock (block HEIGHT); `verified_at_secs` the emission epoch
/// (unix SECONDS). Fail-closed: a human that doesn't meet the gate is skipped silently (no mutation).
fn sweep_finalize(state: &mut dyn State, now_block: u64, verified_at_secs: u64) {
    let pending: Vec<Address> = state
        .humans()
        .into_iter()
        .filter(|h| h.status == HumanStatus::Pending)
        .map(|h| h.address)
        .collect();
    for subject in pending {
        let _ = finalize_registration(state, &subject, now_block, verified_at_secs);
    }
}

/// AI sybil-cluster auto-challenge sweep — byte-identical state effect to `crates/rpc::sweep_sybil_scan`
/// (minus the logs). For each `Pending` subject (address-sorted), run the oracle over the deterministic
/// vouch graph; on a `Sybil` flag auto-file a `system_challenge`. Skips a subject already challenged /
/// on cooldown (the runtime enforces both; benign errors are ignored).
fn sweep_sybil_scan(
    state: &mut dyn State,
    oracle: &dyn HumanityOracle,
    block_hash: [u8; 32],
    now_block: u64,
) {
    let pending: Vec<Address> = state
        .humans()
        .into_iter()
        .filter(|h| h.status == HumanStatus::Pending)
        .map(|h| h.address)
        .collect();
    for subject in pending {
        let graph = state.graph_view();
        if oracle.analyze_sybil(&graph, &subject).verdict != Verdict::Sybil {
            continue;
        }
        let evidence_ref = keccak256(
            [
                b"sybil-scan".as_slice(),
                subject.as_slice(),
                block_hash.as_slice(),
            ]
            .concat(),
        )
        .0;
        let entropy = block_entropy(block_hash, now_block);
        let _ = lc_system_challenge(
            state,
            &HUMANITY_HUB,
            &subject,
            evidence_ref,
            entropy,
            now_block,
        );
    }
}
