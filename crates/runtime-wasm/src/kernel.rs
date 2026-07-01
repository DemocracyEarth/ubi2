//! `LightCore` — the browser follower's block re-execution kernel (spec 07 §2.3, ADR-0006 Decision 3).
//!
//! This is the pure, async-free, networking-free re-execution path the browser light node runs to
//! **verify** a `WireBlock`: decode each raw EIP-155 tx, re-execute it against a `MemState` at
//! `block.timestamp`, recompute `txs_root` + `state_root`, and accept the block only if those roots
//! match the header **byte-for-byte**. It is the same trust guarantee a server follower
//! (`crates/rpc::Chain::validate_and_apply_block`) has — a lying gateway is *caught*, not trusted.
//!
//! ## One shared kernel — no logic fork (ADR-0006 Decision 3)
//! The decode + apply is the **shared** `crates/exec` kernel (`ubi2_exec::decode_tx` +
//! `ubi2_exec::apply_ops`) that the full node's `crates/rpc::execute_block` ALSO calls. The browser
//! follower and the server follower therefore run the SAME ordered-op state transition (charge_fee →
//! the runtime op → the EVM-style failed-tx nonce post-state → the M3 sybil/finalize sweeps), so a
//! block re-executes to a byte-identical `state_root` on both. The parity gate (`tests/parity.rs`,
//! AC-WB) proves it for transfers, streaming, PoH vouching, prompt contracts, AND ZK-passport blocks.
//!
//! ## Full block-kind coverage — re-execution needs NO AI
//! Stage 2 lifts the Stage-1 `UnsupportedKind` fail-close: the light node re-executes EVERY block kind.
//! The key insight (ADR-0006): re-executing a block is deterministic and needs no AI. The AI (PoH jury
//! verdicts, contract interpretation, ZK proving) happens when a juror/proposer/prover PRODUCES a tx
//! (`submitVerdict` / `submitEffect` / `submitZkPassportProof`); APPLYING that tx to state is pure. The
//! few apply-time seam calls that remain (`requestVerification` liveness grading, `invokeContract`'s
//! in-call interpreter quorum, the sybil-scan sweep, and the `submitZkPassportProof` pairing check) are
//! parameterized over the seam traits; the light client passes the SAME deterministic Mock impls the
//! consensus/devnet path ships (`MockOracle`/`MockInterpreter`/`MockZkVerifier`, all pure, in
//! `crates/runtime`), so it re-executes byte-identical without ever running a model.
//!
//! See `kernel.rs`'s module footer for the one documented fail-closed boundary (a chain wired with a
//! *live* — non-Mock — AI backend on the consensus path; out of scope for the devnet / Stage 1–2 model).

use ubi2_runtime::{
    state_root as runtime_state_root, MemState, MockInterpreter, MockOracle, MockZkVerifier, State,
};

use alloy_primitives::{keccak256, B256};

use crate::wire::WireBlock;

/// Why a `WireBlock` failed verification. Every variant is **fail-closed**: the block is NOT applied to
/// the verified state and the tip does not advance (I4 on the client; spec §3.2 step 3 / AC-F-LN1/3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyError {
    /// The block did not decode from its canonical wire bytes.
    BadWire(String),
    /// `shallow_verify` failed: `txs_root` inconsistent OR an unsigned/forged-proposer block
    /// (SEC-M5A-1) — an unsigned block is never trusted for its height.
    ShallowVerify,
    /// The block's height is not exactly `tip + 1` (out of order — the driver must fill the gap).
    NonContiguous { have: u64, got: u64 },
    /// `parent_hash` does not link to the verified tip (a different chain / fork).
    WrongParent,
    /// `timestamp` is not strictly greater than the parent's.
    BadTimestamp,
    /// `proposer` is not the expected (scheduled) proposer, when one was supplied.
    WrongProposer,
    /// The block's `proposer` is not in the pinned PoA validator set (`ln-trust-1` — proposer authority
    /// is enforced on EVERY block; a self-signed block from an unauthorized key is rejected, never
    /// "verified"). Fail-closed; the tip never advances.
    UnauthorizedProposer { proposer: [u8; 20] },
    /// A raw tx in the block did not decode (malformed/forged block).
    UndecodableTx(String),
    /// Re-execution produced a different `state_root` than the header claims — the I1/I2 cross-node
    /// check failed (AC-LC2 / AC-F-LN1). The lying server is **caught**; the verified state is unchanged.
    StateRootMismatch { expected: [u8; 32], got: [u8; 32] },
    /// A genesis snapshot the gateway served re-derived to a `state_root` other than the PINNED constant
    /// (`ln-trust-2`/`ln-trust-3`). The gateway is on the wrong network or lied about the seeded genesis;
    /// the anchor is REJECTED and no block is ever applied on top of it (fail-closed).
    GenesisRootMismatch { expected: [u8; 32], got: [u8; 32] },
    /// The genesis snapshot bytes did not decode (malformed anchor).
    BadGenesisSnapshot(String),
}

impl core::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            VerifyError::BadWire(e) => write!(f, "bad wire block: {e}"),
            VerifyError::ShallowVerify => write!(
                f,
                "shallow-verify failed (txs_root mismatch or unsigned/forged proposer)"
            ),
            VerifyError::NonContiguous { have, got } => {
                write!(f, "non-contiguous block: tip={have}, got={got}")
            }
            VerifyError::WrongParent => write!(f, "parent_hash does not link to verified tip"),
            VerifyError::BadTimestamp => write!(f, "timestamp not greater than parent"),
            VerifyError::WrongProposer => write!(f, "proposer is not the expected proposer"),
            VerifyError::UnauthorizedProposer { proposer } => write!(
                f,
                "proposer 0x{} is not in the pinned validator set",
                proposer
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
            ),
            VerifyError::UndecodableTx(e) => write!(f, "undecodable tx: {e}"),
            VerifyError::StateRootMismatch { expected, got } => write!(
                f,
                "state_root mismatch: header 0x{} re-executed 0x{}",
                hex32(expected),
                hex32(got)
            ),
            VerifyError::GenesisRootMismatch { expected, got } => write!(
                f,
                "genesis state_root mismatch: pinned 0x{} re-derived 0x{}",
                hex32(expected),
                hex32(got)
            ),
            VerifyError::BadGenesisSnapshot(e) => write!(f, "bad genesis snapshot: {e}"),
        }
    }
}

impl std::error::Error for VerifyError {}

fn hex32(b: &[u8; 32]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Recompute the canonical `txs_root` over the carried raw user txs — byte-identical to
/// `WireBlock::recompute_txs_root` and `crates/rpc::Block::compute_txs_root`.
fn compute_txs_root(raw_txs: &[Vec<u8>]) -> B256 {
    let mut buf = Vec::with_capacity(8 + raw_txs.len() * 32);
    buf.extend_from_slice(&(raw_txs.len() as u64).to_be_bytes());
    for raw in raw_txs {
        buf.extend_from_slice(keccak256(raw).as_slice());
    }
    keccak256(&buf)
}

/// The verified post-state of a successfully-applied block — what `applyBlock` returns to the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockOutcome {
    pub number: u64,
    pub hash: [u8; 32],
    pub state_root: [u8; 32],
    pub timestamp: u64,
}

/// The verified light-client state: the `MemState` plus the verified chain tip. This is the in-memory
/// equivalent of what `crates/rpc::Chain` holds, minus the server's mempool/tx-index/networking — a
/// light node only needs the verified state + tip to read balances and verify the next block.
///
/// The AI-seam impls are the deterministic Mocks the consensus/devnet path ships — held by value so the
/// kernel is fully self-contained (no node config crosses the WASM boundary). Re-execution never runs a
/// model: the Mocks reproduce the canonical verdict/effect/proof outcomes the consensus path commits.
pub struct LightCore {
    chain_id: u64,
    state: MemState,
    tip_number: u64,
    tip_hash: [u8; 32],
    tip_state_root: [u8; 32],
    tip_timestamp: u64,
    /// The pinned PoA validator set (`ln-trust-1`): the addresses authorized to propose blocks. When
    /// NON-EMPTY, [`LightCore::apply_decoded`] rejects ANY block whose `proposer` is not in this set —
    /// proposer authority is enforced on every block, never skipped. Empty ⇒ no set pinned (the legacy
    /// `genesis` constructor; the always-on enforcement is engaged via `genesis_import`).
    validator_set: Vec<[u8; 20]>,
    oracle: MockOracle,
    interpreter: MockInterpreter,
    verifier: MockZkVerifier,
}

impl LightCore {
    /// The chain id this core verifies against.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Construct an empty verified state anchored at the gateway's advertised genesis (spec §2.2
    /// `LightState.genesis`). `genesis_hash` is the block-0 hash the gateway advertised in its `Hello`;
    /// `genesis_time` is genesis unix time, `genesis_state_root` block-0's committed root. The state is
    /// empty (genesis seeds no accounts on this chain — the dev account is seeded post-genesis on the
    /// server, and a light node re-derives every later account by replaying blocks). Verified state is
    /// always grown by `apply_block` from here.
    pub fn genesis(
        chain_id: u64,
        genesis_hash: [u8; 32],
        genesis_state_root: [u8; 32],
        genesis_time: u64,
    ) -> Self {
        LightCore {
            chain_id,
            state: MemState::new(),
            tip_number: 0,
            tip_hash: genesis_hash,
            tip_state_root: genesis_state_root,
            tip_timestamp: genesis_time,
            validator_set: Vec::new(),
            oracle: MockOracle::default(),
            interpreter: MockInterpreter::default(),
            verifier: MockZkVerifier::default(),
        }
    }

    /// Construct the verified state from a **pinned, gateway-independent genesis anchor** (spec 07 §3.4,
    /// `ln-trust-1`/`ln-trust-2`/`ln-trust-3`). This is how the shipped light client anchors a REAL seeded
    /// chain:
    ///
    ///   * `genesis_snapshot` is the seeded genesis state the gateway served (untrusted DATA): the seeded
    ///     accounts/humans/jurors/CSCA/governance. It is decoded into a `MemState`.
    ///   * `pinned_state_root` is the app's HARD-CODED genesis `state_root` constant. We re-derive the
    ///     `state_root` from the decoded snapshot LOCALLY and reject (`GenesisRootMismatch`) unless it
    ///     equals `pinned_state_root` — so a lying gateway serving a different seeded genesis is caught,
    ///     and the all-zeros default is never silently accepted (closes `ln-trust-3`).
    ///   * `validator_set` is the app's pinned PoA proposer/validator set; it is stored and enforced on
    ///     EVERY subsequent block (`ln-trust-1` — no None-skip).
    ///   * `genesis_hash` / `genesis_time` anchor the verified tip at height 0 so block #1 links by
    ///     `parent_hash`. (`genesis_hash` is the block-0 header hash — over the ZERO header root — which
    ///     the caller has already checked equals its pinned constant; the SEEDED root the client commits
    ///     as the verified tip's `state_root` is `pinned_state_root`, what re-execution builds upon.)
    ///
    /// On success the verified tip is `(0, genesis_hash, pinned_state_root, genesis_time)` over the
    /// verified seeded state; `apply_block` grows it from there.
    pub fn genesis_import(
        chain_id: u64,
        genesis_hash: [u8; 32],
        pinned_state_root: [u8; 32],
        genesis_time: u64,
        genesis_snapshot: &[u8],
        validator_set: Vec<[u8; 20]>,
    ) -> Result<Self, VerifyError> {
        let state = crate::snapshot::decode_state(genesis_snapshot)
            .map_err(VerifyError::BadGenesisSnapshot)?;
        // ln-trust-2/3: re-derive the root from the served snapshot and verify it equals the PINNED
        // constant BEFORE trusting any byte of the snapshot. A mismatch ⇒ reject the whole anchor.
        let derived = runtime_state_root(&state);
        if derived != pinned_state_root {
            return Err(VerifyError::GenesisRootMismatch {
                expected: pinned_state_root,
                got: derived,
            });
        }
        Ok(LightCore {
            chain_id,
            state,
            tip_number: 0,
            tip_hash: genesis_hash,
            tip_state_root: pinned_state_root,
            tip_timestamp: genesis_time,
            validator_set,
            oracle: MockOracle::default(),
            interpreter: MockInterpreter::default(),
            verifier: MockZkVerifier::default(),
        })
    }

    /// The verified tip `(number, hash, state_root, timestamp)`.
    pub fn tip(&self) -> BlockOutcome {
        BlockOutcome {
            number: self.tip_number,
            hash: self.tip_hash,
            state_root: self.tip_state_root,
            timestamp: self.tip_timestamp,
        }
    }

    /// The 32-byte deterministic `state_root` over the current verified state — `ubi2_runtime::
    /// state_root`, the SAME commitment consensus uses. Pure read.
    pub fn state_root(&self) -> [u8; 32] {
        runtime_state_root(&self.state)
    }

    /// The streaming balance of `addr` at unix-second `now` (settled + emission + Σ incoming streams) —
    /// `State::balance`, an exact-integer function of `(state, now)` (I2). Returned as base units; the
    /// wasm layer crosses it to JS as a **decimal string**, never a float.
    pub fn balance_of(&self, addr: &[u8; 20], now: u64) -> u128 {
        self.state.balance(addr, now)
    }

    /// The current nonce of `addr` (0 if unknown) — for composing the next tx.
    pub fn nonce_of(&self, addr: &[u8; 20]) -> u64 {
        self.state.nonce(addr)
    }

    /// The PoH status tag of `addr` (`0`=Unverified .. `4`=Revoked), matching `state_root`'s
    /// `human_status_tag`. `None`/Unverified ⇒ 0.
    pub fn human_status(&self, addr: &[u8; 20]) -> u8 {
        match self.state.get_human(addr).map(|h| h.status) {
            None | Some(ubi2_runtime::HumanStatus::Unverified) => 0,
            Some(ubi2_runtime::HumanStatus::Pending) => 1,
            Some(ubi2_runtime::HumanStatus::Verified) => 2,
            Some(ubi2_runtime::HumanStatus::Challenged) => 3,
            Some(ubi2_runtime::HumanStatus::Revoked) => 4,
        }
    }

    /// Decode + re-execute + root-verify a `WireBlock` against the verified tip (spec §3.2 step 3). On
    /// success the verified state advances to this block and `BlockOutcome` is returned; on ANY failure
    /// the verified state is left **unchanged** (fail-closed — the tip never advances on a bad block,
    /// LC-2/LC-5/AC-LC2). `expected_proposer`, when supplied, pins the scheduled proposer.
    pub fn apply_block(
        &mut self,
        wire: &[u8],
        expected_proposer: Option<[u8; 20]>,
    ) -> Result<BlockOutcome, VerifyError> {
        let block = WireBlock::decode(wire).map_err(|e| VerifyError::BadWire(e.to_string()))?;
        self.apply_decoded(&block, expected_proposer)
    }

    /// As [`apply_block`], but over an already-decoded `WireBlock` (used by the parity test, which
    /// drives the kernel directly from in-memory blocks).
    pub fn apply_decoded(
        &mut self,
        block: &WireBlock,
        expected_proposer: Option<[u8; 20]>,
    ) -> Result<BlockOutcome, VerifyError> {
        // 1. shallow_verify: txs_root consistent + a NON-EMPTY proposer signature recovering to
        //    `proposer` (SEC-M5A-1 — an unsigned block is never trusted for its height, AC-F-LN3).
        if !block.shallow_verify() {
            return Err(VerifyError::ShallowVerify);
        }

        // 2. Cheap header checks against the verified tip (fail-fast, before re-execution).
        if block.number != self.tip_number + 1 {
            return Err(VerifyError::NonContiguous {
                have: self.tip_number,
                got: block.number,
            });
        }
        if block.parent_hash.0 != self.tip_hash {
            return Err(VerifyError::WrongParent);
        }
        if block.timestamp <= self.tip_timestamp {
            return Err(VerifyError::BadTimestamp);
        }
        if let Some(exp) = expected_proposer {
            if block.proposer.into_array() != exp {
                return Err(VerifyError::WrongProposer);
            }
        }
        // ln-trust-1 (ALWAYS-ON proposer authority): when a PoA validator set is pinned, the block's
        // proposer MUST be in it — on EVERY block, independent of `expected_proposer`. This closes the
        // None-skip: a malicious gateway that self-signs a chain from its own key is rejected here, not
        // shown as "verified". (An empty set means the legacy `genesis` constructor was used — the TS
        // client always pins a set via `genesis_import`, so the shipped app always enforces this.)
        if !self.validator_set.is_empty()
            && !self.validator_set.contains(&block.proposer.into_array())
        {
            return Err(VerifyError::UnauthorizedProposer {
                proposer: block.proposer.into_array(),
            });
        }

        // 3. Decode the ordered raw user txs via the SHARED kernel decode — the SAME structural decode
        //    the proposer / server follower ran (chain-id bind, signer recovery, hub calldata shape), so
        //    a tx decodes byte-identically here. An undecodable tx ⇒ the block is malformed/forged.
        let mut decoded = Vec::with_capacity(block.txs.len());
        for raw in &block.txs {
            decoded.push(
                ubi2_exec::decode_tx(self.chain_id, raw)
                    .map_err(|e| VerifyError::UndecodableTx(e.to_string()))?,
            );
        }

        // 4. Re-execute against a TRIAL copy of the verified state at block.timestamp via the SHARED
        //    apply kernel (charge_fee → op → failed-tx nonce → the M3 sybil/finalize sweeps). The same
        //    pre-execution entropy hash the proposer used feeds jury selection (never balances/roots).
        //    We commit the trial only if the recomputed roots match the header byte-for-byte.
        let entropy_hash = entropy_hash(block.number, block.parent_hash.0, block.timestamp);
        let mut trial = self.state.clone();
        ubi2_exec::apply_ops(
            &mut trial,
            &decoded,
            block.timestamp,
            block.number,
            entropy_hash,
            &self.oracle,
            &self.interpreter,
            &self.verifier,
        );

        // 5. Recompute the consensus roots over the FINAL trial state and assert byte-identical to the
        //    header (the I1/I2 cross-node check — AC-LC2 / AC-F-LN1). A mismatch ⇒ reject, state unchanged.
        let got_txs_root = compute_txs_root(&block.txs);
        if got_txs_root != block.txs_root {
            return Err(VerifyError::StateRootMismatch {
                expected: block.state_root.0,
                got: runtime_state_root(&trial),
            });
        }
        let got_state_root = runtime_state_root(&trial);
        if got_state_root != block.state_root.0 {
            return Err(VerifyError::StateRootMismatch {
                expected: block.state_root.0,
                got: got_state_root,
            });
        }

        // 6. Commit: the trial state becomes the verified state; advance the tip.
        self.state = trial;
        self.tip_number = block.number;
        self.tip_hash = block.hash().0;
        self.tip_state_root = got_state_root;
        self.tip_timestamp = block.timestamp;

        Ok(self.tip())
    }

    /// Canonical snapshot of the verified state + tip, for IndexedDB persistence (spec §3.3). The bytes
    /// round-trip through [`LightCore::deserialize`] to a byte-identical state (same `state_root`).
    pub fn serialize(&self) -> Vec<u8> {
        crate::snapshot::encode(self)
    }

    /// Restore a verified state + tip from a [`LightCore::serialize`] snapshot. The caller (the TS light
    /// client) MUST re-verify the restored `state_root` against the stored tip header on load and
    /// discard + re-sync on mismatch (spec §3.3 — a poisoned IndexedDB entry is not trusted).
    pub fn deserialize(bytes: &[u8]) -> Result<Self, VerifyError> {
        crate::snapshot::decode(bytes).map_err(VerifyError::BadWire)
    }

    /// Construct a `LightCore` directly from parts (used by the snapshot decoder).
    pub(crate) fn from_parts(
        chain_id: u64,
        state: MemState,
        tip_number: u64,
        tip_hash: [u8; 32],
        tip_state_root: [u8; 32],
        tip_timestamp: u64,
    ) -> Self {
        LightCore {
            chain_id,
            state,
            tip_number,
            tip_hash,
            tip_state_root,
            tip_timestamp,
            // A restored IndexedDB snapshot does not carry the validator set; the caller re-pins it via
            // `set_validator_set` after deserialize (the TS client always re-supplies its pinned set on
            // load). Empty here keeps the snapshot codec format unchanged.
            validator_set: Vec::new(),
            oracle: MockOracle::default(),
            interpreter: MockInterpreter::default(),
            verifier: MockZkVerifier::default(),
        }
    }

    /// Re-pin the PoA validator set on a `LightCore` restored from a snapshot (`ln-trust-1`). The TS
    /// client calls this right after `deserialize` so proposer authority is enforced on the next block
    /// even on a resumed session. (The snapshot format itself stays unchanged — the set is app-pinned.)
    pub fn set_validator_set(&mut self, validator_set: Vec<[u8; 20]>) {
        self.validator_set = validator_set;
    }

    // --- accessors for the snapshot encoder (read-only; no mutation) ---
    pub(crate) fn state_ref(&self) -> &MemState {
        &self.state
    }
    pub(crate) fn tip_parts(&self) -> (u64, [u8; 32], [u8; 32], u64) {
        (
            self.tip_number,
            self.tip_hash,
            self.tip_state_root,
            self.tip_timestamp,
        )
    }
}

/// The PRE-execution entropy hash — `keccak256(number ‖ parent_hash ‖ timestamp ‖ 0 ‖ 0 ‖ 0)` — the
/// same value `crates/rpc::execute_block` derives (block hash over zeroed roots + zero proposer) and
/// feeds to the shared kernel's jury selection (it folds ONLY into the seeded PRNG, never balances or
/// roots, so the swap does not change any state). Byte-identical to `Block::compute_hash(number,
/// parent_hash, timestamp, ZERO, ZERO, ZERO)`.
fn entropy_hash(number: u64, parent_hash: [u8; 32], timestamp: u64) -> [u8; 32] {
    let mut buf = Vec::with_capacity(8 + 32 + 8 + 32 + 32 + 20);
    buf.extend_from_slice(&number.to_be_bytes());
    buf.extend_from_slice(&parent_hash);
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.extend_from_slice(&[0u8; 32]); // txs_root placeholder
    buf.extend_from_slice(&[0u8; 32]); // state_root placeholder
    buf.extend_from_slice(&[0u8; 20]); // proposer placeholder
    keccak256(&buf).0
}

// ---------------------------------------------------------------------------------------------
// The ONE documented fail-closed boundary (least authority — I6).
//
// The light client re-executes EVERY block kind — value transfers, streaming, PoH social-vouching,
// prompt contracts, AND ZK-passport proofs — because re-execution is deterministic and needs no AI
// (the AI verdict/effect/proof rides in as a tx that applies purely; the few apply-time seam calls run
// the deterministic Mocks the consensus path ships). There is exactly one case the light client cannot
// reproduce client-side:
//
//   * A chain wired with a *live* (non-Mock) AI backend on its CONSENSUS path — i.e. a node whose
//     `requestVerification` liveness grade / `invokeContract` interpretation depends on a live LLM's
//     output that is NOT carried in the tx. The light client has no model and cannot reproduce that
//     output, so the re-executed `state_root` would diverge from the header and `apply_block` would
//     return `StateRootMismatch` (fail-closed — a visible verification error, never a wrong balance).
//
// This is OUT OF SCOPE for the devnet / Stage 1–2 trust model by construction: the consensus path
// ships the deterministic Mock impls (I5 — tests replay fixtures; the live oracle/interpreter are gated
// and never on the consensus path), and the ZK verifier is a pure deterministic function (the Mock here,
// or `crates/zkpoh`'s Groth16 verifier when a node wires one — that path would have the light client
// link `crates/zkpoh`, which is itself wasm32-compilable). So for every block a devnet/consensus node
// produces, the light client re-executes to a byte-identical `state_root` (proved by the AC-WB parity
// gate over transfers, streaming, PoH-vouching, prompt-contract, and ZK-passport blocks).
// ---------------------------------------------------------------------------------------------
