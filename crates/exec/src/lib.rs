//! ubi2 shared block re-execution kernel (spec 07 §2.3 / ADR-0006 Decision 3).
//!
//! This crate is the **single** implementation of block re-execution: decode an ordered raw-tx list
//! into [`KernelTx`]s, then apply them via the `crates/runtime` lifecycle fns to produce the new state
//! (and thereby the deterministic `state_root`). Both the full node (`crates/rpc`) and the WASM light
//! client (`crates/runtime-wasm`) call it, so there is **no logic fork** — a block re-executes to the
//! same post-state on the server follower and the browser follower (the AC-WB parity gate proves it
//! byte-for-byte).
//!
//! It depends only on `crates/runtime` (deterministic, dependency-free, untouched) + the pure
//! `alloy`/`k256` tx-decode + ecrecover primitives the browser needs. **No** tokio/jsonrpsee/libp2p/
//! reqwest — so it compiles to `wasm32-unknown-unknown` and rides into the browser light-node blob.
//!
//! ## Determinism + the AI boundary (the key insight, ADR-0006)
//! Re-executing a block needs **no AI**. The AI (PoH jury verdicts, contract interpretation, ZK
//! proving) happens when a juror/proposer/prover *produces* a tx (`submitVerdict` / `submitEffect` /
//! `submitZkPassportProof`); *applying* that tx to state is pure. The three apply-time seam calls that
//! remain (`requestVerification` liveness grading, `invokeContract`'s in-call interpreter quorum, the
//! sybil-scan sweep, and the `submitZkPassportProof` pairing check) are taken as **trait parameters** —
//! the kernel never embeds a model. The consensus/devnet path ships the deterministic Mock impls
//! (`MockOracle`/`MockInterpreter`/`MockZkVerifier`, all pure, in `crates/runtime`), and the light
//! client passes those SAME mocks (I5), so it re-executes byte-identical.

pub mod apply;
pub mod effect_codec;
pub mod op;

pub use apply::{
    apply_ops, apply_tx, block_entropy, derive_liveness, derive_trigger, run_sweeps,
    text_commitment, OpOutcome, OpResult,
};
pub use effect_codec::{decode_effect, encode_effect};
pub use op::{
    decode_tx, DecodeError, KernelKind, KernelTx, CONTRACT_HUB, HUMANITY_HUB, MAX_ZK_PROOF_BYTES,
    STREAM_HUB,
};
