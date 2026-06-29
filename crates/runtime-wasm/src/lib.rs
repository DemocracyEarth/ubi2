//! ubi2 browser light-node WASM wrapper (spec `07-browser-light-node.md` §2.2, ADR-0006 Decision 1).
//!
//! A thin bytes/JSON API over the **untouched, dependency-free** `crates/runtime`, so a browser tab
//! re-executes blocks against the **same deterministic core** consensus uses — never trusting a
//! server's claim about a balance or a state root (I1/I2 on the client). This is the ONLY crate that
//! pulls `wasm-bindgen`; `crates/runtime` keeps its empty `[dependencies]` (guarded by
//! `runtime/tests/dependency_free.rs`).
//!
//! ## Layers
//! - [`kernel::LightCore`] — the pure, async-free, networking-free re-execution kernel. Decodes a
//!   `WireBlock`, re-executes its txs via the runtime's own transitions at `block.timestamp`, and
//!   accepts the block only on a **byte-identical** `state_root` (the same trust guarantee a server
//!   follower has). Pure Rust — links + tests on a NATIVE host with NO wasm-bindgen, which is how the
//!   parity gate (`tests/parity.rs`, AC-WB) proves the kernel equals the server follower's.
//! - [`LightState`] (this module, behind the `wasm` feature) — the `wasm-bindgen` handle the TypeScript
//!   light client calls: `genesis`, `applyBlock`, `stateRoot`, `tip`, `balanceOf`, `nonceOf`,
//!   `humanStatus`, `serialize`/`deserialize`. All cross-boundary values are bytes or JSON; **no float
//!   ever crosses** — `balanceOf` returns a **decimal string** of base units (I2, §2.2).
//!
//! ## The determinism rule for the wrapper (spec §2.2)
//! `balanceOf(addr, now)` is the only way the UI gets a balance, and `now` is the caller's wall-clock,
//! used purely to project the stream forward for display — the wrapper computes the SAME integer
//! `Account::balance(now)` the chain commits. The committed consensus balance is always read at a block
//! height (`now = block.timestamp`); the live tick is a pure-integer extrapolation re-anchored on every
//! new verified block. No float, ever.

pub mod kernel;
pub mod snapshot;
pub mod wire;

pub use kernel::{BlockOutcome, LightCore, VerifyError};

// ---------------------------------------------------------------------------------------------
// The wasm-bindgen handle. Compiled only for the `wasm` feature (default for the wasm32 build); the
// native parity test builds `--no-default-features` so it links ONLY the pure `LightCore` kernel.
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "wasm")]
mod bindings {
    use super::*;
    use wasm_bindgen::prelude::*;

    /// Parse a `0x`-prefixed-or-bare hex string into a fixed `[u8; N]`. Used to cross addresses /
    /// hashes from JS as hex strings (never as JS numbers — a 20/32-byte value does not fit a `number`).
    fn from_hex<const N: usize>(s: &str) -> Result<[u8; N], JsError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        if s.len() != N * 2 {
            return Err(JsError::new(&format!(
                "expected {N}-byte hex ({} chars), got {}",
                N * 2,
                s.len()
            )));
        }
        let mut out = [0u8; N];
        for (i, slot) in out.iter_mut().enumerate() {
            *slot = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| JsError::new(&format!("bad hex: {e}")))?;
        }
        Ok(out)
    }

    fn to_hex(bytes: &[u8]) -> String {
        let mut s = String::with_capacity(2 + bytes.len() * 2);
        s.push_str("0x");
        for b in bytes {
            s.push_str(&format!("{b:02x}"));
        }
        s
    }

    /// The JSON shape `tip()` returns to JS: `{ number, hash, stateRoot, timestamp }` of the highest
    /// verified block. `number`/`timestamp` are JS-safe (`< 2^53` for any realistic devnet), hashes are
    /// `0x` hex.
    #[derive(serde::Serialize)]
    struct TipJson {
        number: u64,
        hash: String,
        #[serde(rename = "stateRoot")]
        state_root: String,
        timestamp: u64,
    }

    /// The JSON shape `applyBlock` returns on success: the accepted block's `{ number, hash, stateRoot,
    /// timestamp }`. A rejected block throws a JS error (the verification stop) — never a wrong number.
    #[derive(serde::Serialize)]
    struct OutcomeJson {
        number: u64,
        hash: String,
        #[serde(rename = "stateRoot")]
        state_root: String,
        timestamp: u64,
    }

    impl From<&BlockOutcome> for OutcomeJson {
        fn from(o: &BlockOutcome) -> Self {
            OutcomeJson {
                number: o.number,
                hash: to_hex(&o.hash),
                state_root: to_hex(&o.state_root),
                timestamp: o.timestamp,
            }
        }
    }

    /// The verified light-node state the TypeScript client holds: a `LightCore` (verified `MemState` +
    /// tip). One handle per chain; the client constructs it from the gateway-advertised genesis, then
    /// `applyBlock`s every synced/streamed block before its UI tip advances.
    #[wasm_bindgen]
    pub struct LightState {
        core: LightCore,
    }

    #[wasm_bindgen]
    impl LightState {
        /// Construct the empty verified state at the genesis the gateway advertised (spec §2.2). All
        /// args cross as JS-safe types: `chain_id`/`genesis_time` as numbers (devnet-safe), the genesis
        /// block hash + state root as `0x` hex strings.
        #[wasm_bindgen(constructor)]
        pub fn new(
            chain_id: u64,
            genesis_hash: &str,
            genesis_state_root: &str,
            genesis_time: u64,
        ) -> Result<LightState, JsError> {
            console_error_panic_hook::set_once();
            let hash = from_hex::<32>(genesis_hash)?;
            let root = from_hex::<32>(genesis_state_root)?;
            Ok(LightState {
                core: LightCore::genesis(chain_id, hash, root, genesis_time),
            })
        }

        /// Decode + re-execute + root-verify a canonical `WireBlock` (the bytes the gateway served, the
        /// SAME `ubi2/sync/1` payload a server follower verifies). On success the verified tip advances
        /// and the accepted block's `{number,hash,stateRoot,timestamp}` is returned; on ANY failure a
        /// JS error is thrown and the verified state is unchanged (LC-2/LC-5/AC-LC2 — a forged block is
        /// caught by re-execution, the UI shows a red verification error, never a wrong balance).
        ///
        /// `expected_proposer` (optional `0x`-hex 20-byte address) pins the scheduled proposer.
        #[wasm_bindgen(js_name = applyBlock)]
        pub fn apply_block(
            &mut self,
            wire: &[u8],
            expected_proposer: Option<String>,
        ) -> Result<JsValue, JsError> {
            let exp = match expected_proposer {
                Some(s) => Some(from_hex::<20>(&s)?),
                None => None,
            };
            let outcome = self
                .core
                .apply_block(wire, exp)
                .map_err(|e| JsError::new(&e.to_string()))?;
            serde_wasm_bindgen::to_value(&OutcomeJson::from(&outcome))
                .map_err(|e| JsError::new(&e.to_string()))
        }

        /// The 32-byte `state_root` over the current verified state, as a `0x` hex string — the SAME
        /// commitment consensus uses (`ubi2_runtime::state_root`).
        #[wasm_bindgen(js_name = stateRoot)]
        pub fn state_root(&self) -> String {
            to_hex(&self.core.state_root())
        }

        /// The verified tip `{ number, hash, stateRoot, timestamp }` as a JS object.
        #[wasm_bindgen]
        pub fn tip(&self) -> Result<JsValue, JsError> {
            let t = self.core.tip();
            let json = TipJson {
                number: t.number,
                hash: to_hex(&t.hash),
                state_root: to_hex(&t.state_root),
                timestamp: t.timestamp,
            };
            serde_wasm_bindgen::to_value(&json).map_err(|e| JsError::new(&e.to_string()))
        }

        /// The streaming balance of `addr` at unix-second `now`, as a **decimal string** of base units
        /// (I2, §2.2). NEVER a JS `number` — an 18-decimal UBI balance overflows `2^53` in seconds. The
        /// caller's `now` projects the stream forward for display; the value is the exact integer
        /// `Account::balance(now)` the chain commits, re-anchored on every verified block.
        #[wasm_bindgen(js_name = balanceOf)]
        pub fn balance_of(&self, addr: &str, now: u64) -> Result<String, JsError> {
            let a = from_hex::<20>(addr)?;
            Ok(self.core.balance_of(&a, now).to_string())
        }

        /// The current nonce of `addr` (0 if unknown) — for composing the next tx.
        #[wasm_bindgen(js_name = nonceOf)]
        pub fn nonce_of(&self, addr: &str) -> Result<u64, JsError> {
            let a = from_hex::<20>(addr)?;
            Ok(self.core.nonce_of(&a))
        }

        /// The PoH status tag of `addr` (`0`=Unverified, `1`=Pending, `2`=Verified, `3`=Challenged,
        /// `4`=Revoked).
        #[wasm_bindgen(js_name = humanStatus)]
        pub fn human_status(&self, addr: &str) -> Result<u8, JsError> {
            let a = from_hex::<20>(addr)?;
            Ok(self.core.human_status(&a))
        }

        /// Canonical snapshot of the verified state + tip, for IndexedDB persistence (spec §3.3). The
        /// bytes round-trip through [`LightState::deserialize`] to a byte-identical state (same root).
        #[wasm_bindgen]
        pub fn serialize(&self) -> Vec<u8> {
            self.core.serialize()
        }

        /// Restore a verified state + tip from a [`LightState::serialize`] snapshot. The client MUST
        /// re-verify `stateRoot()` against the stored tip on load and discard + re-sync on mismatch
        /// (spec §3.3 — a poisoned IndexedDB entry is not trusted).
        #[wasm_bindgen]
        pub fn deserialize(bytes: &[u8]) -> Result<LightState, JsError> {
            let core = LightCore::deserialize(bytes).map_err(|e| JsError::new(&e.to_string()))?;
            Ok(LightState { core })
        }
    }
}

#[cfg(feature = "wasm")]
pub use bindings::LightState;
