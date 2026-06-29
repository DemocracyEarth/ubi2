//! The genesis-pinned verifying-key slot (spec §2.3, ADR-0005 D1 — "pin the resulting verifying key in
//! genesis, hash-committed in `state_root`").
//!
//! ## Real-circuit binding — current status (the honest accounting)
//!
//! The production verifying key is the output of the OpenPassport / Self e-passport circuit's
//! **trusted-setup Phase-2 ceremony** (spec §2.3 mitigation 2). Until that ceremony's VK is fetched and
//! its public-input layout is bound to ours (§3.5), this slot is **empty by default**: there is **no**
//! hard-coded "real" VK, because shipping a placeholder VK as if it were the pinned trust anchor would
//! be worse than shipping none — it would look authoritative while being a test key.
//!
//! What this slot DOES provide today:
//!   * [`PinnedVerifyingKey::from_canonical_bytes`](crate::PinnedVerifyingKey::from_canonical_bytes) —
//!     the loader for the real ceremony VK once obtained (canonical compressed bytes, validated).
//!   * The arity pin ([`crate::NUM_PUBLIC_INPUTS`] = 8) the real VK must satisfy (§3.5). A real
//!     OpenPassport/Self VK has a *different* public-input layout (its own nullifier + disclosure
//!     outputs); binding it to ours is the documented **next step**: adapt the circuit's public-output
//!     wiring to emit our 8-field vector (nullifier, 3 attr commitments, CSCA root, submitter, now,
//!     scheme tag), then re-run the ceremony to pin the adapted VK. The verifier code here is unchanged
//!     by that work — only the VK bytes + the circuit's public-output map change.
//!
//! ### Why no VK ships hard-coded in M6 Phase 1
//! The Self/OpenPassport public artifacts are large per-document-type circuit VKs whose **public-input
//! layout does not yet match our §3.5 vector** (they emit the protocol's own scope/nullifier and the
//! selectively-disclosed fields, not our CSCA-root / submitter-address / now-epoch bindings). Pinning
//! one verbatim would verify *their* statement, not ours, so the adaptation (re-wire the circuit's
//! public outputs, re-run Phase-2) is a prerequisite — tracked as the Stage-A `A1` task. Phase 1
//! de-risks the **verifier** (this crate) against a self-generated real-curve VK + proof, which proves
//! the determinism, soundness, and wasm story end-to-end; the real circuit binding is the next step and
//! does not touch any code in this crate.
//!
//! Until then, tests and the devnet wire a VK via `from_*_bytes` / `from_vk` (the real-curve fixture
//! path, spec §6.3) — exactly as the genesis CSCA set is a curated static set wired by `crates/node`.

use crate::keys::PinnedVerifyingKey;

/// The pinned passport-proof verifying key, if one has been compiled in. Returns `None` in M6 Phase 1:
/// the real ceremony VK is not yet bound (see module docs), and we deliberately do **not** ship a
/// placeholder masquerading as the trust anchor. `crates/node` loads the real VK bytes via
/// [`PinnedVerifyingKey::from_canonical_bytes`] at genesis once obtained.
pub fn pinned_passport_vk() -> Option<PinnedVerifyingKey> {
    None
}

/// Whether a real, ceremony-derived passport VK is compiled into this build. `false` in M6 Phase 1 — a
/// node MUST be configured with a VK (test fixture on devnet, ceremony VK in production) or the passport
/// op is unavailable (fail closed: no VK ⇒ no `verify_passport` accepts).
pub const HAS_PINNED_PASSPORT_VK: bool = false;
