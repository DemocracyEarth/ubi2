//! M6 — ZK-passport proof-of-humanity: the runtime-side seam + the additive on-chain types.
//!
//! Spec: `docs/specs/06-zk-passport-poh.md` + `docs/specs/adr/0005-zk-passport-poh.md`.
//!
//! This module holds the **dependency-free** half of M6 — the parts that live in the deterministic
//! consensus core (`crates/runtime` pulls no crypto crate, ADR-0005 D2). It defines:
//!
//!   * The [`ZkPassportVerifier`] **trait** — the verifier seam, the exact analogue of
//!     [`HumanityOracle`](crate::humanity::HumanityOracle): the runtime owns the trait and calls it;
//!     the heavy Groth16/BN254 impl lives in `crates/zkpoh` (and wires by node config). On the
//!     consensus path the deterministic [`MockZkVerifier`] ships, *exactly* as M3 ships `MockOracle`.
//!   * [`ZkPublicInputs`] — the pinned canonical public-input vector (spec §3.5) as **plain bytes**
//!     (no field-element math here). `crates/zkpoh` converts it to BN254 `Fr` via its single canonical
//!     mapping; the runtime only assembles + binds the bytes.
//!   * [`ZkAttrType`] — the attribute-verifier discriminant (M6 ships only `Over18`, spec §4.4).
//!   * [`Assurance`] — the additive `Std | Enh | Dual` level on a [`Human`](crate::humanity::Human).
//!   * [`CscaEntry`] / [`CscaStatus`] — the governance-upgradeable CSCA trust-anchor registry (spec §7).
//!   * [`MockZkVerifier`] — the scripted, fully-deterministic verifier for CI / lifecycle tests (I5).
//!   * [`csca_registry_root`] — the deterministic 32-byte commitment over the sorted Active CSCA set.
//!
//! Everything is integer-only, fail-closed, and free of any non-deterministic iteration: two nodes that
//! processed the same `submitZkPassportProof` txs reach byte-identical state (I1/I2/I4).

use crate::humanity::Hash;
use crate::Address;
use std::collections::HashMap;

// ---------------------------------------------------------------------------------------------
// Constants (devnet starting values — spec §13 open items O-1/O-3; tunable at the gate).
// ---------------------------------------------------------------------------------------------

/// The number of public inputs in the M6 passport-proof statement (spec §3.5). Pinned: the verifying
/// key encodes this arity. Mirrors `ubi2_zkpoh::NUM_PUBLIC_INPUTS`; kept here so the runtime can
/// bound-check the assembled vector without depending on the crypto crate.
pub const NUM_PUBLIC_INPUTS: usize = 8;

/// The number of Pedersen attribute commitments a passport proof emits (age, nationality, expiry —
/// spec §3.4). Stored opaquely (I6); never plaintext.
pub const NUM_ATTRIBUTE_COMMITMENTS: usize = 3;

/// The passport scheme/document-type discriminant for an ICAO-9303 e-passport (spec §2.4 forward-compat
/// `scheme_tag`). M6 ships only this scheme; an unknown tag is rejected fail-closed (§4.2 step 1).
pub const SCHEME_TAG_PASSPORT: u8 = 0;

// ---------------------------------------------------------------------------------------------
// Assurance level — the additive `Human.assurance` metadata (spec §5.1). NEVER gates UBI accrual.
// ---------------------------------------------------------------------------------------------

/// The proof-of-humanity assurance level of a [`Human`](crate::humanity::Human) (spec §5.1).
///
/// **Additive metadata, never a UBI gate (the inclusion constraint, structurally).** UBI accrues iff
/// `status == Verified`; there is no code path where `assurance` affects
/// [`balance()`](crate::State::balance). `Std` humans (the M3 vouching path) are first-class. The level
/// only ever unlocks *features* (M7 DAO gates).
///
///   * [`Std`](Assurance::Std)  — social vouching + AI-jury (M3). The **default** for every existing
///     record (spec §5.6 migration): genesis-seeded humans and all M3 humans are `Std`, untouched.
///   * [`Enh`](Assurance::Enh)  — a ZK-passport proof verified (a *new* ZK-only user lands here).
///   * [`Dual`](Assurance::Dual) — both paths: an existing `Std`-Verified human upgraded by a ZK proof
///     (balance + `verified_at` are **never** touched on this upgrade, the brief's hard rule).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum Assurance {
    /// Social vouching + AI jury (M3). The default for every record (additive-field migration, §5.6).
    #[default]
    Std,
    /// A verified ZK-passport proof (the cryptographic uniqueness path). A new ZK-only user is `Enh`.
    Enh,
    /// Both paths: an `Std` human upgraded with a ZK proof. Balance + `verified_at` untouched (§5.2).
    Dual,
}

impl Assurance {
    /// The 1-byte canonical tag folded into `state_root` (spec §5.3). Stable; a value change is a new
    /// root, never a silent reinterpretation.
    pub fn tag(&self) -> u8 {
        match self {
            Assurance::Std => 0,
            Assurance::Enh => 1,
            Assurance::Dual => 2,
        }
    }

    /// The display string surfaced by `ubi_getHuman` / the PoH-NFT `tokenURI` (spec §5.5, EC-6).
    pub fn as_str(&self) -> &'static str {
        match self {
            Assurance::Std => "STD",
            Assurance::Enh => "ENH",
            Assurance::Dual => "DUAL",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// The verifier seam (spec §6.1) — the runtime owns the trait; the impl lives in crates/zkpoh.
// ---------------------------------------------------------------------------------------------

/// The on-chain ZK-passport verifier seam (spec §6.1, ADR-0005 D2). The exact analogue of
/// [`HumanityOracle`](crate::humanity::HumanityOracle): the runtime defines + calls the trait (staying
/// dependency-free), the heavy Groth16/BN254 impl lives in `crates/zkpoh`.
///
/// **Purity contract (I1/I2 across nodes — the cleanest PoH path).** Every method is a *pure
/// deterministic function* of its inputs: same `(proof, public_inputs)` ⇒ same `bool` on every node,
/// with no clock, no float, no allocation/iteration-order dependence, no randomized verification. Any
/// malformed input (bad proof bytes, wrong arity, non-canonical encoding) returns `false` — **fail
/// closed**, never panic, never silently accept (I4). This is what lets the op ride the M5
/// re-execution consensus: honest nodes re-run the function and agree to the bit (§5.4).
pub trait ZkPassportVerifier: Send + Sync {
    /// Verify a Groth16 proof against the genesis-pinned VK + the canonical public-input vector (§3.5).
    /// Returns `true` iff the pairing equation holds for *exactly* this public-input vector.
    fn verify_passport(&self, proof: &[u8], public_inputs: &ZkPublicInputs) -> bool;

    /// Verify an attribute-opening proof against a stored commitment (§4.4). Same purity contract.
    /// M6 ships only [`ZkAttrType::Over18`]; an unknown/unwired type fails closed.
    fn verify_attribute(&self, attr_type: ZkAttrType, commitment: &Hash, attr_proof: &[u8])
        -> bool;
}

/// The attribute kinds a [`ZkPassportVerifier::verify_attribute`] proof can be about (spec §4.4). M6
/// ships only `Over18`; the enum is the forward-compatible discriminant M7 extends (nationality bucket,
/// expiry gate) — the same `scheme_tag` forward-compat pattern (§2.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ZkAttrType {
    /// Proves `attr_commit[0]` opens to a `born_before_epoch ≤ now − 18y` (DOB never revealed).
    Over18,
}

impl ZkAttrType {
    /// The stable string tag (`keccak256("over18")` selector preimage) — the `eth_call` surface
    /// `verifyAttribute(subject, attributeType, attrProof)` decodes to this enum. An unknown tag fails
    /// closed at the call site.
    pub fn as_str(&self) -> &'static str {
        match self {
            ZkAttrType::Over18 => "over18",
        }
    }
}

/// The canonical, ordered public-input vector for `submitZkPassportProof` (spec §3.5), as **plain
/// bytes**. The runtime assembles this from on-chain state + the tx + the block (re-deriving and
/// binding `csca_registry_root`, `submitter_address`, `now_epoch` — §4.2) and hands it to the verifier;
/// `crates/zkpoh` converts it to BN254 field elements through its single canonical mapping. No
/// field-element math lives here (keeping the runtime crypto-free).
///
/// ```text
/// public_inputs = [
///   nullifier,                  // 32-byte field element                          (§3.3)
///   attribute_commitments[0],   // Pedersen commitment: age threshold             (§3.4 idx 0)
///   attribute_commitments[1],   // Pedersen commitment: nationality bucket        (§3.4 idx 1)
///   attribute_commitments[2],   // Pedersen commitment: document expiry           (§3.4 idx 2)
///   csca_registry_root,         // commitment to the trusted CSCA set             (§7.2)
///   submitter_address,          // 20-byte address (zero-extended) — anti-replay  (§3.3)
///   now_epoch,                  // chain-supplied current time (block.timestamp)
///   scheme_tag,                 // 1-byte document-type discriminant              (§2.4)
/// ]
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkPublicInputs {
    /// `nullifier` — the one-passport-one-human scalar (§3.3).
    pub nullifier: Hash,
    /// The three Pedersen attribute commitments in fixed order `[age, nationality, expiry]` (§3.4).
    pub attribute_commitments: [Hash; NUM_ATTRIBUTE_COMMITMENTS],
    /// `csca_registry_root` — commitment to the trusted CSCA set the proof verifies against (§7.2).
    pub csca_registry_root: Hash,
    /// `submitter_address` — the 20-byte address the proof is bound to (anti-replay, §3.3).
    pub submitter_address: Address,
    /// `now_epoch` — the chain-supplied current time (the block timestamp) the not-expired check used.
    pub now_epoch: u64,
    /// `scheme_tag` — the 1-byte document-type/scheme discriminant (§2.4).
    pub scheme_tag: u8,
}

impl ZkPublicInputs {
    /// Assemble the canonical vector from its on-chain components. Pure: no clock, no allocation beyond
    /// the struct.
    pub fn new(
        nullifier: Hash,
        attribute_commitments: [Hash; NUM_ATTRIBUTE_COMMITMENTS],
        csca_registry_root: Hash,
        submitter_address: Address,
        now_epoch: u64,
        scheme_tag: u8,
    ) -> Self {
        Self {
            nullifier,
            attribute_commitments,
            csca_registry_root,
            submitter_address,
            now_epoch,
            scheme_tag,
        }
    }
}

/// A scripted, fully-deterministic verifier for CI / lifecycle tests (I5) — the runtime-side analogue
/// of [`MockOracle`](crate::humanity::MockOracle) and `ubi2_zkpoh::MockZkVerifier`. **This is the impl
/// the consensus path ships on for Stage B** (exactly as M3 ships `MockOracle`); the real Groth16
/// verifier wires by node config later.
///
/// It returns scripted booleans keyed by the *committed identity* of a submission — `(nullifier,
/// submitter_address)`, the pair the spec scripts the mock against (§6.3) — so the runtime state machine
/// (nullifier uniqueness, level transitions, emission flip, NFT metadata, state-root agreement, EC-7
/// divergence injection) is fully exercised **without any real pairing math**.
///
/// Resolution order (mirrors `MockOracle`):
///   1. an exact override keyed by `(nullifier, submitter)`, if one was scripted;
///   2. otherwise the configured `default` boolean.
#[derive(Clone, Debug)]
pub struct MockZkVerifier {
    /// Returned when no `(nullifier, submitter)` override matches.
    default_passport: bool,
    /// Per-`(nullifier, submitter)` passport-verify overrides.
    passport: HashMap<(Hash, Address), bool>,
    /// Returned when no attribute override matches.
    default_attribute: bool,
    /// Per-`(attr_type, commitment)` attribute-verify overrides.
    attribute: HashMap<(ZkAttrType, Hash), bool>,
}

impl Default for MockZkVerifier {
    /// Default = a confident accept on both paths, so the happy path needs no scripting (mirrors
    /// `MockOracle::default`'s confident `Human` pass).
    fn default() -> Self {
        Self::new(true)
    }
}

impl MockZkVerifier {
    /// A mock whose default passport+attribute verdict is `pass` (used when no override matches).
    pub fn new(pass: bool) -> Self {
        Self {
            default_passport: pass,
            passport: HashMap::new(),
            default_attribute: pass,
            attribute: HashMap::new(),
        }
    }

    /// Always return `pass` for every passport verify regardless of input — the "this node's verifier
    /// returns the wrong boolean" stub for the EC-7 injected-disagreement test (spec §5.4).
    pub fn always(pass: bool) -> Self {
        Self::new(pass)
    }

    /// Script a passport-verify result for a specific `(nullifier, submitter)` pair (builder style).
    pub fn with_passport(mut self, nullifier: Hash, submitter: Address, pass: bool) -> Self {
        self.passport.insert((nullifier, submitter), pass);
        self
    }

    /// Script an attribute-verify result for a specific `(attr_type, commitment)` (builder style).
    pub fn with_attribute(mut self, attr_type: ZkAttrType, commitment: Hash, pass: bool) -> Self {
        self.attribute.insert((attr_type, commitment), pass);
        self
    }
}

impl ZkPassportVerifier for MockZkVerifier {
    fn verify_passport(&self, _proof: &[u8], public_inputs: &ZkPublicInputs) -> bool {
        let key = (public_inputs.nullifier, public_inputs.submitter_address);
        self.passport
            .get(&key)
            .copied()
            .unwrap_or(self.default_passport)
    }

    fn verify_attribute(
        &self,
        attr_type: ZkAttrType,
        commitment: &Hash,
        _attr_proof: &[u8],
    ) -> bool {
        self.attribute
            .get(&(attr_type, *commitment))
            .copied()
            .unwrap_or(self.default_attribute)
    }
}

// ---------------------------------------------------------------------------------------------
// CSCA trust-anchor registry (spec §7) — governance-upgradeable; a static curated genesis set.
// ---------------------------------------------------------------------------------------------

/// Lifecycle status of a [`CscaEntry`]. Only `Active` entries are folded into the
/// [`csca_registry_root`]; a `Revoked` key leaves the trust set (forward-invalidation, §7.4).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum CscaStatus {
    /// A trusted, in-use Country Signing Certification Authority key.
    #[default]
    Active,
    /// A compromised/expired key governance retired; proofs chaining to it no longer verify (§7.4).
    Revoked,
}

impl CscaStatus {
    /// The 1-byte canonical tag folded into `state_root`.
    pub fn tag(&self) -> u8 {
        match self {
            CscaStatus::Active => 0,
            CscaStatus::Revoked => 1,
        }
    }
}

/// A single CSCA trust anchor (spec §7.2). The chain trusts a passport's PA chain iff its DSC chains to
/// a CSCA `Active` in this registry. `key_id` is the unique key fingerprint; `pubkey` is the raw key
/// bytes (opaque to the runtime — only the verifier circuit interprets them). No PII; a CSCA is a
/// *sovereign signing key*, not a person.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CscaEntry {
    /// ICAO 3-letter country code (e.g. `b"USA"`). Informational/grouping; the `key_id` is the key.
    pub country_code: [u8; 3],
    /// The unique CSCA key fingerprint (the registry key — sorted on this).
    pub key_id: Hash,
    /// The raw CSCA public-key bytes (opaque; the circuit interprets them). Length-prefixed in the root.
    pub pubkey: Vec<u8>,
    /// Block height the entry was added at (provenance; folded into the root).
    pub added_at: u64,
    /// `Active` (trusted) or `Revoked` (retired — leaves the root, §7.4).
    pub status: CscaStatus,
}

impl CscaEntry {
    /// A fresh `Active` CSCA entry.
    pub fn active(country_code: [u8; 3], key_id: Hash, pubkey: Vec<u8>, added_at: u64) -> Self {
        Self {
            country_code,
            key_id,
            pubkey,
            added_at,
            status: CscaStatus::Active,
        }
    }
}

/// The deterministic 32-byte commitment over the **sorted `Active`** CSCA entries (spec §7.2). It is a
/// public input to every passport proof (§3.5), so "which CSCAs are trusted" is consensus state and a
/// proof is cryptographically bound to the exact trust set it was built against. Recomputed on every
/// registry mutation; committed in `state_root` (§5.3) so all nodes agree on the trust anchors.
///
/// Uses the **same FNV-1a-256 sponge** the `state_root` uses (dependency-free, integer-only, no float).
/// `Revoked` entries are excluded — revoking a key changes the root (forward-invalidation, §7.4). The
/// entries are sorted by `key_id` so the root is independent of insertion order (I1).
pub fn csca_registry_root(entries: &[CscaEntry]) -> Hash {
    let mut active: Vec<&CscaEntry> = entries
        .iter()
        .filter(|e| e.status == CscaStatus::Active)
        .collect();
    active.sort_by_key(|a| a.key_id);

    let mut h = CscaSponge::new();
    // Domain header pins the encoding — a format change is a new root, never a silent reinterpretation.
    h.bytes(b"ubi2/csca-root/1");
    h.u64(active.len() as u64);
    for e in &active {
        h.write(&e.country_code);
        h.write(&e.key_id);
        h.bytes(&e.pubkey);
        h.u64(e.added_at);
        // Status is always Active here (filtered), but fold the tag for forward-compat/explicitness.
        h.u8(e.status.tag());
    }
    h.finish()
}

/// A streaming 256-bit FNV-1a sponge — the same construction `state_root` uses (`contracts::fnv1a_256`),
/// inlined here so the CSCA root stays dependency-free and integer-only. Four lanes; canonical,
/// length-prefixed, tagged encoding so two distinct registries never collide.
struct CscaSponge {
    lanes: [u64; 4],
}

const FNV_PRIME: u64 = 0x0000_0100_0000_01B3;

impl CscaSponge {
    fn new() -> Self {
        let bases: [u64; 4] = [
            0xcbf2_9ce4_8422_2325,
            0x8422_2325_cbf2_9ce4u64.wrapping_mul(FNV_PRIME),
            0x1000_0000_0000_01B3,
            0xff00_ff00_ff00_ff00,
        ];
        let mut lanes = bases;
        for (i, l) in lanes.iter_mut().enumerate() {
            *l ^= (i as u64).wrapping_add(1).wrapping_mul(FNV_PRIME);
        }
        Self { lanes }
    }

    fn write(&mut self, data: &[u8]) {
        for lane in self.lanes.iter_mut() {
            let mut z = *lane;
            for &b in data {
                z ^= b as u64;
                z = z.wrapping_mul(FNV_PRIME);
            }
            *lane = z;
        }
    }

    fn u64(&mut self, v: u64) {
        self.write(&v.to_be_bytes());
    }

    fn u8(&mut self, v: u8) {
        self.write(&[v]);
    }

    fn bytes(&mut self, data: &[u8]) {
        self.u64(data.len() as u64);
        self.write(data);
    }

    fn finish(self) -> Hash {
        let mut out = [0u8; 32];
        for (i, lane) in self.lanes.into_iter().enumerate() {
            let mut z = lane;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^= z >> 31;
            out[i * 8..i * 8 + 8].copy_from_slice(&z.to_be_bytes());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> Hash {
        [b; 32]
    }
    fn addr(b: u8) -> Address {
        [b; 20]
    }

    #[test]
    fn assurance_default_is_std() {
        assert_eq!(Assurance::default(), Assurance::Std);
        assert_eq!(Assurance::Std.as_str(), "STD");
        assert_eq!(Assurance::Enh.as_str(), "ENH");
        assert_eq!(Assurance::Dual.as_str(), "DUAL");
        // Tags are distinct (state_root sensitivity).
        assert_ne!(Assurance::Std.tag(), Assurance::Enh.tag());
        assert_ne!(Assurance::Enh.tag(), Assurance::Dual.tag());
    }

    #[test]
    fn mock_default_passes_and_is_deterministic() {
        let v = MockZkVerifier::default();
        let pi = ZkPublicInputs::new(h(1), [h(0); 3], h(9), addr(1), 1_700_000_000, 0);
        assert!(v.verify_passport(b"ignored", &pi));
        assert_eq!(
            v.verify_passport(b"x", &pi),
            v.verify_passport(b"x", &pi),
            "same input ⇒ same bool (I1)"
        );
    }

    #[test]
    fn mock_scripts_per_nullifier_submitter() {
        let v = MockZkVerifier::new(false).with_passport(h(7), addr(3), true);
        let ok = ZkPublicInputs::new(h(7), [h(0); 3], h(9), addr(3), 0, 0);
        let wrong_sub = ZkPublicInputs::new(h(7), [h(0); 3], h(9), addr(4), 0, 0);
        let wrong_null = ZkPublicInputs::new(h(8), [h(0); 3], h(9), addr(3), 0, 0);
        assert!(v.verify_passport(b"", &ok), "scripted accept");
        assert!(
            !v.verify_passport(b"", &wrong_sub),
            "different submitter ⇒ reject (F-4)"
        );
        assert!(
            !v.verify_passport(b"", &wrong_null),
            "different nullifier ⇒ reject"
        );
    }

    #[test]
    fn injected_disagreement_stub_returns_wrong_bool() {
        // EC-7: one node's verifier stubbed to the wrong answer — the divergence M5 fork choice out-votes.
        let honest = MockZkVerifier::always(true);
        let stubbed = MockZkVerifier::always(false);
        let pi = ZkPublicInputs::new(h(1), [h(0); 3], h(9), addr(1), 0, 0);
        assert_ne!(
            honest.verify_passport(b"", &pi),
            stubbed.verify_passport(b"", &pi)
        );
    }

    #[test]
    fn csca_root_is_sorted_and_active_only() {
        let e1 = CscaEntry::active(*b"USA", h(2), vec![1, 2, 3], 0);
        let e2 = CscaEntry::active(*b"DEU", h(1), vec![4, 5, 6], 0);
        // Insertion order must not matter — the root sorts by key_id.
        let r_ab = csca_registry_root(&[e1.clone(), e2.clone()]);
        let r_ba = csca_registry_root(&[e2.clone(), e1.clone()]);
        assert_eq!(r_ab, r_ba, "CSCA root is insertion-order independent (I1)");

        // Revoking an entry changes the root (forward-invalidation, §7.4).
        let mut e1_rev = e1.clone();
        e1_rev.status = CscaStatus::Revoked;
        let r_rev = csca_registry_root(&[e1_rev, e2.clone()]);
        assert_ne!(
            r_ab, r_rev,
            "a revoked entry leaves the trust set ⇒ new root"
        );

        // Adding an entry changes the root (a new root is immediately usable, EC-10).
        let e3 = CscaEntry::active(*b"FRA", h(3), vec![7], 1);
        let r_added = csca_registry_root(&[e1, e2, e3]);
        assert_ne!(r_ab, r_added, "a new CSCA changes the root");
    }

    #[test]
    fn empty_registry_root_is_stable() {
        assert_eq!(csca_registry_root(&[]), csca_registry_root(&[]));
    }
}
