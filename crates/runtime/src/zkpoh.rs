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

/// The number of public signals in the **real** Self `vc_and_disclose` statement — CONFIRMED at 21
/// (VK `IC.len() == 22`) by the Stage-C de-risk (spec 06b §4.1). The verifying key encodes this arity;
/// a VK of any other arity is rejected fail-closed. Mirrors `ubi2_zkpoh::SELF_NPUBLIC`; kept here so the
/// runtime can bound-check + index the carried vector without depending on the crypto crate.
pub const SELF_NPUBLIC: usize = 21;

// --- The CONFIRMED 21-signal `vc_and_disclose` slot map (spec 06b §4.1). circom orders public signals
//     as OUTPUTS (declaration order) then public INPUTS in DECLARATION order — NOT the `public[...]`
//     list order — and `forbidden_countries_list_packed` is 4 field elements. Six independent Self
//     sources agree index-for-index. The runtime binds the policy-relevant slots BY INDEX (§4.4). ---

/// `revealedData_packed[3]` — slots 0,1,2. Stored opaquely as the three attribute commitments (I6).
pub const SELF_IDX_REVEALED_DATA: usize = 0;
/// `forbidden_countries_list_packed[4]` — slots 3,4,5,6. Pass-through (proof-tied, not a policy key).
pub const SELF_IDX_FORBIDDEN_COUNTRIES: usize = 3;
/// `nullifier` = Poseidon(secret, scope) — slot 7. Canonicality guard + uniqueness registry key (§3).
pub const SELF_IDX_NULLIFIER: usize = 7;
/// `attestation_id` — slot 8. Bound `== 1` (E-Passport) for `schemeTag = 0`.
pub const SELF_IDX_ATTESTATION_ID: usize = 8;
/// `merkle_root` — slot 9. Bound ∈ accepted Self identity roots (§2.2) — NOT our CSCA root.
pub const SELF_IDX_MERKLE_ROOT: usize = 9;
/// `current_date[6]` (YYMMDD ASCII) — slots 10..=15. Freshness window vs `block.timestamp` (§4.4).
pub const SELF_IDX_CURRENT_DATE: usize = 10;
/// `ofac_passportno_smt_root` — slot 16. Bound ∈ accepted OFAC roots kind 0 (§2.2).
pub const SELF_IDX_OFAC_PASSPORTNO: usize = 16;
/// `ofac_namedob_smt_root` — slot 17. Bound ∈ accepted OFAC roots kind 1.
pub const SELF_IDX_OFAC_NAMEDOB: usize = 17;
/// `ofac_nameyob_smt_root` — slot 18. Bound ∈ accepted OFAC roots kind 2.
pub const SELF_IDX_OFAC_NAMEYOB: usize = 18;
/// `scope` — slot 19. Bound `== UBI2_SELF_SCOPE` (§3).
pub const SELF_IDX_SCOPE: usize = 19;
/// `user_identifier` — slot 20. Bound `== submitter address` (tx sender) — anti-replay (§4.4).
pub const SELF_IDX_USER_IDENTIFIER: usize = 20;

/// The number of Pedersen attribute commitments a passport proof emits (age, nationality, expiry —
/// spec §3.4). Stored opaquely (I6); never plaintext. These are the `revealedData_packed` slots (0..3).
pub const NUM_ATTRIBUTE_COMMITMENTS: usize = 3;

/// The passport scheme/document-type discriminant for an ICAO-9303 e-passport (spec §2.4 forward-compat
/// `scheme_tag`). M6 ships only this scheme; an unknown tag is rejected fail-closed (§4.4 step 1).
pub const SCHEME_TAG_PASSPORT: u8 = 0;

/// The `attestation_id` a Self E-Passport disclosure proof carries (§4.1 slot 8). Bound `== 1`.
pub const SELF_ATTESTATION_ID_EPASSPORT: u64 = 1;

// ---------------------------------------------------------------------------------------------
// The canonical ubi2 scope (spec 06b §3) — one network-wide scope so ONE passport ⇒ exactly ONE
// nullifier on ubi2 (the Sybil key). Self's disclosure nullifier is `Poseidon(secret, scope)`:
// scope-bound, so the same passport under the same scope yields the same nullifier and different scopes
// are unlinkable. Uniqueness on ubi2 holds only if ubi2 uses exactly one scope network-wide.
// ---------------------------------------------------------------------------------------------

/// The human-readable scope seed the frontend passes as `SelfAppBuilder.scope` (spec 06b §3). The Self
/// off-chain scope derivation maps this string to the exact field scalar the proof carries in slot 19.
pub const UBI2_SELF_SCOPE_SEED: &str = "ubi2-poh";

/// The pinned canonical ubi2 scope scalar (32-byte big-endian) the runtime binds `signals[19]` against
/// (spec 06b §3, §4.4 step: scope). One scope network-wide ⇒ one-passport-one-human.
///
/// **PROVISIONAL (O-C5).** Self computes `scope` off-chain as a field element derived from the scope
/// string/endpoint (NOT the on-chain `PoseidonT3(addressHash, scopeSeed)` form — we deploy no verifier
/// contract). The exact scalar for [`UBI2_SELF_SCOPE_SEED`] is pinned from a real Self **staging** proof
/// captured by the C1 SDK flow (the load-bearing EC-C7 prerequisite). Until then this holds a documented
/// deterministic placeholder — the low-8-byte ASCII packing of the seed — so the binding mechanism, the
/// SDK↔Rust parity, and every non-real-proof test are exercisable. Flipping the real verifier to the
/// value-minting default is gated on replacing this with the fixture value (EC-C7). A change here is a
/// consensus migration, never silent.
pub const UBI2_SELF_SCOPE: Hash = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x75, 0x62, 0x69, 0x32, 0x2d, 0x70, 0x6f, 0x68,
];

/// The freshness window (in blocks) an accepted Self root stays valid for (spec 06b §2.2, O-C3). A
/// pinned root is "∈ the accepted set" only while `now_block − pinned_at_block ≤` this. A single pinned
/// root would reject valid fresh proofs; accept-any would lose revocation/OFAC guarantees — so the
/// window is explicit and root updates are governance events. Devnet starting value (tuned at the gate).
pub const SELF_ROOT_WINDOW_BLOCKS: u64 = 5_000_000;

/// The proof-date freshness window (in seconds) `current_date` may deviate from `block.timestamp` by
/// (spec 06b §4.4 step 5, O-C3). Ties the in-circuit not-expired reference to chain time deterministically.
/// Devnet starting value (± ~2 days, so a proof produced within a couple of days of inclusion passes).
pub const SELF_DATE_WINDOW_SECS: u64 = 172_800;

/// The OFAC-root kinds (spec 06b §2.2) — the three Self OFAC SMT trees, one per slot 16/17/18.
pub const OFAC_KIND_PASSPORTNO: u8 = 0;
pub const OFAC_KIND_NAMEDOB: u8 = 1;
pub const OFAC_KIND_NAMEYOB: u8 = 2;

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

/// The **full** Self `vc_and_disclose` public-signal vector for `submitZkPassportProof`, carried
/// on-chain verbatim (spec 06b §4.3). Because a real proof's public vector is fixed by the circuit, the
/// runtime cannot reconstruct it from a few domain fields — it must RECEIVE it. `crates/zkpoh` converts
/// each of the 21 signals to a BN254 field element by the single canonical mapping and verifies against
/// the pinned VK — no adapter, no zeroing. The runtime derives the policy fields BY INDEX (§4.4) and
/// keeps no field-element math (staying crypto-free).
///
/// Slot map (CONFIRMED, spec 06b §4.1): `revealedData_packed[0..3]`, `forbidden_countries_list_packed
/// [3..7]`, `nullifier@7`, `attestation_id@8`, `merkle_root@9`, `current_date[10..16]`, OFAC roots
/// `@16,17,18`, `scope@19`, `user_identifier@20`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ZkPublicInputs {
    /// The raw 21-element public vector (snarkjs order, §4.1), each a 32-byte big-endian field value.
    pub signals: [Hash; SELF_NPUBLIC],
}

impl ZkPublicInputs {
    /// Wrap the raw 21-signal vector. Pure: no clock, no allocation beyond the struct.
    pub fn new(signals: [Hash; SELF_NPUBLIC]) -> Self {
        Self { signals }
    }

    /// The `nullifier` (slot 7) — the one-passport-one-human registry key (§3.3, §4.1).
    pub fn nullifier(&self) -> Hash {
        self.signals[SELF_IDX_NULLIFIER]
    }

    /// The three `revealedData_packed` slots (0,1,2) — stored opaquely as attribute commitments (I6).
    pub fn attribute_commitments(&self) -> [Hash; NUM_ATTRIBUTE_COMMITMENTS] {
        [
            self.signals[SELF_IDX_REVEALED_DATA],
            self.signals[SELF_IDX_REVEALED_DATA + 1],
            self.signals[SELF_IDX_REVEALED_DATA + 2],
        ]
    }

    /// The `attestation_id` slot (8) — bound `== 1` (E-Passport) for `schemeTag = 0`.
    pub fn attestation_id(&self) -> Hash {
        self.signals[SELF_IDX_ATTESTATION_ID]
    }

    /// The `merkle_root` slot (9) — bound ∈ accepted Self identity roots (§2.2).
    pub fn merkle_root(&self) -> Hash {
        self.signals[SELF_IDX_MERKLE_ROOT]
    }

    /// The OFAC-root slot for `kind` (0→16, 1→17, 2→18) — bound ∈ accepted OFAC roots for that kind.
    pub fn ofac_root(&self, kind: u8) -> Hash {
        self.signals[SELF_IDX_OFAC_PASSPORTNO + kind as usize]
    }

    /// The six `current_date` slots (10..=15), each an ASCII-digit field element (YYMMDD).
    pub fn current_date(&self) -> [Hash; 6] {
        let mut out = [[0u8; 32]; 6];
        out.copy_from_slice(&self.signals[SELF_IDX_CURRENT_DATE..SELF_IDX_CURRENT_DATE + 6]);
        out
    }

    /// The `scope` slot (19) — bound `== UBI2_SELF_SCOPE` (§3).
    pub fn scope(&self) -> Hash {
        self.signals[SELF_IDX_SCOPE]
    }

    /// The `user_identifier` slot (20) — bound `== submitter address` (tx sender) — anti-replay (§4.4).
    pub fn user_identifier(&self) -> Hash {
        self.signals[SELF_IDX_USER_IDENTIFIER]
    }

    /// The `user_identifier` interpreted as a 20-byte ubi2 address (the low 20 bytes of slot 20). The
    /// mock verifier keys on this + the nullifier, so the state machine is exercisable without pairing.
    pub fn submitter_address(&self) -> Address {
        let s = self.signals[SELF_IDX_USER_IDENTIFIER];
        let mut a = [0u8; 20];
        a.copy_from_slice(&s[12..32]);
        a
    }
}

/// Encode a `u64` as a 32-byte big-endian [`Hash`] (the on-chain `bytes32` form the runtime compares an
/// integer-valued signal, e.g. `attestation_id`, against). Pure integer — no float, no crypto.
pub fn u64_to_hash(v: u64) -> Hash {
    let mut h = [0u8; 32];
    h[24..32].copy_from_slice(&v.to_be_bytes());
    h
}

/// Zero-extend a 20-byte address to a 32-byte big-endian [`Hash`] (the `user_identifier` slot form the
/// runtime binds the tx sender against — spec 06b §4.4). Pure integer.
pub fn address_to_hash(addr: &Address) -> Hash {
    let mut h = [0u8; 32];
    h[12..32].copy_from_slice(addr);
    h
}

/// Decode the six `current_date` ASCII-digit signals (YYMMDD, each a 32-byte big-endian field value
/// whose meaningful content is a single ASCII byte) into the unix-second timestamp of that civil day at
/// 00:00 UTC, or `None` if any signal is not a `'0'..='9'` ASCII digit (fail-closed, spec 06b §4.4
/// step 5). Assumes 20YY (2000..2099 — Self e-passport dates). Pure integer arithmetic (Howard Hinnant
/// days-from-civil), so it is bit-reproducible across nodes (no chrono, no float, no clock).
pub fn current_date_to_epoch(date: &[Hash; 6]) -> Option<u64> {
    let mut digits = [0u8; 6];
    for (i, sig) in date.iter().enumerate() {
        // A valid current_date signal is a small integer (an ASCII digit code): all high bytes zero.
        if sig[..31].iter().any(|&b| b != 0) {
            return None;
        }
        let b = sig[31];
        if !b.is_ascii_digit() {
            return None;
        }
        digits[i] = b - b'0';
    }
    let yy = digits[0] as i64 * 10 + digits[1] as i64;
    let mm = digits[2] as i64 * 10 + digits[3] as i64;
    let dd = digits[4] as i64 * 10 + digits[5] as i64;
    if !(1..=12).contains(&mm) || !(1..=31).contains(&dd) {
        return None;
    }
    let year = 2000 + yy;
    // days_from_civil (Howard Hinnant): days since 1970-01-01 for `year-mm-dd`.
    let y = if mm <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let doy = (153 * (if mm > 2 { mm - 3 } else { mm + 9 }) + 2) / 5 + dd - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    let days = era * 146_097 + doe - 719_468;
    if days < 0 {
        return None;
    }
    Some(days as u64 * 86_400)
}

/// The BN254 scalar-field order `r` (big-endian). `crates/zkpoh` reduces every 32-byte public input by
/// this modulus via `Fr::from_be_bytes_mod_order`, so a value `≥ r` is folded into a *different*
/// canonical element than its raw bytes. Pinned here as bytes so the runtime stays dependency-free
/// (no arkworks): `r = 0x30644e72…f0000001`.
pub const BN254_FR_MODULUS_BE: Hash = [
    0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29, 0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
    0x28, 0x33, 0xe8, 0x48, 0x79, 0xb9, 0x70, 0x91, 0x43, 0xe1, 0xf5, 0x93, 0xf0, 0x00, 0x00, 0x01,
];

/// Is `bytes` the **canonical** BN254 scalar representation — strictly `< r`? Pure big-endian integer
/// compare (most-significant byte first).
///
/// The malleability guard the public-input contract requires (§3.5): only a canonical 32-byte value
/// round-trips (`bytes == Fr::from_be_bytes_mod_order(bytes)` serialized), so the runtime's raw-byte
/// registry key for the nullifier equals the element the proof actually commits to. Rejecting `≥ r`
/// blocks the `N, N+r, N+2r…` family that would otherwise register as distinct humans from ONE passport.
/// A genuine proof's field outputs are always canonical, so this never rejects a valid submission.
pub fn is_canonical_scalar(bytes: &Hash) -> bool {
    for (b, m) in bytes.iter().zip(BN254_FR_MODULUS_BE.iter()) {
        if b != m {
            return b < m;
        }
    }
    // bytes == r exactly is NON-canonical (r ≡ 0 in the field).
    false
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
        // The scripted key is `(nullifier@7, submitter/user_identifier@20)` — both derived from the
        // full carried vector (spec 06b §4.3), so the mock exercises the state machine with no pairing.
        let key = (public_inputs.nullifier(), public_inputs.submitter_address());
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

// ---------------------------------------------------------------------------------------------
// Self-root anchor registry (spec 06b §2) — the reconciliation crux. A real Self disclosure proof
// commits to the root of Self's OWN identity-commitment registry (a Poseidon Lean-IMT root), NOT to our
// CSCA sponge. To accept a real proof, ubi2 tracks + pins Self's identity root(s) + the three OFAC SMT
// roots as external trust anchors, governance-gated + windowed. Deterministic, folded into state_root.
// The CSCA registry above is RETAINED (reserved for the own-stack milestone, O-C1) but inactive on the
// Self verify path.
// ---------------------------------------------------------------------------------------------

/// An accepted Self **identity-commitment** registry root (spec 06b §2.2). A real `vc_and_disclose`
/// proof's `merkle_root` (slot 9) must be a member of this set AND still within
/// [`SELF_ROOT_WINDOW_BLOCKS`] of the current height. Governance pins/retires these as Self's Lean-IMT
/// root rotates. No PII — a registry root is a Poseidon hash, not a person.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfIdentityRoot {
    /// The Poseidon Lean-IMT root Self's IdentityRegistry currently publishes (opaque 32-byte scalar).
    pub root: Hash,
    /// The block height governance pinned it at (the window clock — folded into `state_root`).
    pub pinned_at_block: u64,
}

/// An accepted Self **OFAC SMT** root (spec 06b §2.2). Self's TEE-authorized OFAC updater rotates three
/// SMT roots (passport-no / name+DOB / name+YOB); a proof's `signals[16..19]` must each be a member of
/// the accepted set for its `kind`, within the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SelfOfacRoot {
    /// `0 = passportno`, `1 = namedob`, `2 = nameyob` ([`OFAC_KIND_PASSPORTNO`] …).
    pub kind: u8,
    /// The OFAC SMT root (opaque 32-byte scalar).
    pub root: Hash,
    /// The block height governance pinned it at (folded into `state_root`).
    pub pinned_at_block: u64,
}

/// Is `root` an accepted Self identity root at `now_block` — present AND still within the freshness
/// window (spec 06b §2.2)? Pure function of state + height (no wall-clock). A stale set only fails
/// *closed* (new proofs rejected until a fresh root is pinned) — never a safety break.
pub fn self_identity_root_accepted(
    roots: &[SelfIdentityRoot],
    root: &Hash,
    now_block: u64,
) -> bool {
    roots.iter().any(|e| {
        &e.root == root && now_block.saturating_sub(e.pinned_at_block) <= SELF_ROOT_WINDOW_BLOCKS
    })
}

/// Is `root` an accepted Self OFAC root of `kind` at `now_block`, within the freshness window? Pure.
pub fn self_ofac_root_accepted(
    roots: &[SelfOfacRoot],
    kind: u8,
    root: &Hash,
    now_block: u64,
) -> bool {
    roots.iter().any(|e| {
        e.kind == kind
            && &e.root == root
            && now_block.saturating_sub(e.pinned_at_block) <= SELF_ROOT_WINDOW_BLOCKS
    })
}

/// The deterministic 32-byte commitment over the sorted Self-root registries (spec 06b §2, §13). Folded
/// into `state_root` so all nodes agree on the trust set to the bit. Identity roots sorted by `root`;
/// OFAC roots sorted by `(kind, root)`. Uses the same FNV-1a-256 sponge the CSCA root + `state_root` use
/// (dependency-free, integer-only, no float). Provided for `ubi_getSelfRoots` and diagnostics; the
/// state-root fold commits the same entries directly (see `state_root.rs`).
pub fn self_root_registry_root(identity: &[SelfIdentityRoot], ofac: &[SelfOfacRoot]) -> Hash {
    let mut ids: Vec<&SelfIdentityRoot> = identity.iter().collect();
    ids.sort_by_key(|e| e.root);
    let mut ofacs: Vec<&SelfOfacRoot> = ofac.iter().collect();
    ofacs.sort_by_key(|e| (e.kind, e.root));

    let mut h = CscaSponge::new();
    h.bytes(b"ubi2/self-root/1");
    h.u64(ids.len() as u64);
    for e in &ids {
        h.write(&e.root);
        h.u64(e.pinned_at_block);
    }
    h.u64(ofacs.len() as u64);
    for e in &ofacs {
        h.u8(e.kind);
        h.write(&e.root);
        h.u64(e.pinned_at_block);
    }
    h.finish()
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
    /// Build a 21-signal vector carrying `nullifier@7` and `submitter@20` (the pair the mock keys on).
    fn pi(nullifier: Hash, submitter: Address) -> ZkPublicInputs {
        let mut s = [[0u8; 32]; SELF_NPUBLIC];
        s[SELF_IDX_NULLIFIER] = nullifier;
        s[SELF_IDX_USER_IDENTIFIER] = address_to_hash(&submitter);
        ZkPublicInputs::new(s)
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
        let p = pi(h(1), addr(1));
        assert!(v.verify_passport(b"ignored", &p));
        assert_eq!(
            v.verify_passport(b"x", &p),
            v.verify_passport(b"x", &p),
            "same input ⇒ same bool (I1)"
        );
    }

    #[test]
    fn mock_scripts_per_nullifier_submitter() {
        let v = MockZkVerifier::new(false).with_passport(h(7), addr(3), true);
        assert!(
            v.verify_passport(b"", &pi(h(7), addr(3))),
            "scripted accept"
        );
        assert!(
            !v.verify_passport(b"", &pi(h(7), addr(4))),
            "different submitter ⇒ reject (F-4)"
        );
        assert!(
            !v.verify_passport(b"", &pi(h(8), addr(3))),
            "different nullifier ⇒ reject"
        );
    }

    #[test]
    fn injected_disagreement_stub_returns_wrong_bool() {
        // EC-7: one node's verifier stubbed to the wrong answer — the divergence M5 fork choice out-votes.
        let honest = MockZkVerifier::always(true);
        let stubbed = MockZkVerifier::always(false);
        let p = pi(h(1), addr(1));
        assert_ne!(
            honest.verify_passport(b"", &p),
            stubbed.verify_passport(b"", &p)
        );
    }

    #[test]
    fn current_date_decode_and_freshness() {
        // 2023-11-14 as YYMMDD ASCII digits: '2','3','1','1','1','4'.
        let mut date = [[0u8; 32]; 6];
        for (i, b) in [b'2', b'3', b'1', b'1', b'1', b'4'].iter().enumerate() {
            date[i] = u64_to_hash(*b as u64);
        }
        let epoch = current_date_to_epoch(&date).expect("valid YYMMDD");
        // 2023-11-14 00:00 UTC = 1_699_920_000.
        assert_eq!(epoch, 1_699_920_000);
        // A non-digit signal fails closed.
        let mut bad = date;
        bad[0] = u64_to_hash(b'Z' as u64);
        assert!(current_date_to_epoch(&bad).is_none());
    }

    #[test]
    fn self_root_windowing_and_root_commitment() {
        let ids = vec![SelfIdentityRoot {
            root: h(0xAA),
            pinned_at_block: 10,
        }];
        assert!(self_identity_root_accepted(&ids, &h(0xAA), 10));
        assert!(self_identity_root_accepted(
            &ids,
            &h(0xAA),
            10 + SELF_ROOT_WINDOW_BLOCKS
        ));
        assert!(!self_identity_root_accepted(
            &ids,
            &h(0xAA),
            11 + SELF_ROOT_WINDOW_BLOCKS
        ));
        assert!(!self_identity_root_accepted(&ids, &h(0xBB), 10));
        // The registry root is insertion-order independent + sensitive to content.
        let ofac = vec![SelfOfacRoot {
            kind: 0,
            root: h(0x01),
            pinned_at_block: 0,
        }];
        assert_eq!(
            self_root_registry_root(&ids, &ofac),
            self_root_registry_root(&ids, &ofac)
        );
        assert_ne!(
            self_root_registry_root(&ids, &ofac),
            self_root_registry_root(&[], &ofac)
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
