# 06 — ZK-Passport Proof of Humanity

- **Milestone:** M6. **Status:** specified (docs-only; implementation begins after M5 ships).
- **Owner:** architect. **Decisions pinned in:** [`adr/0005-zk-passport-poh.md`](adr/0005-zk-passport-poh.md).
- **Product brief:** [`../milestones/zk-passport-poh.md`](../milestones/zk-passport-poh.md). **Invariants:** [`00-overview.md`](00-overview.md).
- **Reuses:** M3 [`03-proof-of-humanity.md`](03-proof-of-humanity.md) (HumanityHub, `Human`, case lifecycle,
  PoH NFT), M5 [`05-p2p-network.md`](05-p2p-network.md) (cross-node quorum, `state_root`).
- **Prior art (read-only):** `../ubi.chain`, `../ubi.agent`, `../ubi.wallet`.

This spec adds an **optional, additive, privacy-preserving** proof-of-humanity path: a zero-knowledge
proof over an **ICAO-9303 NFC e-passport** that yields a cryptographic one-passport-one-human
**nullifier** and a set of opaque **attribute commitments**, verified by a **pure deterministic SNARK
verifier inside the consensus path**. It never replaces the M3 vouching + AI-jury path; it sits beside it
under an **assurance-level** model. The heavy proving stays **client-side**; only the proof + public
inputs reach the chain.

It is written acceptance-criteria-first (§10). Every exit criterion EC-1…EC-10 from the brief maps 1:1 to
a test assertion here.

---

## 0. The invariants this milestone exists to prove (and never weaken)

> **I4 (the cleanest realization).** ZK-passport verification is **pure deterministic cryptography** — no
> LLM, no probabilistic AI in the verify path. Pairing/field arithmetic over a fixed proof + public
> inputs is a *function*, reproducible to the bit across nodes. It therefore slots into the deterministic
> consensus path **more cleanly than the AI jury**: there is nothing to "agree" about the math; honest
> nodes that re-run the verifier get the same boolean. It is the **strongest and most deterministic PoH
> path** the project has.

> **I6 (structural, not by policy).** The chain stores **only commitments** — a nullifier and Pedersen
> attribute commitments — never name, document number, exact date of birth, or nationality in plaintext.
> Privacy is enforced by what the circuit emits, not by an access-control rule that could be misconfigured.

> **The inclusion constraint (non-negotiable, from the brief).** ZK-passport is **never the sole gate.**
> ~20% of the world's adults hold no valid passport, concentrated in exactly the populations UBI most
> needs to reach. A human without a passport verifies via M3 vouching at `STD` level with **identical UBI
> eligibility.** Level is metadata for *features*, never a gate on UBI accrual.

Three structural rules frame every decision below (all inherited, none relaxed):

1. **`crates/runtime` stays deterministic and dependency-free.** No floats, no wall-clock, no `HashMap`
   ordering, no async, no `libp2p`/`tokio`/`reqwest`. The SNARK verifier the runtime calls must itself be
   **deterministic and free of those deps** — see §6 and ADR-0005 Decision 2. The build-level dependency
   test is *extended* to forbid any non-deterministic dependency reachable from the verifier path.
2. **Heavy proving is client-side.** NFC read + witness generation + proof generation happen **off-chain
   on the user's device** (browser/mobile WASM — synergy with the Light-Node track, §8). The chain only
   ever sees the proof bytes and the public inputs.
3. **No new consensus primitive.** The op rides the existing HumanityHub tx surface, the existing `Human`
   record + PoH NFT, and (for the cross-node quorum framing, EC-7) the existing M5 case machinery — see
   §5 and ADR-0005 Decision 5.

---

## 1. Scope

**In scope (Stages A–D):**
- A pinned **standard + circuit + proof system** for ICAO-9303 e-passport ZK (§2, ADR-0005 Decision 1).
- A **client-side proving pipeline** (off-chain): NFC read → passive-authentication witness → proof +
  public inputs (§3). Establishes the **CSCA registry format** and the **nullifier derivation**.
- A **pure deterministic on-chain verifier** in an isolated `crates/zkpoh` crate, called by `runtime`
  via a trait (§6). Pairing/field verification reproducible to the bit across nodes (I1/I2).
- A new HumanityHub op **`submitZkPassportProof(...)`** (§4) and a new `Human` assurance level + on-chain
  **nullifier registry** + **attribute-commitment store** (§5).
- An on-chain, **governance-upgradeable CSCA trust-anchor registry** (§7) with a curated static genesis set.
- Cross-node framing so the op's commit is a quorum decision, not a single node's (§5.4, EC-7).
- PoH-NFT metadata reflecting `STD` / `ENH` / `DUAL` (§5.5, EC-6).
- A new read surface: `ubi_getAttributes(address)`, assurance level on `ubi_getHuman` (§9).
- Stage D: one **attribute verifier** (`over18`) as the template for M7 DAO gates (§4.4, EC-9).

**Out of scope (deferred / M7+):**
- DAO membership gates, citizenship-gated streams/contracts (M7 — this milestone *provides the substrate*).
- Attribute verifiers beyond `over18` (nationality-bucket, expiry) — M7, same template.
- Additional document types (national ID cards, residence permits, mDL/EUDI) — backlog (§2.4 notes the
  forward-compatible shape).
- Revocation of a *spent* nullifier / passport renewal re-binding — §7.4 notes the policy; mechanism is M7.
- Replacing or deprecating the M3 vouching path — explicitly never.

---

## 2. The standard, circuit, and proof system (the load-bearing crypto choice)

This is the most costly-to-reverse decision (wire formats, the verifying key, the nullifier derivation,
and the public-input layout all interoperate forever once a nullifier is registered). It is pinned in
**ADR-0005 Decision 1**; summarized here.

### 2.1 The two document families evaluated

| Family | What it is | Verdict |
|---|---|---|
| **ICAO-9303 NFC e-passport + Passive Authentication + ZK** (zkPassport, Self, OpenPassport, Rarimo) | The chip in a modern passport stores signed **Data Groups** (DG1 = MRZ, DG2 = photo, …); the **SOD** (Document Security Object) signs their hashes with a **Document Signer Certificate (DSC)**; the DSC is signed by a per-country **CSCA**. A ZK circuit proves "the SOD verifies under a DSC chained to a trusted CSCA, and field X has property Y" without revealing the fields. | **CHOSEN.** Globally deployed today, sovereign-issued, strong anti-forgery incentives, mature open-source ZK stacks. |
| **EU EUDI-Wallet / ISO-18013-5 mDL selective disclosure** (SD-JWT-VC, mDoc) | Issuer-signed verifiable credentials with selective disclosure / BBS+; the EU Digital Identity Wallet and mobile driving licences. | **NOT chosen for M6.** Excellent privacy-by-design, but penetration is EU-centric and nascent (rollout through 2026–2027), the trust anchor is a federation of national issuers rather than the single global ICAO masterlist, and it would *narrow* inclusion at launch. Kept as a **forward-compatible second document type** (§2.4): the assurance model, nullifier abstraction, and attribute-commitment store are issuer-agnostic so an mDL path can be added in a later milestone without a hard fork. |

### 2.2 The ZK stack: adapt OpenPassport / Self, do not write a circuit from scratch

**Decision (ADR-0005 D1):** **integrate an existing, audited e-passport ZK circuit** — the
**OpenPassport / Self protocol** family — rather than authoring passive-authentication + RSA/ECDSA-in-ZK
from scratch. Rationale: passive-authentication-in-a-circuit (RSA-2048/4096 and ECDSA-P256 signature
verification, SHA-256 of the data groups, MRZ parsing, certificate-chain checks) is a large, subtle,
security-critical body of work; a from-scratch circuit is exactly where soundness bugs (and thus
fake-human admissions) live. The brief mandates "integrate an EXISTING stack, do NOT build from scratch."
We adapt: (a) the **nullifier derivation** to bind to *our* chain id + user address (§3.3), (b) the
**public-input layout** to emit *our* attribute commitments (§3.4), and (c) the **CSCA root input** to
read *our* on-chain registry (§7).

### 2.3 The proof system: Groth16 (with an honest trusted-setup accounting)

**Decision (ADR-0005 D1):** the on-chain verifier consumes **Groth16** proofs over **BN254 (alt-bn128)**.

Why Groth16/BN254 specifically, against the §6 constraints:
- **Smallest verifier, smallest proof, fastest verify.** A Groth16 verify is a fixed **3-pairing**
  equation (`e(A,B) = e(α,β)·e(L,γ)·e(C,δ)`) plus one multi-scalar-multiplication over the public inputs.
  Proof is **~200 bytes** (3 group elements). Verify is **constant-time, ~milliseconds, allocation-light**
  — it fits the "verifier fits in the WASM-compilable runtime with no external calls" constraint best of
  any option. This is the **dominant** criterion: the verifier runs in the consensus path on every node.
- **BN254 because it is the curve every chain's precompile and every Rust pairing crate supports**, and
  the one the OpenPassport/Self artifacts already target — minimizing adaptation.

**The trusted-setup cost, stated plainly (ADR-0005 D1, security gate item):** Groth16 needs a
**circuit-specific trusted setup** (a per-circuit Phase-2 ceremony on top of a universal Phase-1 powers-of-tau).
If the setup's toxic waste is not destroyed, a holder can forge proofs for *that circuit* → **forge a fake
human**. Mitigations, all mandatory:
1. **Reuse a public, multi-party Phase-1** (e.g. the established perpetual powers-of-tau).
2. **Run an open, multi-contributor Phase-2 ceremony** for our exact circuit; publish all transcripts and
   a verification script; 1-of-N honest contributors suffices for soundness.
3. **Pin the resulting verifying key in genesis**, hash-committed in the `state_root` (§5.3) and in
   ADR-0005, so a swap is a consensus change, never silent.
4. **Document the trust assumption** in the threat model (§11) for the security gate.

**Alternatives considered, deferred to the backlog (ADR-0005 D1):**
- **PLONK / Honk (universal/updatable setup):** removes the *per-circuit* ceremony (one universal SRS
  serves any circuit), which is materially safer operationally. Rejected for M6 only because verify is
  heavier/larger and the verifier code is more complex to land deterministically in `runtime` *now*; it
  is the **documented upgrade path** when the circuit changes or a second document type is added — the
  verifier trait (§6) is written so the proof system behind it can be swapped without touching the op,
  the nullifier registry, or the attribute store.
- **STARKs / SP1 / RISC-Zero (no trusted setup, transparent):** strongest setup story, but proofs and
  verifiers are far larger/heavier — a poor fit for an in-runtime, per-block verifier and for a 60-second
  in-browser prover on a phone. Backlog.

### 2.4 Forward-compatibility (issuer-agnostic by construction)

The assurance level, the nullifier abstraction (a 32-byte scalar + a 1-byte *scheme* tag), the
attribute-commitment store, and the CSCA-style trust registry are all **document-type-agnostic**. Adding
mDL/EUDI later is: a new circuit + verifying key, a new trust-anchor set, a new scheme tag — **no change**
to the `Human` record shape, the op-dispatch pattern, or `state_root` framing. This keeps M6 from
foreclosing the EUDI path the brief flagged.

---

## 3. Client-side proving pipeline (off-chain; Stage A) — nothing personal leaves the device

The entire heavy path is on the user's device. The chain sees only `(proof, public_inputs)`.

### 3.1 NFC read (device)

Using the phone's NFC reader (mobile app, or the Light-Node WASM companion, §8), the app performs **Basic
Access Control / PACE** (deriving the session key from the MRZ the user types or scans optically) and reads
the signed data groups + the SOD. **The raw passport bytes never leave the device and are never sent to any
node** (I6). This is the part that *requires* a device with NFC — the app shows a **graceful fallback to the
M3 vouching path** when NFC or a chip is absent (failure-mode F-7, §10.1).

### 3.2 Passive Authentication (in-circuit)

The circuit proves, in zero knowledge:
1. **SOD integrity:** the data-group hashes the SOD commits to match the read data groups (SHA-256).
2. **DSC signature:** the SOD is correctly signed by a Document Signer Certificate's public key
   (RSA-2048/4096 or ECDSA-P256, per the issuing country).
3. **CSCA chain:** the DSC's certificate is signed by a **CSCA public key present in the on-chain CSCA
   registry** (§7) — the registry root/set is a **public input**, so the proof is only valid against the
   trust anchors the chain actually trusts (this is what makes "untrusted CSCA root ⇒ reject", EC-3).
4. **Not expired:** the document expiry (DG1 MRZ) is **≥ a chain-supplied `now` epoch** that is a public
   input (the block timestamp at submission, §4.2). An expired document fails *in-circuit* (failure-mode
   F-1).

> **Active Authentication / clone detection (noted, scoped):** ICAO PA proves the *data* is genuinely
> government-signed; it does **not** by itself prove the chip is not a cloned copy of a genuine chip's
> data. Active/Chip Authentication (a challenge-response to a chip-held private key) is the anti-clone
> measure. M6 ships PA (universally supported); AA/CA support where the chip provides it is a Stage-D
> hardening item and a §11 threat-model entry, not a launch blocker. Documented, not hidden.

### 3.3 Nullifier derivation (the one-passport-one-human core)

A **deterministic, one-way, address-and-chain-bound** scalar:

```
document_secret = H_circuit( DSC_pubkey_fingerprint || document_number || issuing_country )   // in-circuit, never revealed
nullifier       = H_circuit( document_secret || CHAIN_ID || PASSPORT_SCHEME_TAG )              // public output
```

Properties the circuit must enforce (ADR-0005 D1; tested in Stage A):
- **One-way:** `nullifier` cannot be inverted to `document_secret` or any MRZ field (it is a circuit hash
  output; the preimage stays a private witness).
- **Per-chain:** binding `CHAIN_ID` means a nullifier from this chain is meaningless on another (no
  cross-chain linkage of the same human — unlinkability across chains).
- **Per-passport-not-per-address (the uniqueness binding):** the nullifier binds to the **document**, not
  the address. The *same passport* always yields the *same* nullifier on this chain, so a second address
  presenting a proof from the same passport produces a nullifier **already in the registry** → rejected
  (EC-2). The submitting **address** is bound separately as a public input the proof is *over* (§4.3) so a
  proof cannot be replayed by a different submitter (§3.5).

> **Design note — why not bind the nullifier to the address.** Binding the nullifier to `(document,
> address)` would let one passport register *many* addresses (one nullifier each) — defeating uniqueness.
> Binding to `(document, chain)` only is what enforces one-passport-one-human-per-chain. Address-binding
> is achieved by making the **address a public input the proof commits to** (anti-replay), not by mixing
> it into the nullifier.

### 3.4 Attribute commitments (Pedersen; opaque on-chain)

The same proof emits **Pedersen commitments** (over BN254) to a fixed, ordered set of attributes, each a
public output. M6 emits three (ADR-0005 D1):

| Index | Attribute | Committed scalar | Why a bucket, not the value |
|---|---|---|---|
| 0 | **Age threshold** | `born_before_epoch` for the 18-year and 21-year thresholds (i.e. the circuit proves DOB ≤ `now − 18y` and emits a commitment to that fact), **not** the raw DOB. | Never store an exact birth date (I6). The Stage-D `over18` verifier proves a statement *about this commitment* (§4.4). |
| 1 | **Nationality bucket** | `H(MRZ_nationality_code)` (a hash, not the plaintext code). | Lets a future DAO prove "from country X" by proving the preimage, without the chain ever holding the plaintext. |
| 2 | **Document expiry** | `expiry_epoch` committed (not the validity flag alone — the *epoch* so a future verifier can prove "valid after Y"). | Reusable expiry gate for M7. |

Each commitment is `C_i = g^{m_i} · h^{r_i}` (Pedersen), where `m_i` is the attribute scalar and `r_i` is a
**per-attribute blinding factor** the user's device keeps. Stored on-chain as a 32-byte field element each.
**Hiding:** without `r_i`, `C_i` reveals nothing about `m_i` (perfectly hiding). **Binding:** the user
cannot later open `C_i` to a different `m_i`. **Unlinkability:** the blinding makes two users' identical
attributes (e.g. both over-18) produce *different* commitments, so the store cannot be used to cluster
humans by attribute (§11). The blinding factors are part of the device-held secret material the user needs
to later prove an attribute (§4.4).

### 3.5 The public-input vector (the wire contract — pinned)

The proof's public inputs, in **fixed canonical order** (ADR-0005 D1; changing the order/contents is a new
circuit + verifying key, never a silent break — exactly as M5 versions wire formats):

```
public_inputs = [
  nullifier,                  // 32-byte field element (§3.3)
  attr_commit[0..3],          // 3 × 32-byte Pedersen commitments (§3.4)
  csca_registry_root,         // 32-byte commitment to the trusted CSCA set the proof verifies against (§7.2)
  submitter_address,          // the 20-byte address (zero-extended) the proof is bound to — anti-replay (§3.3 note)
  now_epoch,                  // the chain-supplied "current time" the not-expired check used (§3.2)
  passport_scheme_tag         // 1-byte (zero-extended) document-type/scheme discriminant — forward-compat (§2.4)
]
```

The runtime **re-derives** `csca_registry_root`, `submitter_address`, and `now_epoch` from on-chain state
+ the tx + the block (§4.2/§4.3) and **rejects** the proof if the public inputs do not match — so a valid
proof cannot be lifted to a different submitter, a different CSCA set, or a stale time. This is the
fail-closed binding that prevents replay (F-4) and trust-anchor confusion (EC-3).

---

## 4. The on-chain operation — `submitZkPassportProof`

### 4.1 HumanityHub op (EVM tx, MetaMask-signable — same pattern as M3)

A new operation on the existing **HumanityHub** (`0x…5048`), decoded by `crates/rpc` exactly as the M3 ops
(`requestVerification` / `vouch` / `challenge` / `submitVerdict`) are — a fixed 4-byte selector over an
ABI-encoded calldata, so MetaMask signs it unchanged (I3, ADR-0003's precompile pattern):

```solidity
// added to the HumanityHub interface decoded in crates/rpc/src/humanity.rs
function submitZkPassportProof(
    bytes  proof,                 // ~200-byte Groth16 proof (3 BN254 group elements)
    bytes32 nullifier,
    bytes32[3] attributeCommitments,
    bytes32 cscaRegistryRoot,
    uint8  schemeTag,
    uint64 nowEpoch               // the not-expired reference epoch the proof used (validated == block ts, §4.2)
) external;
```

`submitter_address` is **not** in calldata — it is `ecrecover(tx.sig)`, the tx sender, so it cannot be
forged. Gas: a new constant `GAS_ZKPOH` (the heaviest HumanityHub op — it runs a pairing check; sized
above `GAS_HUMANITY`). **Not** fee-exempt: unlike `requestVerification`, a ZK upgrade is taken by an
account that may already be `STD`-Verified (paying from its UBI), and a *new* user choosing the ZK-only
path must hold a small balance — onboarding fee-exemption remains the M3 `requestVerification` path only.
*(Open item O-1, §13: a fee-exempt new-user ZK path. Resolution must not let a zero-balance address spam
pairing checks — the pairing verify is the cost. Until resolved, a brand-new user verifies via M3 first,
or funds a minimal balance.)*

### 4.2 Verification algorithm (deterministic; fail-closed at every step)

On a `submitZkPassportProof` tx at block `B`, the runtime executes — in order, aborting (status-0 receipt,
no state change) on the first failure (I4):

1. **Decode + bound-check** calldata (proof length, scheme tag in the known set, array lengths). Bad shape
   ⇒ reject.
2. **Re-derive and bind the public inputs:**
   - `submitter_address` must equal the tx sender (`ecrecover`). Mismatch ⇒ reject (anti-replay, F-4).
   - `nowEpoch` must equal `B.timestamp` (the **only** clock execution sees, M5 §5.3 / I2). A proof built
     against a different `now` is rejected — and because the not-expired check (§3.2) used `nowEpoch`, this
     ties expiry to block time deterministically.
   - `cscaRegistryRoot` must equal the **current on-chain CSCA registry root** (§7.2). A proof against an
     untrusted/stale CSCA set ⇒ reject (EC-3). *(Governance updating the registry changes the root; proofs
     must be built against the live root — see §7.3 for the grace-window policy.)*
3. **Nullifier-uniqueness pre-check:** if `nullifier ∈` the on-chain nullifier registry ⇒ reject
   (`NullifierAlreadyUsed`) **before** the expensive pairing check (cheap fail-closed first — EC-2, F-5).
4. **SNARK verify (the pure crypto):** call the `crates/zkpoh` verifier (§6) with the **genesis-pinned
   verifying key** and the public-input vector (§3.5). `false` ⇒ reject (`InvalidProof`, F-3) — this is the
   step that rejects a tampered proof, a forged document, or an expired one. **No partial state on a
   `false`.**
5. **Commit (atomic), on success only:**
   - Insert `nullifier` into the nullifier registry (now permanently spent).
   - Store the three `attributeCommitments` in the attribute store keyed by `submitter_address`.
   - Set the `Human` assurance level: `Unverified`/no-record → create+`ENH`; existing `STD`-Verified →
     `DUAL`; existing `ENH`/`DUAL` → reject (`AlreadyEnhanced`, idempotency guard).
   - If the human was not already `Verified`, transition to `Verified` and **start emission** (set
     `verified_at`, flip the account cache) — exactly the M3 `finalize_registration` emission flip
     (§5.1), so the ZK path is a *first-class* route to `Verified`, not only an upgrade (EC-1).
   - Emit the PoH-NFT metadata-update / mint event (§5.5, EC-6) and a receipt log carrying the assurance
     level (no PII).

Every step is a pure function of (on-chain state, the tx, `B.timestamp`) — two nodes reach the identical
accept/reject and identical post-state (I1/I2), so the `state_root` agrees byte-for-byte (M5 EC-4/EC-10).

### 4.3 Why the address is bound, not in calldata

If `submitter_address` were calldata, a watcher could copy a victim's `(proof, public_inputs)` from the
mempool and front-run with their own address. Binding `submitter_address = ecrecover(tx.sig)` *and* making
it a public input the proof commits to means the proof is **only valid for the address that generated it**
— a copied proof verifies `false` for any other sender (F-4).

### 4.4 Attribute verifier (Stage D) — the `over18` template

A second, **read-only** verification path proves a statement *about a stored commitment* without revealing
it. The user generates a small ZK proof on-device that "`attr_commit[0]` opens to a `born_before_epoch ≤
now − 18y`" (a Pedersen-opening + range statement) and submits it to a view/op:

```solidity
function verifyAttribute(address subject, bytes32 attributeType, bytes attrProof) external view returns (bool);
// attributeType: keccak-tag, e.g. keccak256("over18"); M6 ships only "over18".
```

The verifier (also pure, in `crates/zkpoh`, behind the same trait) checks `attrProof` against the
on-chain `attr_commit[0]` for `subject`. Returns `true`/`false` **without** the chain ever learning the
DOB or the commitment opening (EC-9, F: birth date never exposed). This is the **template** M7 DAOs extend
for nationality-bucket and expiry gates. A prompt contract (M4) can gate an action on `verifyAttribute`
(brief Stage-D exit) — it is an ordinary `eth_call`-able read.

---

## 5. Composition with M3 — assurance levels, lifecycle, NFT (additive, no regression)

### 5.1 `Human` record + assurance level (runtime change — minimal, deterministic)

The M3 `Human` struct (humanity.rs) gains **one field** and the registry gains **two collections**:

```rust
// added to humanity::Human
pub assurance: Assurance,            // STD | ENH | DUAL  (default STD for existing records — see §5.6)

// new enum (1-byte tag in state_root; default STD)
pub enum Assurance { Std, Enh, Dual }

// new registry collections (behind the State trait, sorted accessors — same discipline as humans()/cases())
//  nullifier registry:   a sorted set<[u8;32]>            — one-passport-one-human (queried in §4.2 step 3)
//  attribute store:      sorted map<Address, [[u8;32];3]> — the three Pedersen commitments per ENH/DUAL human
```

**Eligibility is unchanged:** UBI accrues iff `status == Verified` (M3, I2). `assurance` is **metadata**;
it never gates accrual (the inclusion constraint, structurally — there is no code path where `assurance`
affects `balance()`). `STD` humans are first-class (EC-5).

### 5.2 New lifecycle transitions (lifecycle.rs — added beside the M3 ones, none altered)

A new `submit_zk_passport_proof(state, verifier, subject, proof, public_inputs, now) -> Result<Assurance,
ZkPohError>` implementing §4.2. It is the **only** new entry point; every M3 function (`request_verification`,
`vouch`, `challenge`, `submit_verdict`, `finalize_registration`, `revoke`) is **untouched** (EC-5 — tested
by re-running the full M3 suite green). Interactions:

- **New user, ZK-only path:** no prior `Human` record → `submit_zk_passport_proof` creates a `Verified`,
  `ENH` human and starts emission directly (no vouches, no challenge window — the cryptographic proof
  *replaces* the social uniqueness signal). This is a distinct, additive route to `Verified` (EC-1).
- **`STD` upgrade to `DUAL`:** existing `Verified`/`STD` human → set `assurance = Dual`, store nullifier +
  commitments. **`verified_at` and balance are never touched** (the brief's hard rule — no balance/status
  disruption on upgrade; tested).
- **A `Pending` (mid-M3-registration) human submitting ZK:** allowed; the ZK proof finalizes them to
  `Verified`/`ENH` immediately (the cryptographic proof satisfies uniqueness without waiting out the
  challenge window). Their in-flight Registration case is left as-is (it simply no longer gates them).
- **Revocation interaction:** if a `Sybil` quorum later revokes an `ENH`/`DUAL` human (M3 challenge path
  still applies to the *social* dimension), the human is `Revoked` and emission stops — but **the nullifier
  stays spent** (a revoked passport-holder cannot recycle the same passport onto a fresh address; §7.4
  / O-2). `DUAL`→revoked drops to no emission like any revoke; the `assurance` field records `Dual` history
  but `status == Revoked` gates accrual off. *(A challenge can never strip the cryptographic `ENH` fact
  itself — only the social `Verified` status; the nullifier is a permanent on-chain fact.)*

### 5.3 `state_root` (M5 §5.3) extension — two new sections, fully canonical

`crates/runtime/src/state_root.rs` gains, after section 7 (jurors) and before the contracts section, two
new sorted sections, each `count (u64) || items-in-sorted-order`, with a fresh 1-byte domain tag:
- **Nullifier registry** (sorted ascending by the 32-byte value).
- **Attribute store** (sorted by address; each entry = address ‖ the three 32-byte commitments).
- The `Human` `assurance` 1-byte tag is folded in the existing humans section (§5.1).

This keeps the cross-node agreement invariant: two nodes that processed the same `submitZkPassportProof`
txs produce byte-identical roots (M5 EC-4/EC-10). The state-root encoding version string is bumped
(`ubi2/state-root/2`) so the format change is a new root, never a silent reinterpretation.

### 5.4 Cross-node quorum framing (EC-7) — the verifier *math* is deterministic, the *commit* is consensus

ZK verification is pure crypto, so unlike the AI jury there is **no inter-node disagreement to resolve** in
the happy path — every honest node re-runs the verifier and gets the same boolean. Two design options for
EC-7 ("evaluated by the cross-node quorum; no single node alone commits; injected disagreement aborts
deterministically"), with the decision pinned in **ADR-0005 Decision 5**:

- **(A) Re-execution consensus (CHOSEN).** The `submitZkPassportProof` tx is gossiped, included by the M5
  proposer, and **every follower re-executes the verifier as part of block validation** (M5 §5.1 rule 3:
  "re-executing yields a byte-identical `state_root`"). A node whose verifier disagrees (e.g. a tampered
  build, or — the injected-disagreement test — a node that returns `false` on a valid proof) computes a
  **different `state_root`** and the block does not reach agreement / that node forks off; the chain only
  *advances* on the value the honest majority agrees re-executes correctly. This is **exactly the M5 I1
  mechanism** ("no single node alone commits; agreement commits; divergence aborts deterministically")
  applied to a deterministic op — no new primitive, and it is the *cleanest* fit because the function is
  deterministic.
- **(B) Case/jury wrapper (rejected for the happy path; available as a fallback).** Wrap the op in an
  M3-style `Case` whose "jurors" each submit a `verify→bool` and the on-chain `quorum_tally` commits on
  supermajority. Rejected as the default because it adds latency and a quorum-split failure mode to a
  *deterministic* check that cannot honestly split — the re-execution consensus already gives the
  cross-node guarantee. Retained as the documented mechanism **iff** a future verifier becomes non-pure
  (e.g. needs an off-chain artifact); not needed for M6.

> **EC-7 test (injected disagreement):** in the multi-node harness, one node's `zkpoh` verifier is
> swapped for a stub that returns the *wrong* boolean on the test proof. Assert: that node diverges (its
> `state_root` differs) and is out-voted by the honest majority via M5 fork choice; the honest chain
> commits the correct result; **no partial state** anywhere. This reuses the M5 AC-9 / AC-F2 machinery.

### 5.5 PoH NFT (EC-6) — assurance level in the soulbound card

The M3 PoH NFT (poh_nft.rs — one soulbound token per `Verified` human, `tokenId == address`, on-chain SVG)
is extended so `tokenURI`'s JSON + SVG card reflect the **assurance level** (`STD` / `ENH` / `DUAL`) read
from the `Human` record. No new token, no new mint/burn rule — the existing mint-on-Verified /
burn-on-Revoke is unchanged; only the *metadata* gains the level attribute and a visual badge.
MetaMask shows the level (EC-6). The card carries **no PII** — only the level string (I6).

### 5.6 Migration of existing humans (no re-verification — EC-5)

Existing `Human` records have no `assurance` field. The new field **defaults to `STD`** for every existing
record (the brief: "does not require all existing STD-level humans to re-verify"). Genesis-seeded humans
(`seed_verified_human`) are `STD`. No existing human is touched; no balance, status, or vouch changes. This
is a pure additive-field migration with a default, validated by the M3 suite staying green.

---

## 6. The on-chain verifier — pure, deterministic, isolated (`crates/zkpoh`)

### 6.1 Crate boundary (keeps `runtime` dependency-free)

A new crate **`crates/zkpoh`** holds the Groth16/BN254 verifier and the Pedersen-commitment / attribute
verifier. `crates/runtime` calls it **through a trait** — the exact pattern the oracle uses (`runtime`
defines the trait; the impl lives outside):

```rust
// defined in crates/runtime (no crypto deps in runtime)
pub trait ZkPassportVerifier: Send + Sync {
    /// Verify a Groth16 proof against the genesis-pinned VK + the canonical public-input vector (§3.5).
    /// PURE + DETERMINISTIC: same inputs ⇒ same bool on every node, no allocation-order/iteration-order
    /// dependence, no clock, no floats. `false` on any malformed input (fail-closed).
    fn verify_passport(&self, proof: &[u8], public_inputs: &PublicInputs) -> bool;

    /// Verify an attribute-opening proof against a stored commitment (§4.4). Same purity contract.
    fn verify_attribute(&self, attr_type: AttrType, commitment: &[u8; 32], attr_proof: &[u8]) -> bool;
}
```

`runtime` is handed a `&dyn ZkPassportVerifier` (genesis wires the real `crates/zkpoh` impl; tests wire a
**`MockZkVerifier`** — §6.3). The build-level test that forbids `libp2p`/`tokio`/`reqwest` in `runtime` is
extended: **`crates/zkpoh` may depend only on a pure, deterministic pairing library** (`arkworks`
`ark-bn254` / `ark-groth16`, or `bellman`/`blstrs` for BN254 — pinned in ADR-0005 D2) and **must not**
pull async/network/clock/float deps; the verifier path is asserted dependency-clean so it stays
WASM-compilable and consensus-safe.

### 6.2 The reproducibility requirement (I1/I2 across nodes — the cleanest case)

The pairing/field verification **must be bit-reproducible across nodes**. The chosen pairing library must:
- be **deterministic** (no randomized verification, no parallel-reduction nondeterminism, no float);
- serialize/deserialize group elements **canonically** (a single valid encoding per element; reject
  non-canonical encodings — a malleable encoding is a soundness/replay risk, F-3/F-4);
- compile cleanly to **WASM** (the runtime is WASM-targetable; the Light-Node runs it in-browser, §8).

arkworks `ark-bn254 + ark-groth16` satisfies all three and is the **default pin (ADR-0005 D2)**; a node
that links a different/patched pairing impl that disagrees on any proof simply diverges (its `state_root`
differs) and is out-voted (§5.4) — so a verifier discrepancy is *contained* by the same M5 consensus that
contains everything else, never a silent fork.

### 6.3 Offline testability (I5) — `MockZkVerifier` + a test-passport fixture

CI never reads real NFC. Following the `MockOracle`/`MockInterpreter` pattern:
- **`MockZkVerifier`** returns scripted booleans keyed by `(nullifier, submitter)` so the *lifecycle* and
  the *state machine* (nullifier uniqueness, level transitions, emission flip, NFT metadata, state-root
  agreement, EC-7 divergence injection) are fully exercised **without any real pairing math** (I5). Most
  acceptance tests use this — they test the *runtime composition*, not the curve.
- **A real-curve fixture path:** a small set of **test-passport fixtures** (a self-generated test CSCA →
  test DSC → test SOD, never a real person's document) plus a **genuine proof + VK** generated by the
  Stage-A pipeline, so a dedicated reliability test asserts the *real* `crates/zkpoh` verifier accepts a
  valid proof and rejects a tampered one — closing EC-3/F-3 against the actual crypto, not the mock.

This split is the same one M5 uses (mock for the lifecycle, real backend for the live demo): the bulk of
QA is deterministic and offline; a focused real-crypto test guards soundness.

---

## 7. Trust anchors — the CSCA registry (on-chain, governance-upgradeable)

### 7.1 What it is

ICAO maintains the **CSCA Master List**: each country's **Country Signing Certification Authority** root
public key(s), which sign that country's **Document Signer Certificates**, which sign passports. Trusting a
passport's PA chain reduces to **trusting the CSCA root** at the top. The chain therefore needs an on-chain
set of trusted CSCA public keys; a proof is only accepted if its DSC chains to a CSCA **in that set** (§3.2
check 3, EC-3).

### 7.2 On-chain shape (runtime state)

```
CSCA registry (behind the State trait, sorted accessor):
  sorted set of CscaEntry { country_code: [u8;3], key_id: [u8;32], pubkey: bytes, added_at: u64, status: Active|Revoked }
  csca_registry_root: a deterministic 32-byte commitment over the sorted Active entries (a Merkle root or
                      the same FNV-1a-256 sponge state_root uses) — recomputed on every mutation.
```

The **`csca_registry_root` is a public input to the proof** (§3.5), and the proof's in-circuit CSCA check
verifies membership against it. So "which CSCAs are trusted" is consensus state, and a proof is
cryptographically bound to the exact trusted set it was built against. The root is committed in
`state_root` (§5.3) so all nodes agree on the trust anchors to the bit.

### 7.3 Governance upgrade path (EC-10)

A new HumanityHub (or a future GovHub) op, **`registerCsca(country, keyId, pubkey)`** / **`revokeCsca(keyId)`**,
gated by the governance authority:
- **M6 (pre-M7-DAOs):** the authority is a **reserved governance address / a small multisig / the existing
  validator-quorum**, mirroring how M5 gates validator-set changes. A curated **static genesis set** of
  CSCA roots ships in genesis (sufficient for the milestone, per the brief). The architecture makes the
  set **mutable without a hard fork** — adding a root is a transaction, and a newly-added root is
  **immediately usable** for new submissions (the next proof can build against the new root) (EC-10).
- **M7:** the same op is re-pointed at the DAO governance mechanism (quadratic-delegation vote) — no shape
  change, just a different authority check. The registry is the substrate M7 inherits.

**Root-change grace policy (determinism + liveness):** because the root is a proof's public input, a
governance change to the registry **invalidates in-flight proofs** built against the old root. To avoid
racing a user's submission against a governance tx, the runtime accepts a proof whose `cscaRegistryRoot`
matches **either the current root or the immediately-previous root within a `CSCA_ROOT_GRACE_BLOCKS`
window** (a small, deterministic block window — a pure function of block height, no wall-clock). Outside
the window, only the current root is accepted. This is fully deterministic (I2) and bounded. *(Open item
O-3, §13: grace-window width.)*

### 7.4 Trust assumptions + revocation (stated for the security gate)

- **The country-issuer trust assumption:** the chain trusts that a CSCA in the registry is a genuine,
  uncompromised sovereign key. A malicious or compromised country signing key could mint fake passports
  that pass PA → fake humans at `ENH`. This is the **irreducible trust root** of any e-passport system and
  is **why ZK-passport is additive, not sole** (the inclusion constraint doubles as a trust-diversification
  argument): a chain that *also* has the social path is not single-rooted on government keys. Documented in
  §11 + ADR-0005.
- **CSCA revocation:** if a CSCA key is compromised/expired, governance sets its entry `Revoked` (it leaves
  the Active set → the root changes → proofs chaining to it stop verifying). **Already-spent nullifiers
  from that CSCA are *not* retroactively revoked** in M6 (that would require re-checking every past proof —
  a heavier, M7 mechanism). Policy: forward-invalidation in M6; retroactive nullifier purge is M7 (O-2).
- **Nullifier permanence vs. passport renewal:** a renewed passport has a new document number → a new
  nullifier → it would let a renewing human register a *second* identity. M6 accepts this edge (a human who
  renews could in principle hold an old+new `ENH` — but both are *real* and the social/economic cost is
  high); a renewal-binding mechanism (binding to a more stable identifier, or a renewal-attestation) is
  **M7** (O-2). Documented, not hidden.

---

## 8. Client / device synergy with the Light-Node track

The NFC read + witness/proof generation are the **on-device** work the **Browser/Mobile Light Node** track
is already building toward (roadmap parallel track; brief §"Light-node companion"):
- **Stage A of the Light-Node track delivers the in-browser/mobile WASM prover** — the same WASM that
  generates the Groth16 proof under the 60-second budget. M6 Stage C **depends on** that prover for the
  in-app NFC flow (the only cross-track coupling).
- **Mobile NFC** is the device capability M6 needs and the Light-Node mobile companion provides; a
  desktop/browser without NFC uses the graceful **fallback to vouching** (F-7).
- Because the verifier is the *same* `crates/zkpoh` code that compiles to WASM (§6.2), a light node can
  **also re-verify** a passport proof locally against a state proof — a later capability, not an M6 gate.

This is a **dependency, not a blocker**: M6 Stages A/B/D proceed independently; only Stage C (the in-app
end-to-end NFC flow) waits on the Light-Node WASM prover. The tracks are sequenced so the prover lands
before M6 Stage C.

---

## 9. New RPC / interface surface (`crates/rpc`)

- **Write (HumanityHub tx, MetaMask-signable):** `submitZkPassportProof(...)` (§4.1); `registerCsca` /
  `revokeCsca` (§7.3, governance-gated).
- **Read (`ubi_*`):**
  - `ubi_getHuman(address)` — **extended** to return the `assurance` level alongside the M3 fields
    (additive; existing fields unchanged — I3/EC-5).
  - `ubi_getAttributes(address)` → `{ ageCommitment, nationalityCommitment, expiryCommitment }` (the three
    32-byte Pedersen commitments; **opaque** — no preimage; EC-8). Returns empty for `STD`-only humans.
  - `ubi_getCscaRegistry()` → the sorted Active CSCA entries + the current `csca_registry_root` (so a
    client can build a proof against the live trust set).
  - `ubi_isNullifierUsed(nullifier)` → bool (lets a client check before generating a proof; pure read).
- **`eth_call` (view):** `verifyAttribute(subject, attributeType, attrProof)` → bool (§4.4, EC-9); the PoH
  NFT `tokenURI` reflecting the level (§5.5, EC-6).
- **EVM compatibility (I3):** all reads are `ubi_*` extensions; the new writes are HumanityHub txs with
  fixed selectors (MetaMask signs unchanged); **no standard `eth_*` method changes semantics.** Any
  deviation stays documented here.

---

## 10. Acceptance criteria (1:1 with EC-1…EC-10 → tests)

CI uses the **`MockZkVerifier`** for lifecycle/composition tests (I5) and a **real-curve test-passport
fixture** for the soundness tests (§6.3). Multi-node criteria reuse the M5 harness.

| AC | Maps to | Assertion (the test bar) | Stage |
|---|---|---|---|
| **AC-1** | EC-1 | A new address with **no prior record** completes `submitZkPassportProof` (valid fixture) and becomes `Verified`/`ENH`, emission starts. A *different* new address completes the **M3 vouching** path and becomes `Verified`/`STD`. Both accrue UBI; neither path required the other. | B |
| **AC-2** | EC-2 | After AC-1's ENH human registers nullifier `N`, a **second address** submits a proof with the **same `N`**: rejected (`NullifierAlreadyUsed`), the second address is **not** `Verified`, and the rejection is **identical on all nodes** (state_root unchanged). | B |
| **AC-3** | EC-3 | A valid test-passport proof is **accepted**. A proof with (a) a tampered witness, (b) an **untrusted CSCA root** (not in the registry), or (c) an **expired** document is **rejected** — each **fail-closed**, status-0 receipt, **no partial state**. *(Real-curve fixture test for the verifier; mock for the lifecycle path.)* | B |
| **AC-4** | EC-4 | After a successful ZK proof, the on-chain `Human` + stores contain **only**: nullifier, 3 attribute commitments, `assurance`, `verified_at`. A test asserts the serialized record contains **no** name/document-number/DOB/nationality plaintext (structural — there is no field to hold them). | B |
| **AC-5** | EC-5 | The **entire M3 test suite stays green** (vouching, challenge, finalize, revoke). An existing `STD` human's status, `verified_at`, and balance are **byte-unchanged** before/after M6 code lands. No `assurance` value affects `balance()`. | B |
| **AC-6** | EC-6 | After a successful ZK proof, the PoH NFT `tokenURI` JSON/SVG reflects `ENH` (new user) or `DUAL` (STD upgrader); the level is readable via `eth_call` / MetaMask. The card carries no PII. | C |
| **AC-7** | EC-7 | On the **multi-node** devnet, a `submitZkPassportProof` is gossiped, included, and **every follower re-executes the verifier**; agreement commits. **Injected disagreement** (one node's `zkpoh` verifier stubbed to return the wrong bool) causes that node to **diverge and be out-voted** (M5 fork choice); the honest chain commits the correct result; **no partial state**. | (M5 Stage C) D |
| **AC-8** | EC-8 | After ENH verification, `ubi_getAttributes(address)` returns the **three Pedersen commitments**; each is opaque (a test confirms two different humans with the same underlying attribute have **different** commitments — blinding/unlinkability holds). | B |
| **AC-9** | EC-9 | `verifyAttribute(address, keccak256("over18"), attrProof)` returns `true` for a human whose age commitment encodes over-18 and `false` otherwise, **without** the chain accessing the DOB. A prompt contract can gate on it (`eth_call`). | D |
| **AC-10** | EC-10 | The CSCA registry is on-chain; `registerCsca` (governance-gated) **adds a root**; a proof built against the **new** root is **immediately accepted**; the root is in `state_root` (all nodes agree). A non-governance `registerCsca` is rejected. | B |

### 10.1 Failure-mode acceptance (must also pass — maps to the brief's failure table)

| AC | Failure mode | Assertion |
|---|---|---|
| **AC-F1** | Expired document | Proof's in-circuit not-expired check fails (`nowEpoch == B.timestamp` ≥ expiry violated) ⇒ rejected at verify; human not upgraded; no state change. |
| **AC-F2** | Untrusted CSCA root | `cscaRegistryRoot` ∉ live registry (or proof chains to a non-registry CSCA) ⇒ rejected, not committable, **no partial state**. |
| **AC-F3** | Tampered proof | SNARK verify returns `false` ⇒ rejected fail-closed; status-0 receipt with reason; no state change. |
| **AC-F4** | Proof replay / front-run | A `(proof, public_inputs)` copied from the mempool and submitted by a **different** address: `submitter_address` binding fails ⇒ rejected (F-4). |
| **AC-F5** | Nullifier re-use | Second submission with a spent nullifier ⇒ rejected chain-wide, **before** the pairing check (cheap fail-closed). |
| **AC-F6** | STD human's ZK upgrade fails | An `STD` human submits an **invalid** proof: stays `STD`/`Verified`, **no downgrade**, no status/balance loss. |
| **AC-F7** | No NFC / no chip | The app (Stage C) shows a graceful **fallback to the vouching path**; no on-chain effect. |
| **AC-F8** | Quorum/verifier divergence | A node whose verifier disagrees with the majority **diverges and is out-voted**; the chain reaches the same accept/reject on the honest majority; **deterministic**, no partial state (= AC-7's injected-disagreement leg). |
| **AC-F9** | Idempotency | A `DUAL` human re-submitting a (valid) proof is rejected `AlreadyEnhanced`; no double-store, no double-mint, root unchanged. |

---

## 11. Threat model (for the security gate)

The security-engineer must threat-model the new crypto + trust + op surface explicitly. Pointers:

- **Proof replay / front-running:** mitigated by **address-binding the proof** (`submitter_address` a
  public input == `ecrecover`, §3.3/§4.3) and by `nowEpoch == block.timestamp`. Test: AC-F4.
- **Nullifier reuse / double-registration:** the on-chain nullifier registry + per-chain binding makes one
  passport ⇒ one human-per-chain (§3.3). Test: AC-2/AC-F5. **Residual:** passport *renewal* yields a new
  nullifier (§7.4, O-2) — documented edge, M7 mechanism.
- **Forged / cloned passports + the PA chain-of-trust:** PA proves government-signed *data*; a **cloned
  chip** (copied genuine data) is **not** caught by PA alone — Active/Chip Authentication is the
  anti-clone measure, **scoped as Stage-D hardening** (§3.2), not a launch blocker. A **forged** document
  fails PA (no valid CSCA chain). **Residual + irreducible:** a **compromised CSCA** (sovereign key)
  could mint passes — *why the path is additive, not sole* (§7.4).
- **Verifier soundness + trusted setup:** a soundness bug in the circuit, or **un-destroyed Groth16 toxic
  waste**, lets an attacker forge proofs ⇒ fake humans. Mitigated by **adapting an audited circuit** (not
  from scratch), a **public multi-party Phase-2 ceremony** with published transcripts, a **genesis-pinned
  VK** committed in `state_root`, and the **PLONK/Honk universal-setup upgrade path** (§2.3). The
  security gate must review the ceremony + the verifier's canonical-encoding/non-malleability handling
  (§6.2). Test: AC-3/AC-F3 against the real curve.
- **CSCA masterlist staleness / governance / compromise:** stale roots reject valid new passports
  (liveness, not safety); a compromised governance authority could insert a malicious CSCA (safety) —
  mitigated by the same authority model M5 uses for validator-set changes, the **grace-window**
  determinism (§7.3), and the move to DAO governance in M7. Test: AC-10 (governance-gating; non-gov
  rejected).
- **Attribute unlinkability:** per-attribute **blinding factors** make identical attributes produce
  different commitments (§3.4), so the store cannot cluster humans by attribute. Test: AC-8 (two over-18
  humans ⇒ different commitments). The `over18` proof reveals only the boolean (§4.4, AC-9).
- **Determinism / cross-node divergence:** a non-deterministic or non-canonical-encoding verifier could
  diverge silently — prevented by the **purity contract** (§6.2), **canonical group-element encodings**,
  and the **re-execution consensus** that *contains* any divergence (§5.4). Test: AC-7/AC-F8.
- **Inclusion / abuse balance:** the inclusion constraint (never sole-gate) is also the trust-diversification
  argument; the abuse surface (sybil at scale) is *reduced* by adding a cryptographic uniqueness path while
  the social path remains for the passport-less. The security gate weighs the residual sovereign-key trust
  against the M3-only baseline it strictly improves on.
- **DoS via pairing checks:** a flood of `submitZkPassportProof` txs forces pairing verifies. Mitigated by
  **gas (`GAS_ZKPOH`, the heaviest HumanityHub op)**, the **cheap nullifier pre-check before the pairing**
  (§4.2 step 3), the M5 mempool caps (FU-1), and **non-fee-exemption** of the op (§4.1). The new-user
  fee-exempt path (O-1) must be resolved without re-opening this.

---

## 12. Crate / module plan & phased task breakdown

### 12.1 Crate layout

| Crate | Change | New deps |
|---|---|---|
| **`crates/zkpoh`** (NEW) | The **pure deterministic** Groth16/BN254 passport verifier + the Pedersen/attribute verifier; the genesis-pinned VK; canonical group-element (de)serialization; the `MockZkVerifier`; the real-curve test-fixture path. Implements the `ZkPassportVerifier` trait `runtime` defines. **Dependency-clean** (no async/network/clock/float). | **arkworks** (`ark-bn254`, `ark-groth16`, `ark-ff`, `ark-ec`) — pinned (ADR-0005 D2), **isolated here**; WASM-compilable. |
| **`crates/runtime`** | **Minimal, deterministic only:** the `ZkPassportVerifier` **trait** (no impl); `Assurance` enum + the `Human.assurance` field; the **nullifier registry** + **attribute store** + **CSCA registry** behind the `State` trait (sorted accessors); the `submit_zk_passport_proof` lifecycle transition (§5.2); `state_root` extension (§5.3, version bump). **No crypto crate, no async.** | **none** (stays dependency-free; calls `zkpoh` via the trait) |
| **`crates/rpc`** | Decode the new HumanityHub ops (`submitZkPassportProof`, `registerCsca`/`revokeCsca`) — same `sol!`/selector pattern as M3 (humanity.rs); `verifyAttribute` `eth_call`; new `ubi_getAttributes` / `ubi_getCscaRegistry` / `ubi_isNullifierUsed` reads; `ubi_getHuman` + PoH-NFT `tokenURI` carry the assurance level. | none new |
| **`crates/node`** | Genesis wires the **real `crates/zkpoh` verifier** + the genesis CSCA set + the pinned VK; the multi-node harness's **injected-disagreement** stub for AC-7. | none new |
| **`apps/wallet` / `packages/sdk`** | Stage C: the identity-tab "Verify/Upgrade with passport" NFC flow (using the Light-Node WASM prover, §8) + the SDK encoders for the new ops + the attribute/level reads. | (light-node WASM prover) |
| **build-level test** | Extend the `runtime`-purity assertion to cover the **verifier path**: `crates/zkpoh` must not pull async/network/clock/float deps; `runtime` must not pull any crypto/async/network dep. | — |

### 12.2 Phased tasks (map to Stages A–D)

**Stage A — ZK proof pipeline + CSCA format (off-chain; no on-chain state).** *De-risks the crypto first.*
- A1 Pin the circuit (adapt OpenPassport/Self) + the Groth16/BN254 proof system + run/derive the Phase-2
  ceremony → the genesis VK (ADR-0005 D1/D2).
- A2 Nullifier derivation (§3.3) + attribute-commitment scheme (§3.4) + the canonical public-input vector
  (§3.5) — stable + documented.
- A3 CSCA registry **format** + `csca_registry_root` commitment (§7.2); a curated genesis CSCA set.
- A4 A **CLI**: passport-dump (NFC export or test fixture) → proof + public inputs; a verifier binary
  confirming validity. **Exit:** brief Stage-A exit (dev generates + verifies off-chain).
- A5 The **real-curve test-passport fixtures** (test CSCA→DSC→SOD; never a real document) for §6.3.

**Stage B — on-chain verifier + HumanityHub op.** *The runtime composition.*
- B1 `crates/zkpoh`: the pure verifier + `MockZkVerifier` + the `ZkPassportVerifier` trait in `runtime`;
  the build-level purity test.
- B2 `runtime`: `Assurance` + `Human.assurance`; nullifier registry + attribute store + CSCA registry
  (sorted `State` accessors); `state_root` extension + version bump (§5.3).
- B3 `submit_zk_passport_proof` lifecycle (§4.2/§5.2): all level transitions, emission flip, idempotency,
  revocation interaction.
- B4 `rpc`: op decoding + `registerCsca`/`revokeCsca` (governance-gated) + the new reads.
- B5 CI: **AC-1…AC-5, AC-8, AC-10, AC-F1…AC-F6, AC-F9** (mock verifier for lifecycle; real-curve fixture
  for AC-3/AC-F1..3). **Exit:** brief Stage-B exit (submit on devnet → ENH; re-use rejected; invalid
  rejected fail-closed).

**Stage C — app NFC flow.** *Depends on the Light-Node WASM prover (§8).*
- C1 Identity-tab "Verify/Upgrade with passport": NFC read → on-device proof (Light-Node prover) → submit
  via MetaMask/embedded wallet; the **fallback-to-vouching** UX (F-7).
- C2 PoH-NFT level badge in `tokenURI` (§5.5); the SDK encoders/readers.
- C3 CI: **AC-6**, the end-to-end flow (test-fixture proof in CI). **Exit:** brief Stage-C exit (full
  in-app flow, no CLI).

**Stage D — attribute verifier (over-18) + multi-node + hardening.**
- D1 `crates/zkpoh`: the `over18` attribute-opening verifier (§4.4) + `verifyAttribute` `eth_call`.
- D2 Multi-node: **AC-7/AC-F8** (re-execution consensus + injected-disagreement divergence) on the M5
  harness.
- D3 Hardening: Active/Chip-Authentication support where the chip provides it (anti-clone, §3.2);
  CSCA-root grace-window (§7.3); DoS review (§11).
- D4 CI: **AC-9**, plus AC-7 multi-host. **Exit:** brief Stage-D exit (`verifyAttribute('over18')`;
  a prompt contract gates on it).

---

## 13. Open questions (handed to the orchestrator / security gate)

- **O-1 — fee-exempt new-user ZK path.** Should a brand-new (zero-balance) user be able to verify ZK-only
  without first funding gas? A naive exemption invites pairing-check DoS (§11). Options: a one-shot
  fee-exempt ZK submission gated by a cheap proof-of-work / a rate-limited faucet / requiring the
  M3 onboarding first. **Recommend:** keep the op non-fee-exempt for M6 (new ZK-only users fund a minimal
  balance, or onboard via M3 then upgrade); revisit with M7 economics.
- **O-2 — passport renewal + retroactive nullifier revocation.** Binding to a more stable identifier than
  the document number, and purging nullifiers under a revoked CSCA, are **M7** (§5.2/§7.4). M6 documents
  the edges; does not mechanize them.
- **O-3 — `CSCA_ROOT_GRACE_BLOCKS` width** (§7.3) and `GAS_ZKPOH` value — devnet starting constants, tuned
  at the gate (recorded like M5's §10 constants).
- **O-4 — Groth16 now vs. PLONK/Honk at the next circuit change** (§2.3): the verifier trait is written for
  the swap; the decision of *when* is an M7+ call tied to the second-document-type (mDL/EUDI) work.
- **O-5 — Active Authentication scope** (§3.2): which issuing countries' chips support AA/CA, and whether
  the launch set requires it — a security-gate input for Stage D.

---

## 14. Determinism checklist (the reliability gate will assert each)

1. The SNARK verifier (`crates/zkpoh`) is **pure + deterministic + canonical-encoding** — same inputs ⇒
   same bool on every node; no float, no clock, no allocation/iteration-order dependence (§6.2).
2. `submit_zk_passport_proof` reads **only `block.timestamp`** for `nowEpoch` (M5 §5.3 / I2) — no
   node-local wall-clock.
3. The nullifier registry, attribute store, and CSCA registry are iterated in **sorted** order everywhere
   they feed `state_root` (§5.3) — same discipline as humans()/cases().
4. `crates/runtime` pulls **no** crypto/async/network dep (calls `zkpoh` via the trait); `crates/zkpoh`
   pulls **no** async/network/clock/float dep — a build-level assertion (§12.1).
5. The verifying key + the genesis CSCA set + the public-input layout are **pinned** and committed
   (state_root version bump §5.3 / ADR-0005) — a change is a new root, never silent.
6. EC-7's cross-node guarantee is the **M5 re-execution consensus** (§5.4) — the quorum result is ordinary
   committed state reached by replay, no out-of-band consensus, divergence out-voted deterministically.
7. CI runs the full path on the **`MockZkVerifier`** (I5) plus a focused **real-curve** soundness test
   (§6.3) — the AI/crypto path is exercisable offline.
