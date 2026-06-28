# M6 — ZK-Passport Proof of Humanity

**Branch:** `feat/zkpoh-lightnode-design`
**Status:** defined (docs-only; implementation begins after M5 ships)
**Owned by:** product-strategist (this doc) → architect (spec) → orchestrator (decompose)

---

## Why this milestone

### The problem with vouching + AI jury alone

The existing M3 proof-of-humanity path — social vouching adjudicated by an AI-jury quorum — is a good
first gate. It requires no documents, no biometrics, and is inclusive by design. Those properties must
be preserved. But at scale, on a chain that distributes free money, it has three structural
vulnerabilities:

1. **Probabilistic sybil resistance.** A sufficiently motivated actor can cultivate a social graph of
   colluding vouchers, pass the AI jury with fabricated liveness evidence, and run many identities in
   parallel. The cost is social and computational, not cryptographic. On a free-money chain, the
   economic incentive to cheat grows with network value, so the attack surface grows with success.

2. **No uniqueness proof.** Vouching proves "this person has social connections who believe they are
   human." It does not prove "this is a unique human who has not already registered under a different
   address." The absence of a one-human-one-identity binding is the defining sybil-resistance gap.

3. **No reusable private attributes.** The system captures no verifiable facts about a human other
   than "verified." Future capabilities — citizenship-gated DAOs, age-verified contracts, residency
   proofs — have no cryptographic substrate to build on.

### What ZK-passport delivers

Government-issued identity documents (passports, national identity cards) contain a chip that signs
data with a government-held key under the ICAO 9303 / CSCA/DSC trust hierarchy. This is a
cryptographic commitment to a real human's existence, issued by a sovereign authority with strong
anti-forgery incentives. Zero-knowledge proofs over the chip's signature allow us to extract exactly
what we need — unique human, adult, one registration — without revealing the underlying data.

Concretely:

- **Nullifier-based uniqueness.** A ZK circuit derives a deterministic, address-bound, per-chain
  nullifier from the passport's unique identifier (derived from the Document Signer Certificate public
  key + document number or MRZ fields) without revealing those fields. The same passport can only
  produce one valid nullifier on this chain, making double-registration cryptographically impossible
  rather than merely expensive.

- **Attribute commitments.** The same ZK proof can emit Pedersen commitments to: nationality/
  citizenship code, date-of-birth bucket (over-18, over-21, etc.), document expiry, and issuing
  country. These commitments are stored alongside the nullifier — they reveal nothing on their own but
  allow a future ZK verifier to prove "this human is over 18" or "this human holds a passport from
  country X" without doxxing.

- **Privacy by construction.** The ZK proof reveals to the chain only: (a) the nullifier, (b) the set
  of attribute commitments, (c) a validity flag (document is not expired, signature verifies against
  a trusted CSCA root). No name, no document number, no date of birth, no nationality in plaintext.
  Ever. I6 (least authority) is satisfied structurally, not by policy.

- **Legal-identity legitimacy.** A chain that can prove "every verified human here holds a
  government-attested identity" gains credibility with regulators, grant-givers, and partner networks
  while never asking users to hand over personal data.

### Why now (after M5)

The AI-quorum PoH path (M3) is probabilistic and game-able at scale. Adding a cryptographic,
government-attested uniqueness proof is the project's most important sybil-resistance upgrade. The
right moment to add it is:

- After M5 ships a real multi-node network, so the ZK verifier runs as part of the real cross-node
  quorum (not a single-node simulation).
- Before DAOs and governance (M7), because those features depend on PoH quality. A DAO that gates
  membership on "verified human" is only as trustworthy as the PoH system. Hardening PoH before DAOs
  means DAOs are built on a strong foundation.
- Before the public testnet, so the stronger assurance model is live before external users arrive.

---

## The inclusion constraint (non-negotiable)

**ZK-passport must never be the sole gate to PoH.** This is a hard product constraint, not a
preference. The reasoning:

- Approximately 20% of the world's adult population does not hold a valid passport. Passport
  penetration is inversely correlated with poverty — precisely the population UBI most needs to
  serve. A chain that requires a passport to receive UBI is a chain that excludes its most important
  constituency.

- National identity cards, residence permits, and other identity documents vary enormously in
  cryptographic chip support. Even within the passport universe, chip-equipped e-passports are not
  universal across issuing countries.

- The whitepaper's goal is maximum inclusivity. Any verification path that structurally excludes
  a population segment violates the whitepaper.

**The design response:** ZK-passport is an additional, stronger verification path that runs
**alongside** the existing social-vouching + AI-jury path. A human may become verified through
either path, or both. The system records which path(s) were used and assigns an assurance level.

---

## Assurance-level model

Every verified human in the PoH registry carries an assurance level on their soulbound PoH NFT and
in the on-chain `Human` record. The level is set at verification time and upgradeable.

### Levels

| Level | Code | How achieved | What it proves |
|---|---|---|---|
| **Standard** | `STD` | Vouching + AI-jury quorum (M3 path) | Social attestation by human vouchers; liveness + sybil analysis by AI jury. Probabilistic uniqueness. |
| **Enhanced** | `ENH` | ZK-passport proof accepted by the verifier quorum | Cryptographic uniqueness (nullifier), government-attested identity existence, and attribute commitments. Not reliant on social graph. |
| **Dual** | `DUAL` | Both paths completed | The strongest assurance: social attestation + cryptographic uniqueness. A human who holds both a social vouching record and a ZK-passport proof. |

### Rules

- A human at `STD` level is fully verified and accrues UBI at the standard rate. There is no
  second-class status for humans who lack a passport.
- A human at `ENH` or `DUAL` level has a cryptographic uniqueness proof. The nullifier is on-chain
  and prevents re-registration with the same passport on any address.
- A human may upgrade from `STD` to `DUAL` at any time by completing the ZK-passport flow, without
  losing their existing verification status or accrued balance.
- The assurance level is recorded in the `Human` struct (a new field alongside `status`,
  `vouchers`, `case_id`) and emitted in the soulbound PoH NFT metadata.
- The `quorum_tally` logic for `STD` is unchanged from M3. The `ENH`/`DUAL` path adds a new
  on-chain operation (`submitZkProof`) whose validity the verifier quorum checks.
- Core UBI eligibility (`status == Verified`) does not require any particular level. Level is
  advisory metadata for features that want to gate on it (future DAOs, citizenship-restricted
  streams, age-verified contracts).

### What features may use levels (deferred to M7 DAOs)

The attribute commitments stored at `ENH`/`DUAL` verification enable future ZK verifiers to assert:
- "This human is over 18" (from the age bucket commitment).
- "This human holds a passport from country X" (from the nationality commitment).
- "This human's document expires after date Y" (from the expiry commitment).

These verifiers are not built in this milestone. The commitments are stored now so the DAOs and
governance milestone (M7) can use them without requiring re-verification.

---

## The ZK-passport verification flow (user-facing)

**What the user does:**

1. In the ubi2 app (identity tab), the user selects "Upgrade to Enhanced" or "Verify with passport"
   (for a new user who prefers this path).
2. The app prompts the user to tap their e-passport chip with their phone's NFC reader. A
   browser/mobile component (or the light-node companion — see parallel track) reads the
   passport's signed data groups.
3. The app generates a ZK proof locally on the user's device. Nothing leaves the device except the
   proof and the nullifier commitment. The passport data itself never touches the network.
4. The user submits the proof via a new `HumanityHub` operation: `submitZkPassportProof(proof,
   nullifier, attributeCommitments, countryCode)`.
5. The verifier quorum on the validator nodes checks: (a) the ZK proof is valid against the CSCA
   root registry on-chain; (b) the nullifier has not been registered before; (c) the document is not
   expired. On supermajority agreement, the human's assurance level is set to `ENH` (or `DUAL` if
   already `STD`), the nullifier is recorded, and the attribute commitments are stored.
6. The user sees their PoH NFT metadata update. Their soulbound NFT now reflects `ENH` or `DUAL`.

**What the user does NOT do:**

- The user does not upload their passport data to any server.
- The user does not reveal their name, document number, date of birth, or nationality to the chain
  or to any node operator.
- The user does not re-verify if they already have `STD` status; the upgrade is additive.

---

## ZK circuit design constraints (for the architect)

These are product-level constraints. The architect owns the cryptographic decisions in the spec and ADR.

**Must prove:**
- The document's signed data groups verify against a Document Signer Certificate (DSC) public key.
- The DSC is signed by a Country Signing Certification Authority (CSCA) key in the on-chain CSCA
  registry.
- The nullifier is derived deterministically from (document-binding scalar, user address, chain ID).
  The derivation must be one-way: nullifier cannot be reversed to the document scalar.
- The age bucket (e.g., `born_before = timestamp - 18 years`) is derivable from the date-of-birth
  field without revealing the field.
- The nationality commitment is derived from the MRZ nationality code without revealing the code.

**Must NOT prove (out of scope for this circuit):**
- The user's name or document number.
- The exact date of birth (only the bucket: over-18, over-21).
- The exact nationality (only the commitment; the plaintext is revealed only if the user chooses,
  to a future DAO verifier they trust).

**Circuit platform guidance:** the architect should evaluate Noir (Aztec), Circom/snarkjs, and
SP1/RISC Zero against the following criteria: (a) can the prover run in a browser/mobile WASM
environment within a reasonable time budget (target under 60 seconds on a modern phone); (b) does
the verifier fit in the on-chain runtime without external call (the runtime is WASM-compilable and
dependency-free); (c) is there an existing open-source ZK-passport circuit we can adapt (OpenPassport
project) rather than writing from scratch. The architect records the decision in a new ADR-0005.

**CSCA registry:** the chain must maintain an on-chain registry of trusted CSCA public keys, managed
by the governance mechanism (M7). For this milestone, a curated static set of CSCA roots is
sufficient — the architecture must make it upgradeable without a hard fork.

---

## Staged delivery

### Stage A — ZK proof pipeline (no on-chain changes yet)

**Goal:** a working ZK proof that a dev can generate from a test passport (or passport simulator)
and verify off-chain. Establish the circuit, the CSCA registry format, and the nullifier derivation.
No on-chain state changes in this stage. De-risks the cryptographic core before any runtime changes.

**Exit:** a developer runs a CLI command that takes a passport data dump (from an NFC reader or
test fixture), generates a ZK proof, and a verifier binary confirms the proof is valid. Nullifier
derivation is stable and documented.

### Stage B — On-chain verifier + HumanityHub op

**Goal:** the ZK verifier runs inside `crates/runtime` (or a new `crates/zkpoh` crate linked from
runtime via a trait, keeping runtime dependency-free). The `submitZkPassportProof` operation is
added to HumanityHub. The CSCA registry is an on-chain map managed by a `registerCsca` governance
op. The nullifier set is an on-chain collection.

**Exit:** a developer submits a `submitZkPassportProof` tx to the devnet, the verifier quorum checks
the proof on-chain, and the submitter's assurance level changes to `ENH` in the PoH registry. A
second attempt with the same nullifier is rejected. An invalid proof is rejected (fail-closed, I4).

### Stage C — App integration + NFC flow

**Goal:** the ubi2 app's identity tab includes the "upgrade to Enhanced" flow. The user taps their
passport chip (on a device with NFC), the app generates the ZK proof locally, and submits the
`submitZkPassportProof` tx via MetaMask or the embedded wallet.

**Exit:** a user with an NFC-capable device and an e-passport completes the full flow end-to-end in
the app without touching a CLI.

### Stage D — Attribute commitment verifiers (first use: age gate)

**Goal:** ship one concrete use of the attribute commitments: a ZK verifier that proves "this human
is over 18" against their stored age-bucket commitment, without revealing the commitment value. This
is the template for future DAO attribute gates.

**Exit:** a developer calls a `verifyAttribute(address, attributeType='over18')` on-chain and the
verifier returns true/false without accessing the underlying birth date commitment. A prompt contract
can gate an action on `verifyAttribute`.

---

## Exit criteria (testable, user-facing framing)

All exit criteria must pass before M6 is done. The architect will operationalize each into test
assertions. CI uses a test-passport fixture (no real NFC required in CI).

**EC-1 — Passport-path available alongside vouching path.**
A new user can choose to verify either via social vouching (M3 path) or via ZK-passport. Both paths
produce a `Verified` status. Neither is required to use the other.

**EC-2 — Nullifier uniqueness enforced.**
Submitting a `submitZkPassportProof` for the same passport (same nullifier) from a second address
is rejected by the verifier quorum. The second address does not become Verified. The rejection is
deterministic across all nodes.

**EC-3 — ZK proof validates against CSCA registry.**
A proof generated from a valid test e-passport (or fixture) and submitted to the devnet is accepted.
A proof with a tampered document or an untrusted CSCA root is rejected. Rejection is fail-closed (I4).

**EC-4 — Proof reveals nothing personal.**
The on-chain state after a successful `submitZkPassportProof` contains: the nullifier, the attribute
commitments, the assurance level, and a validity flag. It does not contain: name, document number,
exact date of birth, or exact nationality. A chain explorer confirms this by inspection.

**EC-5 — STD-level humans are unaffected.**
A human verified only via the vouching path (STD level) retains full Verified status, full UBI
accrual, and all existing capabilities. No regression in the M3 path.

**EC-6 — Assurance level recorded on PoH NFT.**
After a successful ZK-passport proof, the human's soulbound PoH NFT metadata reflects ENH or DUAL
level. The NFT is viewable in MetaMask and shows the level.

**EC-7 — Cross-node quorum on ZK proof.**
The `submitZkPassportProof` operation is evaluated by the verifier quorum across independent nodes
(using the M5 cross-node AI quorum infrastructure). No single node alone commits the proof. Agreement
commits; injected disagreement aborts deterministically (I4).

**EC-8 — Attribute commitments stored and queryable.**
After a successful ENH verification, the attribute commitments (age bucket, nationality bucket,
expiry) are stored and retrievable via a new `ubi_getAttributes(address)` RPC call. The commitments
are Pedersen commitments — opaque without the user's private input.

**EC-9 — Age-attribute verifier works (Stage D).**
A `verifyAttribute(address, 'over18')` call returns true for a human whose stored age-bucket
commitment encodes over-18, and false otherwise, without requiring the underlying birth date.

**EC-10 — CSCA registry is on-chain and governance-upgradeable.**
The trusted CSCA root set is stored on-chain and can be updated via a governance operation (even in
the minimal form available before M7 DAOs: a multisig or quorum vote). A new CSCA root added to the
registry is immediately usable for new proof submissions.

---

## Failure modes (must also be tested)

| Failure | Required behavior |
|---|---|
| Expired document | Proof rejected at verification time; human not upgraded. |
| Untrusted CSCA root | Proof rejected; not committable; no partial state. |
| Tampered proof (bad ZK witness) | Proof rejects during snark verification; fail-closed. |
| Nullifier re-use | Second submission with same nullifier is rejected chain-wide. |
| STD-human tries ZK upgrade, proof fails | Human stays at STD; no downgrade, no status loss. |
| Missing NFC / no chip in document | App shows graceful fallback to vouching path. |
| Quorum split on proof validity | Case aborts deterministically (I4); user may retry. |

---

## What this milestone hands to M7 (DAOs & Governance)

- A nullifier set: one-human-one-identity proven cryptographically for all ENH/DUAL humans.
- Attribute commitments: nationality, age bucket, expiry — reusable by DAO membership gates.
- A CSCA registry: an on-chain, governance-upgradeable trust root for future document types.
- An assurance-level field on every `Human` record and PoH NFT.
- A ZK attribute verifier template (over-18) that DAO specs can extend.

---

## What this milestone does NOT do

- It does not change UBI eligibility or accrual rate based on assurance level.
- It does not build DAO membership gates (that is M7).
- It does not build a citizenship-specific stream or contract (M7+).
- It does not replace the vouching path or deprecate it.
- It does not require all existing STD-level humans to re-verify.
- It does not build a BFT consensus upgrade (backlog, post-M7).

---

## Dependencies

- **M5 (Network & Consensus) must ship first.** EC-7 requires the real cross-node AI quorum from M5
  Stage C. The ZK verifier runs on the multi-node devnet, not the single-node devnet.
- **M3 (AI PoH) infrastructure is reused.** The `HumanityHub`, `Case` lifecycle, `quorum_tally`,
  and soulbound PoH NFT are extended, not replaced.
- **`crates/runtime` stays deterministic and dependency-free.** The ZK verifier either (a) is a pure
  Rust function with no external deps (preferred), or (b) is behind a trait in a new `crates/zkpoh`
  crate that `crates/runtime` calls via a trait boundary — same pattern as the oracle. The build-level
  test that forbids libp2p/tokio/reqwest in runtime is extended to forbid any non-deterministic dep
  in the verifier path.

---

## Sequencing rationale (why M6 before DAOs)

DAOs (M7) depend on two things this milestone delivers:

1. A hardened, cryptographically-grounded PoH system. A DAO that gates membership on "verified
   human" is only as trustworthy as the PoH it sits on. Vouching alone is game-able at scale; a DAO
   with a nullifier-backed membership is not.

2. Attribute commitments. The design space for DAOs on this chain — citizenship DAOs, age-verified
   vaults, regional UBI supplements — requires that the PoH system has already captured verifiable
   attributes. Building DAOs before the attributes exist means either (a) DAOs have no real
   attributes to gate on, or (b) attributes must be added retroactively, forcing all existing humans
   to re-verify.

Delivering ZK-passport-PoH before DAOs is the minimum investment that makes DAOs substantively
interesting rather than cosmetically interesting.
