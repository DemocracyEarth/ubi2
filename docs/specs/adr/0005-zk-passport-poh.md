# ADR-0005 — ZK-Passport Proof of Humanity: ICAO-9303 e-passport + Groth16, a pure in-runtime verifier, nullifier uniqueness, and an additive assurance model

- **Status:** accepted (M6)
- **Date:** 2026-06-28
- **Deciders:** architect (this ADR) + product-strategist (M6 brief) — to be ratified by protocol-engineer,
  reliability-engineer, and **security-engineer** (the trusted-setup ceremony + the country-issuer trust
  root are security-gate items) at the M6 gates.
- **Supersedes / amends:** nothing. It is **purely additive** to M3 (`03-proof-of-humanity.md`) — it does
  not change any M3 state transition, the vouching path, or UBI eligibility. It builds on M5
  (`adr/0004-consensus-and-networking.md`) for the cross-node guarantee.
- **Spec:** [`../06-zk-passport-poh.md`](../06-zk-passport-poh.md). **Milestone:** [`../../milestones/zk-passport-poh.md`](../../milestones/zk-passport-poh.md).

These decisions are costly to reverse — once a nullifier is registered, the **document standard**, the
**proof system + verifying key**, the **nullifier derivation**, the **public-input layout**, and the
**trust-anchor model** all interoperate forever — so they are pinned here. Where the M6 brief gave a
recommendation, it is adopted unless a reason is stated.

---

## Context

M3 proof-of-humanity is **social vouching adjudicated by an AI-jury quorum**: inclusive (no documents, no
biometrics), but **probabilistic** — it proves "this person has vouchers who believe they are human," not
"this is a unique human not already registered elsewhere." On a chain that distributes free money, the
incentive to cultivate a colluding social graph grows with network value; the absence of a
**one-human-one-identity** binding is the defining sybil gap (brief §"The problem").

A modern passport's NFC chip stores government-signed data under the **ICAO-9303 / CSCA→DSC** trust
hierarchy — a cryptographic commitment to a real human's existence, issued by a sovereign with strong
anti-forgery incentives. A **zero-knowledge proof** over that signature can extract exactly
*unique-human + over-N + one-registration* **without revealing any field**. This is the strongest available
sybil-resistance upgrade.

Four constraints frame every decision (all inherited; none relaxed):
- **`crates/runtime` stays deterministic + dependency-free** (no float/clock/`HashMap`-order/async/`libp2p`/
  `tokio`/`reqwest`). The verifier it calls must itself be deterministic and dep-clean.
- **Heavy proving is client-side** (NFC + witness + proof on the user's device); the chain sees only
  `(proof, public_inputs)`.
- **ZK-passport is never the sole PoH gate** (the inclusion constraint — ~20% of adults hold no passport,
  concentrated where UBI is most needed). It is *additive* to M3.
- **EC-7 needs the M5 cross-node quorum** — the verifier runs on the real multi-node network, not a
  single-node simulation.

Five decisions are load-bearing and recorded here.

---

## Decision 1 — Standard + circuit + proof system: ICAO-9303 e-passport, an adapted OpenPassport/Self circuit, Groth16 over BN254

**Decision.**
- **Document family: ICAO-9303 NFC e-passport with Passive Authentication.** Chosen over the EU
  EUDI-Wallet / ISO-18013-5 **mDL** selective-disclosure family. The e-passport is globally deployed
  *today*, sovereign-issued, and rooted in the single global **ICAO CSCA masterlist** — the right
  inclusion + trust footprint for launch. mDL/EUDI is excellent but EU-centric and nascent (rollout through
  2026–2027) and federates trust across national issuers; choosing it *now* would narrow inclusion. It is
  kept as a **forward-compatible second document type** (the assurance level, the nullifier abstraction
  with a `scheme_tag`, the attribute store, and the CSCA-style registry are all **issuer-agnostic** — spec
  §2.4), addable later with no hard fork.
- **Circuit: adapt an existing, audited e-passport ZK circuit — the OpenPassport / Self protocol family —
  do NOT write passive-authentication-in-ZK from scratch.** The brief mandates integrating an existing
  stack. Passive-authentication-in-a-circuit (RSA-2048/4096 + ECDSA-P256 signature verification, SHA-256
  over data groups, MRZ parsing, the CSCA cert-chain) is a large, security-critical body where soundness
  bugs admit fake humans. We adapt three things: the **nullifier derivation** (bind to our chain id + user
  address, spec §3.3), the **public-input layout** (emit our attribute commitments + bind the
  CSCA-registry root, our submitter address, our `now` epoch, spec §3.5), and the **CSCA root input** (read
  our on-chain registry, §7).
- **Proof system: Groth16 over BN254 (alt-bn128).** The verifier runs in the consensus path on every node
  and (later) in a browser light node, so the **dominant** criterion is a small, fast, allocation-light,
  WASM-friendly verifier. Groth16's verify is a fixed **3-pairing** equation + one public-input MSM; the
  proof is **~200 bytes**; verify is **constant-time, ~milliseconds**. BN254 is the curve the
  OpenPassport/Self artifacts target and the one every Rust pairing crate + chain precompile supports
  (minimal adaptation).

**The trusted-setup cost, stated plainly (security-gate item).** Groth16 needs a **circuit-specific**
trusted setup (a per-circuit Phase-2 atop a universal Phase-1). Un-destroyed toxic waste lets its holder
**forge proofs for that circuit ⇒ forge a fake human.** Mandatory mitigations: (1) reuse a public
multi-party **Phase-1** (perpetual powers-of-tau); (2) run an **open multi-contributor Phase-2** for our
exact circuit, publish all transcripts + a verification script (1-of-N honest contributors suffices);
(3) **pin the resulting verifying key in genesis**, hash-committed in `state_root` (a swap is a consensus
change, never silent); (4) document the assumption in the threat model.

**Rationale (why not the alternatives).**
- **vs. mDL/EUDI:** inclusion + trust-footprint at launch (above). Forward-compatible, not foreclosed.
- **vs. writing the circuit from scratch:** soundness risk + the brief's explicit mandate to integrate.
- **vs. PLONK / Honk (universal/updatable setup):** removes the *per-circuit* ceremony (one universal SRS
  for any circuit) — materially safer **operationally**. Rejected for M6 *only* because the verifier is
  heavier/larger and harder to land deterministically in `runtime` **now**. It is the **documented upgrade
  path**: the verifier trait (Decision 2) is written so the proof system swaps without touching the op, the
  nullifier registry, or the attribute store — the natural moment is the next circuit change / the second
  document type.
- **vs. STARKs / SP1 / RISC-Zero (transparent, no setup):** best setup story, but proofs/verifiers are far
  larger/heavier — a poor fit for an in-runtime per-block verifier and a 60-second in-browser phone prover.
  Backlog.

**Consequences.** A trusted-setup ceremony is a hard prerequisite the security gate must review. The
verifying key, the genesis CSCA set, and the public-input layout are pinned + committed in `state_root`
(version bumped to `ubi2/state-root/2`). A future proof-system change is an explicit consensus migration,
never a silent reinterpretation.

---

## Decision 2 — The verifier is a PURE, DETERMINISTIC function in an isolated `crates/zkpoh`, called by `runtime` via a trait — keeping the cleanest PoH path in the consensus core

**Decision.** ZK verification is **pure deterministic cryptography (no AI)**, so — unlike the AI jury — it
slots **directly into the deterministic consensus path**. Concretely:
- A **new `crates/zkpoh`** crate holds the Groth16/BN254 verifier + the Pedersen/attribute verifier + the
  genesis-pinned VK + canonical group-element (de)serialization + a `MockZkVerifier` + the real-curve
  test-fixture path.
- **`crates/runtime` defines the `ZkPassportVerifier` trait and calls it** — the exact pattern the
  `HumanityOracle`/`ContractInterpreter` use (runtime owns the trait; the impl lives outside). `runtime`
  gains **no** crypto/async dependency.
- The pairing library is **pinned to arkworks (`ark-bn254` + `ark-groth16` + `ark-ff`/`ark-ec`)**, chosen
  because it is **deterministic** (no randomized verification, no float, no parallel-reduction
  nondeterminism), serializes group elements **canonically** (one valid encoding per element; reject
  non-canonical — a malleable encoding is a soundness/replay risk), and **compiles to WASM** (the runtime
  is WASM-targetable; the light node runs it in-browser).
- The build-level dependency test that forbids `libp2p`/`tokio`/`reqwest` in `runtime` is **extended**:
  `runtime` must pull no crypto/async/network dep; **`crates/zkpoh` must pull no async/network/clock/float
  dep**. The verifier path stays consensus-safe and WASM-compilable.

**Rationale.** This is the cleanest PoH path the project has: there is nothing for nodes to "agree" about
the math — every honest node re-runs the verifier and gets the same boolean. Isolating the heavy crypto in
`crates/zkpoh` behind a trait keeps `runtime` dependency-free (the load-bearing structural rule) while
letting the verifier evolve (Decision 1's PLONK/Honk swap) without touching the consensus state machine.
Pinning a deterministic, canonical-encoding pairing library is what makes **I1/I2 hold across nodes for the
crypto** exactly as the bucketed canonical AI output makes them hold for the jury.

**Rejected.** (a) Putting the pairing math directly in `runtime` — breaks the dependency-free rule and
couples the proof system to the state machine. (b) A non-deterministic / non-canonical-encoding verifier —
would let honest nodes diverge silently (a fork), the one thing the consensus core forbids.

**Consequences.** CI exercises the lifecycle/composition with `MockZkVerifier` (offline, I5) and guards
**soundness** with a focused real-curve test against test-passport fixtures (never a real document). A node
that links a divergent/patched verifier produces a different `state_root` and is out-voted (Decision 5) —
divergence is *contained*, never silent.

---

## Decision 3 — Nullifier uniqueness: per-passport, per-chain, address-bound-by-public-input

**Decision.** The circuit emits a **deterministic, one-way nullifier** bound to the **document** and the
**chain**, *not* to the address:

```
document_secret = H_circuit( DSC_pubkey_fingerprint || document_number || issuing_country )   // private witness
nullifier       = H_circuit( document_secret || CHAIN_ID || PASSPORT_SCHEME_TAG )              // public output
```

- **One-way:** the nullifier is a circuit-hash output; its preimage (and every MRZ field) stays a private
  witness — it cannot be inverted to the document.
- **Per-passport, per-chain:** the *same passport* always yields the *same* nullifier on *this* chain, so a
  second address presenting a proof from the same passport produces a nullifier **already in the on-chain
  nullifier registry** → rejected. Binding `CHAIN_ID` means the nullifier is meaningless on another chain
  (no cross-chain linkage of a human).
- **Address binding is by public input, not by mixing into the nullifier:** the submitting address is a
  **public input the proof commits to**, and the runtime checks it equals `ecrecover(tx.sig)`. A copied
  proof therefore verifies `false` for any other sender (anti-replay/front-run). Mixing the address *into*
  the nullifier was **rejected** — it would let one passport register many addresses (one nullifier each),
  defeating uniqueness.

The nullifier is registered atomically on a successful proof and is **permanent** (a spent nullifier is
never re-usable on this chain). Passport *renewal* (a new document number ⇒ a new nullifier) and retroactive
purge of nullifiers under a revoked CSCA are documented edges deferred to **M7** (spec §7.4).

**Rationale.** This is the standard PoH-nullifier construction (one-way, scoped) specialized so that the
**document** is the unit of uniqueness and the **address** is the anti-replay binding. It makes
double-registration **cryptographically impossible**, not merely expensive — the precise gap M3 leaves open.

**Consequences.** The runtime gains a sorted **nullifier registry** (a `State`-trait collection, committed
in `state_root`). The cheap nullifier-membership check runs **before** the expensive pairing verify
(fail-closed + DoS-resistant).

---

## Decision 4 — Privacy by construction: store only commitments; Pedersen attribute commitments with per-attribute blinding for unlinkability

**Decision.** The chain stores **only commitments**, never plaintext PII (I6, structural — there is no
field to hold a name/DOB/document-number/nationality). A successful proof writes exactly: the **nullifier**,
three **Pedersen attribute commitments**, the **assurance level**, and `verified_at`.

The three M6 attributes (each a 32-byte BN254 field element, fixed order — spec §3.4):
1. **Age threshold** — a commitment to `born_before_epoch` for the 18/21-year thresholds (the circuit
   proves DOB ≤ `now − 18y` and commits to *that fact*), **never** the raw DOB.
2. **Nationality bucket** — a commitment to `H(MRZ_nationality_code)` (a hash, never the plaintext code).
3. **Document expiry** — a commitment to `expiry_epoch`.

Each is `C_i = g^{m_i}·h^{r_i}` with a **per-attribute blinding factor `r_i`** the user's device keeps.
**Hiding** (without `r_i`, `C_i` reveals nothing about `m_i`), **binding** (the user cannot reopen to a
different `m_i`), and — critically — **unlinkability**: blinding makes two humans' *identical* attributes
(e.g. both over-18) produce *different* commitments, so the store cannot cluster humans by attribute.

A later **attribute verifier** (Stage D `over18`, the template for M7) proves a statement *about* a stored
commitment (a Pedersen-opening + range proof) and returns only a boolean — the DOB is never revealed (spec
§4.4). The **public-input vector is pinned** (spec §3.5): nullifier, the 3 commitments, the CSCA-registry
root, the submitter address, the `now` epoch, and the scheme tag — the runtime re-derives the last four
from on-chain state + the tx + the block and rejects on mismatch, binding the proof to *this* submitter,
*this* trust set, and *this* time (anti-replay + trust-anchor confusion).

**Rationale.** Commitments + ZK opening proofs give M7 DAOs real attribute selectors (over-18, nationality,
expiry) **without the chain ever holding the data and without the user re-verifying** — the substrate the
brief requires M6 to deliver. Per-attribute blinding is what makes the store privacy-preserving rather than
a queryable attribute database.

**Rejected.** (a) Storing attribute *values* (or unblinded commitments) — would let the store cluster
humans by attribute (a privacy leak). (b) A single combined commitment — would prevent selectively proving
one attribute without touching the others.

**Consequences.** The runtime gains a sorted **attribute store** (`Address → [3×32 bytes]`, committed in
`state_root`). The user's device must retain the blinding factors to later prove an attribute (a wallet
key-management concern, noted for Stage C).

---

## Decision 5 — The cross-node guarantee (EC-7) is the M5 re-execution consensus, not a new AI-style jury

**Decision.** `submitZkPassportProof` rides the **existing M5 mechanism** with **no new consensus
primitive**: the tx is gossiped, included by the M5 proposer, and **every follower re-executes the verifier
as part of block validation** (ADR-0004 / spec 05 §5.1 rule 3 — "re-execution yields a byte-identical
`state_root`"). Because the verifier is deterministic, honest nodes agree; a node whose verifier disagrees
(a tampered build, or the injected-disagreement test) computes a **different `state_root`**, fails to reach
agreement, and is **out-voted by the honest majority via M5 fork choice**. The chain advances only on the
value the honest majority agrees re-executes correctly — i.e. *exactly* the M5 I1 property ("no single node
alone commits; agreement commits; divergence aborts deterministically") applied to a deterministic op.

**Rejected (kept as a documented fallback).** An M3-style **`Case`/jury wrapper** where each "juror"
submits a `verify→bool` and `quorum_tally` commits on supermajority. Rejected as the default because it
adds latency and a quorum-*split* failure mode to a check that **cannot honestly split** (the math is a
function) — the re-execution consensus already delivers the cross-node guarantee more cleanly. The wrapper
is retained as the mechanism to use **iff** a future verifier becomes non-pure (e.g. needs an off-chain
artifact); M6 does not need it.

**Rationale.** Routing a *deterministic* op through re-execution consensus (rather than an AI-style quorum)
is both simpler and a better fit: there is nothing probabilistic to vote on. It reuses the M5 validate-before-
apply + fork-choice machinery verbatim, so equivocation/divergence handling, replay, and auditability come
for free — the same argument ADR-0004 Decision 4 makes for the AI quorum, here even stronger because the
function is pure.

**Consequences.** EC-7's "injected disagreement aborts deterministically" is tested by stubbing one node's
`zkpoh` verifier to return the wrong boolean and asserting that node diverges and is out-voted (reusing M5
AC-9 / AC-F2). No new on-chain tally, no new wire format.

---

## Status of invariants

- **I1 (deterministic consensus over non-deterministic AI):** *strengthened in spirit* — this is the PoH
  path with **no AI in the verify path at all**; determinism is by pure cryptography, and the cross-node
  guarantee is the M5 re-execution consensus (Decision 5). Honest nodes agree by re-running a function;
  divergence is out-voted, never silent.
- **I2 (reproducible integer balances):** preserved. The op reads **only `block.timestamp`** (`nowEpoch`);
  the new collections are integer/byte-array fields committed in `state_root`; emission flips exactly as the
  M3 `finalize_registration` path.
- **I3 (EVM compatibility):** preserved. The op is a HumanityHub tx with a fixed selector (MetaMask signs
  unchanged); all new reads are `ubi_*` extensions; no `eth_*` semantics change.
- **I4 (fail-closed):** preserved + central. Every verification step aborts on the first failure with no
  partial state (expired / untrusted-CSCA / tampered / replay / nullifier-reuse all reject cleanly); a
  verifier divergence is out-voted, not committed.
- **I6 (least authority / privacy):** **structurally** satisfied — only commitments on-chain, blinded
  attribute commitments, no PII field exists; per-attribute blinding gives unlinkability.

## Open follow-ups created / closed by this ADR

- **Requires (hard prerequisites):** a public multi-party **Phase-2 trusted-setup ceremony** for the pinned
  circuit (security-gate review) + the **Light-Node WASM prover** for the in-app NFC flow (M6 Stage C
  depends on it; spec §8).
- **Defers to M7:** DAO attribute gates + verifiers beyond `over18`; passport-renewal binding + retroactive
  nullifier revocation under a revoked CSCA; re-pointing the CSCA-registry governance op at the DAO vote.
- **Defers to backlog:** the **PLONK/Honk** universal-setup migration (Decision 1, the next circuit change);
  additional document types (**mDL/EUDI**, national ID cards, residence permits — the issuer-agnostic
  shape, Decision 1); Active/Chip-Authentication anti-clone hardening across the full issuing-country set.
- **Open questions (spec §13):** O-1 fee-exempt new-user ZK path; O-2 renewal/retroactive revocation;
  O-3 `CSCA_ROOT_GRACE_BLOCKS` + `GAS_ZKPOH` constants; O-4 Groth16→PLONK timing; O-5 Active-Authentication
  launch scope.
