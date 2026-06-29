# ubi2 — A Human-Verified, AI-Executed Network for Universal Basic Income

> Condensed and carried forward from the original framework in `../ubi.agent/README.md`.
> This is the **canonical vision document**. When a spec and this document disagree, the
> `architect` reconciles them and records the decision as an ADR.

## Abstract

ubi2 is a decentralized Universal Basic Income system built on six primitives: **AI proof-of-humanity**
that admits unique real humans via social vouching and AI-jury quorum, **ZK-passport proof-of-humanity**
that adds a stronger, privacy-preserving cryptographic path over government-issued e-passports,
**continuous emission** of one token per hour per verified human, **native streaming** that turns
payments into real-time flows, **prompt contracts** — agreements written in natural language and executed
by AI nodes that reach consensus on intent — and **lightweight browser/mobile nodes** that let anyone
verify the chain from a phone or browser tab without trusting a server. Economic mechanisms (demurrage,
fee recycling) keep value circulating instead of concentrating, and minimal quadratic-delegation
governance keeps the system adaptable without capture. The network exposes an EVM-compatible JSON-RPC
so ordinary wallets can use it.

## 1. Proof-of-Humanity

The right to receive UBI requires proving you are a unique human — without building a surveillance
database. ubi2 offers two complementary, additive paths. Completing either yields full `Verified`
status and starts the UBI stream. Both can be combined for the strongest assurance.

### 1.1 Social-vouching + AI-jury quorum (the inclusive baseline)

The original M3 path admits anyone — no documents, no biometrics, no government ID required:

- **Liveness and interaction challenges** an LLM generates and grades, resistant to replay and bots.
- **Behavioral analysis** over time to flag automated or duplicated participation.
- **Sybil resistance** through multiple weak signals combined (no single hard gate that excludes), with
  privacy-preserving checks rather than stored identity.
- **Verdict as consensus**: a human is admitted only when an independent **quorum of verifier nodes**
  agree. No single node decides who is human.

Design constraint: verification is probabilistic and adversarial. It must degrade safely — deny on
uncertainty for new claims, never silently revoke established humans without quorum and appeal.

This path carries `STD` (Standard) assurance. It is the permanent, unconditional fallback for any human
who does not hold a valid passport, has no NFC reader, or simply prefers not to present a document.

### 1.2 ZK-passport proof-of-humanity (the cryptographic upgrade)

A modern passport's NFC chip stores government-signed data under the ICAO-9303 / CSCA-to-DSC trust
hierarchy — a cryptographic commitment to a real human's existence, issued by a sovereign with strong
anti-forgery incentives. A **zero-knowledge proof** over that signature provides something the AI-jury
path cannot: a **one-passport-one-human nullifier**, enforced cryptographically rather than
probabilistically.

Key properties:

- **Deterministic on-chain verifier.** Groth16 pairing verification over BN254 is a pure mathematical
  function — no AI, no probabilistic judgment. Every honest node re-runs the same math and reaches the
  same boolean. This is the cleanest possible PoH path in the consensus core: disagreement is impossible
  unless a node's verifier is tampered.
- **One-passport-one-human nullifier.** The circuit derives a deterministic, one-way scalar bound to
  the document and the chain — not the address. A second address presenting a proof from the same
  passport produces a nullifier already in the on-chain registry and is rejected chain-wide. This closes
  the sybil gap the social path leaves open.
- **No PII on-chain, ever.** The chain stores only a nullifier and three Pedersen attribute
  commitments (age threshold, nationality bucket, document expiry). No name, document number, exact
  date of birth, or nationality in plaintext is ever written to any node. Privacy is enforced by what
  the circuit emits, not by an access-control rule that could be misconfigured.
- **Opaque attribute commitments, reusable by DAOs.** Each commitment is a Pedersen commitment with a
  per-attribute blinding factor the user's device holds. Without that blinding factor the commitment
  reveals nothing. A user can later prove a statement about a commitment — for example, that their age
  commitment encodes "born before 18 years ago" — without revealing the underlying value. Future DAOs
  inherit these selectors without requiring the user to re-verify.
- **Client-side proving.** NFC passport read, witness generation, and Groth16 proof generation all
  happen on the user's device. Only the compact proof and its public inputs — roughly 200 bytes plus
  public scalars — reach the chain.
- **Additive, not a replacement.** The social-vouching path is never deprecated. Roughly 20% of the
  world's adults hold no valid passport, concentrated in exactly the populations UBI most needs to reach.
  ZK-passport is an optional upgrade lane, not a prerequisite for UBI.

### 1.3 Assurance levels

| Level | Path | Uniqueness guarantee | UBI eligibility |
|---|---|---|---|
| `STD` | Social vouching + AI-jury quorum | Probabilistic; social attestation | Full |
| `ENH` | ZK-passport proof accepted | Cryptographic nullifier; government-attested | Full |
| `DUAL` | Both paths completed | Strongest | Full |

UBI eligibility is `Verified` status, not assurance level. A `STD` human and a `DUAL` human receive
exactly the same 1 UBI/hour stream. The assurance level is metadata for features — future DAOs can gate
membership on `ENH` or `DUAL` — never a gate on UBI accrual.

### 1.4 The inclusion constraint (non-negotiable)

ZK-passport is never the sole PoH gate. A human without a passport verifies via the M3 vouching path
at `STD` level with identical UBI eligibility. This constraint is structural: there is no code path
where `assurance` affects `balance()`.

## 2. Token Distribution

- **Continuous emission.** Each verified human accrues **1 UBI/hour**, streamed continuously from the
  moment of verification. Supply starts at zero and grows only with verified humans — per-capita by design.
- **Demurrage.** Idle balances decay (baseline ~2%/month), scaling progressively with holding size and
  reset by active use — pressure toward circulation, not punishment of participation.
- **Fee recycling.** Network fees return to the commons rather than accruing to a few.

## 3. Streaming Framework

Streaming is a **native protocol primitive**, not an app-layer add-on:

- Directions: one-to-one, one-to-many, many-to-many.
- Temporal controls: start, duration, rate.
- Conditional/programmable flows; composable (split/merge).
- Safety: collateralization limits, rate controls, circuit breakers on anomalous flows, multi-sig on
  critical parameters.

The UBI drip is itself a stream from the protocol to each human; account-to-account streams extend it.
Light-node wallets (§5) observe streaming balances locally from verified chain state — no server trust
required for the number you see ticking upward.

## 4. Prompt Contracts (intent-as-law)

Contracts are written in **natural language** and executed by foundation models running across nodes.
To make non-deterministic models safe for consensus:

- **Deterministic inference**: temperature 0, pinned model and seed, canonical structured-output schemas.
- **Multi-interpreter quorum**: N independent nodes interpret the contract; the **effect** (state delta)
  is committed only if a quorum produces the *same* canonical effect.
- **Deterministic fallback**: on disagreement, the contract aborts deterministically (no partial state).
- Formally-verified primitives (streams, transfers, verification) underlie the natural-language layer.
- A prompt contract can gate an action on a ZK attribute verification — for example, requiring
  `verifyAttribute('over18')` before releasing escrow — combining the expressiveness of natural language
  with the privacy of ZK credentials.

This is the project's hardest invariant — see [`docs/specs/00-overview.md`](docs/specs/00-overview.md).

## 5. Lightweight Browser and Mobile Nodes

Anyone can run a node. The deterministic runtime compiles to **WASM** and runs in a browser tab or on
a phone, making "run a node" a one-tap act rather than a server-administration task.

### 5.1 How it works

The same `crates/runtime` that full nodes run — the deterministic, dependency-free state machine —
compiles to `wasm32-unknown-unknown` unchanged. A thin `wasm-bindgen` wrapper (`crates/runtime-wasm`)
exposes a bytes/JSON API. A TypeScript light client (`packages/light-client`) connects to a full node
over a WebSocket sync gateway, downloads blocks, and **re-executes every block in WASM**, asserting a
byte-identical `state_root` after each one.

### 5.2 Trust model: a lying server is caught, not trusted

A light node does not trust a server's claim about a balance or a state root. It re-derives both by
re-executing the same deterministic core consensus runs. If the re-executed root disagrees with the
header the server served, the block is rejected and a visible verification error is shown — never a
wrong balance shown as correct. A gateway that forges a block is caught the moment that block fails
re-execution; it can withhold blocks (an availability failure) but cannot silently manufacture a false
state.

Verified state persists in IndexedDB; a reload resumes from the last verified height rather than
replaying from genesis. On load, the snapshot's state root is recomputed and checked against the stored
tip — a poisoned cache is discarded, not trusted.

### 5.3 Phone-first and the ZK-passport synergy

The light node's primary distribution target is the phone. This creates a natural synergy with ZK-PoH:
the phone's NFC reader performs the ICAO-9303 passport scan; the same WASM runtime generates the
Groth16 proof on-device; the proof is submitted via the phone's own light node. Passport bytes never
leave the device; the chain receives only the compact proof. A human can go from passport tap to
streaming UBI without touching a desktop.

### 5.4 Progressive capabilities

| Stage | What ships | Where it runs |
|---|---|---|
| 1 (shipped) | WASM re-execution, block sync over WS gateway, IndexedDB persistence, EIP-1193 signing, verification UI | Browser tab |
| 2 | PWA manifest, service worker, offline last-verified read, opt-in PII-free Web Push | Installable app |
| 3 | Native iOS/Android wrapper + NFC bridge for passport scan + on-device ZK proof generation | Phone |
| 4 (opt-in) | Block production (gated on staking) + in-app juror daemon | Phone |

## 6. AI Provider Network

Tokens derive utility from a decentralized network of AI service providers: UBI can purchase AI
compute/inference, creating real demand while democratizing access to AI as a basic utility. This
network also forms the foundation for the AI-jury quorum that adjudicates PoH cases and interprets
prompt contracts.

## 7. Governance

Deliberately minimal. **Quadratic delegation** (voting power scales with the square root of delegated
support) resists plutocratic capture. Scope is limited to: verification-system evolution, bounded
economic-parameter tuning, CSCA trust-anchor registry updates, provider-network integration, and
emergency response (with sunsets and supermajority). Progressive decentralization ossifies parameters
over time.

The CSCA trust-anchor registry — the set of government root keys the ZK-passport verifier trusts — is
an on-chain, governance-upgradeable state collection. Adding or revoking a country's signing authority
is a transaction, not a hard fork. In later milestones, this authority moves to quadratic-delegation
governance.

## 8. Interoperability

An **EVM-compatible JSON-RPC** lets standard wallets (MetaMask, etc.) read balances and blocks and
submit transactions, so the network is usable without bespoke tooling. All PoH and contract operations
are EIP-155 transactions to reserved hub addresses — MetaMask signs them unchanged. The ZK-passport
proof submission is a new HumanityHub operation with the same signing model; the WASM light node's
block-sync gateway reuses the existing `eth_subscribe` WebSocket server. No standard `eth_*` method
changes semantics.

## 9. Why these choices

Removing subjective need-assessment removes bureaucracy, discrimination, and the indignity of proving
poverty. Demurrage and fee recycling favor circulation over hoarding. Natural-language contracts move
participation from "those who can code" to "anyone who can state intent," while quorum interpretation
preserves execution guarantees.

Two specific choices deserve a direct defense:

**Why ZK over a document database.** Storing government-issued identity data would make ubi2 a
surveillance substrate — exactly what it should not be. Zero-knowledge proofs let the chain answer
"is this a unique human over 18?" without ever learning who the human is. Privacy is enforced by the
circuit's public outputs, not by a policy rule.

**Why light nodes, not just wallets.** Trust requires verification, not faith. A wallet that reads from
a server asks you to trust that server. A light node that re-executes every block in the same
deterministic core consensus uses asks you to trust the math. The WASM compilation path makes that
stronger trust model available on any device with a browser — phone-first, by design, because that is
where most of the world computes.

**Why these two PoH paths together.** Social vouching is inclusive but game-able at scale; ZK-passport
is cryptographically strong but excludes those without valid travel documents. Neither alone is
sufficient. Together — with identical UBI eligibility at every level — the system is both maximally
inclusive and maximally resistant to sybil attack.
