# ubi2 — A Human-Verified, AI-Executed Network for Universal Basic Income

> Condensed and carried forward from the original framework in `../ubi.agent/README.md`.
> This is the **canonical vision document**. When a spec and this document disagree, the
> `architect` reconciles them and records the decision as an ADR.

## Abstract

ubi2 is a decentralized Universal Basic Income system built on four primitives: **AI proof-of-humanity**
that admits unique real humans, **continuous emission** of one token per hour per verified human,
**native streaming** that turns payments into real-time flows, and **prompt contracts** —
agreements written in natural language and executed by AI nodes that reach consensus on intent.
Economic mechanisms (demurrage, fee recycling) keep value circulating instead of concentrating, and
minimal quadratic-delegation governance keeps the system adaptable without capture. The network
exposes an EVM-compatible JSON-RPC so ordinary wallets can use it.

## 1. Proof-of-Humanity (AI-based)

The right to receive UBI requires proving you are a unique human — without building a surveillance
database. ubi2 uses **generative AI / LLMs as the verification engine**:

- **Liveness & interaction challenges** an LLM generates and grades, resistant to replay and bots.
- **Behavioral analysis** over time to flag automated or duplicated participation.
- **Sybil resistance** through multiple weak signals combined (no single hard gate that excludes), with
  privacy-preserving checks rather than stored identity.
- **Verdict as consensus**: a human is admitted only when an independent **quorum of verifier nodes**
  agree. No single node decides who is human.

Design constraint: verification is probabilistic and adversarial. It must degrade safely (deny on
uncertainty for new claims, never silently revoke established humans without quorum + appeal).

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

## 4. Prompt Contracts (intent-as-law)

Contracts are written in **natural language** and executed by foundation models running across nodes.
To make non-deterministic models safe for consensus:

- **Deterministic inference**: temperature 0, pinned model + seed, canonical structured-output schemas.
- **Multi-interpreter quorum**: N independent nodes interpret the contract; the **effect** (state delta)
  is committed only if a quorum produces the *same* canonical effect.
- **Deterministic fallback**: on disagreement, the contract aborts deterministically (no partial state).
- Formally-verified primitives (streams, transfers, verification) underlie the natural-language layer.

This is the project's hardest invariant — see [`docs/specs/00-overview.md`](docs/specs/00-overview.md).

## 5. AI Provider Network

Tokens derive utility from a decentralized network of AI service providers: UBI can purchase AI
compute/inference, creating real demand while democratizing access to AI as a basic utility.

## 6. Governance

Deliberately minimal. **Quadratic delegation** (voting power scales with the square root of delegated
support) resists plutocratic capture. Scope is limited to: verification-system evolution, bounded
economic-parameter tuning, provider-network integration, and emergency response (with sunsets and
supermajority). Progressive decentralization ossifies parameters over time.

## 7. Interoperability

An **EVM-compatible JSON-RPC** lets standard wallets (MetaMask, etc.) read balances and blocks and
submit transactions, so the network is usable without bespoke tooling.

## 8. Why these choices

Removing subjective need-assessment removes bureaucracy, discrimination, and the indignity of proving
poverty. Demurrage + fee recycling favor circulation over hoarding. Natural-language contracts move
participation from "those who can code" to "anyone who can state intent," while quorum interpretation
preserves execution guarantees.
