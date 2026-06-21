# ADR-0001 — Record architecture decisions

- **Status:** accepted
- **Date:** 2026-06-20
- **Deciders:** architect (on behalf of the ubi2 team)

## Context
ubi2 makes several unusual, hard-to-reverse bets — AI in the consensus path, natural-language contracts,
streaming-as-a-primitive, EVM compatibility. We need a durable record of *why* decisions were made so the
agent team (and future humans) don't relitigate settled questions or silently violate invariants.

## Decision
We record every architecturally significant, costly-to-reverse decision as an **Architecture Decision
Record (ADR)** in `docs/specs/adr/NNNN-title.md`, using this lightweight format:
**Context → Decision → Consequences**, with a status (`proposed` / `accepted` / `superseded by ADR-NNNN`).

A decision is "architecturally significant" if it affects an invariant in
[`00-overview.md`](../00-overview.md), the public interfaces (RPC/SDK), the consensus/AI seam, the
economic model, or anything expensive to change later. The `architect` owns ADRs; the `orchestrator`
requires one before allowing such a change through the loop.

## Consequences
- Decisions are discoverable and revisable as a numbered, append-only log (supersede, don't delete).
- Specs stay about *what*; ADRs capture *why* and the alternatives rejected.
- Small, reversible choices stay in code/specs and do **not** need an ADR — ADRs are reserved for
  consequential ones, to avoid ceremony.

## Initial consequential decisions already in force (see `00-overview.md`)
These predate the ADR log but are recorded here as accepted, to be expanded into their own ADRs as they
are challenged:
- AI outputs in the consensus path are deterministic (temp 0, pinned model+seed, canonical schema) and
  committed only by interpreter/verifier **quorum**, aborting deterministically on disagreement (I1).
- Time-based balances are integer/fixed-point pure functions of (state, timestamp) (I2).
- The chain presents an **EVM-compatible JSON-RPC** rather than a bespoke interface (I3).
