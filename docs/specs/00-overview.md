# 00 — System Overview & Invariants

This document defines the architecture at a high level and the **invariants** every spec, every diff,
and every gate must uphold. It is owned by the `architect`. When a later spec conflicts with this one,
the conflict is resolved here and recorded as an ADR.

## System shape

```
                         ┌─────────────────────────────┐
   EVM wallets ───JSON-RPC──▶  crates/rpc (EVM compat)  │
   (MetaMask)            │           │                  │
                         │           ▼                  │
                         │  crates/runtime (state:      │
                         │   accounts, emission,        │
                         │   demurrage, streams)        │
                         │           ▲                  │
   apps/wallet ──SDK────▶│           │  deterministic   │
   packages/sdk          │           │  hooks (traits)  │
                         │           ▼                  │
                         │  AI layer (proof-of-humanity,│
                         │  prompt-contract interpreter,│
                         │  interpreter/verifier quorum)│
                         └────────── crates/node ───────┘
                              (networking, blocks, consensus)
```

The **runtime is deterministic**; the **AI layer is probabilistic** and is confined behind interfaces
that only ever commit a deterministic *effect* agreed by a quorum.

## The hard invariants (non-negotiable)

### I1 — Deterministic consensus over non-deterministic AI
Any LLM whose output influences committed state runs at **temperature 0** with a **pinned model + seed**
and emits a **canonical, structured output**. The network commits the **effect** (a state delta), not the
prose, and only when an **independent quorum of N interpreters/verifiers produces the *same* canonical
effect**. On disagreement, the operation **aborts deterministically** — no partial state, ever.
The quorum must be evaluated across **independent processes** (independent nodes with independent AI
backends), not merely independent addresses in one process; honest nodes converge on the same committed
effect and any divergence aborts. *(M5 makes this cross-process — see [`05-p2p-network.md`](05-p2p-network.md) and [ADR-0004](adr/0004-consensus-and-networking.md).)*

### I2 — Reproducible time-based balances
Streaming emission (1 UBI/hour), demurrage, and stream flows are **pure functions of (state, timestamp)**.
Use integer/fixed-point arithmetic — **no floats in any consensus path**. Two nodes computing a balance at
the same height/timestamp must agree **to the smallest unit**.

### I3 — EVM compatibility is a contract
RPC methods follow Ethereum semantics closely enough that **unmodified wallets work** for supported
operations. Every intentional deviation is documented in the method's spec and, if costly to reverse, an ADR.

### I4 — Safe degradation
Proof-of-humanity and prompt-contract execution **deny/abort on uncertainty**. New human claims are denied
when unsure; established humans are only revoked by quorum + appeal. Contracts fail closed.

### I5 — Determinism is testable offline
The AI layer must be exercisable with **recorded fixtures** so QA/reliability can assert reproducibility in
CI without live model calls.

### I6 — Least authority
A prompt contract gets only the state/authority it was explicitly granted. The RPC exposes only what's
specified. Secrets never enter code, logs, or artifacts.

## Token model (summary; details per milestone spec)
- Unit: **UBI**, accrued at **1 UBI/hour** per verified human from `verified_at`.
- Demurrage: idle-balance decay (baseline ~2%/month), reset by activity. *(M5)*
- Fee recycling: fees return to the commons. *(M5)*

## Component responsibilities
- `crates/runtime` — state + deterministic transitions (the source of truth for I2).
- `crates/rpc` — EVM-compatible JSON-RPC (owns I3).
- `crates/node` — networking, block production, consensus, quorum coordination (owns I1's quorum).
- AI layer — interpretation/verification behind runtime traits (owns I1/I4/I5 logic).
- `apps/wallet`, `packages/sdk` — read/write surfaces for humans and wallets.

## How invariants are enforced
The three Definition-of-Done gates exist to enforce these: **qa** (acceptance criteria), **reliability**
(I1/I2 in practice), **security** (I4/I6 under attack). No diff is Done if it violates an invariant here.
