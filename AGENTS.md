# ubi2 — The Agent Development Team

ubi2 is built by a team of ten specialized [Claude Code subagents](.claude/agents/) that run an
explicit, resumable development loop. This file is the one-page index: who's on the team, how the
loop runs, and where the shared state lives. The full cycle and Definition-of-Done are in
[`docs/loop.md`](docs/loop.md).

## The team

| Agent | Owns | One-liner |
|---|---|---|
| [`orchestrator`](.claude/agents/orchestrator.md) | project management | Conducts the loop, decomposes specs into tasks, maintains the board, enforces the Definition-of-Done. |
| [`product-strategist`](.claude/agents/product-strategist.md) | product roadmap | Owns the roadmap and priorities; defines acceptance criteria and the "why". |
| [`architect`](.claude/agents/architect.md) | specifications | Turns vision into precise, testable specs + ADRs; guards cross-cutting invariants. |
| [`protocol-engineer`](.claude/agents/protocol-engineer.md) | core chain | Rust node/runtime/rpc: state, EVM JSON-RPC, emission, demurrage, streaming. |
| [`ai-engineer`](.claude/agents/ai-engineer.md) | AI features | LLM proof-of-humanity + natural-language prompt-contract execution + interpreter quorum. |
| [`interface-engineer`](.claude/agents/interface-engineer.md) | interfaces | Next.js wallet/explorer + TypeScript SDK / EVM provider glue. |
| [`qa-engineer`](.claude/agents/qa-engineer.md) | testing | Unit/integration/property/E2E suites; coverage and regression gates. |
| [`reliability-engineer`](.claude/agents/reliability-engineer.md) | consistency & reliability | Determinism of AI execution, consensus safety, soak/E2E, observability. |
| [`security-engineer`](.claude/agents/security-engineer.md) | security | Threat models, diff audits, pentests, red-team, key/secret hygiene. |
| [`release-engineer`](.claude/agents/release-engineer.md) | build & deploy | Build, CI/CD, devnet/testnet deploy, release notes. |

## The loop (one cycle)

```
① product-strategist  → ② architect → ③ orchestrator → ④ engineers → ⑤ qa
                                                                        ↓
        ⑨ feedback ← ⑧ release-engineer ← ⑦ security ← ⑥ reliability ←─┘
```

A task is **Done** only when QA + reliability + security reports are green. The orchestrator never
advances work past those gates on red. See [`docs/loop.md`](docs/loop.md) for handoffs and escalation.

## Shared state (all version-controlled)

- [`docs/roadmap.md`](docs/roadmap.md) — milestones M0…Mn, goals, exit criteria.
- [`docs/board.md`](docs/board.md) — the live task board (Backlog / In-Progress / Review / Blocked / Done).
- [`docs/specs/`](docs/specs/) — specifications and ADRs.
- `docs/reports/` — QA / reliability / security reports (created as cycles run).

## How to run a cycle

From the repo root in Claude Code, drive the `orchestrator` (or invoke it via the Agent tool):

> "Run the next cycle of the ubi2 loop for the current milestone in `docs/board.md`."

The orchestrator reads the board, dispatches each role via the Agent tool, collects their reports,
updates the board, and reports back. To work a single task, name it: *"Have the protocol-engineer
implement task M1-T2."*

## Current milestone

**M1 — EVM RPC + Wallet.** A devnet node with EVM-compatible JSON-RPC that MetaMask can read, where a
verified account streams 1 UBI/hour, plus a wallet/explorer. Spec:
[`docs/specs/01-evm-rpc-and-wallet.md`](docs/specs/01-evm-rpc-and-wallet.md).
