# The ubi2 Development Loop

This is the process the [agent team](../AGENTS.md) runs to build ubi2. It is an explicit, resumable
cycle. All state lives in version control, so any cycle can be picked up where the last one left off.

## The cycle

```
 ┌──────────────────────────────────────────────────────────────────────────┐
 │                                                                            │
 ▼                                                                            │
① product-strategist   confirm milestone + priorities          → roadmap.md  │
② architect            spec the next slice + invariants         → specs/, adr/│
③ orchestrator         decompose into tasks, assign             → board.md    │
④ engineers            implement (protocol / ai / interface)    → code        │
⑤ qa-engineer          GATE 1: tests vs. acceptance criteria    → reports/    │
⑥ reliability-engineer GATE 2: determinism / consensus / soak   → reports/    │
⑦ security-engineer    GATE 3: threat model + pentest the diff  → reports/    │
⑧ release-engineer     build, CI, deploy to devnet              → release     │
⑨ orchestrator+product feedback → update board + roadmap ───────────────────┘
```

## Definition of Done

A task is **Done** only when **all three gates are green**:

| Gate | Owner | Asks |
|---|---|---|
| 1. Correct | `qa-engineer` | Does every acceptance criterion have a passing test? |
| 2. Consistent | `reliability-engineer` | Does it stay correct across nodes, time, restarts, and load? |
| 3. Safe | `security-engineer` | Is the diff free of open high/critical findings? |

The `orchestrator` never advances a task past a red gate. On red, the task moves to **Blocked** with the
reason, and a fix is dispatched to the owning engineer. The gate re-runs on the fix.

## Handoff protocol

- Every handoff is a **task on the board** with: `id`, `owner agent`, `milestone`, `acceptance
  criteria`, `status`, and links to the relevant spec/report. Nothing is handed off verbally.
- Each agent reads its inputs from the repo (spec, code, prior reports) and writes its outputs to the
  repo (code, tests, or a report under `docs/reports/`). Reports are committed.
- An agent that finds its input underspecified kicks the task **back up** the chain (engineer → architect,
  architect → product) rather than guessing.

## Roles in one line

product-strategist (*what/why*) → architect (*precise how*) → orchestrator (*who/when*) →
protocol/ai/interface engineers (*build*) → qa/reliability/security (*prove*) → release (*ship*).

## Running a cycle

Drive the `orchestrator` from the repo root:

> "Run the next cycle of the ubi2 loop for the current milestone."

It reads `docs/board.md`, dispatches each role via the Agent tool, collects reports, updates the board,
and returns a short summary. To run a single task, name it (e.g. "have the protocol-engineer implement
M1-T2"). To re-plan, ask `product-strategist` then `architect` before the orchestrator decomposes.

## Escalation

Decisions that are costly to reverse, change scope, or break an invariant in
[`specs/00-overview.md`](specs/00-overview.md) are surfaced to the human by the orchestrator **before**
proceeding, and recorded as an ADR.
