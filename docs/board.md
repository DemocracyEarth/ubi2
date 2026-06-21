# ubi2 Task Board

The live work queue, maintained by the `orchestrator`. Tasks move between sections; history is not
deleted. A task is **Done** only when QA + reliability + security gates are green (see
[`loop.md`](loop.md)).

**Current milestone:** M2 — Streaming primitive · **M1 (EVM RPC + Wallet) shipped in cycle 1 ✅**

| Field | Meaning |
|---|---|
| id | `M<milestone>-T<n>` |
| owner | the agent responsible |
| accepts | acceptance criteria (the bar for Done) |

---

## 🔜 Backlog

**M2 — Streaming primitive** (next cycle; needs architect spec first)
- **M2-T1 · architect** — Spec account-to-account streams (1:1 then 1:many) on top of the UBI drip:
  data model, RPC surface, safety controls. *Accepts:* testable acceptance criteria + invariants.
- **M2-T? · protocol/interface** — to be decomposed after the spec lands.

**Cycle-1 follow-ups (carried from the gates — address before they bite)**
- **FU-1 · protocol/security** — Mempool hardening before any multi-node / non-localhost deploy:
  per-sender pending-balance accounting (security F1) + global/per-sender mempool caps (security F2).
  *Source:* `docs/reports/security-m1.md`. *Not an M1 blocker (localhost devnet).*
- **FU-2 · protocol/architect** — Decide the emission-rounding policy (carry remainder vs. document
  bounded loss) before M2/M5 raise settlement frequency. *Source:* [ADR-0002](specs/adr/0002-emission-rounding-policy.md).
- **FU-3 · protocol** — State persistence/checkpoint behind the existing `State` trait (M1 is in-memory).
- **FU-4 · reliability** — Two-node soak once consensus (M3 quorum) exists; metrics/observability.

**Product backlog (field-test feedback · 2026-06-21 — verified live on an EVM wallet)**
- **EXPL-1 · protocol/interface** — A *proper* block explorer: browse all blocks, txs, and accounts,
  with search by hash/address and per-account history. Needs a node-side **address index** first
  (today `txs` is indexed by hash + block only, not by account) — i.e. a lightweight indexer behind the
  RPC, then a dedicated explorer UI (or split `apps/explorer` from `apps/wallet`).
- **UX-1 · interface (+ optional protocol)** — Real-time "dripping" UX. Note: accrual is **already
  continuous** (balance is a pure function of wall-clock time, not block-gated — the 2s tick only
  affects tx confirmation, not UBI growth), and the ubi2 wallet already interpolates per-frame via
  `projectBalance`. Levers left: (a) push freshness over a `newHeads`/balance subscription so the drip
  re-anchors faster; (b) accept that third-party wallets (MetaMask) poll on their own cadence and can't
  show a smooth drip — our own UI is where the feel lives. Largely solved; this is polish + a decision
  on whether to expose a balance-stream subscription.

## 🏗️ In Progress
_(none — cycle 1 closed)_

## 👀 Review (awaiting gates)
_(none)_

## ⛔ Blocked
_(none)_

## ✅ Done
- **M0 · all** — Monorepo + 10-agent loop + seeded specs/roadmap/board scaffolded. *(bootstrap commit)*
- **M1 — EVM RPC + Wallet · SHIPPED (cycle 1).** All gates green.
  - **M1-T1 · architect** — Spec finalized (emission arithmetic, `State`/`Verifier` traits, chainId `0x5542`, EIP-155 txs, 2s tick).
  - **M1-T2/T3/T4 · protocol-engineer** — Rust node + EVM JSON-RPC (HTTP+WS) + devnet; streaming `eth_getBalance`, EIP-155 `eth_sendRawTransaction`, block tick. Orchestrator-verified live.
  - **M1-T5/T6 · interface-engineer** — TS SDK + Next.js wallet/explorer; balance ticks up via rAF interpolation; "Add to MetaMask" card. Both builds green.
  - **M1-T7 · qa-engineer** — ✅ PASS: all 5 acceptance criteria → passing tests; 28 cargo tests + E2E script. `docs/reports/qa-m1.md`.
  - **M1-T8 · reliability-engineer** — ✅ PASS: I2 determinism proven (50k random timelines); no nondeterminism. `docs/reports/reliability-m1.md`.
  - **M1-T9 · security-engineer** — ✅ PASS: no open High/Critical; signature/replay + balance integrity held under pentest. 2 Medium hardening follow-ups (→ FU-1). `docs/reports/security-m1.md`.
  - **M1-T10 · release-engineer** — `rust-toolchain.toml` pin, `scripts/devnet.sh`, `.github/workflows/ci.yml`. *(done inline by orchestrator)*
