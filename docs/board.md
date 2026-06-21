# ubi2 Task Board

The live work queue, maintained by the `orchestrator`. Tasks move between sections; history is not
deleted. A task is **Done** only when QA + reliability + security gates are green (see
[`loop.md`](loop.md)).

**Current milestone:** M1 — EVM RPC + Wallet ([spec](specs/01-evm-rpc-and-wallet.md))

| Field | Meaning |
|---|---|
| id | `M<milestone>-T<n>` |
| owner | the agent responsible |
| accepts | acceptance criteria (the bar for Done) |

---

## 🔜 Backlog (M1)

- **M1-T1 · architect** — Finalize the M1 spec from the seed: exact RPC method signatures, account
  model, and the deterministic balance function. *Accepts:* every M1 acceptance criterion maps to a
  testable statement; invariants from `specs/00-overview.md` referenced.
- **M1-T2 · protocol-engineer** — Runtime account model: `verified` flag + `verified_at`; emission of
  1 UBI/hr; pure `balance(account, t)` (integer/fixed-point, no floats). *Accepts:* unit + property
  tests show balance is an exact, reproducible function of state + timestamp.
- **M1-T3 · protocol-engineer** — EVM JSON-RPC server: `eth_chainId`, `eth_blockNumber`,
  `eth_getBalance`, `eth_call`, `eth_sendRawTransaction`, `eth_subscribe`/pubsub. *Accepts:* a standard
  EVM client (viem/ethers) gets correct responses; deviations documented.
- **M1-T4 · protocol-engineer** — Node binary + devnet: genesis, chain id, block/clock tick, one
  pre-verified dev account. *Accepts:* `cargo run` starts a node serving RPC on a documented port.
- **M1-T5 · interface-engineer** — TS SDK in `packages/sdk`: typed client + EVM provider glue over the
  RPC. *Accepts:* SDK reads chainId/blockNumber/balance against a running devnet; typecheck passes.
- **M1-T6 · interface-engineer** — Wallet/explorer in `apps/wallet`: add-network, **live-ticking**
  streaming balance, block/tx views. *Accepts:* `pnpm build` passes; balance visibly climbs; verified
  in-browser with a screenshot.
- **M1-T7 · qa-engineer** — E2E RPC-contract suite + unit/property tests for balance math.
  *Accepts:* every M1 criterion has a passing test; report in `docs/reports/`.
- **M1-T8 · reliability-engineer** — Determinism + balance-reproducibility property/soak tests across
  random timelines and a node restart. *Accepts:* two nodes agree to the wei; no nondeterminism found.
- **M1-T9 · security-engineer** — Threat model + audit: tx/signature validation, replay, RPC DoS,
  integer overflow in balance math. *Accepts:* no open high/critical; report in `docs/reports/`.
- **M1-T10 · release-engineer** — One-command devnet launch script + CI running build and the three
  gates. *Accepts:* clean checkout → one command → running devnet; CI green.

## 🏗️ In Progress
_(none yet — run cycle 1)_

## 👀 Review (awaiting gates)
_(none)_

## ⛔ Blocked
_(none)_

## ✅ Done
- **M0 · all** — Monorepo + 10-agent loop + seeded specs/roadmap/board scaffolded. *(bootstrap commit)*
