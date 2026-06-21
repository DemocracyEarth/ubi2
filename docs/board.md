# ubi2 Task Board

The live work queue, maintained by the `orchestrator`. Tasks move between sections; history is not
deleted. A task is **Done** only when QA + reliability + security gates are green (see
[`loop.md`](loop.md)).

**Current milestone:** M3 — AI Proof-of-Humanity · **M1 + M2 shipped (cycles 1–2) ✅**

| Field | Meaning |
|---|---|
| id | `M<milestone>-T<n>` |
| owner | the agent responsible |
| accepts | acceptance criteria (the bar for Done) |

---

## 🔜 Backlog

**M3 — AI Proof-of-Humanity** (next cycle; needs architect spec first)
- **M3-T1 · architect** — Spec the LLM proof-of-humanity gate + verifier quorum: challenge/grade flow,
  sybil signals, the deterministic-quorum verdict (I1), safe degradation (I4), and how `verified` stops
  being a genesis flag and becomes earned. *Accepts:* testable acceptance criteria + invariants.

**Follow-ups carried from the gates — address before they bite**
- **FU-1 · protocol/security** — Mempool/registry hardening before any multi-node / non-localhost deploy:
  per-sender pending-balance accounting (M1 F1 + **M2-F2**, extend to stream deposits) + global/per-sender
  mempool caps (M1 F2) + **stream-registry caps (M2-F1)**. *Source:* security-m1/m2 reports. *Not a blocker (localhost).*
- **FU-2 · protocol/architect** — Decide the emission-rounding policy (carry remainder vs. document
  bounded loss) before M5 raises settlement frequency. *Source:* [ADR-0002](specs/adr/0002-emission-rounding-policy.md).
- **FU-3 · protocol** — State persistence/checkpoint behind the existing `State` trait (M1/M2 are in-memory).
- **FU-4 · reliability** — Two-node soak once consensus (M3 quorum) exists; metrics/observability.
- **FU-5 · protocol** — Stream-tx hygiene: reject non-zero `value` on StreamHub ops (M2-F3) and optionally
  reject `openStream` to `0x0` (M2-F4). *Source:* `docs/reports/security-m2.md`. *Low/Info, non-blocking.*
- **FU-6 · protocol/interface** — Stream-rate display precision: a "1 UBI/hr" stream flows at
  ⌊1e18/3600⌋/sec ≈ 0.99999…/hr ([ADR-0003](specs/adr/0003-streaming-and-stream-nfts.md)); decide card
  rounding + a finer `rate` granularity. *Source:* M2-T4 note. (TS test runner for the SDK/wallet too.)

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
_(none — cycle 2 closed)_

## 👀 Review (awaiting gates)
_(none)_

## ⛔ Blocked
_(none)_

## ✅ Done
- **M2 — Streaming primitive · SHIPPED (cycle 2).** All gates green. ([spec](specs/02-streaming.md), [ADR-0003](specs/adr/0003-streaming-and-stream-nfts.md))
  - **M2-T1 · architect** — Spec: collateralized 1:1 streams, StreamHub system-address txs (EVM-signable), live net-stream balances (I2), open/stop/refund, **two ERC-721 stream NFTs** with on-chain SVG card.
  - **M2-T2/T3 · protocol-engineer** — Stream runtime + StreamHub RPC (tx parsing, `ubi_getStream(s)`) + ERC-721 precompile (`ownerOf`/`tokenURI`/…) minting recipient + sender NFTs with the on-chain card. Orchestrator-verified live.
  - **M2-T4 · interface-engineer** — SDK stream helpers (viem) + wallet "Send a stream" + Active streams (live tick, Stop) + NFT card render + "Add NFT to MetaMask". Builds + typecheck green.
  - **M2-T5 · qa-engineer** — ✅ PASS: 8/8 acceptance criteria → tests; 55 cargo tests. `docs/reports/qa-m2.md`.
  - **M2-T6 · reliability-engineer** — ✅ PASS: stream-balance determinism + solvency (200k iters) + bounded conservation + `tokenURI` byte-identical (40k). `docs/reports/reliability-m2.md`.
  - **M2-T7 · security-engineer** — ✅ PASS: no High/Critical; solvency/deposit/soulbound/replay integrity held under pentest. 2 Medium → FU-1, 2 Low/Info → FU-5. `docs/reports/security-m2.md`.
  - **M2-T8 · release-engineer** — `clientVersion`→m2, `t_end` saturating fix (F2). CI green. *(inline)*
- **M0 · all** — Monorepo + 10-agent loop + seeded specs/roadmap/board scaffolded. *(bootstrap commit)*
- **M1 — EVM RPC + Wallet · SHIPPED (cycle 1).** All gates green.
  - **M1-T1 · architect** — Spec finalized (emission arithmetic, `State`/`Verifier` traits, chainId `0x5542`, EIP-155 txs, 2s tick).
  - **M1-T2/T3/T4 · protocol-engineer** — Rust node + EVM JSON-RPC (HTTP+WS) + devnet; streaming `eth_getBalance`, EIP-155 `eth_sendRawTransaction`, block tick. Orchestrator-verified live.
  - **M1-T5/T6 · interface-engineer** — TS SDK + Next.js wallet/explorer; balance ticks up via rAF interpolation; "Add to MetaMask" card. Both builds green.
  - **M1-T7 · qa-engineer** — ✅ PASS: all 5 acceptance criteria → passing tests; 28 cargo tests + E2E script. `docs/reports/qa-m1.md`.
  - **M1-T8 · reliability-engineer** — ✅ PASS: I2 determinism proven (50k random timelines); no nondeterminism. `docs/reports/reliability-m1.md`.
  - **M1-T9 · security-engineer** — ✅ PASS: no open High/Critical; signature/replay + balance integrity held under pentest. 2 Medium hardening follow-ups (→ FU-1). `docs/reports/security-m1.md`.
  - **M1-T10 · release-engineer** — `rust-toolchain.toml` pin, `scripts/devnet.sh`, `.github/workflows/ci.yml`. *(done inline by orchestrator)*
