# ubi2 Task Board

The live work queue, maintained by the `orchestrator`. Tasks move between sections; history is not
deleted. A task is **Done** only when QA + reliability + security gates are green (see
[`loop.md`](loop.md)).

**Current milestone:** M4 — Prompt Contracts · **M1 + M2 + M3 shipped (cycles 1–3) ✅**

| Field | Meaning |
|---|---|
| id | `M<milestone>-T<n>` |
| owner | the agent responsible |
| accepts | acceptance criteria (the bar for Done) |

---

## 🔜 Backlog

**M4 — Prompt Contracts** ([spec](specs/04-prompt-contracts.md)) — NL contracts, AI interpreter quorum (reuses M3)
- **M4-T5 · interface-engineer** — Consolidate the app into the **UBI on-ramp**: wallet + **full block explorer**
  (all blocks/txs/accounts, search, per-account history) + **social/PoH hub** (status, vouches in/out,
  vouch/challenge, pending cases, jurors) + **contracts** (author/deploy/fund/invoke). *Accepts:* full flow against devnet; builds green.
- **M4-T6 · qa-engineer** — Tests for the 6 M4 acceptance criteria (MockInterpreter). *Accepts:* each → passing test.
- **M4-T7 · reliability-engineer** — Interpreter-quorum determinism + effect-application reproducibility + abort-on-split. *Accepts:* two nodes agree.
- **M4-T8 · security-engineer** — Threat model + pentest: over-authority/escrow drain, interpreter prompt-injection,
  quorum/abort integrity, replay, privacy. *Accepts:* no open High/Critical.
- **M4-T9 · release-engineer** — CI + demo contract. *(likely inline)*

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
- **FU-7 · ai/protocol** — Juror daemon for the REAL oracle on the consensus path: the node ships the
  deterministic `MockOracle`; `ClaudeOracle` exists + is fixture-tested but isn't wired into consensus
  (by design — the correct end-state is off-chain juror processes that call Claude and submit signed
  `submitVerdict` txs, not the node grading inline). Build the juror daemon (`ANTHROPIC_API_KEY`).
- **FU-8 · protocol/security (M5)** — Juror staking + rotation (M3 security Finding C, the fixed non-rotatable
  3-juror quorum) and the re-gate's LOW (system-scan cooldown can't auto-re-file under a fooled jury).
  *Source:* `docs/reports/security-m3.md`.

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
- **M4-T6/T7/T8 · qa / reliability / security** — Running the three Definition-of-Done gates on the
  combined M4 diff (contract core + ContractHub RPC + indexer + interpreter + UBI app). *(cycle 4)*

## 👀 Review (awaiting gates)
- **M4-T2/T3/T4 · protocol / ai** — M4 core, **orchestrator-verified** (217 cargo tests, fmt + clippy clean):
  - **T2 runtime**: canonical **effect language** + escrow/least-authority **atomic apply**, `PromptContract`/`ExecCase`,
    generalized `quorum_tally` (shared with M3), `ContractInterpreter` trait + `MockInterpreter`, derived contract-escrow addresses.
  - **T4 RPC/node**: `ContractHub` (`0x…5043`) txs (`deployContract`/`fundContract`/`invokeContract`/`submitEffect`) +
    `ubi_getContract`/`getExecCase`/`getContractsOf` + **EXPL-1 address indexer** (`ubi_getAddressActivity`/`getAccount`); `m4_acceptance` drives invoke→commit over the wire.
  - **T3 oracle**: `ClaudeInterpreter` (structured-output effect schema, temp-0, injection-fenced; `ANTHROPIC_API_KEY`-gated, fixture-tested).
  - **T5 app**: the consolidated **UBI app** — nav + Wallet · Explorer (search/account/activity via the indexer) · Identity (social/PoH hub) · Contracts (author→deploy→fund→invoke); SDK `contracts.ts` + `explorer.ts`. Builds + typecheck green; live deploy→fund→invoke→Committed verified.

## ⛔ Blocked
_(none)_

## ✅ Done
- **M4-T1 · architect** — M4 prompt-contracts spec: NL contracts → canonical **effect language** executed by an
  **interpreter quorum** (reuses M3), escrow/least-authority (I6), deterministic abort (I1/I4), `ContractHub`,
  the app-consolidation (explorer + social hub), 6 acceptance criteria. *(cycle 4 — [spec](specs/04-prompt-contracts.md))*
- **M3 — AI Proof-of-Humanity · SHIPPED (cycle 3).** All gates green. ([spec](specs/03-proof-of-humanity.md))
  - **M3-T1 · architect** — Spec: social vouching + AI-jury quorum, on-chain lifecycle, `HumanityOracle` trait + determinism (I1), privacy (I6), 8 acceptance criteria.
  - **M3-T2 · protocol-engineer** — On-chain substrate: `Human`/`Vouch`/`Case`/`Juror` registries, deterministic lifecycle state machine, quorum tally, vouch graph, `Verified` emission gating, `MockOracle`.
  - **M3-T3 · ai-engineer** — `crates/oracle` `ClaudeOracle`: real `HumanityOracle` via the Anthropic API (forced structured output, temp-0, injection-resistant); `ANTHROPIC_API_KEY`-gated, fixture-tested (I5).
  - **M3-T4 · protocol-engineer** — `HumanityHub` (`0x…5048`) txs + `ubi_*` reads + block-time lifecycle + auto-finalize + sybil sweep + receipt logs + seeded jurors. Orchestrator-verified live (verify→stream, sybil→revoke).
  - **M3-T5 · interface-engineer** — Wallet "Proof of Humanity" card (status/vouches/apply/vouch/challenge/pending cases) + SDK helpers. Builds + typecheck green.
  - **M3-T6 · qa** — ✅ 8/8 acceptance criteria → tests. **M3-T7 · reliability** — ✅ I1/I2 determinism over 10k–50k-iter property tests. **M3-T8 · security** — ✅ PASS after fixing a HIGH challenge-spam DoS (Finding A) + Findings B/F-REL-1/F-REL-2/D. Reports in [`docs/reports/`](reports/).
  - **M3-T9 · release** — CI covers the oracle crate; node ships deterministic `MockOracle` (see FU-7). *(inline)*
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
