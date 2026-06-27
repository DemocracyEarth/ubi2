# ubi2 Roadmap

Owned by the `product-strategist`. Milestones are sequenced to retire the riskiest assumptions with the
smallest demoable step. Each must be demonstrable end-to-end.

Legend: ✅ done · 🚧 in progress · ⬜ planned

---

## M0 — Bootstrap ✅
**Goal:** a consolidated monorepo, the agent development loop, and seeded specs so the loop can run.
**Exit criteria:** team of 10 agents in place; `cargo build` green on the skeleton; wallet skeleton
builds; roadmap/board/specs seeded. **Why now:** nothing else can proceed without a process and a home.

## M1 — EVM RPC + Wallet ✅ *(shipped cycle 1)*
**Goal:** a devnet node exposing an **EVM-compatible JSON-RPC** that MetaMask can add as a custom
network, where a **verified account's balance streams upward at 1 UBI/hour**, plus a wallet + explorer.
**Why now:** a readable, standards-compatible chain is the integration surface that unblocks every
later feature; it also forces the deterministic time-based balance model early.
**Exit criteria:**
- MetaMask adds the devnet RPC and reads a verified account's balance climbing at 1 UBI/hr.
- Explorer renders blocks and transactions.
- E2E test asserts the RPC contract (`eth_chainId`, `eth_blockNumber`, `eth_getBalance`, `eth_call`,
  `eth_sendRawTransaction`, `eth_subscribe`).
**Spec:** [`specs/01-evm-rpc-and-wallet.md`](specs/01-evm-rpc-and-wallet.md)

## M2 — Streaming primitive ✅ *(shipped cycle 2)*
Delivered: collateralized 1:1 streams via StreamHub system-address txs (MetaMask-signable), live
net-stream balances, open/stop/refund, and **two ERC-721 stream NFTs per stream** (recipient + sender)
with a fully on-chain SVG card. 1:many fan-out, uncollateralized stream-through, and transferable streams
remain deferred. Spec [`02-streaming.md`](specs/02-streaming.md), [ADR-0003](specs/adr/0003-streaming-and-stream-nfts.md).
Original goal text:
**Goal:** account-to-account real-time streams (1:1, then 1:many) on top of the UBI drip, with the
safety controls (rate limits, collateralization, circuit breakers). **Exit:** a user opens a stream to
another account and both balances move in real time; safety limits demonstrated. **Depends on:** M1.

## M3 — AI Proof-of-Humanity ✅ *(shipped cycle 3)*
**Goal:** the LLM-based verification gate with a verifier quorum; only verified humans begin accruing
UBI. **Exit:** a human passes verification by quorum and starts streaming; a bot/duplicate is rejected;
verdict integrity holds against a hostile minority of verifiers. **Depends on:** M1. **Shipped:** social
vouching + AI-jury quorum (`HumanityHub`), deterministic on-chain lifecycle, real `ClaudeOracle`
(`ANTHROPIC_API_KEY`-gated) + `MockOracle` for the devnet, AI sybil auto-challenge, hardened against a
challenge-spam DoS. All gates green. Follow-ups: FU-7 (juror daemon for the real oracle on consensus),
FU-8 (M5 juror staking/rotation).

## M4 — Prompt Contracts ✅ *(shipped cycle 4)*
**Goal:** natural-language contracts parsed into canonical effects and committed by interpreter quorum,
with deterministic abort on disagreement. **Exit:** a plain-language contract executes reproducibly
across nodes; a prompt-injection attempt fails closed. **Depends on:** M2, M3. **Shipped:** a bounded
canonical **effect language** + escrow/least-authority **atomic apply** (I4/I6), an **interpreter quorum**
reusing the M3 tally (`ContractHub`), the `ClaudeInterpreter` (+ `MockInterpreter` for the devnet), and the
consolidated **UBI app** (wallet + block explorer + social/PoH hub + contracts). All gates green; injection
fails closed. Follow-ups: FU-9 (stranded-funds desync, before mainnet), FU-10/FU-11.

## M5 — Network & Consensus 🚧 *(current)*
**Goal:** multiple independent node processes form a real peer-to-peer network that gossips transactions
and blocks, agrees on block production via distributed consensus, syncs state when a node joins, and
keeps producing blocks when a node goes down. The AI proof-of-humanity and prompt-contract quorums are
evaluated by independent AI backends on independent nodes — not simulated in one process.

**Why now:** the chain is currently a single-node devnet. One process produces all blocks and runs all
AI quorum calls in-process. Every milestone from M6 onward — economic parameters, fee recycling,
governance, AI-provider rewards, public testnet — depends on a real multi-node network to be meaningful.
FU-15 (node-AI rewards) and the fee-recycling economics (M6) cannot be correctly specified until the AI
quorum they reward is a real multi-process quorum. This is the project's largest unretired engineering
risk and highest-leverage next step.

**Exit criteria (summary; full detail in [`milestones/m5-p2p-network.md`](milestones/m5-p2p-network.md)):**
- Three independent `ubi2-node` processes connect and report each other as peers.
- A tx submitted to node A is gossiped to nodes B and C before the next block.
- All three nodes agree on block height and state root within one block interval.
- After 20 blocks with transactions, all three nodes report byte-identical state roots.
- Block production rotates across at least 2 of 3 nodes over 30 blocks.
- Killing the current proposer does not halt the chain; the remaining nodes elect a successor.
- A late-joining node syncs from genesis to the tip without manual intervention and reaches identical
  state.
- A PoH verification quorum is evaluated by independent AI backends on independent nodes and commits
  on supermajority (with `MockOracle` in CI).
- A prompt-contract invocation is evaluated by independent AI backends on independent nodes; agreement
  commits, injected disagreement aborts deterministically.
- `eth_getBalance` at the same block height returns the same integer on all nodes (I2); state roots
  agree byte-for-byte (I1).

**Staged delivery:**
- **Stage A** — networking transport + block sync (one proposer, N followers): tx gossip, block broadcast,
  join-sync, `ubi_getPeers`. Closes FU-3 (persistence), FU-13.
- **Stage B** — distributed block production: rotating proposer, fork choice, proposer timeout + view
  change (crash-fault tolerant; BFT is backlog). Closes FU-8 (juror staking/rotation).
- **Stage C** — real cross-node AI quorum: `crates/juror` daemon on each node runs its own AI backend
  and submits signed verdict/effect txs independently. Closes FU-7.
- **Stage D** — hardening + multi-host testnet: soak, partition tests, observability (FU-4), mempool
  hardening (FU-1), oracle-URL SSRF fix (FU-12), public testnet with faucet and docs.

**Depends on:** M1–M4 (all shipped). FU-3 and FU-13 are prerequisites for Stage A.
**Milestone brief:** [`milestones/m5-p2p-network.md`](milestones/m5-p2p-network.md)

## M6 — Economics & Governance ⬜
**Goal:** demurrage + fee recycling live on a real multi-node chain; node-AI rewards split contract-invoke
and verification fees to the actual quorum nodes that did the AI work (FU-15); minimal
quadratic-delegation governance over bounded parameters.

**Why after M5:** fee-splitting to the AI quorum is undesignable until the quorum is a real set of
independent nodes. Economic parameters governing multi-node fee flow must be stress-tested against
actual multi-node behavior, not a single-process simulation. Governance over network parameters is
meaningful only when those parameters govern a real network.

**Exit criteria:** demurrage and fee recycling demonstrated on the M5 multi-node devnet; fee-split to
quorum nodes visible on-chain; a parameter change passes via quadratic delegation. **Depends on:** M5.

## M7 — Public Testnet ⬜
**Goal:** a hardened, observable shared testnet with a faucet and docs. **Exit:** external users join,
get verified, receive streaming UBI, and transact via standard wallets. **Depends on:** M5 Stage D
(which targets the multi-host testnet), M6.

---

### Sequencing rationale (M5 before M6)

The previous roadmap had Economics & Governance as M5. This document moves it to M6 for three reasons:

1. **FU-15 (node-AI rewards)** — the primary economic novelty in M6 is rewarding the AI nodes that
   perform quorum work. There is nothing to reward until Stage C of M5 exists: independent nodes with
   independent AI backends. Writing reward-split logic for a quorum that runs in one process is a
   placeholder, not a feature.

2. **Economic parameter validity** — demurrage decay rates and fee-recycling ratios should be calibrated
   against observed multi-node fee flow. Setting them on a single-node chain and then changing them
   after M5 introduces a needless spec churn cycle.

3. **Risk ordering** — I1 (deterministic quorum across independent processes) is the hardest unproven
   invariant. It is safer to prove it before layering economic incentives on top of it.

---

### Backlog (not yet scheduled)
BFT (Byzantine fault tolerance, active-adversary consensus) · full block explorer + chain indexer ·
real-time "dripping" UX polish · AI provider network token-for-compute marketplace · progressive
decentralization / parameter ossification · mobile wallet · cross-chain bridge · advanced stream
composition (split/merge/marketplace) · DHT peer discovery · validator staking and slashing.
