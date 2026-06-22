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

## M4 — Prompt Contracts 🚧 *(current)*
**Goal:** natural-language contracts parsed into canonical effects and committed by interpreter quorum,
with deterministic abort on disagreement. **Exit:** a plain-language contract executes reproducibly
across nodes; a prompt-injection attempt fails closed. **Depends on:** M2, M3.

## M5 — Economics & Governance ⬜
**Goal:** demurrage + fee recycling live; minimal quadratic-delegation governance over bounded
parameters. **Exit:** demurrage and recycling demonstrated on devnet; a parameter change passes via
quadratic delegation. **Depends on:** M1–M4.

## M6 — Public testnet ⬜
**Goal:** a hardened, observable shared testnet with a faucet and docs. **Exit:** external users join,
get verified, receive streaming UBI, and transact via standard wallets. **Depends on:** all above.

---

### Backlog (not yet scheduled)
Full block explorer + chain indexer (browse all blocks/txs/accounts; needs node-side address index) ·
real-time "dripping" UX polish (accrual is already continuous — display/subscription level) ·
AI provider network & token-for-compute · progressive decentralization / parameter ossification ·
mobile wallet · cross-chain bridge · advanced stream composition (split/merge marketplaces).
