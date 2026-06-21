# ubi2

**A Universal Basic Income blockchain where humans are verified by AI, contracts are written
in plain language, and money flows as a continuous stream.**

ubi2 is the next iteration of Democracy Earth's UBI stack ([ubi.chain](../ubi.chain),
[ubi.agent](../ubi.agent), [ubi.wallet](../ubi.wallet)) — consolidated into one monorepo and
rebuilt around four ideas:

1. **AI Proof-of-Humanity** — generative AI / LLMs verify that each node receiving UBI is a real,
   unique human, replacing brittle biometric or document checks.
2. **Prompt Contracts** — smart contracts are written in **natural language** and executed by nodes
   that parse intent with LLMs and reach **consensus on the outcome**. *Intent-as-law*, not code-as-law.
3. **Streaming UBI** — every verified human receives **1 UBI per hour**, continuously. Streams can be
   extended account-to-account in real time, turning payments into flows.
4. **EVM-compatible RPC** — a JSON-RPC surface that standard EVM wallets (e.g. MetaMask) can read,
   so the network meets users where they already are.

> Status: **bootstrapping.** This repo currently contains the development *process* (an agent loop)
> and the project skeleton. The protocol and apps are built milestone-by-milestone by that loop —
> see [`docs/roadmap.md`](docs/roadmap.md).

## How this project is built — the agent loop

ubi2 is developed by a team of ten specialized [Claude Code subagents](.claude/agents/) that run an
explicit development loop: **product → spec → plan → build → test → reliability → security → release →
feedback**. Each role, the cycle, and how to run it are documented in [`AGENTS.md`](AGENTS.md) and
[`docs/loop.md`](docs/loop.md). The live work queue is [`docs/board.md`](docs/board.md).

## Repository layout

```
.claude/agents/   The 10-agent development team (orchestrator, architect, engineers, qa, security…)
docs/             Roadmap, the development loop, the task board, and specs (+ ADRs)
crates/           Rust workspace — the node, runtime, and EVM JSON-RPC (the chain)
apps/wallet/      Next.js wallet + block explorer
packages/sdk/     TypeScript client / EVM provider glue
WHITEPAPER.md     The canonical vision & protocol design
```

## Quickstart (developers)

```bash
# Build the chain (Rust workspace)
cargo build

# Run the wallet/explorer (Next.js)
cd apps/wallet && pnpm install && pnpm dev
```

Prerequisites: Rust + Cargo (stable), Node ≥ 20, pnpm. The chain skeleton compiles today; features
land per milestone.

## Current milestone — M1: EVM RPC + Wallet

Stand up a devnet node that exposes an **EVM-compatible JSON-RPC** MetaMask can add as a custom
network, where a verified account's balance **visibly streams upward at 1 UBI/hour**, plus a wallet
+ explorer to see it. Full spec: [`docs/specs/01-evm-rpc-and-wallet.md`](docs/specs/01-evm-rpc-and-wallet.md).

## License

MIT © 2026 Democracy Earth Foundation
