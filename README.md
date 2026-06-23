# UBI

**A Universal Basic Income blockchain where humans are verified by AI, contracts are written in plain
language, and money flows as a continuous stream.**

UBI is an EVM-compatible chain built around four ideas:

1. **AI proof-of-humanity** — you become a verified, unique human through social **vouching** adjudicated
   by a **quorum of AI verifier nodes** (liveness grading + sybil analysis + dispute resolution). No
   biometrics, no documents.
2. **Streaming UBI** — every verified human accrues **1 UBI per hour**, continuously. Streams extend
   account-to-account in real time, turning payments into flows.
3. **Prompt contracts** — smart contracts written in **natural language** and executed by a **quorum of
   AI interpreter nodes** that agree on the resulting effect, or abort. *Intent-as-law*, not code-as-law.
4. **EVM-compatible JSON-RPC** — standard wallets (MetaMask) add it as a custom network and read
   streaming balances, send txs, and sign contract/vouch operations.

> Status: a working single-node **devnet**. Milestones M1 (EVM RPC + wallet), M2 (streaming + stream
> NFTs), M3 (AI proof-of-humanity), and M4 (prompt contracts) are shipped, plus native UBI fees, a
> configurable LLM backend, and a deep block explorer. See [`docs/roadmap.md`](docs/roadmap.md).

---

## Quickstart

Prerequisites: **Rust** (the toolchain auto-pins via `rust-toolchain.toml`), **Node ≥ 20**, **pnpm**.
No API key is needed — the node defaults to a deterministic mock AI so the devnet always runs.

**Terminal 1 — the chain:**
```bash
pkill -f ubi2-node            # clear any stale node holding :8545
./scripts/devnet.sh          # builds + serves EVM JSON-RPC (HTTP+WS) on http://127.0.0.1:8545
```

**Terminal 2 — the app:**
```bash
pnpm install                 # once
pnpm --filter @ubi2/wallet dev   # → http://localhost:3000
```

**MetaMask (optional):** the app's "Add to MetaMask" button adds the network — name `UBI devnet`,
RPC `http://127.0.0.1:8545`, Chain ID `21826`, symbol `UBI`. Import the public devnet key
`0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80` to see a balance streaming at
1 UBI/hour and to sign transfers, vouches, and contracts.

**Use a real AI (optional):** open **Settings** in the app and point the node at a local model
(**Ollama** — run `ollama serve` and pull a model) or a cloud key (**Anthropic** / **OpenAI**-compatible).
Unconfigured, proof-of-humanity verdicts and contract interpretation use the deterministic mock.

---

## The app (one on-ramp)

- **Wallet** — your streaming balance (ticks live), transfers, and real-time **streams** to other
  accounts (each stream mints two soulbound NFTs you can view in MetaMask).
- **Explorer** — search any address / tx hash / block; drill into blocks (all header fields + decoded
  txs) and transactions (decoded hub call, logs, the resulting effect/verdict, fee).
- **Identity** — proof-of-humanity: your status, vouches in/out, vouch for / challenge others, the
  pending-cases queue, and the jurors.
- **Contracts** — write a contract in plain language (or start from a template), deploy it, fund its
  escrow, and invoke it; watch the AI quorum commit or abort the effect.

---

## Architecture

```
crates/runtime   Deterministic state: accounts, 1-UBI/hr emission, streams, the proof-of-humanity
                 lifecycle, prompt-contract execution, and the shared AI-quorum tally. No floats in
                 any consensus path; balances are pure integer functions of (state, timestamp).
crates/rpc       EVM-compatible JSON-RPC (jsonrpsee, HTTP+WS) + the ubi_* read surface + the EXPL
                 indexer + the loopback-only oracle-admin RPC. Decodes the three system hubs.
crates/oracle    The AI layer: HumanityOracle + ContractInterpreter, with a configurable backend
                 (Anthropic / Ollama / OpenAI-compatible) producing canonical structured outputs at
                 temperature 0, behind injection-fenced prompts. A deterministic MockOracle for tests.
crates/node      The devnet node binary: genesis, block production (2s tick), seeded jurors.
packages/sdk     TypeScript client: EVM JSON-RPC + ubi_* readers + viem encoders for stream / vouch /
                 contract operations.
apps/wallet      The Next.js app (wallet + explorer + identity + contracts + settings).
docs/            WHITEPAPER, the roadmap, the dev loop, the task board, specs (+ ADRs), gate reports.
```

**System hubs** (reserved addresses; operations are EIP-155 txs to them, so MetaMask signs them):

| Hub | Address | Operations |
|---|---|---|
| StreamHub | `0x…5742` | `openStream` / `stopStream` (+ ERC-721 stream NFTs) |
| HumanityHub | `0x…5048` | `requestVerification` / `vouch` / `challenge` / `submitVerdict` |
| ContractHub | `0x…5043` | `deployContract` / `fundContract` / `invokeContract` / `submitEffect` |
| Treasury | `0x…5542` | collects UBI gas fees (the basis for fee-recycling) |

**Fees:** every tx pays a small gas fee in **UBI** (`gas_used × 1 gwei`) to the treasury; onboarding
(`requestVerification`) is fee-exempt. A tx whose op fails is mined with a `status 0` receipt + reason
(it never silently hangs).

**The hard invariant:** AI is non-deterministic, but consensus must be reproducible. So every AI verdict
or contract effect in the consensus path is produced by an **independent quorum** running a pinned model
at temperature 0 with a **canonical structured output**, and is committed only when a supermajority
agree — otherwise it **aborts deterministically**. See [`docs/specs/00-overview.md`](docs/specs/00-overview.md).

---

## How it's built — the agent loop

UBI is developed by a team of specialized [Claude Code subagents](.claude/agents/) running an explicit
loop: **product → spec → build → test → reliability → security → release**, gated by a Definition-of-Done
(QA + reliability + security must be green). See [`AGENTS.md`](AGENTS.md), [`docs/loop.md`](docs/loop.md),
and the live board [`docs/board.md`](docs/board.md). To run or extend a node as an agent, see
[`SKILL.md`](SKILL.md).

## Verify
```bash
cargo test --workspace        # the full Rust suite
pnpm -r build                 # the SDK + wallet
```

## License
MIT © Democracy Earth Foundation. Built on the vision in [`WHITEPAPER.md`](WHITEPAPER.md).
