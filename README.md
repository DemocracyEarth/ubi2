# UBI

**A Universal Basic Income blockchain where humans are verified by AI and zero-knowledge cryptography,
contracts are written in plain language, and money flows as a continuous stream — verifiable from any
browser or phone.**

UBI is an EVM-compatible chain built around six ideas:

1. **AI proof-of-humanity** — you become a verified, unique human through social **vouching** adjudicated
   by a **quorum of AI verifier nodes** (liveness grading + sybil analysis + dispute resolution). No
   biometrics, no documents.
2. **ZK-passport proof-of-humanity** — an optional, additive upgrade path: a zero-knowledge proof over
   an ICAO-9303 NFC e-passport (Groth16/BN254, adapted from the OpenPassport/Self circuit) produces a
   **one-passport-one-human nullifier** and opaque **attribute commitments** (age, nationality, expiry —
   no PII on-chain). Completing either path yields full `Verified` status and the same 1 UBI/hour stream.
3. **Streaming UBI** — every verified human accrues **1 UBI per hour**, continuously. Streams extend
   account-to-account in real time, turning payments into flows.
4. **Prompt contracts** — smart contracts written in **natural language** and executed by a **quorum of
   AI interpreter nodes** that agree on the resulting effect, or abort. *Intent-as-law*, not code-as-law.
5. **EVM-compatible JSON-RPC** — standard wallets (MetaMask) add it as a custom network and read
   streaming balances, send txs, and sign contract/vouch/ZK-passport operations.
6. **Browser and mobile light nodes** — anyone can run a node in a browser tab or on their phone. The
   deterministic runtime compiles to WASM; a light client syncs blocks over a WebSocket gateway,
   re-executes every block, and checks the `state_root` byte-for-byte. A lying server is caught, not
   trusted. Phone + NFC + WASM = ZK-passport proof generated and submitted on-device.

> Status: M1–M4 shipped (EVM RPC, streaming, AI PoH, prompt contracts). M5 Stage A (P2P networking)
> shipped. M6 ZK-passport PoH and the browser/mobile light node are **Stage 1 shipped** (crates
> `zkpoh` and `runtime-wasm` in tree; `packages/light-client` in tree). The in-browser PWA and the
> real NFC passport-scan flow are upcoming stages. See [`docs/roadmap.md`](docs/roadmap.md).

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

## CLI (`ubi`)

`ubi` is the one discoverable binary for running and operating the chain — it replaces the env-var
sprawl and shell scripts. Every command has `--help`. The `ubi node` flags are ergonomic **sugar over
the `UBI2_*` env vars** the node already reads: a flag **overrides** the matching env var; an unset flag
leaves the env var as the documented fallback. Config resolution is unchanged, so the CLI adds no
consensus risk.

### Install

```bash
cargo install --path crates/cli    # installs `ubi` to ~/.cargo/bin (on your PATH)
ubi --help
```

`multi` re-invokes the `ubi` binary itself, so installing the CLI is all you need — no separate
`ubi2-node` on your PATH. Or run it straight from the workspace without installing (note the `--`
before the CLI's own args, and that a bare `ubi` name won't be found until you `cargo install`):

```bash
cargo run -q -p ubi2-cli --bin ubi -- --help          # or, after `cargo build`: ./target/debug/ubi --help
```

### `ubi node` — run a full node

```bash
ubi node --preset devnet          # plain single node (== ./scripts/devnet.sh)
ubi node --preset lightnode       # single node the browser light node accepts (pinned genesis + gateway)
ubi node --preset multi           # multi-node local network (== ./scripts/devnet-multi.sh)
ubi node --rpc 127.0.0.1:9000 --block-ms 1000     # bare (no preset), just flags/env
```

| Flag | Overrides | Meaning |
|---|---|---|
| `--preset <devnet\|lightnode\|multi>` | — | Canned config (see below). Flags still override preset values. |
| `--rpc <addr>` | `UBI2_RPC_ADDR` | JSON-RPC (HTTP+WS) listen address. Default `127.0.0.1:8545`. |
| `--sync-gateway <addr>` | `UBI2_SYNC_ADDR` | Enable the WebSocket sync gateway (browser light node). |
| `--genesis-time <unix>` | `UBI2_GENESIS_TIME` | Pinned genesis time (a shared value ⇒ matching genesis hashes). |
| `--proposer-key <hex32>` | `UBI2_PROPOSER_KEY` | PoA block-author signing key (32-byte hex). |
| `--block-ms <ms>` | `UBI2_BLOCK_MS` | Block interval. Default `2000`. |
| `--data-dir <path>` | `UBI2_DATA_DIR` | Chain snapshot + oracle config dir. Default `./.ubi2-devnet`. |
| `--p2p <addr>` | `UBI2_P2P_ADDR` | Enable libp2p on this listen multiaddr. |
| `-n, --nodes <N>` | — | (`multi` only) number of nodes to launch. Default `3`. |

**Presets:**

- **`devnet`** — plain single node: RPC `127.0.0.1:8545`, 2s blocks, wall-clock genesis, no proposer
  key, sync gateway off unless `--sync-gateway` is given. Identical to `./scripts/devnet.sh`.
- **`lightnode`** — the single node the browser light node accepts: pinned `genesis_time=1700000000`,
  Anvil acct #2 as the PoA proposer, RPC `127.0.0.1:8545`, sync gateway `127.0.0.1:8546`, 1s blocks,
  isolated data dir `.devnet-lightnode-data`. Reproduces the pinned genesis anchor
  `b24d054f…` / `state_root aa2c66cd…`.
- **`multi`** — one designated proposer (Anvil acct #1) + N-1 followers over libp2p, pinned genesis,
  full cross-bootstrap mesh (no mDNS — deterministic). The CLI launches the N processes itself and
  stops them all on Ctrl-C. Identical to `./scripts/devnet-multi.sh` (which now delegates here).

### `ubi genesis anchor` — print/verify the canonical genesis anchor

```bash
ubi genesis anchor --preset lightnode
# genesis_time : 1700000000
# genesis_hash : bc53563fa41f719abe0358f106b067e31915a6ed68d0656ba7443a36f01224e3
# state_root   : 2ceab410e36255e646826ae52093e4ed438700e4654104b2f79ae74a4f03fb98
# pin check    : OK (matches apps/light-node/src/config.ts PINNED_GENESIS_HASH/STATE_ROOT)
```

Recomputes the canonical devnet genesis from the SAME seeds the node applies (one shared function,
no duplicated seed list) and — for the pinned `lightnode` genesis — asserts equality with the constants
shipped in `apps/light-node/src/config.ts`, exiting non-zero on drift. Use it to regenerate or verify
that pin.

### `ubi keys` — the PUBLIC devnet accounts

Prints the standard Hardhat/Anvil test accounts the presets use (the dev account, the 3 jurors, and the
PoA proposers), with addresses, private keys, and roles. These are **public test keys** published in
every EVM dev toolkit — never use them for real value.

---

## The app (one on-ramp)

- **Wallet** — your streaming balance (ticks live), transfers, and real-time **streams** to other
  accounts (each stream mints two soulbound NFTs you can view in MetaMask).
- **Explorer** — search any address / tx hash / block; drill into blocks (all header fields + decoded
  txs) and transactions (decoded hub call, logs, the resulting effect/verdict, fee).
- **Identity** — proof-of-humanity: your status, vouches in/out, vouch for / challenge others, the
  pending-cases queue, and the jurors. The ZK-passport upgrade path (NFC scan + on-device proof
  generation) lands in Stage 3 of the light-node track.
- **Contracts** — write a contract in plain language (or start from a template), deploy it, fund its
  escrow, and invoke it; watch the AI quorum commit or abort the effect.

---

## Architecture

```
crates/runtime      Deterministic state: accounts, 1-UBI/hr emission, streams, the proof-of-humanity
                    lifecycle (social-vouching + AI-jury AND ZK-passport paths), prompt-contract
                    execution, and the shared AI-quorum tally. No floats in any consensus path;
                    balances are pure integer functions of (state, timestamp). Defines the
                    ZkPassportVerifier trait (no crypto deps in runtime itself).

crates/zkpoh        Pure, deterministic Groth16/BN254 SNARK verifier (Stage 1 shipped). Isolated
                    from runtime so the consensus core stays dependency-free. Implements the
                    ZkPassportVerifier trait with arkworks (ark-bn254 + ark-groth16, pinned);
                    compiles to WASM. Also holds the Pedersen attribute verifier, the MockZkVerifier
                    for CI, and a real-curve test-passport fixture path.

crates/runtime-wasm Thin wasm-bindgen wrapper over the untouched crates/runtime (Stage 1 shipped).
                    The only crate that may depend on wasm-bindgen. Exposes applyBlock / stateRoot /
                    balanceOf / serialize as a bytes/JSON API. Used by packages/light-client to run
                    the same deterministic kernel in a browser tab that full nodes run in Rust.

crates/rpc          EVM-compatible JSON-RPC (jsonrpsee, HTTP+WS) + the ubi_* read surface + the EXPL
                    indexer + the loopback-only oracle-admin RPC. Decodes the three system hubs.
                    Hosts the WebSocket sync gateway that serves blocks to light clients.

crates/oracle       The AI layer: HumanityOracle + ContractInterpreter, with a configurable backend
                    (Anthropic / Ollama / OpenAI-compatible) producing canonical structured outputs at
                    temperature 0, behind injection-fenced prompts. A deterministic MockOracle for tests.

crates/network      P2P networking (M5): libp2p transport, block gossip, the ubi2/sync/1 wire protocol.
                    The WireBlock format the light client re-executes is defined here.

crates/node         The devnet node binary: genesis, block production (2s tick), seeded jurors, wires
                    the real ZkPassportVerifier from crates/zkpoh.

packages/sdk        TypeScript client: EVM JSON-RPC + ubi_* readers + viem encoders for stream / vouch /
                    contract operations. No WASM dependency.

packages/light-client  TypeScript light-client (Stage 1 shipped): WebSocket sync driver, WASM glue for
                    crates/runtime-wasm, IndexedDB store, EIP-1193 signer, verifyMode control. Separate
                    from packages/sdk so non-light-node consumers do not pull the WASM artifact.

apps/wallet         The Next.js app (wallet + explorer + identity + contracts + settings).

docs/               WHITEPAPER, the roadmap, the dev loop, the task board, specs (+ ADRs), gate reports.
```

**System hubs** (reserved addresses; operations are EIP-155 txs to them, so MetaMask signs them):

| Hub | Address | Operations |
|---|---|---|
| StreamHub | `0x…5742` | `openStream` / `stopStream` (+ ERC-721 stream NFTs) |
| HumanityHub | `0x…5048` | `requestVerification` / `vouch` / `challenge` / `submitVerdict` / `submitZkPassportProof` |
| ContractHub | `0x…5043` | `deployContract` / `fundContract` / `invokeContract` / `submitEffect` |
| Treasury | `0x…5542` | collects UBI gas fees (the basis for fee-recycling) |

**Fees:** every tx pays a small gas fee in **UBI** (`gas_used × 1 gwei`) to the treasury; onboarding
(`requestVerification`) is fee-exempt. A tx whose op fails is mined with a `status 0` receipt + reason
(it never silently hangs).

**The AI-quorum invariant:** AI is non-deterministic, but consensus must be reproducible. So every AI
verdict or contract effect in the consensus path is produced by an **independent quorum** running a
pinned model at temperature 0 with a **canonical structured output**, and is committed only when a
supermajority agree — otherwise it **aborts deterministically**.

**The ZK-PoH invariant:** ZK verification is pure deterministic cryptography — no AI in the verify
path at all. Every honest node re-runs the Groth16 pairing check and gets the same boolean. A tampered
or patched verifier produces a different `state_root` and is out-voted by the honest majority; the chain
advances only on the value the honest nodes agree on. See [`docs/specs/00-overview.md`](docs/specs/00-overview.md).

**The light-node trust model:** the WASM light client re-executes every block and checks the
`state_root` byte-for-byte before updating any balance. A gateway that serves a forged block is caught
immediately; it cannot make the light node display a wrong balance. See
[`docs/specs/07-browser-light-node.md`](docs/specs/07-browser-light-node.md).

---

## Light-node quick check

The `crates/runtime-wasm` crate and `packages/light-client` are in tree. To verify the WASM kernel
produces byte-identical state roots to the server follower (the AC-WB parity gate):

```bash
cargo test -p ubi2-runtime-wasm --test parity --no-default-features
```

The ZK-passport verifier (real Groth16 curve, test-passport fixture):

```bash
cargo test -p ubi2-zkpoh
```

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
