---
name: run-and-build-a-ubi-node
description: >
  Stand up, operate, and extend a UBI blockchain node — an EVM-compatible chain with AI proof-of-humanity,
  streaming UBI, and natural-language prompt contracts. Use when the task is to run the devnet, add or
  modify a chain feature (runtime/RPC/AI/wallet), plug in an LLM backend, or implement a node from this repo.
---

# Run & build a UBI node

This is the operating manual for an agent working on a UBI node. Read it before touching the chain.

## What a node is
A single Rust binary (`crates/node`) that produces blocks (2s tick) and serves an **EVM-compatible
JSON-RPC** on `127.0.0.1:8545`. Its determinism is the whole game: balances are pure integer functions of
`(state, timestamp)`, and every AI decision in the consensus path is committed only by a **quorum** of
nodes producing the **same canonical structured output**, else it aborts. Never introduce floats,
`HashMap`-iteration order, wall-clock reads, or un-pinned model calls into a consensus path.

## Build & run
```bash
cargo build --release -p ubi2-node      # or: ./scripts/devnet.sh  (builds + runs)
./target/release/ubi2-node              # serves http://127.0.0.1:8545 (HTTP+WS)
# env: UBI2_RPC_ADDR (default 127.0.0.1:8545), UBI2_BLOCK_MS (default 2000), RUST_LOG
```
Genesis seeds one pre-verified dev account (public Hardhat key `0xf39F…2266`) streaming 1 UBI/hr, and
three jurors. The app: `pnpm install && pnpm --filter @ubi2/wallet dev` → `http://localhost:3000`.

## Layout & where things live
- `crates/runtime` — state + transitions. `lib.rs` (accounts, emission, fees, transfers, `State` trait +
  `MemState`), `humanity.rs` (PoH types, oracle trait, `quorum_tally`), `lifecycle.rs` (PoH state machine),
  `contracts.rs` (effect language, escrow apply, `ContractInterpreter`). **Dependency-free** — keep crypto/keccak out of it.
- `crates/rpc` — `lib.rs` (jsonrpsee server, mempool, `produce_block`, EVM + `ubi_*` methods, the indexer),
  `streams.rs` / `humanity.rs` / `contracts.rs` (hub ABI + decode), `oracle_admin.rs` (loopback admin RPC).
- `crates/oracle` — `backend.rs` (Anthropic/Ollama/OpenAI), `client.rs`, `url_policy.rs` (SSRF guard),
  prompt/schema modules. Live calls are gated; tests use recorded fixtures.
- `crates/node` — `main.rs` (genesis, block loop via `spawn_blocking`), `oracle_cfg.rs`.
- `packages/sdk` (TS client + encoders), `apps/wallet` (Next.js app), `docs/` (specs, board, reports).

## RPC surface
- **EVM (for wallets):** `eth_chainId` (`0x5542`/21826), `eth_blockNumber`, `eth_getBalance` (live streaming
  balance), `eth_getTransactionCount`, `eth_gasPrice`/`eth_estimateGas`/`eth_feeHistory` (UBI fees),
  `eth_call`, `eth_sendRawTransaction`, `eth_getTransactionByHash`/`Receipt` (failed txs return `status 0x0`
  + `revertReason`), `eth_getBlockBy*`, `eth_subscribe(newHeads)`.
- **`ubi_*` reads:** `getHuman` / `getCase` / `getVouches` / `getJurors` / `getPendingCases`;
  `getContract` (full: text, parties, escrow, deploy_block/tx, cases) / `getExecCase` / `getContractsOf`;
  `getStream(s)`; `getBlock` / `getTransaction` (decoded calls/logs/result/fee); `getAccount` /
  `getAddressActivity` (indexer); `getOracleConfig` / `setOracleConfig` (**loopback + Origin-allowlisted only**).

## System hubs (operations are EIP-155 txs to these addresses)
- StreamHub `0x…5742`: `openStream(address,uint256,uint256)`, `stopStream(uint256)`; ERC-721 views via `eth_call`.
- HumanityHub `0x…5048`: `requestVerification(bytes32)` (fee-exempt), `vouch(address)`, `challenge(address,bytes32)`, `submitVerdict(uint256,uint8,uint8)`.
- ContractHub `0x…5043`: `deployContract(string,address[])`, `fundContract(uint256)`, `invokeContract(uint256,bytes32)`, `submitEffect(uint256,bytes)`.
- Treasury `0x…5542`: collects fees. To add a hub op: add the `sol!` signature, decode in the hub module,
  queue a `PendingKind`, apply in `produce_block`, emit a receipt log, and expose a `ubi_*` read.

## Invariants (do not break — they are gated)
- **I1** deterministic quorum: pinned model + temp 0 + canonical output; commit only on supermajority; else abort.
- **I2** reproducible integer balances/fees across nodes, to the base unit.
- **I4** fail-closed: on error/ambiguity, abort with no partial state; a failed tx is **mined** (status 0 +
  reason + nonce consumed), never silently dropped.
- **I6** least authority + privacy: a contract moves only its own escrow; only commitments/verdicts/effects
  on-chain (no PII); untrusted text/evidence is fenced from the model; secrets never in logs/env/persisted config.

## Plug in an LLM backend
Implement (or configure) `HumanityOracle` + `ContractInterpreter` in `crates/oracle` for a provider. The
node selects one via `oracle_cfg.rs` / the `ubi_setOracleConfig` admin RPC (loopback-only). Force a
**closed structured output** (the canonical verdict/effect schema), temperature 0, untrusted-input
fencing, and validate any `base_url` (reject internal/metadata IPs; see `url_policy.rs`). Run live calls
off the async block loop (`spawn_blocking`). Keep the deterministic `MockOracle` working for CI.

## Working on the node (the loop)
Make a change → `cargo test --workspace` + `cargo fmt --all --check` + `cargo clippy --workspace
--all-targets -- -D warnings` + `pnpm -r build && pnpm -r typecheck` must all be green. For anything in the
consensus path, add property tests for determinism and run the security/reliability gates (see
`docs/loop.md`, `docs/reports/`). Commit checkpoints; never leave a consensus-path change un-gated.

## Common gotchas
- A stale `ubi2-node` holds `:8545` — `pkill -f ubi2-node` before restarting.
- After a devnet restart MetaMask caches old nonces/activity — clear its activity-tab data.
- The runtime crate is dependency-free; compute hashes (keccak) in the node/rpc layer and pass them in.
- The admin RPC is localhost-only by design; the wallet at `http://localhost:3000` is the allowed Origin.
