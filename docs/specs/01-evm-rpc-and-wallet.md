# 01 — Milestone 1: EVM RPC + Wallet

**Status:** seed (to be finalized by the `architect` as task M1-T1).
**Goal:** stand up a devnet node exposing an **EVM-compatible JSON-RPC** that MetaMask can add as a
custom network, where a **verified account's balance streams upward at 1 UBI/hour**, plus a wallet +
explorer to see it. This is the integration surface that unblocks every later milestone and forces the
deterministic time-based balance model (invariant I2) early.

## In scope
- A minimal deterministic runtime: accounts, a `verified` flag, and streaming emission.
- An EVM-compatible JSON-RPC server.
- A devnet node binary (single-node is fine for M1) with a clock/block tick.
- A TypeScript SDK and a Next.js wallet/explorer.

## Out of scope (later milestones)
Account-to-account streams (M2), real AI proof-of-humanity (M3 — here, verification is a dev/admin
toggle), prompt contracts (M4), demurrage/governance (M5). State persistence beyond a checkpoint is
optional for M1.

## Account & balance model
```
Account {
  address: H160,              // Ethereum-style 20-byte address
  verified: bool,
  verified_at: u64,           // unix seconds; 0 if unverified
  settled_balance: U256,      // in wei-equivalent base units of UBI
  last_settled_at: u64,       // unix seconds
}
```
- **Emission:** a verified account accrues **1 UBI/hour**. Define `UBI = 10^18` base units (wei-style),
  so the rate is `R = 10^18 / 3600` base units per second, applied with integer math (carry remainder;
  no floats — invariant I2).
- **Live balance:** `balance(a, t) = a.settled_balance + emission(a, t)` where
  `emission(a, t) = a.verified ? R_num * (t − max(a.verified_at, a.last_settled_at)) / R_den : 0`,
  computed in integers. Settlement on any state-changing tx folds emission into `settled_balance` and
  advances `last_settled_at`.
- `eth_getBalance(addr, "latest")` returns `balance(addr, now)` so wallets see the stream live.
  The wallet interpolates client-side between polls for a smooth tick.

## JSON-RPC surface (EVM-compatible)
Minimum methods for M1, matching Ethereum semantics (document any deviation inline):

| Method | Behavior |
|---|---|
| `eth_chainId` | returns the devnet chain id (hex). |
| `net_version` | decimal chain id. |
| `eth_blockNumber` | latest block height. |
| `eth_getBalance(addr, block)` | streaming balance at `block`/`latest` (see model). |
| `eth_getTransactionCount(addr, block)` | nonce. |
| `eth_gasPrice` / `eth_estimateGas` | minimal/stub values sufficient for wallets. |
| `eth_call(tx, block)` | read-only call execution. |
| `eth_sendRawTransaction(raw)` | accept a signed tx → settle + apply transfer. |
| `eth_getBlockByNumber` / `…ByHash` | block data for the explorer. |
| `eth_getTransactionByHash` / `…Receipt` | tx + receipt. |
| `eth_subscribe` / `eth_unsubscribe` | pubsub for `newHeads` (and balance polling fallback). |

Transactions are standard secp256k1-signed EVM transactions (so MetaMask can sign). Signature & replay
protection follow EIP-155; document any simplification.

## Devnet
- One node, configurable chain id (e.g. `0x5542 / 21826`), RPC on a documented port (e.g. `8545`).
- Genesis includes **one pre-verified dev account** so a balance is streaming from t=0 (stands in for M3).
- A clock/block tick advances height on a fixed interval.

## Wallet / explorer (`apps/wallet`)
- **Add network / connect:** instructions + one-click add of the devnet (chain id, RPC URL, symbol `UBI`).
- **Streaming balance view:** shows the connected account's balance **ticking up** in real time.
- **Explorer:** latest blocks and transactions, and an account view.
- Stack: Next 15 + React 19 + Tailwind (match prior `ubi.wallet`).

## Acceptance criteria (map 1:1 to tests — owned by qa/reliability)
1. A standard EVM client (viem/ethers) connects and gets correct `eth_chainId`, `eth_blockNumber`,
   `eth_getBalance`, `eth_getTransactionCount`.
2. **MetaMask** adds the devnet as a custom network and displays the pre-verified account's balance
   **increasing at 1 UBI/hour** (±tolerance for poll interval).
3. A signed transfer via `eth_sendRawTransaction` moves balance correctly, with emission settled at the
   moment of transfer (no UBI lost or double-counted across settlement).
4. The explorer renders blocks and a transaction.
5. **Reproducibility (I2):** `balance(a, t)` is identical across two node instances and across a restart,
   asserted by property tests over random `(verified_at, t)` timelines.

## M1-T1 — Finalized decisions (architect)
These lock the open questions so engineering can proceed; changes require an ADR.

1. **Emission arithmetic (I2).** `pending_emission = UBI * elapsed_secs / EMISSION_PERIOD_SECS` in `u128`
   with truncating division (remainder retained in the formula, not dropped from state). `UBI = 10^18`,
   `EMISSION_PERIOD_SECS = 3600`. Already implemented in `crates/runtime`. **No floats** anywhere in the
   balance path. Balance is `settled_balance + pending_emission(now)`; settlement folds pending in and
   advances `last_settled_at`.
2. **Persistence.** M1 is **in-memory state** behind a `State` interface (trait), with an optional
   periodic JSON/bincode checkpoint to disk for restart tests. An embedded KV store is deferred; the
   trait makes it swappable without touching the RPC or runtime logic.
3. **Chain id / ports.** Devnet `chainId = 0x5542` (21826), `net_version = "21826"`. JSON-RPC over
   **HTTP on `127.0.0.1:8545`** (WebSocket for `eth_subscribe` may share the port or use `8546`;
   engineer's choice, documented).
4. **Transactions.** Standard **EIP-155 legacy** secp256k1-signed transactions so MetaMask can sign.
   `eth_sendRawTransaction` RLP-decodes, recovers the sender, verifies the signature + chain id, settles
   both accounts' emission, applies the value transfer, increments nonce, and includes the tx in the next
   block. Gas is nominal on devnet (flat `gasPrice`, `eth_estimateGas` returns 21000 for transfers);
   document this simplification.
5. **Genesis dev account.** One pre-verified account with a **well-known devnet private key** (documented
   constant, clearly marked not-a-secret) so tests and the wallet can sign. Verification stays behind a
   `Verifier` interface the M3 proof-of-humanity layer will implement.
6. **Blocks.** A fixed-interval tick (e.g. 2s) produces blocks; empty blocks are fine. `eth_blockNumber`,
   `eth_getBlockByNumber/Hash`, and `newHeads` subscriptions reflect the tick.

## Deferred to later cycles (out of M1)
Account-to-account streams (M2), real AI PoH (M3), prompt contracts (M4), demurrage/governance (M5),
multi-node consensus, mempool ordering guarantees beyond FIFO.
