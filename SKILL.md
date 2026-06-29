---
name: run-and-build-a-ubi-node
description: >
  Stand up, operate, and extend a UBI blockchain node — an EVM-compatible chain with AI proof-of-humanity,
  ZK-passport proof-of-humanity, streaming UBI, natural-language prompt contracts, and browser/mobile
  light nodes. Use when the task is to run the devnet, add or modify a chain feature (runtime/RPC/AI/ZK/wallet),
  plug in an LLM backend, work on the light-node or ZK-passport pipeline, or implement a node from this repo.
---

# Run & build a UBI node

This is the operating manual for an agent working on a UBI node. Read it before touching the chain.

## What a node is

A UBI node can be **full** or **light**.

A **full node** is a single Rust binary (`crates/node`) that produces blocks (2s tick) and serves an
**EVM-compatible JSON-RPC** on `127.0.0.1:8545`. Its determinism is the whole game: balances are pure
integer functions of `(state, timestamp)`, and every AI decision in the consensus path is committed only
by a **quorum** of nodes producing the **same canonical structured output**, else it aborts. The ZK-passport
verifier is pure crypto — every honest node re-runs the same Groth16 pairing check and gets the same
boolean. Never introduce floats, `HashMap`-iteration order, wall-clock reads, un-pinned model calls, or
non-deterministic pairing libraries into any consensus path.

A **light node** (`crates/runtime-wasm` + `packages/light-client`) runs in a **browser tab or on a
phone**. It syncs blocks from a full node over a WebSocket gateway, **re-executes every block in WASM**
using the same deterministic `crates/runtime` core, and asserts a byte-identical `state_root` after
each block. A gateway that serves a forged block is caught immediately. The light node also holds state
in IndexedDB and signs transactions locally via an EIP-1193 provider. On a phone with NFC, the Stage-3
mobile wrapper reads an ICAO-9303 e-passport on-device and generates the Groth16 ZK proof on-device;
only the proof leaves the device.

## Build & run

```bash
# Full node
cargo build --release -p ubi2-node      # or: ./scripts/devnet.sh  (builds + runs)
./target/release/ubi2-node              # serves http://127.0.0.1:8545 (HTTP+WS)
# env: UBI2_RPC_ADDR (default 127.0.0.1:8545), UBI2_BLOCK_MS (default 2000), RUST_LOG

# Light-node parity gate (WASM kernel == server kernel, byte-for-byte)
cargo test -p ubi2-runtime-wasm --test parity --no-default-features

# ZK-passport verifier (Groth16 real-curve test)
cargo test -p ubi2-zkpoh

# App (wallet + identity + explorer + contracts)
pnpm install && pnpm --filter @ubi2/wallet dev  # → http://localhost:3000
```

Genesis seeds one pre-verified dev account (public Hardhat key `0xf39F…2266`) streaming 1 UBI/hr, and
three jurors.

## Layout & where things live

- `crates/runtime` — state + transitions. `lib.rs` (accounts, emission, fees, transfers, `State` trait +
  `MemState`), `humanity.rs` (PoH types — both the social-vouching path and the `ZkPassportVerifier` trait,
  `Assurance` enum, nullifier registry, attribute store, CSCA registry), `lifecycle.rs` (PoH state machine,
  `submit_zk_passport_proof`), `contracts.rs` (effect language, escrow apply, `ContractInterpreter`).
  **Dependency-free** — no crypto, no async. Defines the `ZkPassportVerifier` trait; the impl lives in `crates/zkpoh`.
- `crates/zkpoh` — pure deterministic Groth16/BN254 SNARK verifier + Pedersen attribute verifier.
  Implements `ZkPassportVerifier`. Uses arkworks (`ark-bn254` + `ark-groth16`, pinned). Compiles to WASM.
  No async/network/clock/float deps — the build-level purity test asserts this.
- `crates/runtime-wasm` — thin `wasm-bindgen` wrapper over the untouched `crates/runtime`. The only
  crate that may depend on `wasm-bindgen`. Exposes `LightState` with `applyBlock` / `stateRoot` /
  `balanceOf` / `serialize` / `deserialize`. A native parity test (`tests/parity.rs`) asserts the WASM
  kernel produces byte-identical `state_root`s to the server follower for a block corpus.
- `crates/rpc` — `lib.rs` (jsonrpsee server, mempool, `produce_block`, EVM + `ubi_*` methods, the indexer),
  `streams.rs` / `humanity.rs` (hub ABI + decode, including `submitZkPassportProof`) / `contracts.rs`,
  `oracle_admin.rs` (loopback admin RPC). Hosts the WebSocket sync gateway (`wss://.../sync`) for light clients.
- `crates/oracle` — `backend.rs` (Anthropic/Ollama/OpenAI), `client.rs`, `url_policy.rs` (SSRF guard),
  prompt/schema modules. Live calls are gated; tests use recorded fixtures.
- `crates/network` — P2P transport (libp2p), block gossip, the `ubi2/sync/1` wire protocol (`WireBlock`,
  `SyncRequest`/`SyncResponse`). The light-client's WS gateway reuses these payloads verbatim.
- `crates/node` — `main.rs` (genesis, block loop via `spawn_blocking`), `oracle_cfg.rs`. Wires the real
  `ZkPassportVerifier` from `crates/zkpoh` and the genesis CSCA set + pinned verifying key.
- `packages/sdk` (TS client + encoders — no WASM), `packages/light-client` (WS sync driver + WASM glue +
  IndexedDB store + EIP-1193 signer; separate from `sdk` so non-light-node consumers do not pull WASM).
- `apps/wallet` (Next.js app), `docs/` (specs, board, reports).

## PoH paths — what they are and how they differ

**Path 1: social-vouching + AI-jury quorum (M3, `STD` assurance)**
- Entry point: `requestVerification(bytes32)` on HumanityHub (fee-exempt). Proceeds through vouching,
  challenge window, AI-jury quorum, `submitVerdict`, finalization.
- AI decisions: `HumanityOracle` in `crates/oracle`, quorum via `quorum_tally` in `crates/runtime`.
- Non-deterministic model calls are off the consensus path; the quorum tally is deterministic.

**Path 2: ZK-passport proof (M6, `ENH` assurance; Stage 1 shipped)**
- Entry point: `submitZkPassportProof(proof, nullifier, attributeCommitments, cscaRoot, schemeTag,
  nowEpoch)` on HumanityHub. No AI in the verify path.
- Verification: `crates/zkpoh` runs the Groth16 pairing check. Pure crypto, same boolean on every
  honest node. A tampered verifier diverges in `state_root` and is out-voted.
- On-chain state: nullifier registry (sorted set), attribute store (sorted map of Pedersen commitments),
  CSCA registry (on-chain, governance-upgradeable trust anchors). All committed in `state_root`.
- Assurance levels: `STD` (social path), `ENH` (ZK path), `DUAL` (both). UBI eligibility is `Verified`
  status — `assurance` never gates `balance()`.
- Client-side: NFC read + witness + Groth16 proof generation happen on the user's device. Only the proof
  and public inputs reach the chain. The mobile wrapper (Stage 3) delivers the NFC bridge.

## RPC surface

- **EVM (for wallets):** `eth_chainId` (`0x5542`/21826), `eth_blockNumber`, `eth_getBalance` (live streaming
  balance), `eth_getTransactionCount`, `eth_gasPrice`/`eth_estimateGas`/`eth_feeHistory` (UBI fees),
  `eth_call`, `eth_sendRawTransaction`, `eth_getTransactionByHash`/`Receipt` (failed txs return `status 0x0`
  + `revertReason`), `eth_getBlockBy*`, `eth_subscribe(newHeads)`.
- **`ubi_*` reads:** `getHuman` (includes `assurance` level) / `getCase` / `getVouches` / `getJurors` /
  `getPendingCases`; `getAttributes(address)` (three Pedersen commitments; opaque); `getCscaRegistry`;
  `isNullifierUsed(nullifier)`; `getContract` / `getExecCase` / `getContractsOf`; `getStream(s)`;
  `getBlock` / `getTransaction`; `getAccount` / `getAddressActivity`; `getOracleConfig` /
  `setOracleConfig` (**loopback + Origin-allowlisted only**).
- **WS sync gateway** (`wss://.../sync`): `SyncRequest`/`SyncResponse` payloads (`Hello`, `GetBlocks`,
  `Blocks`) served to light clients — the same `ubi2/sync/1` wire format full nodes exchange. Read-only
  plus a `SubmitTx` → `ingest_raw_tx` path.

## System hubs (operations are EIP-155 txs to these addresses)

- StreamHub `0x…5742`: `openStream(address,uint256,uint256)`, `stopStream(uint256)`; ERC-721 views via `eth_call`.
- HumanityHub `0x…5048`: `requestVerification(bytes32)` (fee-exempt), `vouch(address)`, `challenge(address,bytes32)`,
  `submitVerdict(uint256,uint8,uint8)`, `submitZkPassportProof(bytes,bytes32,bytes32[3],bytes32,uint8,uint64)`,
  `registerCsca` / `revokeCsca` (governance-gated).
- ContractHub `0x…5043`: `deployContract(string,address[])`, `fundContract(uint256)`, `invokeContract(uint256,bytes32)`, `submitEffect(uint256,bytes)`.
- Treasury `0x…5542`: collects fees. To add a hub op: add the `sol!` signature, decode in the hub module,
  queue a `PendingKind`, apply in `produce_block`, emit a receipt log, and expose a `ubi_*` read.

## Invariants (do not break — they are gated)

- **I1** deterministic quorum: pinned model + temp 0 + canonical output; commit only on supermajority; else abort.
  For ZK-PoH: the Groth16 verifier is a pure function — same inputs, same boolean on every node; a diverging
  node produces a different `state_root` and is out-voted.
- **I2** reproducible integer balances/fees across nodes, to the base unit. `nowEpoch` in `submitZkPassportProof`
  is always `block.timestamp`, never wall-clock.
- **I4** fail-closed: on error/ambiguity, abort with no partial state; a failed tx is **mined** (status 0 +
  reason + nonce consumed), never silently dropped. All ZK verification failure modes (expired, untrusted
  CSCA root, tampered proof, nullifier reuse, replay) are status-0 receipts with no state change.
- **I6** least authority + privacy: a contract moves only its own escrow; only commitments/verdicts/effects
  on-chain (no PII); untrusted text/evidence is fenced from the model; secrets never in logs/env/persisted
  config. For ZK-PoH: no name, document number, exact DOB, or nationality in plaintext is ever stored — only
  the nullifier and three Pedersen attribute commitments. For the light node: no passport byte, no PII, no
  private key ever leaves the device — only signed txs or a succinct ZK commitment.

## Working on ZK-PoH

`crates/zkpoh` is the isolated home of the pairing math. The allowed deps are arkworks only (`ark-bn254`,
`ark-groth16`, `ark-ff`, `ark-ec`, `ark-serialize`, `ark-std`), all pinned to 0.5.x. No async, no network,
no clock, no float. The build-level purity test asserts this.

`crates/runtime` defines the `ZkPassportVerifier` trait — no crypto in runtime. The lifecycle function
`submit_zk_passport_proof` in `lifecycle.rs` calls it through the trait. Tests wire `MockZkVerifier` (the
offline lifecycle path); CI also runs a focused real-curve soundness test against test-passport fixtures.

The canonical public-input vector is pinned: `[nullifier, attr_commit[0..3], csca_registry_root,
submitter_address, now_epoch, passport_scheme_tag]`. Changing the order or contents is a new verifying key
and a `state_root` version bump — never a silent break.

## Working on the light node

`crates/runtime-wasm` must not modify `crates/runtime` — the wrapper re-exports the untouched core.
`crates/runtime` must not gain `wasm-bindgen`/`getrandom`/`js-sys` deps. The `dependency_free.rs` build-level
test guards this.

Balances cross the WASM boundary as **decimal strings**, never JS floats.

The light client (`packages/light-client`) uses the `ubi2/sync/1` payloads from `crates/network` verbatim —
the gateway framing is WebSocket instead of libp2p, but the bytes are identical. Do not introduce a second
block serialization.

The parity gate (`tests/parity.rs` in `crates/runtime-wasm`) is a hard CI artifact: the WASM kernel and
the server follower must produce byte-identical `state_root`s for the same block corpus. If they diverge,
the test fails — not a warning, a failure.

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
  The `ZkPassportVerifier` trait follows the same pattern as `HumanityOracle`: runtime owns the trait,
  `crates/zkpoh` owns the impl.
- The admin RPC is localhost-only by design; the wallet at `http://localhost:3000` is the allowed Origin.
- The `submitZkPassportProof` gas constant (`GAS_ZKPOH`) is the heaviest HumanityHub op — it runs a
  pairing check. The cheap nullifier-uniqueness pre-check runs before the pairing to fail-close fast on
  re-use attempts.
- `crates/runtime-wasm` is compiled `cdylib` + `rlib`. The parity test uses `--no-default-features`
  (native, no `wasm-bindgen`); the WASM artifact uses the default `wasm` feature. Do not mix them.
