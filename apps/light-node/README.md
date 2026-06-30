# ubi2 Browser Light Node

A node in your browser. Open it; it connects to a full-node WebSocket sync gateway,
syncs genesis-to-tip, re-executes every block in WASM against the same deterministic
kernel the consensus runs, asserts a byte-identical `state_root`, and streams a live
UBI balance from locally-verified state.

**Trust model:** the gateway is trusted only for _availability_. The app pins a
**hard-coded, verifiable genesis anchor** (the genesis hash, the seeded genesis
`state_root`, and the authorized PoA proposer set) and re-executes every block on top of
the verified seeded genesis. A lying server — wrong balance, forged state root, reordered
txs, an unauthorized proposer, or even a self-consistent chain served from _its own_
genesis — is caught before the tip advances. A mismatch turns the badge red and freezes
the balance, never shows a wrong number.

---

## Prerequisites

| Tool | Version |
|---|---|
| Rust / cargo | >= 1.96 (pinned in `rust-toolchain.toml`) |
| wasm-pack | >= 0.13 (`cargo install wasm-pack`) |
| Node.js | >= 20 |
| pnpm | >= 10 (`npm i -g pnpm`) |

---

## Build commands

### 1 — Build the WASM kernel (one-time; re-run after Rust changes)

```bash
# From the repo root:
bash packages/light-client/build-wasm/build.sh

# Or via npm script from the app dir:
pnpm --filter @ubi2/light-node build:wasm
```

Output: `packages/light-client/wasm/` — the wasm-pack "web" target artefacts
(`ubi2_runtime_wasm.js`, `ubi2_runtime_wasm_bg.wasm`, `ubi2_runtime_wasm.d.ts`).

### 2 — Build the app

```bash
# Install workspace deps (once):
pnpm install

# Build the light-node app (also runs typecheck):
pnpm --filter @ubi2/light-node build

# Or build the whole workspace:
pnpm -r build
```

Output: `apps/light-node/dist/` — a fully self-contained static PWA (no CDN deps).

### 3 — Run a local devnet + sync gateway

The full node exposes a WebSocket sync gateway on port 8546 alongside the JSON-RPC
on port 8545.

```bash
# From the repo root — start a single-node devnet:
cargo run -p ubi2-node -- \
  --rpc-port 8545 \
  --ws-gateway-port 8546 \
  --chain-id 21826
```

The gateway endpoint is `ws://127.0.0.1:8546`.

### 4 — Open the light node

```bash
# Dev server (hot-reload):
pnpm --filter @ubi2/light-node dev
# Opens at http://localhost:3001

# Or preview the production build:
pnpm --filter @ubi2/light-node preview
```

Navigate to [http://localhost:3001](http://localhost:3001).

**Config via URL hash** (no server round-trip — works on IPFS):

```
http://localhost:3001/#gateway=ws://127.0.0.1:8546&chainId=21826&address=0x<addr>
```

---

## UI overview

| Element | What it shows |
|---|---|
| Badge (top-right) | `Syncing` → `Verified` (green, state_root matched) or `Mismatch` (red, forged block caught) |
| Tip Height | Block number of the last WASM-verified block |
| State Root | 32-byte root of the re-executed state (truncated; full root on hover) |
| Sync progress | Block N / gateway tip |
| Watch address | Enter any 0x address — live balance + PoH status pulled from verified state |
| Live balance | Ticks every second via exact-integer `projectBalance` (re-anchored on each new verified block) |

---

## Trust model (re-execute and match, do not trust)

### The pinned, gateway-independent genesis anchor (spec §3.4)

The whole guarantee — "trust no server, re-execute from genesis" — rests on a genesis
the app can verify _without_ trusting the gateway. The app therefore ships THREE
hard-coded constants in `src/config.ts`, derived from the actual devnet genesis
(`genesis_time = 1700000000`):

| Pinned constant | What it anchors |
|---|---|
| `PINNED_GENESIS_HASH` | the block-0 hash — a gateway advertising a different one is `WrongNetwork` |
| `PINNED_GENESIS_STATE_ROOT` | the **seeded** genesis `state_root` (over the genesis accounts/jurors/CSCA/governance) — re-derived locally from the gateway's snapshot and rejected on mismatch |
| `PINNED_VALIDATOR_SET` | the authorized PoA proposer(s) — every block's proposer must be in this set |

These are **not** overridable from the URL hash (overriding them would defeat the model).
A node started on a different `genesis_time` is a different network and is correctly rejected.
To re-pin after a genesis-seed change, recompute via the node's sealed `genesis_anchor()`
(the regression guard `crates/node/tests/pinned_genesis_anchor.rs` fails CI on drift).

### The verification flow

1. The WASM kernel (`crates/runtime-wasm`) is the **same deterministic core** the consensus
   nodes run (`crates/runtime`), compiled to `wasm32-unknown-unknown`. No float, no wall-clock
   on the consensus path, no networking inside the kernel.

2. On connect the client fetches the **seeded genesis snapshot** from the gateway (a new
   `GetGenesis` message), re-derives its `state_root` in WASM, and **rejects unless it equals
   `PINNED_GENESIS_STATE_ROOT`** — so the snapshot is untrusted DATA verified against the pinned
   anchor. A gateway that lies about the seeded genesis is caught here, before any block is applied.
   The client re-executes blocks on top of this verified seeded state (it no longer starts from
   an empty state, so a real seeded chain reproduces byte-identically).

3. Every block served by the gateway is **re-executed in WASM**: decode raw txs → apply via
   `crates/exec` kernel → recompute `txs_root` + `state_root` → assert byte-identical to the
   header. A block that fails this check is rejected; the tip never advances.

4. **Proposer authority is enforced on EVERY block.** The kernel checks that the block's
   `proposer` is in `PINNED_VALIDATOR_SET` (and the scheduled proposer is always passed to
   `applyBlock`). There is no "skip when unspecified" path — a self-consistent chain a malicious
   gateway signed with its own key is rejected, not shown as "verified".

5. A malicious gateway that ships a forged block (wrong balance, wrong `state_root`, reordered
   txs, an unauthorized proposer) is caught by the kernel. The badge turns red, the balance
   freezes at the last verified value, and the app never displays an unverified number.

6. Verified state is persisted to **IndexedDB** (`ubi2-light-client / snapshots`). On reload the
   client checks `stateRoot()` against the stored tip; a mismatch discards the snapshot and
   re-syncs from the pinned genesis anchor (re-pinning the validator set via `setValidatorSet`).

7. The verify mode is always **`"full"` (re-execution)**. Header-only is a documented degraded
   mode and is never auto-selected (spec §3.4).

---

## PWA (Stage 2)

- Web app manifest: `dist/manifest.webmanifest` — installable on Android Chrome / iOS Safari.
- Service worker (`dist/sw.js`, generated by Workbox via `vite-plugin-pwa`): pre-caches all
  JS/CSS/WASM/HTML assets for offline access.
- Offline: the last-verified balance is readable from IndexedDB with a "not live" indicator
  (the badge shows `Offline` and the balance stops ticking).
- No external CDNs: all assets are bundled into `dist/`, suitable for IPFS deployment.
