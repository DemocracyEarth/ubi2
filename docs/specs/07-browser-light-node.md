# 07 — Browser & Mobile Light Node

- **Milestone:** Browser & Mobile Light Node (parallel track; **not** on the M5→M6→M7 critical path).
- **Status:** specified (Stage 1 implementable once M5 Stage A's `ubi2/sync/1` + WS RPC are in tree).
- **Owner:** architect. **Decisions pinned in:** [`adr/0006-browser-light-node.md`](adr/0006-browser-light-node.md).
- **Product brief:** [`../milestones/browser-light-node.md`](../milestones/browser-light-node.md). **Invariants:** [`00-overview.md`](00-overview.md).
- **Builds on:** [`05-p2p-network.md`](05-p2p-network.md) (the sync protocol, wire formats, block header,
  and `state_root` this spec consumes verbatim), [`adr/0004-consensus-and-networking.md`](adr/0004-consensus-and-networking.md).
- **Prior art (read-only):** `../ubi.wallet`, `../ubi.chain`.

This spec turns a browser tab (and later a phone) into a **light node**: it syncs blocks from full
nodes, **re-executes each block in WASM** against the deterministic core, asserts a **byte-identical
`state_root`** (so a lying server is caught, not trusted), reads live streaming balances from locally
verified state, and signs + submits txs without a private key ever leaving the device. It is the **same
deterministic core** the M5 followers run (`crates/runtime`), compiled to `wasm32` and called from
TypeScript through a thin wrapper. The browser node does **not** run the AI quorum and does **not** yet
participate in libp2p gossip; it verifies what it reads and submits what it signs.

It is written acceptance-criteria-first (§9). Every exit criterion LC-1…LC-14 from the product brief
maps 1:1 to a test assertion here.

---

## 0. The invariant this milestone exists to extend

> **I1/I2, on the client.** A light node must not *trust* a server's claim about a balance or a state
> root. It re-derives both from blocks it re-executes in the **same deterministic core** the consensus
> uses, and surfaces a **visible verification error** — never a wrong number — when the re-execution
> diverges from the header. The deterministic core (`crates/runtime`) is unchanged; this milestone only
> gives it a new *host* (the browser) and a new *caller* (a TypeScript light client).

This milestone adds **no consensus-affecting code** and **does not touch `crates/runtime`**. It adds a
thin WASM wrapper crate, a TypeScript light-client package, a WebSocket sync gateway on full nodes, and
app/packaging surfaces. The non-negotiable structural rule from [ADR-0004](adr/0004-consensus-and-networking.md)
still holds: `crates/runtime` stays deterministic and dependency-free (the build-level
`dependency_free.rs` test guards it). The WASM wrapper is a **separate crate** so `crates/runtime` never
gains a `wasm-bindgen`/`getrandom`/`js-sys` dependency.

**Privacy perimeter (I6).** No PII, no passport bytes, and no private key ever leave the device. The
NFC read (Stage 3) and key storage (Stage 1) are bounded to the device by construction; the only thing
that leaves is a signed tx or (Stage 3) a succinct ZK commitment.

---

## 1. Scope

**In scope (Stages 1–4):**
- **Stage 1 — Browser light node.** A `wasm32-unknown-unknown` build of `crates/runtime` behind a thin
  `wasm-bindgen` wrapper crate (`crates/runtime-wasm`); a TypeScript light client (`packages/light-client`)
  that syncs blocks over a WebSocket sync gateway, re-executes each block in WASM, verifies the
  `state_root`, persists verified state to IndexedDB, reads live balances, and signs/submits txs via
  EIP-1193. A read-only verification UI in `apps/`.
- **Stage 2 — PWA.** Manifest, service worker, offline last-verified read from the IndexedDB store,
  opt-in PII-free Web Push.
- **Stage 3 — Mobile wrapper + NFC.** A Capacitor/React-Native wrapper hosting the Stage 1/2 WASM
  module; on-device ICAO-9303 NFC passport read; on-device ZK proof generation (circuit owned by the
  ZK-Passport PoH track); `requestVerification` submission via the device's own light node.
- **Stage 4 — Optional producing / juror node (opt-in).** Block production (gated on M6 staking;
  disabled by default) and an in-app juror daemon. Both are additive and out of the core inclusion goal.

**Out of scope (backlog):**
- **Full browser-side libp2p gossip / WebRTC mesh.** Stage 1 syncs over a WebSocket *gateway*; direct
  browser gossip is a later optimization (§7, backlog).
- **In-browser AI quorum (WebLLM/WebGPU).** A far-future option (§6); the light node never runs the
  quorum in Stages 1–3.
- **Header-sync + fraud/validity/ZK state proofs** as a *replacement* for re-execution — a documented
  later optimization (§3.4), not the Stage 1 trust model.
- **A bespoke native mobile wallet UI** (Stage 3 hosts the existing app), cross-chain bridge, the ZK
  circuit + HumanityHub extension themselves (owned by the ZK-PoH track — this milestone is the
  delivery vehicle, §8).

---

## 2. The WASM boundary (Stage 1)

### 2.1 What compiles to WASM, and where the line is

`crates/runtime` is already deterministic and dependency-free (no libp2p/tokio/reqwest/floats/wall-clock;
`crates/runtime/tests/dependency_free.rs` is the build-level guard). It therefore compiles to
`wasm32-unknown-unknown` **as-is, untouched**. This spec **does not modify `crates/runtime`**. The
verification line is:

```
┌───────────────────────── browser tab / WebView ─────────────────────────┐
│  TypeScript light client (packages/light-client)                         │
│    • WS sync driver  • IndexedDB store  • EIP-1193 signer  • balance view │
│        │  calls (apply_block / state_root / balance / read)              │
│        ▼                                                                  │
│  crates/runtime-wasm  (thin wasm-bindgen wrapper — NEW, ~1 file)          │
│        │  re-exports a JSON/bytes API over ↓                             │
│        ▼                                                                  │
│  crates/runtime  (the deterministic core — UNTOUCHED, compiled to wasm32) │
└──────────────────────────────────────────────────────────────────────────┘
```

`crates/runtime-wasm` is the **only** new Rust artifact that may depend on `wasm-bindgen`/`serde-wasm-bindgen`.
`crates/runtime` keeps its empty `[dependencies]`. A second build-level test (§9.1, AC-WB) asserts the
wrapper crate does **not** re-export any mutator that bypasses the canonical apply path, and that
`crates/runtime` still declares no forbidden deps.

### 2.2 The wrapper API (exact signatures)

The wrapper exposes a **stateful handle** (`LightState`) holding a `MemState` plus the verified chain
tip, and pure read methods. All cross-boundary values are bytes or JSON (no float ever crosses the
boundary; balances cross as **decimal strings**, never JS `number`). The wrapper is a *re-export*, not a
re-implementation: every state transition is the runtime's own function called with `block.timestamp` as
the only clock.

| Method (TS-facing) | Rust signature (conceptual) | Maps to runtime | Purpose |
|---|---|---|---|
| `LightState.genesis(chain_id, genesis_json)` | `fn genesis(chain_id: u64, genesis: &[u8]) -> LightState` | `MemState::new` + genesis seeding | Construct the empty verified state at the genesis the gateway advertised. |
| `applyBlock(wireBlock: Uint8Array, expectedProposer?: Uint8Array)` | `fn apply_block(&mut self, wire: &[u8], expected_proposer: Option<[u8;20]>) -> Result<BlockOutcome, JsErr>` | the **same re-execution `crates/rpc::Chain::validate_and_apply_block` performs**, factored to take a `&mut MemState` (see §2.3) | Decode the `WireBlock` (§wire), re-execute its txs at `block.timestamp`, recompute `txs_root` + `state_root`, and **return the recomputed `state_root`** plus accept/reject. |
| `stateRoot()` | `fn state_root(&self) -> [u8;32]` | `ubi2_runtime::state_root(&MemState)` | The 32-byte root over current verified state. |
| `tip()` | `fn tip(&self) -> Tip` | wrapper-held | `{ number, hash, stateRoot, timestamp }` of the highest verified block. |
| `balanceOf(addr, now)` | `fn balance_of(&self, addr: [u8;20], now: u64) -> String` | `Account::balance(now)` (settled + emission + Σ incoming streams) | The streaming balance at unix-second `now`, as a **decimal string** of base units (I2). |
| `nonceOf(addr)` | `fn nonce_of(&self, addr: [u8;20]) -> u64` | `State::get(addr).nonce` | For composing the next tx. |
| `humanStatus(addr)` | `fn human_status(&self, addr: [u8;20]) -> u8` | `State::get_human` status tag | PoH status (Unverified/Pending/Verified/Challenged/Revoked). |
| `serialize()` / `deserialize(bytes)` | `fn serialize(&self) -> Vec<u8>` / `fn deserialize(&[u8]) -> Result<LightState,_>` | a canonical encode of `MemState` + tip | Persist/restore the verified state to/from IndexedDB (§3.3). |

**Critical determinism rule for the wrapper:** `balanceOf(addr, now)` is the **only** way the UI gets a
balance, and `now` is supplied by the caller (the UI's wall-clock) purely to *project the stream forward
for display* — exactly as the existing `projectBalance` does (the wrapper computes the same integer
`rate * elapsed` the chain commits). The committed, *consensus* balance is always read at a block height
(`now = block.timestamp`); the live tick is a pure-integer extrapolation re-anchored on every new block.
No float, ever. (Reuse the SDK's `EMISSION_RATE` rational + `projectBalance` for the inter-block tick;
the WASM `balanceOf` is the re-anchor.)

### 2.3 The shared re-execution path (no logic fork)

`crates/rpc::Chain::validate_and_apply_block` already does exactly the follower re-execution this needs
(decode raw txs → execute at `block.timestamp` → recompute `txs_root`/`state_root` → accept only on
byte-identical roots). To avoid a *second* implementation drifting from the consensus one, the block
**execution kernel** (the part that takes `&mut MemState` + ordered raw txs + `timestamp` and returns
the post-state, with no `tokio`/`jsonrpsee`/`std::sync::Mutex`) is factored into a small, dependency-free
helper that **both** `crates/rpc` (server follower) **and** `crates/runtime-wasm` (browser follower) call.

- If that kernel is small enough to be `no_std`-clean and dependency-free, it lives in **`crates/runtime`**
  (it already holds `apply_transfer`, `charge_fee`, `settle_stream`, the hub op handlers, and
  `state_root`) — preferred, since the runtime is the natural home and is the WASM artifact anyway.
- If it must depend on `alloy`/`k256` RLP-decode + ecrecover (which `crates/runtime` currently does
  **not** carry — `crates/network::wire` carries its own `recover_secp256k1`), the kernel lives in a
  thin **`crates/exec`** crate depending only on `runtime` + the decode/recover primitives (still no
  async/networking), and **both** `crates/rpc` and `crates/runtime-wasm` depend on it. **Decision:**
  prefer extracting the tx-decode + ecrecover the browser needs into this `crates/exec` (or directly
  into `runtime` if the decode crates stay light) so there is **one** re-execution implementation. This
  is recorded in [ADR-0006](adr/0006-browser-light-node.md) as the load-bearing "no logic fork" rule.

The acceptance bar (§9, AC-LC2/AC-WB) asserts the browser kernel and the server follower produce
**byte-identical `state_root`s** for the same block — i.e. they are provably the same kernel.

---

## 3. Light-client sync over WebSocket (Stage 1)

### 3.1 Transport decision — a WebSocket sync gateway on full nodes

A browser cannot open a raw TCP socket and cannot speak libp2p-tcp. Three options were weighed (full
analysis + decision in [ADR-0006](adr/0006-browser-light-node.md) Decision 2):

1. **A WebSocket *sync gateway* on the full node that re-uses the M5 `ubi2/sync/1` request/response
   payloads verbatim** — **chosen**. The browser opens a `wss://` connection to a full node and sends
   the **exact same `SyncRequest`/`SyncResponse` bytes** defined in §4.2 of spec 05 (`Hello`,
   `GetBlocks{from,to}`, `Blocks{[WireBlock]}`), just framed in WebSocket messages instead of a libp2p
   request-response stream. The gateway is a thin adapter in `crates/rpc` (it already runs a WS server
   for `eth_subscribe`); it translates a WS frame ↔ a `SyncRequest`/`SyncResponse` and answers from the
   node's persisted block store. **No new wire format** — the canonical `WireBlock` encoding (with
   `txs_root`/`state_root`/`proposer`/`proposer_sig` + raw txs) crosses unchanged, so the browser
   re-executes and verifies exactly what a server follower verifies.
2. **libp2p-websockets / WebRTC in the browser (js-libp2p or rust-libp2p→wasm).** Rejected for Stage 1
   (full mesh peering in the browser is the backlog optimization, §7): it is heavyweight, the WASM
   libp2p story is immature, and it does not change the trust model (re-execution is what gives
   trustlessness, not the transport). It is the documented long-term path to remove the single-gateway
   dependency.
3. **A bespoke JSON-over-WS block API.** Rejected: it would be a *second* block serialization to keep
   byte-compatible with consensus, exactly the drift risk §2.3 forbids.

### 3.2 Sync algorithm (mirrors spec 05 §4.2, re-execution unchanged)

A browser light node starting from empty (or from a restored IndexedDB snapshot):

1. Open `wss://<full-node>/sync`. Send `SyncRequest::Hello { genesis_hash, chain_id, tip: (h_local, ...),
   validator: None, peer_proof: [], protocol_ver }`. Receive the gateway's `Hello` → learn the network
   tip `(H, _)`. **If `genesis_hash`/`chain_id` differ ⇒ refuse to sync** and surface "wrong network"
   (mirrors the §4.1 network-mismatch disconnect).
2. Request `[h_local+1, H]` in batches of `SYNC_MAX_BATCH` (128, the §10 constant) via
   `SyncRequest::GetBlocks{from,to}`, ascending.
3. For each received `WireBlock`, in height order: **`applyBlock`** in the WASM wrapper, which:
   `shallow_verify()` (txs_root consistent + **non-empty proposer signature recovering to `proposer`**,
   §wire — an unsigned block is **never** trusted, SEC-M5A-1), then re-execute against the verified
   parent at `block.timestamp`, then assert the recomputed `state_root` **byte-identically** equals the
   header's `state_root`. **On any failure ⇒ stop, mark the gateway untrusted, surface a verification
   error** (LC-2/LC-5/AC-LC2) and try another gateway. Never advance the tip on a failed block.
4. Once caught up to `H`, subscribe to live block notifications over the same WS (a `block` push that
   carries the new `WireBlock`); each is `applyBlock`-verified before the UI's tip advances.
5. Persist the verified state + tip to IndexedDB (§3.3) at a bounded cadence (e.g. every block or every
   N seconds), so a reload resumes from the last verified height rather than re-syncing from genesis.

Because every block is **re-executed and root-checked client-side**, a malicious gateway that ships a
forged block (wrong balance, wrong state root, reordered txs, forged proposer) is **caught by the
re-execution** — it cannot make the light node show a wrong balance, only fail to advance (LC-5).

### 3.3 Persistence — IndexedDB

The verified `MemState` snapshot + verified tip `(number, hash, state_root, timestamp)` are persisted to
**IndexedDB** via `LightState.serialize()/deserialize()`. On open, the light client:
- loads the last snapshot, sets `h_local` to its tip, and resumes sync from `h_local+1`;
- **re-verifies the snapshot's `state_root` against its stored tip header on load** (a corrupt/poisoned
  IndexedDB entry must not be trusted — recompute `state_root()` and compare to the stored
  `tip.state_root`; on mismatch, discard the snapshot and re-sync from genesis).

A signed checkpoint (§3.4) may be used as the trusted genesis-equivalent to bound the from-genesis
replay; in Stage 1 the default is **replay from genesis**.

### 3.4 Trust model & later optimizations

**Stage 1 trust model (strong): full re-execution from genesis (or a signed checkpoint).**
- The light node trusts **nothing** about balances/state from the gateway; it re-derives them by
  re-executing every block and matching `state_root`. This is the same guarantee a server follower has.
- The gateway is trusted only for **availability** (which blocks exist, the peer count it reports) and
  for **liveness** (serving the range). A lying gateway is detected the moment a served block fails
  re-execution; an *omitting* gateway (withholding the real tip) is mitigated by **multi-gateway
  cross-checking** (Stage 2): connect to ≥2 independent full nodes and require their advertised tips +
  `state_root`s at common heights to agree; a divergence surfaces a warning, not a silent pick.
- **PoA caveat (documented):** finality here is M5's k-deep PoA (`FINALITY_DEPTH=6`), CFT not BFT. A
  light node treats blocks below finality depth as provisional and labels them so in the UI. It does not
  *trust* a chain a majority of validators have not built on; with a single gateway it cannot *detect*
  an eclipse beyond what re-execution + the proposer-schedule check give it — multi-gateway is the
  mitigation, full browser gossip the long-term one (§7).

**The pinned, gateway-independent genesis anchor (closes findings `ln-trust-1/2/3`).** Re-execution from
genesis only gives the guarantee above if the *genesis itself* is fixed independently of the gateway —
otherwise a malicious gateway serves a self-consistent chain signed by **its own** key from **its own**
genesis and the UI still reads "verified". The shipped app therefore pins THREE hard-coded constants
(`apps/light-node/src/config.ts`), derived from the actual devnet genesis:
- **`genesisHash`** — the block-0 hash. The client rejects (`WrongNetwork`) any gateway advertising a
  different one (in its `Hello` AND in the genesis anchor); it **never adopts the gateway's**.
- **`genesisStateRoot`** — the **seeded** genesis `state_root` (over the seeded accounts/jurors/CSCA/
  governance — distinct from the block-0 header's `ZERO` root, which is never re-executed). The node
  seeds genesis via non-block state writes and **seals** an anchor (`Chain::seal_genesis`); it serves the
  seeded genesis **snapshot** over the sync gateway via a new `GetGenesis`/`Genesis` message. The client
  imports the snapshot, **re-derives its `state_root` locally**, and rejects unless it equals this pinned
  constant — so the snapshot is untrusted *data* checked against the pinned *anchor*. The client then
  re-executes blocks on top of the verified seeded state (it no longer starts from an empty state, so a
  real seeded chain reproduces byte-identically — the previous empty-state import was non-functional).
- **`validatorSet`** — the authorized PoA proposer set. Proposer authority is enforced on **every** block
  (the kernel checks `block.proposer ∈ validatorSet`, and the scheduled proposer is always passed to
  `applyBlock`); there is no "skip when unspecified" path.

The on-chain consensus genesis format is unchanged (the block-0 header still commits a `ZERO` state_root,
so M5 consensus + `m5_stage_a` are untouched): the pinned anchor is a separate, app-held verification
constant over the seeded height-0 state, not a change to the committed header.

**Documented later optimizations (backlog, not Stage 1):**
- **Header-only sync** (the brief's Risk-1 fallback): verify the header chain (`parent_hash` links +
  `proposer_sig` recovering to the scheduled proposer) and *trust* the header `state_root` without
  re-executing. Strictly weaker than full verification (it trusts the proposer's claimed root) but far
  stronger than a server read, and a viable degraded mode for a slow phone. The light client exposes a
  `verifyMode: "full" | "header"` flag; **full is the default and the only mode that satisfies LC-2/LC-5.**
- **Signed checkpoints:** a periodically-published, validator-quorum-signed `(height, state_root)` lets
  a light node start re-execution from a recent height instead of genesis, bounding replay cost.
- **Fraud / validity (ZK) state proofs:** a future state-proof scheme (a succinct proof that the
  `state_root` transition for a block is correct) would let the light node verify *without* re-executing
  — the strongest + cheapest model, and the natural convergence point with the ZK-PoH track's proving
  stack. Far-future; recorded as the end-state, not scheduled here.

---

## 4. Wallet, keys, signing, UX (Stage 1)

### 4.1 Keys never leave the device (I6)

Two signer paths, both keeping the private key off the wire:
1. **Injected EIP-1193 provider (MetaMask / any wallet).** The light client requests a signature via the
   standard `window.ethereum` provider (`eth_sendTransaction` is built locally then signed; or
   `personal_sign`/typed-data where applicable). The key lives in MetaMask; the light client only ever
   sees the **signed raw tx**. This is the LC-4 default and reuses the existing app's signing flow.
2. **In-browser key (WebCrypto / passkeys).** For a no-extension flow, the light client generates/holds
   a secp256k1 key in `IndexedDB`/`CryptoKey` storage, optionally gated by a **passkey/WebAuthn**
   user-presence check before each signature. The raw key is **non-exportable** where the platform
   supports it. (secp256k1 is not a native WebCrypto curve, so the key bytes are held in app storage and
   signing is done in-WASM/JS; the passkey gates *use*, not custody — documented as a weaker custody
   story than a hardware wallet, with the MetaMask path as the recommended default.)

### 4.2 Submitting a signed tx

The signed raw EIP-155 tx is sent to a full node for inclusion. Stage 1 submits via the **gateway**: a
`SyncRequest`-sibling `SubmitTx { raw }` WS message that the gateway feeds into the node's existing
`ingest_raw_tx` (the same path `eth_sendRawTransaction` uses), which gossips it on `ubi2/tx/1`. (Equally,
the light client may simply POST to the gateway's standard `eth_sendRawTransaction` JSON-RPC — that
endpoint already exists; the WS `SubmitTx` just avoids a second connection.) The light client then waits
for the tx's effect to appear in a **re-executed, root-verified** block before it shows "confirmed"
(LC-4) — the confirmation is derived from verified state, not from the gateway's say-so.

### 4.3 The verification UI (Stage 1)

A minimal read-only surface in `apps/` (or a route in the existing wallet app): address → live streaming
balance (re-anchored on every verified block, ticked by `projectBalance` between blocks), chain tip,
gateway/peer count, and a **verification badge**: green = latest block re-executed and `state_root`
matched; **red = mismatch / forged block detected** (LC-2/LC-5). The badge is the user-visible
expression of the trust model: a wrong number can never be shown as if it were green.

---

## 5. Packaging path (Stages 2–3)

| Stage | Package | What ships | Depends on |
|---|---|---|---|
| 1 | browser tab | `packages/light-client` (TS) + `crates/runtime-wasm` (WASM) + a verify UI route in `apps/` | M5 Stage A (`ubi2/sync/1` + WS gateway) |
| 2 | **PWA** | manifest + service worker + offline last-verified read (IndexedDB) + opt-in PII-free Web Push | Stage 1 |
| 3 | **Capacitor / React-Native wrapper** | the Stage 1/2 WASM module embedded in a native iOS/Android shell + an **NFC bridge** | Stage 2; ZK-PoH circuit (§8) |
| 4 | wrapper + daemons | opt-in block production (M6 staking) + in-app juror daemon | Stage 3; M6 |

- **PWA first** (Stage 2): installable (Add to Home Screen) on Android + iOS, offline read of the last
  verified balance from IndexedDB with a clear "not live" indicator, Web Push whose **payload carries no
  PII** (a threshold-crossed event, resolved client-side; the relay never learns the user's identity).
  This is the primary, app-store-policy-independent distribution surface.
- **Capacitor/React-Native** (Stage 3): a *thin* wrapper — the consensus path (sync + WASM re-execution +
  signing) is the **same code** as Stage 1, not a re-implementation. The wrapper adds only (a) a native
  **NFC bridge** (ICAO-9303 BAC/PACE, MRTD data-group read, **on-device only**), and (b) on-device ZK
  proof generation using the ZK-PoH circuit (compiled to WASM or native). The proof is submitted as a
  `requestVerification` via the device's **own** light node — no desktop.

---

## 6. The browser node is light: no AI quorum (far-future note)

The browser/mobile node is a **read + verify + sign** node. It does **not** run the AI proof-of-humanity
or prompt-contract quorum in Stages 1–3 (those require an LLM backend and validator-key juror duty). A
phone may *opt in* to the juror role in **Stage 4** by pointing the in-app juror daemon at a
user-configured AI backend (on-device or remote) — that is the same `crates/juror` daemon M5 Stage C
defines, hosted by the wrapper, and gated on the device being a `Verified` validator (which the Stage-3
NFC flow can satisfy). **In-browser AI (WebLLM/WebGPU) running a quorum-grade pinned model at
temperature 0** is noted as a far-future option only; it is **not** in scope and must never be assumed by
the consensus path (I1's canonical-output contract is unchanged regardless of where the model runs).

---

## 7. Threat model (for the security gate)

The security-engineer must threat-model the new surfaces explicitly. The core mitigation throughout is
**client-side re-execution**: a light node never trusts a served balance/root.

| Threat | Vector | Mitigation | Test pointer |
|---|---|---|---|
| **Malicious gateway (lying full node)** | serves a forged block (wrong balance, wrong `state_root`, reordered/forged txs, forged proposer) | **re-execution + byte-identical `state_root` match** (§3.2 step 3) + `shallow_verify` (signed-proposer-only, SEC-M5A-1). A forged block fails re-execution and is rejected; the tip never advances. | AC-LC2, AC-F-LN1 |
| **Gateway eclipse / withholding** | a single gateway hides the real tip or feeds only a minority fork | **multi-gateway cross-check** (Stage 2): require ≥2 independent gateways' tips/roots to agree; surface divergence. k-deep finality bounds a short eclipse. Full browser gossip is the long-term fix (backlog). | AC-F-LN2 |
| **Sync / range-request DoS (against the browser)** | a gateway floods huge `Blocks` responses | `SYNC_MAX_BATCH`-bounded responses (the `Blocks::decode` cap, §wire); abandon-on-invalid; per-message size bound. | AC-F8 (reused) |
| **Sync gateway DoS (against the full node)** | many browsers exhaust a node serving sync | the gateway reuses the node's existing rate limits + a per-connection concurrent-sync cap; the gateway is a *read* surface only (I6) — no admin/write authority beyond `SubmitTx`→`ingest_raw_tx` (which is itself validated + rate-limited). | security gate |
| **Browser key theft** | XSS / malicious dependency reads the in-browser key | prefer the **EIP-1193 (MetaMask) path** (key never in app scope); for the in-browser key, non-exportable storage + passkey-gated use + a strict CSP; document the weaker custody and steer users to a hardware/extension wallet for large balances. | security gate |
| **Supply-chain (JS + WASM)** | a poisoned `packages/light-client` dep or a swapped WASM blob silently weakens verification | **subresource integrity / pinned hashes** on the WASM artifact; reproducible WASM build checked in CI (the WASM `state_root` must match the server's for a corpus of blocks — AC-WB); minimal, audited dep tree; the verification badge is computed *in-WASM*, not in swappable JS. | AC-WB, security gate |
| **Poisoned IndexedDB** | a local attacker rewrites the cached snapshot | **re-verify the snapshot's `state_root` on load** (§3.3); discard + re-sync on mismatch. | AC-LC7 |
| **NFC / passport PII leak** (Stage 3) | raw MRTD/biometric data exfiltrated | **on-device only** read; only the succinct ZK commitment leaves the device (I6); no passport bytes cross any network. | AC-LC11 |
| **Downgrade to header-only** | an attacker forces the weaker mode to slip a bad root | `verifyMode: "full"` is the default and the only mode that satisfies LC-2/LC-5; header-only is opt-in, clearly labelled "trusts proposer root", and never silently selected. | AC-LC2 |

---

## 8. Interface contract with the ZK-Passport PoH track (Stage 3 handoff)

This milestone is the **delivery vehicle** for ZK-PoH, not the designer of the circuit. The two tracks
agree, before Stage 3 begins, a contract covering:

1. **NFC data groups required.** Which ICAO-9303 MRTD data groups (e.g. DG1 MRZ, DG2 face, SOD) the
   circuit consumes, and which the device reads but never transmits (all of them stay on-device — only
   the proof leaves).
2. **Proof schema.** The proving system (Groth16/PLONK/…), the public inputs (e.g. a nullifier / unique
   commitment, an age/nationality predicate), proof + verifying-key byte formats, and the proof size
   (it must fit in a `requestVerification` calldata bound).
3. **HumanityHub extension API.** How a ZK-backed `requestVerification` is encoded (a new calldata shape
   or op on `HumanityHub 0x…5048`), and whether the **AI jury still adjudicates** the claim or the
   **on-chain verifier accepts the proof directly** (to be agreed — likely a verifier op that, on a valid
   proof, transitions the account toward `Verified` with the jury reserved for disputes). **The runtime
   change for this is owned by the ZK-PoH track, not this milestone.** This spec only commits that the
   *submission* of whatever they define flows through the device's own light node (LC-12).

LC-10 (NFC read) and LC-11 (proof gen) are **separable** from LC-12 (on-chain submission): the mobile
wrapper can demonstrate NFC + a placeholder proof independently; LC-12 is the joint integration moment.

---

## 9. Acceptance criteria (1:1 with LC-1…LC-14 → tests)

Stage 1 criteria are Playwright/integration tests against a local devnet (single full node + gateway is
sufficient for LC-1…LC-5; multi-gateway adds AC-F-LN2). The AI path uses `MockOracle`/`MockInterpreter`
(I5) where a verified human is needed.

| AC | Maps to | Assertion (the test bar) | Stage |
|---|---|---|---|
| **AC-LC1** | LC-1 | A headless browser opens the WS gateway, exchanges `Hello`, and syncs the header/block range genesis→tip via `GetBlocks`/`Blocks` **with no server-side validation done on its behalf** (the gateway only serves bytes). The browser reaches the gateway's advertised tip height. | 1 |
| **AC-LC2** | LC-2, LC-5 | After sync, the browser's WASM `stateRoot()` for the latest block **byte-identically equals** the header `state_root`. A **tampered block** injected by a mock gateway (mutated balance/root/tx) makes `applyBlock` **reject** and the UI show a **red verification error** — never a wrong balance. | 1 |
| **AC-LC3** | LC-3 | A verified human's `balanceOf(addr, now)` from the browser equals `eth_getBalance(addr)` from the full node at the same block height (to the base unit, I2), and **ticks upward** between blocks via `projectBalance`, re-anchoring on each new verified block. | 1 |
| **AC-LC4** | LC-4 | The browser signs a transfer/vouch/contract tx via the EIP-1193 provider (and via the in-browser key), submits it, and after it lands in a **re-executed, root-verified** block the browser shows it confirmed and the balance updated. **The private key is never sent over any connection** (asserted by inspecting outbound frames — only a signed raw tx leaves). | 1 |
| **AC-LC5** | LC-5 | An adversarial gateway that lies about the `state_root` (serves a header whose root ≠ the re-executed root) produces a **visible verification error**; the browser does **not** display the lied-about balance. | 1 |
| **AC-WB** | (boundary) | A CI test compiles `crates/runtime-wasm` to `wasm32-unknown-unknown`, runs `applyBlock` over a recorded corpus of blocks, and asserts the WASM `state_root` **equals the server `crates/rpc` follower's `state_root`** for every block — proving one shared kernel (§2.3). `crates/runtime` still declares no forbidden deps (`dependency_free.rs` green); the wrapper exposes no state mutator bypassing the canonical apply. | 1 |
| **AC-LC6** | LC-6 | The PWA installs (Add to Home Screen) on Android Chrome and iOS Safari; opens chromeless; icon on home screen. | 2 |
| **AC-LC7** | LC-7 | Offline, the PWA shows the **last-verified** balance from IndexedDB with a clear "not live" indicator; on reconnect it re-syncs and goes live. A **poisoned IndexedDB snapshot** (root ≠ stored tip) is **discarded** on load and re-synced from genesis. | 2 |
| **AC-LC8** | LC-8 | A balance threshold crossing delivers a Web Push whose **payload contains no PII** (asserted by inspecting the payload); the relay never receives the user's address/identity. | 2 |
| **AC-LC9** | LC-9 | The native wrapper (Capacitor/RN) embeds the Stage 1/2 WASM module and runs the **same** sync + verify + sign path (no separate consensus codebase); a build + smoke test on iOS and Android simulators. | 3 |
| **AC-LC10** | LC-10 | On a **physical** NFC-capable device (tested device/OS matrix in the test plan), tapping a test ICAO-9303 e-passport reads the MRTD data groups **on-device**, with **no raw passport bytes on any network** (asserted by a network capture during the read). | 3 |
| **AC-LC11** | LC-11 | The device generates the ZK proof **on-device** (no PII/MRZ/biometric leaves); the produced proof matches the schema agreed with the ZK-PoH track (§8). *(Conditional on the ZK-PoH circuit landing; demonstrable with a placeholder proof until then.)* | 3 |
| **AC-LC12** | LC-12 | The on-device proof is submitted as a `requestVerification` via the **device's own light node**; the account transitions to `Verified` and streaming UBI begins **on the phone, no desktop** involved. *(Joint with ZK-PoH.)* | 3 |
| **AC-LC13** | LC-13 | With the opt-in flag set (and M6 staking satisfied), the mobile node produces a block in the PoA round-robin schedule; **disabled by default** (asserted: a default-config node never proposes). | 4 |
| **AC-LC14** | LC-14 | With a configured AI backend, the in-app juror daemon submits a signed `submitVerdict`/`submitEffect` for a case assigning its validator address (reuses M5 Stage C's path). | 4 |

### 9.1 Failure-mode acceptance (must also pass)

| AC | Failure mode | Assertion |
|---|---|---|
| **AC-F-LN1** | Forged block from gateway | A block whose re-executed `state_root` ≠ its header is **rejected**; tip does not advance; red badge. (Same bar as M5 AC-F2, now client-side.) |
| **AC-F-LN2** | Gateway eclipse | With ≥2 gateways advertising divergent tips/roots at a common height, the light client **surfaces a divergence warning** and does not silently pick one. |
| **AC-F-LN3** | Unsigned/forged-proposer block | `shallow_verify` rejects an unsigned block (empty `proposer_sig`) or one whose sig does not recover to `proposer` — it is never trusted for its height (SEC-M5A-1). |
| **AC-F-LN4** | Wrong-network gateway | A gateway with a different `genesis_hash`/`chain_id` is refused at the `Hello` exchange; the light client surfaces "wrong network" and does not sync. |
| **AC-F-LN5** | Header-only downgrade | `verifyMode` defaults to `"full"`; selecting `"header"` is explicit, labelled "trusts proposer root", and never auto-selected — LC-2/LC-5 only pass in `"full"`. |

---

## 10. Constants (reused from M5 + light-node additions)

| Constant | Value | Source / meaning |
|---|---|---|
| `SYNC_MAX_BATCH` | 128 | spec 05 §10 — max blocks per `GetBlocks`/`Blocks`; bounds browser sync DoS. |
| `FINALITY_DEPTH` (k) | 6 | spec 05 §10 — blocks below this are shown provisional in the UI. |
| `EMISSION_RATE` | 1 UBI / 3600 s | `packages/sdk` rational — the tick rate for `projectBalance` between verified blocks. |
| `LN_GATEWAYS_MIN` | 1 (Stage 1) → 2 (Stage 2) | min independent gateways; ≥2 enables the cross-check (AC-F-LN2). |
| `LN_SNAPSHOT_EVERY` | 1 block (tunable) | IndexedDB persistence cadence. |
| `LN_VERIFY_MODE` | `"full"` (default) | `"full"` re-executes (LC-2/LC-5); `"header"` is the opt-in degraded mode (§3.4). |

---

## 11. New surfaces (no consensus change)

- **`crates/runtime-wasm`** (NEW): the thin `wasm-bindgen` wrapper (§2.2). Only new Rust crate that may
  depend on `wasm-bindgen`/`serde-wasm-bindgen`. `crates/runtime` is untouched.
- **`crates/exec`** (NEW, conditional, §2.3): the shared re-execution kernel if it cannot live in
  `crates/runtime` directly — depended on by **both** `crates/rpc` and `crates/runtime-wasm` so there is
  one re-execution implementation. No async/networking.
- **WS sync gateway** in **`crates/rpc`**: a `wss://.../sync` adapter translating WS frames ↔
  `SyncRequest`/`SyncResponse` (the §4.2 payloads, **verbatim**) + an optional `SubmitTx` → `ingest_raw_tx`.
  Read-only authority plus the already-validated submit path (I6). No new `eth_*` semantics (I3): the
  light client uses standard `eth_getBalance`/`eth_blockNumber`/`eth_sendRawTransaction` for any
  server-side reads; the gateway only adds the block-range pull the browser re-verifies.
- **`packages/light-client`** (NEW, TS): the WS sync driver, the WASM glue, the IndexedDB store, the
  EIP-1193 signer, and `verifyMode`. **Decision:** a *separate* package from `packages/sdk` (not folded
  in) — the SDK stays a thin RPC/encoder client with no WASM dependency, so non-light-node consumers
  don't pull a WASM blob; the light client *depends on* the SDK for `projectBalance`/encoders and adds
  the verification layer. (Recorded in [ADR-0006](adr/0006-browser-light-node.md) Decision 1.)
- **`apps/`**: a verification UI route (Stage 1), the PWA shell (Stage 2), the native wrapper (Stage 3).

---

## 12. Determinism / privacy checklist (the gates will assert each)

1. `crates/runtime` is **untouched**; `dependency_free.rs` stays green; the WASM artifact is the same
   deterministic core (no float/wall-clock/networking crosses into it). *(reliability)*
2. There is **one** re-execution kernel; the WASM `state_root` matches the server follower's for a block
   corpus (AC-WB). *(reliability)*
3. Balances cross the WASM boundary as **decimal strings**, never JS floats; the live tick is exact
   integer `projectBalance`, re-anchored every verified block (I2). *(reliability)*
4. A served block is **always** re-executed + root-matched before its balance is shown; a mismatch is a
   **visible error**, never a number (I1/I4 on the client). *(qa, security)*
5. `verifyMode` defaults to `"full"`; header-only is explicit + labelled, never auto-selected. *(security)*
6. No private key, no passport byte, no PII ever leaves the device — only signed txs / a succinct ZK
   commitment (I6). Web Push payloads carry no PII. *(security)*
7. The WASM blob is integrity-pinned and reproducibly built; the verification badge is computed in-WASM,
   not in swappable JS. *(security)*
