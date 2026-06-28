# ADR-0006 — Browser & mobile light node: WASM the deterministic core, sync over a WS gateway that reuses `ubi2/sync/1`, verify by client-side re-execution

- **Status:** accepted (Browser & Mobile Light Node milestone — parallel track)
- **Date:** 2026-06-28
- **Deciders:** architect (this ADR) + product-strategist (milestone brief) — to be ratified by
  protocol-engineer, reliability-engineer, security-engineer at the Stage-1 gate.
- **Spec:** [`../07-browser-light-node.md`](../07-browser-light-node.md). **Milestone:** [`../../milestones/browser-light-node.md`](../../milestones/browser-light-node.md).
- **Builds on:** [`0004-consensus-and-networking.md`](0004-consensus-and-networking.md) (the sync protocol,
  wire formats, block header, and `state_root` this milestone consumes verbatim).
- **Does not change** any deterministic state transition in `crates/runtime`, nor any consensus rule.

These decisions are costly to reverse — the WASM API boundary, the light-client transport/wire reuse,
the "one re-execution kernel" rule, and the client trust model are all hard to change once a published
light client and gateways interoperate — so they are pinned here. Where the milestone brief gave a
recommendation, it is adopted unless a reason is stated.

---

## Context

The chain is reachable today only via a full node (Rust, cargo, a server). The milestone makes it
reachable from a **browser tab and a phone** as a *light node* that **verifies what it reads** rather than
trusting a server: it syncs blocks, re-executes them in WASM against the deterministic core, and asserts
a byte-identical `state_root` (the same guarantee an M5 server follower has). The hard constraint that
frames every decision is the structural rule from ADR-0004: **`crates/runtime` must stay deterministic
and dependency-free** — it has no floats, no wall-clock, no networking/async, and the build-level
`crates/runtime/tests/dependency_free.rs` guards it. Four decisions are load-bearing.

---

## Decision 1 — Boundary: WASM the *untouched* `crates/runtime` behind a thin wrapper crate; ship a separate `packages/light-client`

**Decision.**
- Compile **`crates/runtime` as-is** (untouched) to `wasm32-unknown-unknown`. It already satisfies the
  no-float/no-wall-clock/no-networking constraint, so it is WASM-ready by construction.
- Add a **new thin crate `crates/runtime-wasm`** holding only a `wasm-bindgen` wrapper that re-exports a
  bytes/JSON API (`applyBlock`, `stateRoot`, `balanceOf`, `nonceOf`, `humanStatus`, `tip`, `serialize`/
  `deserialize` — full signatures in spec §2.2). `crates/runtime-wasm` is the **only** new Rust artifact
  that may depend on `wasm-bindgen`/`serde-wasm-bindgen`/`getrandom`-js. `crates/runtime` keeps its empty
  `[dependencies]`.
- Add a **new TypeScript package `packages/light-client`** (the WS sync driver, the WASM glue, the
  IndexedDB store, the EIP-1193 signer) **separate from `packages/sdk`**. The light client *depends on*
  the SDK (for `projectBalance`, encoders, RPC types) and adds the verification layer on top.

**Rationale.**
- Wrapping the runtime untouched means the **same audited deterministic core** that consensus runs is the
  one a browser re-executes — no second balance/state implementation to drift (this is the whole point of
  a *verifying* light node). The brief's WASM-readiness claim is honored literally: we add a host, not a
  fork.
- Keeping `wasm-bindgen` out of `crates/runtime` preserves the dependency-free invariant and its
  build-level guard; the wrapper isolates the JS-interop deps exactly as `crates/network` isolates libp2p.
- A **separate** `packages/light-client` (vs. folding WASM into `packages/sdk`) keeps the SDK a thin
  RPC/encoder client with **no WASM blob** — non-light-node consumers (the existing wallet's RPC reads,
  CI tooling) must not be forced to download a multi-hundred-KB WASM artifact. This directly answers the
  brief's open question ("does WASM re-execution live in the SDK or a separate package?"): **separate.**

**Rejected.** (a) Adding `wasm-bindgen` to `crates/runtime` — breaks the dependency-free invariant and
its guard. (b) Re-implementing the state transition in TypeScript for the browser — guarantees drift from
consensus and defeats trustless verification. (c) Folding the light client into `packages/sdk` — taxes
every SDK consumer with a WASM dependency.

---

## Decision 2 — Transport: a WebSocket *sync gateway* on full nodes that reuses the M5 `ubi2/sync/1` payloads verbatim (not browser libp2p, not a bespoke JSON block API)

**Decision.** A browser cannot speak libp2p-tcp. The light node syncs over a **`wss://` sync gateway** on
full nodes that carries the **exact `SyncRequest`/`SyncResponse` bytes** M5 already defines (`Hello`,
`GetBlocks{from,to}`, `Blocks{[WireBlock]}` — spec 05 §4.2, `crates/network::wire`), just framed in
WebSocket messages instead of a libp2p request-response stream. The gateway is a thin adapter in
`crates/rpc` (which already runs a WS server for `eth_subscribe`); it translates a WS frame ↔ a
`SyncRequest`/`SyncResponse` and answers from the node's persisted block store. The canonical `WireBlock`
encoding (header + `txs_root`/`state_root`/`proposer`/`proposer_sig` + raw txs) crosses **unchanged**.

**Rationale (gateway-reuse vs. browser libp2p vs. bespoke API).**
- **Reusing `ubi2/sync/1` verbatim** means the browser re-executes and verifies **exactly what a server
  follower verifies** — same bytes, same `shallow_verify` (signed-proposer-only, SEC-M5A-1), same
  `recompute_txs_root`, same `state_root` check. There is **no second block serialization** to keep
  byte-compatible with consensus — that drift is the single biggest correctness risk and this avoids it.
- **vs. browser libp2p (js-libp2p / rust-libp2p→wasm over WebSockets/WebRTC):** rejected for Stage 1.
  Direct browser mesh peering is heavyweight, the WASM libp2p story is immature, and — decisively — it
  **does not change the trust model**: trustlessness comes from client-side re-execution, not from the
  transport. It is the documented long-term path (it removes the single-gateway availability dependency)
  and is recorded as backlog, not Stage 1.
- **vs. a bespoke JSON-over-WS block API:** rejected — a second block serialization to keep consistent
  with the consensus encoding, exactly the drift this milestone must avoid.

**Consequences.** The gateway is a **read-only** surface (plus an optional `SubmitTx` that feeds the
already-validated, rate-limited `ingest_raw_tx` path) — no admin/write authority (I6). Versioning rides
the existing `ubi2/sync/1` protocol string; a format change is a new protocol id, never a silent break.
A single gateway is an **availability** dependency (it can withhold, not forge — forgery is caught by
re-execution); multi-gateway cross-checking (Stage 2) and full browser gossip (backlog) progressively
remove it.

---

## Decision 3 — One re-execution kernel: the browser follower and the server follower are provably the same code

**Decision.** The block **execution kernel** — take `&mut MemState` + ordered raw txs + `block.timestamp`,
re-execute, recompute `txs_root`/`state_root`, accept only on byte-identical roots — has **exactly one
implementation** shared by `crates/rpc::Chain::validate_and_apply_block` (server follower) and
`crates/runtime-wasm` (browser follower). It lives in **`crates/runtime`** if it stays dependency-free, or
in a thin **`crates/exec`** crate (depending only on `runtime` + the tx-decode/ecrecover primitives the
browser needs, still no async/networking) that **both** `crates/rpc` and `crates/runtime-wasm` consume.
Preference: extract into `crates/exec` (or `runtime` if the decode crates stay light) so there is **no
logic fork**. A CI test (AC-WB) asserts the WASM `state_root` equals the server follower's for a corpus
of blocks — i.e. they are provably the same kernel.

**Rationale.** A verifying light node is only as trustworthy as the *equality* of its kernel to the
consensus kernel. Two implementations would inevitably diverge on an edge case (a rounding boundary, a
sweep tx, a hub op) and silently show a wrong-but-"verified" balance — the worst failure. One kernel +
a byte-identical-root CI gate makes that class of bug impossible by construction.

**Consequences.** If the kernel needs RLP decode + ecrecover (which `crates/runtime` does not currently
carry — `crates/network::wire` carries its own `recover_secp256k1`), those primitives move into the
shared kernel crate, keeping `crates/runtime` itself dependency-free. The acceptance gate (AC-WB) is a
hard, tested artifact.

---

## Decision 4 — Trust model: full client-side re-execution from genesis (or a signed checkpoint) is the default; header-only and state proofs are documented later optimizations, never silent

**Decision.** Stage 1's trust model is **full re-execution**: the light node re-derives every balance and
state root by re-executing every block and matching the header `state_root`; it trusts the gateway only
for **availability**, never for state. `verifyMode: "full"` is the **default and the only mode that
satisfies the verification exit criteria** (LC-2/LC-5). The light client labels blocks below
`FINALITY_DEPTH` (k=6) as provisional (M5 is k-deep PoA, CFT not BFT).

Three optimizations are documented as the future path and are **never auto-selected**:
- **Header-only sync** (verify the header/`proposer_sig`/`parent_hash` chain, trust the proposer's
  `state_root`) — a weaker, faster degraded mode (the brief's Risk-1 fallback for slow phones); opt-in,
  explicitly labelled "trusts proposer root".
- **Signed checkpoints** — a validator-quorum-signed `(height, state_root)` to start re-execution from a
  recent height, bounding from-genesis replay.
- **Fraud / validity (ZK) state proofs** — the strongest + cheapest end-state (verify a `state_root`
  transition without re-executing), and the natural convergence with the ZK-PoH proving stack. Far-future.

**Rationale.** Trustlessness is the milestone's entire value proposition; defaulting to anything weaker
than re-execution, or letting a downgrade happen silently, would let a malicious gateway slip a bad root
past the user — the failure the milestone exists to prevent. Making full re-execution the default and
every weaker mode explicit + labelled keeps the strong guarantee the norm and the trade-offs visible.

**Consequences.** Re-execution from genesis is bounded by IndexedDB persistence (resume from the last
verified height) and, later, by signed checkpoints. The UI's verification badge (green = re-executed +
root-matched; red = mismatch) is the user-visible expression of this model and is computed **in-WASM**,
not in swappable JS (a supply-chain mitigation).

---

## Status of invariants

- **I1 (deterministic effect over non-deterministic AI):** unchanged. The light node does **not** run the
  AI quorum (Stages 1–3); the optional Stage-4 juror reuses M5 Stage C's path and canonical-output
  contract verbatim. In-browser AI (WebLLM/WebGPU) is a far-future note only and never assumed by
  consensus.
- **I2 (reproducible integer balances):** extended to the client. The browser computes balances with the
  **same integer kernel** (Decision 3) and crosses the WASM boundary as decimal strings, never floats; the
  inter-block live tick is exact-integer `projectBalance` re-anchored on every verified block.
- **I3 (EVM compatibility):** unchanged. The light client uses standard `eth_*` for any server reads; the
  WS gateway only adds a block-range pull the browser re-verifies — no `eth_*` semantics change.
- **I4 (fail-closed):** on the client, a block whose re-executed root ≠ its header is **rejected with a
  visible error** — never rendered as a balance. An unsigned/forged-proposer block never verifies
  (SEC-M5A-1).
- **I6 (least authority / no PII):** the gateway is read-only (+ a validated submit path); no private key,
  passport byte, or PII ever leaves the device — only signed txs / a succinct ZK commitment; Web Push
  payloads carry no PII.

## Open follow-ups created by this ADR

- **Creates:** `crates/runtime-wasm` (the wrapper), the shared re-execution kernel (`crates/exec` or
  in-`runtime`), the WS sync gateway in `crates/rpc`, `packages/light-client`, and the AC-WB
  byte-identical-root CI gate.
- **Requires (dependency):** M5 Stage A's `ubi2/sync/1` + a WS surface and FU-3 persistence (the gateway
  serves from the persisted block store).
- **Joint with ZK-Passport PoH track (Stage 3):** the NFC data groups, proof schema, and HumanityHub
  extension contract (spec §8) — owned by the ZK-PoH track; this milestone is the delivery vehicle.
- **Defers to backlog:** full browser-side libp2p/WebRTC gossip; header-only/signed-checkpoint/ZK
  state-proof verification modes as a *replacement* for re-execution; in-browser AI quorum.
