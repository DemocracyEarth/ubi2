# ubi2 Task Board

The live work queue, maintained by the `orchestrator`. Tasks move between sections; history is not
deleted. A task is **Done** only when QA + reliability + security gates are green (see
[`loop.md`](loop.md)).

**Current milestone:** M5 — Network & Consensus (real P2P) · **Stage A shipped ✅ · Stage B next** · **M1–M4 + cycles 5–7 + PoH-NFT shipped ✅** · (Economics & Governance → M6)

| Field | Meaning |
|---|---|
| id | `M<milestone>-T<n>` |
| owner | the agent responsible |
| accepts | acceptance criteria (the bar for Done) |

---

## 🔜 Backlog

**M4 — Prompt Contracts** ([spec](specs/04-prompt-contracts.md)) — NL contracts, AI interpreter quorum (reuses M3)
- **M4-T5 · interface-engineer** — Consolidate the app into the **UBI on-ramp**: wallet + **full block explorer**
  (all blocks/txs/accounts, search, per-account history) + **social/PoH hub** (status, vouches in/out,
  vouch/challenge, pending cases, jurors) + **contracts** (author/deploy/fund/invoke). *Accepts:* full flow against devnet; builds green.
- **M4-T6 · qa-engineer** — Tests for the 6 M4 acceptance criteria (MockInterpreter). *Accepts:* each → passing test.
- **M4-T7 · reliability-engineer** — Interpreter-quorum determinism + effect-application reproducibility + abort-on-split. *Accepts:* two nodes agree.
- **M4-T8 · security-engineer** — Threat model + pentest: over-authority/escrow drain, interpreter prompt-injection,
  quorum/abort integrity, replay, privacy. *Accepts:* no open High/Critical.
- **M4-T9 · release-engineer** — CI + demo contract. *(likely inline)*

**Follow-ups carried from the gates — address before they bite**
- **FU-1 · protocol/security** — Mempool/registry hardening before any multi-node / non-localhost deploy:
  per-sender pending-balance accounting (M1 F1 + **M2-F2**, extend to stream deposits) + global/per-sender
  mempool caps (M1 F2) + **stream-registry caps (M2-F1)**. *Source:* security-m1/m2 reports. *Not a blocker (localhost).*
- **FU-2 · protocol/architect** — Decide the emission-rounding policy (carry remainder vs. document
  bounded loss) before M5 raises settlement frequency. *Source:* [ADR-0002](specs/adr/0002-emission-rounding-policy.md).
- **FU-3 · protocol** — State persistence/checkpoint behind the existing `State` trait (M1/M2 are in-memory).
- **FU-4 · reliability** — Two-node soak once consensus (M3 quorum) exists; metrics/observability.
- **FU-5 · protocol** — Stream-tx hygiene: reject non-zero `value` on StreamHub ops (M2-F3) and optionally
  reject `openStream` to `0x0` (M2-F4). *Source:* `docs/reports/security-m2.md`. *Low/Info, non-blocking.*
- **FU-6 · protocol/interface** — Stream-rate display precision: a "1 UBI/hr" stream flows at
  ⌊1e18/3600⌋/sec ≈ 0.99999…/hr ([ADR-0003](specs/adr/0003-streaming-and-stream-nfts.md)); decide card
  rounding + a finer `rate` granularity. *Source:* M2-T4 note. (TS test runner for the SDK/wallet too.)
- **FU-7 · ai/protocol** — Juror daemon for the REAL oracle on the consensus path: the node ships the
  deterministic `MockOracle`; `ClaudeOracle` exists + is fixture-tested but isn't wired into consensus
  (by design — the correct end-state is off-chain juror processes that call Claude and submit signed
  `submitVerdict` txs, not the node grading inline). Build the juror daemon (`ANTHROPIC_API_KEY`).
- **FU-8 · protocol/security (M5)** — Juror staking + rotation (M3 security Finding C, the fixed non-rotatable
  3-juror quorum) and the re-gate's LOW (system-scan cooldown can't auto-re-file under a fooled jury).
  *Source:* `docs/reports/security-m3.md`.
- **FU-9 · architect/protocol (before mainnet)** — Prompt-contract **stranded-funds desync** (M4 security
  Medium): a *plain* transfer to a contract's escrow **address** raises the account balance but not the
  tracked `contract.escrow`, so the funds are unmovable (footgun, not theft — can't over-draw/halt). Our app
  funds via `fundContract` so it doesn't hit this. Architect picks the fix (preferred: derive `contract.escrow`
  from `balance(escrow_addr)` — single source of truth; or reject plain transfers into ContractHub space).
  *Source:* `docs/reports/security-m4.md`.
- **FU-10 · protocol** — Per-invoke O(N log N) full exec-case scan at block production (M4 security Low):
  thread the `case_id` `invoke_contract` returns through `PendingKind::InvokeContract` instead of re-deriving
  by full-scan; also fixes effect-address mis-attribution when two invokes for one contract share a block.
- **FU-11 · protocol** — M4 Info cleanups: reject `value`-bearing non-fund ContractHub txs at ingestion
  (least-surprise); fix the `fnv1a_256` "eight lanes" docstring (4 lanes); document `MemState::accounts()`/
  `streams()` as unsorted (not on a consensus path today).
- **FU-12 · protocol/security** — Close the residual public-hostname **DNS-rebinding TOCTOU** on the OpenAI
  base_url (Info): resolve-once then dial-by-IP (pin the validated IP into the reqwest connector) so a
  rebind in the validate→dial window can't reach an internal host. *Source:* `docs/reports/security-c5.md`.
- **FU-13 · protocol** — Cycle-5 reliability Info: canonicalize `MemState::incoming()/outgoing()` stream-index
  ordering before any multi-node consensus compares snapshots; tidy the zero-balance TREASURY entry left by a
  rolled-back zero-gas onboarding op. *Source:* `docs/reports/reliability-c5.md`.
- **FU-14 · reliability/ops** — Add a `ubi2_failed_txs_mined_total{kind}` metric (and per-kind tx counters) for
  fleet-level alerting on abnormal failure rates. *Source:* `docs/reports/reliability-c6.md`. *Info, non-blocking.*
- **FU-15 · protocol/economics (M5)** — **Node-AI rewards:** split contract-invoke / verification fees from the
  treasury to the interpreter/verifier **quorum** that did the AI work (reward AI usage), seeding the AI-provider
  network; richer market/staking variants follow. *Requested by Santiago; folded into M5.*
- **FU-16 · protocol** — PoH-NFT security Low: add the 4-arg `safeTransferFrom` selector (`0xb88d4fde`) to the
  soulbound-revert match in `poh_nft_call` + the StreamHub `erc721_call`, so `eth_call` simulation fails closed
  like the real-tx revert (cosmetic — the real tx already reverts). *Source:* `docs/reports/security-poh.md`.
- **FU-17 · interface/security** — Harden NFT-card SVG rendering: the PoH + stream cards use
  `dangerouslySetInnerHTML` on the RPC-returned SVG (on-chain card is clean, but a hostile RPC could inject
  `<script>` = XSS). Render via `<img src=data:image/svg+xml;base64,…>` or DOMPurify. *Source:* `docs/reports/security-poh.md`.
- **FU-20 · protocol/security (M5 Stage D)** — Persistence integrity: `persist::from_snapshot` adopts
  `chain.json` verbatim; on load, recompute `state_root` from the loaded state + verify block-hash/parent
  linkage + the genesis anchor (defensible trusted-disk stance for Stage A). *Source:* `docs/reports/security-m5a.md`.
- **FU-21 · protocol/security (M5 Stage D)** — Eclipse hardening: inbound-connection cap + peer eviction/
  diversity once discovery (Kademlia) lands; Stage A static-bootstrap is not exposed. *Source:* `docs/reports/security-m5a.md`.
- **FU-22 · reliability/test-infra** — (a) migrate the remaining hard-coded-port RPC integration tests
  (m2_acceptance.rs etc.) to `TcpListener::bind(127.0.0.1:0)` to kill the parallel "Address already in use"
  flake (m5a tests already do this); (b) genesis block `state_root` header is `B256::ZERO` by design, so
  `ubi_stateRoot` at height 0 is uninformative — add a doc note / optional `ubi_inMemoryStateRoot`. *Source:* `docs/reports/{qa,reliability}-m5a.md`.
- **FU-18 · protocol** — `ubi_getRecentBlocks(nonEmptyOnly=true)` scans the unbounded blocks Vec under the
  consensus mutex (Low). Bounded by chain length on devnet + matches the existing O(N) read shape; future:
  side-index non-empty heights or cap the scan window. *Source:* `docs/reports/security-txui.md`.
- **FU-19 · protocol** — `ubi_getContracts.createdAt` is a raw `u64` while every other RPC timestamp is
  `hex_u64` (Info). Intentional (the SDK expects an integer) but inconsistent — document the deviation in the
  spec. *Source:* `docs/reports/reliability-txui.md`.

**Product backlog (field-test feedback · 2026-06-21 — verified live on an EVM wallet)**
- **EXPL-1 · protocol/interface** — A *proper* block explorer: browse all blocks, txs, and accounts,
  with search by hash/address and per-account history. Needs a node-side **address index** first
  (today `txs` is indexed by hash + block only, not by account) — i.e. a lightweight indexer behind the
  RPC, then a dedicated explorer UI (or split `apps/explorer` from `apps/wallet`).
- **UX-1 · interface (+ optional protocol)** — Real-time "dripping" UX. Note: accrual is **already
  continuous** (balance is a pure function of wall-clock time, not block-gated — the 2s tick only
  affects tx confirmation, not UBI growth), and the ubi2 wallet already interpolates per-frame via
  `projectBalance`. Levers left: (a) push freshness over a `newHeads`/balance subscription so the drip
  re-anchors faster; (b) accept that third-party wallets (MetaMask) poll on their own cadence and can't
  show a smooth drip — our own UI is where the feel lives. Largely solved; this is polish + a decision
  on whether to expose a balance-stream subscription.

## 🏗️ In Progress
- **ZKID-V2-T0 · architect/SDK/security** — direct-v2 architecture + portable encrypted credential-vault
  foundation. *Accepts:* predicate matrix and threat model documented; plaintext never persisted; AES-GCM
  tamper/binding failures tested; two independent passkeys unlock the same credential; SDK tests run in CI.
  Production UI persistence remains gated on WebAuthn ceremony, recovery and independent review.
- **ZKID-V2-T1 · architect/interface/SDK** — canonical policy + presentation-binding schema and expanded
  `/verify` v2 demo lab. *Accepts:* all documented passport use cases produce normalized deterministic policy
  hashes; chain/consumer/context/subject/challenge bindings are pinned; invalid ranges/roots/consent fail closed;
  the UI labels previews as non-proofs and preserves the separately live v1 verification flow. Compatibility
  slice complete: private-credential ABI, scoped-nullifier preimage, strict lossless 18-field public-signal layout,
  and TypeScript/Solidity/Rust parity vectors. The first isolated desktop circuit baseline now compares direct
  issuer signature, depth-32 active-registry membership, and their hybrid with pinned CI constraints and valid
  Groth16 round trips. Issuer coordinates are now privately/losslessly bound to `issuerKeyId`, and the active
  leaf/path/root is bound to `statusId` with revocation and stale/refreshed witness tests. A transport-neutral
  sparse-registry prototype now exercises activation/revocation, canonical unkeyed deltas, local batched witness
  refresh, trusted-checkpoint matching, and exact-circuit compatibility. Remaining: mobile/browser, alternate
  hash/proof-system, EVM gas, root governance, durable transport/privacy hardening, and the measured ADR.

## 👀 Review (awaiting gates)
_(none)_

## ⛔ Blocked
_(none)_

## ✅ Done
- **Cycle 7 · tx-confirmation + explorer + contract-UX · SHIPPED.** All gates green (446 tests). Fixed the
  field-test bug where MetaMask showed mined txs as **"Dropped"** (the chain advertises baseFeePerGas, so
  MetaMask sends EIP-1559 type-2 txs; `tx_to_json`/`receipt_to_json` hardcoded `type:0x0` + dropped the 1559
  fields, so MetaMask read the returned tx as a different one taking the nonce — now emits the real signed type
  + caps). Real explorer routes `/tx /block /address /account` (+ friendly "rejected before inclusion" panel,
  no bare 404). Two read-RPCs (`ubi_getRecentBlocks` non-empty filter, `ubi_getContracts` directory). Five UI
  items: non-empty-blocks toggle, **AI/Settings as a nav section** (active provider + masked key), template
  **suggestion chips + tags**, **parties-field** clarity (real placeholders, ≥1-party rule), contract
  **detail/interact + an explorer contracts directory + Contract badge**. Reports `docs/reports/*-txui.md`.
  Follow-ups: FU-18/FU-19.
- **Proof-of-Humanity NFT + branding · SHIPPED.** All gates green (415 tests). A **soulbound ERC-721 "Proof of
  Humanity"** on HumanityHub — every Verified human owns one (`tokenId = uint160(address)`; mint/burn on
  Verified↔not-Verified; transfers revert) with a **fully on-chain card** (the fingerprint mark in the yellow→pink
  gradient + address/date/vouches/reputation), viewable + importable in MetaMask. All PoH/Identity UI re-skinned in
  the official **Proof-of-Humanity palette + logo** (scoped; the rest of the app keeps UBI-green/violet). Gates:
  soulbound unbypassable, view surface panic-free, determinism + ownership/log consistency proven. Reports:
  [`docs/reports/`](reports/) (`*-poh.md`). Follow-ups: FU-16/FU-17 (Low).
- **Cycle 6 — Contracts depth, vouch fix & docs · SHIPPED.** All gates green (380 tests). Fixed the
  **failed-tx / perpetual-pending / nonce-too-high** bug (failed ops now mine with a `status 0` receipt + reason
  + consumed nonce); put the **contract NL text on-chain** (`ubi_getContract` returns text + deploy block/tx +
  cases); a **contract template library** + authoring UX + a **detail/interact page**; a **mock-AI banner**, the
  **explorer link in add-network**, the **vouch UX** (valid targets + visible reasons); and a rewritten **README**
  + a node-builder **`SKILL.md`**. Security gate caught + the loop fixed a **High** (unbounded contract-text DoS →
  8 KiB cap + size-metered deploy gas). Reports in [`docs/reports/`](reports/) (`*-c6.md`). Follow-up: FU-14.
- **Cycle 5 — Productionize & polish · SHIPPED.** All gates green (342 tests). Native **UBI gas fees** on every
  tx (treasury `0x…5542`, per-kind gas, onboarding fee-exempt — fixes the MetaMask vouch/deploy stall; seeds M5
  fee-recycling); a **configurable LLM backend** (Anthropic/Ollama/OpenAI) with a loopback-only oracle-config
  RPC; a **deep block explorer** (`ubi_getBlock`/`ubi_getTransaction` fully decoded); and the **"obsidian glass"
  redesign** (wallet + explorer + social + contracts + Settings). Security gate caught + the loop fixed a
  CRITICAL key-exfil (`base_url` SSRF) + 2 HIGH (admin CSRF/rebinding, live-backend DoS) before merge.
  Reports in [`docs/reports/`](reports/) (`*-c5.md`). Follow-ups: FU-12, FU-13.
- **M4 — Prompt Contracts · SHIPPED (cycle 4).** All gates green. ([spec](specs/04-prompt-contracts.md))
  - **M4-T1 · architect** — Spec: NL contracts → canonical **effect language** executed by an **interpreter quorum** (reuses M3), escrow/least-authority (I6), deterministic abort (I1/I4), `ContractHub`, the app-consolidation.
  - **M4-T2 · protocol-engineer** — Contract runtime: effect language + escrow/least-authority **atomic apply**, `PromptContract`/`ExecCase`, generalized `quorum_tally` (shared w/ M3), `ContractInterpreter` trait + `MockInterpreter`, derived escrow addresses.
  - **M4-T3 · ai-engineer** — `ClaudeInterpreter` (structured-output effect schema, temp-0, injection-fenced; `ANTHROPIC_API_KEY`-gated, fixture-tested).
  - **M4-T4 · protocol-engineer** — `ContractHub` (`0x…5043`) txs + `ubi_getContract`/`getExecCase`/`getContractsOf` + **EXPL-1 address indexer** (`ubi_getAddressActivity`/`getAccount`). Orchestrator-verified live (deploy→fund→invoke→commit).
  - **M4-T5 · interface-engineer** — The consolidated **UBI app**: nav + Wallet · Explorer (search/account/activity) · Identity (social/PoH hub) · Contracts (author→deploy→fund→invoke); SDK `contracts.ts` + `explorer.ts`.
  - **M4-T6 · qa** — ✅ 6/6 acceptance criteria → tests. **M4-T7 · reliability** — ✅ interpreter-quorum determinism + atomic-apply reproducibility (10k/5k iters). **M4-T8 · security** — ✅ PASS, no High/Critical; escrow/least-authority + injection + quorum/abort + replay + privacy intact (6 PoCs). Reports in [`docs/reports/`](reports/). 258 tests.
- **M3 — AI Proof-of-Humanity · SHIPPED (cycle 3).** All gates green. ([spec](specs/03-proof-of-humanity.md))
  - **M3-T1 · architect** — Spec: social vouching + AI-jury quorum, on-chain lifecycle, `HumanityOracle` trait + determinism (I1), privacy (I6), 8 acceptance criteria.
  - **M3-T2 · protocol-engineer** — On-chain substrate: `Human`/`Vouch`/`Case`/`Juror` registries, deterministic lifecycle state machine, quorum tally, vouch graph, `Verified` emission gating, `MockOracle`.
  - **M3-T3 · ai-engineer** — `crates/oracle` `ClaudeOracle`: real `HumanityOracle` via the Anthropic API (forced structured output, temp-0, injection-resistant); `ANTHROPIC_API_KEY`-gated, fixture-tested (I5).
  - **M3-T4 · protocol-engineer** — `HumanityHub` (`0x…5048`) txs + `ubi_*` reads + block-time lifecycle + auto-finalize + sybil sweep + receipt logs + seeded jurors. Orchestrator-verified live (verify→stream, sybil→revoke).
  - **M3-T5 · interface-engineer** — Wallet "Proof of Humanity" card (status/vouches/apply/vouch/challenge/pending cases) + SDK helpers. Builds + typecheck green.
  - **M3-T6 · qa** — ✅ 8/8 acceptance criteria → tests. **M3-T7 · reliability** — ✅ I1/I2 determinism over 10k–50k-iter property tests. **M3-T8 · security** — ✅ PASS after fixing a HIGH challenge-spam DoS (Finding A) + Findings B/F-REL-1/F-REL-2/D. Reports in [`docs/reports/`](reports/).
  - **M3-T9 · release** — CI covers the oracle crate; node ships deterministic `MockOracle` (see FU-7). *(inline)*
- **M2 — Streaming primitive · SHIPPED (cycle 2).** All gates green. ([spec](specs/02-streaming.md), [ADR-0003](specs/adr/0003-streaming-and-stream-nfts.md))
  - **M2-T1 · architect** — Spec: collateralized 1:1 streams, StreamHub system-address txs (EVM-signable), live net-stream balances (I2), open/stop/refund, **two ERC-721 stream NFTs** with on-chain SVG card.
  - **M2-T2/T3 · protocol-engineer** — Stream runtime + StreamHub RPC (tx parsing, `ubi_getStream(s)`) + ERC-721 precompile (`ownerOf`/`tokenURI`/…) minting recipient + sender NFTs with the on-chain card. Orchestrator-verified live.
  - **M2-T4 · interface-engineer** — SDK stream helpers (viem) + wallet "Send a stream" + Active streams (live tick, Stop) + NFT card render + "Add NFT to MetaMask". Builds + typecheck green.
  - **M2-T5 · qa-engineer** — ✅ PASS: 8/8 acceptance criteria → tests; 55 cargo tests. `docs/reports/qa-m2.md`.
  - **M2-T6 · reliability-engineer** — ✅ PASS: stream-balance determinism + solvency (200k iters) + bounded conservation + `tokenURI` byte-identical (40k). `docs/reports/reliability-m2.md`.
  - **M2-T7 · security-engineer** — ✅ PASS: no High/Critical; solvency/deposit/soulbound/replay integrity held under pentest. 2 Medium → FU-1, 2 Low/Info → FU-5. `docs/reports/security-m2.md`.
  - **M2-T8 · release-engineer** — `clientVersion`→m2, `t_end` saturating fix (F2). CI green. *(inline)*
- **M0 · all** — Monorepo + 10-agent loop + seeded specs/roadmap/board scaffolded. *(bootstrap commit)*
- **M1 — EVM RPC + Wallet · SHIPPED (cycle 1).** All gates green.
  - **M1-T1 · architect** — Spec finalized (emission arithmetic, `State`/`Verifier` traits, chainId `0x5542`, EIP-155 txs, 2s tick).
  - **M1-T2/T3/T4 · protocol-engineer** — Rust node + EVM JSON-RPC (HTTP+WS) + devnet; streaming `eth_getBalance`, EIP-155 `eth_sendRawTransaction`, block tick. Orchestrator-verified live.
  - **M1-T5/T6 · interface-engineer** — TS SDK + Next.js wallet/explorer; balance ticks up via rAF interpolation; "Add to MetaMask" card. Both builds green.
  - **M1-T7 · qa-engineer** — ✅ PASS: all 5 acceptance criteria → passing tests; 28 cargo tests + E2E script. `docs/reports/qa-m1.md`.
  - **M1-T8 · reliability-engineer** — ✅ PASS: I2 determinism proven (50k random timelines); no nondeterminism. `docs/reports/reliability-m1.md`.
  - **M1-T9 · security-engineer** — ✅ PASS: no open High/Critical; signature/replay + balance integrity held under pentest. 2 Medium hardening follow-ups (→ FU-1). `docs/reports/security-m1.md`.
  - **M1-T10 · release-engineer** — `rust-toolchain.toml` pin, `scripts/devnet.sh`, `.github/workflows/ci.yml`. *(done inline by orchestrator)*
