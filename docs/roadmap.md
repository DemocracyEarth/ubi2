# ubi2 Roadmap

Owned by the `product-strategist`. Milestones are sequenced to retire the riskiest assumptions with the
smallest demoable step. Each must be demonstrable end-to-end.

Legend: ✅ done · 🚧 in progress · ⬜ planned

> **Immediate release override (2026-08-30): PoH Quick Launch v1 is the only shipping priority.** The
> dependency-ordered 14-day cut is in [`releases/poh-quick-launch-v1.md`](releases/poh-quick-launch-v1.md).
> It targets Self verification → sponsored soulbound mint → issuer-attested age/nationality/sanctions
> predicates on Base Sepolia. M5, M6 native, EVM ZK Identity v2, custom circuits/ceremonies, operator fleets,
> additional chains, M7 and M8 are paused as release dependencies. Their code and research remain in the
> monorepo, but none may block or silently enter Quick Launch. Mainnet is not authorized.

> **Freshness note (updated 2026-08-11):** M6 (ZK-Passport PoH) and the
> Browser/Mobile Light Node track — both listed below as ⬜ planned in the previous revision — have each
> shipped their first two stages (M6 Stages A+B; light-node Stages 1+2). See each section for exactly
> what shipped vs. what's still open. M5 Stage A also shipped; **M5 Stage B (rotating proposer + view
> change) is the recommended next milestone-level priority** — it is also the last prerequisite, via
> Stage C, for M6's cross-node ZK quorum (EC-7). See "Re-sequencing reality" in the sequencing rationale
> below for how M6's crypto shipped ahead of that dependency without violating it.
>
> **Product sequencing update:** EVM predicate development now goes directly from the live v1 issuer path to
> the reusable **ZK Identity v2** track below. v1 remains the fallback; v1.5 is reusable Self/Groth16
> infrastructure rather than a separate release. M5 Stage B remains the next native-chain consensus priority.

---

## M0 — Bootstrap ✅
**Goal:** a consolidated monorepo, the agent development loop, and seeded specs so the loop can run.
**Exit criteria:** team of 10 agents in place; `cargo build` green on the skeleton; wallet skeleton
builds; roadmap/board/specs seeded. **Why now:** nothing else can proceed without a process and a home.

## M1 — EVM RPC + Wallet ✅ *(shipped cycle 1)*
**Goal:** a devnet node exposing an **EVM-compatible JSON-RPC** that MetaMask can add as a custom
network, where a **verified account's balance streams upward at 1 UBI/hour**, plus a wallet + explorer.
**Why now:** a readable, standards-compatible chain is the integration surface that unblocks every
later feature; it also forces the deterministic time-based balance model early.
**Exit criteria:**
- MetaMask adds the devnet RPC and reads a verified account's balance climbing at 1 UBI/hr.
- Explorer renders blocks and transactions.
- E2E test asserts the RPC contract (`eth_chainId`, `eth_blockNumber`, `eth_getBalance`, `eth_call`,
  `eth_sendRawTransaction`, `eth_subscribe`).
**Spec:** [`specs/01-evm-rpc-and-wallet.md`](specs/01-evm-rpc-and-wallet.md)

## M2 — Streaming primitive ✅ *(shipped cycle 2)*
Delivered: collateralized 1:1 streams via StreamHub system-address txs (MetaMask-signable), live
net-stream balances, open/stop/refund, and **two ERC-721 stream NFTs per stream** (recipient + sender)
with a fully on-chain SVG card. 1:many fan-out, uncollateralized stream-through, and transferable streams
remain deferred. Spec [`02-streaming.md`](specs/02-streaming.md), [ADR-0003](specs/adr/0003-streaming-and-stream-nfts.md).
Original goal text:
**Goal:** account-to-account real-time streams (1:1, then 1:many) on top of the UBI drip, with the
safety controls (rate limits, collateralization, circuit breakers). **Exit:** a user opens a stream to
another account and both balances move in real time; safety limits demonstrated. **Depends on:** M1.

## M3 — AI Proof-of-Humanity ✅ *(shipped cycle 3)*
**Goal:** the LLM-based verification gate with a verifier quorum; only verified humans begin accruing
UBI. **Exit:** a human passes verification by quorum and starts streaming; a bot/duplicate is rejected;
verdict integrity holds against a hostile minority of verifiers. **Depends on:** M1. **Shipped:** social
vouching + AI-jury quorum (`HumanityHub`), deterministic on-chain lifecycle, real `ClaudeOracle`
(`ANTHROPIC_API_KEY`-gated) + `MockOracle` for the devnet, AI sybil auto-challenge, hardened against a
challenge-spam DoS. All gates green. Follow-ups: FU-7 (juror daemon for the real oracle on consensus),
FU-8 (M5 juror staking/rotation).

## M4 — Prompt Contracts ✅ *(shipped cycle 4)*
**Goal:** natural-language contracts parsed into canonical effects and committed by interpreter quorum,
with deterministic abort on disagreement. **Exit:** a plain-language contract executes reproducibly
across nodes; a prompt-injection attempt fails closed. **Depends on:** M2, M3. **Shipped:** a bounded
canonical **effect language** + escrow/least-authority **atomic apply** (I4/I6), an **interpreter quorum**
reusing the M3 tally (`ContractHub`), the `ClaudeInterpreter` (+ `MockInterpreter` for the devnet), and the
consolidated **UBI app** (wallet + block explorer + social/PoH hub + contracts). All gates green; injection
fails closed. Follow-ups: FU-9 (stranded-funds desync, before mainnet), FU-10/FU-11.

## M5 — Network & Consensus 🚧 *(current — Stage A shipped, Stage B next)*
**Goal:** multiple independent node processes form a real peer-to-peer network that gossips transactions
and blocks, agrees on block production via distributed consensus, syncs state when a node joins, and
keeps producing blocks when a node goes down. The AI proof-of-humanity and prompt-contract quorums are
evaluated by independent AI backends on independent nodes — not simulated in one process.

**Why now:** the chain is currently a single-node devnet. One process produces all blocks and runs all
AI quorum calls in-process. Every milestone from M6 onward — economic parameters, fee recycling,
governance, AI-provider rewards, public testnet — depends on a real multi-node network to be meaningful.
FU-15 (node-AI rewards) and the fee-recycling economics (M6) cannot be correctly specified until the AI
quorum they reward is a real multi-process quorum. This is the project's largest unretired engineering
risk and highest-leverage next step.

**Exit criteria (summary; full detail in [`milestones/m5-p2p-network.md`](milestones/m5-p2p-network.md)):**
- Three independent `ubi2-node` processes connect and report each other as peers.
- A tx submitted to node A is gossiped to nodes B and C before the next block.
- All three nodes agree on block height and state root within one block interval.
- After 20 blocks with transactions, all three nodes report byte-identical state roots.
- Block production rotates across at least 2 of 3 nodes over 30 blocks.
- Killing the current proposer does not halt the chain; the remaining nodes elect a successor.
- A late-joining node syncs from genesis to the tip without manual intervention and reaches identical
  state.
- A PoH verification quorum is evaluated by independent AI backends on independent nodes and commits
  on supermajority (with `MockOracle` in CI).
- A prompt-contract invocation is evaluated by independent AI backends on independent nodes; agreement
  commits, injected disagreement aborts deterministically.
- `eth_getBalance` at the same block height returns the same integer on all nodes (I2); state roots
  agree byte-for-byte (I1).

**Staged delivery:**
- **Stage A ✅ *(shipped, PR #13)*** — networking transport + block sync (one proposer, N followers): tx
  gossip, block broadcast, join-sync, `ubi_getPeers`. Verified live by the `m5_stage_a` multi-node
  acceptance test, now a required CI job (`multinode`). Closed FU-3 (persistence), FU-13.
- **Stage B ⬜ *(next — recommended next milestone-level priority)*** — distributed block production:
  rotating proposer, fork choice, proposer timeout + view change (crash-fault tolerant; BFT is backlog).
  Closes FU-8 (juror staking/rotation). **Spec:**
  [`specs/08-distributed-block-production.md`](specs/08-distributed-block-production.md) +
  [ADR-0007](specs/adr/0007-distributed-block-production.md).
- **Stage C ⬜** — real cross-node AI quorum: `crates/juror` daemon on each node runs its own AI backend
  and submits signed verdict/effect txs independently. Closes FU-7. Also the last prerequisite for M6's
  EC-7 (the ZK-passport proof evaluated by a real cross-node quorum, not a single node — see the M6
  section and "Re-sequencing reality" below).
- **Stage D ⬜** — hardening + multi-host testnet: soak, partition tests, observability (FU-4), mempool
  hardening (FU-1), oracle-URL SSRF fix (FU-12), public testnet with faucet and docs.

**Depends on:** M1–M4 (all shipped). FU-3 and FU-13 were prerequisites for Stage A (closed).
**Milestone brief:** [`milestones/m5-p2p-network.md`](milestones/m5-p2p-network.md)

## M6 — ZK-Passport Proof of Humanity 🚧 *(in progress — Stages A + B shipped, Stage C next)*

**Shipped (as of 2026-07-01):** Stage A (ZK proof pipeline + CSCA registry) and Stage B (on-chain
verifier + `submitZkPassportProof`) are both done: a **deterministic Groth16/BN254 verifier**
(`crates/zkpoh`) behind a trait seam (`MockZkVerifier` is the consensus default; the real
`Groth16Verifier` is opt-in and fixture-tested), fully wired into the chain (`submitZkPassportProof`, a
nullifier registry, `STD`/`ENH`/`DUAL` assurance levels, a governance-gated CSCA registry, opaque
Pedersen attribute commitments, `state_root` v2) — and, going beyond the original Stage A/B bar, the
**real Self `vc_and_disclose` verifying key pinned at genesis**, with a **genuine Groth16 proof verifying
at the real 20-signal public-input arity** (not a toy arity), plus a client SDK
(`packages/sdk/src/passport.ts`) and a wallet "Verify with passport (ZK)" entry point. (PRs #21, #23.)

**Remaining in this track:**
- **Stage C** (app NFC flow) — today a developer pastes a proof bundle by hand; the real on-device NFC
  scan → on-device proof generation isn't built. This is the point where this track converges with the
  Browser/Mobile Light Node track's Stage 3.
- **Stage D** (attribute verifier) — the over-18 verifier is scaffolded only; no real opening/range
  circuit yet.
- **Two pre-consensus prerequisites, tracked here so they aren't lost:** the `self_layout` slot-19
  reconciliation against Self's actual production circuit layout, and Self's production ceremony `.zkey`
  (today's genuine proof verifies under a pinned fixture VK; a proof under Self's real production
  verifying key is not yet in the open repo).
- **EC-7 (cross-node quorum) still depends on M5 Stage C.** Stages A/B prove the verifier is real,
  deterministic, and correctly wired on a single node. They do not yet prove it as an independent
  per-node quorum decision — that is exactly the property M5 Stage C exists to retire. See "Re-sequencing
  reality" in the sequencing rationale below.

**Goal:** harden sybil resistance with an optional, additive, privacy-preserving ZK proof path over
government-issued e-passports, while keeping the existing social-vouching + AI-jury path fully intact
and available for anyone without a passport.

**Why now (before DAOs):** the vouching + AI-jury path is probabilistic and game-able at scale — on a
free-money chain the economic incentive to sybil grows with network value. A nullifier-based uniqueness
proof (one-passport-one-human, cryptographically enforced) is the strongest available sybil-resistance
upgrade. DAOs and governance (M7) gate membership on PoH quality; building them on the hardened PoH
foundation makes them substantively trustworthy. Attribute commitments (citizenship, age bucket, expiry)
captured here give M7 DAOs real selectors without requiring users to re-verify.

**Inclusion constraint (non-negotiable):** ZK-passport is an optional, additive verification path,
never the sole gate. Humans without a passport continue to verify via vouching + AI jury at Standard
assurance level. Full UBI eligibility is unchanged for all verified humans regardless of level.

**Assurance-level model:**
- `STD` — vouching + AI-jury quorum (M3 path). Social attestation, probabilistic uniqueness.
- `ENH` — ZK-passport proof accepted by verifier quorum. Cryptographic nullifier, government-attested
  existence, attribute commitments (nationality bucket, age bucket, expiry).
- `DUAL` — both paths completed. Strongest assurance.

**Key exit criteria (full list in [`milestones/zk-passport-poh.md`](milestones/zk-passport-poh.md)):**
- A new user can verify via social vouching OR ZK-passport. Both yield `Verified` status.
- Submitting a ZK proof for the same passport from a second address is rejected chain-wide (nullifier
  uniqueness enforced).
- A valid test-passport proof is accepted; a tampered proof or untrusted CSCA root is rejected
  fail-closed (I4).
- After a successful proof, the chain stores: nullifier, attribute commitments, assurance level. It
  stores no name, document number, exact date of birth, or nationality in plaintext (I6).
- An existing STD-level human is unaffected; no regression in the M3 path.
- The ZK proof is verified by the cross-node quorum (M5 Stage C infrastructure); no single node alone
  commits. Agreement commits; injected disagreement aborts deterministically.
- A `verifyAttribute(address, 'over18')` call returns correct results without revealing the birth date.

**Staged delivery:**
- **Stage A ✅ *(shipped)*** — ZK proof pipeline + CSCA registry, off-chain.
- **Stage B ✅ *(shipped, PRs #21/#23)*** — on-chain verifier + `submitZkPassportProof` op.
- **Stage C ⬜ *(next in this track)*** — app NFC flow.
- **Stage D ⬜** — attribute verifier, over-18 template.

**Spec:** [`specs/06-zk-passport-poh.md`](specs/06-zk-passport-poh.md),
[ADR-0005](specs/adr/0005-zk-passport-poh.md).
**Depends on:** M5 Stage A (shipped — the substrate this track's chain integration sits on). EC-7
specifically depends on M5 Stage C (not yet started); Stages A/B did not need to wait for it.

---

## EVM ZK Identity v2 🚧 *(foundation started; parallel product track)*

**Goal:** one passport scan issues a portable private credential that can generate unlimited unlinkable,
consumer-bound ZK proofs on the holder's device. Initial policies cover age thresholds/ranges, nationality
and issuing-state sets, document expiry/assurance, one-person-per-context and short-lived sanctions status.
The NFT remains an optional public uniqueness/freshness anchor and stores no attributes.

**Current Stage 0:** [ADR-0010](specs/adr/0010-direct-v2-portable-zk-credential.md) and the full
[v2 spec](specs/10-evm-zk-identity-v2.md) define the privacy boundary, threat model, predicate matrix and
delivery gates. The SDK now has a versioned AES-GCM credential vault with WebAuthn-PRF/HKDF key wrapping,
tamper detection and multiple passkey key slots. It also pins canonical policy/presentation-binding hashes,
and `/verify` exposes an honest non-proof designer for all planned passport use cases. Production persistence
and v2 proof generation are not enabled yet.

**Stages:**
- **Stage 0 🚧** — architecture + encrypted portable-vault foundation and CI tests.
- **Stage 1 🚧** — policy/binding, private-credential ABI, scoped-nullifier preimage, and lossless 18-field
  public-signal layout are pinned with TypeScript/Solidity/Rust parity vectors. An isolated desktop circuit
  harness now measures issuer-signature, depth-32 registry, hybrid, and signature-plus-packed-status relations with
  pinned CI budgets and real Groth16 proof round trips. Issuer coordinates are privately and losslessly bound to
  `issuerKeyId`; the active
  leaf/path/root is bound to the private `statusId`, with revocation and stale/refreshed witness tests. A
  transport-neutral sparse-registry prototype now emits canonical unkeyed deltas, refreshes witnesses locally,
  verifies an independently accepted checkpoint, and feeds the exact circuit relation. Registry depths
  32/64/96/128 are now CI-pinned at 21,723/37,147/52,571/67,995 constraints with verified proofs; depth 96 is the
  current candidate to beat, not a selection. A real fresh-worker Chromium/WASM path now compares packed status
  with depth-96/128 sparse baselines. The packed proof verifies in 7.54 s with 90,308,608 B retained linear memory,
  versus 15.11 s / 214,368,256 B at sparse depth 96; its proving key is 49.8% smaller and retained prover memory is
  57.9% lower. Mid-range mobile is still unmeasured. The packed candidate uses a canonical signed 32-bit slot, 256
  revocation bits per chunk and a depth-24 root; it verifies at 27,157 constraints versus 31,843 for signature +
  depth-32 registry. Deterministic public multiproof/snapshot modeling cuts the holder witness floor from 3,140 B at
  depth 96 to 836 B and reduces
  three 100M/1B-population update workloads by 88.83%–95.93% versus depth-96 sparse batches. It is the status
  candidate to beat, not a selection. A separate pre-deployment issuance registry now constrains authorized
  monotonic `uint32` slot allocation and globally consumes registry-scoped duplicate keys/credential commitments;
  the local write is pinned at 129,886 gas. An immutable transitional Self bridge now binds a pinned off-chain
  proof decision to the subject, registry-scoped key, proof-bound holder commitment, issuer key, slot/epoch and
  verifier configuration through a short-lived EIP-712 authorization. A capability-authenticated refresh now
  recovers slot/epoch/expiry races for the transitional pre-commitment flow without retaining the raw Self
  nullifier or extending the original ten-minute verification window; the pinned holder-reference commitment
  candidate binds slot/epoch; ADR-0013 later selects recommit/rebind for a losing pre-allocation race. Bridge plus
  allocation costs 140,108 local gas. ADR-0014 now ratifies the issuer-authenticated production vault payload and
  private all-cohort depth-24 witness refresh contract without changing the frozen 18 signals; allocated
  reissuance remains blocked pending a separate registry supersession/nullifier-continuity decision. On-chain/native
  passport proof verification, public snapshot builder/distribution, runtime payload/refresh implementation,
  mobile proving, production ceremony and target-chain gas, and independent audits remain. The raw
  five-input arkworks fixture now verifies through the EVM BN254 precompiles at a pinned 230,657 gas with a
  2,211-byte runtime. A fail-closed governance prototype also pins additive circuit IDs/verifier codehashes and
  issuer-scoped monotonic roots with explicit overlap/revocation and irreversible retirement. Both remain
  research/pre-deployment inputs: the public fixture setup is not deployable and production ownership still
  requires a timelocked multisig. A strict 18-signal adapter now binds the actual consumer plus chain, permanent
  host, subject, action context, challenge, policy, credential epoch and scoped-nullifier mode; resolves the
  codehash-pinned circuit/issuer/root; and closes wallet-change replay through a prover-authenticated identifier.
  Host + adapter + registry + replay storage measures 92,066 gas for static policy and 92,377 gas for fresh dynamic
  status with a stub raw verifier. Proposed ADR-0011 now pins the status signal to the exact governed snapshot
  publication Unix time and maximum age; SDK/Solidity
  hashes match, the proof root must equal the exact policy root, and unknown, retired, future, mismatched or stale
  policies fail closed. Chain/registry-bound EIP-712 publication manifests now use strict parsing, canonical hash
  recomputation, signer recovery and the same inclusive freshness window; the trusted publisher remains an
  application configuration and manifest signatures do not authorize registry writes. A deterministic
  public-toxic-waste research circuit now implements the exact 18-input sanctions-clear ABI at 28,499 constraints,
  binds signed issuer/status/epoch data, derives the scoped nullifier and verifies all the way through governed
  replay storage. Its 3,349-byte verifier costs 331,699 gas and the full local Cancun path 419,219 gas; all 18 input
  mutations reject. This is reproducible research evidence, not a production circuit or setup. Independent circuit
  ratification, production ceremony, mobile and target-chain measurements, corrected-host testnet redeploy and
  audits remain.
- **Stage 2 🚧** — the one-time duplicate/slot registry, transitional Self bridge, bounded race recovery,
  allocation-bound packed-status publication/revocation transition, and deterministic fork-recoverable snapshot
  computation core are implemented with adversarial tests and circuit parity. Strict durable restore, bounded
  finalized-RPC ingestion, content-addressed EIP-712 envelopes and two-party root reconciliation are now implemented
  as reference tooling. A deployable single-writer operator, immutable artifact server, third-RPC fleet gate,
  end-to-end immutable retrieval check, non-overwriting offline-verifiable evidence bundle, reviewed-config trust
  binding, intrinsic restart/withholding/divergence evidence gate, systemd/drill runbooks, a secretless
  three-finalized-RPC deployment/topology preflight, a preflight-chained secretless per-host source/executable/
  keystore attestation, and a strict offline-reproducible manifest binding exactly two ready host records to
  authoritative timestamp and provider-independence receipt references are implemented. The manifest rejects
  secret-bearing inputs and explicitly makes no live-readiness or external-receipt-authenticity claim. The
  versioned holder-commitment candidate, Rust/WASM reference generator and sanitized SDK issuance transcript are
  pinned without changing public signals, ABI or status format and without promoting the measured Poseidon profile
  to production. An expiring one-shot SDK handoff now generates holder material,
  binds synthetic issuance evidence and seals an explicitly non-presentable reference payload through the
  encrypted vault; live persistence remains disabled. The strict ADR-0014 payload parser and one-job all-cohort
  Worker/client boundary now implement pre-decrypt trust validation, transferred PRF lifetime, fresh-IV
  witness-only resealing, bounded privacy errors and whole-envelope atomic CAS with adversarial resource/race tests.
  The circuit-native Rust/WASM refresh candidate now verifies the exact Poseidon commitment/root/path and
  Baby-Jubjub subgroup/key-id/Schnorr relations, derives sparse paths under real memory/cancellation limits and is
  packaged behind hash-pinned same-origin Worker loading plus pre-decrypt network lockdown; its independent-audit
  and production bits remain false. A production-header Chromium/PWA harness now covers exact Worker/WASM loading,
  CSP/Trusted Types, malicious service-worker substitution, extension/network boundaries, multi-tab IndexedDB CAS,
  synthetic crash/restart, authenticated backup restore and throttled emulated-mobile memory/cancellation. Both
  admission bits remain false. The real Proof of Humanity PWA now contains a testnet-flagged, explicitly
  production-ineligible holder vault step with WebAuthn-PRF enrollment/unlock/second-passkey ceremonies, atomic
  proof binding, encrypted empty-only recovery and account/session cancellation. Its production-build mobile
  Chromium drill uses a deterministic PRF API double and is not physical evidence. Independent hosting, real externally verified
  timestamp and provider-independence receipts, observed host attestations/actions and real paging/drills, the
  independent cryptographic/browser/source-to-WASM audits, representative physical-mobile native-passkey evidence,
  exact production-payload admission into the holder UX,
  allocated-credential supersession, and canonical
  testnet evidence remain.
  ADR-0013/0014 close the cryptographic profile, pre-allocation race, payload and private-refresh design decisions
  for implementation only. Its required dedicated CI gate watches every byte-exact contract input, pins the
  payload profile and reference circuit to the holder Worker, and preserves the browser's fail-closed production
  boundary until that implementation is admitted.
  A strict release manifest/preflight now records the independent audit, setup, mobile and per-chain evidence
  required for production, verifies exact live codehashes plus timelocked ownership, and emits only unsubmitted
  governance calldata; no current candidate satisfies that admission gate.
- **Stage 3 🚧** — the production-disabled local WASM refresh harness, atomic IndexedDB vault store, synthetic
  E2EE backup/recovery drills and the testnet-flagged real-PWA WebAuthn PRF/recovery UX are implemented. Native
  physical iOS/Android passkey/crash/recovery evidence, exact production-payload integration, representative mobile
  proving and independently audited multi-device recovery remain.
- **Stage 4 ⬜** — audited EVM verifier adapter, policy SDK and all-target-testnet integration.
- **Stage 5 ⬜** — independent audits, ceremony/reproducible artifacts, adversarial testnet and mainnet rollout.

**Mainnet gate:** no open Critical/High; circuit, Solidity and browser/vault reviews complete; reproducible
verifier bytecode; recovery/revocation/key-rotation drills; measured mobile proving and EVM gas budgets. L2s
ship before Ethereum L1 unless the recorded gas gate supports simultaneous release.

**Planning estimate (2026-08-16):** a canonical-testnet alpha is approximately **2–4 weeks**. A full v2 mainnet
release is approximately **14–20 focused engineering weeks**, or **4–6 calendar months** once independent audit and
ceremony scheduling are included: 1–2 weeks to close Stage 2, 3–5 weeks for holder prover/vault/recovery, 4–6 weeks
for production circuits/verifiers and all-target testnets, and 3–5 weeks for audits, remediation, ceremony and an
adversarial soak. Work can overlap, but the audit/ceremony and recovery/mobile gates cannot safely be compressed.
Audit availability and material findings can add roughly four weeks. This estimate is for the private portable v2
product, not a transitional trusted-bridge-only launch.

**Relationship to M6:** M6 proves passport uniqueness and attributes on the ubi2 native chain. This track
provides the portable holder credential and cross-EVM presentation layer. They should share passport roots,
encodings and test vectors where possible, but neither may silently inherit the other's trust assumptions.

---

## Browser/Mobile Light Node 🚧 *(in progress — Stages 1 + 2 shipped, Stage 3 next; parallel track, does not block M6 or M7)*

**Shipped (as of 2026-07-01):** Stage 1 (browser light node: sync/verify/read/sign) and Stage 2
(installable PWA) are both done. Delivered: `crates/runtime-wasm` (the WASM re-execution wrapper) + a WS
sync gateway on full nodes + `packages/light-client` (Stage 1); a shared `crates/exec` re-execution
kernel so the light client follows the **full chain** and matches `state_root` byte-for-byte
("re-execute-and-match, trust no server" — not header-only sync); and a real, openable browser PWA
(`apps/light-node`) with a **pinned, gateway-independent genesis anchor** and **always-on PoA proposer
enforcement**. (PRs #20, #24.)

**Remaining in this track:**
- **Stage 3** (mobile wrapper + on-device NFC + on-device ZK proof generation) — this is the delivery
  vehicle for M6 Stage C (see the M6 section above).
- **A pre-existing WS-gateway DoS-hardening gap** (slowloris / oversized-frame) that the security gate
  flagged and that is not yet fixed.

**Goal:** a WASM-compiled light-node that runs in a browser or mobile app, syncs block headers,
verifies state proofs, and generates ZK-passport proofs locally (so passport NFC data never leaves
the device). This track is parallel: it can proceed alongside M6 and does not gate M7. Its primary
deliverable for M6 is the on-device ZK proof generation (**Stage 3** of the light-node track feeds M6
Stage C). Full light-node sync and verification are a standalone capability.

**Exit criteria (light-node-specific):** a browser tab loads the WASM light node, syncs headers from
a full node, and verifies an account balance against a state proof without running a full node. The
ZK passport proof generator runs in-browser in under 60 seconds on a modern device.

**Milestone brief:** [`milestones/browser-light-node.md`](milestones/browser-light-node.md). **Spec:**
[`specs/07-browser-light-node.md`](specs/07-browser-light-node.md),
[ADR-0006](specs/adr/0006-browser-light-node.md).
**Depends on:** M5 Stage A (shipped — the sync protocol + WS RPC this track's Stage 1 connects to);
WASM-compilable runtime (already enforced by the build-level dependency test).

---

### Gate discipline evidence (Stage-2 security pass, 2026-07-01)

An adversarial security + reliability gate ran against the Stage-2 work above (M6 Stages A/B, light-node
Stages 1/2) and confirmed by proof-of-concept, then the team fixed, three HIGH-severity issues before
merge — not deferred to a follow-up:

1. **M6 nullifier malleability.** The on-chain nullifier registry keyed on raw proof bytes rather than
   the canonical mod-r field reduction, so one physical passport could be re-encoded to mint unlimited
   "unique" humans. Fixed with a canonicality guard that rejects non-canonical nullifier encodings before
   registry insert.
2. **Light-node had no pinned genesis / no proposer enforcement.** A lying WS gateway could hand the
   browser light node a fabricated genesis and proposer set, spoofing the whole chain to a user who
   believed they were verifying independently.
3. **Light-node couldn't reproduce a real seeded genesis against an honest gateway**
   (`StateRootMismatch`), which would have made "trust no server" undemonstrable even in the good-faith
   case.

Findings 2 and 3 were fixed together, via the pinned gateway-independent genesis anchor + always-on PoA
proposer enforcement now shipped in `apps/light-node`.

**Why this belongs in the roadmap, not just a report:** this is direct evidence the gate discipline is
retiring real risk, not rubber-stamping — first-pass Stage-2 code shipped with three exploitable bugs,
and the process caught all three before they reached anyone relying on this chain. Treat that as a
reason to expect (not merely tolerate) further findings in Stage C/D (NFC + mobile) and in M5 Stage B,
and to keep funding the gate at the same rigor rather than relaxing it once the crypto "looks done."

### Operator tooling (shipped)

CI (`.github/workflows/ci.yml`) gates every push/PR on three required jobs: `chain` (fmt/clippy/build/
test), `multinode` (the `m5_stage_a` multi-node acceptance test against a freshly built node binary —
this is what actually catches multi-process regressions a plain `cargo test` would miss), and
`interfaces` (pnpm build + typecheck across the TS packages/apps). The **`ubi` operator CLI** (CalVer
versioned, e.g. `2026.07.01`) now ships `ubi node` (presets: `devnet` / `lightnode` / `multi`), `ubi
genesis anchor`, and `ubi keys` — the reproducible harness the gates (and any operator) actually run,
replacing ad hoc shell invocations.

---

## M7 — DAOs & Governance ⬜
**Goal:** minimal, anti-capture governance over bounded parameters, and the first citizenship/attribute-
gated DAOs built on the hardened PoH + prompt contracts substrate. Node-AI rewards (FU-15) split
contract-invoke and verification fees to the actual quorum nodes. Demurrage + fee recycling tuned
against real multi-node fee flow.

**Why after M6:** DAOs gate membership on PoH quality. A DAO whose membership is backed by
nullifier-proven, government-attested unique humans is substantively sybil-resistant. Building DAOs
before M6 means either no real attribute gates (decorative DAOs) or retroactive re-verification of
all members. The attribute commitments and CSCA registry delivered in M6 are the DAO substrate. FU-15
(node-AI rewards) is also undesignable until the quorum is a real, identifiable set of independent
nodes (M5) with known fee flows to distribute.

**Exit criteria:** a parameter change passes via quadratic delegation on the M5 multi-node devnet;
fee-split to quorum nodes is visible on-chain; at least one attribute-gated DAO (e.g., over-18
membership) uses the M6 ZK attribute verifier; demurrage and fee recycling demonstrated on multi-node.
**Depends on:** M5, M6.

## M8 — Public Testnet ⬜
**Goal:** a hardened, observable shared testnet with a faucet and docs. **Exit:** external users join,
get verified (via either path), receive streaming UBI, and transact via standard wallets. **Depends
on:** M5 Stage D (multi-host hardening), M6, M7.

---

### Sequencing rationale

**M5 before M6 (ZK-Passport-PoH):** M6's EC-7 requires the real cross-node AI quorum (M5 Stage C).
The ZK verifier must run on a real multi-node network. Running it on a single-node devnet would simulate
the cross-node property rather than prove it, which is exactly the risk M5 exists to retire.

**Re-sequencing reality (as of 2026-07-01):** in practice, M6's crypto core (Stages A + B) shipped
*before* M5 Stage C — running ahead of the letter of the rule above. That is a legitimate exception, not
a violation of it: the deterministic Groth16 verifier is pure, dependency-free cryptography, correctly
tested and byte-reproducible on a single node exactly like the rest of `crates/runtime` — it needs no
multi-node network to *be real*. What the rule actually protects is EC-7 specifically (the proof
evaluated as an independent per-node quorum decision, not graded by one process alone), and EC-7 remains
explicitly gated on M5 Stage C. The critical path is unchanged and explicit: **M5 Stage B → M5 Stage C →
M6 EC-7 closes.** M5 Stage B is the recommended next milestone-level priority.

**M6 (ZK-Passport-PoH) before M7 (DAOs):** DAOs gate membership on PoH quality and depend on attribute
commitments that M6 delivers. Building DAOs before M6 yields membership lists with no cryptographic
uniqueness guarantee and no real attribute selectors — the defining properties of interesting DAOs are
absent. Hardening PoH first makes DAOs substantively trustworthy.

**Economics (demurrage, fee recycling, FU-15 node-AI rewards) into M7:** FU-15 rewards the quorum nodes
that did AI work — there is nothing to reward until M5 Stage C delivers independent nodes with
independent AI backends. Economic parameters should be calibrated against observed multi-node fee flow
(M5), not set on a single-node simulation. Both arguments that previously moved Economics from M5 to M6
now move it to M7, where it is bundled with the DAO governance that controls those parameters.

**Light-node track parallel to M6/M7:** the WASM light node does not block the ZK-passport on-chain
work. Its primary coupling to M6 is the in-browser ZK proof generator (M6 Stage C). The rest of the
light-node capability (header sync, state proofs) proceeds independently and feeds into the M8 public
testnet experience.

---

### Backlog (not yet scheduled)
BFT (Byzantine fault tolerance, active-adversary consensus) · full block explorer + chain indexer ·
real-time "dripping" UX polish · AI provider network token-for-compute marketplace · progressive
decentralization / parameter ossification · advanced mobile wallet · cross-chain bridge · advanced
stream composition (split/merge/marketplace) · DHT peer discovery · validator staking and slashing ·
additional ZK document types (national identity cards, residence permits) · citizenship-specific stream
gates · ZK attribute verifiers beyond over-18.
