# ubi2 Roadmap

Owned by the `product-strategist`. Milestones are sequenced to retire the riskiest assumptions with the
smallest demoable step. Each must be demonstrable end-to-end.

Legend: ✅ done · 🚧 in progress · ⬜ planned

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

## M5 — Network & Consensus 🚧 *(current)*
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
- **Stage A** — networking transport + block sync (one proposer, N followers): tx gossip, block broadcast,
  join-sync, `ubi_getPeers`. Closes FU-3 (persistence), FU-13.
- **Stage B** — distributed block production: rotating proposer, fork choice, proposer timeout + view
  change (crash-fault tolerant; BFT is backlog). Closes FU-8 (juror staking/rotation).
- **Stage C** — real cross-node AI quorum: `crates/juror` daemon on each node runs its own AI backend
  and submits signed verdict/effect txs independently. Closes FU-7.
- **Stage D** — hardening + multi-host testnet: soak, partition tests, observability (FU-4), mempool
  hardening (FU-1), oracle-URL SSRF fix (FU-12), public testnet with faucet and docs.

**Depends on:** M1–M4 (all shipped). FU-3 and FU-13 are prerequisites for Stage A.
**Milestone brief:** [`milestones/m5-p2p-network.md`](milestones/m5-p2p-network.md)

## M6 — ZK-Passport Proof of Humanity ⬜ *(leads; next milestone)*
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

**Staged delivery:** Stage A (ZK proof pipeline + CSCA registry, off-chain) → Stage B (on-chain
verifier + `submitZkPassportProof` op) → Stage C (app NFC flow) → Stage D (attribute verifier, over-18
template). **Depends on:** M5.

---

## Browser/Mobile Light Node ⬜ *(parallel track, does not block M6 or M7)*
**Goal:** a WASM-compiled light-node that runs in a browser or mobile app, syncs block headers,
verifies state proofs, and generates ZK-passport proofs locally (so passport NFC data never leaves
the device). This track is parallel: it can proceed alongside M6 and does not gate M7. Its primary
deliverable for M6 is the on-device ZK proof generation (Stage A of the light-node track feeds M6
Stage C). Full light-node sync and verification are a standalone capability.

**Exit criteria (light-node-specific):** a browser tab loads the WASM light node, syncs headers from
a full node, and verifies an account balance against a state proof without running a full node. The
ZK passport proof generator runs in-browser in under 60 seconds on a modern device.

**Milestone brief:** [`milestones/browser-lightnode.md`](milestones/browser-lightnode.md) *(to be authored on the `feat/zkpoh-lightnode-design` branch)*.
**Depends on:** M5 (for the header chain to sync against); WASM-compilable runtime (already enforced
by the build-level dependency test).

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
