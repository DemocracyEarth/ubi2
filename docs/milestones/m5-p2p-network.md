# M5 — Network & Consensus (Real P2P)

**Branch:** `feat/m5-p2p-network`
**Status:** defined (docs-only; implementation begins next cycle)
**Owned by:** product-strategist (this doc) → architect (spec) → orchestrator (decompose)

---

## Why this milestone exists before Economics & Governance

The whitepaper's core claim is a *decentralized* UBI chain secured by a *network* of verified-human
nodes. Every milestone through M4 was built, correctly, as a single-node devnet: one process producing
all blocks, one process running all AI quorum calls in-process. That was the right order for retiring
AI-correctness and EVM-compatibility risk first.

But the remaining roadmap depends on multi-node reality in ways that make sequencing it before M6
Economics & Governance non-negotiable:

1. **FU-15 (node-AI rewards):** fee-splitting to the AI quorum that did the work is meaningless — and
   its economics are undesignatable — until there is a real, identifiable quorum of independent nodes
   to reward. Writing economic parameters for a system where all "quorum" work is done in-process by
   one node rewards nobody.

2. **Fee recycling and demurrage tuning** need a real mempool and real multi-node fee flow to stress the
   economic parameters. On a single node they are trivially satisfied.

3. **Governance over bounded parameters** is most meaningful when those parameters govern a real
   multi-node network. Governance on a single node is theatre.

4. **The hardest invariant (I1: deterministic quorum)** is currently satisfied in a single process. It
   has never been proven across independent processes with independent AI backends. That is the project's
   biggest unretired engineering risk. Deferring it past Economics introduces compounding risk: we will
   have specified economic parameters whose correctness depends on a quorum behavior we have not proven
   works across independent processes.

Conclusion: do Network & Consensus (M5) now; Economics & Governance becomes M6 with real multi-node
fee-flow to validate its parameters. All follow-ups that reference M5 (FU-8, FU-15) are
naturally resolved in or after M5.

---

## User-facing goal

A human opens MetaMask on one of three independent node processes. They submit a transaction — a
transfer, a vouch, a contract deployment. That transaction is gossiped across all three nodes, included
in a block produced by whichever node is the current proposer, and within seconds the human sees an
identical balance on all three nodes. If the proposer goes down, block production continues. If a new
node joins, it syncs to the tip and begins participating without manual intervention. The AI
proof-of-humanity quorum and the prompt-contract quorum are evaluated by independent AI backends on
independent nodes — not one process pretending to be a quorum.

---

## Exit criteria (testable, user-facing framing)

The following must all be demonstrable on a single host (multi-process) before M5 is done. The
architect will operationalize each into a test assertion.

**EC-1 — Multi-node devnet forms.**
Three independent `ubi2-node` processes start with distinct ports, connect to each other via a
configured peer list, and exchange a handshake. A `ubi_getPeers` (or equivalent) call to any node
returns the other two as connected peers.

**EC-2 — Transaction gossip.**
A tx submitted via `eth_sendRawTransaction` to node A appears in the mempool of nodes B and C within
2 seconds (before any block is mined). The transaction is not re-submitted by the test — it is
gossiped.

**EC-3 — Block sync.**
When the current proposer mines a block, nodes B and C receive and apply it, and `eth_blockNumber`
agrees across all three within one block interval (~2 s). `eth_getBalance` returns the same value on
all three nodes at the same block height.

**EC-4 — Identical state roots.**
After 20 consecutive blocks containing transactions, all three nodes report the same state root
(via `eth_getBlockByNumber` or an equivalent `ubi_stateRoot` RPC call). Byte-for-byte agreement
is required; any divergence is a test failure.

**EC-5 — Rotating block production.**
Over 30 blocks, block production is distributed across at least 2 of the 3 nodes. No single node
produces all blocks. (Simple round-robin or PBFT-lite is sufficient for Stage B; the spec defines
the exact algorithm.)

**EC-6 — Liveness under a downed proposer.**
The current proposer process is killed (SIGKILL). The remaining two nodes elect a new proposer and
continue producing blocks within 3 proposer timeouts. The chain does not halt.

**EC-7 — Late-joiner sync.**
A fourth node starts with no state (empty genesis sync) and connects to the three-node network. It
syncs all blocks from genesis to the current tip without manual intervention and reaches the same
state root as the established nodes. Subsequent transactions are visible to it.

**EC-8 — Cross-node AI quorum (PoH).**
A human submits a `requestVerification` to node A. Each of nodes A, B, and C runs its own AI backend
(using `MockOracle` in CI, `ClaudeOracle` in the live demo). Each independently calls
`submitVerdict`. The on-chain tally reaches supermajority and the human transitions to `Verified`.
No single node's AI backend alone is sufficient.

**EC-9 — Cross-node AI quorum (prompt contract).**
A prompt contract is invoked on node A. Each of nodes A, B, C independently interprets the
contract and calls `submitEffect`. On agreement, the effect commits. On injected disagreement (one
node's mock returns a divergent effect), the contract aborts deterministically. Both paths are
tested.

**EC-10 — Determinism invariant holds across nodes.**
`eth_getBalance` for the same address at the same block height returns the same integer on all nodes
(I2). The state root after block N on node A equals the state root after block N on node B and C
(I1). This is asserted by an automated test, not eyeballed.

---

## Staged delivery

### Stage A — Networking foundation + block sync (one proposer, N followers)

Goal: a real network exists; blocks and transactions move across it; state is shared. Block production
is still deterministic (one seeded proposer) to isolate the networking risk from the consensus risk.

Deliverables:
- A peer-to-peer transport layer in `crates/node` (libp2p or a bespoke TCP gossip; architect decides).
- Transaction gossip: a tx received by any node is forwarded to all connected peers (with dedup).
- Block broadcast: the proposer broadcasts a signed block; followers validate and apply it.
- Block sync on startup: a joining node requests blocks from a peer from genesis (or a checkpoint) to
  the tip.
- `ubi_getPeers` RPC call returning connected peer addresses + block heights.
- CI: a three-process integration test asserting EC-1, EC-2, EC-3, EC-4.
- Multi-node devnet script (`scripts/devnet-multi.sh`) that launches 3 nodes on localhost.

Exit: EC-1, EC-2, EC-3, EC-4 pass. EC-7 (late-joiner) also targeted here.

Addresses: FU-3 (state persistence/checkpoints, required for sync), FU-13 (stream-index ordering,
required before cross-node snapshot comparison).

### Stage B — Distributed block production and consensus

Goal: no single hardcoded proposer; the chain is **crash-fault-tolerant (CFT)** — production rotates across
a validator set and does not halt when a proposer goes down. **BFT (tolerating an actively-malicious
proposer/majority) is explicitly out of scope and on the backlog** (Risk 3, below).

Specified in full in [`../specs/08-distributed-block-production.md`](../specs/08-distributed-block-production.md);
load-bearing decisions in [`../specs/adr/0007-distributed-block-production.md`](../specs/adr/0007-distributed-block-production.md).
The chosen mechanism (all deterministic — I1/I2 hold through rotation and view change; local clocks drive
only liveness, never committed state):

- **Validator set + round-robin schedule.** `V` = PoH-gated validators (registered validator ∧ `Verified`
  human), sorted, snapshotted at epoch boundaries (committed to `state_root`). The scheduled proposer for a
  block is the pure function `proposer(height, view) = V[(height + view) mod N]` — every node computes it
  identically from on-chain state. Membership changes take effect at the next epoch boundary.
- **Block header gains a `view` field** (the one consensus-relevant, minimal wire change; committed in the
  header hash + signature). No BFT-style vote messages are added.
- **Proposer timeout + view change.** A local per-height timer: if the scheduled proposer does not deliver
  within `PROPOSER_TIMEOUT`, the node advances `view` and the next validator (`view+1`) becomes the
  legitimate proposer — authorized purely because `(height, view)` makes it the scheduled proposer. A
  minority partition stalls (a local "produce only when connected to a majority of `V`" guard) rather than
  finalizing a divergent chain.
- **Fork choice** = longest valid chain → lowest tip `view` → lowest tip `hash` (a deterministic total
  order, so all honest nodes converge on one chain; a late original proposer re-converges via the
  lowest-view tiebreak). **Commit/finality** is k-deep probabilistic (not BFT single-slot finality).
- **FU-8 (validator/juror membership + rotation)** is delivered here, managed by the same epoch-snapshot
  mechanism as the proposer set; equivocation is handled enough not to split honest nodes plus epoch
  eviction (stake-slashing is backlog).
- **CI** kills the current proposer mid-run (and restarts it) and asserts EC-5, EC-6 (plus the spec's
  EC-B1…EC-B6 / EC-B-F3…F5), while the Stage-A `m5_stage_a` harness stays green (the single-proposer config
  is the `N = 1` degenerate rotation — Stage A is Stage B with one validator).

A single-validator config degenerates exactly to Stage A (one fixed proposer, no view changes).

Exit: EC-5, EC-6 pass in addition to Stage A criteria.

### Stage C — Real cross-node AI quorum

Goal: PoH verdicts and prompt-contract effects are produced by independent AI backends on independent
nodes, not simulated in one process.

Today the "quorum" works as follows: juror *addresses* (seeded at genesis) submit `submitVerdict` /
`submitEffect` transactions to the hub contracts. In the single-node devnet, all of those txs are
originated by code running in the same process. The on-chain tally is correct — but it is not a real
multi-party quorum.

In Stage C, each participating node runs a juror daemon (FU-7: the juror daemon for the real oracle)
that monitors the chain for open `Case` and `ExecCase` entries, calls its own AI backend, and submits
a signed verdict or effect tx. The on-chain tally aggregates across genuinely independent calls.

Deliverables:
- `crates/juror` daemon (or a sub-command of `ubi2-node`): watches the chain, calls the local AI
  backend, submits `submitVerdict` / `submitEffect` txs. Uses `MockOracle` / `MockInterpreter` in CI,
  real backend in the live demo.
- Each node in the multi-node devnet runs its own juror daemon (or has it enabled as a flag).
- CI tests: EC-8, EC-9 — gossip the open case, assert each node submits its own verdict/effect, assert
  supermajority commits and disagreement aborts.
- FU-7 is closed by this stage.

Exit: EC-8, EC-9 pass in addition to Stage A+B criteria.

### Stage D — Hardening + real multi-host testnet

Goal: the chain runs on multiple physical machines / VMs, survives network partitions, and is
observable.

Deliverables:
- NAT traversal / external address announcement (peers on different hosts can find each other).
- Soak test: 72-hour run with simulated packet loss and node restarts; no state divergence.
- Network partition test: partition 1-of-3 nodes for 30 s, heal, assert re-sync.
- FU-1 (mempool hardening): per-sender pending-balance accounting + global caps — mandatory before
  any non-localhost deploy.
- FU-4 (two-node soak + metrics/observability): Prometheus metrics on block height, peer count,
  mempool depth, quorum participation rate.
- FU-12 (DNS-rebinding TOCTOU): close the oracle-URL SSRF before multi-host deploy.
- A public multi-host testnet with a faucet and docs (absorbing what was M6 in the old roadmap).

Exit: EC-1 through EC-10 pass on a multi-host network; soak passes; the original M6 public-testnet
exit criterion is met.

---

## Dependencies

- M1-M4 + PoH-NFT + cycles 5/6/7 shipped (all done).
- FU-3 (state persistence) must be done in Stage A — sync without persistence is not meaningful.
- FU-13 (stream-index ordering) must be done before Stage A's state-root comparison test.
- FU-1 (mempool hardening) must be done before Stage D (multi-host).
- FU-7 (juror daemon) is delivered as Stage C's primary artifact.
- FU-8 (juror staking/rotation) is best scheduled in Stage B alongside proposer-set management.
- FU-12 (DNS-rebinding) must be done before Stage D.

---

## Risks and why it is worth the cost

**Risk 1 — I1 breaks across independent processes.**
The deterministic quorum invariant has only ever been proven in a single process. Across processes
with independent AI backends, non-determinism could creep in through model version drift, timing,
or serialization differences. This is the highest-severity unretired risk in the project. Addressing
it now, before economic parameters are designed on top of it, is strongly preferred.
Mitigation: the `MockOracle` / `MockInterpreter` path is already deterministic by construction;
the cross-node tests use it in CI. The real AI path is pinned (temperature 0, model pin, canonical
schema). Stage C proves the real path works across independent processes.

**Risk 2 — Networking adds a new attack surface.**
Peer-to-peer networking introduces Eclipse attacks, Sybil peers, and amplification vectors.
The security-engineer gate must threat-model the gossip and sync protocols explicitly.
Mitigation: Stage A uses a small, auditable transport; FU-1 closes the mempool surface before
multi-host; FU-12 closes the oracle-URL surface.

**Risk 3 — Scope creep into BFT.**
Full Byzantine Fault Tolerant consensus is a multi-year project. This milestone targets
crash-fault tolerance (CFT) for Stage B — a downed node does not halt the chain — with a
well-understood rotating-proposer protocol. BFT hardening (tolerating actively malicious nodes)
is a later milestone.
Mitigation: the architect's ADR must scope Stage B explicitly to CFT. BFT goes to the backlog.

**Risk 4 — FU-3 (persistence) is larger than estimated.**
The current `State` trait is in-memory only. Persisting and replaying state for sync is non-trivial.
Mitigation: Stage A scopes sync to a full replay from genesis (simple, correct). Checkpoint-based
sync is a Stage D optimization.

**Why the cost is worth it:** a UBI chain that runs on one process is not a UBI chain — it is a demo.
The whitepaper's promise (a network of verified-human nodes, no single point of control) cannot be
delivered without this work. Every subsequent milestone — economics, governance, public testnet,
AI-provider network — is either meaningless or inaccurate on a single-node chain. This is the most
leveraged milestone remaining.

---

## What this milestone does NOT include

The following are explicitly out of scope and pushed to the backlog or M6:

- BFT (Byzantine fault tolerance against actively malicious proposers). Stage B is CFT only.
- Token-incentivized peer recruitment / peer staking.
- Cross-chain bridge or interoperability.
- Full production-grade NAT traversal / DHT peer discovery (Stage D gets basic external-address
  announcement; full DHT is backlog).
- Economic parameters, demurrage, fee recycling, governance (M6).

---

## Handoff to architect

The architect should produce:

1. An ADR choosing the transport protocol (libp2p vs. bespoke TCP; recommend libp2p for maturity).
2. An ADR choosing the Stage B consensus algorithm (round-robin rotating proposer with timeout-based
   view change is recommended as the simplest CFT-correct option; document the fork-choice rule).
3. Specs for Stage A, B, C as separate spec files under `docs/specs/` (05-networking.md,
   05b-consensus.md, 05c-cross-node-ai-quorum.md, or a single 05-p2p-network.md the architect
   prefers to split).
4. Updated invariant I1 in `docs/specs/00-overview.md` to state explicitly that the quorum must be
   evaluated across independent processes (not just independent addresses in one process).
5. Exit criteria EC-1 through EC-10 (above) operationalized as test assertions.
