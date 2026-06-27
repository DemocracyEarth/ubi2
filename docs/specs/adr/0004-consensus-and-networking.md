# ADR-0004 — Consensus & networking: libp2p gossip + PoA round-robin, with a real cross-node AI quorum

- **Status:** accepted (M5)
- **Date:** 2026-06-27
- **Deciders:** architect (this ADR) + product-strategist (M5 brief) — to be ratified by protocol-engineer,
  reliability-engineer, security-engineer at the M5 gates.
- **Supersedes:** the single-node block-production assumption baked into M1–M4 (`crates/node` as the sole
  proposer; the AI quorum evaluated in one process). It does **not** change any deterministic state
  transition in `crates/runtime`.
- **Spec:** [`../05-p2p-network.md`](../05-p2p-network.md). **Milestone:** [`../../milestones/m5-p2p-network.md`](../../milestones/m5-p2p-network.md).

These decisions are costly to reverse (wire formats, the consensus rule, the validator-set trust model,
and the canonical AI-output contract are all hard to change once nodes interoperate), so they are pinned
here. Where the M5 brief gave a recommendation, it is adopted unless a reason is stated.

---

## Context

The chain is a single-node devnet. One `ubi2-node` process produces every block on a 2 s timer
(`crates/rpc::Chain::produce_block`) and runs every AI quorum call in-process: PoH verdicts and
prompt-contract effects are tallied on-chain (`quorum_tally` over signed `submitVerdict`/`submitEffect`
txs from seeded juror **addresses**), but all those txs originate from one process. The on-chain tally is
already structurally correct and deterministic (integer-only, sorted indexes, seeded PRNG juror
selection — invariants I1/I2 hold *within* one process). What does not yet exist is (a) a network, (b)
distributed block production, and (c) a quorum whose members are genuinely independent processes with
independent AI backends.

M5 builds all three. Four decisions are load-bearing and recorded here.

The hard constraint that frames every decision: **`crates/runtime` must stay deterministic and
dependency-free.** It has no floats, no wall-clock reads, no `HashMap` ordering on any consensus path,
and no async/network dependencies. All networking and async lives in a **new `crates/network` crate**
wired by `crates/node`. `runtime` never imports libp2p, tokio, or reqwest. (See spec §8.)

---

## Decision 1 — Networking stack: rust-libp2p (gossipsub + request-response over Noise/TCP/Yamux)

**Decision.** Use **rust-libp2p** as the transport, in a new `crates/network` crate. Concretely:

- **Transport:** TCP, authenticated with **Noise**, multiplexed with **Yamux**.
- **Gossip:** **gossipsub** on two topics — `ubi2/tx/1` (pending txs) and `ubi2/block/1` (new blocks).
- **Sync:** libp2p **request-response** for block-range request/response (a joining or lagging node
  pulls `[from, to]` blocks from a peer).
- **Discovery:** a **static bootstrap-peer list** (configured multiaddrs) plus **mDNS** for the local
  devnet. Kademlia/DHT discovery is explicitly deferred to the backlog.
- **Identity:** each node has a libp2p Ed25519 keypair → `PeerId`. This is the *network* identity and is
  **distinct** from the node's on-chain validator key (the EVM secp256k1 key that signs blocks and juror
  txs). See Decision 3 for how they are bound.

**Rationale (libp2p vs. a hand-rolled TCP gossip).** A bespoke gossip is appealing for auditability, but
M5 needs, on day one, all of: multi-stream muxing, authenticated/encrypted channels, message dedup +
fan-out with mesh maintenance, peer scoring, a request/response RPC for sync, and mDNS discovery.
Hand-rolling that is exactly the surface where Eclipse/amplification/DoS bugs live (the security brief
flags these explicitly). rust-libp2p is a mature, widely-audited implementation of precisely this set,
with gossipsub message-id dedup and peer scoring already built. The cost is a heavyweight dependency
tree — accepted, and **fully isolated in `crates/network`** so the deterministic core never sees it. We
keep our own *application-level* validation (validate-before-rebroadcast, anti-spam caps) on top of
gossipsub's transport-level protections, because libp2p cannot know our tx/block validity rules.

**Rejected.** (a) A bespoke length-prefixed TCP gossip — rejected for the reason above (re-implementing
the hard, security-sensitive parts). (b) Starting with Kademlia/DHT discovery — rejected as premature;
static bootstrap + mDNS covers the single-host devnet (Stages A–C) and the small multi-host testnet
(Stage D); DHT is a scaling concern for a large open network and is backlog.

**Consequences.** New heavy deps (libp2p, tokio already in tree, an async codec) live only in
`crates/network`. Wire formats (Decision below within the spec) are pinned and versioned via the topic
name suffix (`/1`) and the request-response protocol string, so a future format change is a new protocol
id, not a silent break.

---

## Decision 2 — Consensus: Proof-of-Authority **round-robin** among a PoH-gated validator set (CFT, not BFT)

**Decision.** Stage B consensus is **PoA round-robin**:

- The **validator set** `V` is the sorted list of addresses that are both registered validators *and*
  `Verified` humans in the PoH registry. Sybil-resistance of the validator set is **tied to PoH**: only
  verified-human nodes can be validators (whitepaper alignment — a network of verified-human nodes).
- **Deterministic proposer schedule.** Time is sliced into fixed slots: `slot = floor((block_time −
  genesis_time) / BLOCK_MS_secs)`. The proposer for a slot is `V[proposer_index(slot, epoch)]` where
  `proposer_index` is a fixed rule (round-robin `slot mod |V|`, with a per-epoch deterministic shuffle
  seeded by a recent block hash so the order is not statically predictable forever). `V` is read at a
  pinned **epoch boundary** (a fixed block height multiple), so all honest nodes agree on `V` for the
  whole epoch even as humans are verified/revoked mid-epoch.
- **Block validity** = ALL of: (1) the block's proposer signature recovers to the slot's scheduled
  proposer; (2) `parent_hash` is the validating node's current head (correct parent); (3) the block
  re-executes to a **byte-identical post-state root** (the deterministic state transition — I1/I2); (4)
  `timestamp` is within the slot's bounds and strictly greater than the parent's. A block failing any
  check is rejected and the proposer may be penalized (Decision: equivocation handling below).
- **Fork choice** = **longest valid chain** (max height of fully-validated blocks), tie-broken by
  **lowest block hash** at equal height (deterministic). Equivocation (two distinct valid blocks signed
  by the same proposer for the same slot) is detected, both blocks are recorded as evidence, and the
  proposer is penalized (Stage B: dropped from the next epoch's `V`; slashing is FU-8 / backlog).
- **Liveness / view change.** If the scheduled proposer does not produce a valid block within
  `PROPOSER_TIMEOUT` (a small multiple of the slot), the schedule advances to the next validator
  (`V[(index+1) mod |V|]`) for that height — a deterministic, timeout-driven view change. The chain is
  live as long as a majority of `V` is live (crash-fault tolerant).
- **Finality.** **k-deep probabilistic finality**: a block is treated as final once `k`
  (`FINALITY_DEPTH`, devnet default 6) valid blocks are built on it. Reorgs are bounded to depth `< k`.
  Single-slot BFT finality is **not** in scope.

**Rationale (PoA round-robin vs. BFT vs. Nakamoto, for this chain at this stage).**
- **vs. Nakamoto (PoW/longest-chain with open proposer set):** rejected. There is no mining; the
  scarce resource here is *verified humanity*, not hash power. An open proposer set invites the very
  Sybil problem PoH exists to solve. Round-robin over a known, PoH-gated set is the natural fit.
- **vs. BFT (Tendermint/HotStuff, single-slot finality, Byzantine-tolerant):** rejected *for this
  stage*. BFT buys safety under actively-malicious proposers (≤ f of 3f+1) and instant finality, at the
  cost of a multi-round voting protocol, a much larger implementation/test surface, and a harder
  security gate. M5's stated target is **crash-fault tolerance** — "a downed node does not halt the
  chain" — explicitly *not* Byzantine tolerance (M5 brief, Risk 3). PoA round-robin with timeout view
  change delivers exactly CFT with a small, auditable protocol. BFT is the documented upgrade path.
- **PoA round-robin is the simplest CFT-correct option** that satisfies every Stage-B exit criterion
  (rotation across validators; liveness under a downed proposer; deterministic fork choice).

**Upgrade path to BFT.** The validator-set abstraction (`V`, epoch boundaries, proposer schedule) and
the block-validity rule are designed so a future milestone can replace *only* the proposer/finality
mechanism: swap the round-robin schedule + k-deep finality for a BFT round (pre-vote/pre-commit over the
same `V`, single-slot finality) without touching the wire formats, the sync protocol, the AI-quorum
protocol, or the runtime. The fork-choice rule becomes "the BFT-committed chain"; everything else holds.
BFT is on the backlog (M5 brief; roadmap backlog).

**Rejected alternatives within PoA.** (a) A single hardcoded proposer (the M1–M4 status quo) — fails
EC-5/EC-6 (no rotation, halts on death). (b) Random-leader-per-slot via VRF — more machinery than
round-robin needs at this stage and harder to reason about for CFT; deferred. (c) Pure longest-chain
with no slot schedule — would let any validator propose at any time, multiplying forks; the slot
schedule bounds proposer contention to one expected proposer per slot.

---

## Decision 3 — Validator identity binds the libp2p PeerId to the on-chain validator key, gated by PoH

**Decision.** A validator is identified on-chain by its **EVM address** (secp256k1), which is also the
address that must be `Verified` in the PoH registry. Blocks and juror txs are signed with this **EVM
key** (so block-author recovery uses the same ecrecover the chain already uses for txs). The **libp2p
PeerId** (Ed25519) is the transport identity. The two are bound at the handshake: a connecting node
presents its validator address and a signature (its EVM key signing its PeerId), so a peer can verify
that *this transport identity speaks for that validator address*. Network identity ≠ consensus identity;
binding them prevents a Sybil swarm of PeerIds from impersonating one validator and vice-versa.

**Rationale.** Reusing the EVM key for block/juror signing means no new signature scheme on the
consensus path and exact reuse of the existing recovery. Keeping a separate transport key is libp2p's
model and lets the network layer rotate transport keys without touching consensus identity. PoH-gating
the validator address is what makes the validator set Sybil-resistant (Decision 2) — it is the
whitepaper's "network of verified humans" made literal.

**Consequences.** `crates/runtime` gains *only* small, pure, deterministic types if they must be in the
consensus core: the **validator-set membership** read (which is just "registered validator ∧ Verified")
and the **proposer-schedule function** (`proposer_index(slot, validators, epoch_seed)` — pure integer +
the existing `SplitMix64`). No keys, no networking, no async enter `runtime`. The libp2p keypair,
handshake, and PeerId↔address binding live entirely in `crates/network`/`crates/node`.

---

## Decision 4 — The real cross-node AI quorum reuses the existing on-chain tally; nodes contribute via a juror daemon (FU-7)

**Decision.** Stage C makes the AI quorum a **real multi-process quorum without changing the on-chain
consensus rule**. The mechanism is already in place and is *reused verbatim*:

1. A PoH verification or a contract invocation opens a **Case**/**ExecCase** on-chain, with a
   **deterministically selected jury** (`select_jury` over `active_jurors()`, seeded by case id +
   on-chain entropy — already implemented). The jury is the set of validator/juror **addresses** assigned
   to that case.
2. Each node whose validator address is on that jury runs a **juror daemon** (FU-7, delivered as
   `crates/juror` or `ubi2-node --juror`) that: watches the chain for open cases assigning it; calls its
   **own** AI backend (`MockOracle`/`MockInterpreter` in CI; a pinned live backend in the live demo) to
   produce a **canonical structured output** (a `CanonicalVerdict` or a `CanonicalEffect`); and submits a
   **signed `submitVerdict`/`submitEffect` tx** from its validator key.
3. Those txs gossip and are mined like any other tx. The **on-chain `quorum_tally`** aggregates them
   deterministically: **commit on supermajority agreement** (`QUORUM` of `JURY_SIZE` matching canonical
   outputs by `quorum_key`), else **deterministic abort** (split / non-committable ⇒ `NoQuorum` ⇒
   escalate/abort — I4, no partial state). The tally is a pure function of on-chain data, so every node
   reaches the same commit/abort by replaying the same blocks. **No new consensus primitive is added** —
   the quorum result is just ordinary committed state.

**This is the realization of I1 across independent processes.** It was *true within one process* since
M3/M4; Stage C makes the jurors independent processes with independent backends. Because the tally lives
on-chain and consumes only canonical outputs, the AI's non-determinism is contained *below* the commit:
honest jurors converge (pinned model, temperature 0, canonical schema — I1) and the chain commits the
agreed effect; disagreement aborts deterministically. This directly unblocks **FU-15** (node-AI
rewards): there is now an identifiable, on-chain set of jurors who did the work and can be paid (M6).

**Rationale (why reuse, not invent).** A separate off-chain quorum/gossip protocol for verdicts would
duplicate consensus, need its own equivocation/finality story, and create a second source of truth.
Routing juror outputs through ordinary signed txs means the *existing* deterministic tally, replay, and
fork-choice already give us reproducibility, equivocation handling (a juror double-voting is two txs
with the same nonce — the second is invalid), and auditability for free. The only genuinely new piece is
the off-chain **juror daemon** and the **canonical-output contract** that keeps independent backends
convergent (specified in §6 of the spec).

**Consequences.** The canonical-output contract (model pin, temperature 0, schema, tie-breaking,
timeout/no-show handling) becomes a hard, tested artifact (spec §6). Equivocation, timeout, and no-show
are handled by the existing case state machine plus a deterministic timeout (a case that does not reach
quorum within a block-height window aborts). `crates/runtime` is unchanged for the quorum — it already
exposes everything needed.

---

## Status of invariants

- **I1 (deterministic quorum over non-deterministic AI):** strengthened. This ADR is what makes I1 hold
  *across independent processes*, not just independent addresses in one process. The overview's I1 is
  updated to say so (spec §0 of 05, and a one-line edit to `00-overview.md` handed to the orchestrator).
- **I2 (reproducible integer balances):** unchanged and now cross-node-verifiable (EC-4/EC-10). The block
  timestamp — never a node-local wall-clock — is the only time input to execution.
- **I4 (fail-closed):** preserved by the deterministic-abort tally and by validate-before-commit on every
  received block/tx.
- **I6 (least authority):** the network layer is least-authority (only gossip + range-request; no admin
  surface); the juror daemon holds only its own validator key.

## Open follow-ups created/closed by this ADR

- **Closes (on delivery):** FU-3 (persistence — prerequisite, Stage A), FU-7 (juror daemon — Stage C),
  FU-13 (stream-index canonical ordering — Stage A), and enables FU-8 (validator/juror staking +
  rotation — Stage B), FU-1 / FU-4 / FU-12 (Stage D hardening), FU-15 (node-AI rewards — M6).
- **Defers to backlog:** BFT consensus; Kademlia/DHT discovery; VRF leader election; validator slashing
  beyond epoch-eviction.
