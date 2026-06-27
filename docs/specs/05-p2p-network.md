# 05 — Network & Consensus (Real P2P)

- **Milestone:** M5. **Status:** specified (implementation begins next cycle).
- **Owner:** architect. **Decisions pinned in:** [`adr/0004-consensus-and-networking.md`](adr/0004-consensus-and-networking.md).
- **Product brief:** [`../milestones/m5-p2p-network.md`](../milestones/m5-p2p-network.md). **Invariants:** [`00-overview.md`](00-overview.md).
- **Prior art (read-only):** `../ubi.chain`, `../ubi.agent`, `../ubi.wallet`.

This spec turns the single-node devnet into a real peer-to-peer network of independent `ubi2-node`
processes that gossip transactions and blocks, agree on block production via PoA round-robin consensus,
sync joining nodes from genesis, stay live when a node dies, and — the hard part — evaluate the PoH and
prompt-contract AI quorums across **independent processes with independent AI backends**.

It is written acceptance-criteria-first (§9). Every exit criterion EC-1…EC-10 from the milestone brief
maps 1:1 to a test assertion here.

---

## 0. The invariant this milestone exists to prove

> **I1 (strengthened).** The AI quorum must be evaluated across **independent processes**, not just
> independent addresses in one process. Honest nodes, each running a pinned model at temperature 0 with a
> canonical structured output, must converge on the same committed effect; on disagreement the chain
> aborts deterministically.

This sentence is added to invariant I1 in `00-overview.md` (one-line edit handed to the orchestrator).
Everything below serves it. The deterministic core (`crates/runtime`) already satisfies I1/I2 *within* a
process; M5 proves it *between* processes and never weakens it.

**Non-negotiable structural rule (from the ADR):** `crates/runtime` stays deterministic and
dependency-free. No async, no networking, no floats, no wall-clock, no `HashMap` ordering on any
consensus path. All networking/async lives in the **new `crates/network`** crate, wired by
`crates/node`. `runtime` never imports libp2p/tokio/reqwest. Block execution reads **only the block
timestamp** as its clock.

---

## 1. Scope

**In scope (Stages A–D):**
- A libp2p P2P transport (`crates/network`): Noise/TCP/Yamux, gossipsub on two topics, request-response
  for sync, static-bootstrap + mDNS discovery.
- Transaction gossip with dedup, validate-before-rebroadcast, and anti-spam (FU-1).
- Block broadcast + validation; followers re-execute and accept only on byte-identical state root.
- Join-sync from genesis via block-range request/response; fork detection at the handshake.
- PoA round-robin distributed block production: deterministic proposer schedule, longest-valid-chain fork
  choice, timeout view change, k-deep finality (CFT only).
- A real cross-node AI quorum: a juror daemon per node submits signed `submitVerdict`/`submitEffect` from
  an independent backend; the existing on-chain tally commits/aborts (FU-7).
- `ubi_getPeers` + consensus-status reads on `crates/rpc`.
- A 3-node localhost devnet script + a multi-process CI integration harness.
- Stage D hardening: soak, partition test, observability (FU-4), mempool caps (FU-1), SSRF fix (FU-12),
  basic external-address announcement for a multi-host testnet.

**Out of scope (backlog / M6):** BFT/Byzantine tolerance; Kademlia/DHT discovery; VRF leader election;
validator slashing beyond epoch eviction; economic parameters, demurrage, fee recycling, node-AI reward
*payouts* (M6 — M5 only makes the rewardable quorum *exist*); cross-chain bridge.

---

## 2. Data model (consensus-relevant types)

### 2.1 What moves to `crates/runtime` (deterministic core) — minimal

Only pure, integer, deterministic types that the consensus rule depends on. **No keys, no networking.**

- **`ValidatorSet`** — the ordered set `V` of validator addresses active for an epoch. Membership rule
  (pure): an address is in `V` iff it is a registered validator **and** `Verified` in the PoH registry
  (`get_human(addr).status == Verified`). Read at an **epoch boundary** (a fixed block-height multiple,
  `EPOCH_BLOCKS`) so `V` is stable for the whole epoch. Returned **sorted by address** (no hash-order on
  the consensus path — same discipline as `active_jurors()`).
- **`proposer_index(slot: u64, n: usize, epoch_seed: u64) -> usize`** — pure function returning the index
  into `V` for a slot. Round-robin base (`slot mod n`) composed with a per-epoch deterministic shuffle
  seeded by `epoch_seed` (a recent block hash folded to `u64`), using the existing `SplitMix64`. This is
  the *only* new consensus-affecting function and it is integer-only.
- **`BlockHeader` fields needed for validity** (already largely present in `crates/rpc::Block`; the
  `state_root`, `proposer`, and `proposer_sig` fields are added — see §2.2). The header hash becomes a
  commitment over these fields.

Everything else (the libp2p keypair, PeerId, handshake, gossip, sync, timers) stays out of `runtime`.

### 2.2 Block header (extended in `crates/rpc::Block`)

The current devnet `Block` hash is `keccak256(number ‖ parent_hash ‖ timestamp)` and carries no state
commitment or author. M5 extends the header so a follower can validate authorship and agreement:

| Field | Type | Meaning |
|---|---|---|
| `number` | `u64` | height (existing) |
| `parent_hash` | `B256` | parent block hash (existing) |
| `timestamp` | `u64` | block time, unix seconds — the **only** clock execution sees (existing) |
| `txs_root` | `B256` | commitment over the canonical, ordered tx list (new) |
| `state_root` | `B256` | commitment over post-execution state (new — see §5.3) |
| `proposer` | `Address` | the validator that produced the block (new) |
| `proposer_sig` | 65-byte sig | the proposer's EVM-key signature over the header pre-image (new) |

`hash = keccak256(number ‖ parent_hash ‖ timestamp ‖ txs_root ‖ state_root ‖ proposer)`, and
`proposer_sig` signs that pre-image. `ecrecover(proposer_sig)` must equal `proposer` and `proposer` must
equal the slot's scheduled validator. **Determinism:** `txs_root` and `state_root` are pure functions of
ordered txs and state; two honest nodes building/validating the same block compute identical roots
(EC-4/EC-10).

### 2.3 Network/consensus state (lives in `crates/network`/`crates/node`, not `runtime`)

- **`PeerId`** (libp2p Ed25519) ↔ **validator `Address`** (EVM secp256k1) binding, established at the
  handshake (§4). Network identity ≠ consensus identity (ADR Decision 3).
- **Peer table:** `PeerId`, multiaddr, bound validator address (if any), last-seen tip `(height, hash)`,
  per-peer rate-limit counters (§3.3).
- **Fork-choice view:** the set of known valid chains; the canonical head by longest-valid + lowest-hash
  tie-break (§5.2).

---

## 3. Mempool & gossip (Stage A; hardening in Stage D / FU-1)

### 3.1 Wire messages and canonical encodings

Two gossipsub topics. All payloads are **versioned, length-bounded, and canonically encoded** so the
gossipsub message-id (used for dedup) is stable across nodes.

| Topic | Message | Payload | Canonical encoding |
|---|---|---|---|
| `ubi2/tx/1` | `TxAnnounce` | the raw EIP-155 tx bytes (exactly what `eth_sendRawTransaction` accepts) | the RLP tx bytes verbatim; **message-id = `keccak256(rlp)` = the tx hash** |
| `ubi2/block/1` | `BlockAnnounce` | the full block (header + ordered txs, each as raw RLP) | a fixed field order (header fields in §2.2 order, then `txs.len()` then each raw tx); **message-id = block `hash`** |

Sync is **not** gossip; it is request-response (§4.2). Using the tx hash / block hash as the gossipsub
message-id gives free, correct dedup: a message already seen (by id) is neither re-processed nor
re-forwarded. Versioning is in the topic suffix (`/1`) and the request-response protocol string, so a
format change is a new protocol id, never a silent break.

### 3.2 Transaction propagation (validate-before-rebroadcast)

On receiving a `TxAnnounce` (whether from a peer or from the local `eth_sendRawTransaction`):

1. **Dedup** by message-id (tx hash). If already in mempool or already mined ⇒ drop, do not rebroadcast.
2. **Validate** with the *exact same* `ingest_raw_tx` path the RPC already uses: signature/recovery,
   chain id, nonce ≥ account nonce, cumulative-pending affordability (`spendable_debit`), calldata
   shape for hub ops, text/parties caps. **Invalid ⇒ drop, do not rebroadcast, and penalize the source
   peer** (§3.3). This is the load-bearing anti-amplification rule: a node never forwards something it
   has not itself validated.
3. **Admit** to the local mempool (subject to caps, §3.3) and **rebroadcast** on `ubi2/tx/1`.

Result: a tx submitted to node A reaches B and C within one gossip round (EC-2), and an invalid/spam tx
does not propagate or fill mempools.

### 3.3 Anti-spam (FU-1, mandatory before Stage D multi-host)

Deterministic, bounded, fail-closed:

- **Per-sender pending-balance accounting:** a sender's queued txs are admitted only while their summed
  `spendable_debit` ≤ the sender's live balance (the existing cumulative check, now enforced on the
  gossip ingest path too).
- **Bounded mempool:** a global cap (`MEMPOOL_MAX_TXS`) and a per-sender cap (`MEMPOOL_MAX_PER_SENDER`).
  On overflow, drop the lowest-priority tx (lowest nonce-gap / oldest) — never unbounded growth.
- **Per-peer rate limits:** a token-bucket per `PeerId` for tx and block messages. A peer exceeding it is
  throttled; a peer that repeatedly sends **invalid** messages has its gossipsub peer score lowered and
  is eventually disconnected/greylisted (libp2p peer scoring + our own counters).
- **Validate-before-rebroadcast** (§3.2) is the primary amplification defense.

---

## 4. Sync & handshake (Stage A; EC-7)

### 4.1 Handshake

On a new connection, peers exchange a `Hello`:

```
Hello {
  genesis_hash:  B256,        // MUST equal locally — else disconnect (wrong network)
  chain_id:      u64,         // MUST equal locally — else disconnect
  tip:           (u64, B256), // (height, hash) of the sender's current head
  validator:     Option<Address>, // the sender's validator address, if it is a validator
  peer_proof:    Sig,         // validator-key signature over (PeerId ‖ genesis_hash); binds PeerId↔address
  protocol_ver:  u16,
}
```

- **Network-mismatch** (`genesis_hash`/`chain_id` differ) ⇒ disconnect immediately (cannot interoperate).
- **PeerId↔address binding** (ADR Decision 3): `peer_proof` must `ecrecover` to `validator` over
  `(PeerId ‖ genesis_hash)`. A failed binding ⇒ treat the peer as non-validator (it may still relay
  gossip but its blocks/verdicts are not trusted as a validator's).
- **Tip comparison** drives sync: if the peer's tip is higher, request the missing range (§4.2).

### 4.2 Block-range request/response (libp2p request-response, protocol `ubi2/sync/1`)

```
GetBlocks  { from: u64, to: u64 }          // inclusive height range; |range| ≤ SYNC_MAX_BATCH
Blocks     { blocks: Vec<RawBlock> }       // canonically encoded, in ascending height order
```

**Join-sync algorithm (a node starting from empty state):**
1. Handshake with one or more bootstrap peers; learn the network tip `(H, _)`.
2. Request `[1, H]` in batches of `SYNC_MAX_BATCH`, ascending.
3. For each received block, in height order: **validate fully** (§5.1) — correct proposer-for-slot, valid
   parent (== local head), re-execute to a **byte-identical `state_root`**, valid signature. Apply only
   on success; a block that fails validation aborts that peer's sync (the peer is on a bad/forked chain →
   try another peer).
4. Once caught up to `H`, **subscribe to live gossip** (`ubi2/block/1`, `ubi2/tx/1`) and continue.
5. **Sync DoS bound:** `SYNC_MAX_BATCH` caps response size; a peer that sends invalid blocks during sync
   is penalized and abandoned. A node serving sync caps concurrent sync streams per peer.

Because each block is re-executed and the post-state root must match the header's `state_root`, a synced
node reaches the **same state root** as the established nodes (EC-7, EC-10) — sync cannot smuggle in a
divergent state.

### 4.3 Fork detection

A node detects it is on a fork when: (a) at the handshake, peers report the same height but a different
hash; or (b) it receives a valid block whose `parent_hash` it does not have, or two valid blocks at the
same height. Resolution is the deterministic **fork-choice rule** (§5.2): adopt the longest valid chain
(lowest-hash tie-break), re-org up to depth `< FINALITY_DEPTH`. Below finality depth, reorgs do not
happen (k-deep finality); a conflicting block below finality from a validator is **equivocation**
evidence (§5.4).

---

## 5. Consensus — PoA round-robin (Stage B; EC-5, EC-6)

### 5.1 Block validity

A received block at height `n` is valid iff **all** hold (any failure ⇒ reject; do not apply, do not
rebroadcast as accepted):

1. **Author = scheduled proposer.** `ecrecover(proposer_sig) == proposer`, and
   `proposer == V[proposer_index(slot, |V|, epoch_seed)]` for `slot = floor((timestamp − genesis_time) /
   BLOCK_MS_secs)`, where `V` is the validator set for `n`'s epoch (§2.1). A view-changed block (the
   primary missed its slot) is valid for the *next* validator in order after `PROPOSER_TIMEOUT` (§5.5).
2. **Valid parent.** `parent_hash` == the validating node's head at height `n−1` (or a known ancestor on
   the chain being extended).
3. **Valid deterministic state transition.** Re-executing `txs` against the parent state at `timestamp`
   yields a post-state whose root **byte-identically** equals the header `state_root`, and the recomputed
   `txs_root` equals the header `txs_root`. This is the I1/I2 check made cross-node.
4. **Timestamp sanity.** `timestamp > parent.timestamp` and within the slot's bounds (`±` a small skew).

### 5.2 Fork choice

**Longest valid chain** (max height of fully-validated blocks). **Tie-break at equal height: lowest block
hash.** Deterministic and identical on every node. Re-orgs are bounded to depth `< FINALITY_DEPTH`.

### 5.3 Canonical tx ordering & the state root (the determinism core — restated for multi-node)

Two honest nodes must produce byte-identical state from the same ordered blocks (I1/I2). The proposer is
free to *select* which mempool txs to include, but their **order within the block is canonical and
verifiable**, and the resulting `state_root` is a pure function of that order + the parent state +
`timestamp`:

- **Canonical intra-block tx order:** ascending **`(sender, nonce)`**, ties broken by tx hash. A follower
  recomputes this order from the block's tx set and rejects the block if the proposer's order differs
  (so a malicious proposer cannot reorder to a different outcome). This makes execution order a function
  of content, not of proposer whim or mempool arrival order.
- **Execution uses only `block.timestamp`** as its clock — never a node-local wall-clock. (`charge_fee`,
  `apply_transfer`, emission settlement, stream accrual, lifecycle window checks all already take an
  explicit `now`; the block loop passes `block.timestamp`.)
- **`state_root`** is a deterministic commitment over the full post-block state. Computing it requires
  **canonical ordering of every state collection that feeds it** — accounts, streams, humans, vouch
  edges, cases, jurors, contracts, exec-cases. The runtime already returns the M3/M4 registries sorted;
  **FU-13 must canonicalize `MemState::incoming()/outgoing()` (and any remaining unsorted iterator) and
  drop the stray zero-balance TREASURY entry before §9's state-root tests run.** The state-root function
  serializes each collection in its sorted order and hashes the concatenation (a flat sorted hash for
  Stage A; a Merkle/MPT root is a Stage D optimization and a backlog item — Stage A only requires that it
  be a deterministic commitment, not that it be an Ethereum MPT).

> **Gate dependency:** EC-4/EC-10 (byte-identical state roots) cannot pass until FU-13 and the
> account-set canonicalization land. The orchestrator must schedule FU-13 *inside Stage A, before* the
> state-root comparison test, and FU-3 (persistence) *before* sync (you cannot replay state you do not
> persist).

### 5.4 Equivocation

Two distinct valid blocks signed by the same proposer for the same slot/height = equivocation. Both are
recorded as evidence; the proposer is **dropped from the next epoch's `V`** (Stage B penalty). Slashing a
stake is FU-8 (Stage B membership mechanism) and a backlog item. A follower never applies a second block
below finality depth; it keeps the canonical one by the fork-choice rule.

### 5.5 Liveness — proposer timeout & view change (CFT; EC-6)

If the scheduled proposer for a height does not produce a valid block within `PROPOSER_TIMEOUT` (a small
multiple of `BLOCK_MS`), every node deterministically advances the schedule to the **next** validator
(`V[(index+1) mod |V|]`) for that height and waits another `PROPOSER_TIMEOUT`, repeating until a block is
produced. Because the timeout and the next-proposer rule are deterministic functions of slot + `V`, all
honest nodes agree on who is responsible at each step. SIGKILL-ing the current proposer therefore causes
the remaining nodes to elect a successor and resume within ≤ `MAX_VIEW_CHANGES × PROPOSER_TIMEOUT`
(EC-6: "within 3 proposer timeouts"). The chain is live while a majority of `V` is live (crash-fault
tolerant — **not** Byzantine).

### 5.6 Finality

A block is final once `FINALITY_DEPTH` (devnet default 6) valid blocks build on it. Reorgs are bounded to
`< FINALITY_DEPTH`. No single-slot/BFT finality (backlog).

---

## 6. The hard part — real cross-node AI quorum (Stage C; EC-8, EC-9)

This is where I1 is proven across processes. **No new consensus primitive is introduced**; the existing
on-chain case → jury → `submitVerdict`/`submitEffect` → `quorum_tally` machinery is reused, with the
jurors now being independent processes with independent AI backends.

### 6.1 Assignment — when/how a case is assigned to a set of nodes

- A `requestVerification` / `challenge` opens a **`Case`**; an `invokeContract` opens an **`ExecCase`**.
  Both already select a **deterministic jury** via `select_jury(active_jurors(), JURY_SIZE, seed)` where
  `seed = jury_seed(case_id, on_chain_entropy)`. The jury is the assigned set of validator/juror
  addresses. This is **on-chain and reproducible** — every node computes the same jury for the same case.
- In M5 the candidate pool `active_jurors()` is the **PoH-gated validator set** (jurors are
  verified-human validator nodes; FU-8 manages staking/rotation of this set in Stage B). One shared set
  serves both the proposer schedule and jury selection.

### 6.2 Independent evaluation — the juror daemon (FU-7)

Each node runs a **juror daemon** (`crates/juror`, or `ubi2-node --juror`) that:
1. Watches the chain for **open** `Case`/`ExecCase` entries whose jury **includes this node's validator
   address** and for which this node has **not yet** submitted.
2. Reconstructs the canonical, content-addressed **input** from on-chain commitments only (the liveness
   ref / evidence ref / contract text + trigger ref) — never any off-chain PII (I6).
3. Calls its **own** AI backend — `MockOracle`/`MockInterpreter` in CI (deterministic, I5), a **pinned
   live backend** in the live demo — to produce a **canonical structured output** (§6.4).
4. Submits a **signed `submitVerdict(caseId, verdict, confidence)`** or **`submitEffect(caseId, ops)`**
   tx from its validator key. The tx gossips and is mined like any other.

### 6.3 Deterministic tally — commit on supermajority, else abort

The on-chain `quorum_tally` (unchanged) aggregates the submitted canonical outputs:
- **Commit** when `QUORUM` of `JURY_SIZE` jurors produced the **same** canonical output (equal by
  `quorum_key` — for verdicts: `(verdict, confidence)`; for effects: the canonical op list) **and** the
  exemplar is committable. The agreed effect commits as ordinary state (a human becomes `Verified`, an
  effect applies to escrow).
- **Abort** (`NoQuorum`) on a split, or a quorum that is not committable, or **timeout** (§6.5) — a
  **deterministic abort**: no partial state (I4). For a registration, the human simply does not finalize;
  for a contract, the invocation aborts and escrow is untouched.
- The tally is a **pure function of on-chain data**, so every node reaches the same commit/abort by
  replaying the same blocks. This is exactly how I1 becomes true across processes: the AI's
  non-determinism is contained *below* the commit; only the canonical effect, agreed by a supermajority,
  ever reaches state.

### 6.4 The canonical-output contract (what keeps independent backends convergent)

For honest independent jurors to converge (so a quorum forms rather than perpetually splitting):
- **Pinned model + temperature 0 + fixed seed**, identical decoding config across jurors (I1). The model
  id is part of the node's config and is logged; a juror whose model differs is expected to (and may)
  diverge and simply fails to join the quorum.
- **Canonical, bounded structured output.** Verdicts are `(verdict ∈ {Human, Sybil, Uncertain},
  confidence ∈ {Low, Med, High})` — **bucketed, never a float** — so two jurors agree *exactly*
  (`CanonicalVerdict::quorum_eq` already ignores the informational `reasons_hash`). Effects are the
  bounded `CanonicalEffect` op language (M4) — a finite, integer-valued op list with a canonical
  serialization, so two interpreters' effects are equal byte-for-byte or they are not.
- **Content-addressed, identical input.** Every juror grades the *same* bytes derived from on-chain
  commitments; no juror sees node-local state.
- **Fail-closed bucketing.** Any uncertainty maps to `Uncertain` / a non-committable effect, which
  cannot form a committing quorum — so on doubt the chain aborts, never guesses (I4).

This is the concrete realization of I1: probabilistic AI below the line, a deterministic canonical effect
and an on-chain supermajority above it.

### 6.5 Equivocation, timeout, no-show

- **Equivocation (a juror submitting two different verdicts for one case):** the second `submitVerdict`
  carries the same nonce as the first and is **invalid** (replay-protected) — a juror cannot vote twice.
  A juror changing its mind is therefore impossible on-chain; the first canonical output is binding.
- **Timeout:** a case that has not reached quorum within `CASE_TIMEOUT_BLOCKS` (a block-height window,
  deterministic — the existing lifecycle already advances on block height) **aborts** (I4). This bounds
  liveness loss from a no-show juror.
- **No-show (a juror that never submits):** with `JURY_SIZE=3, QUORUM=2`, the quorum still commits if the
  other two agree. If two or more no-show, the case times out and aborts. Persistent no-shows are removed
  from the candidate pool at the epoch boundary (FU-8).
- **A lying juror (submits a verdict that disagrees with the honest majority):** if it is a minority, the
  honest supermajority still commits the correct effect; the liar's verdict is recorded on-chain
  (auditable, and the basis for FU-8 reputation/slashing). If liars are a majority, that is a Byzantine
  scenario explicitly **out of scope** for M5 (CFT, not BFT) — flagged for the security gate and the BFT
  backlog.

### 6.6 Unblocks FU-15

Because the jury that did the AI work is now an identifiable, on-chain set of independent nodes, the
fees collected for the op can be **split to that jury** in M6 (FU-15). M5 makes the rewardable quorum
*exist*; M6 specifies the *payout*.

---

## 7. Threat model pointers (for the security gate)

The security-engineer must threat-model the new transport + consensus + quorum explicitly. Pointers:

- **Eclipse:** an adversary monopolizes a victim's peer connections to feed it a false view. Mitigations:
  multiple bootstrap peers, peer diversity, libp2p peer scoring, k-deep finality bounding the damage of a
  short eclipse. Test: feed a node only a forked chain and assert it does not finalize it.
- **Sybil among validators:** mitigated by **PoH-gating** the validator set (only verified humans).
  Test: a non-`Verified` address cannot be a proposer/juror (block/verdict from it is rejected).
- **Equivocation / double-propose:** §5.4 — detected, evidence recorded, proposer epoch-evicted; followers
  never apply a second block below finality. Test: a proposer signing two blocks for one slot does not
  split honest nodes.
- **Gossip-flood DoS / amplification:** validate-before-rebroadcast (§3.2), per-peer rate limits + peer
  scoring, bounded mempool (§3.3, FU-1). Test: a flood of invalid txs does not propagate and does not grow
  mempools without bound.
- **Sync / range-request DoS:** `SYNC_MAX_BATCH` bound, per-peer concurrent-stream cap, abandon-on-invalid
  (§4.2). Test: a malicious sync server cannot exhaust a joining node.
- **Network partition + recovery:** a minority partition cannot finalize (no majority of `V`); on heal it
  re-syncs to the majority chain via fork choice (§5.2). Test: partition 1-of-3 for 30 s, heal, assert
  re-sync to one chain (Stage D).
- **Long-range / withholding:** k-deep finality + epoch-boundary `V` reads bound long-range reorgs;
  block-withholding by a proposer triggers the timeout view change (§5.5). Equivocation evidence is
  recorded.
- **AI-quorum gaming (a node lying about its verdict):** §6.5 — a minority liar cannot move the outcome;
  the lie is recorded on-chain (auditable). A majority of liars is Byzantine → out of scope (CFT), flagged
  for BFT.
- **Carried-over surfaces that gate Stage D:** FU-1 (mempool hardening) and FU-12 (oracle-URL
  DNS-rebinding SSRF) are **mandatory before any non-localhost deploy**.

---

## 8. Crate / module plan & phased task breakdown

### 8.1 Crate layout

| Crate | Change | New deps |
|---|---|---|
| **`crates/network`** (NEW) | All P2P: libp2p swarm (Noise/TCP/Yamux), gossipsub (2 topics), request-response (`ubi2/sync/1`), mDNS + static bootstrap, the `Hello` handshake + PeerId↔address binding, wire codecs, per-peer rate limits/scoring. Exposes an async, message-passing API (`enum NetEvent` in, `enum NetCmd` out) to `crates/node`. | **libp2p**, tokio (already in tree), an async codec. **Isolated here** — nothing else depends on libp2p. |
| **`crates/node`** | Wires `network` ↔ `rpc::Chain`: routes gossiped txs into the mempool (via the existing `ingest_raw_tx`), drives PoA block production (proposer schedule, timeout view change, broadcast), validates received blocks (re-execute → state-root check), runs sync on startup, and hosts the **juror daemon** (Stage C). Replaces the unconditional single-proposer tick with the schedule-driven proposer. | none new (consumes `network`) |
| **`crates/runtime`** | **Minimal, deterministic only:** `ValidatorSet` membership read (registered ∧ Verified), `proposer_index(slot, n, epoch_seed)` (pure, `SplitMix64`), and the `state_root` serialization helper over its already-sorted collections. **FU-13** canonical-ordering fixes land here. **No async, no libp2p.** | **none** (stays dependency-free) |
| **`crates/rpc`** | Block header gains `txs_root`/`state_root`/`proposer`/`proposer_sig` (§2.2); `produce_block` becomes proposer-aware and emits a signed header; a `validate_and_apply_block` entry point for followers; new reads: `ubi_getPeers`, `ubi_consensusStatus` (validator set, current proposer, finalized height), `ubi_stateRoot`. | none new |
| **`crates/oracle`** | Unchanged interfaces; the juror daemon calls the existing `HumanityOracle`/`ContractInterpreter` backends. FU-12 SSRF fix lands here (Stage D). | none new |
| **`scripts/`** | `devnet-multi.sh` launches 3 nodes on localhost (distinct ports/data dirs/keys, shared bootstrap). | — |

### 8.2 Phased tasks (map to Stages A–D)

**Stage A — networking + block sync (one proposer, N followers).** *Prereqs: FU-3 persistence, FU-13
ordering.*
- A1 `crates/network` skeleton: swarm, Noise/TCP/Yamux, gossipsub 2 topics, `Hello` handshake, peer table.
- A2 Tx gossip: ingest → validate (`ingest_raw_tx`) → dedup → admit → rebroadcast (§3.2).
- A3 Block header extension (`state_root`/`proposer`/sig, §2.2) + `state_root` serialization (§5.3) +
  FU-13 canonicalization.
- A4 Block broadcast + follower `validate_and_apply_block` (re-execute, state-root match).
- A5 Request-response sync (`ubi2/sync/1`) + join-from-genesis (§4.2) + FU-3 persistence.
- A6 `ubi_getPeers` + `scripts/devnet-multi.sh` + 3-process CI harness asserting **EC-1, EC-2, EC-3,
  EC-4, EC-7**.

**Stage B — distributed block production (CFT).** *Closes FU-8.*
- B1 `ValidatorSet` + `proposer_index` in `runtime` (pure); epoch boundaries.
- B2 Proposer-aware production + signed headers; round-robin schedule.
- B3 Fork choice (longest-valid + lowest-hash) + equivocation detection (§5.2/§5.4).
- B4 Proposer timeout + deterministic view change (§5.5); k-deep finality (§5.6).
- B5 FU-8: validator/juror staking + rotation via the epoch membership mechanism.
- B6 CI: kill-the-proposer harness asserting **EC-5, EC-6**.

**Stage C — real cross-node AI quorum.** *Closes FU-7.*
- C1 `crates/juror` daemon: watch assigned open cases → call local backend → submit signed
  `submitVerdict`/`submitEffect` (§6.2). Mock backend in CI, live in demo.
- C2 Each devnet node runs its juror daemon (flag); canonical-output contract enforced (§6.4).
- C3 Case timeout/no-show handling wired to block-height windows (§6.5).
- C4 CI: cross-node PoH + contract quorum asserting **EC-8, EC-9** (agreement commits, injected
  disagreement aborts deterministically).

**Stage D — hardening + multi-host testnet.** *Closes FU-1, FU-4, FU-12.*
- D1 FU-1 mempool hardening (§3.3) on the gossip path; per-peer rate limits + scoring.
- D2 FU-12 oracle-URL DNS-rebinding SSRF fix.
- D3 FU-4 observability: Prometheus metrics — block height, peer count, mempool depth, quorum
  participation rate, finalized height, view-change count.
- D4 Soak (72 h, simulated packet loss + restarts) + partition test (1-of-3, 30 s, heal) — no state
  divergence.
- D5 Basic external-address announcement; public multi-host testnet + faucet + docs. Asserts **EC-1…EC-10
  on multi-host**.

---

## 9. Acceptance criteria (1:1 with EC-1…EC-10 → tests)

Each criterion is an automated assertion (a multi-process integration test unless noted). CI uses
`MockOracle`/`MockInterpreter` so the AI path is deterministic (I5).

| AC | Maps to | Assertion (the test bar) | Stage |
|---|---|---|---|
| **AC-1** | EC-1 | 3 independent `ubi2-node` processes (distinct ports/keys/data dirs) start, connect via the bootstrap list, and `ubi_getPeers` on each returns the other two as connected peers (with bound validator addresses). | A |
| **AC-2** | EC-2 | A tx sent via `eth_sendRawTransaction` to node A appears in B's and C's mempools within 2 s **without resubmission** (it was gossiped). An *invalid* tx sent to A does **not** appear anywhere. | A |
| **AC-3** | EC-3 | After the proposer mines a block, `eth_blockNumber` agrees across A/B/C within one block interval (~2 s); `eth_getBalance` at that height is equal on all three. | A |
| **AC-4** | EC-4 | After 20 consecutive blocks containing txs, `ubi_stateRoot` (and the header `state_root`) is **byte-identical** across A/B/C. Any divergence fails. *(Requires FU-13 + account-set canonicalization first.)* | A |
| **AC-5** | EC-5 | Over 30 blocks, ≥ 2 of 3 nodes each produce ≥ 1 block; no single node produces all (round-robin verified via `ubi_consensusStatus` / block `proposer`). | B |
| **AC-6** | EC-6 | SIGKILL the current proposer; the remaining two elect a successor and resume production within ≤ 3 × `PROPOSER_TIMEOUT`; the chain does not halt. | B |
| **AC-7** | EC-7 | A 4th node with empty state connects, syncs genesis→tip via range request/response **with no manual steps**, reaches the **same state root** as A/B/C, and sees subsequent txs. | A |
| **AC-8** | EC-8 | A `requestVerification` on A: each of A/B/C's juror daemon runs its **own** backend and submits `submitVerdict` from **independent processes**; the on-chain tally reaches supermajority and the human becomes `Verified`. No single node's backend alone commits. | C |
| **AC-9** | EC-9 | A contract invocation on A: A/B/C independently `submitEffect`; **agreement commits** the effect; an **injected disagreement** (one node's mock returns a divergent effect) **aborts deterministically** — escrow untouched, no partial state. Both paths tested. | C |
| **AC-10** | EC-10 | `eth_getBalance` for the same address at the same height is the same integer on all nodes (I2); `state_root` after block N matches byte-for-byte across all nodes at **every** height (I1) — asserted automatically, not eyeballed. | A→C |
| **AC-11** | (Stage D) | Multi-host: AC-1…AC-10 pass across hosts; 72 h soak with packet loss + restarts shows no state divergence; a 1-of-3 partition for 30 s heals and re-syncs to one chain. | D |

### 9.1 Failure-mode acceptance (must also pass)

| AC | Failure mode | Assertion |
|---|---|---|
| **AC-F1** | Invalid tx gossip | An invalid tx (bad sig/nonce/over-spend) is dropped, **not** rebroadcast, and the source peer's score drops. |
| **AC-F2** | Divergent block | A block whose `state_root` ≠ the follower's re-execution is **rejected**; the follower does not apply it. |
| **AC-F3** | Wrong proposer | A block signed by a validator that is **not** the slot's scheduled proposer (and not a valid view-change successor) is rejected. |
| **AC-F4** | Equivocation | A proposer signing two blocks for one slot does not split honest nodes; both are recorded; the proposer is epoch-evicted. |
| **AC-F5** | Quorum split | A PoH/contract case with no supermajority **aborts deterministically** (no `Verified`, escrow untouched) and reaches the same abort on every node. |
| **AC-F6** | Juror equivocation | A juror's second, different `submitVerdict` for one case is rejected (nonce replay); the first is binding. |
| **AC-F7** | Wrong-network peer | A peer with a different `genesis_hash`/`chain_id` is disconnected at the handshake. |
| **AC-F8** | Sync DoS | A sync server sending invalid blocks is abandoned; `SYNC_MAX_BATCH` bounds response size. |

---

## 10. Constants (devnet starting values — tunable, recorded for tests)

| Constant | Value (devnet) | Meaning |
|---|---|---|
| `BLOCK_MS` | 2000 | slot/block interval (existing) |
| `EPOCH_BLOCKS` | 100 | block-height multiple at which `V` is re-read |
| `PROPOSER_TIMEOUT` | 2 × `BLOCK_MS` | wait before a view change to the next validator |
| `MAX_VIEW_CHANGES` | 3 | bounds EC-6's "within 3 proposer timeouts" |
| `FINALITY_DEPTH` (k) | 6 | k-deep probabilistic finality; reorg bound |
| `SYNC_MAX_BATCH` | 128 | max blocks per `GetBlocks`/`Blocks` |
| `MEMPOOL_MAX_TXS` | 4096 | global mempool cap (FU-1) |
| `MEMPOOL_MAX_PER_SENDER` | 64 | per-sender mempool cap (FU-1) |
| `CASE_TIMEOUT_BLOCKS` | reuse `CHALLENGE_WINDOW`-scale | block window before a quorum case aborts (I4) |
| `JURY_SIZE` / `QUORUM` | 3 / 2 | unchanged from M3/M4 (`⌈2N/3⌉`) |

---

## 11. New RPC surface (`crates/rpc`)

- **`ubi_getPeers`** → `[{ peerId, multiaddr, validator?, tip: { height, hash }, connectedAt }]`. Read of
  the node's peer table (EC-1). Read-only; no new write surface (I6).
- **`ubi_consensusStatus`** → `{ validatorSet: [Address], currentProposer: Address, slot, finalizedHeight,
  head: { height, hash, stateRoot } }`. Backs EC-5/EC-6 assertions.
- **`ubi_stateRoot`** (or `state_root` on `ubi_getBlock`) → `B256`. Backs EC-4/EC-10. Pure read.
- **EVM compatibility (I3):** these are `ubi_*` extensions; no standard `eth_*` method changes semantics.
  `eth_blockNumber`/`eth_getBalance`/`eth_getBlockByNumber` keep Ethereum semantics and are the basis for
  the cross-node agreement checks. Any deviation stays documented here and in spec 01.

---

## 12. Determinism checklist (the reliability gate will assert each)

1. Execution reads **only `block.timestamp`** — no node-local wall-clock anywhere on the apply path.
2. Intra-block tx order is canonical `(sender, nonce)`-then-hash and **verified** by followers (§5.3).
3. Every state collection feeding `state_root` is iterated in **sorted** order (M3/M4 already; **FU-13**
   closes the streams/account gap).
4. Juror selection + proposer schedule use the existing seeded `SplitMix64` (no `HashMap` order).
5. AI outputs are **bucketed/canonical** (`CanonicalVerdict`/`CanonicalEffect`) — no floats; equality is
   `quorum_eq`/byte-equal.
6. The quorum result is **ordinary committed state**, reached by replay — no out-of-band consensus.
7. No `libp2p`/`tokio`/`reqwest` symbol is reachable from `crates/runtime` (a build-level assertion).
