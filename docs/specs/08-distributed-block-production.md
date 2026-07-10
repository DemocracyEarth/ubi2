# 08 — Distributed Block Production (M5 Stage B, CFT)

- **Milestone:** M5, **Stage B**. **Status:** specified (implementation follows Stage A, shipped in PR #13).
- **Owner:** architect. **Decisions pinned in:** [`adr/0007-distributed-block-production.md`](adr/0007-distributed-block-production.md).
- **Parent spec:** [`05-p2p-network.md`](05-p2p-network.md) (the M5 umbrella — transport, gossip, sync,
  block header, `state_root`). **Builds on:** [`adr/0004-consensus-and-networking.md`](adr/0004-consensus-and-networking.md).
- **Milestone brief:** [`../milestones/m5-p2p-network.md`](../milestones/m5-p2p-network.md) §"Stage B".
  **Invariants:** [`00-overview.md`](00-overview.md).

This spec makes block production **rotate** across a PoH-gated validator set and **survive proposer
failure**, without halting the chain and without ever weakening I1/I2. It is **crash-fault-tolerant
(CFT)** only: it tolerates up to `f` of `n` validators being *unavailable* (crashed / partitioned /
slow). **Byzantine / active-adversary consensus (BFT) is explicitly out of scope** and is left to the
backlog; §14 marks precisely where a BFT layer would attach.

It supersedes the *sketch* in `05-p2p-network.md` §5 (which was written slot-keyed and view-less) on two
points, both flagged where they occur: (a) the proposer schedule is keyed on **`(height, view)`**, not on
a timestamp-derived slot; (b) the block header gains a **`view`** field. `05` §5 is retained for context;
where the two differ, **this document is authoritative.**

It is written acceptance-criteria-first (§13). Every Stage-B exit criterion (EC-5, EC-6 from the brief,
plus the safety/liveness/determinism refinements) maps 1:1 to a test in §13.

---

## 0. The invariant this stage protects

> Rotation and view change are **liveness** mechanisms. They must not introduce a single non-deterministic
> input into committed state. **I1** (byte-identical state roots across processes) and **I2** (integer
> balances reproducible to the wei) hold *through* rotation and *through* a view change exactly as they
> held for Stage A's single proposer.

The discipline that makes this true (and that every rule below obeys):

- **The schedule, the view number, block validity, and fork choice are PURE functions of on-chain state +
  block headers.** They read no wall-clock and no peer table.
- **Local clocks drive only liveness** — *when* this node escalates a view, and *whether* this node
  chooses to propose. They never enter a committed value. A block's committed validity is identical on a
  node whose clock is fast and a node whose clock is slow.
- The block's **`timestamp`** remains the *only* clock execution reads (unchanged from Stage A / 05 §5.3),
  and it is validated for sanity but **does not select the proposer** (that is the §3 change from the 05
  sketch — see the rationale there).

Structural rule (unchanged, ADR-0004): `crates/runtime` stays deterministic and dependency-free. The two
genuinely-new deterministic primitives (the validator-set membership read and the `proposer_index`
function) live in `runtime`; every timer, peer-count check, and view-escalation decision lives in
`crates/node`.

---

## 1. Scope

**In scope (Stage B):**
- An on-chain, PoH-gated **validator set `V`** with a canonical order and epoch-boundary membership
  changes (§2.1, §3).
- A **deterministic round-robin proposer schedule** `proposer(height, view)` every node computes
  identically from on-chain state (§3).
- A **`view` field** in the block header and the minimal wire change to carry it (§2.2, §9).
- **Proposer timeout + view change**: a local, wall-clock-driven escalation to the next validator when a
  scheduled proposer does not deliver, with a purely-deterministic authorization of the successor (§5).
- **Fork choice**: a deterministic total order over competing chains so all honest nodes converge on one
  chain (§6).
- **k-deep commit/finality** under PoA round-robin CFT, with the CFT safety + liveness properties stated
  and argued (§6.3, §7).
- **Extended block validity + signature check** (§4), **back-compat** with the Stage-A single-proposer
  config (§10), and the RPC/consensus-status surface (§11).

**Out of scope (backlog / a later milestone — see §14):**
- **BFT / Byzantine tolerance**: view-change certificates, pre-vote/pre-commit rounds, accountable-safety
  slashing, equivocation *proofs that bind a quorum*, single-slot finality. Stage B tolerates crashes, not
  a malicious *majority* or a proposer that lies about the schedule.
- VRF / unpredictable leader election (the per-epoch shuffle in the 05 §2.1 sketch is **deferred** — §3.2).
- Validator **stake-slashing** beyond epoch eviction (FU-8 delivers epoch-boundary membership; economic
  slashing is backlog).
- Dynamic validator *onboarding* via live PoH during a run beyond what the epoch snapshot already gives.

---

## 2. Data model

### 2.1 The validator set `V` (new deterministic type in `crates/runtime`)

`V` is the ordered set of validator addresses eligible to propose in the current epoch.

- **Membership rule (pure).** An address `a` is a member iff **both**: (1) `a` is a **registered active
  validator** (`get_juror(a).active == true` — the M3 juror registry *is* the validator registry, one
  shared PoH-gated set, per 05 §6.1 / ADR-0004 D2); **and** (2) `a` is **`Verified`** in the PoH registry
  (`get_human(a).status == HumanStatus::Verified`). A validator that is not (or no longer) a verified
  human is **excluded** — this is the Sybil-resistance gate (only verified humans validate).
- **Canonical order.** `V` is the qualifying addresses **sorted ascending by their 20-byte big-endian
  value, deduplicated** — the identical discipline `active_jurors()` already uses (reliability report
  R5). No `HashMap` iteration order ever reaches the schedule (I1). `N = |V|`.
- **Epoch snapshot (how membership changes take effect — deterministically, at a boundary).** `V` is not
  recomputed per block from live membership; it is **snapshotted at each epoch boundary** so it is stable
  for a whole epoch even as humans are verified/revoked mid-epoch:
  - A new committed field `MemState::epoch_validators: Vec<Address>` holds the snapshot. It is part of
    committed state and **feeds `state_root`** (so all nodes agree on it by replay — see the §8
    serialization note).
  - The snapshot is **refreshed during the execution of every block whose height is a multiple of
    `EPOCH_BLOCKS`** (and seeded at genesis, height 0), by recomputing the membership rule over the
    *pre-block* state and sorting. This is a pure function of the parent state.
  - **Scheduling always reads the snapshot present in the *parent* state.** A boundary block `h`
    (`h % EPOCH_BLOCKS == 0`) is itself scheduled by the *previous* epoch's snapshot (the one already in
    its parent state); executing it installs the *new* snapshot, which governs blocks `h+1 …`. Thus a
    validator added/removed during epoch `e` first affects the schedule at the start of epoch `e+1` — a
    deterministic boundary, identical on every node.
  - This needs **no historical-state queries**: a validating node holds the parent state (with its
    snapshot) before it applies block `h`.

Runtime surface (pure, integer, no keys/networking):

```
// crates/runtime
pub fn validator_set(state: &dyn State) -> Vec<Address>;          // the current epoch snapshot, sorted
pub fn refresh_epoch_validators(state: &mut dyn State, height: u64); // called by execute_block at boundaries
pub fn proposer_index(height: u64, view: u32, n: usize) -> usize;  // = ((height + view) as usize) % n
```

`validator_set` returns the snapshot; `proposer_index` is the schedule (§3).

### 2.2 Block header — the `view` field (the one consensus-relevant addition)

The Stage-A header (05 §2.2) is `number, parent_hash, timestamp, txs_root, state_root, proposer,
proposer_sig`. Stage B inserts **one** field:

| Field | Type | Meaning |
|---|---|---|
| `view` | `u32` | the view (rotation offset) at which this block was produced. `0` for a block from the height's first-scheduled proposer; `k>0` for the `k`-th view-change successor (§5). |

- **Header pre-image (new byte order):**
  `number ‖ parent_hash ‖ timestamp ‖ view ‖ txs_root ‖ state_root ‖ proposer`
  (`view` inserted **after `timestamp`, before `txs_root`**, as a 4-byte big-endian integer).
- `hash = keccak256(header_preimage)`; `proposer_sig` signs that same pre-image. So the committed hash
  **commits the view** — two competing blocks at the same height with different views have different
  hashes, and a follower cannot alter a block's view without breaking the signature.
- `txs_root` is unaffected (`view` is not a tx). `recompute_txs_root` is unchanged.
- **Determinism:** `view` is committed data; it is not derived from any clock. A Stage-A block is exactly
  a Stage-B block with `view == 0`, which keeps the N=1 degenerate case byte-comparable across nodes
  (§10).

### 2.3 Jury-selection entropy includes `view`

`execute_block` derives a pre-execution `entropy_hash` (feeding *only* the seeded PRNG for jury selection,
never balances/roots — 05 §5.3). It currently hashes `(number, parent_hash, timestamp, 0, 0, 0)`. Stage B
**adds `view`** to that pre-image (`(number, parent_hash, timestamp, view, 0, 0, 0)`) so a view-change
successor's jury entropy is a pure function of its (now view-carrying) header. This changes no balance and
no state value; it only keeps `entropy_hash` a pure function of the committed header. Both proposer and
follower compute it identically.

---

## 3. The deterministic proposer schedule

### 3.1 The rule

For a block at height `h` and view `v`, the **scheduled proposer** is:

```
proposer(h, v) = V[(h + v) mod N]           where V = validator_set(parent_state), N = |V|
```

- `V` is the epoch snapshot in the **parent** state (§2.1), sorted ascending — identical on every node.
- At **view 0**, the base round-robin is `V[h mod N]`: consecutive heights rotate through validators, so
  over any `N` consecutive view-0 blocks each validator proposes exactly once (this is what EC-B1 / EC-5
  asserts).
- A **view change** (§5) increments `v`, advancing responsibility to the *next* validator in order:
  `proposer(h, v+1) = V[(h + v + 1) mod N]`. Because both `h` and `v` are on-chain (`h` from the parent,
  `v` from the header), the schedule is a pure integer function — no clock, no peer table, no `HashMap`.

### 3.2 Why `(height, view)` and not the 05-sketch's timestamp-slot (a reconciliation)

The 05 §2.1/§5.1 sketch keyed the schedule on `slot = floor((timestamp − genesis_time) / BLOCK_MS)` plus a
per-epoch shuffle. Stage B **replaces** that with `(height, view)` for two reasons:

1. **Determinism / manipulation.** A slot is derived from `timestamp`, which the proposer chooses. Keying
   the schedule on the proposer's own timestamp lets a validator nudge the timestamp to land itself in the
   proposer seat, and couples "who is the legit author" to a wall-clock-derived value. `(height, view)` is
   free of the timestamp entirely: `height` is fixed by the parent, `view` is committed by whoever
   legitimately view-changed. The timestamp is still validated for sanity (§4) but never *selects* the
   proposer.
2. **View change needs a clean successor index.** A timeout escalation is naturally "the *next* validator
   in rotation" — i.e. `view+1`. Encoding that as an additive `view` term makes the successor's identity a
   one-line pure function and makes the header self-describing (its `view` says which rotation offset
   authorizes it).

The **per-epoch shuffle** (making the order unpredictable-forever) is a grinding/predictability hardening
that matters for BFT, not for CFT — a crashed validator cannot exploit a predictable schedule. It is
**deferred to the BFT backlog** (§14). Stage B uses the plain, auditable round-robin.

### 3.3 Effective `V` resolution (one deterministic source per config)

Every node resolves the same `V` at a given height. There are exactly two modes, chosen by node config
(all nodes on a network must be configured alike — the devnet scripts already pin genesis time and the
proposer identity this way):

1. **Single-proposer override (Stage-A back-compat).** If the node is configured with a single designated
   proposer (`UBI2_DESIGNATED_PROPOSER`), it uses `V = [designated]` (`N = 1`). This takes **precedence**
   over any on-chain snapshot, so it does not matter whether genesis happened to seed other jurors — the
   override pins a 1-member rotation, exactly Stage A (§10).
2. **On-chain snapshot (authoritative Stage-B mode).** Otherwise, `V = validator_set(parent_state)` — the
   epoch snapshot (§2.1). This is the real multi-validator mechanism; membership is bootstrapped by genesis
   seeding (§13 setup) and evolves at epoch boundaries.

Determinism holds because the choice is a function of (identical) config, and each mode yields a `V` that
is identical on every node (a fixed address, or the replayed on-chain snapshot).

---

## 4. Block validity + signatures (extends the Stage-A check)

A received block at height `h`, view `v`, is **valid** iff **all** hold (any failure ⇒ reject; do not
apply, do not re-broadcast as accepted; the source peer may be penalized). This extends 05 §5.1 / the
Stage-A `Chain::validate_and_apply_block`:

1. **Contiguity + parent + timestamp (unchanged from Stage A).** `h == head.number + 1`;
   `parent_hash == head.hash`; `timestamp > parent.timestamp`. (Non-contiguous ⇒ drive sync, §4.2 of 05.)
2. **View in range.** `0 ≤ v < VIEW_MAX` (§12). A block with an absurd view is rejected `ViewOutOfRange`
   — this is the only "view justification" a CFT model needs (see §5.4 and §14 for why a *certificate* is
   not required under crash faults, and where BFT would add one).
3. **Author = scheduled proposer.** Resolve the effective `V` (§3.3): if `validator_override` is `Some(a)`
   then `V = [a]` (the Stage-A singleton, §10); else `V = validator_set(parent_state)` (the on-chain epoch
   snapshot). `N = |V|`; require `N ≥ 1` (`NoValidatorSet` otherwise). Let `expected =
   V[proposer_index(h, v, N)]`. Require `proposer == expected` (`WrongProposer` otherwise).
4. **Signature recovers to the author.** `ecrecover(proposer_sig, header_hash) == proposer`
   (`BadSignature` otherwise). `header_hash` now includes `view` (§2.2).
5. **Deterministic state transition (the I1/I2 cross-node check — unchanged from Stage A).** Re-executing
   the block's ordered raw txs against the parent state at `timestamp` yields a post-state whose root is
   **byte-identical** to the header `state_root`, and the recomputed `txs_root` and `hash` match the
   header. Mismatch ⇒ `StateRootMismatch`, rolled back to a no-op (fail-closed).

`validate_and_apply_block` signature change (in `crates/rpc`):

```
pub fn validate_and_apply_block(
    &self,
    number: u64, parent_hash: B256, timestamp: u64,
    view: u32,                                   // NEW (from the header)
    claimed_txs_root: B256, claimed_state_root: B256,
    proposer: Address, proposer_sig: &[u8],
    raw_txs: &[Vec<u8>],
    validator_override: Option<Address>,         // REPLACES `expected_proposer` — see §3.3 / §10
) -> Result<Block, BlockError>;
```

The follower resolves `V` (§3.3) and computes `expected` itself (checks 3–4). `validator_override` is the
Stage-A back-compat path (§10): when the node is configured with a single designated proposer, it passes
`Some(designated)`, pinning `V = [designated]` — a 1-member rotation identical to Stage A — which takes
**precedence** over any on-chain snapshot. In multi-validator Stage-B mode the node passes `None` and the
authoritative on-chain snapshot is used.

New `BlockError` variants: `NoValidatorSet`, `ViewOutOfRange { view }`. `WrongProposer` / `BadSignature`
keep their meaning (now computed against the schedule, not a fixed designated proposer).

---

## 5. Proposer timeout + view change (CFT liveness)

A crashed or slow scheduled proposer must not halt the chain. Every node runs a **local** timeout that
advances the view; the successor is authorized purely by the schedule.

### 5.1 The local timer (wall-clock is LOCAL only — I2)

Each node tracks, for the height it is trying to extend (`h = head + 1`), a **local `current_view`** and a
**deadline**:

- On adopting a new head at height `h−1` (by production or by applying a received block), the node sets
  `current_view = 0` for height `h` and arms `deadline = now + PROPOSER_TIMEOUT`.
- The node computes `expected = proposer(h, current_view)`:
  - If **this node is `expected`** (its validator key's address == `expected`) *and* the production guard
    (§5.3) is satisfied, it **produces** block `h` at `view = current_view`, signs it, broadcasts it.
  - If this node is *not* `expected`, it waits for a valid block `h` (any view) until `deadline`.
- **On timeout** (no valid block `h` by `deadline`): increment `current_view`, re-arm
  `deadline = now + PROPOSER_TIMEOUT`, recompute `expected = proposer(h, current_view)`. Repeat.
- **On receiving a valid block `h`** (§4): adopt it (per fork choice, §6), advance to `h+1`, reset
  `current_view = 0`. Its header `view` may be `> current_view` (a faster peer escalated first) — that is
  fine; the block is authorized by *its own* `view`, not by this node's local counter.

`now` is a node-local wall-clock. It appears **only** in the deadline arithmetic and the production choice.
It never enters a committed value: two nodes with skewed clocks may escalate at different real instants but
still agree, block-for-block, on *which* block is valid and canonical, because validity (§4) and fork
choice (§6) read only `(state, header)`. This is the concrete preservation of I1/I2 across the view change.

### 5.2 Successor authorization (no BFT vote needed)

When view `v` times out and `proposer(h, v+1)` produces block `h` with `view = v+1`, **followers accept it
by the ordinary validity check** (§4): its `proposer` equals `V[(h + v+1) mod N]` and its signature
recovers to that address, and its header says `view = v+1`. No separate view-change message, no quorum of
timeout votes, no certificate. **This is the CFT simplification:** under crash-only faults a slow/crashed
proposer emits *nothing*, so the successor's block has no legitimate lower-view competitor to improperly
skip; author==schedule(h, view) is sufficient authorization. (Under an active adversary this is exactly
insufficient — §14.)

### 5.3 Production connectivity guard (partition-safe finality — a local liveness policy)

Pure round-robin CFT has a partition hazard: a minority partition's local timers would escalate views
until a validator *inside* that partition is scheduled, and it would keep producing and *finalizing*
(k-deep) a divergent chain — which, on heal, would demand a reorg deeper than `FINALITY_DEPTH`, breaking
the finality guarantee. To keep finality partition-safe **without** adding a BFT vote, a node **produces**
a block only when it is **connected to a majority of the current `V`**:

```
majority = N/2 + 1        // integer; counts this node itself if it is a validator
produce  ⇔ (this node is the scheduled proposer for (h, current_view))
          AND (# of distinct V-members reachable, including self, ≥ majority)
```

- This gates **production** (a liveness decision), never **validation** (which stays a pure function of
  `(state, header)`). A minority partition therefore **stalls** (produces nothing, finalizes nothing)
  rather than forking finalized history; when the partition heals it re-syncs to the majority chain via
  fork choice (§6) and sync (05 §4.2).
- For `N = 1`, `majority = 1` (self) ⇒ always satisfied ⇒ **Stage A is unaffected** (§10).
- "Reachable" is read from the node's live peer table (the bound-validator set from the `Hello` binding,
  05 §4.1). It is a local signal; it never enters state. It only decides whether *this* node proposes.

This is the concrete meaning of the brief's / 05 §5.5 "live while a majority of `V` is live": *production*
needs the scheduled-or-successor proposer up **and** majority-connected; a minority cannot finalize.

### 5.4 Re-convergence when the original proposer recovers

If `proposer(h, 0)` was merely slow (not crashed) and produces block `h @ view 0` *after* a successor
already produced `h @ view 1`, both valid blocks exist at height `h`. Fork choice (§6) resolves this
deterministically: at equal height, **lower view wins**, so the original `view 0` block becomes canonical
and nodes that had adopted the `view 1` block **reorg** to it (bounded to `< FINALITY_DEPTH`). If instead
the `view 1` branch has already grown taller (a child at `h+1`), **longest chain wins** and the late
`view 0` block is orphaned. Either way every honest node converges on one chain. This is how a recovered
proposer is reconciled: no special message, just the fork-choice total order applied to the newly-visible
block.

---

## 6. Fork choice + finality

### 6.1 The canonical-chain rule (a deterministic total order)

Among the valid chains a node knows (each a sequence of §4-valid blocks from genesis), the **canonical**
one is chosen by, in order:

1. **Greatest height** (longest valid chain). *[liveness — the chain that made the most progress wins]*
2. Tie ⇒ **lowest tip `view`**. *[prefer the earlier-scheduled proposer over a view-change successor]*
3. Tie ⇒ **lowest tip `hash`**. *[final deterministic tiebreak; also resolves equivocation, §6.4]*

Two distinct valid chains of equal height have distinct tip blocks (different `hash`), so rule 3 always
terminates the comparison: the order is **total**. Every honest node applies the same rule to the same
eventually-consistent set of valid blocks and selects the same head (I1). Reorgs are bounded to depth
`< FINALITY_DEPTH` (§6.3); a block that would require a deeper reorg is rejected (fork detection, 05 §4.3).

This **refines** the Stage-A rule (05 §5.2, "longest, then lowest hash") by inserting the `view` tiebreak
between them. Stage-A blocks are all `view 0`, so the new tiebreak is a no-op there — **Stage A behavior is
preserved** (§10).

### 6.2 Why tip-only comparison is sufficient

A node need only compare **tips** `(height, view, hash)`, not walk the whole branch: any two distinct
equal-height chains differ in their tip hash, so `(height desc, view asc, hash asc)` on tips is a total
order on chains. This keeps fork choice O(1) per candidate and trivially deterministic.

### 6.3 Commit / finality (k-deep, CFT — *not* BFT finality)

- A block at height `h` is **committed / final** once the canonical head is at height `≥ h +
  FINALITY_DEPTH` (`k = 6` devnet default). Equivalently `finalized_height = head.height − FINALITY_DEPTH`
  (saturating). This matches 05 §5.6 and the existing `NetStatus.finality_depth`.
- **No reorg may cross a finalized block.** A received block whose adoption would reorg at or below
  `finalized_height` is rejected.
- This is **probabilistic / depth-based** finality: it guarantees non-reversal *under the CFT model +
  the §5.3 production guard*. It is **not** BFT single-slot finality — there is no quorum certificate that
  proves a block irreversible the instant it is produced. An actively-malicious *majority* of `V` could,
  in principle, rewrite recent-but-unfinalized history; that is the BFT threat model, out of scope (§14).

### 6.4 Equivocation (a Byzantine action — handled only enough to not split honest nodes)

Two distinct valid blocks signed by the *same* proposer for the *same* `(h, view)` is **equivocation**. It
is a Byzantine action (a crash-only fault emits at most one block per `(h, view)`), so it is outside the
CFT fault model — but the fork choice must still not *split* honest nodes if it occurs:

- The deterministic tiebreak (§6.1 rule 3, lowest hash) means all honest nodes keep the **same** one of the
  two equivocating blocks. No split. *(AC-F4 / EC-B-F4.)*
- **Shipped in Stage B:** only the no-split guarantee above (the lowest-hash tiebreak) — it is the sole
  CFT-relevant property, since equivocation is Byzantine and outside the fault model. Stage B does **not**
  evict; an equivocator simply keeps its round-robin slots like any other faulty CFT validator (covered by
  view-change), with no honest-node divergence.
- **Deferred (FU-8 / BFT, §14):** recording the pair as **equivocation evidence** and **excluding the
  equivocator from `V` at the next epoch boundary**, plus stake-slashing and a *binding, quorum-backed*
  equivocation proof. These are accountable-safety concerns, not CFT-safety ones.

---

## 7. Safety + liveness (the CFT fault model, stated)

**Fault model.** Crash-only: up to `f` of `n = N` validators are *unavailable* (crashed, partitioned, or
too slow to meet `PROPOSER_TIMEOUT`) at any time. Validators do **not** lie about the schedule, do **not**
equivocate as a strategy, and do **not** forge signatures (those are Byzantine — §14). Non-validator peers
may be arbitrarily hostile on the *transport* (handled by 05 §3.3/§4 anti-abuse) but cannot author blocks
(no valid signature from a member of `V`).

**Safety property (no conflicting finalized block).** Under the fault model + the §5.3 production guard,
no two honest nodes finalize conflicting blocks at the same height.
*Argument (convergence, not a BFT certificate).* (a) Every honest node applies the same **total** fork-choice
order (§6.1) to the same eventually-consistent set of §4-valid blocks (gossip + sync deliver every valid
block to every connected node). (b) Crash faults produce no competing signed blocks; the only forks are
original-vs-successor tip races (§5.4), each resolved by the deterministic order. (c) The §5.3 guard
prevents a minority partition from finalizing at all. (d) Finality is k-deep and no reorg crosses it (§6.3).
Therefore below the finalized frontier every honest node holds the identical single chain. ∎ *(This is a
convergence argument valid under crash faults; it is **not** an accountable-safety proof against a
malicious quorum — that is BFT.)*

**Liveness property (production does not halt).** Production continues — a new block is produced and
eventually finalized — as long as, for the height being extended, some validator reached by successive
views is **live and majority-connected**. With the round-robin, as `view` increments responsibility cycles
through all `N` validators; if `f` of them are down, at most `f` consecutive scheduled proposers are dead,
so a live one is reached within `≤ (f + 1) × PROPOSER_TIMEOUT`. For EC-6's `N = 3, f = 1`: the very next
view lands on a live validator, so recovery is `≤ 2 × PROPOSER_TIMEOUT`, within the `MAX_VIEW_CHANGES = 3`
budget. *(Note the CFT/BFT asymmetry: production stays live with any single live+connected proposer, but
partition-safe **finality** requires a majority — the §5.3 guard enforces exactly this.)*

---

## 8. Determinism (I1/I2 preserved through rotation + view change)

Everything that reaches committed state is a pure function of `(state, header, txs)`:

| Quantity | Pure function of | Never reads |
|---|---|---|
| `V` (epoch snapshot) | committed state at the epoch boundary (feeds `state_root`) | clock, peer table |
| `proposer(h, v)` | `(h, v, V)` — integer only | clock, `HashMap` order |
| `view` | committed in the header (signed, hashed) | clock |
| block validity (§4) | `(parent_state, header, txs)` | clock (beyond `timestamp` sanity) |
| fork choice (§6) | tips `(height, view, hash)` of known valid blocks | clock, arrival order |
| `state_root` | post-block state, all collections sorted | `HashMap` order |

**Local-only signals** (never committed, drive liveness only): the view-escalation deadline (`now`), the
production connectivity guard (§5.3 peer count). A node's clock skew or peer count changes *when* it
proposes/escalates, never *what* is valid or canonical.

**`state_root` addition.** The new `epoch_validators` snapshot must be serialized into `state_root` in its
sorted order (it already is — §2.1 stores it sorted), appended to the existing sorted-collection
concatenation (05 §5.3 / runtime `state_root`). This is the only new state that feeds the root; it is a
sorted `Vec<Address>`, so it adds no `HashMap`-order hazard. **Determinism checklist item:** two nodes at
the same height compute a byte-identical `epoch_validators` (they replayed the same boundary blocks) ⇒
byte-identical `state_root` (EC-B5 / EC-4 preserved).

**`entropy_hash`** includes `view` (§2.3) — still a pure function of the header; it feeds only jury
seeding, not balances.

---

## 9. Wire / protocol changes (MINIMAL — no BFT vote messages)

CFT needs **no** new message types — no pre-vote/pre-commit, no view-change certificates. The entire Stage-B
mechanism rides the existing gossip/sync by adding one field to the block:

1. **`WireBlock` (`crates/network/src/wire.rs`) + `rpc::Block` gain `view: u32`.**
   - `WireBlock::encode/decode`: insert `view` as a 4-byte big-endian integer **after `timestamp`, before
     `txs_root`** (mirroring the header pre-image, §2.2). `header_preimage`, `hash`, and
     `recover_proposer` follow automatically. `recompute_txs_root` / `shallow_verify` semantics are
     unchanged (`shallow_verify` still checks `txs_root` + a present, recovering signature).
   - `rpc::Block::header_preimage` / `compute_hash` gain the `view` argument in the same position.
2. **`PROTOCOL_VERSION` bumps `1 → 2`** (`crates/network/src/consts.rs`), and the handshake (`on_hello`,
   `crates/node/src/net.rs`) **adds a check**: a peer whose `hello.protocol_ver` major version differs is
   treated as incompatible and disconnected (alongside the existing genesis/chain-id check). This makes the
   block-encoding change a **loud, explicit break at the handshake** rather than a silent decode mismatch.
3. **No topic / sync-protocol string bump.** The gossip topics (`ubi2/tx/1`, `ubi2/block/1`) and the sync
   protocol (`ubi2/sync/1`) strings are **unchanged**. The block *payload* on `ubi2/block/1` is redefined
   in place to include `view` (see ADR-0007 Decision "wire versioning" for why in-place, not a topic bump:
   there is no deployed `ubi2/block/1` network to silently break — Stage A is devnet-only and upgrades in
   lockstep — and bumping would needlessly fork the browser light node's `ubi2/sync/1` reuse (spec 07)).
   `Hello` is structurally unchanged: its `tip.hash` already commits `view` via the pre-image, so a tip is
   still `(height, hash)`.
4. **`Blocks`/sync** carry the new `WireBlock` encoding automatically (they encode `WireBlock`), bounded as
   before by `SYNC_MAX_BATCH`.

A mixed old/new devnet does not interoperate — the version check disconnects at the handshake and any
stray old-encoding block fails length-checked decode / `shallow_verify` and is dropped, never
misinterpreted into valid-looking state.

---

## 10. Back-compat with Stage A (`N = 1` degenerate rotation)

Stage B is a strict generalization: **a single-validator config is Stage A.**

- **`N = 1`:** `proposer(h, v) = V[0]` for every `h, v` ⇒ the sole validator is always the scheduled
  proposer; a view change never lands on anyone else; every block is `view 0`. This is byte-for-byte the
  Stage-A "one designated proposer + N followers."
- **Validator identity vs. the set.** The per-node key config is unchanged (`UBI2_PROPOSER_KEY` /
  `UBI2_VALIDATOR_KEY` tell a node *which* validator it is). What changes is that in multi-validator mode
  the authoritative `V` is the **on-chain** epoch snapshot (§2.1), not a single env address. For
  back-compat, a node configured with `UBI2_DESIGNATED_PROPOSER` pins `V = [designated]` (`N = 1`), and
  that **override takes precedence** over any on-chain snapshot (§3.3) — so an old-style single-proposer
  config runs Stage B in the `N = 1` case and behaves identically regardless of what genesis seeded.
- **The `m5_stage_a` acceptance test is UNCHANGED and stays green.** It configures one proposer +
  `UBI2_DESIGNATED_PROPOSER` and two key-less followers. Under Stage B this is `N = 1` via the
  single-proposer override (§3.3, which takes precedence over any seeded jurors): all blocks are `view 0`,
  the followers validate against `V[0] == the designated proposer`, no view change ever fires, the `view`
  tiebreak in fork choice is inert, and the production guard's `majority = 1` is always met. The only mechanical change the test
  transits is that produced/validated headers now carry `view = 0` and hash it in — but the test asserts
  *cross-node agreement* (equal `eth_blockNumber` / `ubi_stateRoot` / balances), not any hardcoded hash, so
  all-new nodes running the new binary agree exactly. **No edit to `m5_stage_a.rs` is required.**
- **Multi-validator Stage B** is opted into by seeding `≥ 2` validators into genesis identically on every
  node (the new `scripts/devnet-multi-b.sh`, §13 setup), so `V` is identical on all nodes by replay.

---

## 11. RPC surface (extends 05 §11)

- **`ubi_consensusStatus`** gains: `validatorSet: [Address]` (the current epoch snapshot, sorted),
  `n` (`|V|`), `currentView` (this node's local view for the height it is extending — a *local* value,
  labeled as such), `scheduledProposer` (`proposer(head+1, currentView)`), and the existing
  `finalizedHeight` / `head`. Backs EC-B1/EC-B2 assertions. `NetStatus` gains `validator_set: Vec<Address>`
  and `current_view: u32`.
- **Block reads.** `view` is a `ubi2` extension surfaced on `ubi_consensusStatus` and (optionally) as an
  extra field on `ubi_getBlock`. **I3 (EVM compat) is preserved:** standard `eth_getBlockByNumber` /
  `eth_getBlockByHash` field sets and semantics are **not** changed — `view` never appears as a repurposed
  standard field; unmodified wallets are unaffected.
- All Stage-B reads are **read-only** (I6). No new write surface; the only new tx-like input is the
  optional equivocation-evidence report (§6.4), which is a normal signed tx verified deterministically.

---

## 12. Constants (devnet; reconciles with 05 §10)

| Constant | Value | Meaning | Home |
|---|---|---|---|
| `BLOCK_MS` | 2000 | block interval (existing) | node |
| `EPOCH_BLOCKS` | 100 | height multiple at which `V` is re-snapshotted (§2.1) | runtime/node |
| `PROPOSER_TIMEOUT` | 2 × `BLOCK_MS` | local wait before a view change (§5) | node |
| `MAX_VIEW_CHANGES` | 3 | bounds EC-6's "within 3 proposer timeouts" (a *test/observability* budget, not a hard protocol cap — the view keeps incrementing while any validator is live) | node |
| `FINALITY_DEPTH` (`k`) | 6 | k-deep finality; reorg bound (§6.3) | node |
| `VIEW_MAX` | 1024 | reject a block with `view ≥ VIEW_MAX` (§4 check 2). Healthy operation keeps `view < N`; this is a generous anti-garbage bound. | runtime/node |
| `MAJORITY(N)` | `N/2 + 1` | production connectivity guard threshold (§5.3) | node |

`SYNC_MAX_BATCH`, mempool caps, rate limits, `PROTOCOL_VERSION` (now `2`, §9) live in
`crates/network/src/consts.rs` as today. The consensus-only constants (`EPOCH_BLOCKS`, `PROPOSER_TIMEOUT`,
`MAX_VIEW_CHANGES`, `FINALITY_DEPTH`, `VIEW_MAX`) live with the node/runtime Stage-B work, not the transport
crate (per the `consts.rs` header note).

---

## 13. Acceptance criteria (Stage B — 1:1 with tests)

CI uses `MockOracle`/`MockInterpreter` so the AI path is deterministic (I5). Multi-process tests spawn
independent `ubi2-node` processes (distinct ports/keys/data dirs), as `m5_stage_a.rs` does. Setup for the
rotation/liveness tests: a **`scripts/devnet-multi-b.sh`** launching 3 validator nodes, each with its own
`UBI2_VALIDATOR_KEY`/`UBI2_PROPOSER_KEY`, and an **identical genesis** that seeds all three addresses as
`Verified` humans + registered validators (so `V = {n1, n2, n3}` on every node by replay).

| EC | Maps to | Setup → Assertion | Kind |
|---|---|---|---|
| **EC-B1** | EC-5 (rotation) | 3-validator devnet; mine 30 blocks. **Assert:** ≥ 2 of the 3 addresses appear as `block.proposer`; no single address is the proposer of *all* 30; and for every view-0 block, `proposer == V[height mod 3]` (schedule holds). Read via `ubi_consensusStatus` + block `proposer`. | multi-proc |
| **EC-B2** | EC-6 (liveness) | 3-validator devnet at a known height; SIGKILL the node that is `proposer(head+1, 0)`. **Assert:** the chain height advances again within `≤ MAX_VIEW_CHANGES × PROPOSER_TIMEOUT`; the recovering block has `view ≥ 1` and `proposer == V[(height + view) mod 3]`; the chain never halts (a later block always appears). | multi-proc |
| **EC-B3** | safety | Feed a follower two competing valid blocks at the same height — `h @ view 0` (late original) and `h @ view 1` (successor). **Assert:** the follower's canonical head at `h` is the **`view 0`** block (lowest-view tiebreak), deterministically, regardless of arrival order; and across all nodes the finalized block at every height `≤ finalized_height` is identical (no conflicting finalized block). | integration + unit |
| **EC-B4** | re-convergence | EC-B2's killed node is **restarted**. **Assert:** it re-syncs to the canonical chain (same finalized head hash + same `ubi_stateRoot` as the live nodes) with **no manual steps**, then resumes proposing when next scheduled. (Extends EC-7.) | multi-proc |
| **EC-B5** | I1 | Run 30 blocks with rotation **and** ≥ 1 forced view change (kill+restart mid-run). **Assert:** `ubi_stateRoot` is **byte-identical** across all live nodes at every common height, and `eth_getBalance` for a tracked address at a common height is the same integer on all nodes (I1/I2 through rotation + view change). | multi-proc |
| **EC-B6** | I1 (determinism) | Unit/property test of the pure functions. **Assert:** `validator_set(state)` is identical under shuffled validator *insertion* order; `proposer_index(h, v, N)` is a pure integer function; the fork-choice total order picks the same head under shuffled competing-block *arrival* order (no `HashMap` order, no clock). | unit |
| **EC-B-F3** | AC-F3 | A block whose `proposer ≠ V[(h+view) mod N]` — or one claiming `view = k` but signed by the wrong validator for that view — is submitted. **Assert:** rejected `WrongProposer` (or `BadSignature`); not applied; peer penalized. | unit + integration |
| **EC-B-F4** | AC-F4 | A validator signs two distinct blocks for the same `(h, view)` (equivocation). **Assert:** honest nodes do **not** split — all deterministically keep the lowest-hash block (§6.1 rule 3 / §6.4). *(Evidence recording + epoch eviction are **deferred** to FU-8/BFT per §6.4 — intentionally NOT asserted here; Stage B ships only the no-split property.)* | unit |
| **EC-B-F5** | view bound | A block with `view ≥ VIEW_MAX` is submitted. **Assert:** rejected `ViewOutOfRange`; not applied. And: a `view 1` successor followed by a late `view 0` original triggers a **bounded** reorg to `view 0` (no stuck fork, reorg depth `< FINALITY_DEPTH`). | unit + integration |
| **EC-A (regression)** | Stage A | `m5_stage_a.rs` runs unchanged. **Assert:** EC-1/2/3/4/7 stay green under the Stage-B binary (the `N = 1` degenerate path, §10). | multi-proc |

---

## 14. Open questions + the CFT ↔ BFT boundary

**BFT is explicitly out of scope for Stage B.** The design is deliberately factored so a future BFT
milestone replaces *only* the proposer/finality mechanism, touching neither the wire formats, the sync
protocol, the AI-quorum protocol, nor `crates/runtime`'s state transition (ADR-0004 "upgrade path"). Where
BFT attaches:

- **View-change certificate (the successor authorization, §5.2).** CFT authorizes a successor by
  `author == schedule(h, view)` alone. BFT would require the successor to carry a **certificate** — a
  quorum (`≥ 2f+1`) of signed timeout/`view-change` votes proving the lower views legitimately failed — so
  a malicious validator cannot *skip ahead* to grab a view it is not entitled to. That certificate is the
  new wire message a BFT layer adds; Stage B adds none.
- **Single-slot finality (§6.3).** CFT is k-deep probabilistic. BFT (Tendermint/HotStuff-style
  pre-vote/pre-commit over the same `V`) gives a **commit certificate** that finalizes a block the instant
  a quorum pre-commits — replacing k-deep with instant, accountable finality. The `V`/epoch/schedule
  abstraction is reused verbatim; fork choice becomes "the certified chain."
- **Accountable safety / slashing (§6.4).** CFT records equivocation evidence and epoch-evicts. BFT binds
  equivocation to a **slashable, quorum-verifiable proof** (a validator signing two conflicting commits at
  one height is provably faulty). Stake-slashing (FU-8 beyond epoch eviction) rides on that.
- **Unpredictable leader election (§3.2).** The deferred per-epoch VRF/shuffle is a BFT-era
  grinding/predictability hardening; irrelevant under crash faults.
- **Partition-safe finality (§5.3).** The production connectivity guard is a *pragmatic* CFT safety valve
  (gate production on majority-connectivity). BFT's quorum certificate makes this rigorous: a minority
  partition simply cannot form a commit certificate, so it cannot finalize — no local heuristic needed.

**Open questions handed to the protocol-engineer + the gates:**
1. Should the epoch validator snapshot be an explicit committed `Vec<Address>` (this spec's choice, §2.1)
   or derivable on demand from the juror + human registries with a boundary-quantized read? The explicit
   snapshot is chosen for determinism-safety (no historical-state query); confirm it fits the persistence
   model (FU-3) without bloating `state_root`.
2. Is `PROPOSER_TIMEOUT = 2 × BLOCK_MS` the right default given gossip latency + the production guard's
   peer-count check? The reliability gate should tune it against the soak/partition tests (Stage D).
3. Equivocation-evidence transport: piggy-backed as a normal signed tx (this spec's assumption) vs. a
   dedicated report path. Kept as a normal tx to avoid a new wire message under CFT; revisit for BFT.
4. Should the production guard count `Verified`-bound validator peers only, or any peer? This spec counts
   **bound V-members** (the §4.1 handshake binding); confirm the eclipse threat model (security gate).

---

## 15. Implementation task breakdown (maps to 05 §8.2 Stage B B1–B6)

- **B1 — `runtime` (pure).** `validator_set` + `epoch_validators` snapshot field + `refresh_epoch_validators`
  (boundary + genesis) + `proposer_index`; serialize the snapshot into `state_root` (§2.1, §8). No async,
  no keys.
- **B2 — header `view` + proposer-aware production.** Add `view` to `rpc::Block`/`WireBlock` +
  pre-image/hash/encode (§2.2, §9); `produce_block(timestamp, view)`; `execute_block` folds `view` into
  `entropy_hash` (§2.3).
- **B3 — validity + fork choice + equivocation.** Extend `validate_and_apply_block` (§4 signature change);
  the fork-choice total order (§6.1) + k-deep finality + reorg bound (§6.3); equivocation detection +
  next-epoch eviction (§6.4).
- **B4 — timeout + view change.** The node's local per-height view timer + escalation + the production
  connectivity guard (§5); `PROTOCOL_VERSION` bump + handshake version check (§9).
- **B5 — FU-8 membership.** Validator/juror registration + revocation flowing through the epoch snapshot
  (§2.1); the equivocation eviction path.
- **B6 — CI + devnet.** `scripts/devnet-multi-b.sh` (3 seeded validators); the kill-the-proposer +
  restart harness asserting **EC-B1…EC-B6, EC-B-F3…F5**, and the **EC-A regression** (`m5_stage_a`
  unchanged, green).
</content>
</invoke>
