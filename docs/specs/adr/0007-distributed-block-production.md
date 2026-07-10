# ADR-0007 — Distributed block production (M5 Stage B): round-robin proposer on `(height, view)`, longest-chain + lowest-view fork choice, timeout view change, CFT not BFT

- **Status:** accepted (M5 Stage B)
- **Date:** 2026-07-09
- **Deciders:** architect (this ADR) + product-strategist (M5 brief) — to be ratified by protocol-engineer,
  reliability-engineer, security-engineer at the M5 Stage-B gate.
- **Spec:** [`../08-distributed-block-production.md`](../08-distributed-block-production.md).
  **Milestone:** [`../../milestones/m5-p2p-network.md`](../../milestones/m5-p2p-network.md) §"Stage B".
- **Builds on:** [`0004-consensus-and-networking.md`](0004-consensus-and-networking.md) (the PoA-round-robin
  direction, the validator-identity/PoH-gating model, the transport + wire formats + `state_root` this
  stage consumes). This ADR **refines ADR-0004 Decision 2** with the concrete schedule, view-change, and
  fork-choice mechanics, and **records two deviations** from the `05-p2p-network.md` §5 sketch.
- **Does not change** any deterministic state transition in `crates/runtime` beyond adding two pure,
  integer, dependency-free primitives (the validator-set read and `proposer_index`) and one committed
  sorted `Vec<Address>` snapshot that feeds `state_root`.

These decisions are costly to reverse — the schedule keying, the block-header shape (`view`), the
fork-choice rule, and the CFT-vs-BFT scope line are all hard to change once nodes interoperate and once a
persistent chain commits blocks under them — so they are pinned here. Where the M5 brief or ADR-0004 gave
a recommendation, it is adopted unless a reason is stated.

---

## Context

Stage A (shipped, PR #13) built a real libp2p network with **one fixed designated proposer** and N
followers: the proposer stamps each block with `proposer` + a header signature, and followers validate the
author against a single configured `UBI2_DESIGNATED_PROPOSER` and re-execute to a byte-identical
`state_root` (I1/I2 across processes). It cannot rotate and it halts if that one proposer dies.

Stage B makes production **rotate** across a validator set and **survive proposer failure**, and it must do
so without adding a single non-deterministic input to committed state. The M5 brief scopes Stage B
explicitly to **crash-fault tolerance** ("a downed node does not halt the chain") and puts **BFT on the
backlog** (Risk 3). ADR-0004 Decision 2 already chose PoA round-robin CFT and sketched the pieces; this ADR
pins the exact mechanics an engineer builds from.

The hard constraint remains: `crates/runtime` stays deterministic and dependency-free (no floats, no
wall-clock, no `HashMap` order on any consensus path, no async/network). The two new deterministic
primitives live in `runtime`; every timer and peer-count check lives in `crates/node`.

---

## Decision 1 — Deterministic proposer schedule keyed on `(height, view)`: `proposer(h, v) = V[(h + v) mod N]`

**Decision.**
- The **validator set `V`** is the addresses that are both a **registered active validator** (the M3 juror
  registry, one shared PoH-gated set) **and** `Verified` humans, **sorted ascending by address,
  deduplicated** (the same order `active_jurors()` already guarantees). `N = |V|`.
- `V` is **snapshotted at epoch boundaries** (`EPOCH_BLOCKS = 100`) into a committed
  `MemState::epoch_validators: Vec<Address>` that **feeds `state_root`**. Scheduling reads the snapshot in
  the **parent** state; a boundary block refreshes it for subsequent blocks. Membership changes therefore
  take effect at the **next epoch boundary** — a deterministic point identical on every node — with no
  historical-state query.
- The **scheduled proposer** for height `h`, view `v` is `proposer(h, v) = V[(h + v) mod N]`, a pure
  integer function (`crates/runtime::proposer_index`). View 0 is the base round-robin `V[h mod N]`; a view
  change advances to `V[(h + v + 1) mod N]`.

**Rationale — `(height, view)` over the `05` §5 timestamp-slot sketch.** The 05 sketch keyed the schedule
on `slot = floor((timestamp − genesis_time) / BLOCK_MS)` plus a per-epoch shuffle. We deviate:
- **Determinism / manipulation.** A slot derives from `timestamp`, which the proposer picks — keying "who
  is the legit author" on the author's own timestamp is a manipulation vector and couples authorship to a
  wall-clock value. `(height, view)` reads only on-chain data: `height` is fixed by the parent, `view` is
  committed by whoever legitimately view-changed. The timestamp is still sanity-checked but **never selects
  the proposer**.
- **Clean successor index.** A timeout escalation is exactly "advance to the next validator" = `view + 1`;
  an additive `view` term makes the successor a one-line pure function and makes the header self-describing
  (its `view` says which rotation offset authorizes it).

**Rejected.** (a) **Timestamp-slot schedule** (05 sketch) — the manipulation/coupling above. (b) **Plain
`slot mod N` with no `view`** — no way to name the successor after a timeout without a separate protocol.
(c) **Per-epoch VRF/shuffle** (the 05 sketch's "unpredictable-forever" order) — a grinding/predictability
hardening that matters under an *active adversary* (BFT); a crashed validator cannot exploit a predictable
round-robin. **Deferred to the BFT backlog** to keep Stage B a small, auditable round-robin. (d) **Env-var
validator set** (`UBI2_VALIDATORS` as truth) — two sources of truth is a determinism footgun; `V` is
authoritative **on-chain** (the epoch snapshot), bootstrapped by genesis seeding, with the per-node key
telling a node only *which* member it is.

**Consequences.** `crates/runtime` gains `validator_set`, `refresh_epoch_validators`, `proposer_index`
(pure, integer) and one committed sorted `Vec<Address>` in `state_root`. No keys, no networking enter
`runtime`.

---

## Decision 2 — Proposer timeout + view change: local-clock liveness, schedule-only successor authorization (no BFT vote)

**Decision.**
- Each node runs a **local** per-height timer. For the height it is extending, it holds a local
  `current_view` and a `deadline = now + PROPOSER_TIMEOUT`. If it is `proposer(h, current_view)` (and the
  §"production guard" holds) it produces and signs block `h` at `view = current_view`; otherwise it waits.
  On timeout it increments `current_view`, re-arms the deadline, and recomputes the expected proposer.
- **The successor is authorized purely by the schedule.** A block at `(h, view)` is accepted by the
  ordinary validity check: `proposer == V[(h + view) mod N]` **and** `ecrecover(sig) == proposer` **and**
  `0 ≤ view < VIEW_MAX`. **No view-change message, no quorum of timeout votes, no certificate.**
- **Wall-clock is LOCAL only.** `now` appears solely in the deadline arithmetic and the production choice;
  it never enters a committed value. Clock-skewed nodes may escalate at different real instants but agree
  block-for-block on validity and canonicality (I1/I2).
- **Production connectivity guard (partition-safe finality).** A node *produces* only when it is connected
  to a **majority of `V`** (`N/2 + 1`, counting itself). This gates production (a liveness policy), never
  validation (a pure function), so a minority partition **stalls** rather than finalizing a divergent
  chain; on heal it re-syncs via fork choice. For `N = 1` the majority is 1 ⇒ Stage A unaffected.

**Rationale.** Under **crash-only** faults a slow/crashed proposer emits *nothing*, so a successor's block
has no legitimate lower-view competitor to improperly skip — `author == schedule(h, view)` is sufficient
authorization, and no vote/certificate is needed. This is the whole reason CFT is far simpler than BFT:
the expensive machinery (a `≥ 2f+1` view-change certificate proving the lower views failed) exists only to
stop an *active adversary* from skipping ahead, which is out of scope. Keeping the timer local preserves
determinism: liveness is the only thing a clock may influence. The production guard is the pragmatic patch
for CFT round-robin's one real hazard — a minority partition that would otherwise finalize a fork —
implemented as a local production policy so it costs zero determinism.

**Rejected.** (a) **BFT view-change certificate** — correct, but it is the BFT layer this stage explicitly
excludes; it adds a wire message and a voting round for a threat (malicious skip-ahead) outside the fault
model. Recorded as the exact BFT attach point (§ADR "Upgrade path"). (b) **A committed, on-chain view
timer** — would put a wall-clock into consensus, violating I2. (c) **No production guard (pure
round-robin)** — a minority partition would finalize k-deep on a divergent chain and demand a reorg deeper
than `FINALITY_DEPTH` on heal, breaking finality. (d) **Global view counter in the header agreed by all**
— unnecessary; each node's local `current_view` plus the self-describing block `view` suffices, and the
lowest-view fork-choice tiebreak reconciles any race.

**Consequences.** The block header gains a `view: u32` (Decision 4). Liveness under a downed proposer is
`≤ (f + 1) × PROPOSER_TIMEOUT`; for the EC-6 case (`N = 3, f = 1`) recovery is within 2 timeouts, inside the
`MAX_VIEW_CHANGES = 3` budget.

---

## Decision 3 — Fork choice: longest valid chain, then lowest tip `view`, then lowest tip `hash`; k-deep finality

**Decision.** Among known §4-valid chains, the canonical one is chosen by a **deterministic total order on
tips**: (1) **greatest height**; ties → (2) **lowest tip `view`**; ties → (3) **lowest tip `hash`**. Two
distinct equal-height chains have distinct tip hashes, so rule 3 always terminates — the order is total,
and every honest node selects the same head. A block is **committed / final** once the canonical head is
`FINALITY_DEPTH = 6` blocks beyond it; **no reorg may cross a finalized block**; reorgs are bounded
`< FINALITY_DEPTH`. Comparing **tips only** (not whole branches) is sufficient and O(1) per candidate.

**Rationale.** *Longest chain first* preserves liveness — the chain that made the most progress wins —
and is the Stage-A rule (05 §5.2), so this is a strict refinement. *Lowest view as the equal-height
tiebreak* is what reconciles a late original proposer with its view-change successor: at a tip fork the
`view 0` (original) block beats the `view 1` (successor) block, so a slow-but-alive proposer's block pulls
everyone back to it (a bounded reorg) — this is the concrete "re-convergence when the original recovers."
*Lowest hash* is the final deterministic tiebreak and also keeps honest nodes from splitting on
equivocation (two blocks at the same `(h, view)` resolve to the lower hash — no split). **k-deep** finality
is the natural fit for round-robin CFT (05 §5.6, ADR-0004 D2) and is honestly *not* BFT finality: it
guarantees non-reversal under the CFT model + the production guard, not against a malicious quorum.

**Rejected.** (a) **Lowest view as the *primary* key** (over height) — a late low-view block at an early
height could force a giant reorg discarding many later blocks, wrecking liveness/finality; view must be a
*tiebreak at a height*, not a global primary. (b) **GHOST / heaviest-subtree** — machinery unjustified for
a small PoA round-robin with a slot-like schedule; longest-chain-with-tiebreak is sufficient and simpler.
(c) **BFT single-slot finality** — out of scope (Decision "Upgrade path"). (d) **Whole-branch comparison** —
unnecessary; tip `(height, view, hash)` is already a total order.

**Consequences.** Equivocation is handled *only enough to not split honest nodes* (lowest-hash keeps one
block) — that no-split tiebreak is what Stage B ships and tests (EC-B-F4). **Epoch eviction** of the
equivocator, evidence recording, binding quorum-backed equivocation proofs, and stake slashing are
accountable-safety (BFT) concerns and are **all deferred to the backlog (FU-8 / §14)** — Stage B does not
evict (an equivocator simply keeps its round-robin slots, covered by view-change, with no divergence).

---

## Decision 4 — Wire change is minimal: add `view: u32` to the block header, bump `PROTOCOL_VERSION`, no new message types, no topic bump

**Decision.**
- The **block header gains one field, `view: u32`**, inserted in the pre-image **after `timestamp`, before
  `txs_root`**: `number ‖ parent_hash ‖ timestamp ‖ view ‖ txs_root ‖ state_root ‖ proposer`. The hash and
  `proposer_sig` cover it, so the view is committed and unforgeable. `WireBlock` and `rpc::Block` gain the
  field; `txs_root`/`recompute_txs_root`/`shallow_verify` are otherwise unchanged.
- **No new wire messages.** CFT needs no pre-vote/pre-commit/view-change messages. Rotation and view change
  ride the existing block gossip + sync entirely via the header `view`.
- **`PROTOCOL_VERSION` bumps `1 → 2`**, and the `Hello` handshake **adds a major-version compatibility
  check** (disconnect on mismatch), so the block-encoding change is a **loud, explicit** break at the
  handshake.
- **No topic / sync-protocol string bump.** `ubi2/tx/1`, `ubi2/block/1`, `ubi2/sync/1` strings are kept;
  the `ubi2/block/1` *payload* (and thus the `Blocks` sync payload) is **redefined in place** to include
  `view`.

**Rationale — in-place redefinition over a topic bump.** ADR-0004's versioning discipline ("a format
change is a new protocol id, never a *silent* break") targets *deployed, interoperating* peers. There is
**no persistent `ubi2/block/1` network** — Stage A is devnet-only and upgrades in lockstep, so there is no
peer to silently break. Bumping the topic/sync strings would additionally **fork the browser light node's
`ubi2/sync/1` reuse** (spec 07 / ADR-0006) for zero interop benefit. The discipline's *intent* is
preserved a cheaper way: the `PROTOCOL_VERSION` bump + handshake check makes any old/new mismatch a **loud**
disconnect, and a stray old-encoding block fails length-checked decode / `shallow_verify` and is dropped —
never misinterpreted into valid-looking state. The **first persistent deployment** (the Stage-D testnet) is
the first pinned wire, and it is pinned *with* `view`.

**Rejected.** (a) **Bump `ubi2/block/2` + `ubi2/sync/2`** — the light-node fork + churn above, no interop
benefit on a lockstep devnet. (b) **A separate view-change message type** — a BFT construct; CFT needs none
(Decision 2). (c) **Leave the header untouched and infer `view` from timing** — impossible to make
deterministic (view would not be committed); breaks I1.

**Consequences.** `crates/network/src/wire.rs` (`WireBlock` encode/decode/pre-image), `crates/network/src/consts.rs`
(`PROTOCOL_VERSION = 2`), `crates/node/src/net.rs` (`on_hello` version check), and `crates/rpc` (`Block`
header, `produce_block`, `validate_and_apply_block`) change; the browser light node's transport is
untouched. A Stage-A block is exactly a Stage-B block with `view = 0`, so the `N = 1` degenerate case (and
the unchanged `m5_stage_a` acceptance test) stays byte-comparable across nodes.

---

## Decision 5 — Scope is CFT, not BFT; the validator/finality abstraction is the BFT attach point

**Decision.** Stage B tolerates **crash faults only** (up to `f` of `n` validators unavailable), stated as
the fault model in spec §7. It does **not** tolerate validators that lie about the schedule, equivocate as
a strategy, forge signatures, or a malicious *majority*. BFT — view-change certificates, pre-vote/pre-commit
rounds, single-slot accountable finality, quorum-bound equivocation slashing, unpredictable leader
election — is **backlog**. The `V` / epoch-snapshot / `proposer(h, v)` / block-validity abstractions are
built so a future BFT milestone replaces **only** the proposer + finality mechanism (swap round-robin +
k-deep for a BFT round over the same `V`; fork choice becomes "the certified chain") **without** touching
the wire formats, sync, the AI-quorum protocol, or `crates/runtime`.

**Rationale.** The M5 brief targets CFT explicitly and flags BFT scope-creep as Risk 3; PoA round-robin +
timeout view change is the **simplest CFT-correct** option that satisfies every Stage-B exit criterion
(rotation; liveness under a downed proposer; deterministic fork choice) with a small, auditable protocol
and a tractable security gate. BFT's cost (a multi-round voting protocol, a much larger test surface, a
harder gate) buys tolerance of an *actively malicious* proposer and instant finality — value the devnet
does not yet need and the roadmap sequences later.

**Upgrade path (the exact attach points, from spec §14).**
- **Successor authorization** (Decision 2): CFT uses `author == schedule(h, view)`; BFT adds a
  `≥ 2f+1` **view-change certificate**. ← the new wire message BFT introduces.
- **Finality** (Decision 3): CFT is k-deep; BFT adds a **commit certificate** (single-slot, accountable).
- **Equivocation** (Decision 3): CFT ships only the no-split lowest-hash tiebreak; evidence recording +
  epoch eviction + a **slashable quorum-verifiable proof** are all deferred here (FU-8/BFT).
- **Leader election** (Decision 1): CFT plain round-robin; BFT adds the deferred **per-epoch VRF/shuffle**.
- **Partition finality** (Decision 2): CFT uses the **production connectivity guard**; BFT makes it
  rigorous (a minority cannot form a certificate).

**Rejected.** Starting with BFT now (Tendermint/HotStuff) — rejected for this stage per the brief; it is
the documented next milestone, not this one.

---

## Status of invariants

- **I1 (deterministic consensus):** preserved and extended. The schedule, `view`, validity, and fork choice
  are pure functions of `(state, header)`; the epoch snapshot feeds `state_root`. Local clocks + peer
  counts drive only liveness (view escalation, production guard) and never a committed value. Byte-identical
  `state_root` holds through rotation and view change (EC-B5).
- **I2 (reproducible integer balances):** unchanged. Execution still reads *only* `block.timestamp`;
  `(height, view)` deliberately removes the timestamp from proposer selection, tightening rather than
  loosening the clock's role. No floats anywhere on the schedule/fork-choice path.
- **I3 (EVM compat):** preserved. `view` is a `ubi2_*`-namespaced extension; standard `eth_*` block fields
  and semantics are unchanged — unmodified wallets are unaffected.
- **I4 (fail-closed):** preserved. An unschedulable/unsigned/absurd-view/mismatched-root block is rejected
  and applies no state; a minority partition stalls rather than finalizing.
- **I6 (least authority):** preserved. The new RPC is read-only; validator membership is derived
  deterministically from committed state (registered validators ∧ Verified), no admin surface added. (A
  signed equivocation-evidence tx is deferred together with eviction — FU-8 / §14.)

## Open follow-ups created/closed by this ADR

- **Enables / closes on delivery:** FU-8's validator/juror **membership + rotation via the epoch snapshot**
  ships in Stage B; FU-8's **equivocation eviction** (evidence recording + next-epoch exclusion) is
  **deferred** with the rest of accountable-safety (§14). Closes the Stage-B exit criteria EC-5/EC-6 and the
  refinements EC-B1…EC-B6, EC-B-F3…F5 (EC-B-F4 = the no-split property only), keeping the EC-A
  (`m5_stage_a`) regression green.
- **Defers to backlog:** BFT consensus (view-change + commit certificates, single-slot finality,
  accountable slashing); per-epoch VRF/shuffle leader election; stake-slashing beyond epoch eviction. Each
  has a named attach point above (Decision 5).
</content>
